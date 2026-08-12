#!/usr/bin/env python3
"""Render a self-contained ASPM HTML report from DefectDojo findings (OSS).

Pro Report Builder API is unavailable on OSS; this script builds a shareable
HTML artifact (print → PDF) from /api/v2/findings/.
"""
from __future__ import annotations

import argparse
import json
import os
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any

GENERATOR_VERSION = "1.0.0"
SCRIPT_DIR = Path(__file__).resolve().parent
FABRICA_ROOT = SCRIPT_DIR.parent
DEFAULT_TEMPLATE = FABRICA_ROOT / "templates" / "reports" / "aspm-engagement-report.html.j2"
DEFAULT_KEV_CATALOG = FABRICA_ROOT / "config" / "kev" / "cisa-kev.min.json"
DEFAULT_EPSS_CATALOG = FABRICA_ROOT / "config" / "epss" / "epss_scores.min.json.gz"

# scripts/ on path so ``lib.*`` imports work when run as a script.
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from lib.epss_catalog import load_epss, lookup as epss_lookup  # noqa: E402
from lib.kev_catalog import any_in_kev, extract_cves, load_kev  # noqa: E402

CONTROL_LAYER_ORDER = (
    "secrets",
    "sast-semgrep",
    "osa-trivy-fs",
    "sca-trivy-image",
    "dast-zap",
    "api-fuzz-schemathesis",
)


def slice_out_path(out: Path, layer: str) -> Path:
    """Derive per-layer HTML path next to the full report ``out``.

    Example: ``aspm-report-svc.html`` + ``sast-semgrep`` → ``aspm-report-svc.sast-semgrep.html``.
    """
    safe = str(layer).strip().replace("/", "-").replace(" ", "-")
    if not safe:
        raise ValueError("layer name is empty")
    return out.with_name(f"{out.stem}.{safe}{out.suffix}")


def slices_manifest_path(out: Path) -> Path:
    """Sidecar index next to full HTML: ``aspm-report-svc.slices.json``."""
    return out.with_name(f"{out.stem}.slices.json")


def ssl_ctx() -> ssl.SSLContext | None:
    if os.environ.get("DEFECTDOJO_INSECURE", "").lower() in ("1", "true", "yes"):
        return ssl._create_unverified_context()
    return None


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Render ASPM HTML report from DefectDojo")
    p.add_argument("--product", default=os.environ.get("DEFECTDOJO_PRODUCT_NAME", "data_lake_service"))
    p.add_argument("--engagement", default=os.environ.get("DEFECTDOJO_ENGAGEMENT", "CI/CD"))
    p.add_argument("--out", type=Path, required=True, help="Output HTML path")
    p.add_argument("--from-json", type=Path, help="Offline fixture (skip live API)")
    p.add_argument(
        "--dojo-public-url",
        default=os.environ.get("DEFECTDOJO_PUBLIC_URL", ""),
        help="Base URL for finding deep-links (defaults to DEFECTDOJO_URL)",
    )
    p.add_argument("--wysiwyg", type=Path, help="Optional OSS Report Builder paste-kit markdown")
    p.add_argument("--include-mitigated", action="store_true")
    p.add_argument("--include-false-positive", action="store_true")
    p.add_argument("--top-n", type=int, default=15)
    p.add_argument("--page-size", type=int, default=25, help="Findings per layer page (default 25)")
    p.add_argument(
        "--max-findings-per-layer",
        type=int,
        default=0,
        help="Hard cap per layer after sort (0 = unlimited)",
    )
    p.add_argument(
        "--min-severity",
        default="Info",
        choices=["Info", "Low", "Medium", "High", "Critical"],
        help="Drop findings below this severity from the report body",
    )
    p.add_argument(
        "--kev-catalog",
        type=Path,
        default=DEFAULT_KEV_CATALOG,
        help="Offline CISA KEV min JSON (default config/kev/cisa-kev.min.json)",
    )
    p.add_argument(
        "--epss-catalog",
        type=Path,
        default=DEFAULT_EPSS_CATALOG,
        help="Offline EPSS sparse JSON.gz (default config/epss/epss_scores.min.json.gz)",
    )
    p.add_argument(
        "--epss-prefer",
        choices=["dojo", "catalog"],
        default="dojo",
        help="When both Dojo and catalog have EPSS: keep dojo (default) or force catalog",
    )
    p.add_argument(
        "--write-slices",
        action="store_true",
        help="Also write one HTML per nonempty control layer next to --out",
    )
    p.add_argument(
        "--only-slice",
        metavar="LAYER",
        default="",
        help="Write only this control layer to --out (no full report; not with --write-slices)",
    )
    p.add_argument("--template", type=Path, default=DEFAULT_TEMPLATE)
    return p.parse_args(argv)


def require_data_source(args: argparse.Namespace) -> None:
    if args.from_json:
        if not args.from_json.is_file():
            raise SystemExit(f"[aspm-report] fixture not found: {args.from_json}")
        return
    if not os.environ.get("DEFECTDOJO_URL", "").strip():
        raise SystemExit("[aspm-report] set DEFECTDOJO_URL or pass --from-json")
    if not os.environ.get("DEFECTDOJO_API_TOKEN", "").strip():
        raise SystemExit("[aspm-report] set DEFECTDOJO_API_TOKEN or pass --from-json")


def api_get(base: str, token: str, path: str, params: dict[str, str] | None = None) -> dict[str, Any]:
    q = urllib.parse.urlencode(params or {})
    url = f"{base.rstrip('/')}{path}"
    if q:
        url = f"{url}?{q}"
    req = urllib.request.Request(
        url,
        method="GET",
        headers={"Authorization": f"Token {token}", "Accept": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=120, context=ssl_ctx()) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            return json.loads(body) if body.strip() else {}
    except urllib.error.HTTPError as e:
        detail = e.read().decode("utf-8", errors="replace")[:500]
        raise SystemExit(f"[aspm-report] HTTP {e.code} {path}: {detail}") from e
    except urllib.error.URLError as e:
        raise SystemExit(f"[aspm-report] network error: {e.reason}") from e


def list_all(base: str, token: str, path: str, params: dict[str, str]) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    offset = 0
    limit = 200
    while True:
        q = dict(params)
        q["limit"] = str(limit)
        q["offset"] = str(offset)
        payload = api_get(base, token, path, q)
        chunk = payload.get("results") or []
        if not isinstance(chunk, list):
            raise SystemExit(f"[aspm-report] unexpected list payload for {path}")
        results.extend(chunk)
        if not payload.get("next") or not chunk:
            break
        offset += len(chunk)
    return results


def _as_bool(val: Any, default: bool = False) -> bool:
    if val is None:
        return default
    if isinstance(val, bool):
        return val
    return str(val).lower() in ("1", "true", "yes")


def _parse_date(val: Any) -> date | None:
    if not val:
        return None
    if isinstance(val, date) and not isinstance(val, datetime):
        return val
    text = str(val).strip()
    if not text:
        return None
    try:
        if "T" in text:
            return datetime.fromisoformat(text.replace("Z", "+00:00")).date()
        return date.fromisoformat(text[:10])
    except ValueError:
        return None


import re as _re

_JWT_RE = _re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}")
_B64_RE = _re.compile(r"[A-Za-z0-9+/=]{40,}")
_AKIA_RE = _re.compile(r"(?:AKIA|ASIA|AROA)[A-Z0-9]{16}")
_FENCE_RE = _re.compile(r"```[^\n]*\n(.*?)```", _re.DOTALL)
_BOLD_LABEL_RE = _re.compile(r"\*\*([^*]+):\*\*\s*")


def redact_secrets(text: str) -> str:
    """Replace JWT tokens, long base64 blobs, and AWS key IDs with placeholders."""
    text = _JWT_RE.sub("[REDACTED_JWT]", text)
    text = _AKIA_RE.sub("[REDACTED_AWSKEY]", text)
    text = _B64_RE.sub(lambda m: m.group(0) if len(m.group(0)) < 40 else "[REDACTED_SECRET]", text)
    return text


def sanitize_desc(text: str) -> str:
    """Strip markdown fences and bold label noise from scanner output."""
    def _fence_inner(m: _re.Match) -> str:
        return m.group(1).strip()
    text = _FENCE_RE.sub(_fence_inner, text)
    text = _BOLD_LABEL_RE.sub(r"\1: ", text)
    return text.strip()


def shorten_path(path: str, max_len: int = 64) -> str:
    """Middle-truncate a long file path keeping basename and one parent dir."""
    if len(path) <= max_len:
        return path
    p = Path(path)
    tail = p.name
    parent = p.parent.name
    short = f"…/{parent}/{tail}" if parent else f"…/{tail}"
    if len(short) > max_len:
        short = f"…/{tail}"
    return short


def _vulnerability_id_texts(raw: dict[str, Any]) -> list[str]:
    """Flatten Dojo cve / vulnerability_ids fields into searchable strings."""
    parts: list[str] = []
    cve = raw.get("cve")
    if cve:
        parts.append(str(cve))
    vids = raw.get("vulnerability_ids") or raw.get("vulnerability_id") or []
    if isinstance(vids, str):
        parts.append(vids)
    elif isinstance(vids, list):
        for item in vids:
            if isinstance(item, dict):
                parts.append(str(item.get("vulnerability_id") or item.get("cve") or item))
            elif item is not None:
                parts.append(str(item))
    if raw.get("cve_ids"):
        existing = raw.get("cve_ids")
        if isinstance(existing, list):
            parts.extend(str(x) for x in existing)
        else:
            parts.append(str(existing))
    return parts


def finding_cve_ids(raw: dict[str, Any]) -> list[str]:
    """CVE IDs from structured fields plus title/description regex."""
    return extract_cves(
        *_vulnerability_id_texts(raw),
        str(raw.get("title") or ""),
        str(raw.get("description") or ""),
    )


def normalize_finding(raw: dict[str, Any], *, today: date | None = None) -> dict[str, Any]:
    """Normalize a Dojo finding (or fixture row) into a stable internal shape."""
    today = today or datetime.now(timezone.utc).date()
    test = raw.get("test") if isinstance(raw.get("test"), dict) else {}
    test_title = (
        raw.get("test_title")
        or raw.get("test__title")
        or test.get("title")
        or ""
    )
    if not test_title and isinstance(raw.get("test"), int):
        test_title = ""

    endpoints = raw.get("endpoints") or raw.get("endpoints_to_add") or []
    endpoint_display = ""
    if isinstance(endpoints, list) and endpoints:
        first = endpoints[0]
        if isinstance(first, dict):
            endpoint_display = first.get("host") or first.get("display") or str(first.get("id", ""))
        else:
            endpoint_display = str(first)
    elif raw.get("endpoint"):
        endpoint_display = str(raw.get("endpoint"))

    found = _parse_date(raw.get("date") or raw.get("found_date") or raw.get("created"))
    age_days = (today - found).days if found else 0

    epss = raw.get("epss_score")
    try:
        epss_f = float(epss) if epss is not None and epss != "" else None
    except (TypeError, ValueError):
        epss_f = None

    epss_pct = raw.get("epss_percentile")
    try:
        epss_pct_f = float(epss_pct) if epss_pct is not None and epss_pct != "" else None
    except (TypeError, ValueError):
        epss_pct_f = None

    cwe = raw.get("cwe")
    try:
        cwe_i = int(cwe) if cwe not in (None, "") else None
    except (TypeError, ValueError):
        cwe_i = None

    cve_ids = finding_cve_ids(raw)
    in_kev = bool(raw.get("in_kev")) if "in_kev" in raw else False
    epss_source = str(raw.get("epss_source") or ("dojo" if epss_f is not None else "none"))

    fid = raw.get("id") or raw.get("finding_id")
    return {
        "id": fid,
        "title": str(raw.get("title") or "Untitled"),
        "severity": str(raw.get("severity") or "Info"),
        "description": redact_secrets(sanitize_desc(str(raw.get("description") or ""))),
        "mitigation": str(raw.get("mitigation") or ""),
        "cwe": cwe_i,
        "file_path": shorten_path(str(raw.get("file_path") or "")),
        "line": raw.get("line"),
        "component_name": str(raw.get("component_name") or ""),
        "component_version": str(raw.get("component_version") or ""),
        "test_title": str(test_title or "Other"),
        "active": _as_bool(raw.get("active"), True),
        "verified": _as_bool(raw.get("verified"), False),
        "false_p": _as_bool(raw.get("false_p"), False),
        "is_mitigated": _as_bool(raw.get("is_mitigated"), False),
        "dynamic_finding": _as_bool(raw.get("dynamic_finding"), False),
        "static_finding": _as_bool(raw.get("static_finding"), False),
        "epss_score": epss_f,
        "epss_percentile": epss_pct_f,
        "epss_source": epss_source,
        "cvssv3_score": raw.get("cvssv3_score") or raw.get("cvssv3"),
        "endpoint": endpoint_display,
        "endpoints": endpoints if isinstance(endpoints, list) else [],
        "date": found.isoformat() if found else "",
        "age_days": max(0, age_days),
        "sla_days_remaining": raw.get("sla_days_remaining"),
        "cve_ids": cve_ids,
        "in_kev": in_kev,
    }


def apply_kev_flags(
    findings: list[dict[str, Any]],
    catalog: frozenset[str] | None,
) -> list[dict[str, Any]]:
    """Set ``in_kev`` from offline catalog; no-op if catalog is None."""
    if catalog is None:
        return findings
    out: list[dict[str, Any]] = []
    for f in findings:
        row = dict(f)
        cves = row.get("cve_ids") or []
        row["in_kev"] = any_in_kev(cves, catalog)
        out.append(row)
    return out


def load_kev_catalog_optional(path: Path | None) -> frozenset[str] | None:
    if path is None:
        return None
    if not path.is_file():
        print(f"[aspm-report] WARN KEV catalog missing: {path} (SSVC without KEV)", file=sys.stderr)
        return None
    try:
        return load_kev(path)
    except Exception as e:  # noqa: BLE001 — report continues without KEV
        print(f"[aspm-report] WARN KEV catalog load failed: {e}", file=sys.stderr)
        return None


def load_epss_catalog_optional(path: Path | None) -> dict[str, dict[str, float]] | None:
    if path is None:
        return None
    if not path.is_file():
        print(f"[aspm-report] WARN EPSS catalog missing: {path}", file=sys.stderr)
        return None
    try:
        return load_epss(path)
    except Exception as e:  # noqa: BLE001
        print(f"[aspm-report] WARN EPSS catalog load failed: {e}", file=sys.stderr)
        return None


def _best_catalog_epss(
    cves: list[str],
    catalog: dict[str, dict[str, float]],
) -> dict[str, float] | None:
    best: dict[str, float] | None = None
    for cve in cves:
        hit = epss_lookup(cve, catalog)
        if hit is None:
            continue
        if best is None or hit["epss"] > best["epss"]:
            best = hit
    return best


def apply_epss_fillin(
    findings: list[dict[str, Any]],
    catalog: dict[str, dict[str, float]] | None,
    *,
    prefer: str = "dojo",
) -> list[dict[str, Any]]:
    """Fill epss_score from offline catalog. Dojo-first unless prefer=catalog."""
    if catalog is None:
        return findings
    out: list[dict[str, Any]] = []
    for f in findings:
        row = dict(f)
        dojo_score = row.get("epss_score")
        has_dojo = isinstance(dojo_score, (int, float))
        cat_hit = _best_catalog_epss(list(row.get("cve_ids") or []), catalog)
        if prefer == "catalog" and cat_hit is not None:
            row["epss_score"] = cat_hit["epss"]
            row["epss_percentile"] = cat_hit["percentile"]
            row["epss_source"] = "catalog"
        elif has_dojo:
            row["epss_source"] = "dojo"
            if row.get("epss_percentile") is None and cat_hit is not None:
                row["epss_percentile"] = cat_hit["percentile"]
        elif cat_hit is not None:
            row["epss_score"] = cat_hit["epss"]
            row["epss_percentile"] = cat_hit["percentile"]
            row["epss_source"] = "catalog"
        else:
            row["epss_source"] = "none"
        out.append(row)
    return out


def filter_findings(
    findings: list[dict[str, Any]],
    *,
    include_mitigated: bool,
    include_false_positive: bool,
) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for f in findings:
        if f.get("false_p") and not include_false_positive:
            continue
        if f.get("is_mitigated") and not include_mitigated:
            continue
        if not f.get("active"):
            # Default: active only. Mitigated/inactive kept only with --include-mitigated.
            if not (include_mitigated and f.get("is_mitigated")):
                continue
        out.append(f)
    return out


def fetch_live_bundle(
    *,
    product_name: str,
    engagement_name: str,
    include_mitigated: bool,
    include_false_positive: bool,
) -> dict[str, Any]:
    base = os.environ["DEFECTDOJO_URL"].rstrip("/")
    token = os.environ["DEFECTDOJO_API_TOKEN"]

    products = list_all(base, token, "/api/v2/products/", {"name": product_name})
    match = [p for p in products if p.get("name") == product_name] or [
        p for p in products if product_name in str(p.get("name", ""))
    ]
    if not match:
        raise SystemExit(f"[aspm-report] product not found: {product_name!r}")
    product = match[0]
    pid = product["id"]

    engagements = list_all(base, token, "/api/v2/engagements/", {"product": str(pid)})
    eng_match = [e for e in engagements if e.get("name") == engagement_name] or [
        e for e in engagements if engagement_name in str(e.get("name", ""))
    ]
    if not eng_match:
        raise SystemExit(
            f"[aspm-report] engagement {engagement_name!r} not found for product {product_name!r}"
        )
    engagement = eng_match[0]
    eid = engagement["id"]

    raw_findings = list_all(base, token, "/api/v2/findings/", {"test__engagement": str(eid)})
    # Enrich test titles: Dojo often returns test as id
    tests = {t["id"]: t for t in list_all(base, token, "/api/v2/tests/", {"engagement": str(eid)})}
    for raw in raw_findings:
        tid = raw.get("test")
        if isinstance(tid, int) and tid in tests:
            raw["test_title"] = tests[tid].get("title") or tests[tid].get("test_type_name") or ""
            raw["test"] = {"id": tid, "title": raw["test_title"]}

    findings = [normalize_finding(r) for r in raw_findings]
    findings = filter_findings(
        findings,
        include_mitigated=include_mitigated,
        include_false_positive=include_false_positive,
    )

    return {
        "product": {"id": pid, "name": product.get("name") or product_name},
        "engagement": {
            "id": eid,
            "name": engagement.get("name") or engagement_name,
            "branch_tag": engagement.get("branch_tag") or "",
            "build_id": engagement.get("build_id") or "",
            "commit_hash": engagement.get("commit_hash") or "",
            "version": engagement.get("version") or "",
            "target_start": str(engagement.get("target_start") or ""),
            "target_end": str(engagement.get("target_end") or ""),
        },
        "tests": [
            {
                "id": t.get("id"),
                "title": t.get("title") or t.get("test_type_name") or "",
                "branch_tag": t.get("branch") or t.get("branch_tag") or "",
                "build_id": t.get("build_id") or "",
                "commit_hash": t.get("commit_hash") or "",
            }
            for t in tests.values()
        ],
        "findings": findings,
        "source": "live",
        "dojo_base": base,
    }


def load_fixture_bundle(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise SystemExit("[aspm-report] fixture must be a JSON object")
    raw_findings = data.get("findings") or []
    findings = [normalize_finding(r) for r in raw_findings]
    product = data.get("product") or {"name": "fixture-product", "id": 0}
    engagement = data.get("engagement") or {"name": "CI/CD", "id": 0}
    return {
        "product": product,
        "engagement": engagement,
        "tests": data.get("tests") or [],
        "findings": findings,
        "source": "fixture",
        "dojo_base": data.get("dojo_base") or "",
    }


SEVERITY_ORDER = ("Critical", "High", "Medium", "Low", "Info")
SEVERITY_WEIGHT = {"Critical": 5, "High": 4, "Medium": 3, "Low": 2, "Info": 1}

# Heuristic CWE → OWASP Top 10:2021 bucket ids
CWE_TO_OWASP: dict[int, str] = {
    22: "A01",
    269: "A01",
    284: "A01",
    285: "A01",
    639: "A01",
    311: "A02",
    312: "A02",
    319: "A02",
    326: "A02",
    327: "A02",
    77: "A03",
    78: "A03",
    89: "A03",
    90: "A03",
    91: "A03",
    94: "A03",
    79: "A03",
    80: "A03",
    352: "A01",
    434: "A04",
    501: "A04",
    16: "A05",
    209: "A05",
    215: "A05",
    693: "A05",
    1188: "A05",
    1035: "A06",
    1104: "A06",
    937: "A06",
    287: "A07",
    306: "A07",
    384: "A07",
    798: "A07",
    502: "A08",
    829: "A08",
    918: "A10",
    755: "A04",
}

OWASP_LABELS = {
    "A01": "A01 Broken Access Control",
    "A02": "A02 Cryptographic Failures",
    "A03": "A03 Injection",
    "A04": "A04 Insecure Design",
    "A05": "A05 Security Misconfiguration",
    "A06": "A06 Vulnerable Components",
    "A07": "A07 Auth Failures",
    "A08": "A08 Software/Data Integrity",
    "A09": "A09 Logging Failures",
    "A10": "A10 SSRF",
    "Other": "Other / Unmapped",
}

SSVC_SLA_DAYS = {"Act": 2, "Attend": 14, "Track*": 60, "Track": 90}
SSVC_RANK = {"Act": 0, "Attend": 1, "Track*": 2, "Track": 3}


def by_severity(findings: list[dict[str, Any]]) -> dict[str, int]:
    counts = {s: 0 for s in SEVERITY_ORDER}
    for f in findings:
        sev = f.get("severity") or "Info"
        if sev not in counts:
            counts[sev] = 0
        counts[sev] += 1
    return counts


def by_test_title(findings: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    layers: dict[str, list[dict[str, Any]]] = {k: [] for k in CONTROL_LAYER_ORDER}
    layers["Other"] = []
    for f in findings:
        title = f.get("test_title") or "Other"
        if title in layers:
            layers[title].append(f)
        else:
            layers["Other"].append(f)
    for key in layers:
        layers[key].sort(
            key=lambda f: (
                -SEVERITY_WEIGHT.get(str(f.get("severity") or "Info"), 0),
                -int(f.get("age_days") or 0),
                str(f.get("title") or ""),
            )
        )
    return layers


def owasp_bucket(cwe: int | None) -> str:
    if cwe is None:
        return "Other"
    return CWE_TO_OWASP.get(int(cwe), "Other")


def owasp_histogram(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    counts: dict[str, int] = {k: 0 for k in OWASP_LABELS}
    for f in findings:
        bucket = owasp_bucket(f.get("cwe"))
        counts[bucket] = counts.get(bucket, 0) + 1
    rows = []
    for key, label in OWASP_LABELS.items():
        n = counts.get(key, 0)
        if n or key != "Other":
            rows.append({"id": key, "label": label, "count": n})
    return rows


def _bump_ssvc(action: str) -> str:
    order = ["Track", "Track*", "Attend", "Act"]
    try:
        i = order.index(action)
    except ValueError:
        return action
    return order[min(i + 1, len(order) - 1)]


def ssvc_lite(finding: dict[str, Any]) -> str:
    """Offline SSVC-lite: KEV → Act; else severity + dynamic + EPSS."""
    if finding.get("in_kev"):
        return "Act"

    sev = finding.get("severity") or "Info"
    if sev == "Critical":
        action = "Act"
    elif sev == "High":
        action = "Attend"
    elif sev == "Medium":
        action = "Track*"
    else:
        action = "Track"

    if finding.get("dynamic_finding") and action in ("Track", "Track*"):
        action = _bump_ssvc(action)
    epss = finding.get("epss_score")
    if isinstance(epss, (int, float)) and epss >= 0.5 and action != "Act":
        action = _bump_ssvc(action)
    return action


def ssvc_counts(findings: list[dict[str, Any]]) -> dict[str, int]:
    counts = {"Act": 0, "Attend": 0, "Track*": 0, "Track": 0}
    for f in findings:
        action = ssvc_lite(f)
        counts[action] = counts.get(action, 0) + 1
    return counts


def annotate_ssvc(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out = []
    for f in findings:
        row = dict(f)
        action = ssvc_lite(f)
        row["ssvc_action"] = action
        row["ssvc_sla_days"] = SSVC_SLA_DAYS.get(action, 90)
        row["owasp"] = owasp_bucket(f.get("cwe"))
        sla_rem = f.get("sla_days_remaining")
        try:
            rem = int(sla_rem) if sla_rem is not None else None
        except (TypeError, ValueError):
            rem = None
        overdue = rem is not None and rem < 0
        if rem is None and f.get("age_days", 0) > row["ssvc_sla_days"]:
            overdue = True
        row["sla_overdue"] = overdue
        out.append(row)
    return out


def coverage_matrix(
    findings: list[dict[str, Any]],
    tests: list[dict[str, Any]] | None = None,
    *,
    only_titles: list[str] | None = None,
) -> list[dict[str, Any]]:
    layers = by_test_title(findings)
    present_titles = {str(t.get("title") or "") for t in (tests or []) if t.get("title")}
    titles = list(CONTROL_LAYER_ORDER) + (["Other"] if layers.get("Other") else [])
    if only_titles is not None:
        allow = set(only_titles)
        titles = [t for t in titles if t in allow]
    rows = []
    for title in titles:
        items = layers.get(title) or []
        rows.append(
            {
                "test_title": title,
                "finding_count": len(items),
                "present": title in present_titles or len(items) > 0,
                "empty": len(items) == 0,
            }
        )
    return rows


def risk_score(finding: dict[str, Any]) -> float:
    """Higher = more urgent. Severity weight + age + SSVC + EPSS + KEV."""
    sev_w = SEVERITY_WEIGHT.get(str(finding.get("severity") or "Info"), 1)
    age = float(finding.get("age_days") or 0)
    ssvc_w = 4 - SSVC_RANK.get(finding.get("ssvc_action") or ssvc_lite(finding), 3)
    epss = finding.get("epss_score")
    epss_w = float(epss) if isinstance(epss, (int, float)) else 0.0
    overdue_w = 2.0 if finding.get("sla_overdue") else 0.0
    kev_w = 12.0 if finding.get("in_kev") else 0.0
    return sev_w * 10.0 + min(age, 90) * 0.05 + ssvc_w * 3.0 + epss_w * 5.0 + overdue_w + kev_w


def build_poam(findings: list[dict[str, Any]], top_n: int = 15) -> list[dict[str, Any]]:
    ranked = sorted(findings, key=risk_score, reverse=True)
    rows = []
    for i, f in enumerate(ranked[: max(0, top_n)], start=1):
        action = f.get("ssvc_action") or ssvc_lite(f)
        rows.append(
            {
                "priority": i,
                "id": f.get("id"),
                "title": f.get("title"),
                "severity": f.get("severity"),
                "layer": f.get("test_title") or "Other",
                "ssvc_action": action,
                "sla_days": f.get("ssvc_sla_days") or SSVC_SLA_DAYS.get(action, 90),
                "age_days": f.get("age_days") or 0,
                "sla_overdue": bool(f.get("sla_overdue")),
                "status": "Overdue" if f.get("sla_overdue") else ("Active" if f.get("active") else "Inactive"),
                "owner": "",
                "risk_score": round(risk_score(f), 2),
            }
        )
    return rows


def top_risks(findings: list[dict[str, Any]], n: int = 5) -> list[dict[str, Any]]:
    return build_poam(findings, top_n=n)


def endpoints_rollup(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    buckets: dict[str, dict[str, Any]] = {}
    for f in findings:
        ep = (f.get("endpoint") or "").strip()
        if not ep:
            if f.get("test_title") in ("dast-zap", "api-fuzz-schemathesis"):
                ep = f"{f.get('test_title')} (no host)"
            else:
                continue
        row = buckets.setdefault(
            ep,
            {"endpoint": ep, "count": 0, "max_severity": "Info", "findings": []},
        )
        row["count"] += 1
        row["findings"].append(f.get("id"))
        if SEVERITY_WEIGHT.get(str(f.get("severity")), 0) > SEVERITY_WEIGHT.get(row["max_severity"], 0):
            row["max_severity"] = f.get("severity") or "Info"
    return sorted(buckets.values(), key=lambda r: (-SEVERITY_WEIGHT.get(r["max_severity"], 0), -r["count"]))


def analyze_findings(
    findings: list[dict[str, Any]],
    tests: list[dict[str, Any]] | None = None,
    *,
    top_n: int = 15,
    coverage_only_titles: list[str] | None = None,
) -> dict[str, Any]:
    annotated = annotate_ssvc(findings)
    kev_n = sum(1 for f in annotated if f.get("in_kev"))
    epss_high_n = sum(
        1
        for f in annotated
        if isinstance(f.get("epss_score"), (int, float)) and float(f["epss_score"]) >= 0.5
    )
    return {
        "findings": annotated,
        "severity_counts": by_severity(annotated),
        "ssvc_counts": ssvc_counts(annotated),
        "kev_count": kev_n,
        "epss_high_count": epss_high_n,
        "layers": by_test_title(annotated),
        "owasp": owasp_histogram(annotated),
        "coverage": coverage_matrix(annotated, tests, only_titles=coverage_only_titles),
        "poam": build_poam(annotated, top_n=top_n),
        "top_risks": top_risks(annotated, n=5),
        "endpoints": endpoints_rollup(annotated),
    }


def _require_jinja2():
    try:
        import jinja2  # type: ignore
    except ImportError:
        # CI convenience path: try to bootstrap jinja2 in-place.
        # Offline corp runners may still fail here if the package index is unavailable.
        import subprocess

        try:
            print("[aspm-report] jinja2 missing; attempting bootstrap via pip")
            subprocess.check_call([sys.executable, "-m", "pip", "install", "--quiet", "jinja2"])
            import jinja2  # type: ignore
        except Exception as e:
            venv = FABRICA_ROOT / ".venv-aspm-report" / "bin" / "python"
            raise SystemExit(
                "[aspm-report] jinja2 required. Auto-install failed.\n"
                "Create venv manually:\n"
                f"  python3 -m venv {FABRICA_ROOT / '.venv-aspm-report'} && "
                f"{FABRICA_ROOT / '.venv-aspm-report' / 'bin' / 'pip'} install jinja2\n"
                f"Then re-run with: {venv} scripts/dojo-render-aspm-report.py ..."
            ) from e
    return jinja2


def severity_bar_svg(severity_counts: dict[str, int], width: int = 320, height: int = 120) -> str:
    colors = {
        "Critical": "#8b1e1e",
        "High": "#b54708",
        "Medium": "#a15c07",
        "Low": "#3d6b4f",
        "Info": "#5b6b7a",
    }
    total = sum(severity_counts.get(s, 0) for s in SEVERITY_ORDER) or 1
    x = 0.0
    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
        f'viewBox="0 0 {width} {height}" role="img" aria-label="Severity distribution">'
        f'<rect x="0" y="0" width="{width}" height="{height}" fill="#fffcf7" rx="6"/>'
    ]
    bar_y, bar_h = 28, 28
    for sev in SEVERITY_ORDER:
        n = int(severity_counts.get(sev, 0) or 0)
        w = (n / total) * (width - 16)
        if n:
            parts.append(
                f'<rect x="{8 + x:.1f}" y="{bar_y}" width="{max(w, 1):.1f}" height="{bar_h}" '
                f'fill="{colors[sev]}" rx="3"/>'
            )
            x += w
    parts.append(
        f'<text x="8" y="18" fill="#1a1f24" font-size="12" font-family="Segoe UI, sans-serif">'
        f"Severity mix (n={sum(severity_counts.get(s, 0) for s in SEVERITY_ORDER)})</text>"
    )
    lx = 8
    for sev in SEVERITY_ORDER:
        n = int(severity_counts.get(sev, 0) or 0)
        parts.append(
            f'<rect x="{lx}" y="72" width="10" height="10" fill="{colors[sev]}" rx="2"/>'
            f'<text x="{lx + 14}" y="81" fill="#5b6b7a" font-size="10" font-family="Segoe UI, sans-serif">'
            f"{sev[0]}:{n}</text>"
        )
        lx += 58
    parts.append("</svg>")
    return "".join(parts)


def owasp_strip_svg(owasp_rows: list[dict[str, Any]], width: int = 640, height: int = 140) -> str:
    rows = [r for r in owasp_rows if r.get("count")]
    if not rows:
        return '<p class="muted">No OWASP-mapped CWEs in scope.</p>'
    max_c = max(int(r["count"]) for r in rows) or 1
    bar_max = width - 160
    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{max(height, 20 + 16 * len(rows))}" '
        f'role="img" aria-label="OWASP histogram">'
    ]
    y = 8
    for r in rows:
        w = (int(r["count"]) / max_c) * bar_max
        parts.append(
            f'<text x="0" y="{y + 10}" fill="#1a1f24" font-size="10" font-family="Segoe UI, sans-serif">'
            f'{r["id"]}</text>'
            f'<rect x="40" y="{y}" width="{max(w, 2):.1f}" height="12" fill="#243447" rx="2"/>'
            f'<text x="{48 + w:.1f}" y="{y + 10}" fill="#5b6b7a" font-size="10">{r["count"]}</text>'
        )
        y += 16
    parts.append("</svg>")
    return "".join(parts)


def truncate(text: str, n: int = 280) -> str:
    text = (text or "").strip()
    if len(text) <= n:
        return text
    return text[: n - 1] + "…"


def finding_deep_link(public_url: str, finding_id: Any) -> str:
    if not public_url or finding_id in (None, ""):
        return ""
    return f"{public_url.rstrip('/')}/finding/{finding_id}"


def filter_by_min_severity(findings: list[dict[str, Any]], min_severity: str) -> list[dict[str, Any]]:
    """Keep findings at or above min_severity (Critical is highest)."""
    floor = SEVERITY_WEIGHT.get(min_severity, 1)
    return [f for f in findings if SEVERITY_WEIGHT.get(str(f.get("severity") or "Info"), 0) >= floor]


def _render_finding_card(f: dict[str, Any], public_url: str, escape) -> list[str]:
    parts: list[str] = []
    link = finding_deep_link(public_url, f.get("id"))
    loc = f.get("file_path") or f.get("endpoint") or ""
    if f.get("line") not in (None, ""):
        loc = f"{loc}:{f.get('line')}"
    cwe = f"CWE-{f['cwe']}" if f.get("cwe") else "—"
    overdue = " overdue" if f.get("sla_overdue") else ""
    parts.append(f'<article class="finding-card{overdue}">')
    parts.append(
        f'<header><span class="chip {escape(str(f.get("severity")))}">{escape(str(f.get("severity")))}</span> '
        + (
            '<span class="chip kev">KEV</span> '
            if f.get("in_kev")
            else ""
        )
        + f'<strong>{escape(str(f.get("title")))}</strong></header>'
    )
    parts.append('<dl class="finding-meta">')
    parts.append(f"<div><dt>CWE / OWASP</dt><dd>{cwe} / {escape(str(f.get('owasp') or 'Other'))}</dd></div>")
    cve_disp = ", ".join(str(c) for c in (f.get("cve_ids") or [])[:6]) or "—"
    parts.append(f"<div><dt>CVE</dt><dd>{escape(cve_disp)}</dd></div>")
    epss = f.get("epss_score")
    if isinstance(epss, (int, float)):
        pct = f.get("epss_percentile")
        pct_s = f"{float(pct):.2f}" if isinstance(pct, (int, float)) else "—"
        src = escape(str(f.get("epss_source") or "none"))
        parts.append(
            f"<div><dt>EPSS</dt><dd>{float(epss):.3f} (p{pct_s}, src={src})</dd></div>"
        )
    parts.append(
        f"<div><dt>SSVC</dt><dd>{escape(str(f.get('ssvc_action')))} "
        f"(SLA {f.get('ssvc_sla_days')}d, age {f.get('age_days')}d)"
        f"{' · CISA KEV' if f.get('in_kev') else ''}</dd></div>"
    )
    if loc:
        parts.append(f"<div><dt>Location</dt><dd><code>{escape(str(loc))}</code></dd></div>")
    if f.get("component_name"):
        parts.append(
            f"<div><dt>Component</dt><dd>{escape(str(f.get('component_name')))} "
            f"{escape(str(f.get('component_version') or ''))}</dd></div>"
        )
    if link:
        parts.append(f'<div><dt>DefectDojo</dt><dd><a href="{escape(link)}">{escape(link)}</a></dd></div>')
    parts.append("</dl>")
    desc = truncate(str(f.get("description") or ""))
    if desc:
        parts.append(f'<p class="desc">{escape(desc)}</p>')
    mit = truncate(str(f.get("mitigation") or ""), 200)
    if mit:
        parts.append(f'<p class="mit"><strong>Mitigation:</strong> {escape(mit)}</p>')
    parts.append("</article>")
    return parts


def _render_compact_row(f: dict[str, Any], public_url: str, escape) -> str:
    link = finding_deep_link(public_url, f.get("id"))
    title = escape(str(f.get("title") or ""))
    sev = escape(str(f.get("severity") or "Info"))
    age = f.get("age_days") or 0
    href = f' href="{escape(link)}"' if link else ""
    return (
        f'<div class="finding-row">'
        f'<span class="chip {sev}">{sev}</span> '
        f'<a{href}>{title}</a> '
        f'<span class="muted">{age}d</span>'
        f"</div>"
    )


def render_body_extra(
    analysis: dict[str, Any],
    public_url: str,
    *,
    page_size: int = 25,
    max_findings_per_layer: int = 0,
) -> str:
    """Layer cards, endpoints, POA&M, OWASP, coverage — HTML fragment."""
    from html import escape

    parts: list[str] = []
    page_size = max(1, int(page_size or 25))

    # POA&M
    parts.append('<section id="poam" class="page-break"><h2>POA&amp;M</h2>')
    parts.append(
        '<table class="data"><thead><tr>'
        "<th>#</th><th>Title</th><th>Sev</th><th>Layer</th><th>SSVC</th><th>SLA</th><th>Age</th><th>Status</th>"
        "</tr></thead><tbody>"
    )
    for r in analysis.get("poam") or []:
        overdue_cls = " overdue" if r.get("sla_overdue") else ""
        parts.append(
            f'<tr class="{overdue_cls}">'
            f'<td>{r["priority"]}</td>'
            f'<td>{escape(str(r["title"]))}</td>'
            f'<td><span class="chip {escape(str(r["severity"]))}">{escape(str(r["severity"]))}</span></td>'
            f'<td>{escape(str(r["layer"]))}</td>'
            f'<td>{escape(str(r["ssvc_action"]))}</td>'
            f'<td>{r["sla_days"]}d</td>'
            f'<td>{r["age_days"]}d</td>'
            f'<td>{escape(str(r["status"]))}</td>'
            "</tr>"
        )
    if not analysis.get("poam"):
        parts.append('<tr><td colspan="8" class="muted">No findings.</td></tr>')
    parts.append("</tbody></table></section>")

    # Endpoints
    parts.append('<section id="endpoints"><h2>Vulnerable endpoints</h2>')
    eps = analysis.get("endpoints") or []
    if not eps:
        parts.append('<p class="muted">No endpoint-scoped findings.</p>')
    else:
        parts.append('<table class="data"><thead><tr><th>Endpoint</th><th>Count</th><th>Max severity</th></tr></thead><tbody>')
        for e in eps:
            parts.append(
                f"<tr><td>{escape(str(e['endpoint']))}</td><td>{e['count']}</td>"
                f'<td><span class="chip {escape(str(e["max_severity"]))}">{escape(str(e["max_severity"]))}</span></td></tr>'
            )
        parts.append("</tbody></table>")
    parts.append("</section>")

    # OWASP
    parts.append('<section id="owasp"><h2>OWASP Top 10 mapping</h2>')
    parts.append(owasp_strip_svg(analysis.get("owasp") or []))
    parts.append("</section>")

    # Layers + cards (paginated)
    layers = analysis.get("layers") or {}
    for layer_name in list(CONTROL_LAYER_ORDER) + ["Other"]:
        items = list(layers.get(layer_name) or [])
        if not items:
            continue
        total_before_cap = len(items)
        truncated = False
        if max_findings_per_layer > 0 and len(items) > max_findings_per_layer:
            items = items[:max_findings_per_layer]
            truncated = True

        sev_counts: dict[str, int] = {s: 0 for s in SEVERITY_ORDER}
        for f in items:
            s = str(f.get("severity") or "Info")
            if s in sev_counts:
                sev_counts[s] += 1
        has_crit_high = (sev_counts.get("Critical", 0) + sev_counts.get("High", 0)) > 0
        # Layers start collapsed; toolbar Expand Crit+High / Expand all opens on demand.
        open_attr = ""
        chip_bits = " · ".join(
            f'<span class="chip {s}">{s[0]}{sev_counts[s]}</span>'
            for s in SEVERITY_ORDER
            if sev_counts[s]
        )
        parts.append(f'<section id="layer-{escape(layer_name)}" class="page-break">')
        parts.append(
            f'<details class="layer"{open_attr} data-layer="{escape(layer_name)}" '
            f'data-has-crit-high="{"1" if has_crit_high else "0"}">'
        )
        parts.append(
            f"<summary>Control layer: {escape(layer_name)} "
            f'<span class="muted">({len(items)})</span> {chip_bits}</summary>'
        )
        if truncated:
            parts.append(
                f'<p class="banner truncated">Showing {len(items)} of {total_before_cap} findings '
                f"(--max-findings-per-layer={max_findings_per_layer}).</p>"
            )

        pages = [items[i : i + page_size] for i in range(0, len(items), page_size)] or [[]]
        n_pages = len(pages)
        for pi, page_items in enumerate(pages):
            page_num = pi + 1
            hidden = " hidden" if page_num > 1 else ""
            parts.append(f'<div class="layer-page" data-page="{page_num}"{hidden}>')
            for f in page_items:
                parts.extend(_render_finding_card(f, public_url, escape))
            parts.append("</div>")

        remaining = max(0, len(items) - len(pages[0]))
        if remaining:
            parts.append(
                f'<p class="print-more muted">+ {remaining} more in interactive HTML '
                f"(page 1 of {n_pages} shown for print).</p>"
            )
        if n_pages > 1:
            parts.append(
                f'<nav class="pager" data-pages="{n_pages}" aria-label="Layer pager">'
                f'<button type="button" class="pager-prev" disabled>Prev</button> '
                f'<span class="pager-status">Page <span class="cur">1</span> / {n_pages}</span> '
                f'<button type="button" class="pager-next">Next</button> '
                f'<button type="button" class="pager-all">Show all</button>'
                f"</nav>"
            )
        parts.append("</details></section>")

    # Coverage
    parts.append('<section id="coverage"><h2>Coverage appendix</h2>')
    parts.append(
        '<table class="data coverage"><thead><tr><th>Test title</th><th>Present</th><th>Findings</th></tr></thead><tbody>'
    )
    for row in analysis.get("coverage") or []:
        heat = "heat-ok" if row["finding_count"] == 0 and row["present"] else (
            "heat-hot" if row["finding_count"] else "heat-miss"
        )
        parts.append(
            f'<tr class="{heat}"><td>{escape(str(row["test_title"]))}</td>'
            f'<td>{"yes" if row["present"] else "no"}</td>'
            f'<td>{row["finding_count"]}</td></tr>'
        )
    parts.append("</tbody></table></section>")
    return "\n".join(parts)


def build_template_context(
    bundle: dict[str, Any],
    analysis: dict[str, Any],
    *,
    public_url: str,
    include_mitigated: bool,
    include_false_positive: bool,
    page_size: int = 25,
    max_findings_per_layer: int = 0,
    min_severity: str = "Info",
    slice_label: str | None = None,
) -> dict[str, Any]:
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    filters = ["active-only", f"min-severity={min_severity}", f"page-size={page_size}"]
    if include_mitigated:
        filters.append("include-mitigated")
    if include_false_positive:
        filters.append("include-false-positive")
    if max_findings_per_layer > 0:
        filters.append(f"max-per-layer={max_findings_per_layer}")
    filters.append("redact=on")
    label = (slice_label or "").strip() or None
    if label:
        filters.append(f"slice={label}")
    layer_order = [k for k in CONTROL_LAYER_ORDER if analysis["layers"].get(k)]
    if analysis["layers"].get("Other"):
        layer_order.append("Other")
    layer_toc = []
    for name in layer_order:
        items = analysis["layers"].get(name) or []
        c = sum(1 for f in items if f.get("severity") == "Critical")
        h = sum(1 for f in items if f.get("severity") == "High")
        layer_toc.append({"name": name, "count": len(items), "critical": c, "high": h})
    report_title = f"ASPM — {bundle['product'].get('name')} — {bundle['engagement'].get('name')}"
    if label:
        report_title = f"{report_title} (slice: {label})"
    return {
        "report_title": report_title,
        "slice_label": label,
        "product": bundle["product"],
        "engagement": bundle["engagement"],
        "generated_at": generated_at,
        "findings": analysis["findings"],
        "severity_counts": analysis["severity_counts"],
        "ssvc_counts": analysis["ssvc_counts"],
        "kev_count": analysis.get("kev_count", 0),
        "epss_high_count": analysis.get("epss_high_count", 0),
        "top_risks": analysis["top_risks"],
        "severity_svg": severity_bar_svg(analysis["severity_counts"]),
        "body_extra": render_body_extra(
            analysis,
            public_url,
            page_size=page_size,
            max_findings_per_layer=max_findings_per_layer,
        ),
        "layer_order": layer_order,
        "layer_toc": layer_toc,
        "generator_version": GENERATOR_VERSION,
        "source": bundle.get("source"),
        "filters_note": ",".join(filters),
        "dojo_public_url": public_url,
        "page_size": page_size,
        "min_severity": min_severity,
    }


def render_html(template_path: Path, context: dict[str, Any]) -> str:
    jinja2 = _require_jinja2()
    env = jinja2.Environment(
        loader=jinja2.FileSystemLoader(str(template_path.parent)),
        autoescape=jinja2.select_autoescape(["html", "j2", "xml"]),
    )
    tmpl = env.get_template(template_path.name)
    return tmpl.render(**context)


def render_wysiwyg_kit(
    bundle: dict[str, Any],
    analysis: dict[str, Any],
    *,
    public_url: str,
) -> str:
    """Paste kit for OSS DefectDojo Report Builder (layouts are not saved)."""
    product = bundle["product"].get("name")
    engagement = bundle["engagement"].get("name")
    sev = analysis["severity_counts"]
    ssvc = analysis["ssvc_counts"]
    lines = [
        f"# OSS Report Builder paste kit — {product} / {engagement}",
        "",
        "DefectDojo OSS does **not** import or save report templates. Rebuild widgets each time.",
        f"Generated HTML deep-link base: `{public_url or '(set --dojo-public-url)'}`",
        "",
        "## Report Options",
        f"- **Report Name:** ASPM {product} — {engagement}",
        "- Include Finding Notes: optional",
        "- Include Finding Images: optional",
        "",
        "## Suggested widget order",
        "1. Cover Page — heading `ASPM security report`, sub-heading product name",
        "2. Executive Summary — paste block below; enable Include SLAs if configured",
        "3. Severities — define org severity meanings",
        "4. Table of Contents",
        "5. Findings widgets — one per control layer (filters below)",
        "6. WYSIWYG — closing notes / methodology",
        "",
        "## Executive Summary (paste)",
        "",
        f"Product `{product}`, engagement `{engagement}`. "
        f"Active findings: {len(analysis['findings'])}. "
        f"Severity — Critical {sev.get('Critical', 0)}, High {sev.get('High', 0)}, "
        f"Medium {sev.get('Medium', 0)}, Low {sev.get('Low', 0)}, Info {sev.get('Info', 0)}. "
        f"SSVC-lite — Act {ssvc.get('Act', 0)}, Attend {ssvc.get('Attend', 0)}, "
        f"Track* {ssvc.get('Track*', 0)}, Track {ssvc.get('Track', 0)}.",
        "",
        "Top risks:",
    ]
    for r in analysis.get("top_risks") or []:
        lines.append(f"- [{r['severity']}] {r['title']} ({r['ssvc_action']}, {r['layer']})")
    if not analysis.get("top_risks"):
        lines.append("- (none)")
    lines.extend(
        [
            "",
            "## Findings widget filters (checklist)",
            "",
            "| Layer (test title) | Suggested filters |",
            "|---|---|",
        ]
    )
    for title in list(CONTROL_LAYER_ORDER) + ["Other"]:
        n = len((analysis.get("layers") or {}).get(title) or [])
        if title == "Other" and n == 0:
            continue
        lines.append(
            f"| `{title}` | product=`{product}`, engagement name=`{engagement}`, "
            f"test title contains `{title}`, active=true, false positive=false — preview count ~{n} |"
        )
    lines.extend(
        [
            "",
            "## Note",
            "Prefer the generated HTML artifact from `dojo-render-aspm-report.py` for sharing; "
            "use this kit only when stakeholders insist on native Dojo Report Builder output.",
            "",
        ]
    )
    return "\n".join(lines)


def nonempty_layer_order(analysis: dict[str, Any]) -> list[str]:
    order = [k for k in CONTROL_LAYER_ORDER if analysis.get("layers", {}).get(k)]
    if analysis.get("layers", {}).get("Other"):
        order.append("Other")
    return order


def write_slices_manifest(
    path: Path,
    *,
    product: str,
    full: Path,
    slices: list[dict[str, Any]],
) -> None:
    doc = {
        "product": product,
        "full": str(full.name),
        "slices": slices,
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(doc, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    require_data_source(args)

    only_slice = (args.only_slice or "").strip()
    if only_slice and args.write_slices:
        raise SystemExit("[aspm-report] --only-slice and --write-slices are mutually exclusive")

    if args.from_json:
        bundle = load_fixture_bundle(args.from_json)
        bundle["findings"] = filter_findings(
            bundle["findings"],
            include_mitigated=args.include_mitigated,
            include_false_positive=args.include_false_positive,
        )
    else:
        bundle = fetch_live_bundle(
            product_name=args.product,
            engagement_name=args.engagement,
            include_mitigated=args.include_mitigated,
            include_false_positive=args.include_false_positive,
        )

    public = (args.dojo_public_url or bundle.get("dojo_base") or os.environ.get("DEFECTDOJO_URL", "")).rstrip(
        "/"
    )
    kev_catalog = load_kev_catalog_optional(args.kev_catalog)
    epss_catalog = load_epss_catalog_optional(args.epss_catalog)
    findings = filter_by_min_severity(bundle["findings"], args.min_severity)
    findings = apply_kev_flags(findings, kev_catalog)
    findings = apply_epss_fillin(findings, epss_catalog, prefer=args.epss_prefer)
    analysis = analyze_findings(findings, bundle.get("tests"), top_n=args.top_n)

    if not args.template.is_file():
        raise SystemExit(f"[aspm-report] template not found: {args.template}")

    ctx_kwargs = dict(
        public_url=public,
        include_mitigated=args.include_mitigated,
        include_false_positive=args.include_false_positive,
        page_size=args.page_size,
        max_findings_per_layer=args.max_findings_per_layer,
        min_severity=args.min_severity,
    )

    if only_slice:
        items = (analysis.get("layers") or {}).get(only_slice) or []
        if not items:
            known = ", ".join(nonempty_layer_order(analysis)) or "(none nonempty)"
            raise SystemExit(
                f"[aspm-report] --only-slice={only_slice!r} has no findings; "
                f"nonempty layers: {known}"
            )
        slice_analysis = analyze_findings(
            items,
            bundle.get("tests"),
            top_n=args.top_n,
            coverage_only_titles=[only_slice],
        )
        ctx = build_template_context(
            bundle, slice_analysis, slice_label=only_slice, **ctx_kwargs
        )
        html = render_html(args.template, ctx)
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(html, encoding="utf-8")
        print(
            f"[aspm-report] wrote {args.out} slice={only_slice} "
            f"findings={len(slice_analysis['findings'])}"
        )
        return 0

    ctx = build_template_context(bundle, analysis, slice_label=None, **ctx_kwargs)
    html = render_html(args.template, ctx)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(html, encoding="utf-8")
    print(
        f"[aspm-report] wrote {args.out} source={bundle['source']} "
        f"findings={len(analysis['findings'])} ssvc={analysis['ssvc_counts']} "
        f"severity={analysis['severity_counts']}"
    )

    if args.write_slices:
        manifest_slices: list[dict[str, Any]] = []
        for layer in nonempty_layer_order(analysis):
            items = analysis["layers"][layer]
            slice_analysis = analyze_findings(
                items,
                bundle.get("tests"),
                top_n=args.top_n,
                coverage_only_titles=[layer],
            )
            slice_ctx = build_template_context(
                bundle, slice_analysis, slice_label=layer, **ctx_kwargs
            )
            slice_path = slice_out_path(args.out, layer)
            slice_path.write_text(render_html(args.template, slice_ctx), encoding="utf-8")
            crit = sum(1 for f in items if f.get("severity") == "Critical")
            high = sum(1 for f in items if f.get("severity") == "High")
            manifest_slices.append(
                {
                    "layer": layer,
                    "path": slice_path.name,
                    "finding_count": len(items),
                    "critical": crit,
                    "high": high,
                }
            )
            print(f"[aspm-report] wrote slice {slice_path} findings={len(items)}")
        man_path = slices_manifest_path(args.out)
        write_slices_manifest(
            man_path,
            product=str(bundle.get("product", {}).get("name") or ""),
            full=args.out,
            slices=manifest_slices,
        )
        print(f"[aspm-report] wrote manifest {man_path} slices={len(manifest_slices)}")

    if args.wysiwyg:
        kit = render_wysiwyg_kit(bundle, analysis, public_url=public)
        args.wysiwyg.parent.mkdir(parents=True, exist_ok=True)
        args.wysiwyg.write_text(kit, encoding="utf-8")
        print(f"[aspm-report] wrote wysiwyg kit {args.wysiwyg}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
