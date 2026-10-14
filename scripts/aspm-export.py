#!/usr/bin/env python3
"""Export scan reports to ASPM/ASOC platforms (DefectDojo, noop)."""
from __future__ import annotations

import argparse
import json
import mimetypes
import os
import re
import ssl
import sys
import uuid
import xml.etree.ElementTree as ET
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

try:
    import yaml  # type: ignore
except ImportError:
    yaml = None


def expand_env(value: str) -> str:
    """Expand ${VAR} and ${VAR:-default} patterns (nested defaults supported)."""

    def repl(match: re.Match[str]) -> str:
        body = match.group(1)
        if ":-" in body:
            name, default = body.split(":-", 1)
            return os.environ.get(name, default)
        return os.environ.get(body, "")

    prev = None
    out = value
    # Nested forms like ${A:-${B:-x}} need repeated passes (inner first after outer default).
    for _ in range(8):
        if out == prev:
            break
        prev = out
        out = re.sub(r"\$\{([^{}]+)\}", repl, out)
    return out


def ssl_context_for_dojo() -> ssl.SSLContext | None:
    if os.environ.get("DEFECTDOJO_INSECURE", "").lower() in ("1", "true", "yes"):
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx
    return None


def load_config(path: Path) -> dict:
    text = path.read_text(encoding="utf-8")
    if yaml is not None:
        return yaml.safe_load(text) or {}
    return _parse_config_simple(text)


def _parse_config_simple(text: str) -> dict:
    """Minimal YAML subset when PyYAML is unavailable."""
    cfg: dict = {"controls": {}}
    section = None
    control = None
    for line in text.splitlines():
        if line.strip().startswith("#") or not line.strip():
            continue
        if re.match(r"^[a-z_]+:\s*$", line):
            section = line.split(":")[0]
            if section == "controls":
                cfg.setdefault("controls", {})
            continue
        m = re.match(r"^  (\w+):\s*(.+)$", line)
        if m and section == "defectdojo":
            key, val = m.group(1), m.group(2).strip().strip("'\"")
            cfg.setdefault("defectdojo", {})[key] = val in ("true", "false") if val in ("true", "false") else val
        m2 = re.match(r"^  (\w+):\s*$", line)
        if m2 and section == "controls":
            control = m2.group(1)
            cfg["controls"][control] = {}
        m3 = re.match(r"^    (\w+):\s*(.+)$", line)
        if m3 and section == "controls" and control:
            cfg["controls"][control][m3.group(1)] = m3.group(2).strip().strip("'\"")
    top = re.match(r"^(backend):\s*(.+)$", text)
    if top:
        cfg["backend"] = top.group(2).strip()
    return cfg


def is_enabled(cfg: dict) -> bool:
    env_name = (cfg.get("defaults") or {}).get("enabled_env", "DEFECTDOJO_URL")
    return bool(os.environ.get(env_name, "").strip())


def _checkov_item_has_findings(item: dict) -> bool:
    results = item.get("results")
    if isinstance(results, dict) and "failed_checks" in results:
        failed = results.get("failed_checks") or []
        return bool(failed) if isinstance(failed, list) else bool(failed)
    return False


def report_has_findings(path: Path) -> bool:
    if not path.exists() or path.stat().st_size == 0:
        return False
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return True
    # Checkov multi-framework JSON is a list of per-framework objects.
    if isinstance(data, list):
        return any(_checkov_item_has_findings(x) for x in data if isinstance(x, dict))
    if not isinstance(data, dict):
        return False
    # OpenSCAP / infra summary (top-level counters).
    if "failed_checks" in data or "failed_checks_xccdf" in data:
        return int(data.get("failed_checks", 0) or 0) > 0 or int(
            data.get("failed_checks_xccdf", 0) or 0
        ) > 0
    # Checkov single-object JSON: results.failed_checks (empty → no findings).
    results = data.get("results")
    if isinstance(results, dict) and "failed_checks" in results:
        failed = results.get("failed_checks") or []
        return bool(failed) if isinstance(failed, list) else bool(failed)
    if "runs" in data:
        for run in data.get("runs", []):
            if run.get("results"):
                return True
        return False
    if "site" in data:
        for site in data.get("site", []):
            if site.get("alerts"):
                return True
        return False
    if data.get("vulnerabilities") or data.get("Results"):
        return True
    if data.get("findings"):
        return bool(data["findings"])
    return path.stat().st_size > 50


def sanitize_sarif_for_dojo(path: Path) -> Path:
    """Rewrite SARIF so DefectDojo importer does not 500.

    Root cause (repro 2026-07-29): Ruff emits results with ``"ruleId": null``
    (e.g. notebook SyntaxError). DefectDojo SARIF parser crashes on null ruleId
    → HTTP 500. Gitleaks/semgrep never emit null ruleIds and upload fine.

    Fix: assign synthetic rule id ``missing-rule-id`` and ensure driver.rules
    contains it. Also relativize ``file://`` URIs when they contain ``/checkout/``.
    """
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or "runs" not in data:
        return path

    synth_id = "missing-rule-id"
    synth_rule = {
        "id": synth_id,
        "name": synth_id,
        "shortDescription": {"text": "Finding had null/empty ruleId in source SARIF"},
        "fullDescription": {
            "text": "Normalized for DefectDojo — original scanner omitted ruleId (often syntax errors)."
        },
        "defaultConfiguration": {"level": "error"},
    }
    null_fixed = 0
    uri_fixed = 0

    for run in data.get("runs") or []:
        if not isinstance(run, dict):
            continue
        driver = ((run.get("tool") or {}).get("driver")) or {}
        rules = list(driver.get("rules") or [])
        rule_ids = {r.get("id") for r in rules if isinstance(r, dict)}
        need_synth = False

        for res in run.get("results") or []:
            if not isinstance(res, dict):
                continue
            rid = res.get("ruleId")
            if rid is None or (isinstance(rid, str) and not rid.strip()):
                res["ruleId"] = synth_id
                null_fixed += 1
                need_synth = True
            for loc in res.get("locations") or []:
                if not isinstance(loc, dict):
                    continue
                art = ((loc.get("physicalLocation") or {}).get("artifactLocation")) or {}
                uri = art.get("uri")
                if isinstance(uri, str) and uri.startswith("file://") and "/checkout/" in uri:
                    art["uri"] = uri.split("/checkout/", 1)[1]
                    uri_fixed += 1

        if need_synth and synth_id not in rule_ids:
            rules.append(synth_rule)
            driver["rules"] = rules
            tool = run.setdefault("tool", {})
            tool["driver"] = driver

    if null_fixed == 0 and uri_fixed == 0:
        return path

    out = path.parent / f"{path.stem}.dojo.sarif"
    out.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
    print(
        f"[aspm] sanitized SARIF for Dojo: null_ruleId_fixed={null_fixed} "
        f"file_uri_relativized={uri_fixed} → {out}",
        file=sys.stderr,
    )
    return out


def infra_summary_to_generic(path: Path) -> Path:
    """Convert summary_infra.json to DefectDojo Generic Findings Import JSON."""
    data = json.loads(path.read_text(encoding="utf-8"))
    findings = []
    failed = int(data.get("failed_checks", 0) or 0)
    if failed > 0:
        findings.append(
            {
                "title": f"OpenSCAP OVAL failed_checks={failed}",
                "severity": "High" if failed > 100 else "Medium",
                "description": (
                    f"codename={data.get('codename')} status={data.get('status')} "
                    f"total={data.get('total_checks')} oval_source={data.get('oval_source')}"
                ),
                "file_path": "infra/scap/report",
            }
        )
    xccdf = data.get("failed_checks_xccdf")
    if xccdf is not None and int(xccdf) > 0:
        findings.append(
            {
                "title": f"OpenSCAP XCCDF failed_checks_xccdf={int(xccdf)}",
                "severity": "High",
                "description": f"total_xccdf={data.get('total_checks_xccdf')}",
                "file_path": "infra/scap/report",
            }
        )
    out = path.with_suffix(".generic.json")
    out.write_text(json.dumps({"findings": findings}, indent=2) + "\n", encoding="utf-8")
    return out


_SARIF_LEVEL_TO_SEV = {
    "error": "High",
    "warning": "Medium",
    "note": "Low",
    "none": "Info",
}


def _sarif_result_severity(result: dict) -> str:
    """Map SARIF level / security-severity to DefectDojo severity."""
    props = result.get("properties") if isinstance(result.get("properties"), dict) else {}
    sec = props.get("security-severity") or props.get("security_severity")
    if sec is not None:
        try:
            score = float(sec)
            if score >= 9.0:
                return "Critical"
            if score >= 7.0:
                return "High"
            if score >= 4.0:
                return "Medium"
            if score > 0:
                return "Low"
            return "Info"
        except (TypeError, ValueError):
            label = str(sec).strip().capitalize()
            if label in ("Critical", "High", "Medium", "Low", "Info"):
                return label
    level = str(result.get("level") or "warning").lower()
    return _SARIF_LEVEL_TO_SEV.get(level, "Medium")


def _sarif_result_location(result: dict) -> tuple[str, int | None]:
    for loc in result.get("locations") or []:
        if not isinstance(loc, dict):
            continue
        phys = loc.get("physicalLocation") or {}
        if not isinstance(phys, dict):
            continue
        art = phys.get("artifactLocation") or {}
        uri = ""
        if isinstance(art, dict):
            uri = str(art.get("uri") or "")
        region = phys.get("region") or {}
        line = None
        if isinstance(region, dict) and region.get("startLine") is not None:
            try:
                line = int(region["startLine"])
            except (TypeError, ValueError):
                line = None
        if uri:
            if uri.startswith("file://") and "/checkout/" in uri:
                uri = uri.split("/checkout/", 1)[1]
            return uri, line
    return "", None


def _sarif_result_texts(result: dict) -> list[str]:
    parts: list[str] = []
    rule_id = result.get("ruleId")
    if rule_id:
        parts.append(str(rule_id))
    msg = result.get("message") or {}
    if isinstance(msg, dict):
        parts.append(str(msg.get("text") or ""))
    else:
        parts.append(str(msg))
    props = result.get("properties") or {}
    if isinstance(props, dict):
        for key in ("cve", "vulnerabilityID", "VulnerabilityID", "epssCve"):
            if props.get(key):
                parts.append(str(props[key]))
        for key in ("cisaKevCves",):
            val = props.get(key)
            if isinstance(val, list):
                parts.extend(str(x) for x in val)
            elif val:
                parts.append(str(val))
    return parts


def sarif_result_to_generic_finding(result: dict) -> dict:
    """Map one enriched SARIF result to DefectDojo Generic Findings Import shape."""
    # Local import keeps aspm-export usable when lib/ is absent (rare).
    try:
        from lib.kev_catalog import extract_cves  # type: ignore
    except ImportError:
        _cve_re = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)

        def extract_cves(*texts: str | None) -> list[str]:  # type: ignore
            seen: set[str] = set()
            out: list[str] = []
            for text in texts:
                if not text:
                    continue
                for m in _cve_re.finditer(str(text)):
                    cve = m.group(0).upper()
                    if cve not in seen:
                        seen.add(cve)
                        out.append(cve)
            return out

    props = result.get("properties") if isinstance(result.get("properties"), dict) else {}
    msg = result.get("message") or {}
    msg_text = str(msg.get("text") or "") if isinstance(msg, dict) else str(msg or "")
    rule_id = str(result.get("ruleId") or "").strip() or "unknown"
    cves = extract_cves(*_sarif_result_texts(result))
    title = rule_id if rule_id.startswith("CVE-") else (cves[0] if cves else rule_id)
    if rule_id and not title.startswith("CVE-") and cves:
        title = f"{rule_id}: {cves[0]}"
    elif rule_id and title == rule_id and msg_text:
        title = f"{rule_id}: {msg_text.splitlines()[0][:120]}"

    finding: dict = {
        "title": title[:500],
        "severity": _sarif_result_severity(result),
        "description": msg_text[:4000] or title,
    }
    file_path, line = _sarif_result_location(result)
    if file_path:
        finding["file_path"] = file_path
    if line is not None:
        finding["line"] = line
    if cves:
        # DefectDojo 2.50 Generic importer 500s on deprecated top-level "cve";
        # use vulnerability_ids only (verified against corp Dojo).
        finding["vulnerability_ids"] = cves

    tags: list[str] = []
    if props.get("cisaKev") is True or props.get("cisaKev") == "true":
        finding["known_exploited"] = True
        tags.append("cisa-kev")
    epss = props.get("epss")
    if epss is not None:
        try:
            finding["epss_score"] = float(epss)
            tags.append("epss")
        except (TypeError, ValueError):
            pass
    epss_pct = props.get("epssPercentile")
    if epss_pct is not None:
        try:
            finding["epss_percentile"] = float(epss_pct)
        except (TypeError, ValueError):
            pass
    if tags:
        finding["tags"] = tags
    return finding


def sarif_to_generic(path: Path) -> Path:
    """Convert enriched Trivy SARIF to DefectDojo Generic Findings Import JSON.

    Maps ``properties.epss`` / ``epssPercentile`` / ``cisaKev`` into native Finding
    fields so DefectDojo UI shows EPSS and KEV (SARIF importer ignores custom props).
    """
    data = json.loads(path.read_text(encoding="utf-8"))
    findings: list[dict] = []
    if isinstance(data, dict):
        for run in data.get("runs") or []:
            if not isinstance(run, dict):
                continue
            for result in run.get("results") or []:
                if isinstance(result, dict):
                    findings.append(sarif_result_to_generic_finding(result))
    out = path.with_name(path.stem + ".generic.json")
    out.write_text(json.dumps({"findings": findings}, indent=2) + "\n", encoding="utf-8")
    return out


def junit_to_generic(path: Path) -> Path:
    """Convert Schemathesis/JUnit XML to DefectDojo Generic Findings Import.

    Corp DefectDojo has no \"JUnit Test\" scan_type. Map failures/errors to findings;
    all-pass runs emit one Info finding so the Test always materializes in Dojo.
    """
    root = ET.parse(path).getroot()
    suites = [root] if root.tag == "testsuite" else list(root.findall(".//testsuite"))
    findings: list[dict] = []
    total = 0
    for suite in suites:
        for case in suite.findall("testcase"):
            total += 1
            name = case.attrib.get("name") or "unnamed"
            classname = case.attrib.get("classname") or ""
            err = case.find("error")
            fail = case.find("failure")
            node = err if err is not None else fail
            if node is None:
                continue
            sev = "Critical" if err is not None else "High"
            msg = (node.attrib.get("message") or "").strip()
            body = (node.text or "").strip()
            desc = "\n".join(x for x in (classname, msg, body) if x)
            findings.append(
                {
                    "title": f"schemathesis: {name}",
                    "severity": sev,
                    "description": desc[:4000] or name,
                    "file_path": classname or "api-fuzz",
                }
            )
    if not findings:
        findings.append(
            {
                "title": f"schemathesis: {total} tests passed",
                "severity": "Info",
                "description": f"JUnit report {path.name}: tests={total} failures=0 errors=0",
                "file_path": "api-fuzz",
            }
        )
    out = path.with_name(path.stem + ".generic.json")
    out.write_text(json.dumps({"findings": findings}, indent=2) + "\n", encoding="utf-8")
    return out


def build_multipart(fields: dict[str, str], file_field: str, file_path: Path) -> tuple[bytes, str]:
    boundary = f"----aspm-{uuid.uuid4().hex}"
    lines: list[bytes] = []
    for key, val in fields.items():
        if val is None or val == "":
            continue
        lines.append(f"--{boundary}\r\n".encode())
        lines.append(f'Content-Disposition: form-data; name="{key}"\r\n\r\n'.encode())
        lines.append(f"{val}\r\n".encode())
    mime = mimetypes.guess_type(str(file_path))[0] or "application/octet-stream"
    lines.append(f"--{boundary}\r\n".encode())
    lines.append(
        f'Content-Disposition: form-data; name="{file_field}"; filename="{file_path.name}"\r\n'.encode()
    )
    lines.append(f"Content-Type: {mime}\r\n\r\n".encode())
    lines.append(file_path.read_bytes())
    lines.append(f"\r\n--{boundary}--\r\n".encode())
    body = b"".join(lines)
    return body, f"multipart/form-data; boundary={boundary}"


def export_defectdojo(cfg: dict, control: str, report: Path, dry_run: bool) -> tuple[bool, str]:
    dd = cfg.get("defectdojo") or {}
    ctrl = (cfg.get("controls") or {}).get(control)
    if not ctrl:
        return False, f"unknown control: {control}"

    url_base = os.environ.get("DEFECTDOJO_URL", "").rstrip("/")
    token = os.environ.get("DEFECTDOJO_API_TOKEN", "")
    if not url_base:
        return True, "skip — DEFECTDOJO_URL not set"
    if not token and not dry_run:
        return True, "skip — DEFECTDOJO_API_TOKEN not set"

    endpoint = "reimport-scan" if dd.get("reimport", True) else "import-scan"
    api_url = f"{url_base}/api/v2/{endpoint}/"

    fields = {
        "scan_type": ctrl.get("scan_type", "SARIF"),
        "test_title": ctrl.get("test_title", control),
        "product_name": expand_env(str(dd.get("product_name", "")))
        or os.environ.get("DEFECTDOJO_PRODUCT_NAME")
        or os.environ.get("CI_PROJECT_NAME")
        or "app",
        "product_type_name": expand_env(str(dd.get("product_type_name", "${DEFECTDOJO_PRODUCT_TYPE:-Research}"))),
        "engagement_name": expand_env(str(dd.get("engagement_name", "CI/CD"))),
        "commit_hash": expand_env(str(dd.get("commit_hash", ""))),
        "branch_tag": expand_env(str(dd.get("branch_tag", ""))),
        "build_id": expand_env(str(dd.get("build_id", ""))),
        "minimum_severity": str(dd.get("minimum_severity", "Info")),
        "auto_create_context": "true" if dd.get("auto_create_context", True) else "false",
        "close_old_findings": "true" if dd.get("close_old_findings", False) else "false",
        "active": "true",
        "verified": "false",
    }

    if dry_run:
        return True, f"dry-run POST {api_url} control={control} scan_type={fields['scan_type']}"

    body, content_type = build_multipart(fields, "file", report)
    req = Request(
        api_url,
        data=body,
        method="POST",
        headers={
            "Authorization": f"Token {token}",
            "Content-Type": content_type,
        },
    )
    ctx = ssl_context_for_dojo()
    try:
        with urlopen(req, timeout=120, context=ctx) as resp:
            payload = resp.read().decode("utf-8", errors="replace")
            return True, f"uploaded ({resp.status}): {payload[:200]}"
    except HTTPError as e:
        detail = e.read().decode("utf-8", errors="replace")[:500]
        return False, f"HTTP {e.code}: {detail}"
    except URLError as e:
        return False, f"network error: {e.reason}"


def main() -> None:
    p = argparse.ArgumentParser(description="Export findings to ASPM/ASOC")
    p.add_argument("--control", required=True)
    p.add_argument("--report", required=True, type=Path)
    p.add_argument("--config", default="config/aspm-export.yaml", type=Path)
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--skip-empty", action="store_true", help="Skip upload when report has no findings")
    args = p.parse_args()

    if not args.config.exists():
        print(f"Config not found: {args.config}", file=sys.stderr)
        sys.exit(2)

    cfg = load_config(args.config)
    backend = cfg.get("backend", "defectdojo")

    if not is_enabled(cfg):
        print(f"[aspm] skip — {cfg.get('defaults', {}).get('enabled_env', 'DEFECTDOJO_URL')} not set")
        sys.exit(0)

    if not args.report.exists():
        print(f"[aspm] skip — report missing: {args.report}")
        sys.exit(0)

    if args.skip_empty and not report_has_findings(args.report):
        print(f"[aspm] skip — empty report: {args.report}")
        sys.exit(0)

    if backend == "noop":
        print(f"[aspm] noop backend — would export {args.control} from {args.report}")
        sys.exit(0)

    if backend == "defectdojo":
        report = args.report
        ctrl = (cfg.get("controls") or {}).get(args.control) or {}
        scan_type = str(ctrl.get("scan_type", "SARIF"))
        is_sarif = report.suffix.lower() == ".sarif"
        # Validate + sanitize SARIF locally before POST.
        # DefectDojo 500 on null ruleId (ruff) — fix here, do not soft-fail the job.
        if (scan_type == "SARIF" or is_sarif) and scan_type != "Generic Findings Import":
            try:
                data = json.loads(report.read_text(encoding="utf-8"))
            except Exception as e:
                print(f"[aspm] ERROR: report is not valid JSON ({report}): {e}", file=sys.stderr)
                sys.exit(1)
            if not isinstance(data, dict) or "runs" not in data:
                print(f"[aspm] ERROR: SARIF missing 'runs' key: {report}", file=sys.stderr)
                sys.exit(1)
            report = sanitize_sarif_for_dojo(report)
        # OSA/SCA: Generic Import so KEV/EPSS land on Finding (SARIF props are ignored).
        if is_sarif and (
            scan_type == "Generic Findings Import" or args.control in ("osa", "sca")
        ):
            try:
                data = json.loads(report.read_text(encoding="utf-8"))
            except Exception as e:
                print(f"[aspm] ERROR: report is not valid JSON ({report}): {e}", file=sys.stderr)
                sys.exit(1)
            if not isinstance(data, dict) or "runs" not in data:
                print(f"[aspm] ERROR: SARIF missing 'runs' key: {report}", file=sys.stderr)
                sys.exit(1)
            report = sanitize_sarif_for_dojo(report)
            report = sarif_to_generic(report)
            print(f"[aspm] converted enriched SARIF → {report}")
        if args.control == "infra" and report.name.endswith("summary_infra.json"):
            report = infra_summary_to_generic(report)
            print(f"[aspm] converted infra summary → {report}")
        if args.control in ("fuzzing", "binary_fuzz") and report.suffix.lower() == ".xml":
            report = junit_to_generic(report)
            print(f"[aspm] converted junit → {report}")
        ok, msg = export_defectdojo(cfg, args.control, report, args.dry_run)
    else:
        print(f"[aspm] unknown backend: {backend}", file=sys.stderr)
        sys.exit(2)

    print(f"[aspm:{args.control}] {msg}")
    fail_on_error = os.environ.get("DEFECTDOJO_FAIL_ON_ERROR", "false").lower() == "true"
    if not ok and fail_on_error:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
