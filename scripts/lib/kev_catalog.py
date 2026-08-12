"""Offline CISA KEV catalog: load, lookup, CVE extract, refresh.

CI must not fetch CISA — operators run ``refresh`` on a networked host and commit
``config/kev/cisa-kev.min.json``.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.request
from pathlib import Path
from typing import Any, Iterable

CISA_KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)

_FABRICA_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CATALOG = _FABRICA_ROOT / "config" / "kev" / "cisa-kev.min.json"


def normalize_cve(cve: str) -> str:
    return cve.strip().upper()


def extract_cves(*texts: str | None) -> list[str]:
    """Return unique CVE IDs (upper-case) in first-seen order."""
    seen: set[str] = set()
    out: list[str] = []
    for text in texts:
        if not text:
            continue
        for m in CVE_RE.finditer(str(text)):
            cve = normalize_cve(m.group(0))
            if cve not in seen:
                seen.add(cve)
                out.append(cve)
    return out


def load_kev(path: str | Path | None = None) -> frozenset[str]:
    """Load CVE ID set from min catalog JSON."""
    p = Path(path) if path else DEFAULT_CATALOG
    if not p.is_file():
        raise FileNotFoundError(f"KEV catalog not found: {p}")
    data = json.loads(p.read_text(encoding="utf-8"))
    raw = data.get("cveIDs") or data.get("cve_ids") or []
    if not isinstance(raw, list):
        raise ValueError(f"KEV catalog missing cveIDs list: {p}")
    return frozenset(normalize_cve(str(x)) for x in raw if x)


def load_kev_meta(path: str | Path | None = None) -> dict[str, Any]:
    p = Path(path) if path else DEFAULT_CATALOG
    data = json.loads(p.read_text(encoding="utf-8"))
    return {
        "source": data.get("source") or CISA_KEV_URL,
        "catalogVersion": data.get("catalogVersion") or "",
        "dateReleased": data.get("dateReleased") or "",
        "count": int(data.get("count") or len(data.get("cveIDs") or [])),
    }


def in_kev(cve: str, catalog: Iterable[str]) -> bool:
    return normalize_cve(cve) in catalog


def any_in_kev(cves: Iterable[str], catalog: Iterable[str]) -> bool:
    cat = catalog if isinstance(catalog, (set, frozenset)) else frozenset(catalog)
    return any(in_kev(c, cat) for c in cves)


def min_catalog_from_cisa(doc: dict[str, Any]) -> dict[str, Any]:
    vulns = doc.get("vulnerabilities") or []
    ids = sorted(
        {
            normalize_cve(str(v.get("cveID") or v.get("cveId") or ""))
            for v in vulns
            if isinstance(v, dict) and (v.get("cveID") or v.get("cveId"))
        }
    )
    return {
        "source": CISA_KEV_URL,
        "catalogVersion": str(doc.get("catalogVersion") or ""),
        "dateReleased": str(doc.get("dateReleased") or ""),
        "count": len(ids),
        "cveIDs": ids,
    }


def refresh(out: str | Path | None = None, url: str = CISA_KEV_URL) -> Path:
    """Fetch full CISA KEV JSON and write min catalog. Requires network."""
    dest = Path(out) if out else DEFAULT_CATALOG
    dest.parent.mkdir(parents=True, exist_ok=True)
    req = urllib.request.Request(url, headers={"User-Agent": "fabrica-kev-refresh/1.0"})
    with urllib.request.urlopen(req, timeout=120) as resp:  # noqa: S310 — operator tool
        raw = resp.read()
    doc = json.loads(raw.decode("utf-8"))
    if not isinstance(doc, dict):
        raise ValueError("CISA KEV feed is not a JSON object")
    payload = min_catalog_from_cisa(doc)
    dest.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return dest


def _cmd_lookup(args: argparse.Namespace) -> int:
    try:
        catalog = load_kev(args.catalog)
    except FileNotFoundError as e:
        print(f"[kev] {e}", file=sys.stderr)
        return 2
    cve = normalize_cve(args.cve)
    hit = in_kev(cve, catalog)
    print("true" if hit else "false")
    return 0 if hit else 1


def _cmd_refresh(args: argparse.Namespace) -> int:
    path = refresh(out=args.out, url=args.url)
    meta = load_kev_meta(path)
    print(
        f"[kev] wrote {path} count={meta['count']} "
        f"version={meta['catalogVersion']} date={meta['dateReleased']}"
    )
    return 0


def _cmd_extract(args: argparse.Namespace) -> int:
    cves = extract_cves(*args.text)
    print("\n".join(cves))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Offline CISA KEV catalog tools")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_lookup = sub.add_parser("lookup", help="Exit 0 if CVE is in catalog")
    p_lookup.add_argument("cve")
    p_lookup.add_argument(
        "--catalog",
        default=str(DEFAULT_CATALOG),
        help="Path to cisa-kev.min.json",
    )
    p_lookup.set_defaults(func=_cmd_lookup)

    p_refresh = sub.add_parser("refresh", help="Fetch CISA feed → min JSON (needs network)")
    p_refresh.add_argument("--out", default=str(DEFAULT_CATALOG))
    p_refresh.add_argument("--url", default=CISA_KEV_URL)
    p_refresh.set_defaults(func=_cmd_refresh)

    p_ex = sub.add_parser("extract", help="Extract CVE IDs from text")
    p_ex.add_argument("text", nargs="+")
    p_ex.set_defaults(func=_cmd_extract)

    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
