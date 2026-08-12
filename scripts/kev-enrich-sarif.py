#!/usr/bin/env python3
"""Enrich Trivy SARIF with offline CISA KEV flags (exit 0 always)."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from lib.kev_catalog import DEFAULT_CATALOG, extract_cves, in_kev, load_kev  # noqa: E402


def _result_texts(result: dict[str, Any]) -> list[str]:
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
        for key in ("cve", "vulnerabilityID", "VulnerabilityID"):
            if props.get(key):
                parts.append(str(props[key]))
    return parts


def enrich_sarif(doc: dict[str, Any], catalog: frozenset[str]) -> tuple[dict[str, Any], list[dict[str, str]]]:
    hits: list[dict[str, str]] = []
    for run in doc.get("runs") or []:
        for result in run.get("results") or []:
            if not isinstance(result, dict):
                continue
            cves = extract_cves(*_result_texts(result))
            matched = [c for c in cves if in_kev(c, catalog)]
            if not matched:
                continue
            props = result.get("properties")
            if not isinstance(props, dict):
                props = {}
                result["properties"] = props
            props["cisaKev"] = True
            props["cisaKevCves"] = matched
            hits.append(
                {
                    "ruleId": str(result.get("ruleId") or ""),
                    "cves": ",".join(matched),
                }
            )
    return doc, hits


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Tag SARIF results present in CISA KEV")
    p.add_argument("--in", dest="infile", type=Path, required=True)
    p.add_argument("--out", type=Path, help="Output SARIF (default: overwrite --in)")
    p.add_argument("--catalog", type=Path, default=DEFAULT_CATALOG)
    p.add_argument("--hits", type=Path, default=Path("kev-hits.json"))
    args = p.parse_args(argv)

    out = args.out or args.infile
    if not args.infile.is_file():
        print(f"[kev-enrich] WARN missing SARIF {args.infile}; writing empty hits", file=sys.stderr)
        args.hits.write_text(json.dumps({"count": 0, "hits": [], "error": "missing_sarif"}) + "\n")
        return 0

    try:
        catalog = load_kev(args.catalog)
    except FileNotFoundError as e:
        print(f"[kev-enrich] WARN {e}; skip enrich", file=sys.stderr)
        args.hits.write_text(json.dumps({"count": 0, "hits": [], "error": "missing_catalog"}) + "\n")
        return 0

    try:
        doc = json.loads(args.infile.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        print(f"[kev-enrich] WARN invalid SARIF JSON: {e}", file=sys.stderr)
        args.hits.write_text(json.dumps({"count": 0, "hits": [], "error": "bad_json"}) + "\n")
        return 0

    if not isinstance(doc, dict):
        print("[kev-enrich] WARN SARIF root not object", file=sys.stderr)
        args.hits.write_text(json.dumps({"count": 0, "hits": [], "error": "bad_root"}) + "\n")
        return 0

    enriched, hits = enrich_sarif(doc, catalog)
    out.write_text(json.dumps(enriched, indent=2) + "\n", encoding="utf-8")
    summary = {"count": len(hits), "hits": hits, "catalog": str(args.catalog)}
    args.hits.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    print(f"[kev-enrich] wrote {out} kev_hits={len(hits)} hits_file={args.hits}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
