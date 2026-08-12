#!/usr/bin/env python3
"""Enrich Trivy SARIF with offline FIRST EPSS scores (exit 0 always)."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from lib.epss_catalog import DEFAULT_CATALOG, load_epss, lookup  # noqa: E402
from lib.kev_catalog import extract_cves  # noqa: E402


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


def enrich_sarif(
    doc: dict[str, Any],
    catalog: dict[str, dict[str, float]],
    *,
    high_threshold: float = 0.5,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    hits: list[dict[str, Any]] = []
    for run in doc.get("runs") or []:
        for result in run.get("results") or []:
            if not isinstance(result, dict):
                continue
            cves = extract_cves(*_result_texts(result))
            best = None
            best_cve = ""
            for cve in cves:
                hit = lookup(cve, catalog)
                if hit is None:
                    continue
                if best is None or hit["epss"] > best["epss"]:
                    best = hit
                    best_cve = cve
            if best is None:
                continue
            props = result.get("properties")
            if not isinstance(props, dict):
                props = {}
                result["properties"] = props
            props["epss"] = best["epss"]
            props["epssPercentile"] = best["percentile"]
            props["epssCve"] = best_cve
            if best["epss"] >= high_threshold:
                hits.append(
                    {
                        "ruleId": str(result.get("ruleId") or ""),
                        "cve": best_cve,
                        "epss": best["epss"],
                        "percentile": best["percentile"],
                    }
                )
    return doc, hits


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Attach offline EPSS to SARIF results")
    p.add_argument("--in", dest="infile", type=Path, required=True)
    p.add_argument("--out", type=Path, help="Output SARIF (default: overwrite --in)")
    p.add_argument("--catalog", type=Path, default=DEFAULT_CATALOG)
    p.add_argument("--hits", type=Path, default=Path("epss-hits.json"))
    p.add_argument("--high-threshold", type=float, default=0.5)
    args = p.parse_args(argv)

    out = args.out or args.infile
    if not args.infile.is_file():
        print(f"[epss-enrich] WARN missing SARIF {args.infile}", file=sys.stderr)
        args.hits.write_text(json.dumps({"count": 0, "hits": [], "error": "missing_sarif"}) + "\n")
        return 0

    try:
        catalog = load_epss(args.catalog)
    except FileNotFoundError as e:
        print(f"[epss-enrich] WARN {e}; skip enrich", file=sys.stderr)
        args.hits.write_text(json.dumps({"count": 0, "hits": [], "error": "missing_catalog"}) + "\n")
        return 0

    try:
        doc = json.loads(args.infile.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        print(f"[epss-enrich] WARN invalid SARIF JSON: {e}", file=sys.stderr)
        args.hits.write_text(json.dumps({"count": 0, "hits": [], "error": "bad_json"}) + "\n")
        return 0

    if not isinstance(doc, dict):
        args.hits.write_text(json.dumps({"count": 0, "hits": [], "error": "bad_root"}) + "\n")
        return 0

    enriched, hits = enrich_sarif(doc, catalog, high_threshold=args.high_threshold)
    out.write_text(json.dumps(enriched, indent=2) + "\n", encoding="utf-8")
    summary = {
        "count": len(hits),
        "hits": hits,
        "catalog": str(args.catalog),
        "high_threshold": args.high_threshold,
    }
    args.hits.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    print(f"[epss-enrich] wrote {out} epss_high_hits={len(hits)} hits_file={args.hits}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
