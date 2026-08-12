"""Offline FIRST EPSS catalog: load, lookup, refresh (sparse JSON.gz).

CI must not fetch FIRST — operators run ``refresh`` on a networked host and commit
``config/epss/epss_scores.min.json.gz`` + ``epss_meta.json``.
"""
from __future__ import annotations

import argparse
import csv
import gzip
import io
import json
import sys
import urllib.request
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any

EPSS_CSV_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
DEFAULT_SPARSE_MIN = 0.1
STALE_DAYS = 14

_FABRICA_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CATALOG = _FABRICA_ROOT / "config" / "epss" / "epss_scores.min.json.gz"
DEFAULT_META = _FABRICA_ROOT / "config" / "epss" / "epss_meta.json"

try:
    from lib.kev_catalog import extract_cves, normalize_cve  # type: ignore
except ImportError:  # pragma: no cover — script path variants
    from kev_catalog import extract_cves, normalize_cve  # type: ignore


def _parse_score_date(raw: str) -> str:
    """Normalize score_date to YYYY-MM-DD when possible."""
    s = (raw or "").strip()
    if not s:
        return ""
    if "T" in s:
        s = s.split("T", 1)[0]
    return s[:10]


def _warn_stale(score_date: str, *, stale_days: int = STALE_DAYS) -> None:
    if not score_date:
        return
    try:
        d = date.fromisoformat(score_date[:10])
    except ValueError:
        return
    age = (datetime.now(timezone.utc).date() - d).days
    if age > stale_days:
        print(
            f"[epss] WARN catalog score_date={score_date} is {age}d old "
            f"(>{stale_days}d); run make epss-refresh",
            file=sys.stderr,
        )


def load_epss(path: str | Path | None = None) -> dict[str, dict[str, float]]:
    """Load sparse scores map: CVE → {epss, percentile}."""
    p = Path(path) if path else DEFAULT_CATALOG
    if not p.is_file():
        raise FileNotFoundError(f"EPSS catalog not found: {p}")
    raw = p.read_bytes()
    if p.suffix == ".gz" or raw[:2] == b"\x1f\x8b":
        text = gzip.decompress(raw).decode("utf-8")
    else:
        text = raw.decode("utf-8")
    data = json.loads(text)
    scores_raw = data.get("scores") or {}
    out: dict[str, dict[str, float]] = {}
    for cve, row in scores_raw.items():
        if not isinstance(row, dict):
            continue
        try:
            out[normalize_cve(str(cve))] = {
                "epss": float(row["epss"]),
                "percentile": float(row.get("percentile") or 0.0),
            }
        except (KeyError, TypeError, ValueError):
            continue
    _warn_stale(str(data.get("scoreDate") or ""))
    return out


def load_epss_meta(path: str | Path | None = None) -> dict[str, Any]:
    p = Path(path) if path else DEFAULT_META
    if p.is_file():
        return json.loads(p.read_text(encoding="utf-8"))
    # Fall back to fields inside gzipped catalog
    cat = Path(path).with_name("epss_scores.min.json.gz") if path else DEFAULT_CATALOG
    if not cat.is_file():
        raise FileNotFoundError(f"EPSS meta/catalog not found: {p}")
    raw = gzip.decompress(cat.read_bytes()).decode("utf-8")
    data = json.loads(raw)
    return {
        "source": data.get("source") or EPSS_CSV_URL,
        "model": data.get("model") or "",
        "scoreDate": data.get("scoreDate") or "",
        "sparseMin": float(data.get("sparseMin") or DEFAULT_SPARSE_MIN),
        "count": int(data.get("count") or len(data.get("scores") or {})),
    }


def lookup(cve: str, catalog: dict[str, dict[str, float]] | None = None) -> dict[str, float] | None:
    cat = catalog if catalog is not None else load_epss()
    return cat.get(normalize_cve(cve))


def parse_epss_csv(
    text: str,
    *,
    sparse_min: float = DEFAULT_SPARSE_MIN,
) -> tuple[dict[str, Any], dict[str, dict[str, float]]]:
    """Parse FIRST CSV text (optional #model_version header) → meta + sparse scores."""
    lines = text.splitlines()
    model = ""
    score_date = ""
    body_start = 0
    if lines and lines[0].startswith("#"):
        header = lines[0].lstrip("#").strip()
        body_start = 1
        for part in header.split(","):
            part = part.strip()
            if part.startswith("model_version:"):
                model = part.split(":", 1)[1].strip()
            elif part.startswith("score_date:"):
                score_date = _parse_score_date(part.split(":", 1)[1].strip())
    reader = csv.DictReader(io.StringIO("\n".join(lines[body_start:])))
    scores: dict[str, dict[str, float]] = {}
    for row in reader:
        cve = normalize_cve(str(row.get("cve") or ""))
        if not cve.startswith("CVE-"):
            continue
        try:
            epss = float(row["epss"])
            pct = float(row.get("percentile") or 0.0)
        except (KeyError, TypeError, ValueError):
            continue
        if epss < sparse_min:
            continue
        scores[cve] = {"epss": epss, "percentile": pct}
    meta = {
        "source": EPSS_CSV_URL,
        "model": model,
        "scoreDate": score_date,
        "sparseMin": sparse_min,
        "count": len(scores),
    }
    return meta, scores


def write_catalog(
    meta: dict[str, Any],
    scores: dict[str, dict[str, float]],
    *,
    out_gz: Path,
    out_meta: Path,
) -> None:
    out_gz.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "source": meta.get("source") or EPSS_CSV_URL,
        "model": meta.get("model") or "",
        "scoreDate": meta.get("scoreDate") or "",
        "sparseMin": float(meta.get("sparseMin") or DEFAULT_SPARSE_MIN),
        "count": len(scores),
        "scores": {k: scores[k] for k in sorted(scores)},
    }
    blob = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    out_gz.write_bytes(gzip.compress(blob, compresslevel=9))
    meta_out = {
        "source": payload["source"],
        "model": payload["model"],
        "scoreDate": payload["scoreDate"],
        "sparseMin": payload["sparseMin"],
        "count": payload["count"],
    }
    out_meta.write_text(json.dumps(meta_out, indent=2) + "\n", encoding="utf-8")


def refresh(
    *,
    out: str | Path | None = None,
    meta_out: str | Path | None = None,
    url: str = EPSS_CSV_URL,
    sparse_min: float = DEFAULT_SPARSE_MIN,
    csv_path: str | Path | None = None,
) -> tuple[Path, Path]:
    """Fetch daily CSV.gz (or read local CSV) → sparse catalog. Needs network unless csv_path set."""
    dest = Path(out) if out else DEFAULT_CATALOG
    dest_meta = Path(meta_out) if meta_out else DEFAULT_META
    if csv_path:
        raw = Path(csv_path).read_bytes()
        if str(csv_path).endswith(".gz") or raw[:2] == b"\x1f\x8b":
            text = gzip.decompress(raw).decode("utf-8")
        else:
            text = raw.decode("utf-8")
    else:
        req = urllib.request.Request(url, headers={"User-Agent": "fabrica-epss-refresh/1.0"})
        with urllib.request.urlopen(req, timeout=180) as resp:  # noqa: S310 — operator tool
            raw = resp.read()
        text = gzip.decompress(raw).decode("utf-8")
    meta, scores = parse_epss_csv(text, sparse_min=sparse_min)
    write_catalog(meta, scores, out_gz=dest, out_meta=dest_meta)
    return dest, dest_meta


def _cmd_lookup(args: argparse.Namespace) -> int:
    try:
        catalog = load_epss(args.catalog)
    except FileNotFoundError as e:
        print(f"[epss] {e}", file=sys.stderr)
        return 2
    hit = lookup(args.cve, catalog)
    if hit is None:
        print("null")
        return 1
    print(f"{hit['epss']:.5f},{hit['percentile']:.5f}")
    return 0


def _cmd_refresh(args: argparse.Namespace) -> int:
    path, meta_path = refresh(
        out=args.out,
        meta_out=args.meta,
        url=args.url,
        sparse_min=args.sparse_min,
        csv_path=args.from_csv,
    )
    meta = load_epss_meta(meta_path)
    size = path.stat().st_size
    print(
        f"[epss] wrote {path} ({size} bytes) meta={meta_path} "
        f"count={meta['count']} model={meta.get('model')} "
        f"scoreDate={meta.get('scoreDate')} sparseMin={meta.get('sparseMin')}"
    )
    if size > 5 * 1024 * 1024:
        print(
            "[epss] WARN gzip >5MB — consider raising --sparse-min to 0.5",
            file=sys.stderr,
        )
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Offline FIRST EPSS catalog tools")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_lookup = sub.add_parser("lookup", help="Print epss,percentile or null")
    p_lookup.add_argument("cve")
    p_lookup.add_argument("--catalog", default=str(DEFAULT_CATALOG))
    p_lookup.set_defaults(func=_cmd_lookup)

    p_refresh = sub.add_parser("refresh", help="Fetch CSV → sparse JSON.gz (needs network)")
    p_refresh.add_argument("--out", default=str(DEFAULT_CATALOG))
    p_refresh.add_argument("--meta", default=str(DEFAULT_META))
    p_refresh.add_argument("--url", default=EPSS_CSV_URL)
    p_refresh.add_argument("--sparse-min", type=float, default=DEFAULT_SPARSE_MIN)
    p_refresh.add_argument(
        "--from-csv",
        default=None,
        help="Local CSV or CSV.gz instead of downloading",
    )
    p_refresh.set_defaults(func=_cmd_refresh)

    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
