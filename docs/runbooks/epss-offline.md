# Offline FIRST EPSS (Fabrica)

[EPSS](https://www.first.org/epss/data) scores are a daily exploitability probability (0..1) plus percentile. Fabrica vendors a **sparse** offline snapshot for corp/airgap CI — jobs never call the FIRST API.

## vs CISA KEV

| Signal | Meaning | Fabrica use |
|--------|---------|-------------|
| KEV | Confirmed exploitation | SSVC → Act ([cisa-kev.md](cisa-kev.md)) |
| EPSS | P(exploit ≈ 30d) | SSVC bump if ≥ 0.5 |

## Feed (operators only)

Bulk CSV (preferred):

```text
https://epss.empiricalsecurity.com/epss_scores-current.csv.gz
```

API (`https://api.first.org/data/v1/epss?cve=…`) is lookup-only — **do not** use it to sync the catalog in CI.

## Sparse rule

Only CVEs with `epss >= 0.1` are stored (`config/epss/epss_scores.min.json.gz`). Scores below 0.1 are irrelevant for the SSVC threshold (0.5). Sidecar: `config/epss/epss_meta.json`.

## Refresh (needs network)

```bash
cd projects/fabrica
make epss-refresh
# review size; if gzip > ~5MB, raise sparse min:
# python3 scripts/lib/epss_catalog.py refresh --sparse-min 0.5
make epss-lookup CVE=CVE-2021-44228
make test-epss
```

Airgap: refresh on a networked host, copy `config/epss/` into the repo or mirror pack.

## Files

| Path | Role |
|------|------|
| `config/epss/epss_scores.min.json.gz` | Sparse CVE → epss/percentile (~155 KB gzip @ sparseMin=0.1, ~17k CVEs, 2026-08-12) |
| `config/epss/epss_meta.json` | model / scoreDate / count (no gunzip) |
| `scripts/lib/epss_catalog.py` | load / lookup / refresh |
| `scripts/epss-enrich-sarif.py` | Attach `properties.epss` / `epssPercentile`; sidecar `epss-hits.json` |

Loader warns on stderr if `scoreDate` is older than 14 days (no CI fail).

## ASPM fill-in

`dojo-render-aspm-report.py` uses Dojo `epss_score` when present; otherwise offline catalog (`--epss-catalog`). Override with `--epss-prefer catalog`. Provenance: `epss_source` = `dojo` \| `catalog` \| `none`.

## CI enrich order

Scan → (optional KEV enrich) → `epss-enrich-sarif.py` → `gate-check.py`.

| Platform | Jobs |
|----------|------|
| GitLab | `templates/gitlab/jobs/oss/trivy-osa.yml`, `trivy-sca.yml` |
| GitHub | `templates/github/workflows/jobs/oss/trivy-osa.yml`, `workflows/oss/sca-image.yml` |

Gate prints WARN when `properties.epss >= 0.5`; `block_on_high_epss` stays **false** (see [epss-gate.md](../phases/epss-gate.md)).
