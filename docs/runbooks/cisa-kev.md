# Offline CISA KEV catalog (Fabrica)

[CISA Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) is a curated list of CVEs with **confirmed** exploitation in the wild. Fabrica vendors a minified offline copy for corp/airgap CI — scanners never call CISA at job runtime.

## Files

| Path | Role |
|------|------|
| `config/kev/cisa-kev.min.json` | CVE ID set + catalog metadata |
| `scripts/lib/kev_catalog.py` | load / lookup / extract / refresh |

Feed (operators only):  
`https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`

## Refresh (needs network)

```bash
cd projects/fabrica
make kev-refresh
# review diff, then commit config/kev/cisa-kev.min.json
make kev-lookup CVE=CVE-2021-44228   # prints true / exit 0
make test-kev
```

CI **must not** run `kev-refresh`. Airgap: refresh on a networked host, copy the min JSON into the repo or mirror pack.

## Lookup / extract

```bash
python3 scripts/lib/kev_catalog.py lookup CVE-2021-44228
python3 scripts/lib/kev_catalog.py extract "Trivy hit CVE-2021-44228 in log4j"
```

## Prioritization (with ASPM SSVC)

1. **KEV** → treat as highest urgency (SSVC Act once wired)
2. **EPSS ≥ 0.5** → bump (existing / offline EPSS plan)
3. **Severity / CVSS** → base ladder

KEV is a binary *exploited* signal, not a score. It does not replace environmental risk.

## Staleness

Re-refresh periodically (e.g. weekly). There is lag between real-world exploitation and CISA listing; absence from KEV does not mean “safe”.

## SARIF enrich (CI)

```bash
python3 scripts/kev-enrich-sarif.py \
  --in osa.sarif \
  --catalog config/kev/cisa-kev.min.json \
  --hits kev-hits.json
```

Sets `properties.cisaKev=true` on matching Trivy results. Always exits 0 (enrich-only). Gate block is a separate policy flag (`block_on_kev`).

## GitHub

Job-level enrich before `gate-and-export` (action stays thin):

- `templates/github/workflows/jobs/oss/trivy-osa.yml`
- `templates/github/workflows/oss/sca-image.yml`

Order: Trivy scan → `kev-enrich-sarif.py` → gate-and-export.
