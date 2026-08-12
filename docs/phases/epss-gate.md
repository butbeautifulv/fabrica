# EPSS gate (OSA/SCA annotate)

## Goal

Warn (do not fail) when Trivy SARIF results have `properties.epss >= warn_epss_threshold` (default 0.5) after offline FIRST EPSS enrich.

## DAF

`T-CODE-SC` prioritization signal — exploitability probability (not confirmed exploitation; prefer KEV for Act).

## Files

- `scripts/epss-enrich-sarif.py`
- `scripts/gate-check.py` (`evaluate_epss`, `warn_epss_threshold`, `block_on_high_epss`)
- `config/security-gate-policy.yaml` / `security-gate-policy-adopt.yaml` — `osa/sca.warn_epss_threshold: 0.5`, `block_on_high_epss: false`
- GitLab `trivy-osa.yml` / `trivy-sca.yml`; GitHub OSA/SCA workflows

## Gate mode

| Knob | Strict | Adopt |
|------|--------|-------|
| `warn_epss_threshold` | 0.5 | 0.5 |
| `block_on_high_epss` | **false** (WARN only) | **false** |

Do **not** flip `block_on_high_epss` without an explicit product decision (FIRST: EPSS ≠ org risk). Prefer KEV block if needed.

## Deferred (E8)

- Full (non-sparse) catalog or Nexus-hosted daily artifact
- Adjust `sparseMin` after size/noise review
- Optional merge `kev-enrich` + `epss-enrich` → `vuln-enrich-sarif.py`

## Verification

```bash
make test-epss
bash scripts/validate-mirror-corp.sh
```
