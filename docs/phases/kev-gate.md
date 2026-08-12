# KEV gate (OSA/SCA annotate)

## Goal

Warn (do not fail) when Trivy SARIF results are tagged `properties.cisaKev=true` after offline CISA KEV enrich.

## DAF

`T-CODE-SC` prioritization signal — binary exploited-in-the-wild.

## Files

- `scripts/kev-enrich-sarif.py`
- `scripts/gate-check.py` (`evaluate_kev`, `block_on_kev`)
- `config/security-gate-policy.yaml` / `security-gate-policy-adopt.yaml` — `osa/sca.block_on_kev: false`
- GitLab `trivy-osa.yml` / `trivy-sca.yml`; GitHub OSA/SCA workflows

## Gate mode

| Knob | Strict | Adopt |
|------|--------|-------|
| `block_on_kev` | **false** (WARN only) | **false** |

Flip to `true` on strict only after burn-in (separate micro-PR; see gate-thresholds warn→block queue).

## Verification

```bash
python3 -m unittest tests.test_kev_enrich_sarif tests.test_gate_kev -v
bash scripts/validate-mirror-corp.sh
```
