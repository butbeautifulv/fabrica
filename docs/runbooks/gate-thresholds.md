# Gate thresholds (Security as Code)

Single source of truth: [`config/security-gate-policy.yaml`](../config/security-gate-policy.yaml) (+ adopt twin).

| Control | Mode (strict) | Threshold knobs | Notes |
|---------|---------------|-----------------|-------|
| secrets | block (S1.2) | `max_findings` (0 = severity-only) | adopt stays warn |
| sast / osa / sca / iac | block | `severity_block` | count not duplicated |
| dockerfile | block (S1.3) | paths | — |
| linters | warn | `max_findings` (default 50) | when `ENABLE_REAL_LINTERS` |
| infra | warn → block (S1.4) | `summarize_threshold`, `failed_threshold`, `xccdf_failed_threshold` | count-based OVAL/XCCDF |
| dast / fuzzing | warn | `block_release_debt` | no count in this wave |
| osa / sca + KEV | warn annotate (K7) | `block_on_kev` (default false) | Offline CISA KEV on SARIF `properties.cisaKev`; **CI block deferred** (K8). Trivy still filters `--severity CRITICAL,HIGH` so Medium-in-KEV is invisible in SARIF until severity floor widens. ASPM report maps KEV via CVE → Act. See [cisa-kev.md](cisa-kev.md). |
| osa / sca + EPSS | warn annotate (E7) | `warn_epss_threshold` (0.5), `block_on_high_epss` (false) | Offline FIRST EPSS on SARIF `properties.epss`. **Never fail CI on EPSS alone** (FIRST: EPSS ≠ risk). See [epss-offline.md](epss-offline.md). |

Evaluator: [`scripts/gate-check.py`](../scripts/gate-check.py). Soft-fail contract: [ci-soft-fail-contract.md](ci-soft-fail-contract.md).

## Mirror warn → block queue (no flip yet)

After ≥3 green multi-service pilots (`hwa_service`, `data_lake_service`, `user_service`), tighten **one control per PR**:

1. `secrets` (gitleaks) — drop mirror `allow_failure`, adopt → strict for that control  
2. `dockerfile` (hadolint)  
3. Then `sast` / `osa` / `iac` / `sca` as noise allows  
4. **Later:** `osa`/`sca` `block_on_kev: true` on **strict** only (not adopt) after KEV enrich burn-in  

Do **not** set `block_on_high_epss: true` in this program (prefer KEV for hard block). See [epss-gate.md](../phases/epss-gate.md).

Do **not** edit `security-gate-policy-adopt.yaml` to block in this enrichment wave — document only. Full roadmap: [mirror-security-pipeline-action-log.md](mirror-security-pipeline-action-log.md).
