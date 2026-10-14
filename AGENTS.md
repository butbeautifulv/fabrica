# Agents — Fabrica (DevSecOps CI/CD reference)

## Execution plan

Track progress in [`.cursor/plans/devsecops-execution.plan.md`](.cursor/plans/devsecops-execution.plan.md).

Scaffold (P0–F3 docs + templates) is done. v1.1: references migrated to `docs/references/`. **v1.3:** Cursor dev skills via cxado `make skills-link` → `shared/skills/` (`.agents/skills/` is generated; do not commit).

## Rules

1. **One todo = one PR**, **≤5 files** changed
2. Mirror **GitLab** and **GitHub** job contracts (SARIF, exit codes)
3. **warn → block** in a separate micro-PR
4. WAF/RASP (F2) — runbooks only, not CI jobs
5. Reference material lives in `docs/references/` — vendor xlsx/pdf not in git

## Phase order

CF → G0 → V0 → H-CORE → H-PRE → H-P0…H-F3 → **I1–I5 (infra SaC)** → AI* (optional) → R → MIG (references/skills)

## Skills (canonical: [cxado-skills](https://github.com/butbeautifulv/cxado-skills))

| Skill | cxado-skills path |
|-------|-------------------|
| devsecops-template | `devsecops/devsecops-template/` |
| devsecops-phase-impl | `devsecops/devsecops-phase-impl/` |
| devsecops-reference-lookup | `devsecops/devsecops-reference-lookup/` |
| devsecops-secure-sdlc | `devsecops/devsecops-secure-sdlc/` |
| devsecops-daf | `devsecops/devsecops-daf/` |
| devsecops-gost | `devsecops/devsecops-gost/` |
| devsecops-jcsf | `devsecops/devsecops-jcsf/` |
| devsecops-fintech-sdlc | `devsecops/devsecops-fintech-sdlc/` |
| devsecops-tooling | `devsecops/devsecops-tooling/` |
| devsecops-governance | `devsecops/devsecops-governance/` |
| devsecops-mlsecops | `devsecops/devsecops-mlsecops/` |
| devsecops-ai-security | `devsecops/devsecops-ai-security/` |

Cursor discovery: from [cxado](https://github.com/butbeautifulv/cxado) run `make bootstrap` (or `make skills-link`) for project-local `.agents/skills/` symlinks, or `make skills-install` for `~/.cursor/skills/`.

## Workspace skills → Fabrica runbooks

Actionable guidance from cxado-linked `.agents/skills/` is duplicated in-repo (do not commit skill symlinks):

| Workspace skill | Fabrica runbook / phase |
|-----------------|-------------------------|
| docker-expert | [docs/runbooks/docker-production-baseline.md](docs/runbooks/docker-production-baseline.md), B5 |
| kubernetes-specialist | [docs/runbooks/k8s-workload-baseline.md](docs/runbooks/k8s-workload-baseline.md), E1 |
| terraform-test | [docs/references/supplements/terraform-test-ci.md](docs/references/supplements/terraform-test-ci.md), B4 |
| terraform-style-guide | `examples/sample-app/infra/secure/`, B4 |
| grafana-dashboards | [docs/runbooks/ci-pipeline-observability.md](docs/runbooks/ci-pipeline-observability.md), E4 |

Validate: `make validate`, `make validate-helm`. Infra SaC smoke: `bash scripts/validate-infra-smoke.sh`. Corp mirror: `bash scripts/validate-mirror-corp.sh`.

## Gate invocation canon

- Security gates / OSCAP: run as executables — `python3 scripts/gate-check.py`, `bash scripts/oscap-*.sh`.
- Do **not** `source` / `.` gate scripts (exit-code and state pollution).
- `source` is OK only for env helpers (e.g. `registry-auth-env.sh`).
- Soft-fail rules: [docs/runbooks/ci-soft-fail-contract.md](docs/runbooks/ci-soft-fail-contract.md). Thresholds: [docs/runbooks/gate-thresholds.md](docs/runbooks/gate-thresholds.md).

## Key paths

- Policy: `config/security-gate-policy.yaml` (corp adopt: `config/security-gate-policy-adopt.yaml`)
- Gate script: `scripts/gate-check.py`
- Infra SCAP: `scripts/summarize_infra.py`, `scripts/oscap-*-scan.sh`, control `infra:`
- Adopt: `scripts/adopt.sh --profile shift-left|ai-ml|oss-full|oss-full-node|oss-full-node-k3s --platform gitlab|github --target /path [--policy adopt|strict] [--python-stack auto|uv|pip|node]`
- **Corp mirror:** profile `templates/profiles/oss-full-service-mirror.gitlab-ci.yml`; sync via `scripts/point-copy-mirror.sh` (not `adopt.sh` into existing `.gitlab/jobs`); verify `bash scripts/validate-mirror-corp.sh`
- **Node + k3s:** profile `oss-full-node-k3s` — Bun validate, controls `osa-sca` (composition) + `container` (image), inline KEV/EPSS/ASPM, Kaniko, kustomize deploy; policy `config/security-gate-policy-node-k3s-adopt.yaml`
- Corp DAST: `scripts/run-dast-zap-api-mirror.sh` (`zap-api-scan` + live OpenAPI) — not generic `dast.yml` baseline
- Ephemeral `ci-http-stub` / mongo in deploy-test = **lifespan fixtures**, not scanner fake-green stubs
- Profiles: `templates/profiles/`
- References: `docs/references/` (DAF, extracts, Secure SDLC)
- AI/ML: `examples/sample-ml-app/`, profile `ai-ml`
- Example app: `examples/sample-app/`
- Infra fixtures: `examples/sample-infra-scap/`

## Cursor rules

- `.cursor/rules/phase-impl.mdc` — always apply
- `.cursor/rules/templates-ci.mdc` — when editing `templates/**`

**Note:** Rule «≤5 files / one PR» is relaxed only for land-snapshot merges of a proven corp-mirror stack; day-to-day phases stay micro.
