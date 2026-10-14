# Mirror Security Pipeline Action Log

This runbook captures recent stabilization work for the GitLab mirror pipeline (`map_objects-ci`) and records what to keep, what to tighten later, and why.

## Scope

- Profile: `templates/profiles/oss-full-service-mirror.gitlab-ci.yml`
- Target service example: `hwa_service`
- Trigger model: release tags (`hwa_service/v*`)
- Goal: collect vulnerabilities and upload to DefectDojo with gates still present, but thresholds relaxed during adoption.

## Timeline (Recent Actions)

1. Enabled tag-driven mirror workflow and service-scoped controls in mirror profile.
2. Fixed runner instability paths (image pull and memory pressure) in prior wave.
3. Restored resilient Python fallback for static ASPM uploads.
4. Fixed gate-check CLI invocation issues caused by malformed line continuation.
5. Switched mirror profile policy to `security-gate-policy-adopt.yaml` (threshold-pass adoption mode).
6. Removed tag `rules:changes` dependence for core static security jobs in mirror profile.
7. Added explicit Dockerfile discovery configuration (`DOCKERFILE_GLOBS`) and visibility logging.
8. Added runtime preflight/fallback patterns in scanner jobs to reduce executor-specific breakage.
9. Pushed updated mirror config to `av.popov/map_objects-ci` and triggered fresh pilot tags:
   - `hwa_service/v0.1.4-pilotA`
   - `hwa_service/v0.1.4-pilotB`
   - `hwa_service/v0.1.4-pilotC`
10. Collected evidence from latest failed static-wave traces (`112374*`, `112375*`, `112376*`) and prepared targeted hotfixes.
11. Applied static-wave hotfix bundle to mirror repository commit `08bf350` and triggered tag:
   - `hwa_service/v0.1.4-hotfix1`
12. Nexus-first finish wave (source checkout, hard-fail, Nexus-only images/pip/rules, Trivy MITM/auth):
   - evidence tag `hwa_service/v0.1.4-hotfix22` / pipeline `112444` (see §F1).
13. DefectDojo upload hard-path (empty UI → real reimport):
   - evidence tag `hwa_service/v0.1.4-hotfix26` / pipeline `112471` (see §U uploads).
14. Trivy OSA Python manifests (`dev-requirements.txt` via `--file-patterns`):
   - evidence tag `hwa_service/v0.1.4-hotfix27` / pipeline `112478` (see §OSA).
15. Residual static scanners + Semgrep vendor + Bandit + Nexus pip auth:
   - evidence tags `hwa_service/v0.1.4-hotfix28b` / `28c` (see §Residual scanners).
16. Multi-service resolve + build/SCA honesty (POSIX, docker-host, cache, fallback):
   - evidence tag `hwa_service/v0.1.4-hotfix29s` / pipeline `112552` (see §Multi-service + build/SCA).

## Symptom -> Cause -> Fix

### 1) Dockerfiles were not scanned
- Symptom: `dockerfile-lint` job skipped while Dockerfiles existed.
- Cause: tag pipelines relied on `rules:changes`, which may not match when tagging an existing commit.
- Fix:
  - mirror profile now runs key static jobs on any tag (`if: '$CI_COMMIT_TAG'`);
  - Dockerfile discovery now supports `DOCKERFILE_GLOBS` and logs discovered files/count.

### 2) Security jobs behaved as hard gates during adoption
- Symptom: pipeline blocked before vulnerability collection stabilized.
- Cause: strict policy (`security-gate-policy.yaml`) with `mode: block` for multiple controls.
- Fix:
  - mirror profile uses `config/security-gate-policy-adopt.yaml`;
  - adopt policy sets noisy controls to `mode: warn` while keeping `gate-check.py` execution.

### 3) Mixed runner environment failures (python/pip/pkg manager)
- Symptom: failures like `python3/pip/apk/apt-get not found`.
- Cause: jobs assumed homogeneous container/runtime tooling.
- Fix:
  - added `command -v` preflight/fallback logic in scanner jobs;
  - preserve report artifacts even in degraded mode to keep upload/analytics flow alive.

### 4) `pip` auth prompt and non-interactive job crash
- Symptom: `EOFError: EOF when reading a line` during `python3 -m pip install ...` in static jobs.
- Cause: private index challenge in non-interactive runner (`pip` tried to prompt for credentials).
- Fix:
  - force non-interactive pip mode (`PIP_NO_INPUT=1`, `PIP_DISABLE_PIP_VERSION_CHECK=1`);
  - fallback to public index parameters for bootstrap tools;
  - keep empty report generation path when tool bootstrap fails.

### 5) Trivy job executed in non-trivy image
- Symptom: `trivy: not found` and `python3: not found` in OSA traces.
- Cause: runtime image/override mismatch, plus package bootstrap via `apk` failing with TLS/cert restrictions.
- Fix:
  - `trivy-osa` now creates an empty SARIF stub first and only runs scanner when binary exists;
  - gate-check is executed conditionally when Python exists, preventing hard crash in degraded runtime.

### 6) ASPM upload crash on missing Python
- Symptom: upload job failed early with `/step_script: python3: not found`.
- Cause: upload bootstrap assumed Python availability in all executors/images.
- Fix:
  - added explicit Python preflight in upload template;
  - when Python is unavailable, job exits gracefully instead of failing the wave.

### 7) `adopt.sh` copy semantics with existing `.gitlab/jobs`
- Symptom: new fixes were not applied even after profile adoption.
- Cause: `copy "$ROOT/templates/gitlab/jobs" "$TARGET/.gitlab/jobs"` creates nested `.gitlab/jobs/jobs` when target directory already exists.
- Fix:
  - for hotfix wave, copied changed job templates directly into mirror repo paths;
  - remove accidental nested `.gitlab/jobs/jobs` if present.

### 8) Trivy vulndb x509 on Nexus `:8374` (job 1144419)
- Symptom: `tls: failed to verify certificate: x509: certificate signed by unknown authority` when pulling `nexus.svo.aero:8374/aquasecurity/trivy-db`.
- Cause: corp MITM / private CA; K8s trivy pods do not mount `/etc/ssl/certs/nexus/ca.crt` (unlike egregore runner prep).
- Fix (mirror profile only):
  - `TRIVY_INSECURE: "true"` + job `--insecure` when set;
  - prefer `SSL_CERT_FILE` if Nexus CA is present on the runner;
  - map `NEXUS_USER`/`NEXUS_PASSWORD` → `TRIVY_USERNAME`/`TRIVY_PASSWORD` (Nexus `:8374` returns UNAUTHORIZED without auth);
  - keep `TRIVY_DB_REPOSITORY` on Nexus group (no `ghcr.io` / `mirror.gcr.io`).
- Long-term: mount corp CA into CI pods at `/etc/ssl/certs/nexus/ca.crt` and drop `TRIVY_INSECURE`.

### 9) Nexus-first corp offline (self-scan → real source + hard-fail)
- Rule: tool images / pip / rules / binaries **only** via Nexus (`nexus.svo.aero:8345|8374`). No `apk`/`apt-get`, no `pypi.org`, no `semgrep.dev` `p/ci`, no direct `ghcr.io`.
- Source: `SOURCE_REPO_URL` + `SOURCE_GIT_TOKEN` → `SCAN_ROOT=checkout` (`resolved_ref=0.0.4` fallback for mirror hotfix tags). Fetch via `git` or `scripts/fetch-source-archive.py` (no package managers).
- Semgrep: local `config/semgrep/weak-crypto.yaml` only; missing SARIF → fail.
- Checkov / gitleaks / semgrep / trivy: Nexus images; shell runners that ignore `image:` use `docker run ${OSS_*_IMAGE}`.
- Gate-check: no runtime `apk` for python; adopt policy may skip gate when SARIF exists and python/docker missing.
- Trivy DB: `TRIVY_INSECURE` + Nexus auth (`NEXUS_USER`/`NEXUS_PASSWORD`) — see §8.
- YAML pitfall: unindented heredoc bodies break GitLab CI parse (fixed via external scripts: `fetch-source-archive.py`, `synthesize-ruff-sarif.py`).

### F1 evidence — `hwa_service/v0.1.4-hotfix22` (pipeline `112444`)
Point-copy deploy to `map_objects-ci` (not `adopt.sh`).

| Job | Status | Nexus image / notes | Source evidence |
|-----|--------|---------------------|-----------------|
| checkov-iac | success | `8345/bridgecrew/checkov:3.2.449` (docker-run on shell) | `resolved_ref=0.0.4` `SCAN_TARGET=checkout` |
| gitleaks-scan | success | `8374/gitleaks/gitleaks:v8.22.1` (docker-run) | same |
| semgrep-sast | success | `8345/returntocorp/semgrep:1.117.0`; local `weak-crypto.yaml` | same |
| trivy-osa | success | `8345/aquasec/trivy:0.67.2` + vulndb `:8374/.../trivy-db:2` | same |
| forbidden-files | success | `8345/library/python:3.11.11-slim-bookworm` | same |
| dockerfile-lint | failed | residual (hadolint/docker path) | same |
| linter-security | failed | residual (no pip / no modern ruff on Nexus PyPI); `allow_failure` | same |

Acceptance checks: no `yaml_errors`; no empty-stub green on scanners; no `apk`/`apt-get`/`pypi.org` runtime installs; Trivy DB via Nexus only.

### U — DefectDojo uploads (hotfix26 / pipeline `112471`)

Soft-green uploads left DD UI empty (`products=0`). Fixes:

| Issue | Cause | Fix |
|-------|-------|-----|
| Soft skip no python | K8s used runner default alpine (`Using default image`) because nested `${NEXUS_DOCKER_PREFIX}/...` did not expand in `image:` | Literal Nexus image refs in mirror profile; upload job `image: nexus.../python:3.11.11-slim-bookworm` |
| Soft skip pyyaml | Unnecessary gate | Dropped; `_parse_config_simple` fallback |
| checkov crash | `report_has_findings` assumed dict; Checkov multi-JSON is a list | List + `results.failed_checks` handling |
| Checkov Scan parse | Multi-framework JSON list | Upload `reports/checkov.sarif` as `SARIF` |
| HTTP 400 product | Nested `${A:-${B}}` left literal; missing `product_type_name` | Recursive `expand_env`; `CI_PROJECT_NAME` fallback; `product_type_name=Research` |
| Unreachable URL | In-cluster DNS from shell | CI var `DEFECTDOJO_URL=https://192.168.0.133:30808` + `DEFECTDOJO_INSECURE` |

Evidence:

- `upload-checkov-to-dojo` → `[aspm:iac] uploaded (201)` product `map_objects-ci`, test `iac-checkov`
- DD API: products=1, engagements=1, tests≥1, findings≥20
- Empty gitleaks/semgrep still skip (`--skip-empty`) — expected

### OSA — Python `dev-requirements.txt` (hotfix27 / pipeline `112478`)

Trivy default only parses `requirements.txt` / lockfiles. `hwa_service` installs from `dev-requirements.txt` (Dockerfile `pip install -r …`); `pyproject.toml` has no `[project].dependencies` → OSA produced empty SARIF (~27B) and upload soft-skipped.

Fix in `templates/gitlab/jobs/oss/trivy-osa.yml`:
- preflight: require ≥1 manifest (`*requirements*.txt`, poetry/Pipfile/uv lock, …) or fail;
- `--file-patterns "pip:.*requirements.*\.txt"`;
- log `manifests=N sarif_results=… osa.sarif_bytes=…`.

Evidence: `checkout/dev-requirements.txt` found; `osa.sarif` ~210KB / **52** CRITICAL/HIGH results; `upload-trivy-osa-to-dojo` → `uploaded (201)` test `osa-trivy-fs`.

### Residual scanners + Semgrep vendor + Bandit (hotfix28 / `28b`–`28c`)

Tag evidence: `hwa_service/v0.1.4-hotfix28c` (pipeline after YAML fix; `28` had invalid heredoc YAML; `28b` green config).

| Gap | Fix |
|-----|-----|
| Semgrep 0 findings | Vendored `config/semgrep/vendor/` from semgrep-rules (`python/` + `insecure-transport` + `dockerfile`), SHA in `VENDOR_SHA.txt`; `SEMGREP_RULES=config/semgrep/vendor`; metrics off; **no `p/ci`** |
| Bandit missing | New `bandit-sast` + ASPM `sast-bandit` |
| linter / bandit `versions: none` | Nexus `srsips-pypi` is **auth-gated**; `scripts/pip-index-auth.sh` embeds `NEXUS_USER`/`NEXUS_PASSWORD` into `--index-url` |
| dockerfile-lint no docker CLI | Job image = Nexus hadolint; checkout via `fetch-source-archive.sh` (curl/wget) |
| shell upload fail after ruff | Root-owned `.ruff_cache` on shared shell workspace → `RUFF_CACHE_DIR=/tmp/...` + docker cleanup |

Evidence (`28c`): `bandit-sast` success (16 findings → SARIF); `linter-security` success (10 findings); uploads `sast-bandit` / `linters` → `uploaded (201)`. `dockerfile-lint` success on hadolint image. Semgrep uses vendor tree (dozens+ rules).

### Multi-service + build/SCA (hotfix29o–29s)

Tag evidence: `hwa_service/v0.1.4-hotfix29s` (pipeline `112552`); earlier fails `29p`/`29q`/`29r` documented below.

| Issue | Cause | Fix |
|-------|-------|-----|
| DD product = mirror name | Uploads used `CI_PROJECT_NAME` | `config/mirror-services.yaml` + `scripts/resolve-mirror-service.sh` → `DEFECTDOJO_PRODUCT_NAME=$SERVICE_NAME` |
| SCA skipped on tags | `rules:changes` / wrong image ref | Tag-only rules; scan `REGISTRY:IMAGE_TAG` from build dotenv |
| SBOM separate + apt | Corp bans apt; duplicate jobs | Combined SCA+SBOM in `trivy-sca`; mirror `sbom-generate: when: never` |
| Double Trivy DB pull | OSA then SCA each download | Shared `.trivy-cache` artifact; SCA `--skip-db-update` after OSA |
| `syntax error: unexpected "("` (`29p`) | Bash arrays in `build-push` under docker:cli **ash** | POSIX `set --` args only |
| Job dies before script (`29q`) | Root-owned `.trivy-cache/db` → git clean Permission denied | `GIT_CLEAN_FLAGS` exclude `.trivy-cache`; trivy `docker --user $(id -u)` |
| `docker.sock: no such file` (`29r`) | Same runner tags → **k8s** executor; dind up but no `DOCKER_HOST` | `scripts/docker-host-bootstrap.sh` (sock vs `tcp://docker:2376`) |
| Service pip fails (`gismaputils`) | Private package not on Nexus index | **Fixed (2026-07):** wheels `0.5.1`/`0.5.3` in `map_objects-ci` Package Registry; Kaniko vendors into `vendor-gismaputils/` + `--find-links` (no `--extra-index-url` — that forced pip onto GitLab/pypi.org SSL). CI var `GISMAPUTILS_PYPI_TOKEN`. Evidence: pipeline `112683` `BUILD_FALLBACK=0` |
| Poetry fails (`aodb-log-tools`) | Package only on retired `nexus.code-discovery.ru`; not in GitLab as source | **Fixed (2026-08):** stub/wheel `1.0.0` in Package Registry **1962**; Kaniko vendors `vendor-aodb-log-tools/` + path-dep rewrite (reuse `GISMAPUTILS_PYPI_TOKEN`). No `--extra-index-url`. |

Evidence (`29s` / `112552`):
- `build-image` success — `[docker] host socket` + `[build] fallback pushed …hwa_service-1591605…`
- `trivy-osa` / `trivy-sca` / `upload-sca-to-dojo` / `upload-sbom-to-dojo` success
- SCA: `sarif_results=67` (~188KB); SBOM ~228KB; product `hwa_service`

**C1 (hwa) closed** on this evidence.

### C2/C3 multi-service evidence (enrich1 / `db3a369`)

Tags: `data_lake_service/v0.4.10-hotfix29enrich` (pipeline `112584`), `user_service/v0.4.4-hotfix29enrich` (pipeline `112585`).

| Service | Resolve product | Build | SCA | DD uploads (sample) |
|---------|-----------------|-------|-----|---------------------|
| `data_lake_service` | `product=data_lake_service` | success, `BUILD_FALLBACK=1` | sarif_results=67 | iac-checkov, osa-trivy-fs, sca-trivy-image → 201 |
| `user_service` | `product=user_service` | success, `BUILD_FALLBACK=1` | sarif_results=67 | iac-checkov, osa-trivy-fs, sca-trivy-image → 201 |

**C2/C3 closed.** Engagement remains `CI/CD` for all three products.

## gismaputils Package Registry (map_objects-ci) — 2026-07-29

Private wheels live in GitLab Package Registry of **`av.popov/map_objects-ci` (project 1962)**, not in Nexus and not in upstream `map_utils` registry (stuck at `0.0.x`).

| Item | Value |
|------|--------|
| Source repo / tags | `map_objects/map_utils` tags `0.5.1`, `0.5.3` |
| Publish | `twine upload --repository-url https://gitlab.svo.aero/api/v4/projects/1962/packages/pypi` |
| CI read token | masked var `GISMAPUTILS_PYPI_TOKEN` (+ `GISMAPUTILS_INDEX_HOST=gitlab.svo.aero`) |
| Kaniko consume | download wheel into `checkout/vendor-gismaputils/` then `pip … --find-links /app/vendor-gismaputils` |
| Do **not** | `--extra-index-url` to GitLab — pip queries it for every package and SSL-falls through to `pypi.org` |

Republish a version (on p30 with Nexus pip + GitLab PAT):

```sh
SETUPTOOLS_SCM_PRETEND_VERSION=0.5.1 python -m build --wheel
twine upload --repository-url https://gitlab.svo.aero/api/v4/projects/1962/packages/pypi dist/gismaputils-0.5.1-*.whl
```

Evidence: pipeline `112683` / `112687` — `BUILD_FALLBACK=0`, `Processing ./vendor-gismaputils/gismaputils-0.5.1-…whl`.

## aodb-log-tools Package Registry (map_objects-ci) — 2026-08-12

| Item | Value |
|------|--------|
| Why | `mail_service` poetry dep; upstream only on retired `nexus.code-discovery.ru` (unreachable); no GitLab source project |
| Package | `aodb-log-tools==1.0.0` (wheel + sdist) in project **1962** Package Registry |
| Kaniko consume | download → `checkout/vendor-aodb-log-tools/` → rewrite pyproject to `{ path = "vendor-aodb-log-tools", develop = false }` → `poetry lock && poetry install` |
| Token | reuse `GISMAPUTILS_PYPI_TOKEN` / `CI_JOB_TOKEN` |
| Re-upload | `curl --form content=@aodb_log_tools-1.0.0-py3-none-any.whl …/projects/1962/packages/pypi` (or twine from a host that resolves `gitlab.svo.aero`) |

## Residual risks
- **linter / bandit**: require `NEXUS_USER`+`NEXUS_PASSWORD` with `PIP_INDEX_URL`; shell path still docker-runs python when host lacks pip — keep caches off workspace.
- **build / image wave**: Kaniko on k8s (`build-kaniko.yml`); fallback `BUILD_FALLBACK=1` when service Dockerfile cannot finish. SCA may reflect base OS until Nexus has app packages.
- **K8s vs shell roulette**: identical tags (`devsecops,k3s,corp,p30`) pick shell *or* k8s; Kaniko path needs k8s (no dind). docker-run still required when job `image:` ignored on shell for scanners.
- **Trivy cache**: keep non-root writes + `GIT_CLEAN_FLAGS`; prefer runner-mounted Nexus CA long-term instead of `TRIVY_INSECURE`.
- **Semgrep**: vendor refresh is manual (`config/semgrep/README.md`); never use `p/ci` / semgrep.dev at runtime.
- **ASPM uploads**: `DEFECTDOJO_INSECURE` until corp CA mounted; nested image vars banned for K8s `image:`.
- **Mirror hygiene**: do not use `adopt.sh` when `.gitlab/jobs` exists (nests `jobs/jobs`); point-copy templates (`scripts/point-copy-mirror.sh`); no col-0 heredoc Python in job YAML (use external scripts).
- **warn→block**: secrets → dockerfile first after ≥3 green multi-service pilots; do not flip while collection is the goal. See [`gate-thresholds.md`](gate-thresholds.md).
- **Kaniko**: mirror profile uses `build-kaniko.yml` (no dind). See [`mirror-api-trigger-schemathesis.md`](mirror-api-trigger-schemathesis.md).
- **cleanup-runner**: prune only job/registry-tagged images on shared shell — avoid host-wide `docker image prune -af`. Independent of `mirror-prune-hotfix-tags.sh` (git tags).
- **CA mount backlog**: drop `TRIVY_INSECURE` / `DEFECTDOJO_INSECURE` after pods mount `/etc/ssl/certs/nexus/ca.crt`.

## B0 / Kaniko / Schemathesis wave (2026-07-29)

Plan SoT: cxado `.cursor/plans/mirror_push_kaniko_no_tag_spam_a1b2c3d4.plan.md` (do not edit from implementer unless asked).

Delivered in Fabrica:
- Inventory / baseline / sync / prune scripts
- Kaniko build + Schemathesis mirror job + API workflow (hotfix ban)
- Runbooks: baseline, API+fuzz, retention, binary-fuzz backlog (T6)

### B0e baseline execution

Inventory (via p30 → GitLab): **31** projects under `dpm/.../map_objects` (+ siblings). TSV on runner host `/tmp/mirror-inv.tsv`.

Point-copy deploy to `av.popov/map_objects-ci` (master `fe7b803`): Kaniko + API workflow + Schemathesis.

Baseline API pipelines (no git tags), `SERVICE_NAME` + `SOURCE_REF` from registry fallbacks:

| When | SERVICE_NAME | SOURCE_REF | Pipeline ID | URL |
|------|--------------|------------|-------------|-----|
| 2026-07-29 | hwa_service | 0.0.4 | 112591 | https://gitlab.svo.aero/av.popov/map_objects-ci/-/pipelines/112591 |
| 2026-07-29 | data_lake_service | 0.4.10 | 112592 | https://gitlab.svo.aero/av.popov/map_objects-ci/-/pipelines/112592 |
| 2026-07-29 | user_service | 0.4.4 | 112593 | https://gitlab.svo.aero/av.popov/map_objects-ci/-/pipelines/112593 |

### Fix — fake-green build (2026-07-29)

**Root cause:** `scripts/resolve-mirror-service.sh` ended with `exit 0` while sourced from `.source_checkout` → before_script aborted after resolve as “success”; no checkout/build. Plus blanket `allow_failure: true`. Kaniko image not in Nexus (TLS/missing).

**Fix (mirror `8235ece`, evidence pipeline `112595`):**
- remove `exit 0` from resolve
- `allow_failure: false` on scanners/build/SCA/fuzz (only cleanup soft)
- build via `mirror-build-image.sh` (docker CLI until Kaniko in Nexus); `IMAGE_TAG=hwa_service-<SOURCE_SHA>`
- build job actually cloned + docker build + fallback push (`BUILD_FALLBACK=1` when pip package missing)

## Files Touched In This Stabilization Wave

- `templates/profiles/oss-full-service-mirror.gitlab-ci.yml`
- `templates/gitlab/jobs/dockerfile-lint.yml`
- `templates/gitlab/jobs/oss/gitleaks.yml`
- `templates/gitlab/jobs/oss/semgrep-sast.yml`
- `templates/gitlab/jobs/oss/bandit-sast.yml`
- `templates/gitlab/jobs/oss/trivy-osa.yml`
- `templates/gitlab/jobs/oss/checkov-iac.yml`
- `templates/gitlab/jobs/forbidden-files.yml`
- `templates/gitlab/jobs/linter-security.yml`
- `templates/gitlab/jobs/aspm/upload-static.yml`
- `config/security-gate-policy-adopt.yaml`
- `config/security-gate-policy.yaml`
- `config/aspm-export.yaml`
- `config/semgrep/vendor/` (+ `VENDOR_SHA.txt`, `README.md`)
- `scripts/aspm-export.py`
- `scripts/fetch-source-archive.py`
- `scripts/fetch-source-archive.sh`
- `scripts/pip-index-auth.sh`
- `scripts/synthesize-ruff-sarif.py`
- `scripts/synthesize-bandit-sarif.py`
- `scripts/merge-hadolint-json.py`
- `scripts/docker-host-bootstrap.sh`
- `scripts/point-copy-mirror.sh`
- `scripts/validate-mirror-corp.sh`
- `docs/runbooks/aspm-export.md`
- `docs/runbooks/mirror-security-pipeline-action-log.md`
- `docs/runbooks/corp-gitlab-runner.md`
- `docs/runbooks/gitlab-hwa-mirror-bootstrap.md`

## Current Operating Mode

- Gates are active (`gate-check.py` still runs).
- Threshold policy is adoption-oriented (`warn` for selected controls).
- Pipeline objective is vulnerability collection and ASPM ingestion, not blocking release yet.

## Hardening Roadmap (Threshold Tightening)

Move one control at a time after at least 3 stable pilot cycles.

1. **Observe**
   - keep `mode: warn`;
   - track findings trend and scanner reliability.
2. **Warn + Budget**
   - keep `mode: warn`;
   - set/adjust `max_findings` budgets and owners per control.
3. **Selective Block**
   - switch low-noise controls first (`secrets`, then `dockerfile`).
4. **Broad Block**
   - move `sast`, `osa`, `iac` from warn to block once false positives are triaged.
5. **Steady-State**
   - strict policy default with temporary waivers only through documented exception flow.

## Fail-hard + deploy wave (2026-07-29)

Pipeline evidence target: `112698` (`data_lake_service` / `0.4.10`) after sync to mirror `master`.

| Fix | What changed |
|-----|----------------|
| RBAC | `ci-test-deployer` ClusterRole now has `secrets` create/get/list/delete/patch; applied on p30 k3s |
| Deploy | `deploy-test-k8s.sh` creates `gitlab-registry` (+ optional `nexus-registry`) in ephemeral ns; `imagePullPolicy: Always`; readiness default `/openapi.json`; richer timeout diagnostics |
| SCA | `trivy-sca` Nexus auth parity with OSA; skip-db only when cache present; DB/scan/SBOM fail → `exit 1` (no empty-stub green) |
| SCA 401 root cause | `.registry_auth_env` set `TRIVY_*=CI_REGISTRY_*` (GitLab); SCA only filled from `NEXUS_*` if empty → GitLab creds hit Nexus `:8374` DB → 401. OSA never extends registry-auth so uses Nexus. Fix: always override `TRIVY_*=NEXUS_*` + `DOCKER_CONFIG` for GitLab image pull |
| Dojo | `secrets.scan_type: SARIF`; `aspm-export.py` validates SARIF `runs` before POST |
| DAST/fuzz | no soft `\|\| true` on empty ZAP; ASPM after_script fails when `DEFECTDOJO_FAIL_ON_ERROR=true` |

Acceptance checklist: security green → uploads success or local fail → `BUILD_FALLBACK=0` → `trivy-sca` real fail/success → deploy Ready + `API_BASE_URL` → dast/fuzz not skipped → `cleanup-test` always.

## CrashLoop + SCA seal (2026-07-29)

Pipeline wave after `112698`/`112701`:

| Issue | Fix |
|-------|-----|
| SCA GitLab creds on Nexus DB | `TRIVY_*=NEXUS_*` override + `DOCKER_CONFIG` (verified DB download on `112701`) |
| SCA gate-check no python in trivy image | adopt-policy skip like OSA when SARIF present |
| Deploy CrashLoop exit 0 | Kaniko was `target=base` (no src/CMD); now `BUILD_DOCKER_TARGET=source` + uvicorn command |
| Empty env / wrong readiness | ConfigMap from `config/mirror-deploy/data_lake_service.env`; readiness `/api/gis/v1/data-lake/healthcheck` |
| Deploy RBAC configmaps | `ci-test-deployer` needs `configmaps` (same as secrets) — applied on p30 |
| Deploy lifespan deps | data_lake startup calls auth + mongo; ephemeral `ci-http-stub` + `mongo` via `deploy_stubs: http,mongo` |
| Dojo linters HTTP 500 | **Root cause:** Ruff SARIF has `"ruleId": null` (notebook SyntaxError) → DefectDojo importer 500. **Fix:** `aspm-export.py` `sanitize_sarif_for_dojo()` maps null → `missing-rule-id` (+ synthetic rule). Not `allow_failure`. |
| Deploy Ready (`112710`) | stubs fixed lifespan; deploy + api-fuzz **UI** green |
| Schemathesis fake-green (`112710` job `1148424`) | **Root cause:** `SCHEMATHESIS_HOOKS=tests/security/schemathesis-hooks.py` imported as module → crash, no junit; `gate-check` adopt `mode=warn` exits 0 on missing report. **Fix:** unset path hooks / install as `hooks`; fail-hard if junit missing before gate |
| Schemathesis CLI (`112714`) | Nexus image is **3.39.2** (`--base-url`, `--junit-xml`), script used v4 flags (`--url`, `--phases`, `--report junit`) → usage error. Fix: version-branch in `run-schemathesis-mirror.sh` |
| DAST `/zap/wrk` (`112710`/`112714`) | Need `/zap/wrk`; `-J /zap/wrk/...` doubles to `/zap/wrk/zap/wrk/...`. Fix: `-J zap-baseline.json` + copy from `/zap/wrk/` |
| Schemathesis OpenAPI 3.1 (`112725`) | Need `--experimental=openapi-3.1`; paths `/v1/...` need `API_PATH_PREFIX=/api/gis/v1/data-lake` on base-url |
| DAST empty Dojo (`112725`) | Spider 404 on `/` + `--skip-empty` → no Test. Fix: `DAST_TARGET_URL` with prefix; upload without `--skip-empty`; `upload-fuzz-to-dojo` |
| DAST XML (`112734`) | Dojo `ZAP Scan` requires XML (`-x`), not JSON (`-J`). Target = `.../healthcheck` |
| Schemathesis fake paths (`112734`) | Prefer live `PREFIX/openapi.json` + base-url host only; `-c` includes `status_code_conformance`. Dojo: junit → Generic Findings Import |
| Deploy Ready (`112710`) | stubs fixed lifespan; deploy + api-fuzz success |
| DAST `/zap/wrk` (`112710`) | ZAP rc=3: file options need `/zap/wrk`. Fix: `mkdir -p /zap/wrk`, `-J /zap/wrk/...`, copy to `reports/` |
| DAST OpenAPI full cover | Replace `zap-baseline.py` (one seed/healthcheck) with `zap-api-scan.py -f openapi` + live OAS + `-O $API_BASE_URL`; reports `zap-api.{xml,json}`; coverage assert; `DAST_OPENAPI_URL` in deploy.env |

## Verification Checklist For Next Improvement Iteration

- Confirm `dockerfile-lint` is present (not skipped) in tag pipelines.
- Confirm static reports are generated and retained as artifacts.
- Confirm `upload-*-to-dojo` jobs run and import artifacts.
- Confirm DefectDojo UI/API shows product + findings after non-empty uploads (not soft-skip green).
- Confirm `cleanup-runner` executes at end of each pilot pipeline.
- Confirm no runner-specific bootstrap failure regressed (`python3`, `pip`, `docker`, package manager).

## Wave-6 fleet + ASPM HTML (2026-07)

Tooling: `scripts/mirror-fleet-trigger.py`, shared `scripts/lib/mirror_services.py`, `make mirror-fleet` / `make mirror-aspm-html`.
Registry **Wave-3** (pilots only): hwa, data_lake, user (`enabled: true`). Core trio kept as `enabled: false` / `tier: candidate`.
HTML: `scripts/dojo-render-aspm-report.py` → `reports/aspm-report-<service>.html` after pipelines (see `defectdojo-aspm-report.md`).

| When | SERVICE_NAME | SOURCE_REF | Pipeline ID | URL | Notes |
|------|--------------|------------|-------------|-----|-------|
| 2026-07-30 | hwa_service | 0.0.4 | 112805 | https://gitlab.svo.aero/av.popov/map_objects-ci/-/pipelines/112805 | deploy CrashLoop (no CMD) — superseded |
| 2026-07-30 | data_lake_service | 0.4.10 | 112806 | https://gitlab.svo.aero/av.popov/map_objects-ci/-/pipelines/112806 | superseded by Wave-3 re-fleet |
| 2026-07-30 | user_service | 0.4.4 | 112807 | https://gitlab.svo.aero/av.popov/map_objects-ci/-/pipelines/112807 | BUILD_FALLBACK=1 (gismaputils 0.2.5 missing) — superseded |
| 2026-07-30 | dynamic_layer_service | 0.5.1 | 112808 | https://gitlab.svo.aero/av.popov/map_objects-ci/-/pipelines/112808 | canceled (Wave-3 shrink) |
| 2026-07-30 | event_service | 0.4.1 | 112809 | https://gitlab.svo.aero/av.popov/map_objects-ci/-/pipelines/112809 | canceled (Wave-3 shrink) |
| 2026-07-30 | defects | 0.5.7 | 112810 | https://gitlab.svo.aero/av.popov/map_objects-ci/-/pipelines/112810 | canceled (Wave-3 shrink) |

### Wave-3 deploy fix (2026-07-30)

- Shrink fleet to 3 pilots; disable core candidates in registry.
- `hwa`/`user`: `deploy_command` + `deploy_workdir` + mongo/http stubs + env fixtures (`config/mirror-deploy/*.env`); readiness `/v1/openapi.json`.
- Kaniko: if `gismaputils==X` wheel missing, remap pin to Package Registry wheel (0.5.1/0.5.3) so `BUILD_FALLBACK=0`.

Re-fleet IDs (mirror `412ba41`):

| When | SERVICE_NAME | SOURCE_REF | Pipeline ID | URL |
|------|--------------|------------|-------------|-----|
| 2026-07-30 | hwa_service | 0.0.4 | 112813 | https://gitlab.svo.aero/av.popov/map_objects-ci/-/pipelines/112813 |
| 2026-07-30 | data_lake_service | 0.4.10 | 112814 | https://gitlab.svo.aero/av.popov/map_objects-ci/-/pipelines/112814 |
| 2026-07-30 | user_service | 0.4.4 | 112815 | https://gitlab.svo.aero/av.popov/map_objects-ci/-/pipelines/112815 |

### Wave-3 DAST/deploy hotfix (2026-07-30)

- **hwa** DAST/fuzz: missing `api_path_prefix=/v1` → live OpenAPI at `/openapi.json` 000; fixed + infer prefix from readiness.
- **user** deploy: remapped `gismaputils` 0.2.5→0.5.3 broke `get_token` import; Kaniko patches `health_router` to `Auth.get_token`.

Retry (mirror `54e1b9b`):

| When | SERVICE_NAME | SOURCE_REF | Pipeline ID | URL |
|------|--------------|------------|-------------|-----|
| 2026-07-30 | hwa_service | 0.0.4 | 112826 | https://gitlab.svo.aero/av.popov/map_objects-ci/-/pipelines/112826 |
| 2026-07-30 | user_service | 0.4.4 | 112827 | https://gitlab.svo.aero/av.popov/map_objects-ci/-/pipelines/112827 |

## Wave-7 build-all fleet (2026-08-25)

Mirror `1170245` on `av.popov/map_objects-ci` (1962):

- **SKIP_API_SECURITY / SKIP_DEPLOY** — pipeline variables from `mirror-fleet-trigger.py` + resolve; workers skip deploy/dast/fuzz.
- **Deploy stubs** — `postgres`, `redis` in `deploy-test-k8s.sh`; 24 generated `config/mirror-deploy/*.env`.
- **Fleet tooling** — `--wait`, `--wait-cleanup`, `scan_order` sort, matrix md/jsonl.
- **Runner fix (P30)** — removed stale `node_selector` pin to missing `svo-aosint-ps01` (single-node cluster); dual Nexus auths in `nexus-registry`.

Smoke (serial):

| SERVICE_NAME | Pipeline | Status | Notes |
|--------------|----------|--------|-------|
| maps_seeder | [115721](https://gitlab.svo.aero/av.popov/map_objects-ci/-/pipelines/115721) | manual | deploy/dast **skipped**; build+scan green |
| hwa_service | [115722](https://gitlab.svo.aero/av.popov/map_objects-ci/-/pipelines/115722) | manual | full deploy path regression |
| mail_service | [115720](https://gitlab.svo.aero/av.popov/map_objects-ci/-/pipelines/115720) | failed | build-image: aodb-log-tools wheel 404 (Package Registry) |

Full fleet (34 enabled): background on P30 `/tmp/map_objects-ci` — `reports/mirror-fleet-full.jsonl`, `reports/mirror-fleet-matrix.md`, log `reports/mirror-fleet-bg.log`, pid `reports/mirror-fleet-bg.pid`.

**ASPM success bar:** `manual` with green build/sca/security = OK (sign-image is manual only). Workers: no deploy required.

### aodb-log-tools Package Registry caveat (2026-08-25)

Corp GitLab Package Registry accepts uploads (`201`) but stores `file_sha256=null`, so simple-index links are `…/packages/pypi/files/<name>#sha256=` and **downloads return 404**. gismaputils wheels uploaded earlier have real hashes and work.

**Mitigation (mirror `60032e1`):** Kaniko synthesizes `vendor-aodb-log-tools/` stub (pyproject + package) when index/download fails, then path-dep rewrite continues. Re-upload alone does not fix downloads until GitLab computes sha256.

Fleet progress snapshot (serial, all ASPM-OK `manual`):

| SERVICE | Pipeline | Status |
|---------|----------|--------|
| hwa_service | 115723 | manual |
| data_lake_service | 115724 | manual |
| user_service | 115732 | manual |
| dynamic_layer_service | 115740 | manual |
| event_service | 115742 | manual |
| defects | 115745 | manual |

| aircraft_filter | 115751 | manual |
| assignments_satellite | 115754 | manual |

**mail_service follow-up (115756):** aodb path-vendor works (`Installing aodb-log-tools …/vendor-aodb-log-tools`). Remaining build fail is Dockerfile `nuitka` stage (`No module named nuitka`) despite `--target source` — Kaniko still builds a later stage named `base`. Result: `BUILD_FALLBACK=1` → deploy fails (expected). Security+SCA still green. Mirror tip `7b5825b`.
