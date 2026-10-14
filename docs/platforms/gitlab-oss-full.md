# GitLab OSS Full Pipeline (`oss-full`)

**Shared reference:** [oss-full-shared.md](oss-full-shared.md) (pins, gates, registry, ASPM, validation).

Profile for **GitLab CE / Self-hosted** without GitLab Ultimate Security templates.

```bash
./scripts/adopt.sh --profile oss-full --platform gitlab --target .
bash scripts/validate-gitlab-oss.sh
```

See also: [github-oss-full.md](github-oss-full.md) (GitHub Actions equivalent).

## Pipeline stages

### Standard (`oss-full`)

```
validate → test → security → static-security-upload → build → image-security-upload → deploy → post-deploy
```

### Enterprise (`oss-full-enterprise`, common-templates compatible)

```
validate → test → security → static-security-upload → build → image → supply-chain → image-security-upload → deploy → post-deploy
```

Unit tests live in `validate`/`test` — not mixed into `security` (common-templates v2 naming).

## Full job list (B–F)

| Job | Tool | Stage | Trigger |
|-----|------|-------|---------|
| `lint` / `unit-test` | Ruff / pytest | validate / test | MR, main |
| `conftest-admission` | Conftest | validate | path changes |
| `gitleaks-scan` | Gitleaks (docker) | security | MR, main |
| `forbidden-files` | shell + gate | security | MR, main |
| `semgrep-sast` | Semgrep | security | MR, main |
| `trivy-osa` | Trivy fs | security | MR, main |
| `checkov-iac` | Checkov | security | IaC paths |
| `dockerfile-lint` | Hadolint | security | Dockerfile paths |
| `linter-security` | Ruff | security | MR, main |
| `binary-fuzz` | AFL++ / Go / Jazzer | test | manual |
| `build-image` | Docker build+push | build | main |
| `sbom-generate` | Syft | build | main |
| `trivy-sca` | Trivy image | build | main |
| `deploy-preprod` | Helm | deploy | manual |
| `deploy-prod` | Helm | deploy | manual |
| `sign-image` | cosign | post-deploy | manual |
| `dast-zap` | ZAP baseline | post-deploy | manual |
| `api-fuzz-schemathesis` | Schemathesis | post-deploy | manual |
| `iast-preprod` | ZAP Full Scan | post-deploy | manual |
| `sec-func-tests` | pytest | test | MR, main |
| `sbom-upload` | Dependency-Track | post-deploy | manual |
| `nightly-sast-scheduled` | Semgrep | security | schedule |

Job files: `.gitlab/jobs/` (pins via `.gitlab/jobs/oss/versions.yml` from manifest).

## GitLab CE runner requirements

| Requirement | Jobs |
|-------------|------|
| **Docker executor + privileged** | `gitleaks-scan`, `binary-fuzz`, `build-image` (dind) |
| **Container Registry** | `build-image`, `trivy-sca`, `sign-image` |
| **KUBECONFIG** (file variable) | `deploy-preprod`, `deploy-prod` |

Register a runner with `privileged = true` for dind. See [GitLab Docker executor docs](https://docs.gitlab.com/runner/executors/docker.html#use-docker-in-docker).

### Corp mirror profile (`oss-full-service-mirror`)

Tag-driven service mirror (e.g. `map_objects-ci`) uses tags `devsecops,k3s,corp,p30` and may land on **shell** or **kubernetes** executors. See [`docs/runbooks/corp-gitlab-runner.md`](../runbooks/corp-gitlab-runner.md).

- Profile: [`templates/profiles/oss-full-service-mirror.gitlab-ci.yml`](../../templates/profiles/oss-full-service-mirror.gitlab-ci.yml)
- Sync into an existing mirror: `bash scripts/point-copy-mirror.sh --target DIR` (**not** `adopt.sh` into existing `.gitlab/jobs`)
- Verify: `bash scripts/validate-mirror-corp.sh`
- Nexus hosts (override in GitLab CI/CD variables): `NEXUS_DOCKER_PREFIX` (hosted, default `nexus.svo.aero:8345`), `NEXUS_DOCKER_GROUP` (group, default `nexus.svo.aero:8374`). Tool images use `$OSS_*_IMAGE` built from those prefixes — do not hardcode the host in `image:` lines.
- DAST: `zap-api-scan` via `scripts/run-dast-zap-api-mirror.sh` (live OpenAPI), report `reports/zap-api.xml` → DefectDojo `ZAP Scan`
- Fuzz: Schemathesis + live OpenAPI; Dojo via Generic Findings Import
- Ephemeral deploy stubs (`ci-http-stub`, mongo) are lifespan fixtures — not scanner fake-green
- Soft-fail adoption exception: [`ci-soft-fail-contract.md`](../runbooks/ci-soft-fail-contract.md)
- Action log: [`mirror-security-pipeline-action-log.md`](../runbooks/mirror-security-pipeline-action-log.md)

### Node + k3s profile (`oss-full-node-k3s`)

Bun/Node apps on corp k3s (e.g. Hexenhammer). Same runner tags as the mirror; **Kaniko** build; **kustomize/kubectl** deploy (not Helm sample).

```bash
./scripts/adopt.sh --profile oss-full-node-k3s --platform gitlab --target /path/to/app --policy adopt --python-stack node
```

- Controls: **`osa-sca`** = composition / OSS deps in source; **`container`** = image scan (not “SCA = container”).
- Inline in scan jobs: CISA KEV → EPSS → `gate-check` → DefectDojo upload (`aspm-export-ci.sh`). Companion `*-enrich` jobs disabled.
- Day-1 policy: `config/security-gate-policy-node-k3s-adopt.yaml` (secrets + forbidden_files **block**; other scanners warn).
- Vars: `IMAGE_REPO`, `KUBECONFIG`, `K8S_NAMESPACE` / `K8S_DEPLOYMENT`, `SMOKE_URL` / `HEX_SMOKE_URL`, Nexus + DefectDojo.

## Required CI/CD variables

| Variable | Type | Purpose |
|----------|------|---------|
| `CI_REGISTRY_*` | builtin | Container Registry login (default backend `gitlab`) |
| `KUBECONFIG` | File, masked | kubectl/helm access to cluster |
| `PREPROD_URL` | Variable | DAST / IAST target (alias: `DAST_WEBSITE` in common-templates) |
| `DAST_WEBSITE` | Variable | Opt-in DAST URL — auto-runs `dast-zap` on main when set |
| `DAST_COMPOSE_ENABLED` | Variable | Set `true` to auto-run `dast-compose` on main |
| `SAST_DISABLED` / `SECURITY_DISABLED` | Variable | Kill-switch — skip all security + ASPM upload jobs |
| `HELM_CHART_PATH` | Variable | Default `chart/` (copied on adopt) |
| `HELM_RELEASE` | Variable | Default `sample-app` |
| `NAMESPACE_PREPROD` / `NAMESPACE_PROD` | Variable | K8s namespaces |

Optional: `COSIGN_PRIVATE_KEY`, `DTRACK_*`, `DEFECTDOJO_*`, `REGISTRY_BACKEND` / Nexus — see [oss-full-shared.md](oss-full-shared.md).

## Kubernetes / Helm

On adopt, `templates/k8s/helm/sample-app/` → `chart/` if missing.

```bash
helm upgrade --install sample-app chart/ \
  --namespace preprod \
  --set image.repository=$CI_REGISTRY_IMAGE \
  --set image.tag=$CI_COMMIT_SHA
```

## MR vs main

| Trigger | Jobs |
|---------|------|
| MR | gitleaks, forbidden-files, semgrep, trivy-osa, checkov (if IaC), hadolint, linters, conftest; manual binary-fuzz |
| main | + build/push → sbom → trivy-sca; manual deploy / DAST / IAST / API fuzz / sign |

## Nightly SAST schedule

CI/CD → Schedules → New schedule → target branch `main`, cron e.g. `0 2 * * *`, job `nightly-sast-scheduled`.

## DefectDojo

GitLab uses **ASPM upload waves** (`static-security-upload`, `image-security-upload`) with `needs: optional: true` — see [`aspm/upload-static.yml`](../../templates/gitlab/jobs/aspm/upload-static.yml). Upload jobs skip when `DEFECTDOJO_URL` / `DEFECTDOJO_API_TOKEN` unset or artifact missing.

Enterprise profile: [`oss-full-enterprise.gitlab-ci.yml`](../../templates/profiles/oss-full-enterprise.gitlab-ci.yml). Case study: [common-templates-adaptation-case-study.md](../references/supplements/common-templates-adaptation-case-study.md).

## Validation

```bash
bash scripts/validate-gitlab-oss.sh
bash scripts/validate-yaml.sh
./scripts/adopt.sh --profile oss-full --platform gitlab --target /tmp/t --dry-run
```
