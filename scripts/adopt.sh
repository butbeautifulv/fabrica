#!/usr/bin/env bash
# Adopt DevSecOps template phases into a target repository
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: adopt.sh --profile PROFILE --platform PLATFORM --target DIR [options]

Profiles: minimal | shift-left | supply-chain | full | ai-ml | oss-full | oss-full-node | oss-full-enterprise | oss-full-node-k3s
Platforms: gitlab | github

Options:
  --dry-run              Print copy plan without writing
  --policy adopt|strict  Gate policy mode (default: adopt)
  --python-stack STACK   auto | uv | pip | node (default: auto)

Examples:
  ./scripts/adopt.sh --profile shift-left --platform gitlab --target ~/myapp
  ./scripts/adopt.sh --profile shift-left --platform github --target ~/myapp --python-stack uv
  ./scripts/adopt.sh --profile full --platform github --target ~/myapp --policy strict --dry-run
EOF
  exit 1
}

PROFILE=""
PLATFORM=""
TARGET=""
DRY_RUN=0
POLICY_MODE="adopt"
PYTHON_STACK="auto"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --profile) PROFILE="$2"; shift 2 ;;
    --platform) PLATFORM="$2"; shift 2 ;;
    --target) TARGET="$2"; shift 2 ;;
    --dry-run) DRY_RUN=1; shift ;;
    --policy) POLICY_MODE="$2"; shift 2 ;;
    --python-stack) PYTHON_STACK="$2"; shift 2 ;;
    -h|--help) usage ;;
    *) echo "Unknown: $1"; usage ;;
  esac
done

[[ -n "$PROFILE" && -n "$PLATFORM" && -n "$TARGET" ]] || usage
[[ -d "$TARGET" ]] || { echo "Target not found: $TARGET"; exit 1; }

case "$POLICY_MODE" in
  adopt|strict) ;;
  *) echo "Unknown --policy: $POLICY_MODE (use adopt or strict)"; exit 1 ;;
esac

case "$PYTHON_STACK" in
  auto|uv|pip|node) ;;
  *) echo "Unknown --python-stack: $PYTHON_STACK"; exit 1 ;;
esac

copy() {
  local src="$1" dest="$2"
  mkdir -p "$(dirname "$dest")"
  if [[ $DRY_RUN -eq 1 ]]; then
    echo "COPY $src -> $dest"
  else
    cp -r "$src" "$dest"
    echo "Copied $dest"
  fi
}

echo "=== DevSecOps adopt: profile=$PROFILE platform=$PLATFORM policy=$POLICY_MODE python-stack=$PYTHON_STACK ==="

# Policy always
copy "$ROOT/config/security-gate-policy.yaml" "$TARGET/config/security-gate-policy.yaml"
if [[ -f "$ROOT/config/security-gate-policy-adopt.yaml" ]]; then
  copy "$ROOT/config/security-gate-policy-adopt.yaml" "$TARGET/config/security-gate-policy-adopt.yaml"
fi
copy "$ROOT/config/aspm-export.yaml" "$TARGET/config/aspm-export.yaml"
copy "$ROOT/config/oss-tool-versions.yaml" "$TARGET/config/oss-tool-versions.yaml"
copy "$ROOT/config/artifact-registry.yaml" "$TARGET/config/artifact-registry.yaml"
if [[ -f "$ROOT/config/github-oss-env.yml" ]]; then
  copy "$ROOT/config/github-oss-env.yml" "$TARGET/config/github-oss-env.yml"
fi
copy "$ROOT/scripts/gate-check.py" "$TARGET/scripts/gate-check.py"
copy "$ROOT/scripts/normalize-sarif.py" "$TARGET/scripts/normalize-sarif.py"
copy "$ROOT/scripts/aspm-export.py" "$TARGET/scripts/aspm-export.py"
copy "$ROOT/scripts/aspm-export-ci.sh" "$TARGET/scripts/aspm-export-ci.sh"
copy "$ROOT/scripts/ai-ml-scan.py" "$TARGET/scripts/ai-ml-scan.py"
copy "$ROOT/scripts/kev-enrich-sarif.py" "$TARGET/scripts/kev-enrich-sarif.py"
copy "$ROOT/scripts/epss-enrich-sarif.py" "$TARGET/scripts/epss-enrich-sarif.py"
copy "$ROOT/scripts/registry-login.sh" "$TARGET/scripts/registry-login.sh"
copy "$ROOT/scripts/registry-auth-env.sh" "$TARGET/scripts/registry-auth-env.sh"
copy "$ROOT/scripts/registry-resolve-env.sh" "$TARGET/scripts/registry-resolve-env.sh"
if [[ -f "$ROOT/scripts/lib/kev_catalog.py" ]]; then
  copy "$ROOT/scripts/lib/kev_catalog.py" "$TARGET/scripts/lib/kev_catalog.py"
fi
if [[ -f "$ROOT/scripts/lib/epss_catalog.py" ]]; then
  copy "$ROOT/scripts/lib/epss_catalog.py" "$TARGET/scripts/lib/epss_catalog.py"
fi
if [[ -f "$ROOT/config/kev/cisa-kev.min.json" ]]; then
  copy "$ROOT/config/kev/cisa-kev.min.json" "$TARGET/config/kev/cisa-kev.min.json"
fi
if [[ -f "$ROOT/config/epss/epss_scores.min.json.gz" ]]; then
  copy "$ROOT/config/epss/epss_scores.min.json.gz" "$TARGET/config/epss/epss_scores.min.json.gz"
fi
if [[ -f "$ROOT/config/epss/epss_meta.json" ]]; then
  copy "$ROOT/config/epss/epss_meta.json" "$TARGET/config/epss/epss_meta.json"
fi
if [[ -f "$ROOT/config/security-gate-policy-node-k3s-adopt.yaml" ]]; then
  copy "$ROOT/config/security-gate-policy-node-k3s-adopt.yaml" "$TARGET/config/security-gate-policy-node-k3s-adopt.yaml"
fi
chmod +x "$TARGET/scripts/gate-check.py" 2>/dev/null || true
chmod +x "$TARGET/scripts/normalize-sarif.py" 2>/dev/null || true
chmod +x "$TARGET/scripts/aspm-export.py" 2>/dev/null || true
chmod +x "$TARGET/scripts/aspm-export-ci.sh" 2>/dev/null || true
chmod +x "$TARGET/scripts/kev-enrich-sarif.py" 2>/dev/null || true
chmod +x "$TARGET/scripts/epss-enrich-sarif.py" 2>/dev/null || true
chmod +x "$TARGET/scripts/registry-login.sh" 2>/dev/null || true
chmod +x "$TARGET/scripts/registry-auth-env.sh" 2>/dev/null || true
chmod +x "$TARGET/scripts/registry-resolve-env.sh" 2>/dev/null || true

if [[ "$PROFILE" == "oss-full" ]]; then
  copy "$ROOT/scripts/run-binary-fuzz.sh" "$TARGET/scripts/run-binary-fuzz.sh"
  copy "$ROOT/scripts/binary-fuzz-to-junit.py" "$TARGET/scripts/binary-fuzz-to-junit.py"
  copy "$ROOT/tests/security" "$TARGET/tests/security"
  copy "$ROOT/examples/fuzzing" "$TARGET/examples/fuzzing"
  mkdir -p "$TARGET/examples/openapi"
  copy "$ROOT/examples/openapi/minimal.yaml" "$TARGET/examples/openapi/minimal.yaml"
  chmod +x "$TARGET/scripts/run-binary-fuzz.sh" 2>/dev/null || true
  chmod +x "$TARGET/scripts/binary-fuzz-to-junit.py" 2>/dev/null || true
fi

if [[ "$PLATFORM" == "gitlab" ]]; then
  copy "$ROOT/templates/profiles/${PROFILE}.gitlab-ci.yml" "$TARGET/.gitlab-ci.yml"
  copy "$ROOT/templates/gitlab/jobs" "$TARGET/.gitlab/jobs"
  copy "$ROOT/templates/CODEOWNERS" "$TARGET/CODEOWNERS"
  if [[ "$PROFILE" == "oss-full" ]]; then
    if [[ -d "$TARGET/chart" ]]; then
      echo "Skip chart copy — $TARGET/chart already exists"
    else
      copy "$ROOT/templates/k8s/helm/sample-app" "$TARGET/chart"
    fi
  fi
  if [[ $DRY_RUN -eq 0 ]]; then
    sed -i "s|local: '/templates/gitlab/jobs/|local: '.gitlab/jobs/|g" "$TARGET/.gitlab-ci.yml"
    sed -i 's|local: "/templates/gitlab/jobs/|local: ".gitlab/jobs/|g' "$TARGET/.gitlab-ci.yml"
    echo "Rewrote .gitlab-ci.yml include paths -> .gitlab/jobs/"
  fi
elif [[ "$PLATFORM" == "github" ]]; then
  copy "$ROOT/templates/github/workflows" "$TARGET/.github/workflows"
  copy "$ROOT/templates/github/actions" "$TARGET/.github/actions"
  copy "$ROOT/templates/profiles/${PROFILE}.github.yml" "$TARGET/.github/workflows/ci-profile.yml"
  copy "$ROOT/templates/github/dependabot.yml" "$TARGET/.github/dependabot.yml"
  copy "$ROOT/templates/CODEOWNERS" "$TARGET/CODEOWNERS"
  if [[ "$PROFILE" == "full" ]]; then
    copy "$ROOT/templates/github/workflows/nightly-sast.yml" "$TARGET/.github/workflows/nightly-sast.yml"
  fi
  if [[ "$PROFILE" == "oss-full" ]]; then
    copy "$ROOT/templates/github/workflows/nightly-sast-oss.yml" "$TARGET/.github/workflows/nightly-sast-oss.yml"
    copy "$ROOT/templates/github/workflows/dast-oss.yml" "$TARGET/.github/workflows/dast-oss.yml"
    copy "$ROOT/templates/github/workflows/api-fuzz-oss.yml" "$TARGET/.github/workflows/api-fuzz-oss.yml"
    copy "$ROOT/templates/github/workflows/binary-fuzz-oss.yml" "$TARGET/.github/workflows/binary-fuzz-oss.yml"
    copy "$ROOT/templates/github/workflows/iast-oss.yml" "$TARGET/.github/workflows/iast-oss.yml"
    if [[ $DRY_RUN -eq 0 ]]; then
      cp "$TARGET/.github/workflows/ci-profile.yml" "$TARGET/.github/workflows/ci.yml"
      echo "Activated oss-full as .github/workflows/ci.yml"
    fi
  fi
  if [[ "$PROFILE" == "oss-full-node" ]]; then
    copy "$ROOT/templates/github/workflows/dast-compose-oss.yml" "$TARGET/.github/workflows/dast-compose-oss.yml"
    if [[ $DRY_RUN -eq 0 ]]; then
      cp "$TARGET/.github/workflows/ci-profile.yml" "$TARGET/.github/workflows/ci.yml"
      echo "Activated oss-full-node as .github/workflows/ci.yml"
    fi
  fi
else
  echo "Unknown platform: $PLATFORM"; exit 1
fi

if [[ $DRY_RUN -eq 0 ]]; then
  bash "$ROOT/scripts/post-adopt.sh" "$TARGET" "$PYTHON_STACK" "$POLICY_MODE" "$DRY_RUN"
else
  bash "$ROOT/scripts/post-adopt.sh" "$TARGET" "$PYTHON_STACK" "$POLICY_MODE" "$DRY_RUN"
fi

case "$PROFILE" in
  minimal)    PHASES="A2" ;;
  shift-left) PHASES="A2 B1-B6" ;;
  supply-chain) PHASES="A2 B1-B6 C1-C4" ;;
  full)       PHASES="A2 B1-B6 C1-C4 D1-D3 F1-F3" ;;
  ai-ml)      PHASES="A2 B1-B6 AI1 AI2 ML1 ML2 ML3(optional)" ;;
  oss-full)   PHASES="A2 B1-B6 C1-C4 D1 Helm deploy F3 (100% OSS scanners)" ;;
  oss-full-node) PHASES="A2 B1-B6 (Node validate) C1-C2 optional D1 compose-DAST (100% OSS)" ;;
  oss-full-enterprise) PHASES="A2 B1-B6 C1-C2 enterprise stages + contour Helm (common-templates)" ;;
  oss-full-node-k3s) PHASES="Bun validate + osa-sca/container (inline KEV/EPSS) + Kaniko k3s + kustomize deploy" ;;
  *) echo "Unknown profile: $PROFILE"; exit 1 ;;
esac

cat <<EOF

=== Checklist ===
[ ] GitLab: include paths rewritten to .gitlab/jobs/ (if adopt ran without --dry-run)
[ ] Enable branch protection — docs/platforms/${PLATFORM}.md
[ ] Set REGISTRY / ghcr.io secrets
[ ] Phases included: $PHASES
[ ] Policy mode: $POLICY_MODE | Python stack: $PYTHON_STACK
[ ] Gates: SAST/SCA/IaC block C/H; secrets/dockerfile/linters warn (shift-left adopt policy)
[ ] ai-ml profile: PII block (ml_data); AI scans warn
[ ] oss-full GitLab CE: KUBECONFIG (file var), Container Registry enabled, privileged Docker runner (dind)
[ ] oss-full GitLab CE: CI/CD → Schedules → nightly-sast-scheduled (cron)
[ ] oss-full GitLab CE: validate — bash scripts/validate-gitlab-oss.sh
[ ] oss-full GitHub: enable GHCR (packages: write), copy ci-profile.yml → ci.yml on adopt
[ ] ASPM: set DEFECTDOJO_URL + DEFECTDOJO_API_TOKEN for findings export
[ ] Run: python3 scripts/gate-check.py --help
[ ] Validate: make validate (or bash scripts/validate-yaml.sh && ...)
[ ] See docs/adoption-checklist.md

EOF
