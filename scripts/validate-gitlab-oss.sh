#!/usr/bin/env bash
# Validate GitLab OSS full profile and pin policy.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

fail=0
report() {
  echo "VIOLATION: $1"
  fail=1
}

PROFILE="templates/profiles/oss-full.gitlab-ci.yml"
ENTERPRISE="templates/profiles/oss-full-enterprise.gitlab-ci.yml"

required=(
  "$PROFILE"
  "$ENTERPRISE"
  templates/gitlab/jobs/_security.common.yml
  templates/gitlab/jobs/aspm/upload-static.yml
  templates/gitlab/jobs/aspm/upload-image.yml
  templates/gitlab/jobs/oss/helm-deploy-contour.yml
  templates/gitlab/jobs/oss/versions.yml
  templates/gitlab/jobs/oss/_docker.yml
  templates/gitlab/jobs/oss/_base-validate.yml
  templates/gitlab/jobs/oss/build-push.yml
  templates/gitlab/jobs/oss/gitleaks.yml
  templates/gitlab/jobs/oss/semgrep-sast.yml
  templates/gitlab/jobs/oss/trivy-osa-sca.yml
  templates/gitlab/jobs/oss/trivy-container.yml
  templates/gitlab/jobs/oss/checkov-iac.yml
  templates/gitlab/jobs/oss/helm-deploy.yml
  templates/gitlab/jobs/oss/sbom-upload.yml
  templates/gitlab/jobs/registry/variables.yml
  templates/gitlab/jobs/registry/login.yml
  templates/gitlab/jobs/forbidden-files.yml
  templates/gitlab/jobs/dast.yml
  templates/gitlab/jobs/dast-compose.yml
  templates/gitlab/jobs/api-fuzz-schemathesis.yml
  templates/gitlab/jobs/binary-fuzz.yml
  templates/gitlab/jobs/iast-preprod.yml
  templates/gitlab/jobs/sec-func-tests.yml
  templates/gitlab/jobs/conftest-admission.yml
  templates/gitlab/jobs/nightly-full-sast.yml
  docs/references/supplements/common-templates-adaptation-case-study.md
  docs/references/supplements/gitlab-enterprise-deploy.md
  scripts/run-binary-fuzz.sh
  scripts/binary-fuzz-to-junit.py
)

for f in "${required[@]}"; do
  [[ -f "$f" ]] || report "missing: $f"
done

if grep -vE '^\s*#' "$PROFILE" | grep -qE 'Security/.*\.gitlab-ci\.yml|codeql-action|CodeQL' 2>/dev/null; then
  report "oss-full.gitlab-ci.yml must not use GitLab Security templates or CodeQL"
fi

if ! grep -q '_security.common.yml' "$PROFILE"; then
  report "oss-full.gitlab-ci.yml must include _security.common.yml"
fi

if ! grep -q 'aspm/upload-static.yml' "$PROFILE"; then
  report "oss-full.gitlab-ci.yml must include aspm/upload-static.yml"
fi

if ! grep -q 'static-security-upload' "$PROFILE"; then
  report "oss-full.gitlab-ci.yml must define static-security-upload stage"
fi

if ! grep -q 'SAST_DISABLED' templates/gitlab/jobs/_security.common.yml; then
  report "_security.common.yml must define SAST_DISABLED kill-switch"
fi

if ! grep -q 'dast_opt_in_rules' templates/gitlab/jobs/dast.yml; then
  report "dast.yml must use dast opt-in rules"
fi

if ! grep -q 'checkov-report.json' templates/gitlab/jobs/oss/checkov-iac.yml; then
  report "checkov-iac.yml must emit checkov-report.json for DefectDojo"
fi

if ! grep -q 'hadolint-report.json' templates/gitlab/jobs/dockerfile-lint.yml; then
  report "dockerfile-lint.yml must emit hadolint-report.json for DefectDojo"
fi

for inc in oss/versions.yml oss/_docker.yml _security.common.yml oss/_base-validate.yml oss/build-push.yml \
  oss/gitleaks.yml forbidden-files.yml oss/semgrep-sast.yml oss/trivy-osa-sca.yml \
  oss/checkov-iac.yml aspm/upload-static.yml aspm/upload-image.yml \
  dast.yml dast-compose.yml oss/helm-deploy.yml conftest-admission.yml; do
  if ! grep -q "$inc" "$PROFILE"; then
    report "oss-full.gitlab-ci.yml must include jobs/$inc"
  fi
done

if grep -qE ':latest|:stable' templates/gitlab/jobs/oss/*.yml 2>/dev/null; then
  grep -nE ':latest|:stable' templates/gitlab/jobs/oss/*.yml | while read -r line; do
    report "rolling pin in oss jobs: $line"
  done
fi

for profile in oss-full oss-full-enterprise oss-full-node; do
  ADOPT_TEST="/tmp/gitlab-oss-adopt-test-${profile}-$$"
  mkdir -p "$ADOPT_TEST"
  if ! bash "$ROOT/scripts/adopt.sh" --profile "$profile" --platform gitlab --target "$ADOPT_TEST" --dry-run >/dev/null 2>&1; then
    report "adopt.sh --profile $profile --platform gitlab --dry-run failed"
  fi
  rm -rf "$ADOPT_TEST"
done

if [[ $fail -ne 0 ]]; then
  echo ""
  echo "GitLab OSS validation failed. See docs/platforms/gitlab-oss-full.md"
  exit 1
fi

echo "OK: GitLab OSS profile valid"
