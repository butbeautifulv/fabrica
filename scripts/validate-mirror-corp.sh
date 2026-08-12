#!/usr/bin/env bash
# Corp/offline invariants for oss-full-service-mirror (Nexus-only, Kaniko, no hotfix spam).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
FAIL=0

fail() { echo "FAIL: $*"; FAIL=1; }
ok() { echo "OK: $*"; }

PROFILE="templates/profiles/oss-full-service-mirror.gitlab-ci.yml"
KANIKO="templates/gitlab/jobs/oss/build-kaniko.yml"
FUZZ="templates/gitlab/jobs/oss/api-fuzz-schemathesis-mirror.yml"
ASPM_HTML_JOB="templates/gitlab/jobs/oss/aspm-html-report-mirror.yml"
DFD_JOB="templates/gitlab/jobs/oss/dfd-diagrams-mirror.yml"

[[ -f "$PROFILE" ]] || fail "missing $PROFILE"
[[ -f "$KANIKO" ]] || fail "missing $KANIKO"
[[ -f "$FUZZ" ]] || fail "missing $FUZZ"
[[ -f "$ASPM_HTML_JOB" ]] || fail "missing $ASPM_HTML_JOB"
[[ -f "$DFD_JOB" ]] || fail "missing $DFD_JOB"

# Mirror profile must be Nexus-literal / no public registries.
for pat in 'ghcr\.io' 'pypi\.org' 'semgrep\.dev' '(^|[^a-zA-Z0-9_-])p/ci([^a-zA-Z0-9_]|$)'; do
  if grep -nE "$pat" "$PROFILE" | grep -vE '^\s*[0-9]+:\s*#' >/dev/null 2>&1; then
    grep -nE "$pat" "$PROFILE" || true
    fail "banned '$pat' in mirror profile"
  else
    ok "profile clean of $pat"
  fi
done

RUNTIME_SCAN=(
  templates/gitlab/jobs/aspm
  templates/gitlab/jobs/linter-security.yml
  templates/gitlab/jobs/oss/bandit-sast.yml
  templates/gitlab/jobs/oss/semgrep-sast.yml
  templates/gitlab/jobs/oss/build-kaniko.yml
  templates/gitlab/jobs/oss/api-fuzz-schemathesis-mirror.yml
  templates/gitlab/jobs/oss/sync-sources.yml
)
hits=$(grep -RIn 'pypi\.org' "${RUNTIME_SCAN[@]}" 2>/dev/null | grep -vE '^\S+:\s*#|no pypi|No pypi|not.*pypi' || true)
if [[ -n "$hits" ]]; then
  echo "$hits"
  fail "pypi.org runtime reference in mirror upload/scan jobs"
else
  ok "no pypi.org in mirror runtime jobs"
fi

# Fuzz / DAST / kaniko must not apt-get
for f in "$FUZZ" scripts/run-schemathesis-mirror.sh scripts/run-dast-zap-api-mirror.sh; do
  if grep -nE 'apt-get|apk add' "$f" 2>/dev/null; then
    fail "apt/apk in $f"
  else
    ok "no apt/apk in $f"
  fi
done

# Image refs must go through $OSS_* / $NEXUS_* variables (override hosts via CI vars).
# Ban hardcoded host:port in image:/name: lines — defaults live only under variables:.
if grep -nE '^\s+(name|image):\s*.*nexus\.svo\.aero' "$PROFILE" | grep -vE '^\s*[0-9]+:\s*#' >/dev/null 2>&1; then
  grep -nE '^\s+(name|image):\s*.*nexus\.svo\.aero' "$PROFILE" || true
  fail "hardcoded nexus.svo.aero in image: lines — use \$OSS_*_IMAGE / \$NEXUS_DOCKER_*"
else
  ok "profile image: lines use variables (no hardcoded nexus host)"
fi

grep -q 'NEXUS_DOCKER_PREFIX:' "$PROFILE" || fail "profile must declare NEXUS_DOCKER_PREFIX"
grep -q 'NEXUS_DOCKER_GROUP:' "$PROFILE" || fail "profile must declare NEXUS_DOCKER_GROUP"
ok "profile declares NEXUS_DOCKER_PREFIX/GROUP"

# OSS image vars must be composed from Nexus prefixes (not public registries).
if ! grep -qE 'OSS_KANIKO_IMAGE:.*NEXUS_DOCKER_PREFIX' "$PROFILE"; then
  fail "OSS_KANIKO_IMAGE must reference \$NEXUS_DOCKER_PREFIX"
fi
ok "OSS_KANIKO_IMAGE composed from NEXUS_DOCKER_PREFIX"
grep -q 'build-kaniko.yml' "$PROFILE" || fail "profile must include build-kaniko.yml"
ok "profile includes build-kaniko"

grep -q 'kaniko-mirror-build' "$KANIKO" || fail "build must call kaniko-mirror-build.sh"
ok "kaniko-mirror-build wired"

if grep -nE 'docker:.*dind|DOCKER_HOST|mirror-build-image' "$KANIKO"; then
  fail "build-kaniko must be Kaniko-only (no dind/docker helper)"
else
  ok "Kaniko-only build job"
fi

if grep -q 'cxado-docker/kaniko-executor' "$PROFILE"; then
  ok "kaniko image pin in profile (kaniko-executor)"
elif grep -q 'cxado-docker/kaniko-mirror-helper' "$PROFILE"; then
  ok "kaniko image pin in profile (kaniko-mirror-helper)"
else
  fail "profile must use cxado-docker/kaniko-executor or cxado-docker/kaniko-mirror-helper image"
fi

grep -q 'cxado-docker/schemathesis' "$PROFILE" || fail "profile must use cxado-docker/schemathesis"
ok "schemathesis image pin in profile"

grep -q 'allow_failure: false' "$KANIKO" || fail "build must allow_failure: false"
ok "build hard-fail"

python3 - <<'PY' || fail "non-cleanup allow_failure:true in profile"
from pathlib import Path
text = Path("templates/profiles/oss-full-service-mirror.gitlab-ci.yml").read_text().splitlines()
job = None
for i, line in enumerate(text, 1):
    if line and not line.startswith(" ") and not line.startswith("#") and line.endswith(":"):
        job = line[:-1]
    if "allow_failure: true" in line and job not in ("cleanup-runner",):
        raise SystemExit(f"{job}:{i}")
print("ok")
PY
ok "profile hard-fail (only cleanup soft)"

grep -q 'BUILD_FALLBACK' scripts/kaniko-mirror-build.sh || fail "kaniko script missing BUILD_FALLBACK"
ok "BUILD_FALLBACK in kaniko script"

grep -q 'mirror-build-image.sh' scripts/point-copy-mirror.sh || fail "point-copy missing mirror-build-image.sh"
ok "point-copy lists mirror-build-image"

if grep -E '^exit 0$' scripts/resolve-mirror-service.sh; then
  fail "resolve-mirror-service.sh must not exit 0 (sourced from CI)"
else
  ok "resolve has no exit 0"
fi

grep -q 'hotfix' "$PROFILE" || fail "profile missing hotfix ban"
ok "hotfix workflow ban present"

if grep -q 'cleanup-runner.yml' "$PROFILE"; then
  fail "profile must not include cleanup-runner.yml (uses .oss_docker_job)"
else
  ok "no cleanup-runner.yml include"
fi

grep -q 'api-fuzz-schemathesis-mirror' "$PROFILE" || fail "profile missing schemathesis include"
ok "schemathesis included"
if grep -q '^upload-dast-to-dojo:' "$PROFILE" || grep -q '^upload-fuzz-to-dojo:' "$PROFILE"; then
  fail "legacy upload-*-to-dojo jobs must be removed (use after_script export)"
else
  ok "no legacy upload-*-to-dojo jobs"
fi
if grep -q 'aspm/upload-static.yml' "$PROFILE" || grep -q 'aspm/upload-image.yml' "$PROFILE"; then
  fail "legacy ASPM upload include templates must be removed from mirror profile"
else
  ok "no legacy ASPM upload includes in mirror profile"
fi
grep -q 'aspm/export-after-script.yml' "$PROFILE" || fail "mirror profile must include aspm/export-after-script.yml"
ok "aspm after_script include present"
grep -q 'aspm-html-report-mirror.yml' "$PROFILE" || fail "profile missing ASPM HTML include"
ok "ASPM HTML include present"
grep -q 'dfd-diagrams-mirror.yml' "$PROFILE" || fail "profile missing DFD include"
ok "DFD include present"

grep -q 'sync-sources.yml' "$PROFILE" || fail "profile missing sync-sources"
ok "sync-sources included"

grep -q 'GIT_CLEAN_FLAGS' "$PROFILE" || fail "mirror profile missing GIT_CLEAN_FLAGS"
ok "GIT_CLEAN_FLAGS present"

# Must not include docker build-push for mirror profile
if grep -q 'build-push.yml' "$PROFILE"; then
  fail "mirror profile still includes build-push.yml (use build-kaniko hybrid)"
else
  ok "no build-push in mirror profile"
fi

REG=config/mirror-services.yaml
[[ -f "$REG" ]] || fail "missing $REG"
services=$(awk '
  /^services:/{s=1; next}
  s && /^  [a-zA-Z0-9_]+:[[:space:]]*$/ { n=$1; sub(/:$/,"",n); print n }
  s && /^[^ ]/ { s=0 }
' "$REG")
for svc in $services; do
  out=$(CI_COMMIT_TAG="${svc}/v0.0.0-validate" MIRROR_SERVICES="$REG" sh scripts/resolve-mirror-service.sh --print 2>&1) || {
    fail "resolve failed for $svc: $out"
    continue
  }
  echo "$out" | grep -q "SERVICE_NAME=$svc" || fail "resolve print missing SERVICE_NAME=$svc ($out)"
  ok "resolve $svc"
  # API path without tag
  out2=$(SERVICE_NAME="$svc" SOURCE_REF="1.2.3" MIRROR_SERVICES="$REG" sh scripts/resolve-mirror-service.sh --print 2>&1) || {
    fail "resolve SERVICE_NAME-only failed for $svc: $out2"
    continue
  }
  echo "$out2" | grep -q "SOURCE_REF=1.2.3" || fail "API SOURCE_REF not honored ($out2)"
  ok "resolve API vars $svc"
done

for s in \
  scripts/mirror-inventory-services.py \
  scripts/mirror-baseline-trigger.sh \
  scripts/mirror-sync-sources.py \
  scripts/mirror-prune-hotfix-tags.sh \
  scripts/kaniko-mirror-build.sh \
  scripts/discover-openapi.sh \
  scripts/run-schemathesis-mirror.sh \
  scripts/run-dast-zap-api-mirror.sh \
  scripts/dfd-export-ci.sh
do
  [[ -f "$s" ]] || fail "missing $s"
  ok "present $s"
done

grep -q 'run-dast-zap-api-mirror.sh' scripts/point-copy-mirror.sh || fail "point-copy missing run-dast-zap-api-mirror.sh"
ok "point-copy lists run-dast-zap-api-mirror"

[[ -f scripts/mirror-fleet-trigger.py ]] || fail "missing mirror-fleet-trigger.py"
ok "fleet trigger present"
[[ -f scripts/lib/mirror_services.py ]] || fail "missing scripts/lib/mirror_services.py"
ok "mirror_services parser present"
[[ -f scripts/dojo-render-aspm-report.py ]] || fail "missing dojo-render-aspm-report.py"
ok "ASPM HTML renderer present"
[[ -f templates/reports/aspm-engagement-report.html.j2 ]] || fail "missing ASPM HTML template"
ok "ASPM HTML template present"
grep -q 'templates/reports/aspm-engagement-report.html.j2' scripts/point-copy-mirror.sh || fail "point-copy missing ASPM HTML template"
# Regression: dojo-render looks under templates/reports/, not reports/
if grep -A2 'templates/reports/\*' scripts/point-copy-mirror.sh | grep -q 'dest="\$TARGET/\${rel}"'; then
  ok "point-copy preserves templates/reports path"
else
  fail "point-copy must copy templates/reports/* to TARGET/templates/reports/*"
fi
grep -q 'mirror-fleet-trigger.py' scripts/point-copy-mirror.sh || fail "point-copy missing fleet trigger"
grep -q 'dojo-render-aspm-report.py' scripts/point-copy-mirror.sh || fail "point-copy missing dojo-render"
ok "point-copy lists fleet + HTML renderer"
grep -q 'templates/gitlab/jobs' scripts/point-copy-mirror.sh || fail "point-copy must copy templates/gitlab/jobs overlay"
ok "point-copy overlays templates/gitlab/jobs"

grep -q '^aspm-html-report:' "$ASPM_HTML_JOB" || fail "ASPM HTML job name missing"
grep -q 'allow_failure: false' "$ASPM_HTML_JOB" || fail "ASPM HTML job must hard-fail"
grep -q 'reports/aspm-report-\${SERVICE_NAME}.html' "$ASPM_HTML_JOB" || fail "ASPM HTML artifact path missing"
grep -q -- '--write-slices' "$ASPM_HTML_JOB" || fail "aspm-html job must pass --write-slices"
grep -q 'slices.json' "$ASPM_HTML_JOB" || fail "aspm-html artifacts must include slices.json"
ok "ASPM HTML job hard-fail + artifacts + slices"

grep -q '^dfd-diagrams-report:' "$DFD_JOB" || fail "DFD job name missing"
grep -q 'allow_failure: false' "$DFD_JOB" || fail "DFD job must hard-fail"
grep -q 'reports/dfd/\${SERVICE_NAME}/' "$DFD_JOB" || fail "DFD artifact path missing"
grep -q 'sh scripts/dfd-export-ci.sh' "$DFD_JOB" || fail "DFD job must call scripts/dfd-export-ci.sh"
if grep -q 'fallback' scripts/dfd-export-ci.sh; then
  fail "dfd-export-ci must not contain fallback path"
else
  ok "dfd-export-ci has no fallback path"
fi
if grep -Eq 'apt-get|graphviz|python3 diagrams/main.py|uv pip' scripts/dfd-export-ci.sh; then
  fail "dfd-export-ci must not bootstrap Graphviz/Python diagrams"
else
  ok "dfd-export-ci has no Graphviz/Python bootstrap"
fi
grep -q 'fabrica-diagrams-go' scripts/dfd-export-ci.sh || fail "dfd-export-ci must invoke fabrica-diagrams-go"
grep -q 'diagrams-go' scripts/point-copy-mirror.sh || fail "point-copy must include diagrams-go"
[[ -x diagrams-go/bin/fabrica-diagrams-go ]] || fail "missing diagrams-go/bin/fabrica-diagrams-go binary"
grep -q 'dfd_diagram.dot' scripts/dfd-export-ci.sh || fail "dfd-export-ci must require dfd_diagram.dot"
grep -q 'viz.js' scripts/dfd-export-ci.sh || fail "dfd-export-ci must require offline viz.js"
grep -q 'index.html' scripts/dfd-export-ci.sh || fail "dfd-export-ci must require index.html"
ok "DFD job hard-fail + Go binary path + artifacts"
python3 -c "
import sys
from pathlib import Path
sys.path.insert(0, 'scripts')
from lib.mirror_services import load_services, filter_services
svcs = load_services('testdata/mirror-services-fixture.yaml')
assert len(filter_services(svcs, enabled_only=True)) == 2
" || fail "mirror_services import/fixture failed"
ok "mirror_services fixture load"

[[ -f docs/runbooks/mirror-baseline-inventory.md ]] || fail "missing baseline runbook"
[[ -f docs/runbooks/mirror-api-trigger-schemathesis.md ]] || fail "missing API/fuzz runbook"
[[ -f docs/runbooks/mirror-registry-retention.md ]] || fail "missing retention runbook"
[[ -f docs/runbooks/mirror-binary-fuzz-backlog.md ]] || fail "missing T6 backlog doc"
ok "runbooks present"

heredoc_hits=$(grep -RIn --include='*.yml' -E '^python3 <<|^python <<' templates/gitlab/jobs templates/profiles 2>/dev/null || true)
if [[ -n "$heredoc_hits" ]]; then
  echo "$heredoc_hits"
  fail "col-0 python heredoc in job YAML — use external scripts"
else
  ok "no col-0 python heredoc in job YAML"
fi

[[ -f scripts/point-copy-mirror.sh ]] || fail "missing point-copy-mirror.sh"
ok "point-copy-mirror.sh present"

# Offline CISA KEV catalog (ASPM SSVC + future SARIF enrich)
[[ -f config/kev/cisa-kev.min.json ]] || fail "missing config/kev/cisa-kev.min.json"
[[ -f scripts/lib/kev_catalog.py ]] || fail "missing scripts/lib/kev_catalog.py"
[[ -f docs/runbooks/cisa-kev.md ]] || fail "missing docs/runbooks/cisa-kev.md"
grep -q 'config/kev/cisa-kev.min.json' scripts/point-copy-mirror.sh || fail "point-copy missing KEV catalog"
grep -q 'scripts/lib/kev_catalog.py' scripts/point-copy-mirror.sh || fail "point-copy missing kev_catalog.py"
grep -q 'kev-catalog\|kev_catalog\|cisa-kev' scripts/dojo-render-aspm-report.py || \
  fail "dojo-render must reference KEV catalog"
grep -q 'kev-catalog' templates/gitlab/jobs/oss/aspm-html-report-mirror.yml || \
  fail "aspm-html job must pass --kev-catalog"
grep -q 'kev-enrich-sarif.py' templates/gitlab/jobs/oss/trivy-osa.yml || \
  fail "trivy-osa must call kev-enrich-sarif.py"
grep -q 'kev-enrich-sarif.py' templates/gitlab/jobs/oss/trivy-sca.yml || \
  fail "trivy-sca must call kev-enrich-sarif.py"
grep -q 'trivy-osa-enrich' templates/gitlab/jobs/oss/trivy-osa.yml || \
  fail "trivy-osa-enrich job required (k8s trivy image has no python)"
grep -q 'trivy-sca-enrich' templates/gitlab/jobs/oss/trivy-sca.yml || \
  fail "trivy-sca-enrich job required (k8s trivy image has no python)"
grep -q 'vendor-aodb-log-tools' scripts/kaniko-mirror-build.sh || \
  fail "kaniko must vendor aodb-log-tools"
grep -q 'scripts/kev-enrich-sarif.py' scripts/point-copy-mirror.sh || \
  fail "point-copy missing kev-enrich-sarif.py"
[[ -f scripts/kev-enrich-sarif.py ]] || fail "missing scripts/kev-enrich-sarif.py"
ok "CISA KEV offline catalog wired"

# Offline FIRST EPSS
[[ -f config/epss/epss_scores.min.json.gz ]] || fail "missing config/epss/epss_scores.min.json.gz"
[[ -f config/epss/epss_meta.json ]] || fail "missing config/epss/epss_meta.json"
[[ -f scripts/lib/epss_catalog.py ]] || fail "missing scripts/lib/epss_catalog.py"
[[ -f docs/runbooks/epss-offline.md ]] || fail "missing docs/runbooks/epss-offline.md"
grep -q 'config/epss/epss_scores.min.json.gz' scripts/point-copy-mirror.sh || fail "point-copy missing EPSS catalog"
grep -q 'scripts/lib/epss_catalog.py' scripts/point-copy-mirror.sh || fail "point-copy missing epss_catalog.py"
grep -q 'epss-catalog\|epss_catalog\|epss_scores' scripts/dojo-render-aspm-report.py || \
  fail "dojo-render must reference EPSS catalog"
grep -q 'epss-catalog' templates/gitlab/jobs/oss/aspm-html-report-mirror.yml || \
  fail "aspm-html job must pass --epss-catalog"
grep -q 'epss-enrich-sarif.py' templates/gitlab/jobs/oss/trivy-osa.yml || \
  fail "trivy-osa must call epss-enrich-sarif.py"
grep -q 'epss-enrich-sarif.py' templates/gitlab/jobs/oss/trivy-sca.yml || \
  fail "trivy-sca must call epss-enrich-sarif.py"
grep -q 'scripts/epss-enrich-sarif.py' scripts/point-copy-mirror.sh || \
  fail "point-copy missing epss-enrich-sarif.py"
[[ -f scripts/epss-enrich-sarif.py ]] || fail "missing scripts/epss-enrich-sarif.py"
ok "FIRST EPSS offline catalog wired"

if [[ "$FAIL" -ne 0 ]]; then
  echo "validate-mirror-corp: FAILED"
  exit 1
fi
echo "validate-mirror-corp: OK"
exit 0
