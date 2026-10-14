#!/usr/bin/env bash
# Point-copy Fabrica mirror templates into a target (or pack a tarball).
# Prefer this over adopt.sh when target already has .gitlab/jobs/.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TARGET=""
PACK=""
DRY_RUN=0

usage() {
  cat <<'EOF'
Usage:
  point-copy-mirror.sh --target DIR [--dry-run]
  point-copy-mirror.sh --pack FILE.tgz

Copies mirror-critical templates/scripts/config into TARGET:
  - .gitlab-ci.yml from oss-full-service-mirror (includes rewritten)
  - .gitlab/jobs/** from templates/gitlab/jobs (overlay)
  - scripts/ + config/ pieces used by mirror profile

EOF
  exit 1
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --target) TARGET="$2"; shift 2 ;;
    --pack) PACK="$2"; shift 2 ;;
    --dry-run) DRY_RUN=1; shift ;;
    -h|--help) usage ;;
    *) echo "Unknown: $1"; usage ;;
  esac
done

FILES=(
  templates/profiles/oss-full-service-mirror.gitlab-ci.yml
  templates/gitlab/jobs
  config/mirror-services.yaml
  config/security-gate-policy-adopt.yaml
  config/aspm-export.yaml
  config/mirror-deploy
  config/semgrep
  scripts/resolve-mirror-service.sh
  scripts/mirror-build-image.sh
  scripts/kaniko-mirror-build.sh
  scripts/discover-openapi.sh
  scripts/run-schemathesis-mirror.sh
  scripts/run-dast-zap-api-mirror.sh
  scripts/dfd-export-ci.sh
  diagrams-go
  scripts/mirror-sync-sources.py
  scripts/mirror-fleet-trigger.py
  scripts/gen-mirror-deploy-env.py
  scripts/mirror-baseline-trigger.sh
  scripts/mirror-inventory-services.py
  scripts/lib/mirror_services.py
  scripts/lib/kev_catalog.py
  scripts/lib/epss_catalog.py
  scripts/lib/__init__.py
  scripts/dojo-render-aspm-report.py
  config/kev/cisa-kev.min.json
  config/epss/epss_scores.min.json.gz
  config/epss/epss_meta.json
  templates/reports/aspm-engagement-report.html.j2
  docs/runbooks/cisa-kev.md
  docs/runbooks/epss-offline.md
  scripts/docker-host-bootstrap.sh
  scripts/registry-resolve-env.sh
  scripts/registry-login.sh
  scripts/registry-auth-env.sh
  scripts/fetch-source-archive.sh
  scripts/fetch-source-archive.py
  scripts/pip-index-auth.sh
  scripts/gate-check.py
  scripts/kev-enrich-sarif.py
  scripts/epss-enrich-sarif.py
  scripts/aspm-export.py
  scripts/aspm-export-ci.sh
  scripts/deploy-test-k8s.sh
  scripts/cleanup-test-k8s.sh
  scripts/ci-ephemeral-stub-server.py
  scripts/synthesize-ruff-sarif.py
  scripts/synthesize-bandit-sarif.py
  scripts/merge-hadolint-json.py
)

if [[ -n "$PACK" ]]; then
  tar czf "$PACK" -C "$ROOT" "${FILES[@]}"
  echo "packed $PACK"
  exit 0
fi

[[ -n "$TARGET" ]] || usage
[[ -d "$TARGET" ]] || { echo "Target not found: $TARGET"; exit 1; }

apply_one() {
  local rel="$1"
  local src="$ROOT/$rel"
  local dest
  if [[ "$rel" == "templates/profiles/oss-full-service-mirror.gitlab-ci.yml" ]]; then
    dest="$TARGET/.gitlab-ci.yml"
  elif [[ "$rel" == templates/gitlab/jobs ]]; then
    dest="$TARGET/.gitlab/jobs"
  elif [[ "$rel" == templates/reports/* ]]; then
    # Keep templates/reports/... — dojo-render expects FABRICA_ROOT/templates/reports/
    dest="$TARGET/${rel}"
  elif [[ "$rel" == config/* || "$rel" == scripts/* || "$rel" == diagrams-go || "$rel" == diagrams-go/* ]]; then
    dest="$TARGET/${rel}"
  else
    dest="$TARGET/${rel#templates/}"
  fi
  if [[ "$DRY_RUN" -eq 1 ]]; then
    echo "COPY $rel -> $dest"
    return
  fi
  mkdir -p "$(dirname "$dest")"
  if [[ -d "$src" ]]; then
    mkdir -p "$dest"
    # Overlay contents without nesting jobs/jobs when dest exists.
    cp -a "$src"/. "$dest"/
  else
    cp -a "$src" "$dest"
  fi
}

for f in "${FILES[@]}"; do
  apply_one "$f"
done

if [[ "$DRY_RUN" -eq 1 ]]; then
  echo "dry-run ok"
  exit 0
fi

# Rewrite includes for local mirror layout.
TARGET="$TARGET" python3 - <<'PY'
from pathlib import Path
import os
p = Path(os.environ["TARGET"]) / ".gitlab-ci.yml"
text = p.read_text()
text = text.replace("local: '/templates/gitlab/jobs/", "local: '.gitlab/jobs/")
p.write_text(text)
try:
    import yaml
    yaml.safe_load(p.read_text())
    print("yaml ok (PyYAML):", p)
except ImportError:
    t = p.read_text()
    if "local: '/templates/gitlab/jobs/" in t:
        raise SystemExit("include rewrite failed")
    if "stages:" not in t:
        raise SystemExit("missing stages:")
    print("yaml rewrite ok (no PyYAML):", p)
PY

chmod +x "$TARGET"/scripts/*.sh 2>/dev/null || true
echo "point-copy done -> $TARGET"
