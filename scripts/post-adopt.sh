#!/usr/bin/env bash
# Post-adopt patches: stack detection, policy wiring, sast job selection.
set -euo pipefail

TARGET="${1:?target directory required}"
PYTHON_STACK="${2:-auto}"
POLICY_MODE="${3:-adopt}"
DRY_RUN="${4:-0}"

log() { echo "post-adopt: $*" >&2; }

warn() { echo "post-adopt WARNING: $*" >&2; }

patch_file() {
  local file="$1"
  shift
  [[ -f "$file" ]] || return 0
  if [[ "$DRY_RUN" == "1" ]]; then
    log "would patch $file: $*"
    return 0
  fi
  "$@"
  log "patched $file"
}

detect_stack() {
  local stack="$PYTHON_STACK"
  if [[ "$stack" == "auto" ]]; then
    if [[ -f "$TARGET/uv.lock" ]]; then
      stack="uv"
    elif [[ -f "$TARGET/package.json" && ! -f "$TARGET/pyproject.toml" ]]; then
      stack="node"
    else
      stack="pip"
    fi
    log "auto-detected stack: $stack"
  fi
  echo "$stack"
}

set_sast_job() {
  local job="$1"
  local wf
  for wf in \
    "$TARGET/.github/workflows/ci-profile.yml" \
    "$TARGET/.github/workflows/ci.yml" \
    "$TARGET/.github/workflows/security-shift-left.yml"; do
    [[ -f "$wf" ]] || continue
    if grep -q 'uses:.*security-gates.yml' "$wf" 2>/dev/null; then
      if grep -q 'sast_job:' "$wf"; then
        patch_file "$wf" sed -i "s/sast_job: .*/sast_job: $job/" "$wf"
      elif grep -q 'security_policy:' "$wf"; then
        patch_file "$wf" sed -i "/security_policy:/a\\      sast_job: $job" "$wf"
      else
        patch_file "$wf" sed -i "/uses:.*security-gates.yml/a\\    with:\\n      sast_job: $job" "$wf"
      fi
    fi
  done
}

set_policy_ref() {
  local policy="$1"
  local wf
  for wf in \
    "$TARGET/.github/workflows/ci-profile.yml" \
    "$TARGET/.github/workflows/ci.yml" \
    "$TARGET/.github/workflows/security-shift-left.yml"; do
    [[ -f "$wf" ]] || continue
    if grep -q 'security_policy:' "$wf"; then
      patch_file "$wf" sed -i "s|security_policy: .*|security_policy: $policy|" "$wf"
    fi
  done

  if [[ -f "$TARGET/.gitlab-ci.yml" ]]; then
    if grep -q 'SECURITY_POLICY:' "$TARGET/.gitlab-ci.yml"; then
      patch_file "$TARGET/.gitlab-ci.yml" sed -i "s|SECURITY_POLICY:.*|SECURITY_POLICY: \"$policy\"|" "$TARGET/.gitlab-ci.yml"
    fi
  fi
}

STACK="$(detect_stack)"

case "$STACK" in
  uv)
    set_sast_job "sast-python"
    ;;
  pip)
    set_sast_job "sast"
    ;;
  node)
    warn "Node/TypeScript stack detected — consider profile oss-full-node"
    ;;
  *)
    warn "unknown python-stack: $STACK"
    ;;
esac

case "$POLICY_MODE" in
  adopt)
    if [[ -f "$TARGET/config/security-gate-policy-node-k3s-adopt.yaml" ]] \
      && grep -q 'oss-full-node-k3s\|node-k3s-adopt' "$TARGET/.gitlab-ci.yml" 2>/dev/null; then
      set_policy_ref "config/security-gate-policy-node-k3s-adopt.yaml"
    else
      set_policy_ref "config/security-gate-policy-adopt.yaml"
    fi
    ;;
  strict)
    set_policy_ref "config/security-gate-policy.yaml"
    ;;
  *)
    warn "unknown policy mode: $POLICY_MODE"
    ;;
esac

log "done (stack=$STACK policy=$POLICY_MODE)"
