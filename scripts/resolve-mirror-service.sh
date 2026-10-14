#!/usr/bin/env sh
# Resolve SERVICE_* for mirror CI.
# Env in (either):
#   CI_COMMIT_TAG = service/vX.Y.Z…  OR
#   SERVICE_NAME + optional SOURCE_REF (API/schedule pipelines)
# Env out: SERVICE_NAME SOURCE_REPO_URL SOURCE_PROJECT_ID SOURCE_REF_FALLBACK
#          DEFECTDOJO_PRODUCT_NAME OPENAPI_PATH API_BASE_URL SERVICE_PORT
#          DEPLOY_COMMAND DEPLOY_WORKDIR READINESS_PATH DEPLOY_ENV_FILE
#          DEPLOY_STUBS API_PATH_PREFIX SKIP_API_SECURITY SKIP_DEPLOY (optional)
set -eu

PRINT=0
case "${1:-}" in
  --print) PRINT=1 ;;
esac

REG="${MIRROR_SERVICES:-config/mirror-services.yaml}"
if [ ! -f "$REG" ]; then
  echo "[resolve] ERROR: missing registry $REG" >&2
  exit 1
fi

TAG="${CI_COMMIT_TAG:-}"
if [ -n "$TAG" ]; then
  case "$TAG" in
    *-hotfix*)
      echo "[resolve] WARN: hotfix tag '$TAG' — prefer API variables (SERVICE_NAME+SOURCE_REF)" >&2
      ;;
  esac
  SERVICE_NAME="${TAG%%/*}"
  if [ -z "$SERVICE_NAME" ] || [ "$SERVICE_NAME" = "$TAG" ]; then
    echo "[resolve] ERROR: tag must be <service>/v… (got: $TAG)" >&2
    exit 1
  fi
elif [ -n "${SERVICE_NAME:-}" ]; then
  :
else
  echo "[resolve] ERROR: set CI_COMMIT_TAG or SERVICE_NAME" >&2
  exit 1
fi

_awk_extract() {
  service="$1"
  awk -v svc="$service" '
    BEGIN {
      in_svc=0; pid=""; url=""; fb=""; oapi=""; abase=""; sport=""
      dcmd=""; dwd=""; rpath=""; denv=""; dstubs=""; apref=""
      skipapi=""; btarget=""
    }
    /^services:[[:space:]]*$/ { next }
    /^[[:space:]]+[A-Za-z0-9_]+:[[:space:]]*$/ {
      name=$1; sub(/:$/, "", name); gsub(/^[[:space:]]+/, "", name)
      if (name == svc) { in_svc=1; next }
      if (in_svc) { in_svc=0 }
    }
    in_svc && /project_id:/ && $0 !~ /^[[:space:]]*#/ {
      line=$0; sub(/.*project_id:[[:space:]]*/, "", line)
      gsub(/["'\'']/, "", line); gsub(/[[:space:]]+$/, "", line); pid=line
    }
    in_svc && /repo_url:/ && $0 !~ /^[[:space:]]*#/ {
      line=$0; sub(/.*repo_url:[[:space:]]*/, "", line)
      gsub(/["'\'']/, "", line); gsub(/[[:space:]]+$/, "", line); url=line
    }
    in_svc && /source_ref_fallback:/ && $0 !~ /^[[:space:]]*#/ {
      line=$0; sub(/.*source_ref_fallback:[[:space:]]*/, "", line)
      gsub(/["'\'']/, "", line); gsub(/[[:space:]]+$/, "", line); fb=line
    }
    in_svc && /openapi_path:/ && $0 !~ /^[[:space:]]*#/ {
      line=$0; sub(/.*openapi_path:[[:space:]]*/, "", line)
      gsub(/["'\'']/, "", line); gsub(/[[:space:]]+$/, "", line); oapi=line
    }
    in_svc && /api_base_url:/ && $0 !~ /^[[:space:]]*#/ {
      line=$0; sub(/.*api_base_url:[[:space:]]*/, "", line)
      gsub(/["'\'']/, "", line); gsub(/[[:space:]]+$/, "", line); abase=line
    }
    in_svc && /service_port:/ && $0 !~ /^[[:space:]]*#/ {
      line=$0; sub(/.*service_port:[[:space:]]*/, "", line)
      gsub(/["'\'']/, "", line); gsub(/[[:space:]]+$/, "", line); sport=line
    }
    in_svc && /deploy_command:/ && $0 !~ /^[[:space:]]*#/ {
      line=$0; sub(/.*deploy_command:[[:space:]]*/, "", line)
      gsub(/^["'\'']|["'\'']$/, "", line); gsub(/[[:space:]]+$/, "", line); dcmd=line
    }
    in_svc && /deploy_workdir:/ && $0 !~ /^[[:space:]]*#/ {
      line=$0; sub(/.*deploy_workdir:[[:space:]]*/, "", line)
      gsub(/["'\'']/, "", line); gsub(/[[:space:]]+$/, "", line); dwd=line
    }
    in_svc && /readiness_path:/ && $0 !~ /^[[:space:]]*#/ {
      line=$0; sub(/.*readiness_path:[[:space:]]*/, "", line)
      gsub(/["'\'']/, "", line); gsub(/[[:space:]]+$/, "", line); rpath=line
    }
    in_svc && /deploy_env_file:/ && $0 !~ /^[[:space:]]*#/ {
      line=$0; sub(/.*deploy_env_file:[[:space:]]*/, "", line)
      gsub(/["'\'']/, "", line); gsub(/[[:space:]]+$/, "", line); denv=line
    }
    in_svc && /deploy_stubs:/ && $0 !~ /^[[:space:]]*#/ {
      line=$0; sub(/.*deploy_stubs:[[:space:]]*/, "", line)
      gsub(/["'\'']/, "", line); gsub(/[[:space:]]+$/, "", line); dstubs=line
    }
    in_svc && /api_path_prefix:/ && $0 !~ /^[[:space:]]*#/ {
      line=$0; sub(/.*api_path_prefix:[[:space:]]*/, "", line)
      gsub(/["'\'']/, "", line); gsub(/[[:space:]]+$/, "", line); apref=line
    }
    in_svc && /skip_api_security:/ && $0 !~ /^[[:space:]]*#/ {
      line=$0; sub(/.*skip_api_security:[[:space:]]*/, "", line)
      gsub(/["'\'']/, "", line); gsub(/[[:space:]]+$/, "", line); skipapi=line
    }
    in_svc && /build_docker_target:/ && $0 !~ /^[[:space:]]*#/ {
      line=$0; sub(/.*build_docker_target:[[:space:]]*/, "", line)
      gsub(/["'\'']/, "", line); gsub(/[[:space:]]+$/, "", line); btarget=line
    }
    END {
      if (pid == "" || url == "") { exit 2 }
      print pid "\t" url "\t" fb "\t" oapi "\t" abase "\t" sport "\t" dcmd "\t" dwd "\t" rpath "\t" denv "\t" dstubs "\t" apref "\t" skipapi "\t" btarget
    }
  ' "$REG"
}

ROW=$(_awk_extract "$SERVICE_NAME") || {
  echo "[resolve] ERROR: unknown service '$SERVICE_NAME' (not in $REG)" >&2
  exit 1
}

SOURCE_PROJECT_ID=$(printf '%s' "$ROW" | cut -f1)
SOURCE_REPO_URL=$(printf '%s' "$ROW" | cut -f2)
SOURCE_REF_FALLBACK=$(printf '%s' "$ROW" | cut -f3)
_YAML_OPENAPI=$(printf '%s' "$ROW" | cut -f4)
_YAML_API_BASE=$(printf '%s' "$ROW" | cut -f5)
_YAML_SERVICE_PORT=$(printf '%s' "$ROW" | cut -f6)
_YAML_DEPLOY_COMMAND=$(printf '%s' "$ROW" | cut -f7)
_YAML_DEPLOY_WORKDIR=$(printf '%s' "$ROW" | cut -f8)
_YAML_READINESS_PATH=$(printf '%s' "$ROW" | cut -f9)
_YAML_DEPLOY_ENV_FILE=$(printf '%s' "$ROW" | cut -f10)
_YAML_DEPLOY_STUBS=$(printf '%s' "$ROW" | cut -f11)
_YAML_API_PATH_PREFIX=$(printf '%s' "$ROW" | cut -f12)
_YAML_SKIP_API=$(printf '%s' "$ROW" | cut -f13)
_YAML_BUILD_TARGET=$(printf '%s' "$ROW" | cut -f14)
DEFECTDOJO_PRODUCT_NAME="$SERVICE_NAME"

SKIP_API_SECURITY="${SKIP_API_SECURITY:-}"
if [ -z "$SKIP_API_SECURITY" ] && [ -n "${_YAML_SKIP_API:-}" ]; then
  case "${_YAML_SKIP_API}" in
    true|True|TRUE|1|yes|Yes|YES) SKIP_API_SECURITY=true ;;
    *) SKIP_API_SECURITY=false ;;
  esac
fi

if [ -n "${_YAML_BUILD_TARGET:-}" ] && [ -z "${BUILD_DOCKER_TARGET:-}" ]; then
  BUILD_DOCKER_TARGET="$_YAML_BUILD_TARGET"
fi

SKIP_DEPLOY="${SKIP_DEPLOY:-false}"
if [ "$SKIP_API_SECURITY" = "true" ]; then
  SKIP_DEPLOY=true
fi

if [ -z "${OPENAPI_PATH:-}" ] && [ -n "${_YAML_OPENAPI:-}" ]; then
  OPENAPI_PATH="$_YAML_OPENAPI"
fi
if [ -z "${API_BASE_URL:-}" ] && [ -n "${_YAML_API_BASE:-}" ]; then
  API_BASE_URL="$_YAML_API_BASE"
fi
if [ -z "${SERVICE_PORT:-}" ] && [ -n "${_YAML_SERVICE_PORT:-}" ]; then
  SERVICE_PORT="$_YAML_SERVICE_PORT"
fi
SERVICE_PORT="${SERVICE_PORT:-8000}"

if [ -z "${DEPLOY_COMMAND:-}" ] && [ -n "${_YAML_DEPLOY_COMMAND:-}" ]; then
  DEPLOY_COMMAND="$_YAML_DEPLOY_COMMAND"
fi
if [ -z "${DEPLOY_WORKDIR:-}" ] && [ -n "${_YAML_DEPLOY_WORKDIR:-}" ]; then
  DEPLOY_WORKDIR="$_YAML_DEPLOY_WORKDIR"
fi
if [ -z "${READINESS_PATH:-}" ] && [ -n "${_YAML_READINESS_PATH:-}" ]; then
  READINESS_PATH="$_YAML_READINESS_PATH"
fi
if [ -z "${DEPLOY_ENV_FILE:-}" ] && [ -n "${_YAML_DEPLOY_ENV_FILE:-}" ]; then
  DEPLOY_ENV_FILE="$_YAML_DEPLOY_ENV_FILE"
fi
if [ -n "${DEPLOY_ENV_FILE:-}" ] && [ ! -f "$DEPLOY_ENV_FILE" ]; then
  echo "[resolve] WARN: deploy_env_file missing on disk: $DEPLOY_ENV_FILE — SKIP_DEPLOY=true" >&2
  SKIP_DEPLOY=true
fi
if [ -z "${DEPLOY_STUBS:-}" ] && [ -n "${_YAML_DEPLOY_STUBS:-}" ]; then
  DEPLOY_STUBS="$_YAML_DEPLOY_STUBS"
fi
if [ -z "${API_PATH_PREFIX:-}" ] && [ -n "${_YAML_API_PATH_PREFIX:-}" ]; then
  API_PATH_PREFIX="$_YAML_API_PATH_PREFIX"
fi
# Normalize: leading slash, no trailing slash (empty stays empty).
if [ -n "${API_PATH_PREFIX:-}" ]; then
  case "$API_PATH_PREFIX" in
    /*) ;;
    *) API_PATH_PREFIX="/$API_PATH_PREFIX" ;;
  esac
  while [ "${API_PATH_PREFIX%/}" != "$API_PATH_PREFIX" ]; do
    API_PATH_PREFIX="${API_PATH_PREFIX%/}"
  done
fi

if [ -z "${SOURCE_REF:-}" ]; then
  if [ -n "$TAG" ]; then
    SOURCE_REF="$TAG"
  else
    SOURCE_REF="${SOURCE_REF_FALLBACK:-}"
  fi
fi

export SERVICE_NAME SOURCE_REPO_URL SOURCE_PROJECT_ID SOURCE_REF_FALLBACK DEFECTDOJO_PRODUCT_NAME
export SOURCE_REF SERVICE_PORT
if [ -n "${OPENAPI_PATH:-}" ]; then
  export OPENAPI_PATH
fi
if [ -n "${API_BASE_URL:-}" ]; then
  export API_BASE_URL
fi
if [ -n "${DEPLOY_COMMAND:-}" ]; then
  export DEPLOY_COMMAND
fi
if [ -n "${DEPLOY_WORKDIR:-}" ]; then
  export DEPLOY_WORKDIR
fi
if [ -n "${READINESS_PATH:-}" ]; then
  export READINESS_PATH
fi
if [ -n "${DEPLOY_ENV_FILE:-}" ]; then
  export DEPLOY_ENV_FILE
fi
if [ -n "${DEPLOY_STUBS:-}" ]; then
  export DEPLOY_STUBS
fi
if [ -n "${API_PATH_PREFIX:-}" ]; then
  export API_PATH_PREFIX
fi
if [ -n "${BUILD_DOCKER_TARGET:-}" ]; then
  export BUILD_DOCKER_TARGET
fi
export SKIP_API_SECURITY="${SKIP_API_SECURITY:-false}"
export SKIP_DEPLOY="${SKIP_DEPLOY:-false}"

echo "[resolve] service=$SERVICE_NAME project_id=$SOURCE_PROJECT_ID product=$DEFECTDOJO_PRODUCT_NAME SOURCE_REF=${SOURCE_REF:-none} fallback=${SOURCE_REF_FALLBACK:-none} skip_api=$SKIP_API_SECURITY skip_deploy=$SKIP_DEPLOY"

if [ "$PRINT" = 1 ]; then
  printf 'export SERVICE_NAME=%s\n' "$SERVICE_NAME"
  printf 'export SOURCE_PROJECT_ID=%s\n' "$SOURCE_PROJECT_ID"
  printf 'export SOURCE_REPO_URL=%s\n' "$SOURCE_REPO_URL"
  printf 'export SOURCE_REF_FALLBACK=%s\n' "$SOURCE_REF_FALLBACK"
  printf 'export SOURCE_REF=%s\n' "$SOURCE_REF"
  printf 'export DEFECTDOJO_PRODUCT_NAME=%s\n' "$DEFECTDOJO_PRODUCT_NAME"
  printf 'export SERVICE_PORT=%s\n' "$SERVICE_PORT"
  if [ -n "${OPENAPI_PATH:-}" ]; then
    printf 'export OPENAPI_PATH=%s\n' "$OPENAPI_PATH"
  fi
  if [ -n "${API_BASE_URL:-}" ]; then
    printf 'export API_BASE_URL=%s\n' "$API_BASE_URL"
  fi
  if [ -n "${DEPLOY_COMMAND:-}" ]; then
    printf 'export DEPLOY_COMMAND=%s\n' "$DEPLOY_COMMAND"
  fi
  if [ -n "${DEPLOY_WORKDIR:-}" ]; then
    printf 'export DEPLOY_WORKDIR=%s\n' "$DEPLOY_WORKDIR"
  fi
  if [ -n "${READINESS_PATH:-}" ]; then
    printf 'export READINESS_PATH=%s\n' "$READINESS_PATH"
  fi
  if [ -n "${DEPLOY_ENV_FILE:-}" ]; then
    printf 'export DEPLOY_ENV_FILE=%s\n' "$DEPLOY_ENV_FILE"
  fi
  if [ -n "${API_PATH_PREFIX:-}" ]; then
    printf 'export API_PATH_PREFIX=%s\n' "$API_PATH_PREFIX"
  fi
  if [ -n "${BUILD_DOCKER_TARGET:-}" ]; then
    printf 'export BUILD_DOCKER_TARGET=%s\n' "$BUILD_DOCKER_TARGET"
  fi
  printf 'export SKIP_API_SECURITY=%s\n' "${SKIP_API_SECURITY:-false}"
  printf 'export SKIP_DEPLOY=%s\n' "${SKIP_DEPLOY:-false}"
fi
# Do NOT exit — this file is sourced from CI before_script (. script).
