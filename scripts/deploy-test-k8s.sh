#!/usr/bin/env sh
# Deploy ephemeral test instance of a mirror service into k8s for DAST/fuzz.
# Outputs deploy.env with API_BASE_URL (and OPENAPI_PATH if fetched live).
#
# Required env:
#   SERVICE_NAME    — e.g. data_lake_service
#   BUILT_IMAGE     — from build.env artifact (set by build-image job)
#   CI_PIPELINE_ID  — set by GitLab CI
#
# Optional env (from resolve-mirror-service / mirror-services.yaml):
#   SERVICE_PORT       — container port (default 8000)
#   OPENAPI_PATH       — if set, skip live-fetch of /openapi.json
#   BUILD_FALLBACK     — if 1, skip deploy (base image, not app image)
#   READINESS_PATH     — HTTP readiness path (default /openapi.json)
#   DEPLOY_COMMAND     — override container command (shell-split into argv)
#   DEPLOY_WORKDIR     — container workingDir
#   DEPLOY_ENV_FILE    — KEY=VALUE file → ConfigMap + envFrom
#
# Corp offline: no apt/apk. Uses kubectl from image.
set -eu

if [ "${BUILD_FALLBACK:-0}" = "1" ]; then
  echo "[deploy] ERROR — BUILD_FALLBACK=1 (image is base, not app). Failing because you requested a real run."
  printf 'API_BASE_URL=\nDEPLOY_SKIPPED=1\n' > deploy.env || true
  exit 1
fi

SVC="${SERVICE_NAME:?SERVICE_NAME is required}"
# K8s DNS-1035 / RFC1123: underscores illegal — map data_lake_service → data-lake-service
K8S_NAME=$(printf '%s' "$SVC" | tr '[:upper:]_' '[:lower:]-' | sed 's/[^a-z0-9.-]/-/g; s/--*/-/g; s/^-//; s/-$//' )
if [ -z "$K8S_NAME" ]; then
  echo "[deploy] ERROR: empty K8S_NAME from SERVICE_NAME=$SVC" >&2
  exit 1
fi
if [ -z "${BUILT_IMAGE:-}" ] && [ -n "${IMAGE_TAG:-}" ] && [ "${IMAGE_TAG}" != "none" ] && [ -n "${REGISTRY:-}" ]; then
  BUILT_IMAGE="${REGISTRY}:${IMAGE_TAG}"
fi
IMG="${BUILT_IMAGE:?BUILT_IMAGE is required (from build.env BUILT_IMAGE or REGISTRY:IMAGE_TAG)}"
PORT="${SERVICE_PORT:-8000}"
NS="ci-test-${CI_PIPELINE_ID:?CI_PIPELINE_ID is required}"
READINESS_PATH="${READINESS_PATH:-/openapi.json}"
DEPLOY_WORKDIR="${DEPLOY_WORKDIR:-}"
DEPLOY_COMMAND="${DEPLOY_COMMAND:-}"
DEPLOY_ENV_FILE="${DEPLOY_ENV_FILE:-}"
DEPLOY_STUBS="${DEPLOY_STUBS:-}"
NEXUS_DOCKER_PREFIX="${NEXUS_DOCKER_PREFIX:-nexus.svo.aero:8345}"
NEXUS_DOCKER_GROUP="${NEXUS_DOCKER_GROUP:-nexus.svo.aero:8374}"
OSS_PYTHON_IMAGE="${OSS_PYTHON_IMAGE:-${NEXUS_DOCKER_PREFIX}/library/python:3.11.11-slim-bookworm}"
OSS_MONGO_IMAGE="${OSS_MONGO_IMAGE:-${NEXUS_DOCKER_PREFIX}/library/mongo:6}"
OSS_POSTGRES_IMAGE="${OSS_POSTGRES_IMAGE:-${NEXUS_DOCKER_PREFIX}/library/postgres:16}"
OSS_REDIS_IMAGE="${OSS_REDIS_IMAGE:-${NEXUS_DOCKER_PREFIX}/library/redis:7-alpine}"

echo "[deploy] service=$SVC k8s_name=$K8S_NAME image=$IMG port=$PORT ns=$NS readiness=$READINESS_PATH"
echo "[deploy] workdir=${DEPLOY_WORKDIR:-<image default>} command=${DEPLOY_COMMAND:-<image CMD>}"
echo "[deploy] env_file=${DEPLOY_ENV_FILE:-<none>} stubs=${DEPLOY_STUBS:-<none>}"

# Create namespace (idempotent).
kubectl create namespace "$NS" --dry-run=client -o yaml | kubectl apply -f -

# Pull secrets for GitLab registry (BUILT_IMAGE) and Nexus (base layers if needed).
PULL_SECRETS=""
REG_HOST="${CI_REGISTRY:-registry.svo.aero:443}"
REG_USER="${CI_REGISTRY_USER:-gitlab-ci-token}"
REG_PASS="${CI_REGISTRY_PASSWORD:-${CI_JOB_TOKEN:-}}"
if [ -n "$REG_PASS" ]; then
  kubectl create secret docker-registry gitlab-registry \
    --namespace="$NS" \
    --docker-server="$REG_HOST" \
    --docker-username="$REG_USER" \
    --docker-password="$REG_PASS" \
    --dry-run=client -o yaml | kubectl apply -f -
  PULL_SECRETS="${PULL_SECRETS}
        - name: gitlab-registry"
  echo "[deploy] created pull secret gitlab-registry for $REG_HOST"
else
  echo "[deploy] ERROR: CI_REGISTRY_PASSWORD/CI_JOB_TOKEN unset — cannot pull $IMG" >&2
  printf 'API_BASE_URL=\nDEPLOY_SKIPPED=1\n' > deploy.env
  exit 1
fi

if [ -n "${NEXUS_USER:-}" ] && [ -n "${NEXUS_PASSWORD:-}" ]; then
  kubectl create secret docker-registry nexus-registry \
    --namespace="$NS" \
    --docker-server="$NEXUS_DOCKER_PREFIX" \
    --docker-username="$NEXUS_USER" \
    --docker-password="$NEXUS_PASSWORD" \
    --dry-run=client -o yaml | kubectl apply -f -
  PULL_SECRETS="${PULL_SECRETS}
        - name: nexus-registry"
  echo "[deploy] created pull secret nexus-registry for $NEXUS_DOCKER_PREFIX"
fi

# Optional ConfigMap from KEY=VALUE file (comments/# blank ignored).
ENV_FROM_BLOCK=""
CM_NAME="${K8S_NAME}-config"
if [ -n "$DEPLOY_ENV_FILE" ] && [ -f "$DEPLOY_ENV_FILE" ]; then
  # Print keys only (no values) for diagnostics.
  KEYS=$(awk -F= '/^[[:space:]]*#/ {next} /^[[:space:]]*$/ {next} {print $1}' "$DEPLOY_ENV_FILE" | tr '\n' ' ')
  echo "[deploy] ConfigMap keys: $KEYS"
  kubectl create configmap "$CM_NAME" \
    --namespace="$NS" \
    --from-env-file="$DEPLOY_ENV_FILE" \
    --dry-run=client -o yaml | kubectl apply -f -
  ENV_FROM_BLOCK="
          envFrom:
            - configMapRef:
                name: $CM_NAME"
elif [ -n "$DEPLOY_ENV_FILE" ]; then
  echo "[deploy] WARN: DEPLOY_ENV_FILE=$DEPLOY_ENV_FILE missing — deploying without ConfigMap"
fi

# Optional in-namespace stubs (data_lake lifespan needs auth + mongo).
case ",${DEPLOY_STUBS}," in
  *,mongo,*)
    echo "[deploy] deploying mongo stub ($OSS_MONGO_IMAGE)"
    kubectl apply -n "$NS" -f - <<MONGO
apiVersion: apps/v1
kind: Deployment
metadata:
  name: mongo
  namespace: $NS
spec:
  replicas: 1
  selector:
    matchLabels:
      app: mongo
  template:
    metadata:
      labels:
        app: mongo
    spec:
      imagePullSecrets:$PULL_SECRETS
      containers:
        - name: mongo
          image: $OSS_MONGO_IMAGE
          imagePullPolicy: IfNotPresent
          ports:
            - containerPort: 27017
          env:
            - name: MONGO_INITDB_ROOT_USERNAME
              value: root
            - name: MONGO_INITDB_ROOT_PASSWORD
              value: example
---
apiVersion: v1
kind: Service
metadata:
  name: mongo
  namespace: $NS
spec:
  selector:
    app: mongo
  ports:
    - port: 27017
      targetPort: 27017
MONGO
    echo "[deploy] waiting for mongo..."
    kubectl rollout status deployment/mongo -n "$NS" --timeout=180s
    ;;
esac

case ",${DEPLOY_STUBS}," in
  *,http,*)
    STUB_PY="scripts/ci-ephemeral-stub-server.py"
    if [ ! -f "$STUB_PY" ]; then
      echo "[deploy] ERROR: missing $STUB_PY" >&2
      exit 1
    fi
    echo "[deploy] deploying ci-http-stub ($OSS_PYTHON_IMAGE)"
    kubectl create configmap ci-http-stub-code \
      --namespace="$NS" \
      --from-file=stub.py="$STUB_PY" \
      --dry-run=client -o yaml | kubectl apply -f -
    kubectl apply -n "$NS" -f - <<STUB
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ci-http-stub
  namespace: $NS
spec:
  replicas: 1
  selector:
    matchLabels:
      app: ci-http-stub
  template:
    metadata:
      labels:
        app: ci-http-stub
    spec:
      imagePullSecrets:$PULL_SECRETS
      containers:
        - name: stub
          image: $OSS_PYTHON_IMAGE
          imagePullPolicy: IfNotPresent
          command: ["python", "/stub/stub.py"]
          ports:
            - containerPort: 8000
          volumeMounts:
            - name: code
              mountPath: /stub
          readinessProbe:
            tcpSocket:
              port: 8000
            initialDelaySeconds: 2
            periodSeconds: 5
      volumes:
        - name: code
          configMap:
            name: ci-http-stub-code
---
apiVersion: v1
kind: Service
metadata:
  name: ci-http-stub
  namespace: $NS
spec:
  selector:
    app: ci-http-stub
  ports:
    - port: 8000
      targetPort: 8000
STUB
    echo "[deploy] waiting for ci-http-stub..."
    kubectl rollout status deployment/ci-http-stub -n "$NS" --timeout=120s
    ;;
esac

case ",${DEPLOY_STUBS}," in
  *,postgres,*)
    echo "[deploy] deploying postgres stub ($OSS_POSTGRES_IMAGE)"
    kubectl apply -n "$NS" -f - <<PG
apiVersion: apps/v1
kind: Deployment
metadata:
  name: postgres
  namespace: $NS
spec:
  replicas: 1
  selector:
    matchLabels:
      app: postgres
  template:
    metadata:
      labels:
        app: postgres
    spec:
      imagePullSecrets:$PULL_SECRETS
      containers:
        - name: postgres
          image: $OSS_POSTGRES_IMAGE
          imagePullPolicy: IfNotPresent
          ports:
            - containerPort: 5432
          env:
            - name: POSTGRES_USER
              value: gis
            - name: POSTGRES_PASSWORD
              value: gis
            - name: POSTGRES_DB
              value: gis
---
apiVersion: v1
kind: Service
metadata:
  name: postgres
  namespace: $NS
spec:
  selector:
    app: postgres
  ports:
    - port: 5432
      targetPort: 5432
PG
    echo "[deploy] waiting for postgres..."
    kubectl rollout status deployment/postgres -n "$NS" --timeout=180s
    ;;
esac

case ",${DEPLOY_STUBS}," in
  *,redis,*)
    echo "[deploy] deploying redis stub ($OSS_REDIS_IMAGE)"
    kubectl apply -n "$NS" -f - <<REDIS
apiVersion: apps/v1
kind: Deployment
metadata:
  name: redis
  namespace: $NS
spec:
  replicas: 1
  selector:
    matchLabels:
      app: redis
  template:
    metadata:
      labels:
        app: redis
    spec:
      imagePullSecrets:$PULL_SECRETS
      containers:
        - name: redis
          image: $OSS_REDIS_IMAGE
          imagePullPolicy: IfNotPresent
          ports:
            - containerPort: 6379
---
apiVersion: v1
kind: Service
metadata:
  name: redis
  namespace: $NS
spec:
  selector:
    app: redis
  ports:
    - port: 6379
      targetPort: 6379
REDIS
    echo "[deploy] waiting for redis..."
    kubectl rollout status deployment/redis -n "$NS" --timeout=120s
    ;;
esac

# Optional workingDir
WORKDIR_BLOCK=""
if [ -n "$DEPLOY_WORKDIR" ]; then
  WORKDIR_BLOCK="
          workingDir: \"$DEPLOY_WORKDIR\""
fi

# Optional command — split on spaces into YAML list (simple argv; no quotes in command).
COMMAND_BLOCK=""
if [ -n "$DEPLOY_COMMAND" ]; then
  COMMAND_BLOCK="
          command:"
  # shellcheck disable=SC2086
  set -- $DEPLOY_COMMAND
  for arg in "$@"; do
    COMMAND_BLOCK="${COMMAND_BLOCK}
            - \"$arg\""
  done
fi

kubectl apply -n "$NS" -f - <<MANIFEST
apiVersion: apps/v1
kind: Deployment
metadata:
  name: $K8S_NAME
  namespace: $NS
  labels:
    app: $K8S_NAME
    ci-pipeline: "$CI_PIPELINE_ID"
    mirror-service: "$SVC"
spec:
  replicas: 1
  selector:
    matchLabels:
      app: $K8S_NAME
  template:
    metadata:
      labels:
        app: $K8S_NAME
    spec:
      imagePullSecrets:$PULL_SECRETS
      containers:
        - name: app
          image: $IMG
          imagePullPolicy: Always
          ports:
            - containerPort: $PORT
$WORKDIR_BLOCK
$COMMAND_BLOCK
$ENV_FROM_BLOCK
          readinessProbe:
            httpGet:
              path: $READINESS_PATH
              port: $PORT
            initialDelaySeconds: 30
            periodSeconds: 10
            timeoutSeconds: 5
            failureThreshold: 18
---
apiVersion: v1
kind: Service
metadata:
  name: $K8S_NAME
  namespace: $NS
  labels:
    app: $K8S_NAME
spec:
  selector:
    app: $K8S_NAME
  ports:
    - port: $PORT
      targetPort: $PORT
  type: ClusterIP
MANIFEST

echo "[deploy] waiting for rollout (timeout 240s)..."
kubectl rollout status deployment/"$K8S_NAME" -n "$NS" --timeout=240s || {
  echo "[deploy] ERROR: rollout timed out — diagnostics:" >&2
  kubectl get pods -n "$NS" -o wide 2>/dev/null || true
  kubectl get events -n "$NS" --sort-by=.lastTimestamp 2>/dev/null | tail -40 || true
  kubectl describe pods -n "$NS" -l "app=$K8S_NAME" 2>/dev/null | tail -100 || true
  echo "[deploy] --- current logs ---" >&2
  kubectl logs -n "$NS" -l "app=$K8S_NAME" --tail=120 2>/dev/null || true
  echo "[deploy] --- previous logs ---" >&2
  kubectl logs -n "$NS" -l "app=$K8S_NAME" --previous --tail=120 2>/dev/null || true
  printf 'API_BASE_URL=\nDEPLOY_SKIPPED=1\n' > deploy.env
  exit 1
}

API_BASE_URL="http://${K8S_NAME}.${NS}.svc.cluster.local:${PORT}"
echo "[deploy] API_BASE_URL=$API_BASE_URL"

# Path prefix for OpenAPI-relative paths (fuzz) and DAST api-scan OpenAPI URL.
PREFIX="${API_PATH_PREFIX:-}"
# Infer from readiness probe when YAML omitted api_path_prefix (e.g. /v1/openapi.json → /v1).
if [ -z "$PREFIX" ] || [ "$PREFIX" = "/" ]; then
  case "${READINESS_PATH:-}" in
    */openapi.json)
      PREFIX="${READINESS_PATH%/openapi.json}"
      ;;
  esac
fi
case "$PREFIX" in
  ""|/) PREFIX="" ;;
  *)
    case "$PREFIX" in
      /*) ;;
      *) PREFIX="/$PREFIX" ;;
    esac
    while [ "${PREFIX%/}" != "$PREFIX" ]; do PREFIX="${PREFIX%/}"; done
    ;;
esac
# DAST uses zap-api-scan against OpenAPI — DAST_TARGET_URL is host only (logging).
DAST_TARGET_URL="$API_BASE_URL"
if [ -n "$PREFIX" ]; then
  DAST_OPENAPI_URL="${API_BASE_URL}${PREFIX}/openapi.json"
else
  DAST_OPENAPI_URL="${API_BASE_URL}/openapi.json"
fi
echo "[deploy] API_PATH_PREFIX=${PREFIX:-none} DAST_TARGET_URL=$DAST_TARGET_URL DAST_OPENAPI_URL=$DAST_OPENAPI_URL"

FETCHED_OPENAPI=""
# Always try live OpenAPI for DAST/fuzz artifacts (even if OPENAPI_PATH preset from YAML).
echo "[deploy] trying live OpenAPI fetch → $DAST_OPENAPI_URL"
mkdir -p checkout reports
HTTP_CODE=$(curl -sf --connect-timeout 10 --max-time 20 \
  -o reports/live-openapi.json \
  -w '%{http_code}' \
  "$DAST_OPENAPI_URL" 2>/dev/null) || HTTP_CODE="000"
# Also try readiness path when it points at OpenAPI (prefix inference missed).
if { [ "$HTTP_CODE" != "200" ] || [ ! -s reports/live-openapi.json ]; } \
  && [ -n "${READINESS_PATH:-}" ] && [ "$READINESS_PATH" != "/openapi.json" ]; then
  case "$READINESS_PATH" in
    *openapi.json)
      HTTP_CODE=$(curl -sf --connect-timeout 10 --max-time 20 \
        -o reports/live-openapi.json \
        -w '%{http_code}' \
        "${API_BASE_URL}${READINESS_PATH}" 2>/dev/null) || HTTP_CODE="000"
      ;;
  esac
fi
if [ "$HTTP_CODE" != "200" ] || [ ! -s reports/live-openapi.json ]; then
  HTTP_CODE=$(curl -sf --connect-timeout 10 --max-time 20 \
    -o reports/live-openapi.json \
    -w '%{http_code}' \
    "${API_BASE_URL}/openapi.json" 2>/dev/null) || HTTP_CODE="000"
fi
if [ "$HTTP_CODE" = "200" ] && [ -s reports/live-openapi.json ]; then
  echo "[deploy] fetched live OpenAPI spec (${HTTP_CODE}) → reports/live-openapi.json"
  cp -f reports/live-openapi.json checkout/openapi.json
  # Prefer checkout path in dotenv — fuzz job must not depend on reports/live surviving a re-fetch.
  FETCHED_OPENAPI="checkout/openapi.json"
else
  echo "[deploy] live OpenAPI fetch: HTTP $HTTP_CODE (not available)"
  rm -f reports/live-openapi.json
  if [ -f checkout/openapi.json ] && [ -s checkout/openapi.json ]; then
    echo "[deploy] keeping checkout/openapi.json from source"
    FETCHED_OPENAPI="checkout/openapi.json"
  fi
fi

{
  printf 'API_BASE_URL=%s\n' "$API_BASE_URL"
  printf 'API_PATH_PREFIX=%s\n' "$PREFIX"
  printf 'DAST_TARGET_URL=%s\n' "$DAST_TARGET_URL"
  printf 'DAST_OPENAPI_URL=%s\n' "$DAST_OPENAPI_URL"
  printf 'DEPLOY_SKIPPED=0\n'
  if [ -n "$FETCHED_OPENAPI" ]; then
    printf 'OPENAPI_PATH=%s\n' "$FETCHED_OPENAPI"
  elif [ -n "${OPENAPI_PATH:-}" ]; then
    printf 'OPENAPI_PATH=%s\n' "$OPENAPI_PATH"
  fi
} > deploy.env

echo "[deploy] done — wrote deploy.env"
cat deploy.env
