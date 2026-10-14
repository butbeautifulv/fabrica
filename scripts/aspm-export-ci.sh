#!/usr/bin/env sh
# ASPM export entry for scan-job after_script (DefectDojo upload).
# Env:
#   ASPM_CONTROL  — required (secrets|sast|osa|…)
#   ASPM_REPORT   — required path to report artifact
#   ASPM_SKIP_EMPTY — default "true"; set "false" for DAST/fuzz (create Test even if empty)
#   ASPM_CONFIG   — optional path to aspm-export.yaml
#   DEFECTDOJO_*  — aspm-export.py / DefectDojo
#   OSS_PYTHON_IMAGE — docker fallback when python3 missing (shell runners)
#
# Runtime order: python3 → docker+$OSS_PYTHON_IMAGE → curl multipart reimport
# (system curl, else scripts/vendor/curl-amd64 static binary for distroless scanners).
# Exit 0 on skip (missing/empty artifact). Fail when export fails and
# DEFECTDOJO_FAIL_ON_ERROR=true, or when artifact exists but no runner available.
set -eu

CONTROL="${ASPM_CONTROL:-}"
REPORT="${ASPM_REPORT:-}"
SKIP_EMPTY="${ASPM_SKIP_EMPTY:-true}"
CONFIG="${ASPM_CONFIG:-config/aspm-export.yaml}"
# Resolve script dir for vendored curl (works when cwd is project root).
ASPM_SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" 2>/dev/null && pwd) || ASPM_SCRIPT_DIR="scripts"
ASPM_VENDOR_CURL="${ASPM_SCRIPT_DIR}/vendor/curl-amd64"

if [ -z "$CONTROL" ]; then
  echo "[aspm] skip — ASPM_CONTROL unset"
  exit 0
fi
if [ -z "$REPORT" ]; then
  echo "[aspm] skip — ASPM_REPORT unset"
  exit 0
fi

if [ -f scripts/resolve-mirror-service.sh ] && { [ -n "${CI_COMMIT_TAG:-}" ] || [ -n "${SERVICE_NAME:-}" ]; }; then
  # shellcheck disable=SC1091
  . scripts/resolve-mirror-service.sh || true
fi

echo "[aspm] product=${DEFECTDOJO_PRODUCT_NAME:-unset} control=$CONTROL report=$REPORT"

if [ ! -f "$REPORT" ]; then
  echo "[aspm] skip — artifact $REPORT not found (scan failed or skipped; not an import success)"
  exit 0
fi
if [ ! -s "$REPORT" ]; then
  echo "[aspm] skip — artifact $REPORT is empty (not an import success)"
  exit 0
fi

# Empty JSON list payload (e.g. [] from some scanners) — skip when skip-empty on.
if [ "$SKIP_EMPTY" = "true" ] && command -v python3 >/dev/null 2>&1; then
  if python3 -c "import json,sys; d=json.load(open(sys.argv[1], encoding='utf-8')); raise SystemExit(0 if isinstance(d,list) and len(d)==0 else 1)" "$REPORT" 2>/dev/null; then
    echo "[aspm] skip — artifact $REPORT contains empty list payload (not an import success)"
    exit 0
  fi
fi

EXTRA=""
if [ "$SKIP_EMPTY" = "true" ]; then
  EXTRA="--skip-empty"
fi

# Read scan_type / test_title for control from aspm-export.yaml (curl path).
aspm_yaml_field() {
  # $1 = control key, $2 = field name (scan_type|test_title), $3 = config path
  _ctrl="$1"
  _field="$2"
  _cfg="${3:-$CONFIG}"
  if [ ! -f "$_cfg" ]; then
    return 1
  fi
  awk -v ctrl="$_ctrl" -v field="$_field" '
    $0 ~ "^  " ctrl ":" { in_ctrl=1; next }
    in_ctrl && $0 ~ /^  [a-zA-Z0-9_]+:/ && $0 !~ "^  " ctrl ":" { in_ctrl=0 }
    in_ctrl && $0 ~ "^    " field ":" {
      line = $0
      sub("^    [^:]+:[[:space:]]*", "", line)
      gsub(/"/, "", line)
      print line
      exit
    }
  ' "$_cfg"
}

run_aspm_curl() {
  url_base="${DEFECTDOJO_URL:-}"
  token="${DEFECTDOJO_API_TOKEN:-}"
  if [ -z "$url_base" ]; then
    echo "[aspm] skip — DEFECTDOJO_URL not set"
    return 0
  fi
  if [ -z "$token" ]; then
    echo "[aspm] skip — DEFECTDOJO_API_TOKEN not set"
    return 0
  fi

  curl_bin=""
  if command -v curl >/dev/null 2>&1; then
    curl_bin="$(command -v curl)"
  elif [ -x "$ASPM_VENDOR_CURL" ]; then
    curl_bin="$ASPM_VENDOR_CURL"
  elif [ -f "$ASPM_VENDOR_CURL" ]; then
    chmod +x "$ASPM_VENDOR_CURL" 2>/dev/null || true
    if [ -x "$ASPM_VENDOR_CURL" ]; then
      curl_bin="$ASPM_VENDOR_CURL"
    fi
  fi
  if [ -z "$curl_bin" ]; then
    echo "[aspm] ERROR: artifact present but python3/docker/curl unavailable — refusing soft-green skip"
    return 1
  fi

  scan_type="$(aspm_yaml_field "$CONTROL" scan_type "$CONFIG" || true)"
  test_title="$(aspm_yaml_field "$CONTROL" test_title "$CONFIG" || true)"
  if [ -z "$scan_type" ]; then
    scan_type="SARIF"
  fi
  if [ -z "$test_title" ]; then
    test_title="$CONTROL"
  fi

  # Generic Findings Import needs aspm-export.py SARIF→generic conversion (KEV/EPSS).
  case "$scan_type" in
    "Generic Findings Import")
      case "$REPORT" in
        *.sarif|*.SARIF)
          echo "[aspm] ERROR: Generic Findings Import from SARIF requires python3/docker (curl cannot convert)"
          return 1
          ;;
      esac
      ;;
  esac

  product_name="${DEFECTDOJO_PRODUCT_NAME:-${CI_PROJECT_NAME:-app}}"
  product_type_name="${DEFECTDOJO_PRODUCT_TYPE:-Research}"
  engagement_name="${DEFECTDOJO_ENGAGEMENT:-CI/CD}"
  api_url="${url_base%/}/api/v2/reimport-scan/"

  curl_insecure=""
  if [ "${DEFECTDOJO_INSECURE:-false}" = "true" ]; then
    curl_insecure="-k"
  fi

  echo "[aspm] curl-fallback bin=$curl_bin control=$CONTROL scan_type=$scan_type test_title=$test_title"

  # shellcheck disable=SC2086
  body="$(
    "$curl_bin" -sS -f -X POST $curl_insecure \
      -H "Authorization: Token ${token}" \
      -F "scan_type=${scan_type}" \
      -F "test_title=${test_title}" \
      -F "product_name=${product_name}" \
      -F "product_type_name=${product_type_name}" \
      -F "engagement_name=${engagement_name}" \
      -F "commit_hash=${CI_COMMIT_SHA:-}" \
      -F "branch_tag=${CI_COMMIT_REF_NAME:-}" \
      -F "build_id=${CI_PIPELINE_ID:-}" \
      -F "minimum_severity=Info" \
      -F "auto_create_context=true" \
      -F "close_old_findings=false" \
      -F "active=true" \
      -F "verified=false" \
      -F "file=@${REPORT}" \
      "$api_url"
  )" || {
    echo "[aspm] ERROR: curl reimport failed for control=$CONTROL"
    return 1
  }
  printf '%s\n' "[aspm:${CONTROL}] uploaded (curl): ${body}" | cut -c1-240
  return 0
}

run_aspm() {
  if command -v python3 >/dev/null 2>&1; then
    # shellcheck disable=SC2086
    python3 scripts/aspm-export.py --control "$CONTROL" --report "$REPORT" --config "$CONFIG" $EXTRA
    return $?
  fi
  if command -v docker >/dev/null 2>&1 && [ -n "${OSS_PYTHON_IMAGE:-}" ]; then
    echo "[aspm] python3 missing — docker run ${OSS_PYTHON_IMAGE}"
    # shellcheck disable=SC2086
    docker run --rm \
      -e DEFECTDOJO_URL \
      -e DEFECTDOJO_API_TOKEN \
      -e DEFECTDOJO_PRODUCT_NAME \
      -e DEFECTDOJO_ENGAGEMENT \
      -e DEFECTDOJO_FAIL_ON_ERROR \
      -e DEFECTDOJO_INSECURE \
      -e CI_PROJECT_NAME \
      -e CI_COMMIT_SHA \
      -e CI_COMMIT_REF_NAME \
      -e CI_PIPELINE_ID \
      -v "$PWD:/work" -w /work \
      "${OSS_PYTHON_IMAGE}" \
      python3 scripts/aspm-export.py --control "$CONTROL" --report "$REPORT" --config "$CONFIG" $EXTRA
    return $?
  fi
  run_aspm_curl
  return $?
}

if run_aspm; then
  exit 0
fi
rc=$?
if [ "${DEFECTDOJO_FAIL_ON_ERROR:-false}" = "true" ]; then
  exit "$rc"
fi
echo "[aspm] WARN: export failed (rc=$rc) but DEFECTDOJO_FAIL_ON_ERROR!=true — continuing"
exit 0
