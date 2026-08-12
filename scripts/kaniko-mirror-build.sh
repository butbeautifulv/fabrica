#!/usr/bin/env sh
# Kaniko build for corp mirror — NO docker CLI / NO dind / NO python required.
# Writes build.env: IMAGE_TAG, BUILD_FALLBACK, SOURCE_SHA
# IMAGE_TAG=${SERVICE_NAME}-${SOURCE_SHA}
set -eu

# Kaniko debug image tools live under /busybox
export PATH="/busybox:/kaniko:${PATH:-/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin}"

SCAN_ROOT="${SCAN_ROOT:-checkout}"
SERVICE_NAME="${SERVICE_NAME:-app}"
REGISTRY="${REGISTRY:?REGISTRY required}"
NEXUS_DOCKER_PREFIX="${NEXUS_DOCKER_PREFIX:-nexus.svo.aero:8345}"
NEXUS_DOCKER_GROUP="${NEXUS_DOCKER_GROUP:-nexus.svo.aero:8374}"
BUILD_BASE_IMAGE="${BUILD_BASE_IMAGE:-${NEXUS_DOCKER_PREFIX}/library/python:3.11.11-slim-bookworm}"
BUILD_DOCKER_TARGET="${BUILD_DOCKER_TARGET:-source}"
BUILD_FALLBACK_ALLOW="${BUILD_FALLBACK:-1}"
echo "[kaniko] BUILD_DOCKER_TARGET=${BUILD_DOCKER_TARGET}"
echo "[kaniko] BUILD_BASE_IMAGE=${BUILD_BASE_IMAGE}"
echo "[kaniko] IMAGE_NAME=${BUILD_BASE_IMAGE} (Docker build-arg)"
echo "[kaniko] BUILD_FALLBACK_ALLOW=${BUILD_FALLBACK_ALLOW} (0=no retag fallback)"
echo "[kaniko] NEXUS_DOCKER_PREFIX=${NEXUS_DOCKER_PREFIX} NEXUS_DOCKER_GROUP=${NEXUS_DOCKER_GROUP}"

if [ "${MIRROR_REQUIRE_REGISTRY_BASE:-0}" = "1" ]; then
  case "${BUILD_BASE_IMAGE}" in
    *map_objects/infra/python_prod*)
      echo "[kaniko] registry base OK (map_objects/infra/python_prod*)"
      ;;
    *)
      echo "[kaniko] ERROR: MIRROR_REQUIRE_REGISTRY_BASE=1 but BUILD_BASE_IMAGE is not registry python_prod:" >&2
      echo "[kaniko]   got: ${BUILD_BASE_IMAGE}" >&2
      echo "[kaniko]   want: …/map_objects/infra/python_prod_3.11 (subsidiary parity)" >&2
      exit 1
      ;;
  esac
fi
NEXUS_PYPI_URL="${NEXUS_PYPI_URL:-}"
if [ -z "$NEXUS_PYPI_URL" ] && [ -n "${PIP_INDEX_URL:-}" ]; then
  NEXUS_PYPI_URL=$(printf '%s' "$PIP_INDEX_URL" | sed -E 's|^https?://||; s|/simple/?$||')
fi
NEXUS_PYPI_URL_LOG="${NEXUS_PYPI_URL:-<unset>}"
# Nexus PyPI can require auth.
# IMPORTANT: do NOT embed user/pass into NEXUS_PYPI_URL here.
# Dockerfiles typically build the final index URL from NEXUS_USERNAME/NEXUS_PASSWORD build-args.
# Double-embedding can lead to malformed URLs and 401s.
NEXUS_PYPI_HAS_AUTH=0
case "${NEXUS_PYPI_URL:-}" in
  *@*) NEXUS_PYPI_HAS_AUTH=1 ;;
esac
echo "[kaniko] pip NEXUS_PYPI_URL=${NEXUS_PYPI_URL_LOG} NEXUS_PYPI_HAS_AUTH=${NEXUS_PYPI_HAS_AUTH} PIP_TRUSTED_HOST=${PIP_TRUSTED_HOST:-<unset>} NEXUS_USER_set=$([ -n \"${NEXUS_USER:-}\" ] && echo 1 || echo 0) NEXUS_PASSWORD_set=$([ -n \"${NEXUS_PASSWORD:-}\" ] && echo 1 || echo 0)"

write_env() {
  echo "IMAGE_TAG=${1}" >> build.env
  echo "BUILD_FALLBACK=${2}" >> build.env
  echo "SOURCE_SHA=${3}" >> build.env
  if [ "$1" != "none" ] && [ -n "${REGISTRY:-}" ]; then
    echo "BUILT_IMAGE=${REGISTRY}:${1}" >> build.env
  else
    echo "BUILT_IMAGE=" >> build.env
  fi
}

: > build.env

SOURCE_SHA=""
if command -v git >/dev/null 2>&1 && [ -d "$SCAN_ROOT/.git" ]; then
  SOURCE_SHA=$(git -C "$SCAN_ROOT" rev-parse HEAD)
elif [ -n "${SOURCE_REF_RESOLVED:-}" ]; then
  SOURCE_SHA=$(printf '%s' "$SOURCE_REF_RESOLVED" | tr -c 'A-Za-z0-9' '-' | cut -c1-40)
elif [ -n "${SOURCE_REF:-}" ]; then
  SOURCE_SHA=$(printf '%s' "$SOURCE_REF" | tr -c 'A-Za-z0-9' '-' | cut -c1-40)
else
  SOURCE_SHA="${CI_COMMIT_SHA:-unknown}"
fi
IMAGE_TAG="${SERVICE_NAME}-${SOURCE_SHA}"
DESTINATION="${REGISTRY}:${IMAGE_TAG}"

if [ ! -x /kaniko/executor ]; then
  echo "[kaniko] ERROR: /kaniko/executor missing"
  write_env none 0 "$SOURCE_SHA"
  exit 1
fi

DF=""
if [ -d "$SCAN_ROOT" ]; then
  DF=$(find "$SCAN_ROOT" \( -path "$SCAN_ROOT/Docker/*/Dockerfile" -o -path "$SCAN_ROOT/Docker/Dockerfile" -o -name Dockerfile \) -type f 2>/dev/null | head -n 1 || true)
fi
if [ -z "$DF" ] && [ -f Dockerfile ]; then
  DF=Dockerfile
fi

if [ -z "$DF" ] || [ ! -f "$DF" ]; then
  echo "[kaniko] ERROR: No Dockerfile under $SCAN_ROOT"
  write_env none 0 "$SOURCE_SHA"
  exit 1
fi

# Parity with Jenkins: remove local-only VSCode block from Dockerfile.
# This block is intentionally deleted before building so it doesn't affect prod-like builds.
if [ -n "$DF" ] && [ -f "$DF" ]; then
  sed -i '/# Only for local useage for VSCode/,/# End of local useage for VSCode/d' "$DF" || true
  echo "[kaniko] patched Dockerfile VSCode-local block (if present): $DF"
fi

CONTEXT="$SCAN_ROOT"
if [ ! -d "$CONTEXT" ]; then
  CONTEXT=$(dirname "$DF")
fi

echo "[kaniko] dockerfile=$DF context=$CONTEXT dest=$DESTINATION"
echo "[kaniko] BUILD_BASE_IMAGE=$BUILD_BASE_IMAGE target=$BUILD_DOCKER_TARGET SOURCE_SHA=$SOURCE_SHA"

# Auth: in k8s jobs `/kaniko` can be mounted read-only.
# Prefer writing docker config into a writable dir and letting kaniko read it via DOCKER_CONFIG.
KANIKO_DOCKER_CONFIG_DIR="${KANIKO_DOCKER_CONFIG_DIR:-/tmp/kaniko-docker-config}"
export DOCKER_CONFIG="$KANIKO_DOCKER_CONFIG_DIR"
CONFIG_JSON="$KANIKO_DOCKER_CONFIG_DIR/config.json"
mkdir -p "$KANIKO_DOCKER_CONFIG_DIR"
b64_auth() {
  # busybox base64 -w0 may not exist; strip newlines
  printf '%s' "$1" | base64 | tr -d '\n'
}
if [ ! -s "$CONFIG_JSON" ]; then
  AUTH_ENTRIES=""
  if [ -n "${NEXUS_USER:-}" ] && [ -n "${NEXUS_PASSWORD:-}" ]; then
    NA=$(b64_auth "${NEXUS_USER}:${NEXUS_PASSWORD}")
    AUTH_ENTRIES="${AUTH_ENTRIES}\"${NEXUS_DOCKER_PREFIX}\":{\"auth\":\"${NA}\"},\"${NEXUS_DOCKER_GROUP}\":{\"auth\":\"${NA}\"},"
  fi
  user="${CI_REGISTRY_USER:-gitlab-ci-token}"
  password="${CI_REGISTRY_PASSWORD:-${CI_JOB_TOKEN:-}}"
  reg="${CI_REGISTRY:-}"
  if [ -n "$reg" ] && [ -n "$password" ]; then
    GA=$(b64_auth "${user}:${password}")
    AUTH_ENTRIES="${AUTH_ENTRIES}\"${reg}\":{\"auth\":\"${GA}\"},"
  fi
  AUTH_ENTRIES=$(printf '%s' "$AUTH_ENTRIES" | sed 's/,$//')
  printf '{"auths":{%s}}\n' "$AUTH_ENTRIES" > "$CONFIG_JSON"
  echo "[kaniko] wrote $CONFIG_JSON"
else
  echo "[kaniko] using existing docker config from DOCKER_CONFIG=$DOCKER_CONFIG"
fi

PIP_HOST="${PIP_TRUSTED_HOST:-}"
if [ -z "$PIP_HOST" ] && [ -n "${NEXUS_PYPI_URL:-}" ]; then
  PIP_HOST=$(printf '%s' "$NEXUS_PYPI_URL" | cut -d/ -f1)
fi
# Hostname only for pip --trusted-host (strip :port). Keep Nexus-only installs — no public pypi.org.
PIP_TRUST_NAME=$(printf '%s' "$PIP_HOST" | cut -d: -f1)
if [ -n "$PIP_TRUST_NAME" ] && [ -f "$DF" ]; then
  echo "[kaniko] patch trusted-host -> ${PIP_TRUST_NAME}"
  sed -i "s/--trusted-host [^ ]*/--trusted-host ${PIP_TRUST_NAME}/g" "$DF" || true
fi

# Services that bake ENV PIP_INDEX_URL=…@gitlab…/packages/pypi/simple (e.g. project 673)
# steal the sole index away from Nexus → "No matching distribution" for public deps (aiodns).
# Rewrite those lines to Nexus with auth; gismaputils stays via --find-links vendor (below).
# Note: avoid shell `else` immediately after a python heredoc (busybox ash: `else:: not found`).
if [ -f "$DF" ] && [ -n "${NEXUS_PYPI_URL:-}" ] && [ -n "${NEXUS_USER:-}" ] && [ -n "${NEXUS_PASSWORD:-}" ]; then
  if grep -qE 'PIP_INDEX_URL.*(gitlab\.svo\.aero|/packages/pypi/simple)' "$DF" 2>/dev/null; then
    NEXUS_SIMPLE="${NEXUS_PYPI_URL}"
    case "$NEXUS_SIMPLE" in
      http://*|https://*) ;;
      *) NEXUS_SIMPLE="https://${NEXUS_SIMPLE}" ;;
    esac
    case "$NEXUS_SIMPLE" in
      */simple|*/simple/) ;;
      *) NEXUS_SIMPLE="${NEXUS_SIMPLE%/}/simple" ;;
    esac
    AUTH_INDEX=""
    if [ -f "$(dirname "$0")/pip-index-auth.sh" ]; then
      AUTH_INDEX=$(PIP_INDEX_URL="$NEXUS_SIMPLE" NEXUS_USER="$NEXUS_USER" NEXUS_PASSWORD="$NEXUS_PASSWORD" \
        sh "$(dirname "$0")/pip-index-auth.sh" 2>/dev/null || true)
    fi
    if [ -z "${AUTH_INDEX:-}" ] && command -v python3 >/dev/null 2>&1; then
      AUTH_INDEX=$(PIP_INDEX_URL="$NEXUS_SIMPLE" NEXUS_USER="$NEXUS_USER" NEXUS_PASSWORD="$NEXUS_PASSWORD" \
        python3 -c 'import os; from urllib.parse import quote,urlparse,urlunparse; u=urlparse(os.environ["PIP_INDEX_URL"]); netloc=quote(os.environ["NEXUS_USER"],safe="")+":"+quote(os.environ["NEXUS_PASSWORD"],safe="")+"@"+u.hostname+(f":{u.port}" if u.port else ""); print(urlunparse((u.scheme,netloc,u.path,u.params,u.query,u.fragment)))')
    fi
    if [ -n "${AUTH_INDEX:-}" ] && command -v python3 >/dev/null 2>&1; then
      KANIKO_AUTH_INDEX="$AUTH_INDEX" KANIKO_DOCKERFILE="$DF" python3 -c '
import os, re
df = os.environ["KANIKO_DOCKERFILE"]
auth = os.environ["KANIKO_AUTH_INDEX"]
text = open(df, encoding="utf-8", errors="replace").read()
pat = re.compile(r"^([ \t]*ENV[ \t]+PIP_INDEX_URL[ \t]*(?:=|[ \t]))([^\n]*)$", re.M)
new, n = pat.subn(lambda m: m.group(1) + "\"" + auth + "\"", text)
if n:
    open(df, "w", encoding="utf-8").write(new)
    print("[kaniko] rewritten PIP_INDEX_URL gitlab->nexus (%d line(s))" % n)
else:
    print("[kaniko] WARN: gitlab PIP_INDEX_URL detected but no ENV line rewritten")
'
    fi
    if [ -z "${AUTH_INDEX:-}" ]; then
      echo "[kaniko] WARN: could not build Nexus auth PIP_INDEX_URL" >&2
    fi
  fi
fi

# gismaputils: do NOT use --extra-index-url (pip would query GitLab for every pkg and fall through to pypi.org SSL).
# Instead vendor wheels from map_objects-ci Package Registry into build context and --find-links locally.
GISMAPUTILS_INDEX_HOST="${GISMAPUTILS_INDEX_HOST:-gitlab.svo.aero}"
GISMAPUTILS_PYPI_PROJECT_ID="${GISMAPUTILS_PYPI_PROJECT_ID:-1962}"
VENDOR_DIR="${CONTEXT}/vendor-gismaputils"
GISMAP_TOKEN="${GISMAPUTILS_PYPI_TOKEN:-${CI_JOB_TOKEN:-}}"
GISMAP_VENDOR_SET=0
if [ -n "$GISMAP_TOKEN" ] && [ -d "$CONTEXT" ]; then
  mkdir -p "$VENDOR_DIR"
  # Pull versions referenced in requirements (fallback: 0.5.1 0.5.3).
  REQ_FILES=""
  for rf in "$CONTEXT/dev-requirements.txt" "$CONTEXT/requirements.txt"; do
    [ -f "$rf" ] && REQ_FILES="$REQ_FILES $rf"
  done
  VERS=$( { [ -n "$REQ_FILES" ] && grep -hE '^[[:space:]]*gismaputils[[:space:]]*==' $REQ_FILES || true; } \
    | sed -E 's/.*==[[:space:]]*([0-9][^[:space:]#]+).*/\1/' | sort -u )
  if [ -z "$VERS" ]; then
    VERS="0.5.1
0.5.3"
  fi
  for ver in $VERS; do
    # GitLab simple index → wheel URL via python (TLS ok in helper image).
    # If exact pin missing (e.g. user_service gismaputils==0.2.5), remap req to
    # nearest available Package Registry wheel so BUILD_FALLBACK stays 0.
    if command -v python3 >/dev/null 2>&1; then
      GISMAP_TOKEN="$GISMAP_TOKEN" GISMAPUTILS_INDEX_HOST="$GISMAPUTILS_INDEX_HOST" \
      GISMAPUTILS_PYPI_PROJECT_ID="$GISMAPUTILS_PYPI_PROJECT_ID" VENDOR_DIR="$VENDOR_DIR" \
      VER="$ver" CONTEXT="$CONTEXT" python3 - <<'PY'
import os, ssl, urllib.request, re, sys
from pathlib import Path

ver = os.environ["VER"]
host = os.environ["GISMAPUTILS_INDEX_HOST"]
pid = os.environ["GISMAPUTILS_PYPI_PROJECT_ID"]
tok = os.environ["GISMAP_TOKEN"]
vendor = os.environ["VENDOR_DIR"]
context = Path(os.environ["CONTEXT"])
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
simple = f"https://{host}/api/v4/projects/{pid}/packages/pypi/simple/gismaputils/"
req = urllib.request.Request(simple, headers={"PRIVATE-TOKEN": tok})
try:
    html = urllib.request.urlopen(req, context=ctx, timeout=60).read().decode("utf-8", "replace")
except Exception as e:
    print(f"[kaniko] WARN: cannot list gismaputils simple index: {e}", file=sys.stderr)
    sys.exit(0)

def wheel_for(v: str):
    pat = re.compile(r'href="([^"]*gismaputils-' + re.escape(v) + r'-[^"]+\.whl)[^"]*"', re.I)
    return pat.search(html)

m = wheel_for(ver)
use_ver = ver
if not m:
    avail = sorted(set(re.findall(r"gismaputils-([0-9][^\"/]+?)-py", html, flags=re.I)))
    prefer = [x for x in ("0.5.1", "0.5.3") if x in avail]
    use_ver = (prefer or avail)[-1] if (prefer or avail) else ""
    if not use_ver:
        print(f"[kaniko] WARN: no wheel for gismaputils=={ver} in Package Registry", file=sys.stderr)
        sys.exit(0)
    print(
        f"[kaniko] WARN: no wheel for gismaputils=={ver}; remapping requirements → {use_ver}",
        file=sys.stderr,
    )
    pin_re = re.compile(rf"^(?P<pre>\s*gismaputils\s*==\s*){re.escape(ver)}(?P<post>\b.*)$", re.M)
    for rf in (context / "dev-requirements.txt", context / "requirements.txt"):
        if not rf.is_file():
            continue
        text = rf.read_text(encoding="utf-8", errors="replace")
        new, n = pin_re.subn(rf"\g<pre>{use_ver}\g<post>", text)
        if n:
            rf.write_text(new, encoding="utf-8")
            print(f"[kaniko] rewritten {rf.name}: gismaputils=={ver} → {use_ver} ({n} hit(s))")
            (context / ".gismaputils_remapped").write_text(f"{ver}->{use_ver}\n", encoding="utf-8")
    m = wheel_for(use_ver)
    if not m:
        print(f"[kaniko] WARN: remap target gismaputils=={use_ver} also missing", file=sys.stderr)
        sys.exit(0)

url = m.group(1)
if url.startswith("/"):
    url = f"https://{host}{url}"
req2 = urllib.request.Request(url, headers={"PRIVATE-TOKEN": tok})
data = urllib.request.urlopen(req2, context=ctx, timeout=120).read()
name = url.split("/")[-1].split("#")[0]
path = os.path.join(vendor, name)
with open(path, "wb") as f:
    f.write(data)
print(f"[kaniko] vendored {name} ({len(data)} bytes)")
PY
    fi
  done
fi
# After remapping gismaputils to 0.5.x, old services may import module-level get_token.
# Soft-fail only (never exit 1): SystemExit("WARN…") would kill mobile builds.
if [ -f "${CONTEXT}/.gismaputils_remapped" ] && command -v python3 >/dev/null 2>&1; then
  CONTEXT="$CONTEXT" python3 - <<'PY'
import os, re, sys
from pathlib import Path

ctx = Path(os.environ["CONTEXT"])
IMPORT_OLD = "from gismaputils.auth.network.auth_requests import get_token"
IMPORT_NEW = "from gismaputils.auth.network.auth_requests import auth"
# Prefer specific multiline (user_service / historical); then looser await get_token(...).
PAT_STRICT = re.compile(
    r"token\s*=\s*await\s+get_token\(\s*"
    r"url_stand\s*=.*?"
    r"btb_password\s*=\s*get_settings\(\)\.BACK_TO_BACK_PASSWORD\s*,?\s*"
    r"\)",
    re.S,
)
REPL_STRICT = (
    "auth.set_config(\n"
    "        url_auth=get_settings().URL_AUTH,\n"
    "        b2b_user=get_settings().BACK_TO_BACK_USER,\n"
    "        b2b_pwd=get_settings().BACK_TO_BACK_PASSWORD,\n"
    "    )\n"
    "    token = await auth.get_token()"
)
PAT_LOOSE = re.compile(r"await\s+get_token\s*\(", re.M)
patched = 0
for hr in ctx.rglob("*.py"):
    try:
        text = hr.read_text(encoding="utf-8", errors="replace")
    except OSError:
        continue
    if IMPORT_OLD not in text:
        continue
    text2 = text.replace(IMPORT_OLD, IMPORT_NEW)
    text3, n = PAT_STRICT.subn(REPL_STRICT, text2, count=1)
    if n == 0:
        # Import-only / alternate call shapes: auth.get_token() after set_config elsewhere,
        # or bare await get_token( → auth.get_token(
        text3, n2 = PAT_LOOSE.subn("await auth.get_token(", text2)
        if n2 == 0 and "get_token(" in text2:
            # Last resort: leave auth import; warn but do not fail the build.
            print(f"[kaniko] WARN: remapped gismaputils; import rewritten but no get_token() call patch in {hr.relative_to(ctx)}", file=sys.stderr)
            hr.write_text(text2, encoding="utf-8")
            patched += 1
            continue
        if n2 == 0:
            print(f"[kaniko] WARN: remapped gismaputils; import rewritten only in {hr.relative_to(ctx)}", file=sys.stderr)
            hr.write_text(text2, encoding="utf-8")
            patched += 1
            continue
    hr.write_text(text3, encoding="utf-8")
    print(f"[kaniko] patched {hr.relative_to(ctx)} for gismaputils Auth.get_token compat")
    patched += 1
if patched == 0:
    print("[kaniko] WARN: remapped gismaputils but no get_token imports found to patch", file=sys.stderr)
sys.exit(0)
PY
fi
if ls "$VENDOR_DIR"/*.whl >/dev/null 2>&1; then
  GISMAP_VENDOR_SET=1
fi
echo "[kaniko] gismaputils_vendor set=${GISMAP_VENDOR_SET} dir=${VENDOR_DIR}"

# aodb-log-tools: same Package Registry vendor pattern (poetry path-dep; no --extra-index-url).
AODB_INDEX_HOST="${AODB_INDEX_HOST:-${GISMAPUTILS_INDEX_HOST:-gitlab.svo.aero}}"
AODB_PYPI_PROJECT_ID="${AODB_PYPI_PROJECT_ID:-${GISMAPUTILS_PYPI_PROJECT_ID:-1962}}"
AODB_VENDOR_DIR="${CONTEXT}/vendor-aodb-log-tools"
AODB_TOKEN="${GISMAPUTILS_PYPI_TOKEN:-${CI_JOB_TOKEN:-}}"
AODB_VENDOR_SET=0
if [ -n "$AODB_TOKEN" ] && [ -d "$CONTEXT" ] && command -v python3 >/dev/null 2>&1; then
  NEED_AODB=0
  if [ -f "$CONTEXT/pyproject.toml" ] && grep -qE 'aodb-log-tools|aodb_log_tools' "$CONTEXT/pyproject.toml"; then
    NEED_AODB=1
  elif [ -f "$CONTEXT/poetry.lock" ] && grep -qE 'name = "aodb-log-tools"' "$CONTEXT/poetry.lock"; then
    NEED_AODB=1
  fi
  if [ "$NEED_AODB" = "1" ]; then
    mkdir -p "$AODB_VENDOR_DIR"
    AODB_TOKEN="$AODB_TOKEN" AODB_INDEX_HOST="$AODB_INDEX_HOST" \
    AODB_PYPI_PROJECT_ID="$AODB_PYPI_PROJECT_ID" AODB_VENDOR_DIR="$AODB_VENDOR_DIR" \
    CONTEXT="$CONTEXT" python3 - <<'PY'
import os, ssl, urllib.request, re, sys, tarfile, io
from pathlib import Path

host = os.environ["AODB_INDEX_HOST"]
pid = os.environ["AODB_PYPI_PROJECT_ID"]
tok = os.environ["AODB_TOKEN"]
vendor = Path(os.environ["AODB_VENDOR_DIR"])
context = Path(os.environ["CONTEXT"])
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
simple = f"https://{host}/api/v4/projects/{pid}/packages/pypi/simple/aodb-log-tools/"
req = urllib.request.Request(simple, headers={"PRIVATE-TOKEN": tok})
try:
    html = urllib.request.urlopen(req, context=ctx, timeout=60).read().decode("utf-8", "replace")
except Exception as e:
    print(f"[kaniko] WARN: cannot list aodb-log-tools simple index: {e}", file=sys.stderr)
    sys.exit(0)

# Prefer sdist for path-dep; fall back to wheel extract via sdist only.
m = re.search(r'href="([^"]*aodb_log_tools-1\.0\.0\.tar\.gz)[^"]*"', html, re.I)
if not m:
    m = re.search(r'href="([^"]*aodb_log_tools-1\.0\.0[^"]+\.whl)[^"]*"', html, re.I)
if not m:
    print("[kaniko] WARN: no aodb-log-tools==1.0.0 artifact in Package Registry", file=sys.stderr)
    sys.exit(0)
url = m.group(1)
if url.startswith("/"):
    url = f"https://{host}{url}"
req2 = urllib.request.Request(url, headers={"PRIVATE-TOKEN": tok})
data = urllib.request.urlopen(req2, context=ctx, timeout=120).read()
name = url.split("/")[-1].split("#")[0]
pkg_path = vendor / name
pkg_path.write_bytes(data)
print(f"[kaniko] downloaded {name} ({len(data)} bytes)")

# Unpack into vendor-aodb-log-tools/ so poetry path dep sees package root.
if name.endswith(".tar.gz"):
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tf:
        tf.extractall(vendor)
    # flatten aodb_log_tools-1.0.0/* → vendor/
    for child in list(vendor.iterdir()):
        if child.is_dir() and child.name.startswith("aodb_log_tools"):
            for item in child.iterdir():
                dest = vendor / item.name
                if dest.exists():
                    continue
                item.rename(dest)
            try:
                child.rmdir()
            except OSError:
                pass
            break
elif name.endswith(".whl"):
    import zipfile
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        zf.extractall(vendor)
    # synthesize minimal pyproject for path install
    (vendor / "pyproject.toml").write_text(
        "[build-system]\nrequires=['setuptools']\nbuild-backend='setuptools.build_meta'\n"
        "[project]\nname='aodb-log-tools'\nversion='1.0.0'\n"
        "requires-python='>=3.10'\n",
        encoding="utf-8",
    )

# Mark for Dockerfile hardener
(context / ".aodb_log_tools_vendored").write_text("1.0.0\n", encoding="utf-8")
print(f"[kaniko] vendored aodb-log-tools==1.0.0 → {vendor}")
PY
    if [ -f "${CONTEXT}/.aodb_log_tools_vendored" ]; then
      AODB_VENDOR_SET=1
    fi
  fi
fi
echo "[kaniko] aodb_log_tools_vendor set=${AODB_VENDOR_SET} dir=${AODB_VENDOR_DIR}"

# O5/O6: harden Dockerfile — setuptools pin, poetry inject, skip public apt, PIP_NO_INPUT.
if [ -f "$DF" ] && command -v python3 >/dev/null 2>&1; then
  DF="$DF" CONTEXT="$CONTEXT" GISMAP_VENDOR_SET="$GISMAP_VENDOR_SET" AODB_VENDOR_SET="$AODB_VENDOR_SET" \
  PIP_TRUST_NAME="${PIP_TRUST_NAME:-nexus.svo.aero}" \
  BUILD_BASE_IMAGE="$BUILD_BASE_IMAGE" NEXUS_PYPI_URL="${NEXUS_PYPI_URL:-}" \
  NEXUS_APT_MIRROR="${NEXUS_APT_MIRROR:-}" \
  NEXUS_USER="${NEXUS_USER:-}" NEXUS_PASSWORD="${NEXUS_PASSWORD:-}" python3 - <<'PY'
import os, re
from urllib.parse import quote
df = os.environ["DF"]
context = os.environ.get("CONTEXT") or ""
vendor = os.environ.get("GISMAP_VENDOR_SET") == "1"
aodb_vendor = os.environ.get("AODB_VENDOR_SET") == "1"
trust = os.environ.get("PIP_TRUST_NAME") or "nexus.svo.aero"
base = os.environ.get("BUILD_BASE_IMAGE") or ""
pypi = (os.environ.get("NEXUS_PYPI_URL") or "").strip().rstrip("/")
apt_mirror = (os.environ.get("NEXUS_APT_MIRROR") or "").strip()
nexus_user = os.environ.get("NEXUS_USER") or ""
nexus_password = os.environ.get("NEXUS_PASSWORD") or ""
with open(df, "r", encoding="utf-8", errors="replace") as f:
    text = f.read()
lines = text.splitlines(True)

# B3: dead corp test registry cannot be pulled from CI — force BUILD_BASE_IMAGE.
DEAD_HOSTS = ("registry.test.model.svo.aero",)
if base:
    out = []
    for line in lines:
        up = line.upper()
        if up.startswith("FROM ") or (up.lstrip().startswith("FROM ")):
            if any(h in line for h in DEAD_HOSTS):
                # Preserve stage alias: FROM dead AS name → FROM base AS name
                m = re.match(r"^(\s*FROM\s+)\S+(.*)$", line, re.I)
                if m:
                    line = f"{m.group(1)}{base}{m.group(2)}"
                    if not line.endswith("\n"):
                        line += "\n"
                    print(f"[kaniko] rewritten dead FROM → {base}")
        out.append(line)
    lines = out

# Vendor COPY + find-links (existing behavior).
joined = "".join(lines)
if vendor and "vendor-gismaputils" not in joined:
    out, inserted = [], False
    for line in lines:
        out.append(line)
        if not inserted and re.match(r"^COPY\s+", line):
            out.append("COPY ./vendor-gismaputils /app/vendor-gismaputils\n")
            inserted = True
    if not inserted:
        out.insert(0, "COPY ./vendor-gismaputils /app/vendor-gismaputils\n")
    lines = out

# aodb-log-tools path vendor: COPY into image; pyproject rewrite happens on CONTEXT below.
if aodb_vendor:
    joined = "".join(lines)
    if "vendor-aodb-log-tools" not in joined:
        out, inserted = [], False
        for line in lines:
            out.append(line)
            if not inserted and re.match(r"^COPY\s+", line):
                out.append("COPY ./vendor-aodb-log-tools /code/vendor-aodb-log-tools\n")
                inserted = True
        if not inserted:
            out.insert(0, "COPY ./vendor-aodb-log-tools /code/vendor-aodb-log-tools\n")
        lines = out
        print("[kaniko] inserted COPY vendor-aodb-log-tools")
    # Path-dep in pyproject so poetry does not hit Nexus for aodb-log-tools.
    if context:
        from pathlib import Path
        pp = Path(context) / "pyproject.toml"
        if pp.is_file():
            ppt = pp.read_text(encoding="utf-8", errors="replace")
            ppt2, n = re.subn(
                r'(?m)^(\s*)aodb-log-tools\s*=\s*["\'][^"\']+["\']\s*$',
                r'\1aodb-log-tools = { path = "vendor-aodb-log-tools", develop = false }',
                ppt,
            )
            if n == 0:
                ppt2, n = re.subn(
                    r'(?m)^(\s*)aodb-log-tools\s*=\s*\{[^}]*\}\s*$',
                    r'\1aodb-log-tools = { path = "vendor-aodb-log-tools", develop = false }',
                    ppt,
                )
            if n:
                pp.write_text(ppt2, encoding="utf-8")
                print(f"[kaniko] rewritten pyproject aodb-log-tools → path vendor ({n})")

# ENV PIP_NO_INPUT after first FROM (avoid interactive gitlab.svo.aero auth EOF).
if not any("PIP_NO_INPUT" in ln for ln in lines):
    tmp, inserted_env = [], False
    for line in lines:
        tmp.append(line)
        if not inserted_env and line.upper().startswith("FROM "):
            tmp.append("ENV PIP_NO_INPUT=1 CI=1 PYTHONUNBUFFERED=1\n")
            tmp.append(f"ENV PIP_TRUSTED_HOST={trust}\n")
            inserted_env = True
    lines = tmp

elif not any("PIP_TRUSTED_HOST" in ln for ln in lines):
    tmp, inserted_env = [], False
    for line in lines:
        tmp.append(line)
        if not inserted_env and "PIP_NO_INPUT" in line:
            tmp.append(f"ENV PIP_TRUSTED_HOST={trust}\n")
            inserted_env = True
    lines = tmp

PUBLIC_APT = (
    "deb.debian.org",
    "security.debian.org",
    "archive.ubuntu.com",
    "security.ubuntu.com",
    "cdn-fastly.deb.debian.org",
)

def is_apt_run(ln: str) -> bool:
    return bool(re.search(r"\bapt(-get)?\b", ln, re.I)) and ln.lstrip().upper().startswith("RUN ")

# P3: skip public apt when no corp mirror (aosint has no egress to debian.org).
if not apt_mirror:
    out_apt = []
    for line in lines:
        if is_apt_run(line) and (
            any(h in line for h in PUBLIC_APT)
            or re.search(r"apt-get\s+(update|install|upgrade)\b", line, re.I)
        ):
            # Bare apt-get without local mirror → no-op (base image usually has runtime deps).
            if any(h in line for h in PUBLIC_APT) or not re.search(
                r"(nexus\.svo\.aero|mirror\.|/etc/apt/sources)", line, re.I
            ):
                print("[kaniko] skip public apt RUN (offline)")
                out_apt.append('RUN echo "[kaniko] skip public apt (offline)" && true\n')
                continue
        out_apt.append(line)
    lines = out_apt
else:
    # Rewrite common public hosts → NEXUS_APT_MIRROR host.
    host = re.sub(r"^https?://", "", apt_mirror).split("/")[0]
    out_apt = []
    for line in lines:
        new = line
        for h in PUBLIC_APT:
            if h in new:
                new = new.replace(h, host)
        if new != line:
            print(f"[kaniko] rewritten apt host → {host}")
        out_apt.append(new)
    lines = out_apt

# P2: inject poetry before first poetry RUN (base python_prod often lacks poetry).
joined = "".join(lines)
uses_poetry = bool(re.search(r"\bpoetry\b", joined, re.I))
has_poetry_install = bool(
    re.search(r"pip\s+install\b[^\n]*\bpoetry\b", joined, re.I)
)
if uses_poetry and not has_poetry_install:
    host_path = pypi if pypi else f"{trust}:8443/repository/srsips-pypi"
    host_path = re.sub(r"^https?://", "", host_path)
    if nexus_user and nexus_password:
        idx_url = (
            f"https://{quote(nexus_user, safe='')}:{quote(nexus_password, safe='')}"
            f"@{host_path}/simple"
        )
        print("[kaniko] poetry index uses Nexus basic auth")
    else:
        idx_url = f"https://{host_path}/simple"
        print(
            "[kaniko] WARN: poetry index without auth — Nexus may return empty",
            file=__import__("sys").stderr,
        )
    poetry_run = (
        f"RUN pip install --no-cache-dir --trusted-host {trust} "
        f"'poetry<2' -i {idx_url}\n"
    )
    out_po, inserted_po = [], False
    for line in lines:
        if (
            not inserted_po
            and line.lstrip().upper().startswith("RUN ")
            and re.search(r"\bpoetry\b", line, re.I)
            and not re.search(r"pip\s+install\b[^\n]*\bpoetry\b", line, re.I)
        ):
            out_po.append(poetry_run)
            inserted_po = True
            print(f"[kaniko] inserted pip install poetry (<2) index={idx_url}")
        out_po.append(line)
    if not inserted_po:
        # poetry only in COPY/ENV — still insert after first FROM
        tmp = []
        for line in lines:
            tmp.append(line)
            if not inserted_po and line.upper().startswith("FROM "):
                tmp.append(poetry_run)
                inserted_po = True
                print(f"[kaniko] inserted pip install poetry after FROM index={idx_url}")
        out_po = tmp
    lines = out_po

# Stale poetry.lock vs pyproject.toml → "changed significantly"; refresh before install.
# Path-vendored aodb needs a real lock refresh (not --no-update).
if uses_poetry:
    lock_cmd = "poetry lock" if aodb_vendor else "poetry lock --no-update"
    out_lock, n_lock = [], 0
    for line in lines:
        if (
            re.search(r"\bpoetry\s+install\b", line, re.I)
            and not re.search(r"poetry\s+lock\b", line, re.I)
        ):
            line = re.sub(
                r"\bpoetry\s+install\b",
                f"{lock_cmd} && poetry install",
                line,
                count=1,
                flags=re.I,
            )
            n_lock += 1
        out_lock.append(line)
    if n_lock:
        print(f"[kaniko] prepended {lock_cmd} before poetry install ({n_lock})")
        lines = out_lock

# Corp Nexus often has custom CA; poetry/requests fail CERTIFICATE_VERIFY_FAILED.
if uses_poetry:
    out_cert, n_cert = [], 0
    for line in lines:
        if re.search(r"poetry\s+config\s+http-basic\.(\S+)", line, re.I) and "certificates." not in line:
            line2, n = re.subn(
                r"poetry\s+config\s+http-basic\.(\S+)\s+(\S+)\s+(\S+)",
                r"poetry config http-basic.\1 \2 \3 && poetry config certificates.\1.cert false",
                line,
                count=1,
                flags=re.I,
            )
            if n:
                line = line2
                n_cert += 1
        out_cert.append(line)
    if n_cert:
        print(f"[kaniko] poetry certificates.*.cert false after http-basic ({n_cert})")
        lines = out_cert

# B2: dedicated setuptools/wheel RUN before any pip install -r (cx_Oracle pkg_resources).
# setuptools 82+ dropped pkg_resources; pip build-isolation also pulls unconstrained
# setuptools into /tmp/pip-build-env-* unless PIP_CONSTRAINT is set.
# Keep base 65.x (already in python_prod) — do NOT --upgrade into 80.x.
CONSTRAINT_PATH = "/tmp/cxado-pip-constraints.txt"
if not any("PIP_CONSTRAINT" in ln or "cxado-pip-constraints" in ln for ln in lines):
    tmp, inserted_c = [], False
    for line in lines:
        tmp.append(line)
        if not inserted_c and (
            "PIP_TRUSTED_HOST" in line or "PIP_NO_INPUT" in line or line.upper().startswith("FROM ")
        ):
            tmp.append(f"RUN printf 'setuptools<70\\n' > {CONSTRAINT_PATH}\n")
            tmp.append(f"ENV PIP_CONSTRAINT={CONSTRAINT_PATH}\n")
            inserted_c = True
            print("[kaniko] inserted PIP_CONSTRAINT setuptools<70")
            if line.upper().startswith("FROM "):
                # also ensure PIP_NO_INPUT block already handled above
                pass
    lines = tmp

setup_run = (
    f"RUN pip install --no-cache-dir 'setuptools>=65,<70' wheel "
    f"--trusted-host {trust}\n"
)

def pin_setuptools_line(ln: str) -> str:
    """Rewrite bare setuptools upgrades to setuptools<70 (keep pkg_resources)."""
    if not re.search(r"pip\s+install\b", ln) or "setuptools" not in ln:
        return ln
    if "-r" in ln:
        return ln
    if re.search(r"setuptools\s*[<>=]", ln):
        # Replace any --upgrade setuptools<81 with <70 pin without upgrade
        new = re.sub(
            r"--upgrade\s+'setuptools<81'",
            "'setuptools>=65,<70'",
            ln,
        )
        new = re.sub(
            r"--upgrade\s+setuptools\b",
            "'setuptools>=65,<70'",
            new,
        )
        if new != ln:
            print("[kaniko] rewritten setuptools pin to >=65,<70")
        return new
    new = re.sub(
        r"(--upgrade\s+)?setuptools(\s|$)",
        r"'setuptools>=65,<70'\2",
        ln,
        count=1,
    )
    if new != ln:
        print("[kaniko] pinned setuptools>=65,<70 on existing RUN")
    return new

lines = [pin_setuptools_line(ln) for ln in lines]

has_setup_run = any(
    re.search(r"pip\s+install\b.*setuptools", ln)
    and "-r" not in ln
    for ln in lines
)
out = []
inserted_setup = has_setup_run
for i, line in enumerate(lines):
    if (
        not inserted_setup
        and re.search(r"pip\s+install\b", line)
        and "-r" in line
    ):
        out.append(setup_run)
        inserted_setup = True
        print("[kaniko] inserted separate RUN pip install 'setuptools>=65,<70' wheel")
    if re.search(r"pip\s+install\b", line) and "-r" in line:
        # Drop redundant setuptools token on the -r line (installed above).
        line = re.sub(r"\bsetuptools\s+", "", line)
        if vendor and "--find-links" not in line:
            line = line.rstrip("\n") + " --find-links /app/vendor-gismaputils\n"
        if "--trusted-host" not in line:
            line = line.rstrip("\n") + f" --trusted-host {trust}\n"
        # Avoid isolated build-env pulling setuptools>=82 without pkg_resources.
        if "--no-build-isolation" not in line:
            line = line.rstrip("\n") + " --no-build-isolation\n"
        out.append(line if line.endswith("\n") else line + "\n")
    else:
        out.append(line)
with open(df, "w", encoding="utf-8") as f:
    f.writelines(out)
print(f"[kaniko] patched Dockerfile setuptools+poetry+apt vendor={vendor}")
PY
fi

# Pass non-interactive pip into kaniko executor environment (defense in depth).
export PIP_NO_INPUT="${PIP_NO_INPUT:-1}"
export CI="${CI:-true}"
export PYTHONUNBUFFERED="${PYTHONUNBUFFERED:-1}"

# URL-encode for build-args without python (minimal: leave as-is if encoding unavailable)
NEXUS_USER_ENC="${NEXUS_USER:-}"
NEXUS_PASSWORD_ENC="${NEXUS_PASSWORD:-}"

CONTEXT_ABS=$(cd "$CONTEXT" && pwd)
set -- --dockerfile "$DF" --context "dir://${CONTEXT_ABS}" --destination "$DESTINATION" \
  --target "$BUILD_DOCKER_TARGET" \
  --build-arg "IMAGE_NAME=${BUILD_BASE_IMAGE}" \
  --skip-tls-verify \
  --insecure \
  --cache=false
if [ -n "${NEXUS_PYPI_URL:-}" ]; then
  set -- "$@" --build-arg "NEXUS_PYPI_URL=${NEXUS_PYPI_URL}"
fi
if [ -n "${NEXUS_USER_ENC}" ]; then
  set -- "$@" --build-arg "NEXUS_USERNAME=${NEXUS_USER_ENC}"
fi
if [ -n "${NEXUS_PASSWORD_ENC}" ]; then
  set -- "$@" --build-arg "NEXUS_PASSWORD=${NEXUS_PASSWORD_ENC}"
fi

echo "[kaniko] executor start"
set +e
/kaniko/executor "$@"
rc=$?
set -e

if [ "$rc" -eq 0 ]; then
  write_env "$IMAGE_TAG" 0 "$SOURCE_SHA"
  echo "[kaniko] pushed $DESTINATION BUILD_FALLBACK=0"
  exit 0
fi

if [ "${BUILD_FALLBACK_ALLOW}" = "0" ]; then
  echo "[kaniko] ERROR: service build failed rc=$rc and BUILD_FALLBACK=0 (parity wave — no base retag)" >&2
  write_env none 1 "$SOURCE_SHA"
  exit 1
fi

echo "[kaniko] WARN: service build failed rc=$rc — fallback FROM $BUILD_BASE_IMAGE"
FB_DIR="${CI_PROJECT_DIR:-.}/.kaniko-fallback"
rm -rf "$FB_DIR"
mkdir -p "$FB_DIR"
printf 'FROM %s\n' "$BUILD_BASE_IMAGE" > "$FB_DIR/Dockerfile"
FB_ABS=$(cd "$FB_DIR" && pwd)
set +e
/kaniko/executor \
  --dockerfile "$FB_DIR/Dockerfile" \
  --context "dir://${FB_ABS}" \
  --destination "$DESTINATION" \
  --skip-tls-verify \
  --insecure \
  --cache=false
frc=$?
set -e
if [ "$frc" -eq 0 ]; then
  write_env "$IMAGE_TAG" 1 "$SOURCE_SHA"
  echo "[kaniko] fallback pushed $DESTINATION BUILD_FALLBACK=1"
  exit 0
fi
echo "[kaniko] ERROR: fallback also failed"
write_env none 1 "$SOURCE_SHA"
exit 1
