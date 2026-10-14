#!/usr/bin/env python3
"""Generate config/mirror-deploy/*.env stubs for mirror services.

Remaps cluster IPs and legacy hosts to in-namespace stub DNS names used by
deploy-test-k8s.sh (mongo, redis, postgres, ci-http-stub).
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from lib.mirror_services import load_services  # noqa: E402

REMAP_HOSTS = (
    (re.compile(r"10\.96\.\d+\.\d+"), "postgres"),
    (re.compile(r"10\.248\.\d+\.\d+"), "ci-http-stub"),
    (re.compile(r"localhost:9092"), "localhost:9092"),
)

REMAP_URLS = (
    (re.compile(r"redis://[^@]*@:[0-9]+"), "redis://:gis_secret@redis:6379/0"),
    (re.compile(r"redis://[^/]+/"), "redis://redis:6379/0"),
    (re.compile(r"mongodb://[^@]+@[^:/]+"), "mongodb://root:example@mongo"),
    (re.compile(r"postgresql\+asyncpg://[^@]+@[^:/]+"), "postgresql+asyncpg://gis:gis@postgres"),
    (re.compile(r"postgresql://[^@]+@[^:/]+"), "postgresql://gis:gis@postgres"),
    (re.compile(r"https?://[^/]*auth[^/]*"), "http://ci-http-stub:8000/api/v1/auth"),
    (re.compile(r"https?://[^/]*uat[^/]*"), "http://ci-http-stub:8000/uat"),
)


def _stubs_for(service: dict) -> set[str]:
    raw = str(service.get("deploy_stubs") or "http,mongo")
    return {x.strip() for x in raw.split(",") if x.strip()}


def _lines_for(service: dict) -> list[str]:
    name = service["name"]
    stubs = _stubs_for(service)
    lines = [
        f"# Ephemeral CI deploy env for {name} (generated — NOT production).",
        "TZ=Europe/Moscow",
        "LOG_LEVEL=INFO",
        "SSL_VERIFY=False",
    ]
    if "http" in stubs:
        lines += [
            "URL_AUTH=http://ci-http-stub:8000/api/v1/auth",
            "URL_UAT=http://ci-http-stub:8000/uat",
            "UAT_USERNAME=ci",
            "UAT_PASSWORD=ci",
            "USE_UAT_INTEGRATION=False",
            "BACK_TO_BACK_USER=gis_admin",
            "BACK_TO_BACK_PASSWORD=123",
        ]
    if "mongo" in stubs:
        lines += [
            "MONGO_DB_CONNECTOR=mongodb://root:example@mongo:27017/?authSource=admin",
            f"MONGO_DB_NAME={name.replace('-', '_')}",
        ]
    if "postgres" in stubs:
        lines += [
            "POSTGRES_DB_CONNECTOR=postgresql+asyncpg://gis:gis@postgres:5432/gis",
            "POSTGRES_HOST=postgres",
            "POSTGRES_PORT=5432",
            "POSTGRES_USER=gis",
            "POSTGRES_PASSWORD=gis",
            "POSTGRES_DB=gis",
        ]
    if "redis" in stubs:
        lines += [
            "REDIS_HOST=redis",
            "REDIS_PORT=6379",
            "REDIS_DB_CONNECTOR=redis://:gis_secret@redis:6379/0",
        ]
    prefix = service.get("api_path_prefix") or "/v1"
    if not str(prefix).startswith("/"):
        prefix = f"/{prefix}"
    lines.append(f"BASE_API_PREFIX={prefix.rstrip('/')}")
    lines.append("KAFKA_BOOTSTRAP_SERVER_GIS=localhost:9092")
    lines.append("KAFKA_GROUP_GIS=ci-mirror")
    return lines


def _rewrite_line(line: str) -> str:
    out = line
    for pat, repl in REMAP_URLS:
        out = pat.sub(repl, out)
    for pat, repl in REMAP_HOSTS:
        out = pat.sub(repl, out)
    if re.search(r"=\s*$", out) and "_PORT" in out.split("=", 1)[0]:
        key = out.split("=", 1)[0]
        if key.endswith("_PORT"):
            out = f"{key}=5432" if "POSTGRES" in key else f"{key}=6379"
    return out


def write_env(service: dict, out_root: Path, *, force: bool) -> bool:
    rel = service.get("deploy_env_file")
    if not rel:
        return False
    path = out_root / rel
    if path.is_file() and not force:
        return False
    path.parent.mkdir(parents=True, exist_ok=True)
    content = "\n".join(_lines_for(service)) + "\n"
    if path.is_file():
        existing = path.read_text(encoding="utf-8").splitlines()
        merged = []
        for line in existing:
            if line.strip().startswith("#"):
                merged.append(line)
            else:
                merged.append(_rewrite_line(line))
        seen = {ln.split("=", 1)[0] for ln in merged if "=" in ln and not ln.startswith("#")}
        for line in content.splitlines():
            if "=" in line and not line.startswith("#"):
                key = line.split("=", 1)[0]
                if key not in seen:
                    merged.append(line)
        content = "\n".join(merged) + "\n"
    path.write_text(content, encoding="utf-8")
    return True


def main() -> int:
    ap = argparse.ArgumentParser(description="Generate mirror-deploy env stubs")
    ap.add_argument(
        "--registry",
        default=str(ROOT / "config" / "mirror-services.yaml"),
    )
    ap.add_argument("--force", action="store_true", help="Overwrite existing env files")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    services = load_services(args.registry)
    created = 0
    for svc in services:
        rel = svc.get("deploy_env_file")
        if not rel or svc.get("skip_api_security"):
            continue
        path = ROOT / rel
        if path.is_file() and not args.force:
            print(f"[gen-env] skip existing {rel}")
            continue
        if args.dry_run:
            print(f"[gen-env] would write {rel}")
            created += 1
            continue
        if write_env(svc, ROOT, force=args.force):
            print(f"[gen-env] wrote {rel}")
            created += 1
    print(f"[gen-env] done count={created}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
