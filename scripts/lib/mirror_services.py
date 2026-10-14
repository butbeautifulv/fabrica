"""Shared parser for config/mirror-services.yaml (fleet / sync / inventory tooling).

CI resolve-mirror-service.sh stays shell/awk — this module is Python-only helpers.
Compat defaults when keys absent: enabled=True, tier=core.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any


def _parse_bool(raw: str, default: bool = True) -> bool:
    v = raw.strip().strip("\"'").lower()
    if v in ("true", "yes", "1", "on"):
        return True
    if v in ("false", "no", "0", "off"):
        return False
    return default


def load_services(path: str | Path) -> list[dict[str, Any]]:
    """Load services from mirror-services.yaml (minimal YAML subset, no PyYAML)."""
    text = Path(path).read_text(encoding="utf-8")
    services: list[dict[str, Any]] = []
    name: str | None = None
    cur: dict[str, Any] = {}
    in_svc = False

    def flush() -> None:
        nonlocal name, cur, in_svc
        if name and cur.get("project_id"):
            if "enabled" not in cur:
                cur["enabled"] = True
            if "tier" not in cur:
                cur["tier"] = "core"
            services.append({"name": name, **cur})
        name = None
        cur = {}
        in_svc = False

    for line in text.splitlines():
        if line.startswith("services:"):
            continue
        # service name: "  hwa_service:"
        if (
            line.startswith("  ")
            and not line.startswith("    ")
            and line.rstrip().endswith(":")
            and not line.strip().startswith("#")
        ):
            key = line.strip().rstrip(":")
            if key and ":" not in key:
                flush()
                name = key
                cur = {}
                in_svc = True
                continue
        if not in_svc or name is None:
            continue
        if line.startswith("    ") and ":" in line and not line.strip().startswith("#"):
            k, _, v = line.strip().partition(":")
            v = v.strip().strip("\"'")
            if k == "enabled":
                cur["enabled"] = _parse_bool(v, True)
            elif k == "tier":
                cur["tier"] = v or "core"
            elif k in (
                "project_id",
                "repo_url",
                "source_ref_fallback",
                "openapi_path",
                "api_base_url",
                "service_port",
                "deploy_command",
                "deploy_workdir",
                "readiness_path",
                "api_path_prefix",
                "deploy_env_file",
                "deploy_stubs",
                "build_docker_target",
            ):
                cur[k] = v
            elif k == "scan_order":
                try:
                    cur["scan_order"] = int(v)
                except ValueError:
                    cur["scan_order"] = 9999
            elif k == "skip_api_security":
                cur["skip_api_security"] = _parse_bool(v, False)
        if line and not line.startswith(" ") and not line.startswith("#"):
            flush()
    flush()
    return services


def filter_services(
    services: list[dict[str, Any]],
    *,
    tier: str | None = None,
    enabled_only: bool = True,
    names: list[str] | None = None,
) -> list[dict[str, Any]]:
    """Filter loaded services.

    tier: exact match, or \"all\" = any tier except skip.
    enabled_only: drop enabled=false when True.
    names: optional allow-list of service names.
    """
    out: list[dict[str, Any]] = []
    name_set = set(names) if names else None
    for s in services:
        if enabled_only and not s.get("enabled", True):
            continue
        t = str(s.get("tier") or "core")
        if tier == "all":
            if t == "skip":
                continue
        elif tier:
            if t != tier:
                continue
        else:
            # no tier filter: still exclude skip
            if t == "skip":
                continue
        if name_set is not None and s.get("name") not in name_set:
            continue
        out.append(s)
    out.sort(key=lambda x: (int(x.get("scan_order") or 9999), str(x.get("name") or "")))
    return out
