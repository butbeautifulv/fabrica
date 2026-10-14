#!/usr/bin/env python3
"""Create map_objects-ci pipelines for curated mirror-services.yaml entries.

  GITLAB_TOKEN=… MIRROR_PROJECT_ID=1962 \\
    python3 scripts/mirror-fleet-trigger.py --dry-run
  python3 scripts/mirror-fleet-trigger.py --services a,b --wait --concurrency 1

No git tags. Variables: SERVICE_NAME, SOURCE_REF (= source_ref_fallback).
"""
from __future__ import annotations

import argparse
import json
import os
import ssl
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from lib.mirror_services import filter_services, load_services  # noqa: E402

WAVE3 = [
    "hwa_service",
    "data_lake_service",
    "user_service",
]
WAVE6 = WAVE3

TERMINAL = frozenset({"success", "failed", "canceled", "skipped", "manual"})


def api_base() -> str:
    base = os.environ.get("CI_API_V4_URL") or os.environ.get("GITLAB_URL") or "https://gitlab.svo.aero"
    base = base.rstrip("/")
    if not base.endswith("/api/v4"):
        base = f"{base}/api/v4"
    return base


def token() -> str:
    for k in ("GITLAB_TOKEN", "GITLAB_PAT", "SOURCE_GIT_TOKEN", "PRIVATE_TOKEN", "GITLAB_PAT_RUNNER"):
        v = os.environ.get(k)
        if v:
            return v
    raise SystemExit("ERROR: GITLAB_TOKEN required (unless --dry-run)")


def ssl_ctx() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    if os.environ.get("SOURCE_SSL_NO_VERIFY", "1") in ("1", "true", "TRUE"):
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


def http_json(method: str, url: str, tok: str, ctx: ssl.SSLContext, body: dict | None = None):
    data = None
    headers = {"PRIVATE-TOKEN": tok, "Content-Type": "application/json"}
    if body is not None:
        data = json.dumps(body).encode()
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    with urllib.request.urlopen(req, context=ctx, timeout=120) as resp:
        return json.load(resp)


def detect_ref(api: str, tok: str, project_id: str, ctx: ssl.SSLContext, explicit: str) -> str:
    if explicit:
        return explicit
    env_ref = os.environ.get("MIRROR_PIPELINE_REF", "")
    if env_ref:
        return env_ref
    try:
        p = http_json("GET", f"{api}/projects/{project_id}", tok, ctx)
        return str(p.get("default_branch") or "main")
    except urllib.error.HTTPError:
        return "main"


def poll_pipeline(
    api: str,
    tok: str,
    ctx: ssl.SSLContext,
    project_id: str,
    pipeline_id: int,
    *,
    timeout_s: float,
    interval_s: float,
) -> dict:
    deadline = time.monotonic() + timeout_s
    last = {}
    while time.monotonic() < deadline:
        last = http_json("GET", f"{api}/projects/{project_id}/pipelines/{pipeline_id}", tok, ctx)
        status = str(last.get("status") or "")
        if status in TERMINAL:
            return last
        time.sleep(interval_s)
    raise TimeoutError(f"pipeline {pipeline_id} not terminal after {timeout_s}s (last={last.get('status')})")


def poll_jobs(
    api: str,
    tok: str,
    ctx: ssl.SSLContext,
    project_id: str,
    pipeline_id: int,
    job_names: list[str],
    *,
    timeout_s: float,
    interval_s: float,
) -> dict[str, str]:
    deadline = time.monotonic() + timeout_s
    terminal_job = frozenset({"success", "failed", "canceled", "skipped"})
    statuses: dict[str, str] = {}
    while time.monotonic() < deadline:
        jobs = http_json("GET", f"{api}/projects/{project_id}/pipelines/{pipeline_id}/jobs?per_page=100", tok, ctx)
        by_name = {j["name"]: j for j in jobs}
        done = True
        for name in job_names:
            j = by_name.get(name)
            if not j:
                done = False
                continue
            st = str(j.get("status") or "")
            statuses[name] = st
            if st not in terminal_job:
                done = False
        if done and all(n in statuses for n in job_names):
            return statuses
        time.sleep(interval_s)
    return statuses


def write_matrix_row(jsonl_path: Path, row: dict) -> None:
    with jsonl_path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(row, ensure_ascii=False) + "\n")


def refresh_matrix_md(jsonl_path: Path, matrix_path: Path) -> None:
    if not jsonl_path.is_file():
        return
    rows = []
    for line in jsonl_path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            rows.append(json.loads(line))
    lines = [
        "# Mirror fleet matrix (report — not parallel execution)",
        "",
        "| ts (UTC) | service | source_ref | pipeline | status | duration_s | notes |",
        "|----------|---------|------------|----------|--------|------------|-------|",
    ]
    for r in rows:
        pid = r.get("pipeline_id") or ""
        url = r.get("web_url") or ""
        pipe_col = f"[{pid}]({url})" if pid and url else str(pid)
        lines.append(
            "| {ts} | {service} | {source_ref} | {pipe} | {status} | {dur} | {notes} |".format(
                ts=r.get("ts", "")[:19],
                service=r.get("service", ""),
                source_ref=r.get("source_ref", ""),
                pipe=pipe_col,
                status=r.get("status", r.get("error", "")),
                dur=r.get("duration_s", ""),
                notes=r.get("notes", ""),
            )
        )
    matrix_path.parent.mkdir(parents=True, exist_ok=True)
    matrix_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    ap = argparse.ArgumentParser(description="Mirror fleet pipeline trigger")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--ref", default="", help="Pipeline git ref on mirror (default: project default_branch)")
    ap.add_argument("--tier", default="", help="pilot|core|candidate|skip|all (empty = no tier filter)")
    ap.add_argument("--concurrency", type=int, default=1, help="Max in-flight creates; sleep between POSTs")
    ap.add_argument("--sleep", type=float, default=2.0, help="Seconds between pipeline creates")
    ap.add_argument("--services", default="", help="Comma-separated allow-list (default: all matching filters)")
    ap.add_argument("--enabled-only", action=argparse.BooleanOptionalAction, default=True)
    ap.add_argument("--wave3", action="store_true", help="Shorthand: Wave-3 pilot allow-list")
    ap.add_argument("--wave6", action="store_true", help="Alias for --wave3")
    ap.add_argument("--wait", action="store_true", help="Poll each pipeline until terminal before next")
    ap.add_argument("--wait-cleanup", action="store_true", help="After --wait, poll cleanup-test and cleanup-runner")
    ap.add_argument("--stop-on-fail", action="store_true", help="Stop queue when pipeline status=failed")
    ap.add_argument("--poll-interval", type=float, default=30.0)
    ap.add_argument("--poll-timeout", type=float, default=7200.0)
    ap.add_argument(
        "--registry",
        default=os.environ.get("MIRROR_SERVICES", str(ROOT / "config" / "mirror-services.yaml")),
    )
    ap.add_argument(
        "--jsonl",
        default=str(ROOT / "reports" / "mirror-fleet-last.jsonl"),
        help="Append live create results here",
    )
    ap.add_argument(
        "--matrix",
        default=str(ROOT / "reports" / "mirror-fleet-matrix.md"),
        help="Refresh markdown matrix from jsonl",
    )
    args = ap.parse_args()

    reg = Path(args.registry)
    if not reg.is_file():
        print(f"ERROR: missing {reg}", file=sys.stderr)
        return 1

    names = None
    if args.wave3 or args.wave6:
        names = list(WAVE3)
    elif args.services.strip():
        names = [x.strip() for x in args.services.split(",") if x.strip()]

    tier = args.tier.strip() or None
    svcs = filter_services(
        load_services(reg),
        tier=tier,
        enabled_only=args.enabled_only,
        names=names,
    )
    if not svcs:
        print("[fleet] no services matched filters", file=sys.stderr)
        return 1

    for s in svcs:
        sref = s.get("source_ref_fallback") or ""
        print(
            f"[fleet] SERVICE_NAME={s['name']} SOURCE_REF={sref} "
            f"tier={s.get('tier')} scan_order={s.get('scan_order')} skip_api={s.get('skip_api_security')}"
        )

    if args.dry_run:
        print(f"[fleet] dry-run count={len(svcs)}")
        return 0

    tok = token()
    project_id = os.environ.get("MIRROR_PROJECT_ID") or os.environ.get("CI_PROJECT_ID")
    if not project_id:
        print("ERROR: MIRROR_PROJECT_ID required", file=sys.stderr)
        return 1

    api = api_base()
    ctx = ssl_ctx()
    ref = detect_ref(api, tok, str(project_id), ctx, args.ref)
    jsonl_path = Path(args.jsonl)
    matrix_path = Path(args.matrix)
    jsonl_path.parent.mkdir(parents=True, exist_ok=True)

    failed = 0
    created = 0
    t0_queue = time.monotonic()

    for s in svcs:
        name = s["name"]
        sref = s.get("source_ref_fallback") or ""
        if not sref:
            print(f"[fleet] SKIP {name}: empty source_ref_fallback")
            failed += 1
            continue

        skip_api = bool(s.get("skip_api_security"))
        skip_deploy = skip_api
        env_rel = s.get("deploy_env_file") or ""
        if env_rel:
            env_path = ROOT / env_rel if not Path(env_rel).is_absolute() else Path(env_rel)
            if not env_path.is_file():
                skip_deploy = True
                print(f"[fleet] WARN {name}: missing {env_rel} — SKIP_DEPLOY=true")

        variables = [
            {"key": "SERVICE_NAME", "value": name},
            {"key": "SOURCE_REF", "value": sref},
            {"key": "SKIP_API_SECURITY", "value": "true" if skip_api else "false"},
            {"key": "SKIP_DEPLOY", "value": "true" if skip_deploy else "false"},
        ]
        body = {
            "ref": ref,
            "variables": variables,
        }
        t0 = time.monotonic()
        try:
            p = http_json("POST", f"{api}/projects/{project_id}/pipeline", tok, ctx, body)
            pipeline_id = int(p.get("id") or 0)
            row = {
                "ts": datetime.now(timezone.utc).isoformat(),
                "service": name,
                "source_ref": sref,
                "pipeline_id": pipeline_id,
                "status": p.get("status"),
                "web_url": p.get("web_url"),
                "notes": "",
            }
            print(f"  pipeline id={pipeline_id} status={row['status']} url={row['web_url']}")

            if args.wait and pipeline_id:
                final = poll_pipeline(
                    api,
                    tok,
                    ctx,
                    str(project_id),
                    pipeline_id,
                    timeout_s=float(args.poll_timeout),
                    interval_s=float(args.poll_interval),
                )
                row["status"] = final.get("status")
                notes = []
                if args.wait_cleanup:
                    jstat = poll_jobs(
                        api,
                        tok,
                        ctx,
                        str(project_id),
                        pipeline_id,
                        ["cleanup-test", "cleanup-runner"],
                        timeout_s=min(600.0, float(args.poll_timeout)),
                        interval_s=float(args.poll_interval),
                    )
                    notes.append(
                        "cleanup="
                        + ",".join(f"{k}={jstat.get(k, '?')}" for k in ("cleanup-test", "cleanup-runner"))
                    )
                row["notes"] = "; ".join(notes)
                row["duration_s"] = round(time.monotonic() - t0, 1)
                print(f"  final status={row['status']} duration_s={row['duration_s']} {row['notes']}")
                if row["status"] == "failed" and args.stop_on_fail:
                    write_matrix_row(jsonl_path, row)
                    refresh_matrix_md(jsonl_path, matrix_path)
                    print(f"[fleet] stop-on-fail after {name}", file=sys.stderr)
                    return 1

            write_matrix_row(jsonl_path, row)
            refresh_matrix_md(jsonl_path, matrix_path)
            created += 1
        except (urllib.error.HTTPError, TimeoutError) as e:
            print(f"[fleet] ERROR {name}: {e}", file=sys.stderr)
            failed += 1
            write_matrix_row(
                jsonl_path,
                {
                    "ts": datetime.now(timezone.utc).isoformat(),
                    "service": name,
                    "source_ref": sref,
                    "error": str(e),
                },
            )
            refresh_matrix_md(jsonl_path, matrix_path)
            if args.stop_on_fail:
                return 1
        # unbuffered progress line for bg logs
        print(f"[fleet] progress created={created} failed={failed}", flush=True)
        time.sleep(max(0.0, float(args.sleep)))

    refresh_matrix_md(jsonl_path, matrix_path)
    print(
        f"[fleet] done created={created} failed={failed} "
        f"elapsed_s={round(time.monotonic() - t0_queue, 1)} jsonl={jsonl_path} matrix={matrix_path}"
    )
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
