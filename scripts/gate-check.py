#!/usr/bin/env python3
"""Evaluate scan reports against security-gate-policy.yaml."""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

SEVERITY_ORDER = {"note": 0, "none": 0, "info": 1, "low": 2, "medium": 3, "high": 4, "critical": 5, "error": 5}


def load_policy_section(path: Path, control: str) -> dict:
    text = path.read_text(encoding="utf-8")
    lines = text.splitlines()
    in_section = False
    section: dict = {}
    indent = None
    for line in lines:
        if re.match(rf"^{re.escape(control)}:\s*$", line):
            in_section = True
            indent = len(line) - len(line.lstrip())
            continue
        if not in_section:
            continue
        if line.strip() and not line.startswith(" ") and not line.startswith("\t"):
            break
        m = re.match(r"^\s+(\w+):\s*(.+)$", line)
        if m:
            key, val = m.group(1), m.group(2).strip()
            if val.startswith("[") and val.endswith("]"):
                section[key] = [x.strip().strip("'\"") for x in val[1:-1].split(",") if x.strip()]
            elif val in ("true", "false"):
                section[key] = val == "true"
            else:
                section[key] = val.strip("'\"")
    defaults = {}
    in_defaults = False
    for line in lines:
        if line.strip() == "defaults:":
            in_defaults = True
            continue
        if in_defaults:
            if line.strip() and not line.startswith(" "):
                break
            m = re.match(r"^\s+(\w+):\s*(.+)$", line)
            if m:
                key, val = m.group(1), m.group(2).strip()
                if val.startswith("[") and val.endswith("]"):
                    defaults[key] = [x.strip().strip("'\"") for x in val[1:-1].split(",") if x.strip()]
    section.setdefault("mode", "warn")
    section.setdefault("severity_block", defaults.get("severity_block", ["critical", "high"]))
    section.setdefault("severity_warn", defaults.get("severity_warn", ["medium"]))
    section.setdefault("block_on_kev", False)
    section.setdefault("block_on_high_epss", False)
    section.setdefault("warn_epss_threshold", 0.5)
    return section


def normalize_level(level: str) -> str:
    return (level or "note").lower().replace("warning", "medium").replace("error", "high")


def parse_sarif(path: Path) -> list[str]:
    data = json.loads(path.read_text(encoding="utf-8"))
    levels: list[str] = []
    for run in data.get("runs", []):
        for result in run.get("results", []):
            levels.append(normalize_level(result.get("level", "note")))
    return levels


def parse_gitlab_secrets(path: Path) -> list[str]:
    data = json.loads(path.read_text(encoding="utf-8"))
    levels: list[str] = []
    for vuln in data.get("vulnerabilities", data.get("secrets", [])):
        sev = normalize_level(vuln.get("severity", "high"))
        levels.append(sev)
    if data.get("total") or data.get("secret_detection"):
        levels.append("high")
    return levels


def parse_zap_baseline(path: Path) -> list[str]:
    data = json.loads(path.read_text(encoding="utf-8"))
    levels: list[str] = []
    risk_map = {"3": "high", "2": "medium", "1": "low", "0": "info"}
    for site in data.get("site", []):
        for alert in site.get("alerts", []):
            code = str(alert.get("riskcode", alert.get("risk", "1")))
            levels.append(risk_map.get(code, normalize_level(alert.get("riskdesc", "medium"))))
    return levels


def parse_junit(path: Path) -> list[str]:
    if not path.exists() or path.stat().st_size == 0:
        return []
    root = ET.parse(path).getroot()
    levels: list[str] = []
    suites = [root] if root.tag == "testsuite" else root.findall(".//testsuite")
    for suite in suites:
        for _ in range(int(suite.attrib.get("errors", "0") or "0")):
            levels.append("critical")
        for _ in range(int(suite.attrib.get("failures", "0") or "0")):
            levels.append("high")
        for case in suite.findall("testcase"):
            if case.find("error") is not None:
                levels.append("critical")
            elif case.find("failure") is not None:
                levels.append("high")
    return levels


def missing_report(path: Path, policy: dict) -> tuple[bool, str]:
    """A scanner produced no report at all — distinct from a report with zero findings.

    Treating "missing" the same as "clean" lets a crashed, misconfigured, or never-run
    tool pass a blocking gate as if a real scan happened. Only fail closed in block mode;
    warn mode still passes (warn->block is a deliberate phased rollout, see AGENTS.md),
    but always says so loudly instead of silently reporting findings=0.
    """
    mode = policy.get("mode", "warn")
    msg = f"missing report: {path} — tool produced no output; refusing to silently pass a blocking gate"
    if mode == "block":
        return False, msg
    return True, f"warn — {msg}"


def check_artifact(path: Path, policy: dict, label: str) -> tuple[bool, str]:
    mode = policy.get("mode", "warn")
    if not path.exists() or path.stat().st_size == 0:
        msg = f"missing or empty {label}: {path}"
        if mode == "block":
            return False, msg
        if policy.get("required_on_main") and mode == "warn":
            return True, f"warn — {msg}"
        return True, f"warn — {msg}" if mode == "warn" else msg
    return True, f"{label} present ({path.stat().st_size} bytes)"


def check_ml_data(path: Path, policy: dict) -> tuple[bool, str]:
    if not path.exists():
        return True, "no ml_data report (clean or no datasets)"
    levels = parse_report(path)
    # PII findings emitted as error/high — block when mode=block
    if policy.get("block_pii"):
        high = [l for l in levels if l in ("high", "critical", "error")]
        if high and policy.get("mode") == "block":
            return False, f"PII or blocking ml_data findings: {len(high)}"
    return evaluate(levels, policy)


def check_sbom_artifact(path: Path, policy: dict) -> tuple[bool, str]:
    return check_artifact(path, policy, "SBOM")


def check_sec_func_tests(path: Path, policy: dict) -> tuple[bool, str]:
    mode = policy.get("mode", "warn")
    if not path.exists():
        return True, "no sec-func report (tests skipped or passed)"
    levels = parse_report(path)
    return evaluate(levels, policy)


def check_infra(path: Path, policy: dict) -> tuple[bool, str]:
    """Count-based OVAL/XCCDF gate from summary_infra.json (not SARIF severity)."""
    mode = policy.get("mode", "warn")
    if not path.exists() or path.stat().st_size == 0:
        return missing_report(path, policy)

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as e:
        msg = f"invalid summary_infra.json: {e}"
        if mode == "block":
            return False, msg
        return True, f"warn — {msg}"

    failed = int(data.get("failed_checks", 0))
    env_override = os.environ.get("INFRA_FAILED_THRESHOLD")
    threshold = int(env_override if env_override is not None else policy.get("failed_threshold", 0))

    xccdf_failed = data.get("failed_checks_xccdf")
    xccdf_threshold = int(policy.get("xccdf_failed_threshold", 50))

    parts = [f"failed_checks={failed}", f"failed_threshold={threshold}"]
    over = failed > threshold
    if xccdf_failed is not None:
        xccdf_failed = int(xccdf_failed)
        parts.append(f"failed_checks_xccdf={xccdf_failed}")
        parts.append(f"xccdf_failed_threshold={xccdf_threshold}")
        over = over or xccdf_failed > xccdf_threshold

    detail = ", ".join(parts)
    if over:
        msg = f"infra threshold exceeded ({detail})"
        if mode == "block":
            return False, msg
        return True, f"warn only — {msg}"
    return True, f"ok ({detail})"


def parse_report(path: Path) -> list[str]:
    if not path.exists():
        return []
    text = path.read_text(encoding="utf-8").strip()
    if not text:
        return []
    data = json.loads(text)
    levels = [normalize_level(r.get("level", "note")) for r in data.get("runs", [{}])[0].get("results", [])]
    if levels:
        return levels
    if "runs" in data:
        return parse_sarif(path)
    if "vulnerabilities" in data or "secrets" in data:
        return parse_gitlab_secrets(path)
    if isinstance(data, list):
        return [normalize_level(x.get("severity", "high")) for x in data]
    return []


def count_kev_hits(path: Path) -> int:
    """Count SARIF results with properties.cisaKev=true."""
    if not path.exists() or path.stat().st_size == 0:
        return 0
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return 0
    n = 0
    for run in data.get("runs") or []:
        for result in run.get("results") or []:
            if not isinstance(result, dict):
                continue
            props = result.get("properties") or {}
            if isinstance(props, dict) and props.get("cisaKev"):
                n += 1
    return n


def evaluate_kev(path: Path, policy: dict) -> tuple[bool, str]:
    """WARN (or block if block_on_kev) when SARIF has CISA KEV hits."""
    n = count_kev_hits(path)
    if n <= 0:
        return True, "kev=0"
    msg = f"CISA KEV hits in SARIF: {n}"
    if policy.get("block_on_kev"):
        return False, msg
    return True, f"WARN — {msg} (block_on_kev=false)"


def count_high_epss(path: Path, threshold: float) -> int:
    """Count SARIF results with properties.epss >= threshold."""
    if not path.exists() or path.stat().st_size == 0:
        return 0
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return 0
    n = 0
    for run in data.get("runs") or []:
        for result in run.get("results") or []:
            if not isinstance(result, dict):
                continue
            props = result.get("properties") or {}
            if not isinstance(props, dict):
                continue
            raw = props.get("epss")
            try:
                score = float(raw) if raw is not None and raw != "" else None
            except (TypeError, ValueError):
                score = None
            if score is not None and score >= threshold:
                n += 1
    return n


def evaluate_epss(path: Path, policy: dict) -> tuple[bool, str]:
    """WARN (or block if block_on_high_epss) when SARIF has high EPSS hits."""
    try:
        threshold = float(policy.get("warn_epss_threshold", 0.5))
    except (TypeError, ValueError):
        threshold = 0.5
    n = count_high_epss(path, threshold)
    if n <= 0:
        return True, "epss=0"
    msg = f"EPSS>={threshold} hits in SARIF: {n}"
    if policy.get("block_on_high_epss"):
        return False, msg
    return True, f"WARN — {msg} (block_on_high_epss=false)"


def evaluate(levels: list[str], policy: dict) -> tuple[bool, str]:
    mode = policy.get("mode", "warn")
    if mode in ("info", "optional", "artifact"):
        return True, f"mode={mode}, gate skipped"

    block_set = {normalize_level(s) for s in policy.get("severity_block", ["critical", "high"])}
    warn_set = {normalize_level(s) for s in policy.get("severity_warn", ["medium"])}

    blocking = [l for l in levels if l in block_set]
    warning = [l for l in levels if l in warn_set]

    if blocking:
        msg = f"blocking findings: {blocking}"
        if mode == "block":
            return False, msg
        return True, f"warn only — {msg}"

    if warning and mode == "block":
        return True, f"warnings only: {warning}"

    # Count cap (SaC): max_findings > 0 fails when total finding levels exceed
    raw_max = policy.get("max_findings")
    if raw_max is not None and str(raw_max) != "":
        try:
            max_findings = int(raw_max)
        except (TypeError, ValueError):
            max_findings = 0
        if max_findings > 0 and len(levels) > max_findings:
            msg = f"max_findings exceeded: count={len(levels)} max={max_findings}"
            if mode == "block":
                return False, msg
            return True, f"warn only — {msg}"

    return True, "ok"


def main() -> None:
    p = argparse.ArgumentParser(description="Security gate check")
    p.add_argument("--control", required=True)
    p.add_argument("--report", required=True, type=Path)
    p.add_argument("--policy", default="config/security-gate-policy.yaml", type=Path)
    args = p.parse_args()

    if not args.policy.exists():
        print(f"Policy not found: {args.policy}", file=sys.stderr)
        sys.exit(2)

    # Canonical: osa-sca (composition), container (image). Legacy aliases still resolve.
    control = args.control
    _CONTROL_ALIASES = {
        "osa": "osa-sca",
        "sca": "container",
    }
    control = _CONTROL_ALIASES.get(control, control)

    policy = load_policy_section(args.policy, control)

    if args.control == "sbom":
        ok, msg = check_sbom_artifact(args.report, policy)
    elif args.control in ("ml_bom", "aibom"):
        ok, msg = check_artifact(args.report, policy, args.control)
    elif args.control == "ml_data":
        ok, msg = check_ml_data(args.report, policy)
    elif args.control == "dast":
        if args.report.exists():
            ok, msg = evaluate(parse_zap_baseline(args.report), policy)
        else:
            ok, msg = missing_report(args.report, policy)
    elif args.control == "iast":
        if args.report.exists():
            ok, msg = evaluate(parse_zap_baseline(args.report), policy)
        else:
            ok, msg = missing_report(args.report, policy)
    elif args.control == "fuzzing":
        if args.report.exists():
            ok, msg = evaluate(parse_junit(args.report), policy)
        else:
            ok, msg = missing_report(args.report, policy)
    elif args.control == "binary_fuzz":
        if args.report.exists():
            ok, msg = evaluate(parse_junit(args.report), policy)
        else:
            ok, msg = missing_report(args.report, policy)
    elif args.control == "sec_func_tests":
        ok, msg = check_sec_func_tests(args.report, policy)
    elif args.control == "infra":
        ok, msg = check_infra(args.report, policy)
    else:
        if args.report.exists():
            ok, msg = evaluate(parse_report(args.report), policy)
        else:
            ok, msg = missing_report(args.report, policy)

    if ok and control in ("osa-sca", "container", "osa", "sca") and args.report.exists():
        kev_ok, kev_msg = evaluate_kev(args.report, policy)
        if kev_msg != "kev=0":
            msg = f"{msg}; {kev_msg}"
        if not kev_ok:
            ok = False
        epss_ok, epss_msg = evaluate_epss(args.report, policy)
        if epss_msg != "epss=0":
            msg = f"{msg}; {epss_msg}"
        if not epss_ok:
            ok = False

    findings = 0
    if args.control == "sbom":
        findings = 1 if args.report.exists() else 0
    elif args.control == "infra" and args.report.exists():
        try:
            findings = int(json.loads(args.report.read_text(encoding="utf-8")).get("failed_checks", 0))
        except (json.JSONDecodeError, OSError, TypeError, ValueError):
            findings = 0
    elif args.control == "dast" and args.report.exists():
        findings = len(parse_zap_baseline(args.report))
    elif args.control == "iast" and args.report.exists():
        findings = len(parse_zap_baseline(args.report))
    elif args.control == "fuzzing" and args.report.exists():
        findings = len(parse_junit(args.report))
    elif args.control == "binary_fuzz" and args.report.exists():
        findings = len(parse_junit(args.report))
    elif args.control not in ("sbom", "dast", "iast", "fuzzing", "binary_fuzz", "infra"):
        findings = len(parse_report(args.report)) if args.report.exists() else 0
    print(f"[{args.control}] {msg} (findings={findings}, mode={policy.get('mode')})")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
