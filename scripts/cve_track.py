#!/usr/bin/env python3
"""
cve_track.py

Category 기반 evaluate-gate 위에 얹는 dependency CVE 보정 레이어.

역할:
  - Trivy baseline 판정(severity·fix·purl)을 유지한 채
  - cve-policy-decision.json 의 KEV/EPSS/CVSS 신호로 promote / demote / keep
  - monitor 또는 annotateOnly=true 이면 판정은 바꾸지 않고 표시만 한다

상세: docs/cve-track-integration.md
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

SCRIPT_DIR = Path(__file__).resolve().parent
TOOLING_ROOT = SCRIPT_DIR.parent
TOOLING_SCRIPTS = TOOLING_ROOT / "scripts"
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import gate_policy
from paths import resolve_report
from severity import CVSS_BAND_FLOOR, SEVERITY_RANK as SEV_RANK

REPORTS_DIR = Path("security/reports")
SBOM_FILE = REPORTS_DIR / "sbom.cdx.json"

RUNNER_WHITELIST = {
    "cve-policy-evaluate": {
        "script": str(TOOLING_SCRIPTS / "cve-policy-evaluate.py"),
        "input_probe": "security/sbom/generated/cve-risk-assessment.json",
    },
}

CVE_DECISION_REQUIRED_KEYS = {
    "total_cves",
    "block_count",
    "warn_count",
    "package_failures",
    "cves",
}

DEPENDENCY_REPORT_KEYS = {"dependency_scan"}
DEPENDENCY_TOOLS = {"trivy"}


def _read_json_safe(path: Path) -> dict | None:
    try:
        if not path.is_file():
            return None
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return data if isinstance(data, dict) else None


def _cve_decision_valid(data: Any) -> bool:
    return isinstance(data, dict) and CVE_DECISION_REQUIRED_KEYS.issubset(data.keys())


def is_cve_adjustable_finding(
    finding: dict,
    *,
    report_key: str | None = None,
    tool: str | None = None,
) -> bool:
    """dependency vuln 이면서 CVE 보정 대상인지 여부."""
    if not isinstance(finding, dict):
        return False
    category = gate_policy.infer_category(finding)
    if category != "vuln":
        return False
    finding_id = str(finding.get("id") or "")
    if not finding_id.upper().startswith("CVE-"):
        return False
    if report_key in DEPENDENCY_REPORT_KEYS:
        return True
    if str(tool or finding.get("tool") or "").lower() in DEPENDENCY_TOOLS:
        return True
    return False


def annotate_verdicts(finding: dict, policy: dict) -> dict:
    """category 정책 기준 blocking/warning 플래그를 finding에 붙인다."""
    annotated = gate_policy.with_category(finding)
    annotated["blocking"] = gate_policy.should_block_finding(annotated, policy)
    annotated["warning"] = (
        not annotated["blocking"]
        and gate_policy.should_warn_finding(annotated, policy)
    )
    return annotated


def load_cve_decision(policy: dict) -> dict:
    """반환: {source, failure_type, decision, duration_ms}."""
    ct = policy.get("cveTrack") or {}
    mode = ct.get("enabled", "off")
    result = {
        "source": "skipped",
        "failure_type": None,
        "decision": None,
        "duration_ms": None,
    }
    if mode == "off":
        return result

    decision_default = Path(
        ct.get("decisionFile") or "security/reports/cve-policy-decision.json"
    )
    decision_file = (
        resolve_report(decision_default.name, env_var="SECURE_GATE_CVE_DECISION")
        or decision_default
    )

    data = _read_json_safe(decision_file)
    if _cve_decision_valid(data):
        result["source"] = "file"
        result["decision"] = data
        return result

    runner = ct.get("runner") or {}
    spec = RUNNER_WHITELIST.get(runner.get("runnerId"))
    allow = bool(runner.get("allowSelfInvoke"))
    input_present = bool(spec) and Path(spec["input_probe"]).exists()

    if allow and spec and input_present:
        argv = [sys.executable, spec["script"]]
        start = time.monotonic()
        try:
            subprocess.run(
                argv,
                timeout=ct.get("timeoutSeconds", 120),
                capture_output=True,
                text=True,
                check=False,
            )
        except subprocess.TimeoutExpired:
            result["source"] = "failed"
            result["failure_type"] = "timeout"
            result["duration_ms"] = int((time.monotonic() - start) * 1000)
            return result
        result["duration_ms"] = int((time.monotonic() - start) * 1000)
        data = _read_json_safe(decision_file)
        if _cve_decision_valid(data):
            result["source"] = "executed"
            result["decision"] = data
            return result
        result["source"] = "failed"
        result["failure_type"] = "scriptError"
        return result

    result["source"] = "failed"
    if SBOM_FILE.exists():
        result["failure_type"] = "scriptError"
    else:
        result["failure_type"] = "dataUnavailable"
    return result


def _bypass_active(policy: dict) -> bool:
    bypass = (policy.get("cveTrack") or {}).get("bypass") or {}
    if not bypass.get("enabled"):
        return False
    env_name = bypass.get("signalEnv", "CVE_TRACK_BYPASS")
    return os.environ.get(env_name, "").strip().lower() not in ("", "0", "false")


def _cve_top_findings(decision: dict, n: int = 3) -> list:
    def sort_key(item):
        evidence = item.get("evidence") or {}
        return (1 if evidence.get("kev") else 0, evidence.get("epss") or 0.0)

    relevant = [
        item
        for item in decision.get("cves") or []
        if item.get("verdict") in ("block", "warn")
    ]
    top = sorted(relevant, key=sort_key, reverse=True)[:n]
    return [
        {
            "cve": item.get("cve"),
            "epss": (item.get("evidence") or {}).get("epss"),
            "kev": (item.get("evidence") or {}).get("kev"),
            "verdict": item.get("verdict"),
        }
        for item in top
    ]


def _norm_purl(purl: Any) -> str | None:
    if not purl:
        return None
    normalized = str(purl).split("?", 1)[0].strip().lower()
    return normalized or None


def _norm_sev(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    severity = value.lower()
    return {"moderate": "medium"}.get(severity, severity)


def _coerce_epss(value: Any) -> float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value.strip())
        except ValueError:
            return None
    return None


def _more_severe(left: str | None, right: str | None) -> str | None:
    left_rank = SEV_RANK.get(left or "", 0)
    right_rank = SEV_RANK.get(right or "", 0)
    return left if left_rank >= right_rank else right


def _verdict_of(finding: dict) -> str:
    if finding.get("blocking"):
        return "block"
    if finding.get("warning"):
        return "warn"
    return "pass"


def _build_evidence_index(cve_decision: dict):
    by_key = {}
    by_cve = {}
    for item in cve_decision.get("cves") or []:
        cve = item.get("cve")
        evidence_raw = item.get("evidence") or {}
        entry = {
            "cve": cve,
            "kev": evidence_raw.get("kev") is True,
            "epss": _coerce_epss(evidence_raw.get("epss")),
            "severity": _norm_sev(evidence_raw.get("severity")),
        }
        for package in item.get("packages") or []:
            by_key[(_norm_purl(package.get("purl")), cve)] = entry
        if cve:
            by_cve.setdefault(cve, entry)
    return by_key, by_cve


def _match_evidence(finding: dict, by_key: dict, by_cve: dict):
    cve = finding.get("id")
    purl = _norm_purl(finding.get("purl"))
    if purl is not None:
        return by_key.get((purl, cve))
    return by_cve.get(cve)


def _decide_adjustment(finding: dict, evidence: dict, adj_cfg: dict):
    promote = adj_cfg.get("promote") or {}
    demote = adj_cfg.get("demote") or {}
    severity = _norm_sev(finding.get("severity"))

    if severity == "secret" or gate_policy.infer_category(finding) == "secret":
        return "keep", "", None

    if promote.get("kev") and evidence["kev"]:
        if not finding.get("blocking"):
            return "promote", "KEV 등재 — severity 무관 차단", "block"
        return "keep", "", None

    if finding.get("blocking") and demote.get("enabled", True):
        require_not_kev = demote.get("requireNotKev", True)
        max_epss = demote.get("maxEpss")
        min_sev = demote.get("minSeverity", "high")
        only_no_fix = demote.get("demoteOnlyWhenNoFix", True)
        guard = demote.get("neverDemoteAtOrAboveCvss")

        if require_not_kev and evidence["kev"]:
            return "keep", "", None
        if max_epss is not None and (
            evidence["epss"] is None or evidence["epss"] >= max_epss
        ):
            return "keep", "", None
        if SEV_RANK.get(severity or "", 0) < SEV_RANK.get(min_sev, 0):
            return "keep", "", None
        if only_no_fix and finding.get("fixedVersion"):
            return "keep", "", None
        if guard is not None:
            guard_sev = _more_severe(severity, evidence["severity"])
            if CVSS_BAND_FLOOR.get(guard_sev or "", 0.0) >= guard:
                return "keep", "", None
        epss_txt = (
            f"EPSS={evidence['epss']}" if evidence["epss"] is not None else "EPSS=?"
        )
        return (
            "demote",
            f"KEV 아님 · {epss_txt} < {max_epss} · fix 없음 → 차단→경고 강등",
            "warn",
        )

    return "keep", "", None


def _apply_verdict(finding: dict, target_verdict: str) -> None:
    if target_verdict == "block":
        finding["blocking"] = True
        finding["warning"] = False
    elif target_verdict == "warn":
        finding["blocking"] = False
        finding["warning"] = True


def _iter_adjustable_findings(decision: dict, policy: dict):
    reports = decision.get("reports") or {}
    for report_key, report in reports.items():
        if not isinstance(report, dict):
            continue
        tool = report.get("tool")
        findings = report.get("findings") or []
        for index, finding in enumerate(findings):
            if not is_cve_adjustable_finding(
                finding, report_key=report_key, tool=tool
            ):
                continue
            annotated = annotate_verdicts(finding, policy)
            findings[index] = annotated
            yield annotated


def _cve_only_kev_warnings(by_cve: dict, adjustable_ids: set[str]) -> list[str]:
    warnings = []
    for cve, evidence in by_cve.items():
        if evidence["kev"] and cve not in adjustable_ids:
            warnings.append(
                f"KEV 등재 CVE {cve}가 Trivy 결과에 없습니다 — 확인 필요(보정 대상 아님)."
            )
    return warnings


def _handle_track_failure(cve_result: dict, ct: dict, policy: dict):
    on_fail = ct.get("onTrackFailure") or {}
    bypass_cfg = ct.get("bypass") or {}
    failure_type = cve_result.get("failure_type") or "scriptError"
    behavior = on_fail.get(failure_type, "failClosed")

    warnings = ["CVE 입력 미생성 — 앞단 실행 여부 확인 필요"]
    block_reasons = []
    suppression = None

    if (
        behavior == "failClosed"
        and bypass_cfg.get("enabled")
        and bypass_cfg.get("scope") == "trackFailureOnly"
        and _bypass_active(policy)
    ):
        behavior = "failOpen"
        actor = os.environ.get("GITHUB_ACTOR", "unknown")
        suppression = {
            "active": True,
            "type": "cve-track-failure",
            "source": "env:CVE_TRACK_BYPASS",
            "actor": actor,
            "reason": None,
            "note": "coarse track-level bypass; 향후 per-finding suppression으로 확장",
        }
        warnings.append(
            f"CVE 트랙 실패가 우회(bypass)되었습니다 — actor:{actor}. "
            "이 PR은 CVE 검증 없이 통과됩니다."
        )

    if behavior == "failClosed":
        block_reasons.append(
            f"CVE 보정 트랙 실패({failure_type}) — 안전하게 차단합니다(fail-closed)."
        )
    else:
        warnings.append("CVE 검증 미수행")
    return block_reasons, warnings, suppression


def _recompute_from_findings(decision: dict, policy: dict) -> tuple[bool, list, list]:
    """CVE 보정 반영 후 category 판정 + finding blocking 플래그로 재계산."""
    blocked = False
    block_reasons: list[str] = []
    warnings: list[str] = []

    for report_key, report in (decision.get("reports") or {}).items():
        if not isinstance(report, dict):
            continue
        tool = report.get("tool")
        for finding in report.get("findings") or []:
            if not isinstance(finding, dict):
                continue
            annotated = gate_policy.with_category(finding)
            adjustable = is_cve_adjustable_finding(
                annotated, report_key=report_key, tool=tool
            )

            if adjustable and "blocking" in finding:
                is_block = bool(finding.get("blocking"))
                is_warn = bool(finding.get("warning")) and not is_block
            else:
                is_block = gate_policy.should_block_finding(annotated, policy)
                is_warn = gate_policy.should_warn_finding(annotated, policy)

            if is_block:
                blocked = True
                reason = gate_policy.block_reason_for_finding(annotated)
                if reason not in block_reasons:
                    block_reasons.append(reason)
            elif is_warn:
                reason = gate_policy.warn_reason_for_finding(annotated)
                if reason not in warnings:
                    warnings.append(reason)

    return blocked, block_reasons, warnings


def apply_cve_track(decision: dict, cve_result: dict, policy: dict) -> dict:
    """CVE 트랙을 게이트에 반영. monitor/annotateOnly면 표시만."""
    ct = policy.get("cveTrack") or {}
    mode = ct.get("enabled", "off")

    if mode == "off":
        decision["cve_track"] = {"mode": "off", "source": cve_result.get("source")}
        return decision

    if cve_result.get("source") == "skipped":
        return decision

    adj_cfg = ct.get("adjustment") or {}
    annotate_only = bool(adj_cfg.get("annotateOnly", True))
    apply_changes = (mode == "enforce") and not annotate_only

    adjustments: list[dict] = []
    cve_only_kev: list[str] = []
    decision_cve = cve_result.get("decision")
    adjustable_findings = list(_iter_adjustable_findings(decision, policy))
    adjustable_ids = {finding.get("id") for finding in adjustable_findings}

    # Preserve pre-CVE category reasons unless enforce applies changes.
    base_blocked = bool(decision.get("blocked"))
    base_block_reasons = list(decision.get("block_reasons") or [])
    base_warnings = list(decision.get("warnings") or [])

    if decision_cve is not None:
        by_key, by_cve = _build_evidence_index(decision_cve)
        for finding in adjustable_findings:
            evidence = _match_evidence(finding, by_key, by_cve)
            if evidence is None:
                continue
            action, reason, target = _decide_adjustment(finding, evidence, adj_cfg)
            if action == "keep":
                continue
            adjustments.append(
                {
                    "cve": finding.get("id"),
                    "purl": finding.get("purl"),
                    "action": action,
                    "from": _verdict_of(finding),
                    "to": target,
                    "reason": reason,
                    "applied": apply_changes,
                }
            )
            if apply_changes:
                _apply_verdict(finding, target)
        cve_only_kev = _cve_only_kev_warnings(by_cve, adjustable_ids)

    if apply_changes:
        blocked, block_reasons, warnings = _recompute_from_findings(decision, policy)
    else:
        blocked = base_blocked
        block_reasons = base_block_reasons
        warnings = list(base_warnings)

    for adjustment in adjustments:
        tag = "" if adjustment["applied"] else " [미반영]"
        warnings.append(
            "CVE 보정"
            f"{tag}: {adjustment['cve']} {adjustment['from']}→{adjustment['to']} "
            f"({adjustment['reason']})"
        )
    warnings.extend(cve_only_kev)

    suppression = None
    if decision_cve is None:
        fb_reasons, fb_warnings, suppression = _handle_track_failure(
            cve_result, ct, policy
        )
        warnings.extend(fb_warnings)
        if mode == "enforce":
            block_reasons.extend(fb_reasons)
        else:
            warnings.extend(f"[monitor] {reason}" for reason in fb_reasons)

    track_failure_block = mode == "enforce" and any(
        "CVE 보정 트랙 실패" in reason for reason in block_reasons
    )
    blocked = blocked or track_failure_block

    decision["blocked"] = blocked
    decision["block_reasons"] = block_reasons
    decision["warnings"] = warnings
    decision["gate_status"] = "FAILED" if blocked else "PASSED"
    decision["cve_adjustments"] = adjustments
    decision["cve_track"] = {
        "mode": mode,
        "source": cve_result.get("source"),
        "failure_type": cve_result.get("failure_type"),
        "would_block": track_failure_block,
        "block": decision_cve.get("block_count", 0) if decision_cve else 0,
        "warn": decision_cve.get("warn_count", 0) if decision_cve else 0,
        "policy_version": decision_cve.get("policy_version") if decision_cve else None,
        "annotate_only": annotate_only,
        "promoted": sum(1 for item in adjustments if item["action"] == "promote"),
        "demoted": sum(1 for item in adjustments if item["action"] == "demote"),
        "applied": sum(1 for item in adjustments if item["applied"]),
        "cve_only_kev": len(cve_only_kev),
        "top_findings": _cve_top_findings(decision_cve) if decision_cve else [],
        "duration_ms": cve_result.get("duration_ms"),
    }
    if suppression:
        decision["suppression"] = suppression
    return decision
