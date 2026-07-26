#!/usr/bin/env python3
"""
evaluate-gate.py

security-summary.json과 security-gate-policy.json을 읽어
Merge 차단 여부를 판단하고 gate-decision.json을 생성한다.

정책 기준:
- 검사는 PR soft / Post-merge hard로 강도가 달라도 차단 기준은 동일
- Secret, 실제 고위험 vuln, 가용성 장애, 스캐너 기술 실패만 Block
- misconfig / Medium 위생 이슈는 Warn
- dependency CVE는 category 판정 후 cve_track 보정 레이어로 promote/demote
"""

import json
import os
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import cve_track
import gate_policy

REPORTS_DIR = Path("security/reports")
SUMMARY_FILE = REPORTS_DIR / "security-summary.json"
POLICY_FILE = Path(
    os.environ.get(
        "SECURE_GATE_POLICY",
        "security/policies/security-gate-policy.json",
    )
)
SUPPRESSIONS_FILE = Path(
    os.environ.get(
        "SECURE_GATE_SUPPRESSIONS",
        "security/policies/suppressions.json",
    )
)
DECISION_FILE = REPORTS_DIR / "gate-decision.json"


def load_json(path: Path) -> dict:
    if not path.exists():
        print(f"[ERROR] File not found: {path}")
        sys.exit(1)
    with open(path) as f:
        return json.load(f)


def load_suppressions(path: Path) -> list:
    if not path.exists():
        return []
    try:
        with open(path) as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError) as error:
        print(f"[ERROR] Failed to parse suppressions: {error}")
        sys.exit(1)

    if isinstance(data, list):
        return data
    if isinstance(data, dict) and isinstance(data.get("suppressions"), list):
        return data["suppressions"]
    print("[ERROR] suppressions.json must be a list or {\"suppressions\": []}")
    sys.exit(1)


def evaluate(summary: dict, policy: dict, suppressions: list | None = None) -> dict:
    blocked = False
    block_reasons = []
    warnings = []
    suppressed = []
    suppressions = suppressions or []

    if summary.get("has_error") and policy.get("blockOnScannerError", True):
        blocked = True
        block_reasons.append(
            "필수 보안 보고서가 누락되었거나 올바르게 처리되지 않았습니다."
        )

    annotated_reports = {}
    for report_name, report in (summary.get("reports") or {}).items():
        if not isinstance(report, dict):
            annotated_reports[report_name] = report
            continue

        findings = []
        for finding in report.get("findings") or []:
            if not isinstance(finding, dict):
                continue
            annotated = gate_policy.with_category(finding)
            rule = gate_policy.is_suppressed(annotated, suppressions)
            if rule:
                suppressed.append(
                    {
                        "id": annotated.get("id"),
                        "location": annotated.get("location"),
                        "reason": rule.get("reason") or "suppressed",
                        "approved_by": rule.get("approved_by") or "",
                        "expires_on": rule.get("expires_on") or "",
                    }
                )
                warnings.append(
                    "예외 승인된 이슈: "
                    f"{annotated.get('title') or annotated.get('id')} "
                    f"(expires {rule.get('expires_on') or 'n/a'})"
                )
                continue

            if gate_policy.should_block_finding(annotated, policy):
                blocked = True
                reason = gate_policy.block_reason_for_finding(annotated)
                if reason not in block_reasons:
                    block_reasons.append(reason)
            elif gate_policy.should_warn_finding(annotated, policy):
                reason = gate_policy.warn_reason_for_finding(annotated)
                if reason not in warnings:
                    warnings.append(reason)

            findings.append(annotated)

        annotated_report = dict(report)
        annotated_report["findings"] = findings
        annotated_reports[report_name] = annotated_report

    # Backward-compatible severity flags still honor policy toggles when
    # reports were produced without per-finding details.
    if not annotated_reports:
        if policy.get("blockOnVulnCritical", True) and summary.get("has_critical"):
            blocked = True
            block_reasons.append("Critical 등급 취약점이 탐지되었습니다.")
        if policy.get("blockOnVulnHigh", True) and summary.get("has_high"):
            blocked = True
            block_reasons.append("High 등급 취약점이 탐지되었습니다.")
        if policy.get("blockOnSecret", True) and summary.get("has_secret"):
            blocked = True
            block_reasons.append("하드코딩된 Secret/자격증명이 탐지되었습니다.")
        if policy.get("warnOnMedium", True) and summary.get("has_medium"):
            warnings.append("Medium 등급 취약점이 탐지되었습니다. 수정을 권장합니다.")

    return {
        "gate_status": "FAILED" if blocked else "PASSED",
        "blocked": blocked,
        "block_reasons": block_reasons,
        "warnings": warnings,
        "suppressed": suppressed,
        "total_findings": summary.get("total_findings", 0),
        "reports": annotated_reports or summary.get("reports", {}),
    }


def main():
    summary = load_json(SUMMARY_FILE)
    policy = load_json(POLICY_FILE)
    suppressions = load_suppressions(SUPPRESSIONS_FILE)
    decision = evaluate(summary, policy, suppressions)

    cve_result = cve_track.load_cve_decision(policy)
    decision = cve_track.apply_cve_track(decision, cve_result, policy)

    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    with open(DECISION_FILE, "w") as f:
        json.dump(decision, f, indent=2)

    print(f"[Gate Status] {decision['gate_status']}")
    for reason in decision["block_reasons"]:
        print(f"  [BLOCK] {reason}")
    for warning in decision["warnings"]:
        print(f"  [WARN]  {warning}")
    for item in decision["suppressed"]:
        print(
            "  [SUPPRESS] "
            f"{item.get('id')} ({item.get('expires_on') or 'n/a'}): "
            f"{item.get('reason')}"
        )
    cve_meta = decision.get("cve_track") or {}
    if cve_meta:
        print(
            "  [CVE] "
            f"mode={cve_meta.get('mode')} source={cve_meta.get('source')} "
            f"promoted={cve_meta.get('promoted', 0)} "
            f"demoted={cve_meta.get('demoted', 0)} "
            f"applied={cve_meta.get('applied', 0)}"
        )
    print(f"  Total findings: {decision['total_findings']}")

    if decision["blocked"]:
        print("\nMerge is BLOCKED by Security Gate.")
        sys.exit(1)

    print("\nSecurity Gate PASSED. Merge is allowed.")


if __name__ == "__main__":
    main()
