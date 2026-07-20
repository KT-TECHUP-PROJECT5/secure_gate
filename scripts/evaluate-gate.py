#!/usr/bin/env python3
"""
evaluate-gate.py

security-summary.json, security-gate-policy.json(도구별 severity 매핑과
차단/경고 기준), remediation-guide.json(카테고리별 수정 가이드)을 읽어
Merge 차단 여부를 판단하고 gate-decision.json을 생성한다.

- 각 finding의 원본 severity를 도구별 매핑 테이블로 공통 등급
  (critical/high/medium/low/secret)으로 정규화한다.
- 정규화된 등급이 gateRules.blockOnSeverity에 있으면 차단,
  warnOnSeverity에 있으면 경고로 판정한다.
- 매핑 테이블에 없는 원본 severity는 unknownSeverityFallback으로 대체하고,
  해당 finding에 severity_fallback 표시를 남겨 PR 댓글에서도 드러나게 한다.

E 파트가 security/policies/security-gate-policy.json과
security/policies/remediation-guide.json 두 파일만 갱신하면
도구가 추가되거나 매핑 기준이 바뀌어도 이 스크립트는 수정할 필요가 없다.
"""

import json
import sys
from pathlib import Path

REPORTS_DIR   = Path("security/reports")
SUMMARY_FILE  = REPORTS_DIR / "security-summary.json"
POLICY_FILE   = Path("security/policies/security-gate-policy.json")
GUIDE_FILE    = Path("security/policies/remediation-guide.json")
DECISION_FILE = REPORTS_DIR / "gate-decision.json"

# block_reasons / warnings 문장을 만들 때 사용하는 표시 순서 및 라벨.
SEVERITY_ORDER  = ["critical", "high", "secret", "medium", "low"]
SEVERITY_LABELS = {
    "critical": "Critical",
    "high":     "High",
    "medium":   "Medium",
    "low":      "Low",
    "secret":   "Secret",
}


def load_json(path: Path) -> dict:
    if not path.exists():
        print(f"[ERROR] File not found: {path}")
        sys.exit(1)
    with open(path) as f:
        return json.load(f)


def normalize_severity(tool: str, raw_severity, severity_mapping: dict, fallback: str) -> tuple[str, bool]:
    """도구별 원본 severity를 공통 등급으로 변환한다.

    반환값은 (정규화된 등급, fallback 사용 여부).
    Gitleaks는 원본 severity 개념이 없는 도구이므로, finding에 어떤 값이
    들어있든 무시하고 항상 "default" 키로만 조회한다.
    """
    tool_mapping = severity_mapping.get(tool, {})

    if tool == "gitleaks":
        if "default" in tool_mapping:
            return tool_mapping["default"], False
        return fallback, True

    normalized = tool_mapping.get(raw_severity)
    if normalized is None:
        return fallback, True
    return normalized, False


def build_findings(reports: dict, policy: dict, guides: dict) -> list:
    severity_mapping = policy.get("severityMapping", {})
    category_map     = policy.get("toolCategoryMap", {})
    fallback         = policy.get("unknownSeverityFallback", "medium")
    block_set        = set(policy.get("gateRules", {}).get("blockOnSeverity", []))
    warn_set         = set(policy.get("gateRules", {}).get("warnOnSeverity", []))

    findings = []

    for report in reports.values():
        tool = report.get("tool", "")

        for finding in report.get("findings", []):
            raw_severity = finding.get("severity")
            normalized, used_fallback = normalize_severity(
                tool, raw_severity, severity_mapping, fallback
            )

            if used_fallback:
                print(
                    f"[WARN] Unknown severity '{raw_severity}' from tool '{tool}' "
                    f"-> falling back to '{fallback}'. security-gate-policy.json "
                    f"severityMapping 갱신이 필요할 수 있습니다."
                )

            category = category_map.get(tool)
            guide    = guides.get(category) if category else None

            blocking = normalized in block_set
            warning  = (not blocking) and normalized in warn_set

            record = {
                "id":                finding.get("id"),
                "tool":              tool,
                "category":          category,
                "title":             finding.get("title"),
                "location":          finding.get("location"),
                "original_severity": raw_severity,
                "severity":          normalized,
                "blocking":          blocking,
                "warning":           warning,
                "guide":             guide,
            }
            if used_fallback:
                record["severity_fallback"] = True

            findings.append(record)

    return findings


def _sorted_by_severity(severities: set) -> list:
    return sorted(
        severities,
        key=lambda s: SEVERITY_ORDER.index(s) if s in SEVERITY_ORDER else len(SEVERITY_ORDER),
    )


def build_reasons(findings: list) -> tuple[list, list]:
    blocking_severities = {f["severity"] for f in findings if f["blocking"]}
    warning_severities   = {f["severity"] for f in findings if f["warning"]}

    block_reasons = [
        f"{SEVERITY_LABELS.get(sev, sev)} 등급 취약점이 탐지되었습니다."
        for sev in _sorted_by_severity(blocking_severities)
    ]
    warnings = [
        f"{SEVERITY_LABELS.get(sev, sev)} 등급 취약점이 탐지되었습니다. 수정을 권장합니다."
        for sev in _sorted_by_severity(warning_severities)
    ]

    # 매핑 실패로 fallback이 발동한 finding은, 걸린 등급과 별개로
    # "정책 갱신이 필요하다"는 신호를 PR 댓글에서도 볼 수 있도록 warnings에 남긴다.
    for f in findings:
        if f.get("severity_fallback"):
            warnings.append(
                f"매핑되지 않은 severity '{f['original_severity']}' (도구: {f['tool']}) 이(가) "
                f"발견되어 '{f['severity']}'로 대체 처리되었습니다. "
                f"security-gate-policy.json 갱신이 필요합니다."
            )

    return block_reasons, warnings


def evaluate(summary: dict, policy: dict, guides: dict) -> dict:
    reports  = summary.get("reports", {})
    findings = build_findings(reports, policy, guides)

    blocked = any(f["blocking"] for f in findings)
    block_reasons, warnings = build_reasons(findings)

    return {
        "gate_status":    "FAILED" if blocked else "PASSED",
        "blocked":        blocked,
        "block_reasons":  block_reasons,
        "warnings":       warnings,
        "total_findings": len(findings),
        "reports":        reports,
        "findings":       findings,
    }


def main():
    summary  = load_json(SUMMARY_FILE)
    policy   = load_json(POLICY_FILE)
    guides   = load_json(GUIDE_FILE)
    decision = evaluate(summary, policy, guides)

    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    with open(DECISION_FILE, "w") as f:
        json.dump(decision, f, indent=2, ensure_ascii=False)

    print(f"[Gate Status] {decision['gate_status']}")
    for reason in decision["block_reasons"]:
        print(f"  [BLOCK] {reason}")
    for warning in decision["warnings"]:
        print(f"  [WARN]  {warning}")
    print(f"  Total findings: {decision['total_findings']}")

    if decision["blocked"]:
        print("\nMerge is BLOCKED by Security Gate.")
        sys.exit(1)
    else:
        print("\nSecurity Gate PASSED. Merge is allowed.")


if __name__ == "__main__":
    main()
