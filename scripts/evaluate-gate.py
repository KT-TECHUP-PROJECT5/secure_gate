#!/usr/bin/env python3
"""
evaluate-gate.py

security-summary.json과 security-gate-policy.json을 읽어
Merge 차단 여부를 판단하고 gate-decision.json을 생성한다.

- Critical / High / Secret 탐지 시 → FAILED (exit 1) → Merge 차단
- Medium 탐지 시 → PASSED with warning → PR 댓글 경고
- 모두 통과 시 → PASSED → Merge 허용

차단 기준은 security/policies/security-gate-policy.json에서 관리한다.
E 파트의 정책이 확정되면 해당 파일만 업데이트하면 된다.
"""

import json
import sys
from pathlib import Path

REPORTS_DIR   = Path("security/reports")
SUMMARY_FILE  = REPORTS_DIR / "security-summary.json"
POLICY_FILE   = Path("security/policies/security-gate-policy.json")
DECISION_FILE = REPORTS_DIR / "gate-decision.json"


def load_json(path: Path) -> dict:
    if not path.exists():
        print(f"[ERROR] File not found: {path}")
        sys.exit(1)
    with open(path) as f:
        return json.load(f)


def evaluate(summary: dict, policy: dict) -> dict:
    blocked       = False
    block_reasons = []
    warnings      = []

    if policy.get("blockOnCritical") and summary.get("has_critical"):
        blocked = True
        block_reasons.append("Critical 등급 취약점이 탐지되었습니다.")

    if policy.get("blockOnHigh") and summary.get("has_high"):
        blocked = True
        block_reasons.append("High 등급 취약점이 탐지되었습니다.")

    if policy.get("blockOnSecret") and summary.get("has_secret"):
        blocked = True
        block_reasons.append("하드코딩된 Secret/자격증명이 탐지되었습니다.")

    if policy.get("warnOnMedium") and summary.get("has_medium"):
        warnings.append("Medium 등급 취약점이 탐지되었습니다. 수정을 권장합니다.")

    return {
        "gate_status":    "FAILED" if blocked else "PASSED",
        "blocked":        blocked,
        "block_reasons":  block_reasons,
        "warnings":       warnings,
        "total_findings": summary.get("total_findings", 0),
        "reports":        summary.get("reports", {}),
    }


def main():
    summary  = load_json(SUMMARY_FILE)
    policy   = load_json(POLICY_FILE)
    decision = evaluate(summary, policy)

    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    with open(DECISION_FILE, "w") as f:
        json.dump(decision, f, indent=2)

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
