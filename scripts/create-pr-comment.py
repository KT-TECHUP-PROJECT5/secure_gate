#!/usr/bin/env python3
"""
create-pr-comment.py

gate-decision.json을 읽어 PR에 보안 검사 결과 댓글을 작성한다.
GitHub API를 표준 라이브러리(urllib)로 호출하므로 외부 의존성이 없다.

필요한 환경변수 (GitHub Actions에서 자동 주입):
  GITHUB_TOKEN : secrets.GITHUB_TOKEN
  PR_NUMBER    : github.event.pull_request.number
  REPO         : github.repository  (owner/repo 형식)
"""

import json
import os
import sys
import urllib.request
import urllib.error
from pathlib import Path

DECISION_FILE = Path("security/reports/gate-decision.json")

TOOL_LABELS = {
    "build":              "Build / Test",
    "sast":               "SAST (Semgrep)",
    "secret_scan":        "Secret Scan (Gitleaks)",
    "dependency_scan":    "Dependency Scan (Trivy)",
    "runtime_validation": "Runtime Validation",
}


def load_decision() -> dict:
    if not DECISION_FILE.exists():
        print(f"[WARN] gate-decision.json not found. Posting fallback comment.")
        return None
    with open(DECISION_FILE) as f:
        return json.load(f)


def report_row(label: str, report: dict) -> str:
    status = report.get("status", "not_found")
    count  = len(report.get("findings", []))

    if status == "not_found":
        return f"| {label} | ⚠️ Not Run | - |"
    elif status in ("passed",) and count == 0:
        return f"| {label} | ✅ Passed | 탐지 없음 |"
    elif status == "warning":
        return f"| {label} | ⚠️ Warning | {count}건 |"
    else:
        return f"| {label} | ❌ Failed | {count}건 |"


def finding_guide_block(finding: dict) -> str:
    icon     = "❌" if finding.get("blocking") else "⚠️"
    severity = (finding.get("severity") or "").capitalize()
    title    = finding.get("title") or "(제목 없음)"
    tool     = finding.get("tool", "-")
    location = finding.get("location") or "-"
    guide    = finding.get("guide") or {}

    lines = [f"#### {icon} [{severity}] {title} ({tool})", f"- 위치: `{location}`"]

    if guide.get("summary"):
        lines.append(f"- {guide['summary']}")
    if guide.get("recommendation"):
        lines.append(f"- **조치**: {guide['recommendation']}")
    if guide.get("reference"):
        lines.append(f"- 참고: {guide['reference']}")
    if finding.get("severity_fallback"):
        lines.append(
            f"- ⚠️ 원본 값 `{finding.get('original_severity')}`이(가) 정책에 매핑되어 있지 않아 "
            f"임시로 `{finding.get('severity')}`로 처리되었습니다."
        )

    return "\n".join(lines)


def build_guide_section(decision: dict) -> str:
    findings = decision.get("findings")

    # 구버전 gate-decision.json(findings 필드 없음)과의 하위 호환:
    # 차단/경고 사유는 있는데 finding 상세가 없으면 기존 안내 문구만 보여준다.
    if findings is None:
        if decision.get("block_reasons") or decision.get("warnings"):
            return (
                "\n### 수정 가이드\n\n"
                "- 수정 후 다시 push하면 Security Gate가 재실행됩니다.\n"
            )
        return ""

    relevant = [f for f in findings if f.get("blocking") or f.get("warning")]
    if not relevant:
        return ""

    blocks = "\n\n".join(finding_guide_block(f) for f in relevant)
    return (
        f"\n### 수정 가이드\n\n{blocks}\n\n"
        f"수정 후 다시 push하면 Security Gate가 재실행됩니다.\n"
    )


def build_comment(decision: dict | None) -> str:
    if decision is None:
        return (
            "## Secure PR Gate 결과\n\n"
            "⚠️ Gate 결과 파일을 불러오지 못했습니다. "
            "Workflow 로그를 확인해 주세요.\n\n"
            "---\n*Secure PR Gate by A-Part Pipeline*"
        )

    gate_status = decision.get("gate_status", "UNKNOWN")
    status_icon = "✅" if gate_status == "PASSED" else "❌"

    reports       = decision.get("reports", {})
    block_reasons = decision.get("block_reasons", [])
    warnings      = decision.get("warnings", [])

    rows = "\n".join(
        report_row(label, reports.get(key, {}))
        for key, label in TOOL_LABELS.items()
    )

    block_section = ""
    if block_reasons:
        items = "\n".join(f"- {r}" for r in block_reasons)
        block_section = f"\n### 차단 사유\n\n{items}\n"

    warning_section = ""
    if warnings:
        items = "\n".join(f"- {w}" for w in warnings)
        warning_section = f"\n### 경고\n\n{items}\n"

    guide_section = build_guide_section(decision)

    return (
        f"## Secure PR Gate 결과\n\n"
        f"### 최종 판단\n\n"
        f"**Gate Status: {status_icon} {gate_status}**\n\n"
        f"### 검사 요약\n\n"
        f"| 영역 | 결과 | 요약 |\n"
        f"| --- | --- | --- |\n"
        f"{rows}\n"
        f"{block_section}"
        f"{warning_section}"
        f"{guide_section}"
        f"\n---\n*Secure PR Gate by A-Part Pipeline*"
    )


def post_comment(token: str, repo: str, pr_number: str, body: str) -> None:
    url  = f"https://api.github.com/repos/{repo}/issues/{pr_number}/comments"
    data = json.dumps({"body": body}).encode("utf-8")

    req = urllib.request.Request(
        url,
        data=data,
        headers={
            "Authorization":        f"Bearer {token}",
            "Accept":               "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "Content-Type":         "application/json",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(req) as resp:
            if resp.status == 201:
                print("[OK] PR comment posted successfully.")
            else:
                print(f"[WARN] Unexpected status: {resp.status}")
    except urllib.error.HTTPError as e:
        print(f"[ERROR] HTTP {e.code}: {e.read().decode()}")
        sys.exit(1)


def main():
    token     = os.environ.get("GITHUB_TOKEN")
    pr_number = os.environ.get("PR_NUMBER")
    repo      = os.environ.get("REPO")

    if not all([token, pr_number, repo]):
        print("[ERROR] Missing environment variables: GITHUB_TOKEN, PR_NUMBER, REPO")
        sys.exit(1)

    decision = load_decision()
    body     = build_comment(decision)

    post_comment(token, repo, pr_number, body)


if __name__ == "__main__":
    main()
