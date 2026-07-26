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
AI_SUMMARY_FILE = Path("security/reports/ai-security-summary.json")

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


def load_ai_summary() -> dict | None:
    if not AI_SUMMARY_FILE.exists():
        return None
    try:
        with open(AI_SUMMARY_FILE) as summary_file:
            data = json.load(summary_file)
    except (OSError, json.JSONDecodeError):
        return None
    return data if isinstance(data, dict) else None


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


def build_ai_section(ai_summary: dict | None) -> str:
    if not ai_summary:
        return ""

    status = ai_summary.get("status")
    if status != "succeeded":
        return (
            "\n### AI 설명\n\n"
            f"- 생성 상태: `{status or 'unknown'}`\n"
            f"- Gate 판정에는 영향을 주지 않습니다.\n"
        )

    analysis = ai_summary.get("analysis")
    if not isinstance(analysis, dict):
        return ""

    executive_summary = analysis.get("executive_summary", "")
    prioritized_findings = analysis.get("prioritized_findings", [])
    lines = ["\n### AI 요약\n", executive_summary]
    if prioritized_findings:
        lines.extend(["\n#### 우선 개선 방향\n"])
        for finding in prioritized_findings[:5]:
            if not isinstance(finding, dict):
                continue
            lines.append(
                f"- **{finding.get('title', 'Untitled finding')}** "
                f"(`{finding.get('severity', 'unknown')}`): "
                f"{finding.get('remediation', '')}"
            )
    lines.append(
        "\n> AI 내용은 설명용이며, 최종 판정은 Gate Evaluator 결과를 따릅니다.\n"
    )
    return "\n".join(lines)


def build_comment(
    decision: dict | None,
    ai_summary: dict | None = None,
) -> str:
    if decision is None:
        return (
            "## Secure PR Gate 결과\n\n"
            "⚠️ Gate 결과 파일을 불러오지 못했습니다. "
            "Workflow 로그를 확인해 주세요.\n\n"
            "---\n*Secure PR Gate by A-Part Pipeline*"
        )

    gate_status = decision.get("gate_status", "UNKNOWN")
    status_icon = "✅" if gate_status == "PASSED" else "❌"
    policy_profile = decision.get("policy_profile", "unknown")

    reports       = decision.get("reports", {})
    block_reasons = decision.get("block_reasons", [])
    warnings      = decision.get("warnings", [])
    accepted_risks = decision.get("accepted_risks", [])

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

    exception_section = ""
    if accepted_risks:
        items = "\n".join(
            (
                f"- `{entry.get('id', 'unknown')}` "
                f"(만료: {entry.get('expiresAt', 'unknown')}, "
                f"승인: {entry.get('approvedBy', 'unknown')})"
            )
            for entry in accepted_risks
        )
        exception_section = f"\n### 승인된 예외\n\n{items}\n"

    guide_section = (
        "\n### 수정 가이드\n\n"
        "<!-- E 파트의 수정 가이드 템플릿과 연결 예정 -->\n"
        "- 수정 후 다시 push하면 Security Gate가 재실행됩니다.\n"
        if block_reasons else ""
    )
    ai_section = build_ai_section(ai_summary)

    return (
        f"## Secure PR Gate 결과\n\n"
        f"### 최종 판단\n\n"
        f"**Gate Status: {status_icon} {gate_status}**\n\n"
        f"- Policy profile: `{policy_profile}`\n\n"
        f"### 검사 요약\n\n"
        f"| 영역 | 결과 | 요약 |\n"
        f"| --- | --- | --- |\n"
        f"{rows}\n"
        f"{block_section}"
        f"{warning_section}"
        f"{exception_section}"
        f"{guide_section}"
        f"{ai_section}"
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
    token = os.environ.get("GITHUB_TOKEN", "").strip()
    pr_number = os.environ.get("PR_NUMBER", "").strip()
    repo = os.environ.get("REPO", "").strip()

    # push / workflow_dispatch 등 PR이 아닌 이벤트에서는 댓글 대상이 없다.
    if not pr_number:
        print("[WARN] PR_NUMBER is empty — skipping PR comment (non-PR event).")
        return

    missing = [
        name
        for name, value in (
            ("GITHUB_TOKEN", token),
            ("REPO", repo),
        )
        if not value
    ]
    if missing:
        print(f"[ERROR] Missing environment variables: {', '.join(missing)}")
        sys.exit(1)

    decision = load_decision()
    ai_summary = load_ai_summary()
    body = build_comment(decision, ai_summary)

    post_comment(token, repo, pr_number, body)


if __name__ == "__main__":
    main()
