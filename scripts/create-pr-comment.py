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


# 그룹당 나열할 최대 위치 수. 취약점이 많아도 댓글이 GitHub 한계(65536자)를
# 넘지 않도록, 같은 카테고리는 가이드를 한 번만 쓰고 위치는 이만큼만 보여준다.
MAX_LOCATIONS_PER_GROUP = 10

# 그룹 내 위치를 심각도 높은 순으로 정렬하기 위한 순위.
SEVERITY_RANK = {"critical": 0, "high": 1, "secret": 2, "medium": 3, "low": 4}


def _severity_display(finding: dict) -> str:
    sev = (finding.get("severity") or "").capitalize()
    if finding.get("severity_fallback"):
        return f"{sev}(원본:{finding.get('original_severity')})"
    return sev


def _group_key(finding: dict) -> str:
    # 같은 카테고리는 같은 수정 가이드를 공유하므로 카테고리 기준으로 묶는다.
    return finding.get("category") or finding.get("tool") or "기타"


def guide_group_block(findings: list, blocking: bool) -> str:
    """같은 카테고리 finding들을 하나의 블록으로: 가이드 1회 + 위치 목록(상한)."""
    icon   = "❌" if blocking else "⚠️"
    sample = findings[0]
    guide  = sample.get("guide") or {}
    tool   = sample.get("tool", "-")
    label  = guide.get("label") or _group_key(sample)

    lines = [f"#### {icon} {label} — {tool} ({len(findings)}건)"]
    if guide.get("summary"):
        lines.append(f"- {guide['summary']}")
    if guide.get("recommendation"):
        lines.append(f"- **조치**: {guide['recommendation']}")
    if guide.get("reference"):
        lines.append(f"- 참고: {guide['reference']}")

    ordered = sorted(
        findings,
        key=lambda f: SEVERITY_RANK.get(f.get("severity"), len(SEVERITY_RANK)),
    )
    shown = ordered[:MAX_LOCATIONS_PER_GROUP]

    lines.append("- 해당 위치:")
    for f in shown:
        title = (f.get("title") or "").strip()
        if len(title) > 80:
            title = title[:80] + "…"
        suffix = f" — {title}" if title else ""
        lines.append(f"  - [{_severity_display(f)}] `{f.get('location') or '-'}`{suffix}")

    remaining = len(findings) - len(shown)
    if remaining > 0:
        lines.append(f"  - …외 {remaining}건 (동일 유형)")

    return "\n".join(lines)


def _render_grouped(findings: list, blocking: bool, heading: str) -> str:
    if not findings:
        return ""
    groups: dict = {}
    for f in findings:
        groups.setdefault(_group_key(f), []).append(f)
    blocks = "\n\n".join(guide_group_block(items, blocking) for items in groups.values())
    return f"{heading}\n\n{blocks}"


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

    blocking = [f for f in findings if f.get("blocking")]
    warning  = [f for f in findings if f.get("warning") and not f.get("blocking")]
    if not blocking and not warning:
        return ""

    sections = [
        s for s in (
            _render_grouped(blocking, True,  "**🚫 차단 대상**"),
            _render_grouped(warning,  False, "**⚠️ 경고 (수정 권장)**"),
        ) if s
    ]
    body = "\n\n".join(sections)
    return (
        f"\n### 수정 가이드\n\n{body}\n\n"
        f"수정 후 다시 push하면 Security Gate가 재실행됩니다.\n"
    )


def build_banner(decision: dict) -> str:
    """CVE 트랙 상태 배너를 '한 곳에서' 결정한다.

    조용한 fail-open이 가장 위험하므로, 최종 판단 바로 아래에 blockquote로
    눈에 띄게 렌더한다. 우선순위: bypass > 트랙 실패(monitor/fail-closed/
    fail-open) > monitor 정상. 향후 suppression 배너는 여기에 추가한다.
    """
    cve = decision.get("cve_track") or {}
    supp = decision.get("suppression") or {}
    mode = cve.get("mode")
    source = cve.get("source")
    parts = []

    if supp.get("active"):
        parts.append(
            "> 🟠 **CVE 트랙 우회(bypass) 적용됨**  \n"
            f"> actor: `{supp.get('actor', 'unknown')}` · 유형: `{supp.get('type')}`  \n"
            "> 이 PR은 **CVE 검증 없이** 통과되었습니다. "
            "**우회 사유를 PR 코멘트로 남겨 주세요.**"
        )

    if source == "failed":
        ft = cve.get("failure_type") or "unknown"
        if mode == "monitor":
            parts.append(
                "> 🔵 **CVE 트랙 실패 (monitor 모드 — 차단 안 함)**  \n"
                f"> 유형: `{ft}` · 결과는 기록만 됩니다. "
                "앞단(SBOM→OSV→CVE) 실행 여부를 확인하세요."
            )
        elif cve.get("would_block"):
            parts.append(
                "> 🔴 **CVE 검증 실패로 Merge가 차단되었습니다 (fail-closed)**  \n"
                f"> 유형: `{ft}` · 앞단 실행/스크립트 상태를 확인하세요."
            )
        else:
            parts.append(
                "> 🟡 **CVE 검증이 수행되지 않았습니다 (fail-open)**  \n"
                f"> 유형: `{ft}` · 이 PR은 **CVE 트랙 없이** 판정되었습니다. "
                "앞단 실행 여부를 확인하세요."
            )
    elif mode == "monitor" and source in ("file", "executed"):
        parts.append(
            "> 🔵 **CVE 트랙 monitor 모드**  \n"
            f"> 차단 후보 {cve.get('block', 0)}건 / 경고 {cve.get('warn', 0)}건 "
            "— 결과 기록만, Merge 차단 없음."
        )

    return ("\n\n".join(parts) + "\n") if parts else ""


def build_adjustment_section(decision: dict) -> str:
    """CVE 보정(승격/강등) 내역을 '무엇을 왜'로 표시. 강등은 반드시 명시된다.

    annotateOnly / monitor 로 판정 미반영인 항목은 '표시만'으로 구분한다.
    """
    adjustments = decision.get("cve_adjustments") or []
    if not adjustments:
        return ""

    label = {"promote": "🔺 승격", "demote": "🔻 강등"}
    rows = []
    for a in adjustments:
        applied = "반영" if a.get("applied") else "표시만"
        rows.append(
            f"| {a.get('cve')} | `{a.get('purl') or '-'}` | {label.get(a.get('action'), a.get('action'))} "
            f"| {a.get('from')} → {a.get('to')} | {applied} | {a.get('reason')} |"
        )

    return (
        "\n### CVE 보정 내역\n\n"
        "| CVE | 패키지 | 조치 | 변화 | 반영 | 근거 |\n"
        "| --- | --- | --- | --- | --- | --- |\n"
        + "\n".join(rows) + "\n"
    )


# GitHub 이슈/PR 댓글 본문 한계는 65536자. 안전 여유를 두고 그 아래에서 자른다.
MAX_COMMENT_CHARS = 60000


def _enforce_length_limit(body: str) -> str:
    """그룹화 후에도 본문이 한계를 넘으면 마지막 안전장치로 잘라낸다."""
    if len(body) <= MAX_COMMENT_CHARS:
        return body
    notice = (
        "\n\n> ⚠️ 결과가 많아 댓글이 잘렸습니다. 전체 내역은 "
        "Actions 아티팩트(gate-decision.json)를 확인하세요.\n"
        "\n---\n*Secure PR Gate by A-Part Pipeline*"
    )
    return body[: MAX_COMMENT_CHARS - len(notice)] + notice


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
    adjustment_section = build_adjustment_section(decision)
    banner = build_banner(decision)
    banner_section = f"\n{banner}\n" if banner else ""

    body = (
        f"## Secure PR Gate 결과\n\n"
        f"### 최종 판단\n\n"
        f"**Gate Status: {status_icon} {gate_status}**\n\n"
        f"{banner_section}"
        f"### 검사 요약\n\n"
        f"| 영역 | 결과 | 요약 |\n"
        f"| --- | --- | --- |\n"
        f"{rows}\n"
        f"{block_section}"
        f"{warning_section}"
        f"{adjustment_section}"
        f"{guide_section}"
        f"\n---\n*Secure PR Gate by A-Part Pipeline*"
    )
    return _enforce_length_limit(body)


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
    body = build_comment(decision)

    post_comment(token, repo, pr_number, body)


if __name__ == "__main__":
    main()
