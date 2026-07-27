#!/usr/bin/env python3
"""
notify-discord.py

gate-decision.json 요약을 Discord Incoming Webhook으로 전송한다.

메시지 구성:
  제목: Hard/Soft mode · FAILED/SUCCESS
  레포지토리 / 커밋
  차단사유
  링크: GitHub Actions, PR 결과, AI 보고서 Artifact

환경변수:
  DISCORD_WEBHOOK_URL   Discord webhook URL (없으면 skip)
  GATE_DECISION_FILE    기본 security/reports/gate-decision.json
  NOTIFY_PROFILE        soft | hard (기본 hard)
  GITHUB_REPOSITORY     owner/repo
  GITHUB_SHA            commit sha
  GITHUB_RUN_ID         Actions run id
  GITHUB_SERVER_URL     기본 https://github.com
  PR_COMMENT_URL        soft 결과 링크 (PR 페이지/댓글)
  AI_REPORT_URL         AI Markdown 단독 Artifact 다운로드 링크
  DISCORD_FAIL_CLOSED   true면 webhook/HTTP 실패 시 exit 1
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

DEFAULT_DECISION = Path("security/reports/gate-decision.json")


def env(name: str, default: str = "") -> str:
    return os.environ.get(name, default).strip()


def load_decision(path: Path) -> dict:
    if not path.is_file():
        raise FileNotFoundError(f"gate-decision not found: {path}")
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("gate-decision.json must be an object")
    return data


def _truncate(text: str, limit: int = 900) -> str:
    text = text.strip()
    if len(text) <= limit:
        return text
    return text[: limit - 1] + "…"


def _clean_reason(text: str) -> str:
    text = str(text or "").strip()
    lowered = text.lower()
    if any(token in lowered for token in ("token", "password", "secret=", "api_key")):
        return "[상세 내용 생략]"
    # Drop trailing period noise for a tighter list.
    return text.rstrip("。.").strip() or text


def _reason_block(items: list[Any], *, failed: bool, limit: int = 5) -> str:
    if not failed:
        return "차단 사유 없음"
    lines = []
    for item in items[:limit]:
        cleaned = _clean_reason(item)
        if cleaned:
            lines.append(f"› {cleaned}")
    remaining = len(items) - limit
    if remaining > 0:
        lines.append(f"› 외 {remaining}건")
    return "\n".join(lines) if lines else "› (사유 미기재)"


def build_run_url() -> str:
    server = env("GITHUB_SERVER_URL", "https://github.com").rstrip("/")
    repo = env("GITHUB_REPOSITORY")
    run_id = env("GITHUB_RUN_ID")
    if repo and run_id:
        return f"{server}/{repo}/actions/runs/{run_id}"
    return ""


def build_commit_url(sha: str) -> str:
    server = env("GITHUB_SERVER_URL", "https://github.com").rstrip("/")
    repo = env("GITHUB_REPOSITORY")
    if repo and sha:
        return f"{server}/{repo}/commit/{sha}"
    return ""


def display_status(decision: dict) -> str:
    raw = str(decision.get("gate_status") or "").upper()
    if raw == "PASSED":
        return "SUCCESS"
    if raw == "FAILED":
        return "FAILED"
    return "FAILED" if decision.get("blocked") else "SUCCESS"


def _spacer_field(*, inline: bool = False) -> dict:
    # Horizontal spacer only (repo | gap | commit). Do not use for vertical gaps.
    return {"name": "\u200b", "value": "\u200b", "inline": inline}


def _section_pad(value: str) -> str:
    """Same trailing pad used after title/description → keeps vertical gaps uniform."""
    return f"{value}\n\u200b"


def build_message(decision: dict, *, profile: str) -> dict:
    status = display_status(decision)
    failed = status == "FAILED"
    block_reasons = decision.get("block_reasons") or []
    repo = env("GITHUB_REPOSITORY") or "unknown/repo"
    sha = env("GITHUB_SHA")
    short_sha = sha[:7] if sha else "unknown"
    run_url = build_run_url()
    commit_url = build_commit_url(sha)
    pr_url = env("PR_COMMENT_URL")
    ai_report_url = env("AI_REPORT_URL")

    mode_label = "Hard" if profile == "hard" else "Soft"
    title = f"{mode_label} mode · {status}"
    color = 0xED4245 if failed else 0x57F287  # Discord red / green
    # Trailing pad = reference gap (title → repo/commit). Reuse for every section.
    description = _section_pad(
        "보안 게이트에서 **차단**되었습니다."
        if failed
        else "보안 게이트를 **통과**했습니다."
    )

    commit_value = f"[`{short_sha}`]({commit_url})" if commit_url else f"`{short_sha}`"

    # Keep logs, PR result, and the standalone AI report as separate destinations.
    action_link = f"[실행 로그]({run_url})" if run_url else "`실행 로그 없음`"
    result_links = [action_link]
    if profile == "soft" and pr_url:
        result_links.append(f"[PR 결과]({pr_url})")
    if ai_report_url:
        result_links.append(f"[AI 보고서 다운로드]({ai_report_url})")
    else:
        result_links.append("`AI 보고서 다운로드 링크 없음`")

    fields = [
        # 3-column row: repo | spacer | commit → wider horizontal gap
        {"name": "레포지토리", "value": f"`{repo}`", "inline": True},
        _spacer_field(inline=True),
        # Pad last cell of the row so gap before 차단사유 matches title gap.
        {"name": "커밋", "value": _section_pad(commit_value), "inline": True},
        {
            "name": "차단사유",
            "value": _truncate(
                _section_pad(_reason_block(block_reasons, failed=failed))
            ),
            "inline": False,
        },
        {
            "name": "필수 확인",
            "value": "\n".join(result_links),
            "inline": False,
        },
    ]

    embed = {
        "title": title,
        "description": description,
        "color": color,
        "fields": fields,
        "footer": {"text": "Secure Gate"},
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    # Avoid duplicating the title in content; keep a short mobile-friendly line.
    return {
        "content": f"**{mode_label} mode 분석결과 {status}**",
        "embeds": [embed],
        "allowed_mentions": {"parse": []},
    }


def post_webhook(url: str, payload: dict, *, timeout: float = 15.0) -> None:
    data = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json", "User-Agent": "secure-gate-notify"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        if response.status not in (200, 204):
            raise RuntimeError(f"unexpected Discord status: {response.status}")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Send Secure Gate summary to Discord")
    parser.add_argument(
        "--decision",
        default=env("GATE_DECISION_FILE", str(DEFAULT_DECISION)),
        help="Path to gate-decision.json",
    )
    parser.add_argument(
        "--profile",
        default=env("NOTIFY_PROFILE", "hard"),
        choices=("soft", "hard"),
        help="Notification profile label",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print payload JSON without sending",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    fail_closed = env("DISCORD_FAIL_CLOSED", "").lower() in {"1", "true", "yes"}
    webhook = env("DISCORD_WEBHOOK_URL")

    try:
        decision = load_decision(Path(args.decision))
        payload = build_message(decision, profile=args.profile)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"[ERROR] Failed to build Discord payload: {error}", file=sys.stderr)
        return 1 if fail_closed else 0

    if args.dry_run:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
        return 0

    if not webhook:
        print("[INFO] DISCORD_WEBHOOK_URL unset — skipping Discord notification")
        return 0

    try:
        post_webhook(webhook, payload)
    except (urllib.error.URLError, TimeoutError, RuntimeError) as error:
        print(f"[WARN] Discord notification failed: {error}", file=sys.stderr)
        return 1 if fail_closed else 0

    print("[OK] Discord notification sent")
    return 0


if __name__ == "__main__":
    sys.exit(main())
