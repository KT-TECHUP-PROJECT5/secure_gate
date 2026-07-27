---
문서명: Discord 게이트 요약 알림
최신화: 2026-07-26
작성자: A파트
Version: 0.1.0
---

# Discord 게이트 요약 알림

Soft(PR) / Hard(post-merge) Gate 결과를 Discord Incoming Webhook으로 요약 전송한다.  
Telegram은 범위에서 제외한다.

| 모드 | Discord | 결과 리포트 링크 |
| --- | --- | --- |
| Soft | PR 댓글 후 알림 | PR 페이지 (`PR_COMMENT_URL`) |
| Hard | aggregate 후 알림 | AI/Artifact URL (`AI_REPORT_URL`, 없으면 Actions) |

## 무엇을 보내는가

`scripts/notify-discord.py`의 `build_message()`가 `gate-decision.json`을 읽어 아래 형식으로 전송한다.

```text
제목: Hard/Soft mode · FAILED/SUCCESS
설명: 차단/통과 한 줄
레포지토리 | 커밋
차단사유
필수 확인: 실행 로그 / 결과 리포트
```

색상: 실패 빨강 / 통과 초록

보내지 않는 것:

- Secret 원문 / 토큰성 문자열
- finding 전체 dump
- 상세 보고서 본문 (링크만)

결과 리포트 URL:

- soft: `PR_COMMENT_URL` (PR html_url) → 없으면 Actions run
- hard: `AI_REPORT_URL`(repo variable) → 없으면 Actions run

## Caller 설정

1. Discord 채널 → 채널 설정 → 연동 → **웹후크** 생성
2. caller 저장소 Secrets에 등록:

```text
DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/...
```

3. post-merge caller에서 secret을 전달:

```yaml
secrets:
  DISCORD_WEBHOOK_URL: ${{ secrets.DISCORD_WEBHOOK_URL }}
  # ...existing secrets
```

Webhook이 없으면 알림 step은 skip하며 게이트 판정에 영향을 주지 않는다 (fail-open).

## 실행 위치

`post-merge-security-gate.yml`의 aggregate job:

```text
Evaluate → Upload artifacts → Notify Discord → Enforce
```

Evaluate가 실패해도 Notify는 `if: always()`로 실행된 뒤 Enforce가 job을 실패시킨다.

## 로컬 확인

```bash
DISCORD_WEBHOOK_URL=... \
NOTIFY_PROFILE=hard \
GITHUB_REPOSITORY=owner/repo \
GITHUB_RUN_ID=1 \
python3 scripts/notify-discord.py --decision security/reports/gate-decision.json

# 전송 없이 payload만 보기
python3 scripts/notify-discord.py --decision security/reports/gate-decision.json --dry-run
```

## 관련 문서

- `docs/incident-response-playbook.md` — 알림 이후 사람 대응
- `docs/AI-reference.md` — AI 상세 보고서는 별도 채널
- `docs/aggregator-policy-baseline.md` — Block/Warn 기준
