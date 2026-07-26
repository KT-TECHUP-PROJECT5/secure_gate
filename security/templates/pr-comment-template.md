---
문서명: PR 댓글 템플릿
최신화: 2026-06-30
작성자: A파트
Version: 1.0
---

# PR Comment Template

아래 형식은 `create-pr-comment.py`가 생성하는 PR 댓글의 기준 구조입니다.
자동 수정 가이드 생성은 계획에서 제외했으며, AI 결과 보고서는 별도 담당이 구성한다.
Gate 판단 기준은 `docs/aggregator-policy-baseline.md`를 따른다.

---

## Secure PR Gate 결과

### 최종 판단

**Gate Status: [PASSED ✅ / FAILED ❌]**

### 검사 요약

| 영역               | 결과    | 요약       |
| ------------------ | ------- | ---------- |
| Build / Test       | -       | -          |
| SAST               | -       | -          |
| Secret Scan        | -       | -          |
| Dependency Scan    | -       | -          |
| Runtime Validation | -       | -          |

### 차단 사유

- [차단 사유가 있는 경우 기재]

### 경고

- [Medium 등급 경고가 있는 경우 기재]

### 다음 행동

- 상세 결과는 Artifact의 `gate-decision.json` / `security-summary.json`을 확인한다.
- 수정 후 다시 push하면 Security Gate가 재실행된다.

---
*Secure PR Gate by A-Part Pipeline*
