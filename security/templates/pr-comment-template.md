---
문서명: PR 댓글 템플릿
최신화: 2026-07-26
작성자: A파트
Version: 1.1
---

# PR Comment Template

아래 형식은 `create-pr-comment.py`가 생성하는 PR 댓글의 기준 구조입니다.
E 파트의 수정 가이드 템플릿이 확정되면 이 파일을 업데이트하고 스크립트와 연결합니다.

---

## Secure PR Gate 결과

### 최종 판단

**Gate Status: [PASSED ✅ / FAILED ❌]**

- Policy profile: `[pr / post_merge / training]`

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

### 승인된 예외

- [적용된 Accepted Risk의 Finding ID, 만료일, 승인자]

### 수정 가이드

<!-- E 파트의 수정 가이드 템플릿과 연결 예정 -->
- 수정 후 다시 push하면 Security Gate가 재실행됩니다.

### AI 요약

- [AI 전체 요약과 우선 개선 방향]

> AI 내용은 설명용이며, 최종 판정은 Gate Evaluator 결과를 따릅니다.

---
*Secure PR Gate by A-Part Pipeline*
