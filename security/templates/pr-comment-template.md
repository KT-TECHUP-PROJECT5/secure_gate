---
문서명: PR 댓글 템플릿
최신화: 2026-07-14
작성자: E파트
Version: 2.0
---

# PR Comment Template

`scripts/create-pr-comment.py`가 `gate-decision.json`을 읽어 실제로 생성하는 PR 댓글의
구조다. 이 문서는 스크립트의 출력과 동기화되어 있으며, 스크립트를 바꾸면 이 문서도 함께 갱신한다.

- 각 섹션은 **해당 데이터가 있을 때만** 표시된다 (차단 사유·경고·수정 가이드는 조건부).
- 수정 가이드는 `security/policies/remediation-guide.json`의 카테고리별 가이드가
  finding에 자동으로 주입되어 렌더된다. (더 이상 placeholder가 아니다.)
- 등급 판정 기준은 [취약점 등급 기준 문서](../../docs/severity-policy.md)를 따른다.

---

## 렌더 구조

### 1. 최종 판단 (항상 표시)

```markdown
## Secure PR Gate 결과

### 최종 판단

**Gate Status: ✅ PASSED**   ← 통과 시
**Gate Status: ❌ FAILED**   ← 차단 시
```

### 2. 검사 요약 (항상 표시)

| 영역 | 결과 | 요약 |
| --- | --- | --- |
| Build / Test | ✅ Passed / ❌ Failed / ⚠️ Warning / ⚠️ Not Run | 탐지 없음 · N건 |
| SAST (Semgrep) | 〃 | 〃 |
| Secret Scan (Gitleaks) | 〃 | 〃 |
| Dependency Scan (Trivy) | 〃 | 〃 |
| Runtime Validation | 〃 | 〃 |

결과 아이콘 규칙:

| 상태 | 표시 |
| --- | --- |
| 리포트 없음 | `⚠️ Not Run` |
| 통과·탐지 0건 | `✅ Passed / 탐지 없음` |
| 경고 | `⚠️ Warning / N건` |
| 차단 | `❌ Failed / N건` |

### 3. 차단 사유 (차단이 있을 때만)

```markdown
### 차단 사유

- Critical 등급 취약점이 탐지되었습니다.
- Secret 등급 취약점이 탐지되었습니다.
```

### 4. 경고 (Medium 또는 매핑 실패가 있을 때만)

```markdown
### 경고

- Medium 등급 취약점이 탐지되었습니다. 수정을 권장합니다.
- 매핑되지 않은 severity 'XXX' (도구: YYY) 이(가) 발견되어 '...'로 대체 처리되었습니다.
  security-gate-policy.json 갱신이 필요합니다.
```

### 5. 수정 가이드 (차단·경고 finding이 있을 때만)

finding 하나당 아래 블록이 반복된다. 내용은 `remediation-guide.json`에서 자동 주입된다.

```markdown
### 수정 가이드

#### ❌ [Critical] SQL Injection (semgrep)
- 위치: `src/user.py:42`
- 정적 분석 도구가 코드에서 잠재적인 보안 취약점 패턴을 발견했습니다.
- **조치**: (해당 카테고리 recommendation)
- 참고: https://owasp.org/www-project-top-ten/

수정 후 다시 push하면 Security Gate가 재실행됩니다.
```

- 아이콘: 차단 finding은 `❌`, 경고 finding은 `⚠️`
- 매핑 실패(`severity_fallback`) finding은 원본 값과 대체 등급을 함께 안내

### 6. 푸터 (항상 표시)

```markdown
---
*Secure PR Gate by A-Part Pipeline*
```

---

## 하위 호환

`findings` 필드가 없는 구버전 `gate-decision.json`의 경우, 수정 가이드는
상세 블록 대신 아래 기본 문구만 표시된다.

```markdown
### 수정 가이드

- 수정 후 다시 push하면 Security Gate가 재실행됩니다.
```
