---
문서명: Incident Response 플레이북
최신화: 2026-07-14
작성자: E파트
Version: 1.0.0
---

# Incident Response 플레이북

Security Gate가 탐지한 주요 보안 이벤트에 대해 **누가, 무엇을, 어떤 순서로**
대응할지를 정의한다. 모든 플레이북은 공통 4단계 절차를 따른다.

```text
탐지(Detect) → 확인(Triage) → 대응(Respond) → 복구(Recover)
```

- **탐지**: 어떤 도구/게이트가 무엇을 잡았는가
- **확인**: 진짜 문제인가(오탐 여부), 영향 범위는 어디까지인가
- **대응**: 확산을 막고 위협을 제거하는 즉시 조치
- **복구**: 정상화, 재발 방지, 기록

> 이벤트 등급과 처리 기준의 근거는 [취약점 등급 기준 문서](./severity-policy.md)를 따른다.

---

## 이벤트 등급 및 대응 SLA

| 등급 | 정의 | 초기 대응 시작 | 담당 |
| --- | --- | --- | --- |
| P1 (Critical) | Secret 노출, 실제 악용(KEV) CVE, Critical 취약점 | 즉시 (발견 즉시) | 보안 담당 + 커밋 작성자 |
| P2 (High) | High 취약점, 차단된 PR | 당일 내 | 커밋 작성자 |
| P3 (Medium) | Medium 경고 | 다음 스프린트 내 | 커밋 작성자 |
| P4 (Low) | Low 기록 | 백로그 관리 | 파트 리드 |

---

## SEC-01. Secret 노출 (P1) — 최우선

가장 위험한 이벤트다. **노출된 키는 지금 이 순간에도 악용될 수 있으므로, 코드 정리보다
키 폐기가 항상 먼저다.**

### 탐지
- Gitleaks가 `secret` 등급 finding 생성 → Gate `FAILED`, Merge 차단
- PR 댓글 "차단 사유"에 Secret 탐지 표시

### 확인
1. PR 댓글의 `위치(location)`에서 노출된 값의 종류 식별 (API 키 / 토큰 / 비밀번호 / 인증서)
2. 해당 자격증명이 **실제 유효한 것인지, 테스트/더미 값인지** 확인
   - 더미/오탐이면 → SEC-05(오탐 처리)로 이동
3. 유효한 키라면 **이미 노출된 것으로 간주**하고 아래 대응을 즉시 시작

### 대응 (순서 엄수)
1. **키 즉시 폐기(revoke) 및 재발급** — 가장 먼저. 코드 수정보다 우선
2. 폐기 전 사용 로그를 확인해 비인가 사용 흔적 조사
3. 코드에서 값 제거 → 환경변수 / Secret Manager(GitHub Actions Secrets, Vault 등)로 이전
4. git history에도 남아 있으면 `git filter-repo` 또는 BFG Repo-Cleaner로 이력 정리
   - 이력 정리 후 강제 push는 팀에 사전 공지 (다른 브랜치 영향)

### 복구
- 재발급된 키로 서비스 정상 동작 확인
- 노출 범위·기간·조치 내용 기록 (아래 사고 기록 양식)
- 재발 방지: pre-commit hook에 Gitleaks 추가 권장

---

## SEC-02. 실제 악용 중인 CVE (P1)

### 탐지
- `cve-policy-evaluate.py`에서 `kev_listed = true`(규칙 1) 또는 EPSS 임계 초과(규칙 2)로 **차단**
- 판정 근거에 KEV 등재 / EPSS 값(evidence)과 NVD/OSV 링크 포함

### 확인
1. 판정 근거의 CVE ID와 영향 패키지 확인
2. NVD/OSV 링크로 취약점 상세와 패치 버전 확인
3. 해당 패키지가 **실제 취약 경로로 사용되는지** 코드에서 확인

### 대응
1. 패치된 버전으로 즉시 업그레이드
2. 즉시 업그레이드 불가 시 → 임시 완화책(해당 기능 비활성화, WAF 룰 등) 적용 후 팀 공유
3. 재검사(재push)로 Gate 통과 확인

### 복구
- 업그레이드 후 회귀 테스트
- 의존성 정기 점검 주기 확인, SBOM 갱신

---

## SEC-03. Critical / High 코드·의존성 취약점 (P1/P2)

### 탐지
- Semgrep `ERROR`(→high), Trivy `CRITICAL/HIGH`, ZAP `High` 등으로 Gate `FAILED`
- PR 댓글 "수정 가이드"에 finding별 위치·조치·참고 링크 표시

### 확인
1. PR 댓글 수정 가이드에서 취약점 유형과 위치 확인
2. 오탐 여부 검토 (문맥상 도달 불가 경로 등) → 오탐이면 SEC-05
3. OWASP 분류([등급 기준 문서](./severity-policy.md) 2절)로 취약점 성격 파악

### 대응
- 유형에 맞게 수정: 입력 검증/이스케이프, 안전한 API 사용, 위험 함수 대체, 접근 제어 보강
- 수정 후 다시 push → Gate 재실행

### 복구
- 재검사 통과 확인, 유사 패턴이 다른 파일에 없는지 점검

---

## SEC-04. 런타임(DAST) 취약점 (P1/P2)

### 탐지
- ZAP Alert `High/Medium`로 `runtime-report.json`에 finding
- 보안 헤더 미설정(CSP, HSTS 등) 포함

### 확인
1. 알림 대상 엔드포인트/URL 확인
2. Staging 환경 특유의 문제인지, 코드/설정 문제인지 구분

### 대응
- 입력 처리 로직 점검, 응답 보안 헤더 설정, 설정 미흡 보완
- Staging 재배포 → 재검사 통과

### 복구
- Post-deploy 재검사 결과 확인, 프로덕션 반영 전 재확인

---

## SEC-05. 오탐(False Positive) 처리

차단이 오탐으로 확인된 경우, **정책을 우회(무조건 통과)하지 말고 근거를 남긴다.**

### 절차
1. 오탐 근거를 PR 또는 이슈에 명시 (왜 실제 위험이 아닌지)
2. 파트 리드 또는 보안 담당 리뷰 승인
3. 도구 레벨 예외 처리 (Semgrep `# nosemgrep`, Gitleaks allowlist, Trivy `.trivyignore` 등)
   - 예외에는 반드시 사유 주석과 만료/재검토 시점을 함께 기록
4. 반복되는 오탐 패턴은 [등급 기준 문서](./severity-policy.md) 3절 매핑 재검토

> `severity_fallback`(매핑 안 된 등급)이 뜬 경우는 오탐이 아니라
> **정책 갱신 신호**다. `security-gate-policy.json`의 `severityMapping`을 보완한다.

---

## 사고 기록 양식

P1/P2 이벤트는 대응 종료 후 아래 양식으로 기록한다.

```text
## [사고 ID] SEC-YYYYMMDD-NN

- 이벤트 등급: P1 / P2 / P3 / P4
- 플레이북: SEC-0N
- 탐지 도구 / 게이트:
- 탐지 시각:
- 영향 범위 (노출 대상 / 기간 / 사용 흔적):
- 대응 내용 (시간순):
- 복구 완료 시각:
- 재발 방지 조치:
- 관련 PR / 이슈 링크:
```

---

## 참고 링크

| 대상 | 링크 |
| --- | --- |
| OWASP Top 10 | https://owasp.org/www-project-top-ten/ |
| NVD (CVE 조회) | https://nvd.nist.gov/ |
| CISA KEV 카탈로그 | https://www.cisa.gov/known-exploited-vulnerabilities-catalog |
| Gitleaks | https://github.com/gitleaks/gitleaks |
| ZAP 문서 | https://www.zaproxy.org/docs/ |
