---
문서명: Incident Response 플레이북
최신화: 2026-07-26
작성자: GateKeepers
Version: 1.1.0
---

# Incident Response 플레이북

Security Gate가 탐지한 이벤트에 대해 **누가, 무엇을, 어떤 순서로** 대응할지 정의한다.  
이 문서는 운영 매뉴얼이며 Gate 판정 로직·AI 보고서 본문을 대체하지 않는다.

관련 문서:

- 차단 기준: `docs/aggregator-policy-baseline.md`
- CVE 보정: `docs/cve-track-integration.md`
- AI 보고서 입력 계약: `docs/AI-reference.md`
- 예외 승인: `security/policies/suppressions.json`

---

## 1. 공통 절차

모든 플레이북은 아래 4단계를 따른다.

```text
탐지(Detect) → 확인(Triage) → 대응(Respond) → 복구(Recover)
```

| 단계 | 의미                                                      |
| ---- | --------------------------------------------------------- |
| 탐지 | 어떤 도구/게이트가 무엇을 잡았는가 (`gate-decision.json`) |
| 확인 | 진짜 문제인가(오탐 여부), 영향 범위는 어디인가            |
| 대응 | 확산을 막고 위협을 제거하는 즉시 조치                     |
| 복구 | 정상화, 재발 방지, 기록                                   |

---

## 2. 이벤트 등급 및 SLA

등급은 Gate `category` + 심각도를 기준으로 매핑한다.  
PR soft / Post-merge hard의 **차단 기준은 동일**하다.

| 등급 | 정의 (우리 정책)                                                 | 초기 대응 시작   | 담당                         |
| ---- | ---------------------------------------------------------------- | ---------------- | ---------------------------- |
| P1   | `secret`, KEV CVE, `vuln` critical, `availability` high/critical | 즉시             | 보안 담당 + 커밋/배포 작성자 |
| P2   | `vuln` high (Block), 차단된 PR/Post-merge                        | 당일 내          | 커밋/배포 작성자             |
| P3   | `misconfig`, medium 경고(Warn)                                   | 다음 스프린트 내 | 커밋 작성자                  |
| P4   | low / informational                                              | 백로그           | 파트 리드                    |
| Ops  | `scanner-error` (파이프라인 장애)                                | 당일 내          | 파이프라인/보안 게이트 담당  |

> `misconfig`(헤더/HTTP Only/캐시)는 Warn이다. confirmed XSS/SQLi/`vuln`과 동일 등급으로 취급하지 않는다.

---

## 3. Gate 결과 → 플레이북 선택

| `gate-decision` 신호                                               | 우선 플레이북 |
| ------------------------------------------------------------------ | ------------- |
| category=`secret`                                                  | SEC-01        |
| CVE adjustment promote / KEV / `cve_track.top_findings[].kev=true` | SEC-02        |
| category=`vuln` critical/high (코드·의존성·런타임)                 | SEC-03        |
| category=`availability`                                            | SEC-04        |
| category=`misconfig` 또는 medium Warn                              | SEC-05        |
| category=`scanner-error` 또는 보고서 누락/처리 실패                | SEC-06        |
| 오탐으로 판정                                                      | SEC-07        |

여러 신호가 겹치면 **더 높은 등급(P1 > P2 > Ops > P3)** 플레이북을 먼저 수행한다.

---

## SEC-01. Secret 노출 (P1) — 최우선

노출된 키는 지금 이 순간에도 악용될 수 있다. **코드 정리보다 키 폐기가 항상 먼저다.**

### 탐지

- Gitleaks 등이 `category=secret` finding 생성 → Gate `FAILED`
- `block_reasons`에 Secret 노출 표시

### 확인

1. `location`에서 노출 값 종류 식별 (API 키 / 토큰 / 비밀번호 / 인증서)
2. 실제 유효한 자격증명인지, 테스트/더미인지 확인
   - 더미/오탐이면 → SEC-07
3. 유효하면 **이미 노출된 것으로 간주**하고 즉시 대응

### 대응 (순서 엄수)

1. **키 즉시 폐기(revoke) 및 재발급**
2. 폐기 전 사용 로그에서 비인가 사용 흔적 조사
3. 코드에서 값 제거 → 환경변수 / Secret Manager로 이전
4. git history에 남아 있으면 `git filter-repo` 또는 BFG로 이력 정리
   - 강제 push 전 팀 공지

### 복구

- 재발급 키로 서비스 정상 동작 확인
- 사고 기록 양식 작성
- 재발 방지: pre-commit Gitleaks 권장

---

## SEC-02. 실제 악용 중(KEV) / 고위험 CVE (P1)

### 탐지

- `cve_track` / `cve_adjustments`에서 KEV promote 또는 CVE track block
- `cve-policy-decision.json` evidence에 KEV/EPSS 포함

### 확인

1. CVE ID, 영향 패키지(`purl`), `fixedVersion` 확인
2. NVD/OSV/KEV 링크로 상세·패치 버전 확인
3. 실제 취약 경로 사용 여부를 코드에서 확인

### 대응

1. 패치 버전으로 즉시 업그레이드
2. 불가 시 임시 완화(기능 비활성화, WAF 등) 후 팀 공유
3. 재push / Post-merge 재실행으로 Gate 통과 확인

### 복구

- 회귀 테스트, SBOM 갱신, 의존성 점검 주기 확인

---

## SEC-03. Critical / High 보안 취약점 (P1/P2)

코드(SAST), 의존성(Trivy), 런타임 confirmed vuln(XSS/SQLi/권한 우회 등)을 포함한다.  
`misconfig`는 여기 넣지 않는다 → SEC-05.

### 탐지

- `category=vuln` + severity `critical|high` → Gate `FAILED`

### 확인

1. `location` / title로 취약 유형 파악
2. 오탐·도달 불가 경로면 SEC-07
3. dependency면 `fixedVersion`·CVE evidence 함께 확인

### 대응

- 입력 검증/이스케이프, 안전한 API, 위험 함수 대체, 접근 제어 보강, 패키지 업그레이드
- 수정 후 Gate 재실행

### 복구

- 재검사 통과, 유사 패턴 잔존 여부 점검

---

## SEC-04. 가용성 장애 (P1)

### 탐지

- `category=availability` (health/smoke 실패, 서비스 미검출 등) → Gate `FAILED`

### 확인

1. 실패 엔드포인트/환경(PR runner-local vs Staging) 확인
2. 앱 장애인지, 인프라/시드/의존 서비스 문제인지 구분
3. Dynatrace problem이 있으면 영향 범위 확인

### 대응

1. 서비스 복구(배포/설정/DB/의존성)
2. health/smoke 경로와 기대 상태 코드 재확인
3. Gate 재실행

### 복구

- 안정화 확인, 재발 방지(헬스체크·시드·타임아웃 조정)

---

## SEC-05. misconfig / Medium 경고 (P3)

배포를 막지 않는 Warn 이슈다.  
헤더 미설정·HTTP Only·cacheable 등을 confirmed XSS로 과장하지 않는다.

### 탐지

- `category=misconfig` 또는 medium Warn → Gate는 통과할 수 있으나 warnings 존재

### 확인

1. 대상 URL/응답 헤더/쿠키 플래그 확인
2. Staging 전용 이슈인지 구분

### 대응

- 보안 헤더(CSP, HSTS, X-Frame-Options 등), 쿠키 플래그, 캐시 정책 보완
- 스프린트 내 수정 후 재검사

### 복구

- warnings 감소 확인, 필요 시 문서화

---

## SEC-06. 스캐너/파이프라인 장애 (Ops)

앱 취약점이 아니라 **검사 결과를 신뢰할 수 없는 상태**다.

### 탐지

- `category=scanner-error`
- 또는 block reason: `필수 보안 보고서 누락` / `보안 보고서 처리 실패`
- `has_error=true`

### 확인

1. 어떤 리포트 키(`sast`, `dependency_track` 등)가 실패/누락인지 확인
2. Job 실패인지, Artifact 다운로드 누락인지, 스키마 오류인지 구분
3. Semgrep PartialParsing 같은 soft warning과 hard failure를 혼동하지 말 것

### 대응

1. 워크플로/스캐너/Artifact 경로 복구
2. 필요 시 `secure_gate` 또는 caller workflow 수정
3. 재실행으로 정상 보고서 생성 확인

### 복구

- Gate가 실제 보안 finding 기준으로만 판정하는지 확인
- 반복되면 aggregator 계약/테스트를 보강

---

## SEC-07. 오탐(False Positive) 처리

정책을 조용히 우회하지 말고 **근거를 남긴다.**

### 절차

1. 오탐 근거를 PR/이슈에 명시 (왜 실제 위험이 아닌지)
2. 파트 리드 또는 보안 담당 승인
3. `security/policies/suppressions.json`에 등록
   - 필수: `id` 또는 `location_contains` / `category`, `reason`, `approved_by`, `expires_on`
4. 도구 레벨 예외(nosemgrep, allowlist, `.trivyignore` 등)가 필요하면 사유·만료일을 함께 기록
5. 만료 전 재검토

```json
{
  "suppressions": [
    {
      "id": "CVE-2020-1747",
      "location_contains": "requirements-legacy.txt:PyYAML",
      "reason": "accepted lab fixture",
      "approved_by": "policy-owner",
      "expires_on": "2026-12-31"
    }
  ]
}
```

---

## 4. 사고 기록 양식

P1 / P2 / Ops 이벤트는 대응 종료 후 아래 양식으로 기록한다.  
(팀 Notion/이슈 트래커에 붙여도 된다.)

```text
## [사고 ID] SEC-YYYYMMDD-NN

- 이벤트 등급: P1 / P2 / P3 / P4 / Ops
- 플레이북: SEC-0N
- 탐지 도구 / 게이트:
- 탐지 시각:
- Gate run URL / Artifact:
- 영향 범위 (노출 대상 / 기간 / 사용 흔적):
- 대응 내용 (시간순):
- 복구 완료 시각:
- 재발 방지 조치:
- 관련 PR / 이슈 링크:
```

---

## 5. 참고 링크

| 대상         | 링크                                                         |
| ------------ | ------------------------------------------------------------ |
| OWASP Top 10 | https://owasp.org/www-project-top-ten/                       |
| NVD          | https://nvd.nist.gov/                                        |
| CISA KEV     | https://www.cisa.gov/known-exploited-vulnerabilities-catalog |
| Gitleaks     | https://github.com/gitleaks/gitleaks                         |
| ZAP          | https://www.zaproxy.org/docs/                                |
| OSV          | https://osv.dev/                                             |
