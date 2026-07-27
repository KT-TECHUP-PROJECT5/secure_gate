---
문서명: Incident Response 플레이북
최신화: 2026-07-27
작성자: GateKeepers
Version: 1.2.0
---

# Incident Response 플레이북

Security Gate가 탐지한 이벤트에 대해 **누가, 무엇을, 어떤 순서로** 대응할지 정의한다.

> 이 문서는 운영 대응 매뉴얼이다. Gate 판정 로직, CVE 보정 정책, AI 보고서 본문을 대체하지 않는다.

## 빠른 선택

1. `gate-decision.json`에서 `category`, `severity`, `block_reasons`, `has_error`를 확인한다.
2. 아래 표에서 해당하는 SEC 플레이북을 연다.
3. 여러 신호가 있으면 **가장 높은 이벤트 등급의 플레이북을 먼저 수행**하고, 나머지 finding은 사고 기록에 남긴다.

| Gate 신호 | 플레이북 | 기본 등급 |
| --- | --- | --- |
| `category=secret` | [SEC-01](#sec-01-secret-노출-p1--최우선) | P1 |
| KEV, CVE promote, `cve_track.top_findings[].kev=true` | [SEC-02](#sec-02-실제-악용-중kev--고위험-cve-p1) | P1 |
| `category=vuln`, severity `critical` 또는 `high` | [SEC-03](#sec-03-critical--high-보안-취약점-p1p2) | P1/P2 |
| `category=availability` | [SEC-04](#sec-04-가용성-장애-p1) | P1 |
| `category=misconfig` 또는 medium Warn | [SEC-05](#sec-05-misconfig--medium-경고-p3) | P3 |
| `category=scanner-error`, 필수 보고서 누락·처리 실패 | [SEC-06](#sec-06-스캐너파이프라인-장애-ops) | Ops |
| 오탐으로 확인됨 | [SEC-07](#sec-07-오탐false-positive-처리) | 해당 등급 유지 후 종료 |

## 관련 문서

- 차단 기준: `docs/aggregator-policy-baseline.md`
- CVE 보정: `docs/cve-track-integration.md`
- AI 보고서 입력 계약: `docs/AI-reference.md`
- 예외 승인: `security/policies/suppressions.json`

---

## 1. 공통 절차

모든 플레이북은 다음 순서로 수행한다.

```text
탐지(Detect) → 확인(Triage) → 대응(Respond) → 복구(Recover)
```

| 단계 | 수행 내용 |
| --- | --- |
| 탐지 | 어떤 도구와 Gate 신호가 무엇을 탐지했는지 확인한다. (`gate-decision.json`) |
| 확인 | 오탐 여부와 영향 범위·노출 경로를 확인한다. |
| 대응 | 확산을 차단하고 위협 원인을 제거한다. |
| 복구 | 정상 동작, 재검사, 재발 방지와 사고 기록을 완료한다. |

### P1 공통 권한 및 공유

P1에서는 보안 담당 또는 파이프라인 담당자가 추가 승인 대기 없이 **키 폐기, 배포 중지, 롤백**을 수행할 수 있다. 조치 직후 팀 채널과 관련 PR/이슈에 원인·영향·조치 시각을 공유한다.

---

## 2. 이벤트 등급 및 SLA

등급은 Gate `category`와 심각도를 기준으로 매핑한다. PR soft와 Post-merge hard의 **차단 기준은 동일**하다.

| 등급 | 정의 | 초기 대응 시작 | 담당 |
| --- | --- | --- | --- |
| P1 | `secret`, KEV CVE, `vuln` critical, `availability` high/critical | 탐지 후 15분 내 | 보안 담당 + 커밋/배포 작성자 |
| P2 | `vuln` high(Block), 차단된 PR/Post-merge | 영업일 4시간 내 | 커밋/배포 작성자 |
| P3 | `misconfig`, medium Warn | 다음 스프린트 계획 내 | 커밋 작성자 |
| P4 | low / informational | 백로그 등록 | 파트 리드 |
| Ops | `scanner-error` 등 파이프라인 장애 | 영업일 4시간 내 | 파이프라인/보안 게이트 담당 |

> `misconfig`(보안 헤더, HTTP Only, 캐시 설정)는 Warn이다. confirmed XSS·SQLi·`vuln`과 동일 등급으로 취급하지 않는다.

---

## SEC-01. Secret 노출 (P1) — 최우선

노출된 키는 즉시 악용될 수 있다. **코드 정리보다 키 폐기가 항상 먼저다.**

### 탐지

- Gitleaks 등이 `category=secret` finding을 생성하고 Gate가 `FAILED` 처리한다.
- `block_reasons`에 Secret 노출 사유가 표시된다.

### 확인

1. `location`에서 값의 종류를 식별한다. (API 키, 토큰, 비밀번호, 인증서 등)
2. PR diff, Git history, GitHub Actions 로그·Artifact, 컨테이너 이미지, 배포 환경변수에 노출 범위가 있는지 확인한다.
3. 더미/테스트 값인지 확인한다. 더미 또는 오탐이면 [SEC-07](#sec-07-오탐false-positive-처리)로 이동한다.
4. 유효한 자격증명이라면 **이미 노출된 것으로 간주**한다.

### 대응 — 순서 엄수

1. **키를 즉시 폐기(revoke)하고 재발급한다.**
2. 폐기 전후 사용 로그에서 비인가 사용 흔적을 조사한다.
3. 코드에서 값을 제거하고 환경변수 또는 Secret Manager로 이전한다.
4. 공개 저장소이거나 Git 이력에 노출 값이 지속적으로 남아 제거가 필요하면, 키 폐기 후 `git filter-repo` 또는 BFG를 검토한다.
   - 강제 push 전 팀에 공지하고, 영향받는 개발자의 재동기화 방법을 공유한다.

### 복구

- 재발급 키로 서비스 정상 동작을 확인한다.
- 사고 기록을 작성한다.
- pre-commit Gitleaks 적용 여부를 점검한다.

---

## SEC-02. 실제 악용 중(KEV) / 고위험 CVE (P1)

### 탐지

- `cve_track` 또는 `cve_adjustments`에서 KEV promote / CVE track block이 발생한다.
- `cve-policy-decision.json` evidence에 KEV 또는 EPSS 정보가 포함된다.

### 확인

1. CVE ID, 영향 패키지(`purl`), `fixedVersion`을 확인한다.
2. NVD, OSV, CISA KEV에서 영향 조건과 패치 버전을 확인한다.
3. 실제 취약 경로가 서비스에서 사용되는지 확인한다.

### 대응

1. 패치 버전으로 즉시 업그레이드한다.
2. 즉시 업그레이드가 불가능하면 기능 비활성화, 접근 제한, WAF 룰 등 임시 완화 조치를 적용하고 팀에 공유한다.
3. 재push 또는 Post-merge 재실행으로 Gate 통과를 확인한다.

### 복구

- 회귀 테스트를 수행하고 SBOM을 갱신한다.
- 의존성 점검 주기와 자동 업데이트 정책을 점검한다.

---

## SEC-03. Critical / High 보안 취약점 (P1/P2)

코드(SAST), 의존성(Trivy), 런타임 confirmed vuln(XSS, SQLi, 권한 우회 등)을 포함한다. `misconfig`는 [SEC-05](#sec-05-misconfig--medium-경고-p3)에서 처리한다.

### 탐지

- `category=vuln`과 severity `critical|high` 조합으로 Gate가 `FAILED` 처리한다.

### 확인

1. `location`과 title로 취약 유형·영향 코드를 파악한다.
2. 오탐 또는 도달 불가 경로라면 [SEC-07](#sec-07-오탐false-positive-처리) 절차를 따른다.
3. 의존성 취약점은 `fixedVersion`과 CVE evidence를 함께 확인한다.

### 대응

- 입력 검증과 출력 이스케이프를 적용한다.
- 안전한 API로 교체하거나 위험 함수를 제거한다.
- 인증·인가와 접근 제어를 보강한다.
- 취약 패키지를 패치 버전으로 업그레이드한다.
- 수정 후 Gate를 재실행한다.

### 복구

- 재검사 통과와 회귀 테스트를 확인한다.
- 같은 패턴이 다른 코드 경로에 남아 있는지 점검한다.

---

## SEC-04. 가용성 장애 (P1)

### 탐지

- `category=availability`가 발생한다. (health/smoke 실패, 서비스 미검출 등)

### 확인

1. 실패한 엔드포인트와 실행 환경(PR runner-local / Staging)을 확인한다.
2. 앱, 인프라, 시드 데이터, 외부 의존 서비스 중 원인을 구분한다.
3. Dynatrace problem이 있으면 영향 범위를 확인한다.

### 대응

1. 배포·설정·DB·의존성을 복구하거나 필요한 경우 롤백한다.
2. health/smoke 경로와 기대 상태 코드를 다시 확인한다.
3. Gate를 재실행한다.

### 복구

- 안정화 여부를 확인한다.
- 헬스체크, 시드, 재시도, 타임아웃 설정을 보완한다.

---

## SEC-05. misconfig / Medium 경고 (P3)

배포를 막지 않는 Warn 이슈다. 헤더 미설정, HTTP Only, cacheable 등을 confirmed XSS로 과장하지 않는다.

### 탐지

- `category=misconfig` 또는 medium Warn이 발생한다. Gate는 통과할 수 있으나 warnings가 존재한다.

### 확인

1. 대상 URL의 응답 헤더와 쿠키 플래그를 확인한다.
2. Staging 전용 이슈인지 서비스 환경에도 재현되는지 구분한다.

### 대응 및 복구

- CSP, HSTS, X-Frame-Options 등 보안 헤더를 보완한다.
- 쿠키 플래그와 캐시 정책을 조정한다.
- 스프린트 내 수정 후 재검사하고 warning 감소 여부를 기록한다.

---

## SEC-06. 스캐너/파이프라인 장애 (Ops)

앱 취약점이 아니라 **검사 결과를 신뢰할 수 없는 상태**다. 필수 보안 리포트를 신뢰할 수 없으면 보안 통과로 간주하지 않는다.

### 탐지

- `category=scanner-error`
- `필수 보안 보고서 누락` 또는 `보안 보고서 처리 실패` block reason
- `has_error=true`

### 확인

1. 실패 또는 누락된 리포트 키를 확인한다. (예: `sast`, `dependency_track`)
2. Job 실패, Artifact 다운로드 누락, 스키마 오류를 구분한다.
3. Semgrep PartialParsing 같은 soft warning과 hard failure를 혼동하지 않는다.

### 대응

1. 워크플로, 스캐너 설정, Artifact 경로를 복구한다.
2. 필요하면 `secure_gate` 또는 caller workflow를 수정한다.
3. 재실행하여 모든 필수 보고서가 정상 생성되는지 확인한다.

### 복구

- Gate가 scanner-error가 아닌 실제 보안 finding을 기준으로 판정하는지 확인한다.
- 반복 장애라면 aggregator 입력 계약과 테스트를 보강한다.

---

## SEC-07. 오탐(False Positive) 처리

정책을 조용히 우회하지 말고 **근거와 승인 기록을 남긴다.**

1. PR 또는 이슈에 오탐 근거와 실제 위험이 아닌 이유를 명시한다.
2. 파트 리드 또는 보안 담당의 승인을 받는다.
3. `security/policies/suppressions.json`에 예외를 등록한다.
   - 필수: `id` 또는 `location_contains`, `category`, `reason`, `approved_by`, `expires_on`
4. 도구 레벨 예외(`nosemgrep`, allowlist, `.trivyignore` 등)가 필요하면 사유와 만료일을 함께 기록한다.
5. 만료 전에 재검토한다. `expires_on`이 지난 suppression은 무효로 간주하고 Gate가 finding을 다시 평가한다.

```json
{
  "suppressions": [
    {
      "id": "CVE-2020-1747",
      "location_contains": "requirements-legacy.txt:PyYAML",
      "category": "vuln",
      "reason": "accepted lab fixture",
      "approved_by": "policy-owner",
      "expires_on": "2026-12-31"
    }
  ]
}
```

---

## 3. 사고 기록 양식

P1, P2, Ops 이벤트는 대응 종료 후 아래 양식으로 기록한다. 팀 Notion 또는 이슈 트래커에 등록해도 된다.

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

## 4. 참고 링크

| 대상 | 링크 |
| --- | --- |
| OWASP Top 10 | https://owasp.org/www-project-top-ten/ |
| NVD | https://nvd.nist.gov/ |
| CISA KEV | https://www.cisa.gov/known-exploited-vulnerabilities-catalog |
| Gitleaks | https://github.com/gitleaks/gitleaks |
| ZAP | https://www.zaproxy.org/docs/ |
| OSV | https://osv.dev/ |
