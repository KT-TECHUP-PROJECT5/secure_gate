---
문서명: Aggregator 및 Gate Policy 기준선
최신화: 2026-07-26
상태: Baseline v0.2 / 팀 진행 기준 (category 기반 코드 반영)
---

# Aggregator 및 Gate Policy 기준선

## 1. 한 줄 원칙

**검사는 단계마다 더 깊게 하고, 차단은 “서비스 장애·큰 보안 이슈”만 한다.**

PR / Post-merge의 차이는 “무엇을 더 찾아보느냐”이지, “언제 막느냐”가 아니다.

팀 설명용 문장:

> Secure Gate는 ESLint처럼 동작한다.
> PR에서는 빠르게, merge 후에는 더 깊게 검사하지만 막는 기준은 같다.
> 서비스 장애나 큰 보안 이슈만 Block하고, 그 외는 Warn으로 남기며,
> 확인된 오탐과 예외는 만료일 있는 승인으로 관리한다.

## 2. 역할 분리

| 구분 | 의미 |
| --- | --- |
| 검사 강도 | PR = 빠른 soft scan / Post-merge = 깊은 hard scan |
| 차단 기준 | 둘 다 동일 |
| 결과 활용 | soft에서 본 이슈 + hard에서 추가된 이슈를 같은 기준으로 판단 |

### Aggregator

`scripts/aggregate-results.py`가 담당한다.

- 도구별 원본 JSON을 공통 finding 형식으로 변환
- 전체 finding 수와 심각도 존재 여부 계산
- 필수 보고서 누락과 형식 오류 기록
- `security/reports/security-summary.json` 생성

### Policy Evaluator

`scripts/evaluate-gate.py`가 담당한다.

- Aggregator 요약을 정책과 비교
- Block / Warn / Pass 결정
- `security/reports/gate-decision.json` 생성
- Block이면 종료 코드 `1` 반환

Aggregator는 결과를 모으고, 최종 Block/Pass는 Policy Evaluator가 결정한다.

## 3. Block / Warn / Pass

### Block (막음)

서비스 장애나 명확한 대형 보안 이슈만 막는다.

- Secret 노출
- Critical / High 중 실제로 위험한 것  
  예: RCE, 인증 우회, XSS/SQLi 실탐지, 심각한 의존성 CVE
- Health / Smoke 실패처럼 서비스가 안 뜨는 상태
- 스캐너가 아예 실패해서 결과를 신뢰할 수 없는 경우 (Fail Closed 최소선)

### Warn (알림만)

고치는 게 맞지만 당장 배포를 막을 정도는 아닌 것.

- Medium
- 보안 헤더 누락
- HTTP Only / 캐시 이슈
- 오탐 가능성이 큰 Low~Medium SAST

### Pass

- Low
- Informational
- 예외 승인된 항목 (사유, 승인자, 만료일 기록)

### 중요: 방어 태세와 실제 취약점을 섞지 않는다

| 유형 | 예시 | 권장 |
| --- | --- | --- |
| 실제 취약점 | XSS, SQLi, RCE, Auth bypass | Block |
| 보호 설정 미흡 | CSP 없음, X-Frame-Options 없음, HTTP Only | Warn |
| 환경/캐시 | Cacheable Content | Warn |

헤더 누락을 Warn으로 둔다고 해서 XSS/SQLi가 Warn으로 내려가면 안 된다.
둘은 다른 finding이며, 실제 취약점 finding은 별도로 Block한다.

## 4. PR (soft) vs Post-merge (hard)

### PR soft

- 빠르게 큰 구멍만 본다
- 같은 Block 기준으로 merge를 막거나 허용

### Post-merge hard

- ZAP Full, Nuclei 확대, Dynatrace 등 더 깊게 본다
- 새로 나온 결과도 같은 Block 기준으로 다음 단계 승격을 막거나 허용

적용 규칙:

- soft에서 이미 Critical급 Block 이슈면 PR에서 막힘
- hard에서 추가로 Block 이슈가 나오면 그때 막힘
- soft에서 Warn이었던 것이 hard에서도 Warn이면 계속 Warn
- hard라고 해서 Medium까지 갑자기 Block으로 올리지 않음

## 5. 오탐 / 예외 고도화

엄격함을 줄이려면 Block 목록만 줄이지 말고, 예외를 명시적으로 관리한다.

1. 기본은 Fail Closed  
   결과 없음 / 도구 고장 → 막음
2. 다만 아래는 예외 가능  
   - 확인된 오탐  
   - Accepted Risk (기한 있음)  
   - 아직 수정 중인 알려진 이슈
3. 예외는 “무시”가 아니라 아래를 남긴다  
   - 왜 예외인지  
   - 누가 승인했는지  
   - 언제 만료되는지

## 6. 입력 보고서

### PR Gate

- `build-report.json`
- `sast-report.json`
- `secret-report.json`
- `dependency-report.json`
- `runtime-report.json`

### Post-merge Gate

- `dependency-report.json`
- `dependency-track-upload-report.json`
- `runtime-report.json`

Post-merge `runtime-report.json`은 내부적으로 다음 원본을 검증한다.

- `zap-report.json`
- `nuclei-report.jsonl`
- `nuclei-cve-coverage.json`
- `dynatrace-problems.json`

PR에서는 SBOM을 Artifact로만 보존하고 Dependency-Track 업로드를 수행하지 않는다.
Post-merge에서는 CycloneDX SBOM 업로드 성공을 필수로 본다.

## 7. 공통 finding 형식

```json
{
  "id": "finding identifier",
  "severity": "critical | high | medium | low | secret",
  "title": "finding title",
  "description": "finding description",
  "location": "file:line or URL"
}
```

향후 고도화 시 아래 필드를 추가할 수 있다.

- `category`: `vuln` | `misconfig` | `secret` | `availability` | `scanner-error`
- `remediation`: 권고 문구 (자동 수정 가이드 생성은 별도 AI 담당, 본 기준선 범위 밖)

## 8. 현재 코드 반영 상태

`scripts/gate_policy.py`가 finding `category`를 분류하고,
`evaluate-gate.py`가 아래 정책 파일로 Block/Warn을 판단한다.

```json
{
  "blockOnSecret": true,
  "blockOnScannerError": true,
  "blockOnAvailability": true,
  "blockOnAvailabilityMedium": false,
  "blockOnVulnCritical": true,
  "blockOnVulnHigh": true,
  "warnOnMedium": true,
  "warnOnMisconfig": true,
  "cveTrack": {
    "enabled": "monitor",
    "adjustment": { "annotateOnly": true }
  }
}
```

| 항목 | 현재 코드 | 상태 |
| --- | --- | --- |
| finding category | `vuln` / `misconfig` / `secret` / `availability` / `scanner-error` | 반영 |
| Critical/High vuln | Block | 반영 |
| misconfig (헤더/HTTP Only/캐시) | Warn | 반영 |
| Secret / 가용성 / 스캐너 오류 | Block | 반영 |
| dependency CVE 보정 | `cve_track` promote/demote (기본 monitor + annotateOnly) | 반영 |
| Trivy `purl` / `fixedVersion` | aggregator 정규화 | 반영 |
| PR vs Post-merge 차단 기준 | 동일 | 유지 |
| 예외 승인 | `security/policies/suppressions.json` | 기본 골격 반영 |
| AI 보고서 참고 | `docs/AI-reference.md` | 반영 |
| IR 플레이북 | `docs/incident-response-playbook.md` | 반영 |
| ZAP XSS 탐지 고도화 | 별도 DAST 과제 | 보류 |

CVE 트랙은 category 판정 **이후** dependency(`CVE-*`) finding만 보정한다.
초기 기본값은 `monitor` + `annotateOnly=true`라서 판정을 바꾸지 않고
`gate-decision.json`의 `cve_track` / `cve_adjustments`에 기록한다.
상세: `docs/cve-track-integration.md`

예외 파일 예시:

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

## 9. 기술 실패 정책

Fail Closed 최소선은 유지한다.

- 필수 Artifact 미생성
- JSON 파싱 실패
- 지원하지 않는 보고서 형식
- Semgrep / Gitleaks / Trivy / Runtime Job 실패 또는 취소
- ZAP / Nuclei 실행 오류나 timeout
- Post-merge 필수 원본 보고서 누락
- Post-merge Dependency-Track 업로드 실패 또는 skip

이 경우는 취약점 없음으로 처리하지 않고 Block한다.

## 10. 판단 예시

### 예시 A: 실제 XSS / SQLi 탐지

- Gate: `FAILED`
- 이유: 실제 취약점 (Block)

### 예시 B: 보안 헤더 누락, HTTP Only

- Gate: `PASSED` + Warning
- 이유: 보호 설정 미흡 (Warn)
- 같은 실행에서 XSS가 따로 탐지되면 그 finding은 Block

### 예시 C: Secret 1건

- Gate: `FAILED`
- Secret 원문은 출력하지 않음

### 예시 D: Critical CVE이지만 Accepted Risk (만료 전)

- Gate: `PASSED` + Warning 또는 예외 기록
- 만료 후에는 다시 Block

### 예시 E: 스캐너 보고서 누락

- Gate: `FAILED`
- 이유: 기술 실패 (Fail Closed)

## 11. 계획에서 제외 / 보류

- E 파트 자동 수정 가이드 생성: 계획에서 제외  
  다른 담당자가 AI 결과 보고서를 별도로 구성한다.
- ZAP 탐지 고도화(예: Reflected/Stored XSS 커버리지): DAST 고도화 항목으로 별도 진행
- Discord / Telegram 요약 알림: 정책 확정 후 Gate 요약 연동으로 진행 가능

## 12. 고도화 순서

### 1단계: 기준 고정 (현재)

- 본 문서의 한 줄 원칙과 Block/Warn/Pass 구분 확정
- PR/Post-merge 차단 기준 동일 원칙 확정

### 2단계: finding 분류

- `vuln` / `misconfig` / `secret` / `availability` / `scanner-error` 분류 도입
- Critical/High를 무조건 Block하지 않고 분류 기준으로 거름

### 3단계: 예외 관리

- finding ID + 위치 기반 Suppression
- 승인자, 사유, 만료일 필수
- 만료된 예외 자동 Block

### 4단계: 운영 알림

- `gate-decision.json` 요약본을 Discord / Telegram으로 전송
- Secret 원문과 과도한 finding dump는 알림에 포함하지 않음

### 5단계: 품질 강화

- 회귀 테스트 (Pass 1건 + Block 1건 이상)
- 중복 finding 제거
- 실제 GitHub Actions fixture 보강

## 13. 변경 원칙

정책 변경 시 함께 갱신한다.

- 이 기준선 문서
- `security/policies/security-gate-policy.json`
- `scripts/aggregate-results.py`
- `scripts/evaluate-gate.py`
- 관련 회귀 테스트

정책 변경은 최소 한 개의 Pass 사례와 한 개의 Block 사례를 테스트로 추가한 뒤 반영한다.
