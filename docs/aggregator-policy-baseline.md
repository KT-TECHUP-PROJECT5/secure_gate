---
문서명: Aggregator 및 Gate Policy 기준선
최신화: 2026-07-24
상태: Baseline v0.1 / 팀 합의 전 임시 기준
---

# Aggregator 및 Gate Policy 기준선

## 1. 문서 목적

이 문서는 현재 Secure Gate 코드가 검사 결과를 어떻게 통합하고,
어떤 조건으로 Block/Pass를 결정하는지 설명한다.

현재 기준은 최종 팀 정책이 아니다.
기존 `security-gate-policy.json`, `evaluate-gate.py`와 프로젝트 문서를 바탕으로
False Pass를 방지하기 위해 적용한 보수적인 초기 기준이다.

팀은 이 문서를 출발점으로 심각도 매핑, 허용 임계값, 예외 승인,
PR/Post-merge 정책 차이를 단계적으로 확정한다.

## 2. 책임 분리

### Aggregator

`scripts/aggregate-results.py`가 담당한다.

- 도구별 원본 JSON을 공통 finding 형식으로 변환
- 전체 finding 수와 심각도 존재 여부 계산
- 필수 보고서 누락과 형식 오류 기록
- `security/reports/security-summary.json` 생성

### Policy Evaluator

`scripts/evaluate-gate.py`가 담당한다.

- Aggregator가 만든 요약 결과를 정책과 비교
- Block 사유와 Warning 생성
- `security/reports/gate-decision.json` 생성
- Block이면 종료 코드 `1` 반환

Aggregator는 원본 결과를 통합하고, 최종 Block/Pass는 Policy Evaluator가 결정한다.
단, 도구별 심각도를 공통 심각도로 변환하는 현재 로직에는 일부 정책적 가정이 포함되어 있다.

## 3. 입력 보고서

PR Gate는 다음 보고서를 필수 입력으로 사용한다.

- `build-report.json`
- `sast-report.json`
- `secret-report.json`
- `dependency-report.json`
- `runtime-report.json`

Post-merge Gate는 다음 보고서를 Aggregator의 직접 입력으로 사용한다.

- `dependency-report.json`
- `dependency-track-upload-report.json`
- `runtime-report.json`

Post-merge의 `runtime-report.json`은 내부적으로 다음 원본 보고서의 존재와 결과를 검증한다.

- `zap-report.json`
- `nuclei-report.jsonl`
- `nuclei-cve-coverage.json`
- `dynatrace-problems.json`

PR에서는 SBOM을 Artifact로만 보존하고 Dependency-Track 업로드를 수행하지 않는다.
Post-merge에서는 CycloneDX SBOM을 Dependency-Track에 업로드하며, 업로드 실패나
skip을 기술 실패로 처리한다.

## 4. 공통 finding 형식

도구별 결과는 다음 필드로 정규화한다.

```json
{
  "id": "finding identifier",
  "severity": "critical | high | medium | low | secret",
  "title": "finding title",
  "description": "finding description",
  "location": "file:line or URL"
}
```

보고서 공통 형식은 다음과 같다.

```json
{
  "status": "passed | warning | failed | error | not_found",
  "tool": "tool name",
  "findings": [],
  "errors": []
}
```

`status`는 보고서 표시와 오류 판별에 사용한다.
취약점 차단 여부는 최종적으로 정규화된 finding의 심각도 플래그로 결정한다.

## 5. 도구별 정규화 기준

### Semgrep

현재 임시 매핑:

- `ERROR` → `high`
- `WARNING` → `medium`
- `INFO` → `low`
- `errors[]`가 한 건 이상 존재 → 기술 오류로 기록

주의: Semgrep의 `ERROR`는 CVSS High와 완전히 동일한 개념이 아니다.
이 매핑은 팀 합의가 필요한 가장 중요한 임시 기준 중 하나다.

### Gitleaks

- 탐지 결과 한 건 → `secret`
- 탐지 결과가 없으면 `passed`
- Secret 원문은 Summary와 Artifact에 복사하지 않음

### Trivy

Trivy의 원본 `Severity`를 소문자로 변환하여 그대로 사용한다.

- `CRITICAL` → `critical`
- `HIGH` → `high`
- `MEDIUM` → `medium`
- `LOW` → `low`

Gate 입력은 `dependency-report.json`의 `Results[].Vulnerabilities[]`다.
CycloneDX SBOM의 `vulnerabilities[]`는 Gate 근거로 사용하지 않는다.

### Runtime Validation

`runtime-validation.py`가 ZAP, Nuclei, Dynatrace 및 직접 Runtime 검사를
공통 finding으로 변환한 뒤 Aggregator에 전달한다.

현재 주요 매핑:

- ZAP risk code `4` → `critical`
- ZAP risk code `3` → `high`
- ZAP risk code `2` → `medium`
- 그 외 ZAP risk code → `low`
- Nuclei `critical/high/medium/low` → 동일 심각도
- Dynatrace Availability/Error/Monitoring unavailable → `high`
- Dynatrace Performance/Resource contention/Custom alert → `medium`
- Dynatrace의 그 외 문제 → `low`
- Health/Smoke 실패 및 필수 보고서 누락 → `high`

범용 Post-merge Reusable Workflow에서는 애플리케이션별 인증정보 오용을 막기 위해
Custom Runtime Check 기본값을 `none`으로 둔다.

### Build/Test

현재 `build-report.json`은 공통 보고서 형식을 사용한다.
다만 실제 Build/Test Job은 아직 Placeholder이므로 품질 Gate 근거로 확정할 수 없다.

## 6. 현재 Block/Pass 기준

현재 `security-gate-policy.json`의 기준:

```json
{
  "blockOnCritical": true,
  "blockOnHigh": true,
  "blockOnSecret": true,
  "warnOnMedium": true
}
```

Policy Evaluator의 실제 판단:

- Critical finding이 한 건 이상이면 Block
- High finding이 한 건 이상이면 Block
- Secret finding이 한 건 이상이면 Block
- Medium finding만 있으면 Pass와 Warning
- Low finding만 있으면 Pass하고 결과만 기록
- finding이 없으면 Pass
- 필수 보고서 누락, JSON 오류, 지원하지 않는 형식 또는 선행 Job 실패가 있으면 Block

현재는 finding 건수 임계값이 없다.
따라서 Block 대상 심각도가 한 건만 있어도 차단한다.

## 7. 기술 실패 정책

현재 기준은 Fail Closed다.

다음 상황을 취약점 없음으로 처리하지 않는다.

- 필수 Artifact가 생성되지 않음
- 보고서 JSON을 파싱할 수 없음
- 지원하지 않는 보고서 형식
- Semgrep/Gitleaks/Trivy/Runtime Job 실패 또는 취소
- ZAP/Nuclei 실행 오류나 timeout
- Post-merge 필수 원본 보고서 누락

이 경우 Summary의 `has_error`가 `true`가 되고 Gate는 Block된다.

PR에서는 Dependency-Track 업로드를 수행하지 않으므로 업로드 결과를 Gate에 포함하지 않는다.
Post-merge에서는 SBOM 추적이 하드 프로필의 필수 단계이므로 Dependency-Track 업로드
실패 또는 skip을 기술 실패로 처리하여 Gate를 차단한다.

## 8. PR과 Post-merge 차이

### PR

- 전체 정적·의존성·Runtime 결과를 통합
- ZAP Baseline과 제한된 Nuclei 프로필 사용
- `enable_dast=false`이면 동적 스캐너는 실행하지 않음
- Critical/High/Secret 또는 기술 실패 시 Merge 차단

### Post-merge

- 배포된 Staging URL을 대상으로 실행
- ZAP Full Scan과 확대된 Nuclei 프로필 사용
- Dynatrace Problems 및 해당 애플리케이션 Service entity 확인
- ZAP/Nuclei/Coverage/Dynatrace 보고서를 모두 필수로 요구
- Trivy CVE 보고서와 CycloneDX SBOM 생성
- Dependency-Track SBOM 업로드 성공을 필수로 요구
- Dependency/Dependency-Track/Runtime 보고서를 집계하여 다음 환경 승격 여부 판단

현재 PR과 Post-merge의 심각도 차단 기준은 동일하다.
검사 강도와 필수 보고서 범위만 다르다.

## 9. 판단 예시

### 예시 A: Trivy High 1건

- `has_high=true`
- Gate 결과: `FAILED`
- 이유: High finding 탐지

### 예시 B: Semgrep Warning 2건

- 두 finding을 Medium으로 변환
- `has_medium=true`
- Gate 결과: `PASSED`
- Warning 메시지 포함

### 예시 C: Gitleaks 1건

- `has_secret=true`
- Gate 결과: `FAILED`
- Secret 값은 출력하지 않음

### 예시 D: 모든 finding이 Low

- Gate 결과: `PASSED`
- Summary에는 finding을 유지

### 예시 E: SAST Artifact 누락

- SAST 보고서 상태: `not_found` 또는 `error`
- `has_error=true`
- Gate 결과: `FAILED`

## 10. 현재 기준의 알려진 한계

- Semgrep 심각도와 CVSS 심각도를 동일하게 볼 수 없음
- 도구별 신뢰도와 오탐 가능성을 정책에 반영하지 않음
- finding 건수 또는 누적 위험 점수 기준이 없음
- 같은 취약점의 중복 탐지를 제거하지 않음
- Accepted Risk, Suppression, 만료일이 있는 예외 승인이 없음
- 파일·서비스·환경별 정책 차이가 없음
- 신규 또는 알 수 없는 심각도의 명시적인 처리 기준이 없음
- Build/Test가 실제 구현이 아닌 Placeholder
- 실제 GitHub Actions E2E 결과로 기준을 보정하지 않음

## 11. 팀 합의가 필요한 항목

우선순위 1:

- Semgrep `ERROR/WARNING/INFO`를 어떤 공통 심각도로 볼 것인지
- 스캐너 기술 실패 시 항상 차단할 것인지
- PR과 Post-merge에 같은 차단 기준을 적용할 것인지
- Critical/High 한 건 차단 정책을 유지할 것인지

우선순위 2:

- Medium finding 허용 개수
- 도구별 차단 예외
- 오탐 승인 주체와 증빙 방식
- 예외 만료일과 재검토 주기
- Dynatrace 문제의 서비스·환경 범위

우선순위 3:

- 중복 finding 식별 기준
- 누적 위험 점수 모델
- 추세 악화 기준
- Dependency-Track 결과를 Gate에 포함할 시점

## 12. 권장 고도화 순서

### 1단계: 기준 승인

- 본 문서의 임시 매핑을 팀 리뷰
- PR/Post-merge 차단 기준 확정
- 기술 실패 정책 확정

### 2단계: 정책 파일 확장

현재 Boolean 정책을 다음 개념까지 표현하도록 확장한다.

- 도구별 최소 차단 심각도
- 심각도별 허용 건수
- PR/Post-merge 프로필별 정책
- 알 수 없는 심각도 처리

### 3단계: 예외 관리

- finding ID와 위치 기반 Suppression
- 승인자와 사유 기록
- 만료일 필수
- 만료된 예외 자동 차단

### 4단계: 품질 강화

- 공통 보고서 JSON Schema 검증
- 중복 finding 제거
- 실제 GitHub Actions E2E fixture 추가
- Policy 회귀 테스트 추가

### 5단계: 운영 지표

- PR별 finding 증감
- 신규 취약점과 기존 취약점 구분
- 스캐너 실패율
- 예외 건수와 만료 현황

## 13. 변경 원칙

정책 변경 시 다음 내용을 함께 갱신한다.

- 이 기준선 문서
- `security/policies/security-gate-policy.json`
- `scripts/aggregate-results.py`의 도구별 정규화
- `scripts/evaluate-gate.py`의 판단 로직
- `tests/test_aggregate_results.py`의 회귀 테스트

정책 변경은 최소 한 개의 Pass 사례와 한 개의 Block 사례를 테스트로 추가한 뒤 반영한다.
