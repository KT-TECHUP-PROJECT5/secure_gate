---
문서명: Aggregator 및 Gate Policy 기준선
최신화: 2026-07-24
상태: Policy v1 / 초기 운영 기준
---

# Aggregator 및 Gate Policy 기준선

## 1. 문서 목적

이 문서는 현재 Secure Gate 코드가 검사 결과를 어떻게 통합하고,
어떤 조건으로 Block/Pass를 결정하는지 설명한다.

Policy v1은 False Pass를 방지하는 보수적인 초기 운영 기준이다.
공통 finding 형식은 유지하면서 PR/Post-merge/교육용 프로필, 기술 실패 정책,
만료일이 있는 Accepted Risk를 정책 파일과 Evaluator에서 처리한다.

도구 신뢰도, 신규/기존 finding 비교, 중복 제거는 공통 스키마 확장과 팀 합의가
필요하므로 후속 단계로 관리한다.

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

Semgrep 원본의 `errors` 배열은 `level`을 다시 확인한다. `error`와 `fatal`은
필수 보고서 오류로 처리하지만, `warn`, `warning`, `info`는 분석 범위가 일부
제한되었다는 보고서 경고로 보존하고 그 자체만으로 Gate를 차단하지 않는다.

범용 Post-merge Reusable Workflow에서는 애플리케이션별 인증정보 오용을 막기 위해
Custom Runtime Check 기본값을 `none`으로 둔다.

### Build/Test

현재 `build-report.json`은 공통 보고서 형식을 사용한다.
다만 실제 Build/Test Job은 아직 Placeholder이므로 품질 Gate 근거로 확정할 수 없다.

## 6. Policy v1 구조

`security-gate-policy.json`은 프로필별 판단 기준을 가진다.

```json
{
  "version": 1,
  "defaultProfile": "pr",
  "profiles": {
    "pr": {
      "blockOnReportError": true,
      "blockSeverities": ["critical", "high", "secret"],
      "warnSeverities": ["medium"],
      "unknownSeverity": "block"
    },
    "post_merge": {
      "blockOnReportError": true,
      "blockSeverities": ["critical", "high", "secret"],
      "warnSeverities": ["medium"],
      "unknownSeverity": "block"
    },
    "training": {
      "blockOnReportError": true,
      "blockSeverities": ["secret"],
      "warnSeverities": ["critical", "high", "medium"],
      "unknownSeverity": "warn"
    }
  }
}
```

프로필은 `evaluate-gate.py --profile <name>` 또는 `SECURE_GATE_PROFILE`로 선택한다.
지정하지 않으면 `dependency_track` 보고서는 있고 `build` 보고서는 없는 Post-merge
통합 결과를 자동으로 `post_merge`로 식별한다. 그 외에는 `defaultProfile`을 사용한다.
기존 Boolean 정책도 하위 호환으로 읽는다.

## 7. 프로필별 기준

### PR

- Critical, High, Secret finding이 한 건 이상이면 Merge 차단
- Medium은 경고
- Low는 기록
- 알 수 없는 severity는 차단
- 필수 보고서 오류는 Fail Closed
- Dependency-Track 업로드 결과는 PR 직접 입력에서 제외

PR Aggregator 기본 입력:

```text
build,sast,secret_scan,dependency_scan,runtime_validation
```

### Post-merge

- Critical, High, Secret finding이 한 건 이상이면 다음 환경 승격 중단
- Health/Smoke 실패와 필수 Runtime 원본 누락은 High로 변환되어 차단
- Dynatrace Availability/Error/Monitoring unavailable은 High
- Dynatrace Performance/Resource contention은 Medium 경고
- Dependency-Track 업로드 실패 또는 skip은 기술 실패로 차단
- 알 수 없는 severity와 필수 보고서 오류는 차단

### Training

- 교육용 취약 웹의 Critical/High/Medium은 경고로 기록
- Secret은 교육 환경에서도 차단
- 필수 보고서 오류는 차단
- 기대 취약점 탐지 여부 검증은 별도의 Detection Baseline으로 관리

Training 프로필은 운영 보안 Gate로 사용하지 않는다.

## 8. 기술 실패 정책

필수 보안 검사의 기술 실패는 Fail Closed다.

- 필수 Artifact 미생성
- 보고서 JSON 파싱 실패
- 지원하지 않는 보고서 형식
- 필수 Scanner Job 실패 또는 취소
- ZAP/Nuclei timeout 또는 결과 누락
- Post-merge Dynatrace 결과 누락
- Policy 또는 Accepted Risk 파일 형식 오류

AI 설명 생성 실패는 보안 검사 실패가 아니므로 Gate에 영향을 주지 않는다.

## 9. Accepted Risk

예외는 `security/policies/accepted-risks.json`에서 관리한다.

```json
{
  "version": 1,
  "exceptions": [
    {
      "id": "runtime.nuclei.top-xss-params",
      "location": "https://example.test/posts",
      "reason": "교육용 취약점 탐지 검증",
      "owner": "D-part",
      "approvedBy": "security-lead",
      "expiresAt": "2026-08-31",
      "profiles": ["training"]
    }
  ]
}
```

필수 필드:

- `id`: finding ID
- `reason`: 예외 사유
- `owner`: 조치 책임자
- `approvedBy`: 승인자
- `expiresAt`: `YYYY-MM-DD` 만료일

선택 필드:

- `location`: 같은 ID 중 특정 위치만 예외
- `profiles`: 예외를 적용할 프로필

적용 원칙:

- 만료일이 지난 예외는 적용하지 않음
- Secret finding에는 예외를 적용하지 않음
- 잘못된 예외 파일은 정책 오류로 차단
- 적용·만료된 예외는 `gate-decision.json`에 기록

## 10. Gate 결과

`gate-decision.json`은 기존 필드에 다음 감사 정보를 추가한다.

- `policy_version`
- `policy_profile`
- `effective_findings`
- `severity_counts`
- `accepted_risks`
- `expired_risks`

`total_findings`는 원본 탐지 수이고 `effective_findings`는 유효한 예외를 제외한
정책 평가 대상 수다.

## 11. AI 설명 계층

`generate-ai-security-summary.py`는 확정된 `gate-decision.json`을 입력으로 사용한다.

- 전체 결과와 심각도 분포 요약
- 우선 확인할 실제 Finding 선별
- 간단한 개선 방향 제시
- 보고서 읽는 법과 한계 설명

AI는 Gate 상태, Severity, 예외를 변경하지 않는다. 입력에 없는 Finding ID를
제시하면 결과에서 제거한다. API Key 누락이나 AI 호출 실패도 Gate에 영향을 주지
않는다. 결과 파일은 `ai-security-summary.json`과 `ai-security-summary.md`이며
Aggregator 입력이 아니다.

## 12. 판단 예시

### PR에서 High 1건

- `policy_profile=pr`
- Gate 결과: `FAILED`

### Training에서 High 1건

- `policy_profile=training`
- Gate 결과: `PASSED`
- Warning에 High finding 기록

### 유효한 High 예외

- finding ID, 위치, 프로필이 일치
- 승인자, 사유, 만료일이 유효
- Gate 평가 대상에서 제외
- `accepted_risks`에 기록

### 만료된 High 예외

- 예외를 적용하지 않음
- High 기준에 따라 차단
- `expired_risks`에 기록

### Secret 예외 등록

- 예외를 적용하지 않음
- Secret 기준에 따라 차단

## 13. 후속 고도화 항목

현재 공통 finding 형식을 변경하지 않기 위해 다음 항목은 Policy v1에 포함하지 않는다.

- ZAP Risk와 Confidence를 함께 사용하는 판정
- 공식·Custom Nuclei template 신뢰도 구분
- 신규 finding과 기존 finding 비교
- 도구 간 중복 finding fingerprint
- CVSS Threat/Environmental, KEV, EPSS 기반 위험 우선순위
- Critical/High 예외 최대 승인 기간 자동 검증
- 서비스·환경별 정책

이 항목들은 공통 스키마 변경과 팀 합의 후 Policy v2에서 반영한다.

## 14. 변경 원칙

정책 변경 시 다음 내용을 함께 갱신한다.

- 이 기준선 문서
- `security/policies/security-gate-policy.json`
- `security/policies/accepted-risks.json`
- `scripts/aggregate-results.py`
- `scripts/evaluate-gate.py`
- `tests/test_aggregate_results.py`

정책 변경은 Pass, Block, 예외 적용, 예외 만료 사례를 회귀 테스트에 포함해야 한다.
