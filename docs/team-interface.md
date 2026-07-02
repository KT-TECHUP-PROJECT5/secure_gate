---
문서명: 프로젝트 협업용 가이드
최신화: 2026-06-30
작성자: 이윤재
Version: 1.1.0
---

# Team Interface — A 파트 연동 가이드

각 파트는 작업 완료 후 아래 **협업 프로세스**에 따라 PR을 올리고 Merge한다.
Notion에 작업 내용 요약과 Workflow Job 등록 정보를 기록한 뒤 PR 링크와 함께 공유한다.

---

## 협업 프로세스

```text
1. 자신의 파트 브랜치 생성
   예) feat/c-sast, feat/d-runtime, feat/e-policy

2. 작업 수행
   - pr-security-gate.yml의 해당 Placeholder Job을 실제 명령어로 교체
   - 결과 파일이 공통 스키마를 준수하는지 로컬에서 확인

3. Notion에 작업 내용 기록 (아래 양식 참고)

4. PR 생성 (자신의 브랜치 → main)
   - PR 설명에 Notion 링크 포함

5. 팀 리뷰 후 직접 Merge
```

---

## Notion 작성 양식

각 파트는 아래 항목을 Notion에 작성하고 PR과 함께 공유한다.

```
## [파트명] 작업 내용 요약

### 작업 개요
- 담당 파트:
- 작업 브랜치:
- PR 링크:

### 구현 내용
- 사용 도구:
- 실행 명령어:
- 결과 파일 경로:
- 로컬 테스트 결과:

### Workflow Job 등록 정보
pr-security-gate.yml의 [Job명] Job에 아래 내용을 등록했습니다.

steps:
  - name: [단계명]
    run: [실행 명령어]

### 결과 파일 샘플
(실제 실행 결과 JSON 일부 첨부)

### 특이사항 / 전달 사항
-
```

---

## 공통 결과 파일 스키마

모든 보안 검사 결과 파일은 아래 JSON 형식을 준수해야 합니다.

```json
{
  "status": "passed | failed | warning",
  "tool": "<tool-name>",
  "findings": [
    {
      "id": "<finding-id>",
      "severity": "critical | high | medium | low | secret",
      "title": "<title>",
      "description": "<description>",
      "location": "<file:line 또는 url>"
    }
  ]
}
```

결과 파일은 `security/reports/` 경로에 저장하고 Artifact로 업로드합니다.

---

## B 파트: Application Security / Red Team

| 항목                                        | 내용 | 상태   |
| ------------------------------------------- | ---- | ------ |
| 취약점 포함 테스트 앱 브랜치 또는 코드 경로 |      | 미확정 |
| 취약 API 목록                               |      | 미확정 |
| 공격 PoC 목록 및 실행 방법                  |      | 미확정 |
| 탐지되어야 하는 취약점 목록                 |      | 미확정 |
| 정상 탐지 / 미탐 / 오탐 검증 기준           |      | 미확정 |

---

## C 파트: Security Scan

| 항목                           | 내용                                      | 상태       |
| ------------------------------ | ----------------------------------------- | ---------- |
| Semgrep 실행 명령어            | `semgrep scan --config auto . --json --output security/reports/sast-report.json` | 확정       |
| Semgrep 설정 파일 경로         | 별도 파일 없음 (`--config auto`)                                                | 초기 확정  |
| SAST 결과 파일 경로            | `security/reports/sast-report.json`                                             | A파트 고정 |
| Gitleaks 실행 명령어           |                                           | 미확정     |
| Secret Scan 결과 파일 경로     | `security/reports/secret-report.json`     | A파트 고정 |
| Trivy 실행 명령어              |                                           | 미확정     |
| Dependency Scan 결과 파일 경로 | `security/reports/dependency-report.json` | A파트 고정 |
| 각 도구의 실패 기준            | 결과 파일 미생성 또는 유효하지 않은 JSON | 초기 확정  |
| 출력 형식                      | 도구별 원본 JSON                         | 확정       |

---

## D 파트: Runtime Validation

| 항목                              | 내용                                   | 상태       |
| --------------------------------- | -------------------------------------- | ---------- |
| Staging 실행 방식                 |                                        | 미확정     |
| Staging URL                       |                                        | 미확정     |
| Health Check Endpoint             |                                        | 미확정     |
| Smoke Test 실행 명령어            |                                        | 미확정     |
| ZAP 실행 명령어                   |                                        | 미확정     |
| Runtime Validation 결과 파일 경로 | `security/reports/runtime-report.json` | A파트 고정 |
| 보안 헤더 검증 기준               |                                        | 미확정     |
| Runtime Validation 실패 기준      |                                        | 미확정     |

---

## E 파트: AppSec / Policy / IR

| 항목                       | 내용                                             | 상태        |
| -------------------------- | ------------------------------------------------ | ----------- |
| Merge 차단 기준            | Critical / High / Secret (초기 정책 적용 중)     | 초기값 적용 |
| Warning 처리 기준          | Medium (초기 정책 적용 중)                       | 초기값 적용 |
| CVSS 등급 기준             |                                                  | 미확정      |
| 도구별 Severity 매핑 기준  |                                                  | 미확정      |
| PR 댓글 수정 가이드 템플릿 | `security/templates/pr-comment-template.md` 참고 | 미확정      |
| IR 플레이북 연결 기준      |                                                  | 미확정      |

---

## 파일 경로 요약

| 파트                   | 결과 파일 경로                            |
| ---------------------- | ----------------------------------------- |
| C - SAST               | `security/reports/sast-report.json`       |
| C - Secret Scan        | `security/reports/secret-report.json`     |
| C - Dependency Scan    | `security/reports/dependency-report.json` |
| D - Runtime Validation | `security/reports/runtime-report.json`    |
| A - Summary            | `security/reports/security-summary.json`  |
| A - Gate Decision      | `security/reports/gate-decision.json`     |
