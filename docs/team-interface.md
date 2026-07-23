---
문서명: 프로젝트 협업용 가이드
최신화: 2026-07-23
작성자: 이윤재
Version: 1.3.0
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
   - `pr-security-gate.yml`(reusable)의 해당 Placeholder Job을 실제 명령어로 교체
   - 이 저장소 검증은 `call-pr-security-gate.yml` caller를 통해 실행된다
   - 결과 파일이 공통 스키마를 준수하는지 로컬에서 확인
   - 타 프로젝트 연동 변경 시 `examples/caller-security-gate.yml`도 함께 갱신

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
| SAST 기본 도구                 | Semgrep (CodeQL 비교 후 미선정)           | 확정       |
| Semgrep 실행 명령어            | `semgrep scan --config auto . --json --output security/reports/sast-report.json` | 확정       |
| Semgrep 설정 파일 경로         | 별도 파일 없음 (`--config auto`)                                                | 초기 확정  |
| SAST 결과 파일 경로            | `security/reports/sast-report.json`                                             | A파트 고정 |
| Gitleaks 실행 명령어           | `gitleaks git . --report-format json --report-path security/reports/secret-report.json --redact=100 --exit-code 0 --no-banner` | 확정       |
| Secret Scan 결과 파일 경로     | `security/reports/secret-report.json`     | A파트 고정 |
| Trivy 실행 명령어 (fs)     | `trivy fs --scanners vuln --file-patterns "pip:requirements-legacy.txt" --format json --output security/reports/dependency-report.json --exit-code 0 --no-progress .` | 확정 |
| Trivy 실행 명령어 (image)  | Dockerfile 존재 시 `docker build` 후 `trivy image ...` (CVE JSON + CycloneDX 분리 실행). 모노레포는 `dockerfile_path` / `docker_build_context` 명시 | 확정 |
| Trivy SBOM 명령어          | `trivy {fs\|image} --format cyclonedx ...` (`fs`는 CVE와 동일하게 `--file-patterns "pip:requirements-legacy.txt"` 포함) | 확정 |
| Dependency Scan 결과 파일 경로 | `security/reports/dependency-report.json` | A파트 고정 |
| SBOM 형식 / 경로           | CycloneDX **1.6** → `security/reports/sbom.cdx.json` (`bomFormat == "CycloneDX"`, `specVersion == "1.6"` 검증, 실패 시 Job 실패) | 확정 |
| Dependency-Track           | 기존 프로젝트 UUID에 BOM 업로드 (선택). URL+API Key+UUID 모두 있을 때만. `autoCreate` 없음. DT는 Gate가 아니라 SBOM/SCA 대시보드. `succeeded`=BOM 수신 성공(분석 완료 아님) | 확정 |
| DT 업로드 리포트           | `security/reports/dependency-track-upload-report.json` (artifact `dependency-track-upload-report`) | 확정 |
| 각 도구의 실패 기준        | 결과 파일 미생성 또는 유효하지 않은 JSON. DT API 실패는 Job 비차단 | 초기 확정 |
| 출력 형식                  | 도구별 원본 JSON                         | 확정       |
| 선정 근거 문서             | `docs/sast/sast-tool-selection-summary.md` | 확정     |

---

## D 파트: Runtime Validation

| 항목                              | 내용                                   | 상태       |
| --------------------------------- | -------------------------------------- | ---------- |
| PR 단계 DAST 환경                 | runner-local 또는 `target_url` (`enable_dast`) | 확정 방향 |
| Staging CD 실행 방식              | `push main` → `cd-staging.yml` (Build/Deploy/Post-deploy) | 목표 확정 / 구현 Placeholder |
| Staging URL                       |                                        | 미확정     |
| Health Check Endpoint             |                                        | 미확정     |
| Smoke Test 실행 명령어            |                                        | 미확정     |
| DAST 도구                         | OWASP ZAP + Nuclei                     | 확정       |
| ZAP 실행 명령어                   |                                        | 미확정     |
| Nuclei 실행 명령어                | Docker 기반 JSONL 출력 (D파트 Workflow 연동) | 진행 중 |
| Runtime Validation 결과 파일 경로 | `security/reports/runtime-report.json` | A파트 고정 |
| 보안 헤더 검증 기준               | CSP, X-Frame-Options, X-Content-Type-Options 등 | 초기 확정 |
| Runtime Validation 실패 기준      | 통합 finding의 Critical/High → Policy Evaluator | 확정 방향 |
| PR DAST vs CD DAST                | PR=선택적 경량 검사, Staging=배포 후 재검증 | 확정 |

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
| C - Dependency Scan    | `security/reports/dependency-report.json` (latest 계약) |
| C - SBOM               | `security/reports/sbom.cdx.json`          |
| C - DT upload report   | `security/reports/dependency-track-upload-report.json` |
| C - Scan history       | `security/reports/history/<run_id>/` (스냅샷 + `meta.json`) |
| D - Runtime Validation | `security/reports/runtime-report.json`    |
| A - Summary            | `security/reports/security-summary.json`  |
| A - Gate Decision      | `security/reports/gate-decision.json`     |
