---
문서명: 파이프라인 운영 가이드
최신화: 2026-07-24
작성자: 이윤재
Version: 1.5.0
---

# Pipeline Guide

## 개요

Secure PR Gate는 GitHub Actions **Reusable Workflow** 기반 DevSecOps 보안 게이트웨이 시스템이다.
사용자 프로젝트에서 PR이 생성되면 얇은 caller workflow가 Secure PR Gate를 호출하고, 보안 검사를 자동 실행한 뒤 Merge 가능 여부를 판단한다.

---

## Workflow vs Reusable Workflow

| 항목 | Caller (일반 Workflow) | Reusable Workflow |
| --- | --- | --- |
| 파일 | PR/Post-merge caller | `pr-security-gate.yml`, `post-merge-security-gate.yml` |
| 트리거 | `pull_request` 또는 Staging 배포 완료 | `workflow_call` |
| 역할 | 실행 시점·배포 순서 결정, inputs 전달 | 프로필별 보안 검사·Gate 실행 |
| 배포 | 사용자 저장소에 최소 파일 추가 | `uses: ...@v1` 로 버전 고정 호출 |

```text
사용자 PR 생성
  -> 사용자 저장소 caller.yml (pull_request)
  -> uses: KT-TECHUP-PROJECT5/secure_gate/.../pr-security-gate.yml@v1
  -> SAST / Secret / Dependency / Runtime / Aggregate / Gate / PR Comment

사용자 main 병합 및 Staging 배포
  -> 사용자 저장소 post-merge caller.yml (배포 workflow 완료)
  -> uses: KT-TECHUP-PROJECT5/secure_gate/.../post-merge-security-gate.yml@v1
  -> Health / ZAP Full / Nuclei 확대 / Dynatrace / Runtime / Policy
```

---

## Workflow 구성

### 1. `pr-security-gate.yml` — Reusable 보안 게이트

트리거: `workflow_call` (직접 실행되지 않음)

| Job | 역할 | 상태 |
| --- | --- | --- |
| `build-test` | 빌드 및 테스트 | Placeholder |
| `sast` | Semgrep 정적 분석 | 연동됨 |
| `secret-scan` | Gitleaks 민감정보 탐지 | 연동됨 |
| `dependency-scan` | Trivy CVE + CycloneDX SBOM (+ Dependency-Track 업로드, 선택) | 연동됨 |
| `runtime-validation` | Health Check / Smoke Test / DAST (ZAP·Nuclei) | inputs 기반 runner-local 지원 |
| `aggregate-and-gate` | 결과 통합 및 Gate 판단 | 구현 완료 |
| `pr-comment` | PR 댓글 작성 | 구현 완료 |

### 2. `call-pr-security-gate.yml` — 이 저장소용 Caller

트리거: `pull_request` → `main`, `develop`

이 저장소 PR에서 reusable workflow를 호출한다.
`gate_ref`는 `${{ github.sha }}`로 두어, 태그 없이도 PR 커밋의 scripts를 사용한다.

### 3. `post-merge-security-gate.yml` — Reusable Post-merge 보안 게이트

트리거: `workflow_call` (직접 실행되지 않음)

Staging URL을 입력받아 Trivy CVE/SBOM 생성, Dependency-Track 업로드,
Health Check, ZAP/Nuclei `post-merge` 프로필, Dynatrace 수집,
필수 원본 보고서 검증 및 Policy Evaluator를 실행한다.

### 4. `cd-staging.yml` — 이 저장소용 수동 Staging 검증 Caller

트리거: `workflow_dispatch`

| Job | 역할 | 상태 |
| --- | --- | --- |
| `post-deploy-validation` | 기존 Staging을 대상으로 `post-merge-security-gate.yml` 호출 | Reusable 연결 완료 |

실제 애플리케이션은 배포가 완료된 뒤
`examples/caller-post-merge-security-gate.yml` 패턴으로 Reusable Workflow를 호출한다.

### 5. PR DAST와 Staging CD DAST 역할 구분

DAST는 PR Gate와 Staging CD에서 목적이 다르다. `enable_dast=true`이고 Staging 배포 후에도 DAST를 돌리면 검사가 두 번 실행될 수 있다.

| 구분 | PR Security Gate | 애플리케이션 Post-merge Caller |
| --- | --- | --- |
| 트리거 | `pull_request` | Staging 배포 성공 후 |
| 환경 | runner-local 또는 `target_url` | 실제 Staging 배포 환경 |
| 목적 | Merge 전 선택적·경량 동적 검사 | 배포 후 환경·헤더·프록시까지 포함한 재검증 |
| 도구 | ZAP, Nuclei, 직접 보안 헤더 검사 | Trivy/SBOM/Dependency-Track, Health Check, Smoke Test, DAST |
| 기본값 | `enable_dast: false` (선택), DT 업로드 안 함 | Dependency-Track/ZAP/Nuclei/Dynatrace 필수 하드 프로필 |
| 결과 처리 | `runtime-report.json` → Aggregator → Policy Evaluator → Required Check | 배포 성공/중단·Rollback 판단 |

PR 단계에서는 시간을 고려해 Baseline·제한 심각도 중심의 검사를 두고, 전체 검증은 Staging 배포 후에 수행하는 구성을 권장한다.

---

## 다른 프로젝트에서 사용하기

### 최소 준비물

1. `.github/workflows/security-gate.yml` 추가  
   → 템플릿: [`examples/caller-security-gate.yml`](../examples/caller-security-gate.yml)
2. (선택) `security/policies/security-gate-policy.json` — 없으면 Secure Gate 기본 정책 사용
3. (선택, DAST) `install_command` / `build_command` / `start_command` / `app_port` / `health_path`  
   또는 이미 떠 있는 `target_url`
4. Branch Protection에서 Secure PR Gate Check를 Required로 설정
5. Post-merge 사용 시 Staging 배포 완료 Workflow와
   [`examples/caller-post-merge-security-gate.yml`](../examples/caller-post-merge-security-gate.yml)을 연결

EC2나 Staging 서버는 **필수가 아니다.**  
기본은 GitHub Actions runner에서 앱을 기동하는 `runner-local` 방식이다.

### Caller 예시

```yaml
name: Secure PR Gate

on:
  pull_request:
    branches: [main, develop]

permissions:
  contents: read
  pull-requests: write
  checks: write
  security-events: write

jobs:
  secure-pr-gate:
    uses: KT-TECHUP-PROJECT5/secure_gate/.github/workflows/pr-security-gate.yml@v1
    with:
      gate_repository: KT-TECHUP-PROJECT5/secure_gate
      gate_ref: v1
      enable_dast: true
      install_command: npm ci
      build_command: npm run build
      start_command: npm start
      app_port: "3000"
      health_path: /health
    secrets:
      DEPENDENCY_TRACK_URL: ${{ secrets.DEPENDENCY_TRACK_URL }}
      DEPENDENCY_TRACK_API_KEY: ${{ secrets.DEPENDENCY_TRACK_API_KEY }}
```

### Inputs 계약

| Input | 기본값 | 설명 |
| --- | --- | --- |
| `gate_repository` | `KT-TECHUP-PROJECT5/secure_gate` | scripts/정책이 있는 저장소 |
| `gate_ref` | `v1` | tooling checkout ref/tag |
| `enable_dast` | `false` | PR 단계 DAST 실행 여부 (Staging CD DAST와 별개) |
| `install_command` | `""` | 예: `npm ci` |
| `build_command` | `""` | 예: `npm run build` |
| `start_command` | `""` | 예: `npm start` (백그라운드 기동) |
| `app_port` | `3000` | runner-local 포트 |
| `health_path` | `/health` | readiness 경로 |
| `target_url` | `""` | 외부 Preview/Staging URL (있으면 localhost 대신 사용) |
| `dast_scan_path` | `/` | PR DAST 시작 경로. Base URL과 분리하며 취약 앱은 `/posts`처럼 지정 |
| `policy_path` | `""` | caller 정책 경로 (비어 있으면 기본/로컬 정책) |
| `gate_profile` | `pr` | 정책 프로필. 일반 PR은 `pr`, 의도적으로 취약한 교육용 앱은 `training` 사용 |
| `node_version` | `20` | Node 기반 install/build/start 시 사용 |
| `dockerfile_path` | `""` | Dockerfile 경로. 비어 있으면 루트 `Dockerfile` → `dockerfile`만 자동 탐색 (하위 경로 자동 선택 안 함) |
| `docker_build_context` | `"."` | Docker build context. 모노레포는 caller가 명시 |
| `dependency_track_service_name` | `""` | 모노레포 서비스명 (예: `frontend`). 단일이면 비움 |
| `dependency_track_project_version` | `main` | DT Project version |
| `dependency_track_upload_mode` | `main-only` | `main-only` / `always` / `never` |

상세: [`docs/dependency-track.md`](./dependency-track.md)

### Secrets

| Secret | 필수 | 설명 |
| --- | --- | --- |
| `GITHUB_TOKEN` | 자동 | PR 댓글용. 별도 전달 불필요 |
| `DEPENDENCY_TRACK_URL` | Post-merge 필수 | Dependency-Track **Backend API** base URL (UI 전용 주소 아님) |
| `DEPENDENCY_TRACK_API_KEY` | Post-merge 필수 | Dependency-Track API Key |
| `DYNATRACE_TOKEN` | Post-merge 필수 | Post-merge Reusable Workflow에서 Problems와 Service entities 조회 |
| `ZAP_AUTH_PASSWORD` | 인증 ZAP 사용 시 필수 | ZAP Automation Framework 테스트 계정 비밀번호 |
| `CUSTOM_RUNTIME_PASSWORD` | 인증 Custom Check 사용 시 필수 | Admin/IDOR 검사 테스트 계정 비밀번호 |
| `OPENAI_API_KEY` | 선택 | Gate 판정 이후 비차단 AI 설명 보고서 생성. 미등록·API 실패 시 `skipped`/`failed` 보고서만 생성 |

PR에서는 Dependency-Track 업로드를 생략한다. Post-merge에서는 URL/API Key와
SBOM 업로드 성공을 필수로 요구하며 실패 또는 skip 시 Gate를 차단한다.

Dynatrace 연동값은 Post-merge caller가 Reusable Workflow에 전달한다.

| 구분 | 값 |
| --- | --- |
| Environment URL | `https://xlj20734.live.dynatrace.com` |
| Staging URL | `http://www.securegate.n-e.kr` |
| Problem Selector | `status("open")` |
| Problem Entity Selector | `type("SERVICE"),entityName.equals("OWASP practice board DAST")` |
| Service Entity Selector | `type("SERVICE"),entityName.equals("OWASP practice board DAST")` |
| 수집 스크립트 | `scripts/fetch-dynatrace-problems.py` |
| 원본 결과 | `security/reports/dynatrace-problems.json` |
| 통합 결과 | `security/reports/runtime-report.json` |

---

## Dependency Scan (Trivy + SBOM + Dependency-Track)

`dependency-scan` Job은 CVE 보고서(Gate용)와 CycloneDX SBOM을 **분리 생성**한다.

### Dockerfile 탐색 우선순위

1. `dockerfile_path` input이 있으면 해당 경로 사용
2. 없으면 저장소 **루트**의 `Dockerfile`, 그다음 `dockerfile`
3. 하위 경로 Dockerfile은 자동 선택하지 않음 → 모노레포는 `dockerfile_path` / `docker_build_context`를 caller가 명시

| 분기 | CVE | SBOM |
| --- | --- | --- |
| Dockerfile 있음 | `docker build` 후 `trivy image` (JSON) | 동일 이미지에 `trivy image --format cyclonedx` |
| Dockerfile 없음 | `trivy fs` (JSON, `--file-patterns pip:requirements-legacy.txt`) | `trivy fs --file-patterns ... --format cyclonedx` |

검증:

- `dependency-report.json`: `SchemaVersion == 2` (실패 시 Job 실패)
- `sbom.cdx.json`: `bomFormat == "CycloneDX"` 및 `specVersion == "1.6"` (실패 시 Job 실패)
  - Trivy가 더 높은 specVersion을 내더라도 생성 직후 `scripts/pin-cyclonedx-specversion.py`로 **1.6 고정** (Dependency-Track 5.0.x 호환)
- finding은 `--exit-code 0`으로 Job을 막지 않음. Docker/Trivy 기술 실패는 Job 실패 (`continue-on-error` 미사용)

### Artifacts

| Artifact | 경로 | 역할 |
| --- | --- | --- |
| `dependency-report` | `security/reports/dependency-report.json` | Gate/Aggregator/DAST용 **최신** Trivy CVE JSON (계약 경로) |
| `sbom` | `security/reports/sbom.cdx.json` | **최신** CycloneDX SBOM (specVersion 1.6) |
| `dependency-track-upload-report` | `security/reports/dependency-track-upload-report.json` | **최신** DT 업로드 결과 (`if: always()`). Aggregator 필수 입력 아님 |
| `dependency-scan-history-<run_id>` | `security/reports/history/<run_id>/` | 실행 스냅샷 (동일 파일명 + `meta.json`). Gate 계약 경로와 분리 |

### 결과 파일 레이아웃

```text
security/reports/
  dependency-report.json                 # latest (계약)
  sbom.cdx.json                          # latest (계약)
  dependency-track-upload-report.json    # latest
  history/
    20260723T063542Z_abc1234_run123456/
      dependency-report.json
      sbom.cdx.json
      dependency-track-upload-report.json
      meta.json
```

`history/<run_id>/`는 UTC 시각 + commit short SHA (+ `GITHUB_RUN_ID`)로 구분한다.
Gate/DAST는 항상 latest 계약 경로만 읽고, 과거 비교·감사용으로 history를 사용한다.

### Dependency-Track 연동

Dependency-Track은 Gate 판정기가 아니라 **SBOM/SCA 추적 대시보드**다.
운영 규칙·식별·모노레포·업로드 시기는 [`docs/dependency-track.md`](./dependency-track.md)를 본다.

- 식별: `secure-gate/github/<owner>/<repo>[/<service>]` + version `main` (UUID input 없음, `autoCreate`)
- PR 소프트 프로필: 업로드하지 않음
- Post-merge 하드 프로필: `always` 모드로 업로드하고 성공을 필수로 검증
- `DEPENDENCY_TRACK_URL`은 Backend API base URL (UI 주소 아님)
- Post-merge 업로드 실패 또는 skip은 기술 실패로 Gate를 차단
- `succeeded` = BOM **수신** 성공 (분석 완료 보장 아님)

## 스크립트 checkout 방식

Reusable job의 기본 `actions/checkout`은 **caller(사용자) 저장소**를 받는다.  
Aggregator / Evaluator / PR Comment 스크립트는 Secure Gate 저장소를 `.secure-gate/`에 추가 checkout한다.

```text
workspace/
  <caller source>          # SAST 등 검사 대상
  .secure-gate/scripts/    # aggregate / evaluate / create-pr-comment
  security/reports/        # 결과 파일
```

정책 우선순위:

1. `inputs.policy_path`가 가리키는 파일
2. caller의 `security/policies/security-gate-policy.json`
3. `.secure-gate/security/policies/security-gate-policy.json`

---

## 버전 배포 (`@v1`)

Secure PR Gate는 서버 배포가 아니라 **Git 태그로 Reusable Workflow를 배포**한다.

```bash
# 릴리즈 예시 (maintainers)
git tag v1.0.0
git push origin v1.0.0

# major 이동 태그 (사용자가 @v1 로 따라가도록)
git tag -f v1 v1.0.0
git push origin v1 --force
```

사용자 프로젝트는 다음처럼 고정한다.

```yaml
uses: KT-TECHUP-PROJECT5/secure_gate/.github/workflows/pr-security-gate.yml@v1
# 또는 완전 고정:
# uses: .../pr-security-gate.yml@v1.0.0
```

`with.gate_ref`도 동일한 태그(`v1` 또는 `v1.0.0`)로 맞춘다.  
워크플로우 YAML과 scripts가 같은 버전에서 오도록 하기 위함이다.

---

## 결과 파일 구조

```text
security/reports/
  build-report.json         # Build/Test 결과
  sast-report.json          # SAST 결과 (C파트)
  secret-report.json        # Secret Scan 결과 (C파트)
  dependency-report.json    # Dependency Scan 최신 결과 (C파트)
  sbom.cdx.json             # CycloneDX 1.6 SBOM (C파트)
  dependency-track-upload-report.json # Dependency-Track 업로드 결과 (C파트)
  history/<run_id>/         # Dependency Scan 실행 스냅샷 (C파트)
  zap-report.json           # OWASP ZAP 원본 JSON (D파트 중간 입력)
  nuclei-cve-ids.txt        # Trivy High/Critical CVE에서 만든 Nuclei template ID 입력
  nuclei-cve-matched-templates.txt # 설치된 Nuclei 템플릿 사전 확인 결과
  nuclei-base-report.jsonl  # Nuclei 기본 검사 결과
  nuclei-cve-report.jsonl   # Trivy CVE 우선 검사 결과
  nuclei-report.jsonl       # Nuclei 원본 JSONL (D파트 중간 입력)
  nuclei-cve-coverage.json  # CVE 후보/템플릿/finding coverage 상태
  dynatrace-problems.json   # Dynatrace Problems API 원본 JSON (D파트 중간 입력)
  runtime-report.json       # Runtime Validation 결과 (D파트)
  security-summary.json     # Aggregator 통합 결과
  gate-decision.json        # Gate Evaluator 판단 결과
  ai-security-summary.json  # AI 설명 구조화 결과 (비차단)
  ai-security-summary.md    # 사람이 읽는 AI 설명 보고서 (비차단)
```

---

## 결과 파일 공통 스키마

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

---

## Gate 정책

`security/policies/security-gate-policy.json`에서 관리한다.
현재 동작과 팀 합의가 필요한 임시 기준은
[`docs/aggregator-policy-baseline.md`](./aggregator-policy-baseline.md)에 정리한다.
이 기준은 Baseline v0.2이며, 목표 정책과 현재 코드 차이를 문서에 명시한다.

| 조건 | 처리 |
| --- | --- |
| 실제 Critical/High `vuln` | 차단 |
| Secret, 스캐너 기술 실패 | 차단 |
| High/Critical 가용성 실패 | 차단 |
| Medium 또는 `misconfig` | 경고 |
| 승인·소유자·사유·만료일이 유효한 예외 | 판정 제외, 기록 유지 |
| 모두 통과 | 허용 |

환경변수 `SECURE_GATE_POLICY`로 정책 파일 경로를 오버라이드할 수 있다.
`SECURE_GATE_PROFILE` 또는 `evaluate-gate.py --profile`로 `pr`,
`post_merge`, `training` 프로필을 선택한다.

---

## Merge 차단 메커니즘

1. `evaluate-gate.py`가 선택 프로필의 Block 조건 탐지 시 `exit 1`
2. `aggregate-and-gate` Job 실패 → GitHub Check 실패
3. Branch Protection Rule에서 해당 Check를 Required로 설정 → Merge 버튼 비활성화

> Settings → Branches → Branch protection rules → Require status checks

---

## 스크립트

| 파일 | 역할 |
| --- | --- |
| `scripts/aggregate-results.py` | 각 보안 결과 파일 통합 |
| `scripts/evaluate-gate.py` | 정책 기준 Pass/Fail 판단 |
| `scripts/gate_policy.py` | finding 카테고리 분류와 Block/Warn 공통 규칙 |
| `scripts/generate-ai-security-summary.py` | 확정 Gate 결과의 비차단 AI 요약과 개선 방향 생성 |
| `scripts/create-pr-comment.py` | GitHub API로 PR 댓글 작성 |
| `scripts/runtime-validation.py` | Health / Smoke / Header / Custom Check / ZAP / Nuclei / Dynatrace 결과를 `runtime-report.json`으로 생성하고, Post-merge 필수 원본 결과 누락을 검증 |
| `scripts/fetch-dynatrace-problems.py` | Dynatrace Problems API v2의 열린 문제와 최근 Service entities를 JSON으로 수집 |
| `scripts/run-zap-validation.py` | PR ZAP Baseline과 Post-merge ZAP Full Scan 실행, 종료 코드와 JSON 생성 여부 검증 |
| `scripts/trivy-to-nuclei.py` | Trivy 원본 JSON의 High/Critical CVE를 Nuclei template ID 입력 파일로 변환 |
| `scripts/run-nuclei-validation.py` | PR 제한 프로필 또는 Post-merge 광범위 프로필 실행, Trivy CVE 조건부 검사, JSONL 통합과 coverage 결과 생성 |
| `scripts/upload-sbom-to-dependency-track.py` | CycloneDX SBOM을 DT에 name/version + autoCreate로 업로드 |
| `scripts/pin-cyclonedx-specversion.py` | CycloneDX `specVersion`을 1.6으로 고정 (DT 호환) |
| `scripts/snapshot-dependency-scan-history.py` | dependency-scan latest → `history/<run_id>/` 스냅샷 |
