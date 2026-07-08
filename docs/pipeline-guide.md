---
문서명: 파이프라인 운영 가이드
최신화: 2026-06-30
작성자: 이윤재
Version: 1.0.0
---

# Pipeline Guide

## 개요

Secure PR Gate는 GitHub Actions 기반 DevSecOps 보안 게이트웨이 시스템이다.
PR 생성 시 보안 검사를 자동 실행하고, 결과를 통합하여 Merge 가능 여부를 판단한다.

---

## Workflow 구성

### 1. `pr-security-gate.yml` — PR 보안 게이트

트리거: `pull_request` → `main`, `develop`

| Job                  | 역할                             | 상태                          |
| -------------------- | -------------------------------- | ----------------------------- |
| `build-test`         | 빌드 및 테스트                   | Placeholder                   |
| `sast`               | Semgrep 정적 분석                | Placeholder (C파트 연결 예정) |
| `secret-scan`        | Gitleaks 민감정보 탐지           | Placeholder (C파트 연결 예정) |
| `dependency-scan`    | Trivy 의존성 CVE 검사            | Placeholder (C파트 연결 예정) |
| `runtime-validation` | Health Check / Smoke Test / Header / ZAP JSON | D파트 연결 완료 |
| `aggregate-and-gate` | 결과 통합 및 Gate 판단           | 구현 완료                     |
| `pr-comment`         | PR 댓글 작성                     | 구현 완료                     |

### 2. `cd-staging.yml` — Staging 배포

트리거: `push` → `main`

| Job                      | 역할               | 상태                          |
| ------------------------ | ------------------ | ----------------------------- |
| `docker-build`           | Docker 이미지 빌드 | Placeholder (4차 구현)        |
| `staging-deploy`         | Staging 환경 배포  | Placeholder (4차 구현)        |
| `post-deploy-validation` | 배포 후 Runtime Validation | D파트 연결 완료 |

---

## 결과 파일 구조

```text
security/reports/
  build-report.json         # Build/Test 결과
  sast-report.json          # SAST 결과 (C파트)
  secret-report.json        # Secret Scan 결과 (C파트)
  dependency-report.json    # Dependency Scan 결과 (C파트)
  zap-report.json           # OWASP ZAP 원본 JSON (D파트 중간 입력)
  runtime-report.json       # Runtime Validation 결과 (D파트)
  security-summary.json     # Aggregator 통합 결과
  gate-decision.json        # Gate Evaluator 판단 결과
```

---

## 결과 파일 공통 스키마

각 보안 검사 파트는 아래 형식을 준수해야 한다.

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

| 조건          | 처리         |
| ------------- | ------------ |
| Critical 탐지 | Merge 차단   |
| High 탐지     | Merge 차단   |
| Secret 탐지   | Merge 차단   |
| Medium 탐지   | PR 댓글 경고 |
| 모두 통과     | Merge 허용   |

---

## Merge 차단 메커니즘

1. `evaluate-gate.py`가 Critical/High/Secret 탐지 시 `exit 1`
2. `aggregate-and-gate` Job 실패 → GitHub Check 실패
3. Branch Protection Rule에서 해당 Check를 Required로 설정 → Merge 버튼 비활성화

> Branch Protection Rule 설정은 레포지터리 관리자가 수행해야 한다.
> Settings → Branches → Branch protection rules → Require status checks

---

## 스크립트

| 파일                           | 역할                      |
| ------------------------------ | ------------------------- |
| `scripts/aggregate-results.py` | 각 보안 결과 파일 통합    |
| `scripts/evaluate-gate.py`     | 정책 기준 Pass/Fail 판단  |
| `scripts/create-pr-comment.py` | GitHub API로 PR 댓글 작성 |
| `scripts/runtime-validation.py` | Health / Smoke / Header / ZAP 결과를 `runtime-report.json`으로 생성 |
| `scripts/runtime-validation-v3.py` | D파트 학습용 v3 코드 |
