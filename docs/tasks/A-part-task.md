---
문서명: A파트 작업 체크리스트
최신화: 2026-06-30
작성자: 이윤재
Version: 1.0.0
---

# A파트 작업 체크리스트

전체 구현 단계별 진행 현황을 기록한다.
완료 항목은 `[x]`, 미완료 항목은 `[ ]`로 표시한다.

---

## 1차 구현 — 파이프라인 뼈대 ✅ 완료

### GitHub Actions Workflow

- [x] `.github/workflows/pr-security-gate.yml` 생성
- [x] PR 트리거 설정 (`pull_request` → `main`, `develop`)
- [x] 기본 권한 설정 (`contents`, `pull-requests`, `checks`, `security-events`)

### Placeholder Job 구성

- [x] Build/Test Placeholder Job 생성
- [x] SAST Placeholder Job 생성 (C파트 연결 대기)
- [x] Secret Scan Placeholder Job 생성 (C파트 연결 대기)
- [x] Dependency Scan Placeholder Job 생성 (C파트 연결 대기)
- [x] Runtime Validation Placeholder Job 생성 (D파트 연결 대기)
- [x] 각 Job에서 Dummy Report 생성
- [x] 각 Job 결과를 Artifact로 업로드

### Aggregator

- [x] `scripts/aggregate-results.py` 생성
- [x] 각 보안 결과 파일 읽기
- [x] `security-summary.json` 통합 생성

### Gate Evaluator

- [x] `scripts/evaluate-gate.py` 생성
- [x] `security-summary.json` 읽기
- [x] `security-gate-policy.json` 기준 차단 여부 판단
- [x] `gate-decision.json` 생성
- [x] Critical / High / Secret 탐지 시 `exit 1`

### Security Policy

- [x] `security/policies/security-gate-policy.json` 생성
- [x] 초기 차단 기준 정의 (Critical / High / Secret → 차단, Medium → 경고)

### PR 댓글 자동화

- [x] `security/templates/pr-comment-template.md` 생성
- [x] `scripts/create-pr-comment.py` 생성
- [x] `gate-decision.json` 기반 댓글 내용 구성
- [x] GitHub API (urllib)로 PR 댓글 등록
- [x] Gate 실패 시에도 댓글 작성 (`if: always()`)

### CD Workflow 뼈대

- [x] `.github/workflows/cd-staging.yml` 생성
- [x] `main` 브랜치 push 트리거 설정
- [x] Docker Build Placeholder Job 생성
- [x] Staging Deploy Placeholder Job 생성
- [x] Post-deploy Validation Placeholder Job 생성 (D파트 연결 대기)

### 문서

- [x] `docs/pipeline-guide.md` 생성
- [x] `docs/team-interface.md` 생성
- [x] `docs/task.md` 생성 (이 파일)

---

## 2차 구현 — 실제 스캔 결과 연결

> C파트 / D파트 / E파트 결과물 확정 후 진행

### C파트 연결

- [ ] Semgrep 실제 명령어 교체 (`sast` Job)
- [ ] Gitleaks 실제 명령어 교체 (`secret-scan` Job)
- [ ] Trivy 실제 명령어 교체 (`dependency-scan` Job)
- [ ] SARIF / JSON 출력 형식 통합

### D파트 연결

- [ ] Health Check 실제 명령어 교체
- [ ] Smoke Test 실제 명령어 교체
- [ ] ZAP 결과 연결 (`runtime-validation` Job)

### E파트 연결

- [ ] CVSS / 도구별 Severity 매핑 기준 반영 (`evaluate-gate.py`)
- [ ] E파트 PR 댓글 수정 가이드 템플릿 반영 (`create-pr-comment.py`)
- [ ] `security-gate-policy.json` 세분화 업데이트

### Merge 차단 확정

- [ ] Branch Protection Rule 설정 문서화
- [ ] Required Status Check 항목 확정

---

## 3차 구현 — Runtime Validation 완전 연결

- [ ] DAST (ZAP) Staging 환경 대상 실행 연결
- [ ] 보안 헤더 검증 결과 통합
- [ ] Health Check / Smoke Test 결과 통합
- [ ] `runtime-report.json` 실제 결과 연결

---

## 4차 구현 — CD 실제 배포 연결

- [ ] Dockerfile 확정 및 Docker Build 실제 연결
- [ ] Staging 배포 방식 확정 (EC2 / Docker Compose / Cloud)
- [ ] 실제 Staging Deploy 명령어 연결
- [ ] Post-deploy DAST 재검사 연결
- [ ] Production 배포 차단 / Rollback 시나리오 정리

---

## 1차 완료 기준 검증

| 항목                                                                  | 상태                                  |
| --------------------------------------------------------------------- | ------------------------------------- |
| PR 생성 시 `pr-security-gate.yml` 자동 실행                           | ✅                                    |
| SAST / Secret / Dependency / Runtime Job 병렬 실행                    | ✅                                    |
| 각 Job이 결과 Artifact 생성                                           | ✅                                    |
| Aggregator가 결과를 통합                                              | ✅                                    |
| Gate Evaluator가 Pass/Fail 판단                                       | ✅                                    |
| PR 댓글이 자동 작성됨                                                 | ✅                                    |
| Gate 실패 시 Merge 차단 가능                                          | ✅ (Branch Protection Rule 설정 필요) |
| main 브랜치 push 시 CD Workflow 실행                                  | ✅                                    |
| Docker Build / Staging Deploy / Post-deploy Validation Hook 구조 존재 | ✅                                    |
