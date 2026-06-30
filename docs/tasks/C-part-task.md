---
문서명: C파트 작업 체크리스트
최신화: 2026-06-30
담당: C. Security Scan
Version: 1.1.0
---

# C파트 작업 체크리스트

Semgrep, Gitleaks, Trivy를 이용한 보안 검사를 구성하고, 각 검사 결과를 프로젝트 공통 JSON 형식으로 변환하여 A파트 파이프라인에 연결한다.

완료 항목은 `[x]`, 진행 예정 항목은 `[ ]`로 표시한다.

---

## 1주차 — 공통 준비 및 Semgrep 기본 구성

### 공통 준비

- [x] C파트 담당 범위와 A파트 연동 규격 확인
- [x] Semgrep 로컬 설치 및 버전 확인
- [x] Secure PR Gate 저장소 대상 Semgrep 시험 실행
- [x] Semgrep 원본 JSON 생성 (`semgrep-raw.json`)
- [x] Semgrep 시험 결과 확인 (14개 파일 검사, Warning 1건)
- [ ] 작업 브랜치 생성 (`feat/c-security-scan`)
- [ ] B파트 테스트 앱의 코드 경로 및 사용 언어 확인

### SAST — Semgrep

- [ ] Semgrep 검사 대상 경로 확정
- [ ] Semgrep 실행 명령어 확정
- [ ] 사용할 Semgrep Ruleset 확정 (`--config auto` 또는 프로젝트 설정 파일)
- [ ] Semgrep 설정 파일 경로 확정
- [ ] 정상 코드 대상 통과 테스트
- [ ] 취약 샘플 대상 탐지 테스트
- [ ] 탐지 결과와 파싱 경고 내용 기록

### 1주차 완료 기준

- [ ] Semgrep 실행 명령어와 검사 대상이 확정됨
- [ ] 정상 코드와 취약 샘플의 검사 결과를 확인함
- [ ] Semgrep 원본 JSON 구조를 파악함

---

## 2주차 — Semgrep 결과 변환 및 Gitleaks 구성

### Semgrep 결과 변환

- [ ] Semgrep 원본 JSON을 공통 JSON으로 변환하는 스크립트 작성
- [ ] Semgrep Severity를 공통 등급으로 변환
- [ ] `security/reports/sast-report.json` 생성 확인
- [ ] Semgrep 파싱 경고 및 오탐 처리 기준 기록

### Secret Scan — Gitleaks

- [ ] Gitleaks 설치 및 버전 확인
- [ ] Gitleaks 검사 범위 확정 (Git 이력 또는 현재 파일)
- [ ] Gitleaks 실행 명령어 확정
- [ ] 테스트용 가짜 Secret 탐지 확인
- [ ] 정상 파일 대상 통과 테스트
- [ ] 테스트용 Secret이 실제 자격증명이 아님을 확인

### 2주차 완료 기준

- [ ] Semgrep 결과가 공통 JSON으로 자동 변환됨
- [ ] Gitleaks가 가짜 Secret을 탐지함
- [ ] Gitleaks 원본 JSON 구조를 파악함

---

## 3주차 — Gitleaks 결과 변환 및 Trivy 구성

### Gitleaks 결과 변환

- [ ] Gitleaks 원본 JSON을 공통 JSON으로 변환하는 스크립트 작성
- [ ] Secret 탐지 결과의 Severity를 `secret`으로 변환
- [ ] `security/reports/secret-report.json` 생성 확인

### Dependency Scan — Trivy

- [ ] Trivy 설치 및 버전 확인
- [ ] 프로젝트 패키지 파일 확인 (`requirements.txt`, `package-lock.json` 등)
- [ ] Trivy 검사 대상 및 실행 방식 확정
- [ ] Trivy 실행 명령어 확정
- [ ] 취약 의존성 탐지 테스트
- [ ] 정상 의존성 또는 탐지 없음 테스트
- [ ] Trivy 원본 JSON 구조 확인

### 3주차 완료 기준

- [ ] Gitleaks 결과가 공통 JSON으로 자동 변환됨
- [ ] Trivy가 프로젝트 의존성을 검사함
- [ ] Trivy 원본 JSON 구조를 파악함

---

## 4주차 — Trivy 결과 변환 및 GitHub Actions 통합

### Trivy 결과 변환

- [ ] Trivy 원본 JSON을 공통 JSON으로 변환하는 스크립트 작성
- [ ] Trivy Severity를 공통 등급으로 변환
- [ ] `security/reports/dependency-report.json` 생성 확인

### Workflow Job 교체

- [ ] `sast` Job의 Placeholder를 Semgrep 실제 명령어로 교체
- [ ] `secret-scan` Job의 Placeholder를 Gitleaks 실제 명령어로 교체
- [ ] `dependency-scan` Job의 Placeholder를 Trivy 실제 명령어로 교체
- [ ] 각 Job에서 필요한 도구 설치 단계 추가
- [ ] 각 Job에서 공통 JSON 변환 스크립트 실행
- [ ] 각 결과 파일의 Artifact 업로드 확인
- [ ] 스캐너가 finding을 탐지해도 결과 파일이 먼저 생성되도록 종료 코드 처리

### 파이프라인 연동 검증

- [ ] 정상 코드 PR에서 세 Scan Job 통과 확인
- [ ] High/Critical 탐지 PR에서 Gate 차단 확인
- [ ] Secret 탐지 PR에서 Gate 차단 확인
- [ ] Medium 탐지 PR에서 Warning 처리 확인
- [ ] 결과가 PR 댓글에 올바르게 표시되는지 확인
- [ ] 스캐너 실행 오류와 취약점 탐지를 구분하여 처리
- [ ] E파트와 도구별 Severity 매핑 기준 최종 확인
- [ ] 실행 명령어, 결과 샘플 및 테스트 결과를 A파트에 전달

### 4주차 완료 기준

- [ ] 세 도구의 결과 파일이 공통 JSON 규격으로 생성됨
- [ ] 세 Scan Job의 Placeholder가 실제 명령어로 교체됨
- [ ] 정상·경고·차단 시나리오가 PR에서 검증됨
- [ ] A파트 전달 항목과 작업 문서가 정리됨

---

## 공통 결과 파일 규격

각 결과 파일은 아래 형식을 준수한다.

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
      "location": "<file:line>"
    }
  ]
}
```

### 결과 파일 경로

| 검사 | 도구 | 결과 파일 |
| --- | --- | --- |
| SAST | Semgrep | `security/reports/sast-report.json` |
| Secret Scan | Gitleaks | `security/reports/secret-report.json` |
| Dependency Scan | Trivy | `security/reports/dependency-report.json` |

---

## 임시 Severity 매핑

> E파트의 최종 정책이 확정되기 전까지 사용하는 임시 기준이다.

| 도구 결과 | 공통 Severity | Gate 처리 |
| --- | --- | --- |
| Critical / Error | `critical` 또는 `high` | Merge 차단 |
| High | `high` | Merge 차단 |
| Warning / Medium | `medium` | PR 경고 |
| Low / Info | `low` | 기록 |
| Gitleaks 탐지 | `secret` | Merge 차단 |

---

## A파트 전달 항목

- [ ] Semgrep 실행 명령어
- [ ] Semgrep 설정 파일 경로
- [ ] Gitleaks 실행 명령어
- [ ] Gitleaks 설정 파일 경로
- [ ] Trivy 실행 명령어
- [ ] 각 도구의 결과 파일 경로
- [ ] 각 도구의 실패 기준
- [ ] Severity 매핑 기준
- [ ] 공통 JSON 결과 샘플
- [ ] 로컬 테스트 결과
- [ ] Workflow Job 등록 정보

---

## 4주 전체 완료 현황

| 항목 | 상태 |
| --- | --- |
| 1주차: Semgrep 기본 구성 및 로컬 검사 | 진행 중 |
| 2주차: Semgrep 결과 변환 및 Gitleaks 구성 | 예정 |
| 3주차: Gitleaks 결과 변환 및 Trivy 구성 | 예정 |
| 4주차: Trivy 결과 변환 및 CI 통합 검증 | 예정 |
