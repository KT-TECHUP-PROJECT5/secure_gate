---
문서명: C파트 작업 체크리스트
최신화: 2026-07-23
담당: C. Security Scan
Version: 1.3.0
---

# C파트 작업 체크리스트

Semgrep, Gitleaks, Trivy를 이용한 보안 검사를 구성하고, 각 도구의 원본 JSON을 약속된 `security/reports/` 경로에 생성하여 A파트 중앙 Gate에 전달한다.

완료 항목은 `[x]`, 진행 예정 항목은 `[ ]`로 표시한다.

---

## 1주차 — 공통 준비 및 Semgrep 기본 구성

### 공통 준비

- [x] C파트 담당 범위와 A파트 연동 규격 확인
- [x] Semgrep 로컬 설치 및 버전 확인
- [x] Secure PR Gate 저장소 대상 Semgrep 시험 실행
- [x] Semgrep 원본 JSON 생성 (`semgrep-raw.json`)
- [x] Semgrep 시험 결과 확인 (14개 파일 검사, Warning 1건)
- [x] 작업 브랜치 생성 (`feat/C-sast`)
- [ ] B파트 테스트 앱의 코드 경로 및 사용 언어 확인

### SAST — Semgrep

- [x] Semgrep 초기 검사 대상 경로 확정 (저장소 루트 `.`)
- [x] Semgrep 실행 명령어 확정
- [x] 초기 Semgrep Ruleset 확정 (`--config auto`)
- [x] 별도 설정 파일 없이 Registry 자동 설정 사용
- [ ] 정상 코드 대상 통과 테스트
- [ ] 취약 샘플 대상 탐지 테스트
- [ ] 탐지 결과와 파싱 경고 내용 기록

### 1주차 완료 기준

- [x] Semgrep 실행 명령어와 검사 대상이 확정됨
- [ ] 정상 코드와 취약 샘플의 검사 결과를 확인함
- [x] Semgrep 원본 JSON 구조를 파악함

---

## 2주차 — Semgrep 원본 결과 연동 및 Gitleaks 구성

### Semgrep 원본 결과 연동

- [x] `sast` Job의 Placeholder를 Semgrep 실제 명령어로 교체
- [x] Semgrep 버전 고정 (`1.168.0`)
- [x] Semgrep 원본 JSON 구조 검증 (`results`, `errors`)
- [ ] `security/reports/sast-report.json` 생성 확인
- [ ] `sast-report` Artifact 업로드 확인
- [ ] Semgrep 파싱 경고 및 오탐 처리 기준 기록

### Secret Scan — Gitleaks

- [ ] Gitleaks 설치 및 버전 확인
- [ ] Gitleaks 검사 범위 확정 (Git 이력 또는 현재 파일)
- [ ] Gitleaks 실행 명령어 확정
- [ ] 테스트용 가짜 Secret 탐지 확인
- [ ] 정상 파일 대상 통과 테스트
- [ ] 테스트용 Secret이 실제 자격증명이 아님을 확인

### 2주차 완료 기준

- [ ] Semgrep 원본 JSON이 지정된 경로에 생성되고 Artifact로 전달됨
- [ ] Gitleaks가 가짜 Secret을 탐지함
- [ ] Gitleaks 원본 JSON 구조를 파악함

---

## 3주차 — Gitleaks 원본 결과 연동 및 Trivy 구성

### Gitleaks 원본 결과 연동

- [ ] Gitleaks 원본 JSON 구조 검증
- [ ] `security/reports/secret-report.json` 생성 확인
- [ ] `secret-report` Artifact 업로드 확인

### Dependency Scan — Trivy

- [x] Trivy 설치 및 버전 확인 (`0.70.0` pin + checksum)
- [x] 프로젝트 패키지 파일 확인 (`requirements.txt`, `package-lock.json` 등)
- [x] Trivy 검사 대상 및 실행 방식 확정 (Dockerfile 있으면 `image`, 없으면 `fs`)
- [x] Trivy 실행 명령어 확정 (CVE JSON + CycloneDX SBOM 분리)
- [ ] 취약 의존성 탐지 테스트
- [ ] 정상 의존성 또는 탐지 없음 테스트
- [x] Trivy 원본 JSON 구조 확인 (`SchemaVersion == 2`)
- [x] CycloneDX SBOM 생성 및 `bomFormat == "CycloneDX"` / `specVersion == "1.6"` 검증
- [x] CycloneDX specVersion 1.6 고정 스크립트 (`scripts/pin-cyclonedx-specversion.py`)
- [x] Dependency-Track UUID BOM 업로드 스크립트 (`scripts/upload-sbom-to-dependency-track.py`)

### 3주차 완료 기준

- [ ] Gitleaks 원본 JSON이 지정된 경로에 생성되고 Artifact로 전달됨
- [ ] Trivy가 프로젝트 의존성을 검사함
- [ ] Trivy 원본 JSON 구조를 파악함

---

## 4주차 — Trivy 원본 결과 연동 및 GitHub Actions 통합

### Trivy 원본 결과 연동

- [x] Trivy 원본 JSON 구조 검증
- [x] `security/reports/dependency-report.json` 생성 확인
- [x] `dependency-report` Artifact 업로드 확인
- [x] `sbom` / `dependency-track-upload-report` Artifact 추가

### Workflow Job 교체

- [x] `sast` Job의 Placeholder를 Semgrep 실제 명령어로 교체
- [x] `secret-scan` Job의 Placeholder를 Gitleaks 실제 명령어로 교체
- [x] `dependency-scan` Job의 Placeholder를 Trivy 실제 명령어로 교체
- [x] 각 Job에서 필요한 도구 설치 단계 추가
- [x] 각 Job에서 도구별 원본 JSON 생성
- [ ] 각 결과 파일의 Artifact 업로드 확인
- [x] 스캐너가 finding을 탐지해도 결과 파일이 먼저 생성되도록 종료 코드 처리

### 파이프라인 연동 검증

- [ ] 정상 코드 PR에서 세 Scan Job 통과 확인
- [ ] High/Critical 탐지 PR에서 Gate 차단 확인
- [ ] Secret 탐지 PR에서 Gate 차단 확인
- [ ] Medium 탐지 PR에서 Warning 처리 확인
- [ ] 결과가 PR 댓글에 올바르게 표시되는지 확인
- [ ] 스캐너 실행 오류와 취약점 탐지를 구분하여 처리
- [ ] 중앙 Gate의 도구별 원본 스키마 처리 여부 확인
- [ ] 실행 명령어, 결과 샘플 및 테스트 결과를 A파트에 전달

### 4주차 완료 기준

- [ ] 세 도구의 원본 JSON이 약속된 결과 경로에 생성됨
- [ ] 세 Scan Job의 Placeholder가 실제 명령어로 교체됨
- [ ] 정상·경고·차단 시나리오가 PR에서 검증됨
- [ ] A파트 전달 항목과 작업 문서가 정리됨

---

## C파트 결과 파일 계약

각 도구의 결과는 별도 변환 없이 원본 JSON 형식을 유지한다. 파일 경로와 Artifact 이름은 고정하고, 도구별 Severity 통일과 Gate 판정은 A파트 중앙 처리에서 수행한다.

### 결과 파일 및 Artifact

| 검사 | 도구 | 결과 파일 | Artifact |
| --- | --- | --- | --- |
| SAST | Semgrep | `security/reports/sast-report.json` | `sast-report` |
| Secret Scan | Gitleaks | `security/reports/secret-report.json` | `secret-report` |
| Dependency Scan | Trivy | `security/reports/dependency-report.json` | `dependency-report` |
| SBOM | Trivy (CycloneDX 1.6) | `security/reports/sbom.cdx.json` | `sbom` |
| DT upload | Dependency-Track | `security/reports/dependency-track-upload-report.json` | `dependency-track-upload-report` |
| Scan history | snapshot | `security/reports/history/<run_id>/` | `dependency-scan-history-<run_id>` |

---

## 중앙 Gate 연동 원칙

- C파트는 도구별 원본 Severity와 필드 값을 변경하지 않는다.
- C파트는 결과 파일 생성과 Artifact 전달까지 담당한다.
- A파트 중앙 Gate가 원본 스키마를 파싱하고 Severity를 통일한다.
- 도구 실행 오류와 취약점 탐지 결과를 구분할 수 있도록 원본 오류 필드를 유지한다.

---

## A파트 전달 항목

- [x] Semgrep 실행 명령어
- [x] Semgrep 설정 방식 (`--config auto`, 별도 설정 파일 없음)
- [x] Gitleaks 실행 명령어
- [ ] Gitleaks 설정 파일 경로
- [x] Trivy 실행 명령어 (fs/image + CycloneDX SBOM)
- [x] 각 도구의 결과 파일 경로
- [x] 각 도구의 실행 오류 확인 기준
- [ ] 도구별 원본 JSON 결과 샘플
- [ ] 원본 Severity 및 오류 필드 위치
- [ ] 로컬 테스트 결과
- [x] Workflow Job 등록 정보

---

## 4주 전체 완료 현황

| 항목 | 상태 |
| --- | --- |
| 1주차: Semgrep 기본 구성 및 로컬 검사 | 진행 중 |
| 2주차: Semgrep 원본 결과 연동 및 Gitleaks 구성 | 진행 중 |
| 3주차: Gitleaks 원본 결과 연동 및 Trivy 구성 | 예정 |
| 4주차: Trivy 원본 결과 연동 및 CI 통합 검증 | 예정 |
