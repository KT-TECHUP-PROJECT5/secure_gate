---
문서명: B파트 Application Security / Red Team 작업 체크리스트
최신화: 2026-07-06
작성자: 김재헌
Version: 1.0.0
---

# B파트 작업 체크리스트

## 연동 정보

| 항목 | 내용 | 상태 |
| --- | --- | --- |
| 작업 브랜치 | `feat/b-vulnerable-app` | 준비 |
| 취약 앱 경로 | `web/` | 완료 |
| 취약 API 목록 | `web/docs/api-list.txt` | 완료 |
| 취약점 매트릭스 | `web/docs/vulnerability-matrix.md` | 완료 |
| PoC 가이드 | `docs/red-team/poc-guide.md` | 완료 |
| PoC 실행 스크립트 | `scripts/run-redteam-poc.sh` | 완료 |
| 탐지 기대치 | `security/baselines/redteam-expected-findings.json` | 완료 |
| 오탐·미탐 기준 | `docs/red-team/detection-baseline.md` | 완료 |

## 구현 범위

- [x] FastAPI + Jinja2 + SQLAlchemy 2.0 + PostgreSQL 취약 웹 통합
- [x] SQL Injection, Stored/Reflected XSS
- [x] IDOR, 관리자 접근, 타인 글 삭제 권한 우회
- [x] 확장자·MIME·크기 무제한 파일 업로드
- [x] 약한 비밀번호, 로그인 시도 제한·계정 잠금 미구현
- [x] 보안 이벤트 로그·알림 누락
- [x] 예외, DB 오류, 내부 경로 노출
- [x] `/docs`, `/redoc`, 보안 헤더 누락

## A·C·D·E 파트 전달 사항

### A 파트

- Build/Test 작업 디렉터리: `web/`
- 의존성 설치: `pip install -r web/requirements.txt`
- 앱 실행 절차: `web/README.md`
- B 파트는 `.github/workflows/pr-security-gate.yml`을 수정하지 않음

### C 파트

- SAST 주요 대상: `web/app/routers/`, `web/app/templates/`
- Dependency Scan 정상 대상: `web/requirements.txt`
- 취약 의존성 실습 대상: `web/requirements-legacy.txt`
- 탐지 기대치: `security/baselines/redteam-expected-findings.json`

### D 파트

- 기본 URL: `http://127.0.0.1:8000`
- Health Check 대체 경로: `GET /posts`
- DAST 시작 경로: `/login`, `/posts`, `/upload`, `/debug/error`
- 수동 인증 계정: `user1 / password123`

### E 파트

- 취약점 등급·Merge 차단 기준은 E 파트 정책을 최종 적용
- B 파트 JSON의 severity는 교차검증을 위한 초기 기대치

## 로컬 검증 결과

- [x] 일반 로그인 및 SQLi 인증 우회
- [x] 검색 SQLi로 비공개 글 노출
- [x] user1의 user2 비공개 글 접근
- [x] 일반 사용자의 관리자 화면 접근
- [x] 타인 게시글 삭제
- [x] Stored/Comment/Reflected XSS 페이로드 출력
- [x] `.html`, `.svg`, `.php`, `.js`, `.txt` 업로드 및 다운로드
- [x] 약한 비밀번호 가입, 10회 실패 후 로그인
- [x] 빈 활동 기록, 오류 정보, 보안 헤더 누락, API 문서 노출

## PR 전 체크

- [ ] Notion에 B 파트 작업 내용 요약 작성
- [ ] PR 본문에 Notion 링크 추가
- [ ] `web/.env`, `web/.venv`, `web/app.db`, 실제 업로드 파일 제외 확인
- [ ] `scripts/run-redteam-poc.sh` 로컬 실행 결과 첨부
- [ ] C·D 파트에 탐지 기대치 링크 전달
