# OWASP 실습용 게시판

## 프로젝트 소개
보안 진단 실습을 위해 FastAPI로 만든 작은 게시판입니다. 
실습 항목별로 취약한 코드와 재현 경로를 일부러 남겨 두었습니다.

## 교육 및 허가된 테스트 환경 전용 안내
로컬 또는 허가된 테스트 환경에서만 사용합니다. 실제 서비스에 배포하지 마세요.

## 기술 스택
- Backend: FastAPI
- Template: Jinja2
- ORM: SQLAlchemy 2.0
- Database: PostgreSQL
- Migration: Alembic
- Settings: Pydantic Settings
- Session: Starlette SessionMiddleware
- Local DB: Docker Compose

## 실행 방법

Docker Desktop을 먼저 실행합니다.

### 처음 실행할 때

```bash
cd 프로젝트 위치
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp -n .env.example .env
docker compose up -d postgres
alembic upgrade head
python -m app.seed
uvicorn app.main:app --reload
```

로컬 PostgreSQL은 다른 실습 환경과의 충돌을 피하기 위해 호스트 `5433` 포트를 사용합니다.
`python -m app.seed`는 사용자 데이터가 이미 있으면 건너뜁니다.

### 다음부터 실행할 때

```bash
cd 프로젝트 위치
source .venv/bin/activate
docker compose up -d postgres
alembic upgrade head
uvicorn app.main:app --reload
```

### 종료

Uvicorn은 실행 중인 터미널에서 `Ctrl+C`로 종료합니다. DB까지 중지하려면
`docker compose down`을 실행합니다.

### 자주 발생하는 오류

`[Errno 48] Address already in use`는 보통 `8000` 포트에서 Uvicorn이 이미 실행 중이라는
뜻입니다. 먼저 `http://127.0.0.1:8000/posts`를 열어 확인합니다. 다른 포트를 쓰려면:

```bash
uvicorn app.main:app --reload --port 8001
```

DB 상태는 `docker compose ps`로 확인합니다. `web-postgres-1`이 `healthy`이고
포트가 `5433->5432`로 나오면 정상입니다.

서버가 뜨면 `http://127.0.0.1:8000/posts`에서 시작하면 됩니다.
자동 생성된 API 문서는 `/docs`, `/redoc`에 남겨 두었습니다.

주요 URL:
- http://127.0.0.1:8000/register
- http://127.0.0.1:8000/login
- http://127.0.0.1:8000/posts
- http://127.0.0.1:8000/upload
- http://127.0.0.1:8000/admin/security-events
- http://127.0.0.1:8000/debug/error
- http://127.0.0.1:8000/docs
- http://127.0.0.1:8000/redoc

## 초기 계정 정보
- admin / admin123 / 관리자 / admin
- user1 / password123 / 사용자1 / user
- user2 / password123 / 사용자2 / user

## 디렉터리 구조
```text
web/
├── app/
│   ├── core/          # 환경설정, DB 세션
│   ├── models/        # SQLAlchemy 모델
│   ├── schemas/       # Pydantic 스키마
│   ├── routers/       # 화면·기능별 라우터
│   ├── templates/
│   ├── static/
│   └── uploads/       # 업로드 파일(정적 서빙 안 함)
├── alembic/
├── docs/
├── tests/
├── docker-compose.yml
├── requirements.txt
├── requirements-legacy.txt
└── README.md
```

## 작업 기록

### 1일차
- FastAPI 프로젝트 기본 구조 생성
- PostgreSQL DB 연결
- 회원가입 기능 구현
- 로그인 / 로그아웃 기능 구현
- 게시글 목록 조회
- 게시글 작성
- 게시글 상세 조회
- 로그인 SQL Injection 취약점 재현
- 게시글 Stored XSS 취약점 재현

### 2일차
- docs/ 문서 구조 추가
- 댓글 기능 추가
- 게시글 검색 기능 추가
- 비공개 게시글 조회 기능 추가
- 관리자 페이지 추가
- A01 Broken Access Control 취약점 추가
- A05 Injection 취약점 확장
- A02 Security Misconfiguration 일부 반영

### 3일차
- SQLAlchemy 2.0 모델과 세션 구성
- PostgreSQL 로컬 환경 추가
- Alembic 초기 마이그레이션 작성
- `core`, `models`, `schemas`, `routers` 단위로 구조 정리

### 4일차 - Application Security (Red Team)
- 파일 업로드·다운로드 및 `uploads` 모델 추가
- 확장자·MIME Type·파일 크기 검증 누락 시나리오 추가
- 약한 비밀번호, 로그인 제한·계정 잠금·세션 만료 미설정 반영
- 빈 보안 이벤트 화면 추가
- 예외·DB 오류·내부 경로 노출 디버그 경로 추가

## OWASP Top 10:2025 매핑
A01:2025 Broken Access Control
- 비공개 게시글 IDOR
- 관리자 페이지 접근제어 미흡
- 게시글 삭제 권한 우회

A02:2025 Security Misconfiguration
- FastAPI /docs, /redoc 노출 유지
- 보안 헤더 미설정 상태 유지
- 파일 확장자 제한 없음
- MIME Type 검증 없음
- 파일 크기 제한 없음

A03:2025 Software Supply Chain Failures
- requirements-legacy.txt를 이용한 예전 의존성 점검

A05:2025 Injection
- 로그인 SQL Injection
- 검색 SQL Injection
- 게시글 Stored XSS
- 댓글 Stored XSS
- 검색어 Reflected XSS

A07:2025 Authentication Failures
- 약한 비밀번호 허용
- 로그인 실패 횟수 제한 없음
- 계정 잠금 없음
- 세션 만료 미설정

A09:2025 Security Logging & Alerting Failures
- 공격 시도 로그 미기록
- 관리자 접근 실패 로그 미기록
- 알림 없음

A10:2025 Mishandling of Exceptional Conditions
- 예외 메시지 노출
- DB 에러 메시지 노출
- 내부 경로 노출

## PoC 시나리오
### 로그인 SQL Injection
- username: ' OR '1'='1' --
- password: 아무 값

### 검색 SQL Injection
- /posts?keyword=') OR '1'='1' --

### 검색어 Reflected XSS
- /posts?keyword=<script>alert('reflected-xss')</script>

### 게시글 Stored XSS
- 게시글 내용: <script>alert('stored-xss')</script>

### 댓글 Stored XSS
- 댓글 내용: <script>alert('comment-xss')</script>

### 비공개 게시글 IDOR
- user1 로그인 후 /posts/private/2 접근

### 관리자 페이지 접근제어 미흡
- user1 로그인 후 /admin 접근

### 파일 업로드 / 다운로드
1. 로그인 후 `/upload`에 접근합니다.
2. `test.html`, `test.svg`, `test.php`, `test.js`, `test.txt`를 각각 업로드합니다.
3. 확장자·MIME Type·크기 제한 없이 모두 저장되는지 확인합니다.
4. 목록의 파일명을 눌러 `/download/{upload_id}` 다운로드를 확인합니다.

업로드 파일은 `app/uploads/`에 UUID 기반 이름으로 저장됩니다. 이 디렉터리는
정적 파일로 노출하지 않습니다.

### A07 Authentication Failures
- `weakuser / 1234 / 약한비밀번호사용자`로 회원가입이 성공하는지 확인합니다.
- user1의 잘못된 비밀번호로 10회 이상 로그인해도 지연, CAPTCHA, IP 차단,
  계정 잠금이 없는지 확인합니다.
- 로그인 후 브라우저를 유지해 명확한 idle/absolute timeout이 없는 상태를 확인합니다.

### A09 Security Logging & Alerting Failures
1. SQL Injection 로그인, XSS 게시글, user1의 `/admin` 접근, `test.php` 업로드를 실행합니다.
2. `/admin/security-events`에 접근합니다.
3. 공격 이후에도 “현재 기록된 보안 이벤트가 없습니다.”가 표시되는지 확인합니다.

### A10 Mishandling of Exceptional Conditions
- `/debug/error`: 일반 예외 메시지 노출
- `/debug/db-error`: SQL과 DB 오류 메시지 노출
- `/debug/path-error`: 내부 모듈·파일 경로 노출

## 의존성 파일
- `requirements.txt`: 실제 앱 실행용
- `requirements-legacy.txt`: 구버전 의존성을 대상으로 한 A03 스캔 실습용

```bash
pip-audit -r requirements-legacy.txt
# 또는
trivy fs .
```

## 참고 레포 반영 방식
본 프로젝트는 KT TechUp-Team304/broken_regist_backend의 문서화 방식과 취약점
시나리오 구성을 참고했습니다. PostgreSQL은 동일하게 사용하고, NestJS의 모듈과
TypeORM 엔티티는 FastAPI 라우터와 SQLAlchemy 모델로 대응시켰습니다.


