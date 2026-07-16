---
문서명: Runtime Validation 가이드
최신화: 2026-07-15
작성자: D파트
Version: 1.1.0
---

# Runtime Validation Guide

## 개요

D파트 Runtime Validation은 실행 중인 테스트/Staging 환경을 대상으로 런타임 보안 검증을 수행하고, A파트 공통 스키마 그대로 `security/reports/runtime-report.json`을 생성한다.

검증 범위:

- Health Check
- Smoke Test
- Security Header Check
- Custom Runtime Check
- OWASP ZAP JSON 결과 연동
- Nuclei JSONL 결과 연동

최종 제출용 실행 파일:

```text
scripts/runtime-validation.py
```

현재 저장소에는 혼선을 줄이기 위해 v1/v2/v3 학습용 파일을 남기지 않고, 최종 제출용 `runtime-validation.py`만 유지한다.

---

## A파트 전달 사항

D파트는 Workflow YAML을 직접 수정하지 않고, 아래 실행 방식과 명령어, 결과 파일 기준을 A파트에 전달한다. A파트는 이 내용을 PR Workflow의 Runtime Validation Job에 등록하고 임시 실행 환경의 시작과 종료를 담당한다.

| 전달 항목 | D파트 전달 내용 |
| --- | --- |
| Staging 실행 방식 | PR 단계에서는 GitHub Actions Runner 안에 테스트 앱을 임시 실행한다. 현재 구성은 PostgreSQL만 Docker Compose로 실행하고 FastAPI는 Runner의 Uvicorn 프로세스로 실행한다. |
| Staging URL | 고정 Staging URL이 없는 PR 단계에서는 `http://127.0.0.1:8000`을 `RUNTIME_BASE_URL`로 사용한다. 외부 Staging이 확정된 경우에만 `STAGING_URL`을 사용한다. |
| Health Check Endpoint | `GET /posts`, 기대 상태 코드 `200`. 이 앱은 전용 `/health`가 없으므로 `/posts`를 대체 경로로 사용한다. `HEAD /posts`는 `405`이므로 GET 요청으로 검사한다. |
| Smoke Test 실행 명령어 | `RUNTIME_BASE_URL=http://127.0.0.1:8000 HEALTH_CHECK_PATH=/posts HEALTH_EXPECTED_STATUS=200 SMOKE_TEST_PATHS="/login=200,/posts=200,/upload=200\|303,/docs=200,/redoc=200" python3 scripts/runtime-validation.py` |
| ZAP 실행 명령어 | 아래 `PR 임시 환경에서 ZAP 실행` 명령어를 사용한다. |
| ZAP 결과 파일 경로 | `security/reports/zap-report.json` |
| Nuclei 실행 명령어 | 아래 `PR 임시 환경에서 Nuclei 실행` 명령어를 사용한다. PR 기본값은 `medium,high,critical`, `xss`, `timeout 5m`이다. |
| Nuclei 결과 파일 경로 | `security/reports/nuclei-report.jsonl` |
| 보안 헤더 검증 기준 | HTTP: `x-content-type-options`, `x-frame-options`, `content-security-policy`. HTTPS에서는 `strict-transport-security`를 자동으로 추가한다. |
| Custom Runtime Check | `debug-exposure`, `docs-exposure`, `reflected-xss`, `search-sqli`, `admin-access`, `idor`를 기본 실행한다. |
| Runtime Validation 실패 기준 | Critical/High/Secret finding이 하나라도 있으면 `failed`, Medium/Low만 있으면 `warning`, finding이 없으면 `passed`. 실제 Merge 차단은 E파트 Policy Evaluator가 결정한다. |

추가 연동 결과는 Nuclei 원본 `security/reports/nuclei-report.jsonl`이며, ZAP과 Nuclei 결과를 파싱한 D파트 최종 결과는 `security/reports/runtime-report.json`이다.

### 역할 구분

| 파트 | 담당 범위 |
| --- | --- |
| B파트 | 실행 가능한 애플리케이션 코드, 의존성, DB 마이그레이션, Seed, 실행 방법을 제공한다. 앱까지 완전 Docker화할 경우 `Dockerfile`과 Compose의 `app` 서비스도 B파트가 제공해야 한다. |
| D파트 | Health/Smoke/Header 기준, ZAP/Nuclei 실행 명령어, 결과 파싱 코드와 결과 파일 형식을 제공한다. |
| A파트 | Checkout부터 앱 시작, 준비 상태 대기, 스캐너 실행, Artifact 업로드, 앱 종료까지 Workflow YAML에 연결한다. Repository Variables/Secrets도 A파트가 등록한다. |
| E파트 | D파트 finding의 severity를 기준으로 최종 Merge 차단 정책을 적용한다. |

현재 `web/docker-compose.yml`에는 `postgres` 서비스만 있고 FastAPI `app` 서비스와 `Dockerfile`은 없다. 따라서 현재 상태에서 `docker compose up -d`만 실행해서 웹까지 뜨는 구조는 아니다.

---

## PR 단계 임시 실행 환경

DAST는 소스 파일 자체가 아니라 실제로 실행 중인 웹에 HTTP 요청을 보내는 검사다. 따라서 고정 `STAGING_URL`이 없으면 PR마다 GitHub Actions Runner 안에 앱을 잠깐 실행하고, 검사가 끝난 뒤 종료하는 임시 환경을 사용한다. 이 환경은 팀원이 함께 접속하는 공용 Staging 서버가 아니며 해당 Workflow 실행 동안만 존재한다.

현재 저장소에서 가능한 실행 순서는 다음과 같다.

```text
코드 Checkout
-> Python 의존성 설치
-> PostgreSQL 컨테이너 시작
-> Alembic 마이그레이션과 Seed 실행
-> Uvicorn 백그라운드 실행
-> GET /posts가 200이 될 때까지 대기
-> ZAP/Nuclei/Runtime Validation 실행
-> 결과 Artifact 업로드
-> Uvicorn과 PostgreSQL 종료
```

### 1. PostgreSQL과 FastAPI 임시 실행

다음 명령은 A파트가 Workflow step으로 옮길 실행 예시다. D파트는 이 명령을 문서로 전달하고 Workflow YAML은 수정하지 않는다.

```bash
python3 -m venv web/.venv
source web/.venv/bin/activate
pip install -r web/requirements.txt

cd web
cp -n .env.example .env
docker compose up -d --wait postgres
alembic upgrade head
python -m app.seed
uvicorn app.main:app --host 0.0.0.0 --port 8000 > /tmp/secure-gate-uvicorn.log 2>&1 &
echo $! > /tmp/secure-gate-uvicorn.pid
cd ..
```

`--wait`는 `web/docker-compose.yml`에 정의된 PostgreSQL health check가 성공할 때까지 기다린다. 이 대기 없이 바로 Alembic을 실행하면 DB가 아직 준비되지 않아 연결 오류가 날 수 있다.

### 2. 준비 상태 확인

Uvicorn 명령 직후 바로 검사하면 앱이 아직 준비되지 않아 `Connection refused`가 발생할 수 있다. 다음처럼 최대 60초 동안 GET 요청을 반복한 뒤 최종 확인한다.

```bash
for attempt in {1..30}; do
  if curl --fail --silent http://127.0.0.1:8000/posts > /dev/null; then
    break
  fi
  sleep 2
done

curl --fail http://127.0.0.1:8000/posts > /dev/null
```

### 3. PR 임시 환경에서 ZAP 실행

ZAP은 별도 Docker 컨테이너에서 실행되므로 GitHub의 Linux Runner에서는 `--network host`를 사용해야 Runner의 `127.0.0.1:8000`에 접근할 수 있다.

```bash
mkdir -p security/reports

docker run --rm \
  --network host \
  -v "$GITHUB_WORKSPACE/security/reports:/zap/wrk:rw" \
  ghcr.io/zaproxy/zaproxy:stable \
  zap-baseline.py \
  -t http://127.0.0.1:8000/posts \
  -J zap-report.json || true
```

`--network host` 설명은 GitHub의 Ubuntu/Linux Runner 기준이다. macOS Docker Desktop에서 같은 방식으로 로컬 테스트할 때는 동작 방식이 다를 수 있으므로 `host.docker.internal`을 사용한다.

### 4. PR 임시 환경에서 Nuclei 실행

```bash
: > security/reports/nuclei-report.jsonl

timeout 5m docker run --rm \
  --network host \
  -v "$GITHUB_WORKSPACE/security/reports:/app/reports:rw" \
  projectdiscovery/nuclei:latest \
  -u http://127.0.0.1:8000/posts \
  -severity medium,high,critical \
  -tags xss \
  -rate-limit 10 \
  -c 5 \
  -retries 0 \
  -timeout 5 \
  -ni \
  -jsonl \
  -o /app/reports/nuclei-report.jsonl \
  -silent || true
```

### 5. Runtime Validation 실행

```bash
RUNTIME_BASE_URL=http://127.0.0.1:8000 \
HEALTH_CHECK_PATH=/posts \
HEALTH_EXPECTED_STATUS=200 \
SMOKE_TEST_PATHS="/login=200,/posts=200,/upload=200|303,/docs=200,/redoc=200" \
REQUIRED_SECURITY_HEADERS="x-content-type-options,x-frame-options,content-security-policy" \
CUSTOM_RUNTIME_CHECKS="debug-exposure,docs-exposure,reflected-xss,search-sqli,admin-access,idor" \
ZAP_REPORT_PATH=security/reports/zap-report.json \
NUCLEI_REPORT_PATH=security/reports/nuclei-report.jsonl \
python3 scripts/runtime-validation.py
```

### 6. 임시 환경 종료

검사 성공 여부와 관계없이 항상 실행되어야 하는 정리 단계다.

```bash
if [ -f /tmp/secure-gate-uvicorn.pid ]; then
  kill "$(cat /tmp/secure-gate-uvicorn.pid)" || true
fi

docker compose -f web/docker-compose.yml down -v
```

### 앱까지 완전 Docker로 실행하려면

B파트가 FastAPI 앱용 `Dockerfile`과 Compose의 `app` 서비스를 제공하면 A파트는 PR 단계에서 전체 환경을 다음처럼 단순하게 시작할 수 있다.

```bash
docker compose -f web/docker-compose.yml up -d --build
```

이 방식에서는 Compose 내부의 앱이 PostgreSQL에 접근할 때 `localhost`가 아니라 서비스 이름인 `postgres:5432`를 사용해야 한다. 현재 저장소에는 FastAPI용 `Dockerfile`과 `app` 서비스가 없으므로 위 명령만으로 웹까지 실행할 수 없다.

---

## 실행 명령어

로컬 실행 예시:

```bash
RUNTIME_BASE_URL=http://127.0.0.1:8000 \
HEALTH_CHECK_PATH=/posts \
HEALTH_EXPECTED_STATUS=200 \
SMOKE_TEST_PATHS="/login=200,/posts=200,/upload=200|303,/docs=200,/redoc=200" \
REQUIRED_SECURITY_HEADERS="x-content-type-options,x-frame-options,content-security-policy" \
CUSTOM_RUNTIME_CHECKS="debug-exposure,docs-exposure,reflected-xss,search-sqli,admin-access,idor" \
python3 scripts/runtime-validation.py
```

A파트는 아래 흐름을 `.github/workflows/pr-security-gate.yml`의 `runtime-validation` Placeholder Job에 등록해야 한다. D파트는 Workflow YAML을 직접 수정하지 않고 이 가이드의 명령어를 전달한다.

등록 대상 PR Workflow 흐름:

```text
Run ZAP Baseline
-> security/reports/zap-report.json 생성
Run Nuclei Scan
-> security/reports/nuclei-report.jsonl 생성
-> python scripts/runtime-validation.py 실행
-> security/reports/runtime-report.json 생성
-> Artifact 업로드
```

---

## 환경 변수

| 변수 | 설명 | 기본값 |
| --- | --- | --- |
| `ZAP_TARGET_URL` | ZAP Baseline 대상 URL. 앱 루트가 404이면 `/posts` 같은 진입 화면을 지정 | 없음 |
| `NUCLEI_TARGET_URL` | Nuclei 대상 URL. 미설정 시 `ZAP_TARGET_URL`, `RUNTIME_BASE_URL`, `STAGING_URL` 순서로 사용 | 없음 |
| `NUCLEI_SEVERITIES` | 실행할 Nuclei 템플릿 severity 범위. PR 단계에서도 필수 탐지 범위인 Medium 이상은 포함 | `medium,high,critical` |
| `NUCLEI_TAGS` | PR 단계에서 실행할 Nuclei 템플릿 태그 범위 | `xss` |
| `NUCLEI_RATE_LIMIT` | 초당 요청 제한. PR 단계에서 시간과 부하를 함께 조절 | `10` |
| `NUCLEI_CONCURRENCY` | 동시 실행 템플릿 수. 임시 앱 부하를 고려해 과도하게 올리지 않음 | `5` |
| `NUCLEI_RETRIES` | 실패 요청 재시도 횟수. PR 단계에서는 지연을 줄이기 위해 재시도하지 않음 | `0` |
| `NUCLEI_TIMEOUT_SECONDS` | Nuclei 요청 timeout | `5` |
| `NUCLEI_SCAN_TIMEOUT` | PR 단계 Nuclei 전체 실행 제한 시간 | `5m` |
| `RUNTIME_BASE_URL` | PR 단계 Runtime Validation 대상 URL | 없음 |
| `STAGING_URL` | `RUNTIME_BASE_URL`이 없을 때 사용할 Staging URL | 없음 |
| `HEALTH_CHECK_PATH` | Health Check 경로 | `/health` |
| `HEALTH_EXPECTED_STATUS` | Health Check 기대 HTTP Status. `200|204` 형식 가능 | `200` |
| `SMOKE_TEST_PATHS` | 쉼표 구분 Smoke Test 경로. `/login=200,/posts=200` 형식 가능 | `/` |
| `REQUIRED_SECURITY_HEADERS` | 쉼표 구분 필수 보안 헤더. `none`이면 비활성화 | `x-content-type-options,x-frame-options,content-security-policy` |
| `CUSTOM_RUNTIME_CHECKS` | 쉼표 구분 custom 검사. `none`이면 비활성화 | `debug-exposure,docs-exposure,reflected-xss,search-sqli,admin-access,idor` |
| `CUSTOM_RUNTIME_USERNAME` | 인증 기반 custom 검사에 사용할 일반 사용자 계정 | `user1` |
| `CUSTOM_RUNTIME_PASSWORD` | 인증 기반 custom 검사에 사용할 일반 사용자 비밀번호 | `password123` |
| `CUSTOM_RUNTIME_PRIVATE_POST_ID` | IDOR custom 검사 대상 private post id | `4` |
| `CUSTOM_RUNTIME_SQLI_PAYLOAD` | 검색 SQLi custom 검사에 사용할 payload | `') OR '1'='1' --` |
| `ZAP_REPORT_PATH` | OWASP ZAP JSON 리포트 경로 | `security/reports/zap-report.json` |
| `NUCLEI_REPORT_PATH` | Nuclei JSONL 리포트 경로 | `security/reports/nuclei-report.jsonl` |
| `RUNTIME_TIMEOUT_SECONDS` | HTTP 요청 timeout | `10` |

HTTPS 대상이면 `strict-transport-security`가 필수 헤더 목록에 자동 추가된다.

---

## Custom Runtime Check

기본 DAST 도구가 놓치기 쉬운 프로젝트 전용 취약점을 PR 단계에서도 일부 중복 검증하기 위해 custom runtime check를 추가한다.

| Check | 검증 내용 | 실패 시 Finding |
| --- | --- | --- |
| `debug-exposure` | `/debug/error`, `/debug/db-error`, `/debug/path-error`가 내부 오류 정보나 경로를 노출하는지 확인 | `runtime.custom.debug-exposure.*` |
| `docs-exposure` | `/docs`, `/redoc` FastAPI 문서 엔드포인트 노출 확인 | `runtime.custom.docs-exposure.*` |
| `reflected-xss` | `/posts?keyword=`에 script payload를 넣고 응답에 escape 없이 반사되는지 확인 | `runtime.custom.reflected-xss.keyword` |
| `search-sqli` | 검색 SQLi payload로 비공개 게시글이 공개 검색 응답에 섞이는지 확인 | `runtime.custom.search-sqli.private-posts` |
| `admin-access` | 일반 사용자 `user1`로 로그인한 뒤 `/admin` 접근이 가능한지 확인 | `runtime.custom.admin-access.user-role` |
| `idor` | 일반 사용자 `user1`로 로그인한 뒤 다른 사용자의 private post 접근 가능 여부 확인 | `runtime.custom.idor.private-post` |

삭제, 대용량 업로드, 계정 잠금 반복 시도처럼 상태 변경이 큰 검사는 PR 단계 기본 custom check에 포함하지 않는다. 필요하면 별도 merge 이후 또는 정기 스캔으로 분리한다.

---

## 결과 파일

출력 경로:

```text
security/reports/runtime-report.json
```

원본 및 참고 결과 파일:

```text
security/reports/zap-report.json
security/reports/nuclei-report.jsonl
```

출력 스키마는 `docs/team-interface.md`의 공통 결과 파일 스키마를 따른다. 임의의 추가 필드를 넣지 않는다.

```json
{
  "status": "passed | failed | warning",
  "tool": "runtime-validation",
  "findings": [
    {
      "id": "runtime.health.bad-status",
      "severity": "high",
      "title": "Health check returned unexpected status",
      "description": "Expected [200], got HTTP 500.",
      "location": "https://staging.example.com/health"
    }
  ]
}
```

---

## 실패 기준

| 검증 항목 | 조건 | Severity |
| --- | --- | --- |
| Target URL | `RUNTIME_BASE_URL` / `STAGING_URL` 미설정 | Medium |
| Health Check | 요청 실패 또는 기대하지 않은 Status | High |
| Smoke Test | 요청 실패 또는 기대하지 않은 Status | High |
| Security Header | 필수 헤더 누락 | Medium |
| ZAP | `riskcode=4` | Critical |
| ZAP | `riskcode=3` | High |
| ZAP | `riskcode=2` | Medium |
| ZAP | `riskcode=1` 또는 `0` | Low |
| ZAP JSON | 파싱 실패 | Medium |
| Nuclei | `severity=critical` | Critical |
| Nuclei | `severity=high` | High |
| Nuclei | `severity=medium` | Medium |
| Nuclei | `severity=low`, `info`, `unknown` | Low |
| Nuclei JSONL | 파싱 실패 | Medium |

초기 정책상 Critical/High/Secret은 Merge 차단, Medium은 PR 댓글 경고로 처리된다. 최종 차단 여부는 E파트 Policy Evaluator 기준에 따른다.

---

## OWASP ZAP 연동

ZAP Baseline은 GitHub Actions에서 Docker로 실행하고, JSON 결과를 아래 경로에 저장한다.

```text
security/reports/zap-report.json
```

Workflow 예시:

```bash
docker run --rm \
  --network host \
  -v "$GITHUB_WORKSPACE/security/reports:/zap/wrk:rw" \
  ghcr.io/zaproxy/zaproxy:stable \
  zap-baseline.py \
  -t "${ZAP_TARGET_URL:-$RUNTIME_BASE_URL}" \
  -J zap-report.json || true
```

`runtime-validation.py`는 이 JSON을 읽어 `runtime.zap.<pluginid>` finding으로 변환한다. ZAP 명령이 finding 때문에 non-zero로 끝나도 Runtime Validation Job이 먼저 종료되지 않도록 Workflow에서는 `|| true`로 처리하고, 최종 차단 판단은 Aggregator와 Policy Evaluator가 담당한다.

B파트 취약 웹 앱처럼 `/`가 404이고 `/posts`가 실제 진입 화면인 경우, `RUNTIME_BASE_URL`은 루트 URL로 두고 `ZAP_TARGET_URL`만 `/posts`까지 포함해서 지정한다.

---

## Nuclei 연동

Nuclei는 GitHub Actions에서 Docker로 실행하고, JSONL 결과를 아래 경로에 저장한다.

```text
security/reports/nuclei-report.jsonl
```

Workflow 예시:

```bash
: > security/reports/nuclei-report.jsonl

timeout "${NUCLEI_SCAN_TIMEOUT:-5m}" docker run --rm \
  -v "$GITHUB_WORKSPACE/security/reports:/app/reports:rw" \
  projectdiscovery/nuclei:latest \
  -u "${NUCLEI_TARGET_URL:-${ZAP_TARGET_URL:-$RUNTIME_BASE_URL}}" \
  -severity "${NUCLEI_SEVERITIES:-medium,high,critical}" \
  -tags "${NUCLEI_TAGS:-xss}" \
  -rate-limit "${NUCLEI_RATE_LIMIT:-10}" \
  -c "${NUCLEI_CONCURRENCY:-5}" \
  -retries "${NUCLEI_RETRIES:-0}" \
  -timeout "${NUCLEI_TIMEOUT_SECONDS:-5}" \
  -ni \
  -jsonl \
  -o /app/reports/nuclei-report.jsonl \
  -silent || true
```

`runtime-validation.py`는 이 JSONL을 한 줄씩 읽어 `runtime.nuclei.<template-id>` finding으로 변환한다. Nuclei의 `critical/high/medium/low`는 그대로 매핑하고, `info/unknown`은 팀 공통 schema에 맞춰 `low`로 기록한다. PR 단계 기본값은 필수 탐지 범위를 유지하기 위해 `medium,high,critical` severity와 `xss` 태그를 사용한다. 대신 `timeout 5m`, `-retries 0`, `-timeout 5`, `-rate-limit 10`, `-c 5`, `-ni`로 실행 시간을 제어한다. `exposure,misconfig,cves` 같은 넓은 태그 확장은 PR 게이트가 아니라 별도 정밀 점검이나 merge 이후 staging 검증에서 수행한다.

---

## B파트 취약 웹 앱 기준 예시

B파트 전달 기준:

| 항목 | 값 |
| --- | --- |
| 기본 URL | `http://127.0.0.1:8000` |
| Health Check 대체 경로 | `/posts` |
| Smoke Test 후보 | `/login`, `/posts`, `/upload`, `/docs`, `/redoc` |
| 테스트 계정 | `user1 / password123` |

실행 예시:

```bash
RUNTIME_BASE_URL=http://127.0.0.1:8000 \
HEALTH_CHECK_PATH=/posts \
HEALTH_EXPECTED_STATUS=200 \
SMOKE_TEST_PATHS="/login=200,/posts=200,/upload=200|303,/docs=200,/redoc=200" \
python scripts/runtime-validation.py
```

`/upload`이 GET 페이지가 아니라 POST 전용이면 `405`가 정상일 수 있으므로 B파트 API 문서를 기준으로 기대 status를 조정한다.

---

## 제출 시 한 줄 요약

D파트는 실행 중인 애플리케이션을 대상으로 Health Check, Smoke Test, Security Header Check, Custom Runtime Check, OWASP ZAP/Nuclei 결과 파싱을 수행하고, 공통 스키마의 `runtime-report.json`을 생성하도록 구현했다.
