---
문서명: Runtime Validation 가이드
최신화: 2026-07-24
작성자: D파트
Version: 1.9.0
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
- Trivy High/Critical CVE 기반 Nuclei 우선 검사
- Dynatrace Problems API v2와 서비스 엔티티 탐지 결과 연동

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
| Staging URL | 공용 Staging은 `http://www.securegate.n-e.kr`이다. 외부 검증에서는 `STAGING_URL=http://www.securegate.n-e.kr`을 사용한다. PR 임시 환경에서는 기존대로 `RUNTIME_BASE_URL=http://127.0.0.1:8000`을 사용한다. |
| Health Check Endpoint | `GET /posts`, 기대 상태 코드 `200`. 이 앱은 전용 `/health`가 없으므로 `/posts`를 대체 경로로 사용한다. `HEAD /posts`는 `405`이므로 GET 요청으로 검사한다. |
| Smoke Test 실행 명령어 | `RUNTIME_BASE_URL=http://127.0.0.1:8000 HEALTH_CHECK_PATH=/posts HEALTH_EXPECTED_STATUS=200 SMOKE_TEST_PATHS="/login=200,/posts=200,/upload=200\|303,/docs=200,/redoc=200" python3 scripts/runtime-validation.py` |
| PR ZAP 실행 명령어 | `python3 scripts/run-zap-validation.py --profile pr --target-url http://127.0.0.1:8000/posts` |
| Merge 이후 ZAP 실행 명령어 | `python3 scripts/run-zap-validation.py --profile post-merge --target-url "${STAGING_URL}/posts"` |
| ZAP 결과 파일 경로 | `security/reports/zap-report.json` |
| PR Nuclei 실행 명령어 | `python3 scripts/run-nuclei-validation.py --profile pr --target-url http://127.0.0.1:8000/posts --trivy-report security/reports/dependency-report.json`. PR 기본값은 `medium,high,critical`, `xss`, 전체 timeout 5분이다. |
| Merge 이후 Nuclei 실행 명령어 | `python3 scripts/run-nuclei-validation.py --profile post-merge --target-url "${STAGING_URL}/posts" --reports-dir security/reports`. 태그 제한 없이 `low,medium,high,critical`, 전체 timeout 30분이다. |
| Nuclei 결과 파일 경로 | 통합 finding은 `security/reports/nuclei-report.jsonl`, CVE 검사 수행 상태는 `security/reports/nuclei-cve-coverage.json` |
| Trivy CVE 연동 | C파트 `dependency-scan` Job이 생성한 원본 `security/reports/dependency-report.json` Artifact를 A파트가 다운로드한다. `run-nuclei-validation.py`가 High/Critical CVE 추출, 템플릿 사전 확인, 조건부 검사와 결과 통합을 수행한다. |
| Dynatrace 실행 방식 | ECS Service는 OneAgent Code Module이 포함된 `secure-gate-dast:4`를 실행 중이다. Python Agent가 Uvicorn 프로세스에 로드되고 Dynatrace endpoint에 연결된 것까지 확인했다. `fetch-dynatrace-problems.py`가 Problems와 최근 `SERVICE` 엔티티를 함께 조회한다. |
| Dynatrace 설정값 | Environment URL은 `https://xlj20734.live.dynatrace.com`, Problem selector는 `status("open")`, Service selector는 `type("SERVICE")`이다. ECS 설치용 PaaS Token과 조회용 `problems.read` + `entities.read` 토큰은 분리한다. APM 엔티티의 `environment:staging` 태그 적용을 확인하기 전에는 Problem selector에 해당 태그 조건을 넣지 않는다. |
| Dynatrace 결과 파일 경로 | `security/reports/dynatrace-problems.json`에 `problems`와 `serviceCoverage`가 함께 저장되고, 공통 스키마 통합 결과는 `security/reports/runtime-report.json`이다. |
| 보안 헤더 검증 기준 | HTTP: `x-content-type-options`, `x-frame-options`, `content-security-policy`. HTTPS에서는 `strict-transport-security`를 자동으로 추가한다. |
| Custom Runtime Check | `debug-exposure`, `docs-exposure`, `reflected-xss`, `search-sqli`, `admin-access`, `idor`를 기본 실행한다. |
| Runtime Validation 실패 기준 | Critical/High/Secret finding이 하나라도 있으면 `failed`, Medium/Low만 있으면 `warning`, finding이 없으면 `passed`. PR의 Merge 차단과 배포 후 승격 차단은 E파트 Policy Evaluator가 결정한다. |

ZAP, Nuclei, Dynatrace 원본 결과는 각각 중간 입력으로 보존한다. 이를 공통 finding으로 변환한 D파트 최종 결과는 `security/reports/runtime-report.json`이다.

현재 공용 Staging 기준값:

```text
STAGING_URL=http://www.securegate.n-e.kr
ZAP_TARGET_URL=http://www.securegate.n-e.kr/posts
NUCLEI_TARGET_URL=http://www.securegate.n-e.kr/posts
DYNATRACE_ENV_URL=https://xlj20734.live.dynatrace.com
DYNATRACE_PROBLEM_SELECTOR=status("open")
DYNATRACE_SERVICE_ENTITY_SELECTOR=type("SERVICE")
HEALTH_CHECK_PATH=/posts
SMOKE_TEST_PATHS=/login=200,/posts=200,/upload=200|303,/docs=200,/redoc=200
```

`http://www.securegate.n-e.kr/login`은 Staging의 로그인 페이지다. Runtime Validation의 Base URL에는 `/login`을 붙이지 않고, `/login`은 Smoke Test 경로로 분리한다. 루트 경로 `/`는 `404`이므로 Health Check와 스캐너의 시작 경로로 사용하지 않는다. 2026-07-23 기준 `GET /posts`의 HTTP `200` 응답과 ALB Target Group의 `healthy` 상태를 확인했다.

현재 Staging 배포 정보:

| 항목 | 값 |
| --- | --- |
| 실행 환경 | AWS ECS Fargate |
| ECS Cluster | `secure-gate-dast` |
| ECS Service | `secure-gate-dast` |
| Launch Type | `FARGATE` |
| 현재 실행 Task Definition | `secure-gate-dast:4`, 2026-07-23 17:49:26 KST 배포 완료 |
| OneAgent 적용 방식 | `initoneagent`가 Code Module을 공유 볼륨에 복사하고 `web`이 로드 |
| Container | `web`, port `8000`, process `uvicorn` |
| ALB Health Check | `GET /posts`, matcher `200-399` |
| 현재 ALB Target | revision 4의 새 target, 상태 `healthy` |
| 외부 Health Check | `GET /posts` -> `200`, 확인 시 응답 시간 `0.027061s` |
| 배포 Repository | `https://github.com/KT-TECHUP-PROJECT5/web` |
| 배포 Git 기준 | `main` / `1574f7c845e1736dccc3b32120cb02e97c863bad` |

ALB Target IP는 Fargate Task가 교체되면 변경될 수 있는 내부 주소다. Runtime Validation과 Synthetic Monitor는 Target IP가 아니라 고정 ALB 도메인 `http://www.securegate.n-e.kr`을 사용한다.

### 역할 구분

| 파트 | 담당 범위 |
| --- | --- |
| B파트 | 실행 가능한 애플리케이션 코드, 의존성, DB 마이그레이션, Seed, 실행 방법을 제공한다. 앱까지 완전 Docker화할 경우 `Dockerfile`과 Compose의 `app` 서비스도 B파트가 제공해야 한다. |
| D파트 | Health/Smoke/Header 기준, ZAP/Nuclei/Dynatrace 실행 명령어, 결과 파싱 코드와 결과 파일 형식을 제공한다. |
| A파트 | Checkout부터 앱 시작, 준비 상태 대기, 스캐너와 Dynatrace 수집 실행, Artifact 업로드, 앱 종료까지 Workflow YAML에 연결한다. Repository Variables/Secrets도 A파트가 등록한다. |
| E파트 | D파트 finding의 severity를 기준으로 최종 Merge 차단 정책을 적용한다. |

현재 `web/docker-compose.yml`에는 `postgres` 서비스만 있고 FastAPI `app` 서비스와 `Dockerfile`은 없다. 따라서 현재 상태에서 `docker compose up -d`만 실행해서 웹까지 뜨는 구조는 아니다.

---

## 고정 Staging Dynatrace 연동

Dynatrace 연동은 세 부분으로 나뉜다.

```text
ECS Fargate Task
-> ALB를 통해 고정 Staging URL 제공
-> OneAgent Code Module을 포함한 revision 4 실행
-> initoneagent 완료 후 web 컨테이너 기동

Dynatrace Synthetic HTTP Monitor
-> 외부에서 GET http://www.securegate.n-e.kr/posts 실행
-> HTTP 200 여부와 응답 시간을 지속 확인

Problems API 수집 스크립트
-> 열린 Dynatrace 문제를 dynatrace-problems.json으로 저장
-> runtime-validation.py가 공통 finding으로 변환
```

revision 4 배포, Python Agent 주입과 외부 Synthetic HTTP Monitor는 정상이다. 2026-07-24 Python 전역 모니터링과 `Python FastAPI [Opt-In]` 계측을 활성화한 뒤 ECS Service를 강제 재배포했고, Dynatrace `Services`에서 `OWASP practice board DAST` 서비스와 `/posts` HTTP 200 트레이스를 확인했다. Problems API는 열린 문제를 결과 파일로 수집하는 별도 연동이며, 서비스 목록 표시 여부와 동일한 검증이 아니다.

### 1. ECS Fargate OneAgent 현재 상태

현재 Staging은 EC2 인스턴스에 직접 접속해 프로세스를 실행하는 구조가 아니다. Fargate에서는 호스트 설치 파일을 실행하지 않고 `initoneagent` 컨테이너가 공유 볼륨에 Python OneAgent Code Module을 복사한 뒤 `web` 컨테이너가 `LD_PRELOAD`로 로드하는 application-only 방식을 사용한다. 따라서 EC2용 `systemctl status oneagent`나 `oneagentctl` 명령은 적용하지 않는다.

2026-07-24 재배포 및 검증 상태:

| 항목 | 상태 |
| --- | --- |
| AWS Secrets Manager | `secure-gate/dynatrace/fargate` 생성 완료 |
| ECS Task Execution Role | Secret 읽기 권한 추가 완료 |
| OneAgent Task Definition | `secure-gate-dast:4` 등록 및 Service 배포 완료 |
| 현재 ECS Service | `secure-gate-dast:4`, steady state |
| Dynatrace 설치용 PaaS Token | Secret 등록 및 배포 사용 완료 |
| Connection Info | `tenantUUID`, `tenantToken`, `communicationEndpoints`와 Secret 매핑 일치 확인 |
| Secret 필수 Key | `DT_PAAS_TOKEN`, `DT_TENANT`, `DT_TENANTTOKEN`, `DT_CONNECTION_POINT` |
| Code Module | `1.341.56.20260720-124252-python`, `linux-x86-64` |
| `initoneagent` | `STOPPED`, exit code `0`, Python Code Module copy 성공 |
| `web` | `RUNNING`, `python:3.12-slim`, `linux/amd64` |
| Agent 주입 | `/proc/<uvicorn PID>/maps`에서 `liboneagentproc.so` 로드 확인 |
| Agent 통신 | CloudWatch에서 Python Agent 로드 및 communication endpoint 연결 성공 확인 |
| Python 모니터링 | Environment의 `Monitor Python` 활성화 |
| FastAPI 계측 | `Python FastAPI [Opt-In]`, `Instrumentation enabled` 활성화 |
| 진단 로그 | `DT_LOGSTREAM=stdout`, `DT_LOGLEVELCON=INFO` |
| ALB Target | revision 4의 새 target, `healthy` |
| Health Check | `GET /posts` -> `200`, 재배포 확인 응답 시간 `0.023734s` |
| CloudWatch | ERROR 수준 로드 실패 `0`, PaaS Token 접두 문자열 노출 `0` |
| Dynatrace `Services` | `OWASP practice board DAST` 서비스 1개 탐지 |
| 분산 추적 | `/posts` HTTP `200`, 응답 시간 약 `4~7ms` 트레이스 수집 확인 |

실제 토큰, Tenant Token, Connection Point, 전체 Secret ARN은 문서나 Git 저장소에 기록하지 않는다.

배포 완료 흐름과 남은 검증:

```text
Secret 세 필수 Key 등록 완료
-> ECS Service를 secure-gate-dast:4로 배포 완료
-> initoneagent exit code 0 확인 완료
-> web RUNNING, ALB Target healthy, GET /posts 200 확인 완료
-> Uvicorn 프로세스의 liboneagentproc.so 로드 확인 완료
-> Dynatrace communication endpoint 연결 확인 완료
-> Python 전역 모니터링과 FastAPI 계측 활성화
-> ECS Service force new deployment 완료
-> 정상 요청 트래픽 발생
-> Dynatrace Services에서 OWASP practice board DAST 서비스 확인 완료
-> Distributed Tracing에서 /posts HTTP 200 트레이스 확인 완료
```

Task Definition, IAM, Secrets Manager와 ECS Service 변경은 B파트 또는 배포/인프라 담당 범위다. D파트는 Dynatrace 설치값과 Staging 검증 기준을 전달하고, 배포 후 서비스 데이터 유입, Synthetic Monitor, Problems API 수집과 Runtime finding 변환을 확인한다.

2026-07-24 revision 4 강제 재배포 후 `web` 컨테이너의 Secret 매핑, 아키텍처, OneAgent 공유 볼륨, Uvicorn 프로세스 주입과 Dynatrace endpoint 통신을 확인했다. Python 전역 모니터링과 FastAPI 계측을 활성화한 뒤 `OWASP practice board DAST` 서비스와 `/posts` 트레이스가 생성된 것도 확인했다. 이후 자동 검증에서는 Dynatrace `Services` UI 대신 `fetch-dynatrace-problems.py`의 `serviceCoverage`를 사용한다.

ECS OneAgent용 Secret과 GitHub Actions용 Secret은 목적이 다르다.

| Secret | 목적 |
| --- | --- |
| AWS Secrets Manager `secure-gate/dynatrace/fargate` | Fargate OneAgent Code Module 설치와 Dynatrace 통신 |
| GitHub Secret `DYNATRACE_TOKEN` | `fetch-dynatrace-problems.py`의 Problems와 Service entities 조회 |

PaaS Token은 `InstallerDownload` 범위가 필요하고, `DYNATRACE_TOKEN`은 `problems.read`와 `entities.read`를 사용한다. 두 토큰을 서로 대체하거나 코드에 저장하지 않는다.

### 2. Synthetic HTTP Monitor 생성

2026-07-23 Dynatrace UI의 `Synthetic` 앱에서 아래 HTTP Monitor를 생성했다.

| 설정 | 값 |
| --- | --- |
| 이름 | `secure-gate-staging-health` |
| Monitor ID | `HTTP_CHECK-D9507A08C7F0DC5E` |
| 요청 방식 | `GET` |
| URL | `http://www.securegate.n-e.kr/posts` |
| 실패 조건 | HTTP Status `!= 200` |
| 실행 주기 | `5 minutes` |
| 실행 위치 | `Busan (Azure)`, Public |
| 태그 | `environment:staging`, `service:secure-gate` |

HTTP Monitor 생성은 현재 API가 아니라 UI에서 수행한다. Monitor가 실패해 Dynatrace Problem이 생성돼야 Problems API 결과와 Runtime Validation에 장애가 나타난다.

2026-07-23 실행 확인 결과는 `Last status: Success`, Availability `100%`, HTTP `200`이며 확인 시점 응답 시간은 `153 ms`였다.

### 3. Problems/Entities API 토큰

새 API 토큰은 읽기 전용 `problems.read`, `entities.read` 권한만 부여한다. 토큰을 파일, 명령줄 인자, Git 저장소에 넣지 않는다. 이전에 채팅이나 터미널 출력으로 노출한 토큰은 폐기하고 새 토큰으로 교체한다.

로컬 macOS zsh에서 토큰을 화면에 표시하지 않고 입력하는 예:

```zsh
export DYNATRACE_ENV_URL=https://xlj20734.live.dynatrace.com
export DYNATRACE_PROBLEM_SELECTOR='status("open")'
export DYNATRACE_SERVICE_ENTITY_SELECTOR='type("SERVICE")'
read -s "DYNATRACE_API_TOKEN?Dynatrace API token: "
echo
export DYNATRACE_API_TOKEN
```

### 4. Dynatrace 문제 결과 수집

저장소 루트에서 실행한다.

```bash
python3 scripts/fetch-dynatrace-problems.py
```

생성 파일:

```text
security/reports/dynatrace-problems.json
```

이 파일과 ZAP/Nuclei 원본 결과를 함께 사용해 고정 Staging Runtime Validation을 실행한다.

```bash
STAGING_URL=http://www.securegate.n-e.kr \
HEALTH_CHECK_PATH=/posts \
HEALTH_EXPECTED_STATUS=200 \
SMOKE_TEST_PATHS="/login=200,/posts=200,/upload=200|303,/docs=200,/redoc=200" \
ZAP_REPORT_PATH=security/reports/zap-report.json \
NUCLEI_REPORT_PATH=security/reports/nuclei-report.jsonl \
DYNATRACE_PROBLEMS_PATH=security/reports/dynatrace-problems.json \
python3 scripts/runtime-validation.py
```

결과를 확인한 뒤 현재 셸에서 토큰을 제거한다.

```bash
python3 -m json.tool security/reports/dynatrace-problems.json
python3 -m json.tool security/reports/runtime-report.json
unset DYNATRACE_API_TOKEN
```

`problems: []`는 수집 실패가 아니라 조회 시간 범위 안에 selector와 일치하는 열린 문제가 없다는 뜻이다. `serviceCoverage.status`가 `detected`이면 같은 범위에서 서비스 엔티티가 확인된 것이고, `not_detected`이면 OneAgent 통신 성공 여부와 별개로 APM 서비스가 생성되지 않은 상태다. 기본 조회 범위는 최근 30분이며 `DYNATRACE_FROM=now-2h`처럼 변경할 수 있다.

### 5. GitHub Actions 전달값

D파트는 Workflow YAML을 수정하지 않고 A파트에 다음 값과 실행 순서를 전달한다.

| GitHub 설정 | 값 |
| --- | --- |
| Repository Variable `DYNATRACE_ENV_URL` | `https://xlj20734.live.dynatrace.com` |
| Repository Variable `DYNATRACE_PROBLEM_SELECTOR` | `status("open")` |
| Repository Variable `DYNATRACE_SERVICE_ENTITY_SELECTOR` | `type("SERVICE")` |
| Repository Secret `DYNATRACE_TOKEN` | `problems.read`, `entities.read` 읽기 전용 토큰 |

현재 reusable workflow의 Secret 이름은 `DYNATRACE_TOKEN`이고 Python 스크립트가 읽는 환경변수 이름은 `DYNATRACE_API_TOKEN`이다. A파트는 수집 step에서 Secret을 다음처럼 환경변수로 매핑해야 한다.

```text
DYNATRACE_API_TOKEN <- secrets.DYNATRACE_TOKEN
```

Staging 배포 후 자동화 순서:

```text
main Merge
-> OneAgent 적용 후에는 현재 검증된 ECS Service secure-gate-dast:4를 배포
-> ALB Target healthy 확인
-> GET /posts Health Check
-> ZAP Full Scan 실행
-> Nuclei 광범위 스캔 실행
-> fetch-dynatrace-problems.py로 Problems와 Service entities 수집
-> runtime-validation.py 실행
-> runtime-report.json과 원본 결과 Artifact 업로드
```

## Merge 이후 Staging Full Scan

PR 검사는 개발 피드백 속도를 위해 ZAP Baseline과 제한된 Nuclei 템플릿을 사용한다. `main` Merge 이후에는 실제 Merge 결과가 ECS Fargate Staging에 배포된 다음 아래 검사를 수행한다.

```text
main Merge
-> ECS Staging 배포
-> ALB Target healthy 및 GET /posts 200 확인
-> ZAP Full Scan
-> Nuclei 광범위 스캔
-> Dynatrace Problems와 Service entities 수집
-> Runtime Validation 통합
-> Artifact 업로드
-> Policy Evaluator 결과에 따라 다음 환경 승격 차단 또는 배포 실패 처리
```

Merge가 이미 끝난 뒤 실행되는 검사이므로 이 단계의 실패는 이전 Merge를 취소하는 의미가 아니다. Post-deploy Job을 실패 처리하고 Production 승격을 막거나, 팀 배포 정책에 따라 ECS rollback을 수행하는 기준으로 사용한다.

두 스캐너는 동시에 실행하지 않는다. ZAP Active Scan과 Nuclei가 같은 Staging에 동시에 많은 요청을 보내면 앱 부하가 커지고 어떤 도구가 장애를 유발했는지 구분하기 어려우므로 ZAP 완료 후 Nuclei를 실행한다. 대상은 승인된 Staging ALB 도메인으로 한정하고 Production URL에는 실행하지 않는다.

### 1. ZAP Full Scan

ZAP `zap-full-scan.py`는 Spider로 경로를 수집하고 Passive Scan에 이어 실제 공격 요청을 보내는 Active Scan을 수행한다. 전체 실행 시간은 Python 실행기 내부 timeout 30분으로 제한하고, Spider 탐색 시간은 `-m 5`, ZAP 시작과 Passive Scan 대기 시간은 `-T 10`으로 제한한다. `-j`는 Ajax Spider를 추가한다.

```bash
python3 scripts/run-zap-validation.py \
  --profile post-merge \
  --target-url "${ZAP_TARGET_URL:-${STAGING_URL}/posts}" \
  --reports-dir security/reports
```

`post-merge` 프로필은 내부에서 `zap-full-scan.py`, Spider 5분, Passive Scan 대기 10분, Ajax Spider, 전체 timeout 30분을 적용한다. ZAP의 `0`은 경고와 실패가 없는 실행, `1`은 FAIL finding, `2`는 WARN finding이므로 세 코드는 정상적으로 `zap-report.json`을 Runtime Validation에 전달한다. ZAP 자체 오류 `3`, Docker 오류, timeout, 결과 누락, JSON 오류는 실행기 종료 코드 `2`로 Post-deploy Job을 실패시킨다.

결과 파일:

```text
security/reports/zap-report.json
```

### 2. Nuclei 광범위 스캔

Nuclei에는 ZAP의 `zap-full-scan.py`와 같은 단일 Full Scan 모드가 없다. Merge 이후 검사는 `-tags` 제한을 제거하고 설치된 기본 서명 템플릿 전체에서 `low,medium,high,critical`을 실행하는 것을 프로젝트의 광범위 검사 기준으로 정의한다.

```bash
python3 scripts/run-nuclei-validation.py \
  --profile post-merge \
  --target-url "${NUCLEI_TARGET_URL:-${STAGING_URL}/posts}" \
  --trivy-report "${TRIVY_REPORT_PATH:-security/reports/dependency-report.json}" \
  --reports-dir security/reports
```

`post-merge` 프로필은 태그 제한 없음, `low,medium,high,critical`, `rate-limit=20`, `concurrency=10`, `bulk-size=10`, 재시도 1회, 요청 timeout 10초, 전체 timeout 30분을 적용한다. Interactsh도 기본 활성화하므로 외부 OAST를 허용하지 않는 팀 정책이면 `--disable-interactsh`를 추가하고 탐지 범위 감소를 기록한다.

Trivy 리포트가 있으면 High/Critical CVE 템플릿 우선 검사도 이어서 수행한다. Post-merge 광범위 검사는 Trivy 리포트가 없어도 실행되며, 이 경우 `nuclei-cve-coverage.json`에 `skipped: trivy-report-not-found`가 기록된다. PR 프로필은 C파트 Artifact 연동 누락을 숨기지 않기 위해 기본적으로 Trivy 리포트를 필수로 요구한다.

Headless와 Fuzzing 템플릿은 기본 실행 범위와 부하 특성이 다르므로 이 Merge 이후 기본 명령에는 자동으로 포함하지 않는다. 필요하면 `-headless`, `-fuzz`를 사용하는 별도 야간/수동 정밀 검사로 분리하고, 상태 변경 가능성과 실행 시간을 먼저 검토한다.

결과 파일:

```text
security/reports/nuclei-report.jsonl
```

Nuclei는 finding이 없어도 정상 종료할 수 있고 JSONL 파일이 비어 있을 수 있다. 따라서 파일이 비었다는 이유만으로 스캐너 실패로 판단하지 않고 명령 exit code와 실행 로그를 함께 확인한다.

### 3. 통합과 배포 후 판정

스캐너 실행 뒤 Dynatrace 문제를 수집하고 동일한 원본 파일 경로로 Runtime Validation을 실행한다.

```bash
python3 scripts/fetch-dynatrace-problems.py

STAGING_URL=http://www.securegate.n-e.kr \
HEALTH_CHECK_PATH=/posts \
HEALTH_EXPECTED_STATUS=200 \
SMOKE_TEST_PATHS="/login=200,/posts=200,/upload=200|303,/docs=200,/redoc=200" \
ZAP_REPORT_PATH=security/reports/zap-report.json \
NUCLEI_REPORT_PATH=security/reports/nuclei-report.jsonl \
NUCLEI_COVERAGE_PATH=security/reports/nuclei-cve-coverage.json \
DYNATRACE_PROBLEMS_PATH=security/reports/dynatrace-problems.json \
RUNTIME_REQUIRED_REPORTS="zap,nuclei,nuclei-coverage,dynatrace" \
python3 scripts/runtime-validation.py --fail-on-failed
```

Active Scan 뒤에도 `GET /posts`가 `200`인지 다시 확인해 스캔으로 애플리케이션이 비정상 상태가 되지 않았는지 검증한다. ZAP/Nuclei 원본과 `runtime-report.json`은 모두 Artifact로 보존한다.

`RUNTIME_REQUIRED_REPORTS`는 Post-merge 전용 안전장치다. 파일이 없으면 "취약점 없음"으로 처리하지 않고 High finding을 생성한다. `nuclei-cve-coverage.json`의 상태가 `failed`여도 `runtime.nuclei.execution-failed` High finding으로 변환한다. PR 단계의 기존 호환성을 위해 기본값은 `none`이다.

현재 명령은 비인증 스캔이다. 로그인 뒤에만 접근 가능한 화면까지 정밀 검사하려면 B파트가 테스트 계정과 인증 흐름을 확정한 뒤 ZAP Context/User 설정과 Nuclei 인증 헤더 또는 쿠키를 별도로 추가해야 한다.

고정 Staging이 아직 해당 PR 코드로 갱신되지 않은 상태라면 PR 전 검사를 이 URL에 실행해도 PR 변경분을 검증하는 것이 아니다. PR 단계는 runner-local/Preview 환경을 사용하고, 고정 Staging Dynatrace 연동은 배포 후 검증에 사용한다.

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
python3 scripts/run-zap-validation.py \
  --profile pr \
  --target-url http://127.0.0.1:8000/posts \
  --reports-dir security/reports
```

PR 프로필은 `zap-baseline.py`, Spider 1분, Passive Scan 대기 5분, 전체 timeout 10분, Docker host network를 사용한다. macOS Docker Desktop에서 로컬 테스트할 때는 `--docker-network none`과 `host.docker.internal` 대상 URL을 사용한다.

### 4. PR 임시 환경에서 Nuclei 기본 검사

```bash
python3 scripts/run-nuclei-validation.py \
  --target-url http://127.0.0.1:8000/posts \
  --trivy-report security/reports/dependency-report.json \
  --reports-dir security/reports
```

이 명령 하나가 다음 작업을 순서대로 수행한다.

```text
Nuclei 기본 XSS 검사
-> Trivy High/Critical CVE 추출
-> 설치된 Nuclei 템플릿 사전 확인
-> 매칭 템플릿이 있을 때만 CVE 우선 검사
-> 기본 결과와 CVE 결과를 nuclei-report.jsonl로 통합
-> nuclei-cve-coverage.json에 후보·템플릿·finding 수 기록
```

기본 검사는 애플리케이션 코드에서 발생한 일반 XSS처럼 CVE 번호가 없는 취약점을 검사한다. Trivy CVE 우선 검사는 이 기본 검사를 대체하지 않는다. 아래 5~6절은 실행기 내부 동작과 개별 확인 명령을 설명한다.

### 5. Trivy 결과를 Nuclei 입력으로 변환

Trivy 원본 JSON의 `Results[].Vulnerabilities[]`에서 `Severity`가 `HIGH` 또는 `CRITICAL`이고 `VulnerabilityID`가 CVE 형식인 항목만 추출한다.

```bash
python3 scripts/trivy-to-nuclei.py \
  security/reports/dependency-report.json \
  --output security/reports/nuclei-cve-ids.txt \
  --severities HIGH,CRITICAL
```

C파트의 확정 원본 경로는 `security/reports/dependency-report.json`, Artifact 이름은 `dependency-report`다. 이 스크립트는 팀 공통 스키마로 변환된 보고서가 아니라 `SchemaVersion: 2`와 `Results` 배열이 있는 Trivy 원본 JSON을 입력으로 받는다.

`dependency-scan`과 `runtime-validation`은 서로 다른 Runner에서 실행되므로 저장소에 파일이 자동으로 공유되지 않는다. A파트는 `runtime-validation` Job이 `dependency-scan`을 기다리게 하고 `dependency-report` Artifact를 다운로드한 뒤 `run-nuclei-validation.py`를 실행해야 한다. 이 실행기가 내부에서 변환 스크립트를 호출한다.

```text
dependency-scan Job
-> dependency-report Artifact 업로드
runtime-validation Job
-> dependency-report Artifact 다운로드
-> run-nuclei-validation.py 실행
-> 내부에서 trivy-to-nuclei.py 호출
```

생성 예시:

```text
CVE-2018-1000656
CVE-2023-30861
```

Nuclei는 `-id` 옵션에서 쉼표 목록뿐 아니라 파일도 받을 수 있으므로 이 파일을 그대로 전달할 수 있다.

Trivy와 Nuclei의 결과는 다음 세 단계로 구분한다.

```text
Trivy 후보 CVE 수
-> 설치된 Nuclei 템플릿과 일치하는 CVE 수
-> 실행 환경에서 Nuclei가 실제 탐지한 CVE 수
```

Trivy 후보가 존재해도 Nuclei 템플릿이 없을 수 있고, 템플릿이 있어도 실행 환경에서 취약 기능이 노출되지 않으면 실제 finding은 발생하지 않을 수 있다. 따라서 세 수치를 같은 의미로 해석하면 안 된다.

### 6. Trivy CVE 우선 Nuclei 검사

```bash
: > security/reports/nuclei-cve-report.jsonl
: > security/reports/nuclei-cve-matched-templates.txt

if [ -s security/reports/nuclei-cve-ids.txt ]; then
  docker run --rm \
    -v "$GITHUB_WORKSPACE/security/reports:/app/reports:ro" \
    projectdiscovery/nuclei:latest \
    -id /app/reports/nuclei-cve-ids.txt \
    -tl \
    -silent \
    > security/reports/nuclei-cve-matched-templates.txt

  if [ -s security/reports/nuclei-cve-matched-templates.txt ]; then
    timeout 5m docker run --rm \
      --network host \
      -v "$GITHUB_WORKSPACE/security/reports:/app/reports:rw" \
      projectdiscovery/nuclei:latest \
      -u http://127.0.0.1:8000/posts \
      -id /app/reports/nuclei-cve-ids.txt \
      -rate-limit 10 \
      -c 5 \
      -retries 0 \
      -timeout 5 \
      -ni \
      -jsonl \
      -omit-raw \
      -o /app/reports/nuclei-cve-report.jsonl \
      -silent
  else
    echo "Trivy CVE-targeted Nuclei scan skipped: no matching Nuclei template"
  fi
else
  echo "Trivy CVE-targeted Nuclei scan skipped: no High/Critical CVE candidate"
fi
```

`nuclei-cve-matched-templates.txt`는 실제 실행 가능한 Nuclei 템플릿 경로 목록이다. 이 파일이 비어 있으면 CVE 우선 검사는 `passed`가 아니라 `skipped: no-matching-nuclei-template`로 기록한다. 이 경우에도 Trivy의 High/Critical finding은 제거하지 않고 Aggregator와 Policy Evaluator에 그대로 전달한다.

템플릿 존재 여부만 별도로 확인하려면 다음 명령을 사용한다.

```bash
docker run --rm \
  -v "$GITHUB_WORKSPACE/security/reports:/app/reports:ro" \
  projectdiscovery/nuclei:latest \
  -id /app/reports/nuclei-cve-ids.txt \
  -tl \
  -silent
```

여기서는 Nuclei `-severity`를 다시 적용하지 않는다. 우선순위는 이미 Trivy의 High/Critical 기준으로 결정됐고, 같은 CVE라도 Nuclei 템플릿의 severity 표기가 다를 수 있기 때문이다.

`nuclei-cve-report.jsonl`이 비어 있어도 해당 CVE가 안전하다는 뜻은 아니다. 다음 중 하나일 수 있다.

- 해당 CVE용 Nuclei 템플릿이 없음
- 취약 패키지가 실행 중인 HTTP 경로에 노출되지 않음
- 인증, 특정 파라미터 또는 클라우드 런타임 조건이 충족되지 않음
- Nuclei matcher가 요구하는 증거가 응답에 나타나지 않음

수동 검증에서 팀원 Next.js 포트폴리오를 대상으로 다음 결과를 확인했다.

```text
Trivy 전체 취약점: 22
Trivy High: 8
High 중 CVE 형식 후보: 5
Nuclei 매칭 템플릿: 1
Nuclei 실제 finding: 0
```

매칭된 `CVE-2026-44578` 템플릿은 Next.js WebSocket Upgrade Handler SSRF를 검사한다. 로컬 실행 환경에는 AWS/GCP/DigitalOcean 메타데이터 응답이 없어 finding이 발생하지 않았다. 이 결과는 Trivy finding이 오탐이라는 뜻이 아니라, 현재 실행 환경에서 Nuclei가 동적 악용 증거를 확인하지 못했다는 뜻이다.

`run-nuclei-validation.py`는 기본 검사와 CVE 우선 검사 결과를 최종 `security/reports/nuclei-report.jsonl`로 합친 뒤 Runtime Validation에 전달한다.

```bash
: > security/reports/nuclei-report.jsonl

for report in \
  security/reports/nuclei-base-report.jsonl \
  security/reports/nuclei-cve-report.jsonl; do
  if [ -f "$report" ]; then
    cat "$report" >> security/reports/nuclei-report.jsonl
  fi
done
```

동시에 다음 상태 파일을 생성한다.

```text
security/reports/nuclei-cve-coverage.json
```

Staging `http://www.securegate.n-e.kr/posts`와 C파트 Trivy 결과로 검증한 결과는 다음과 같다.

```text
Trivy High/Critical CVE 후보: 8
Nuclei 매칭 템플릿: 0
Nuclei CVE finding: 0
Nuclei 기본 XSS finding: 2
최종 상태: skipped (no-matching-nuclei-template)
```

여기서 `skipped`는 CVE 우선 검사에 대한 상태다. 기본 Nuclei 검사는 정상 수행됐고 Medium `xss-fuzz`, High `top-xss-params`가 탐지됐다.

### 7. Runtime Validation 실행

```bash
RUNTIME_BASE_URL=http://127.0.0.1:8000 \
HEALTH_CHECK_PATH=/posts \
HEALTH_EXPECTED_STATUS=200 \
SMOKE_TEST_PATHS="/login=200,/posts=200,/upload=200|303,/docs=200,/redoc=200" \
REQUIRED_SECURITY_HEADERS="x-content-type-options,x-frame-options,content-security-policy" \
CUSTOM_RUNTIME_CHECKS="debug-exposure,docs-exposure,reflected-xss,search-sqli,admin-access,idor" \
ZAP_REPORT_PATH=security/reports/zap-report.json \
NUCLEI_REPORT_PATH=security/reports/nuclei-report.jsonl \
DYNATRACE_PROBLEMS_PATH=security/reports/dynatrace-problems.json \
python3 scripts/runtime-validation.py
```

### 8. 임시 환경 종료

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
Wait for dependency-scan Job
-> dependency-report Artifact 다운로드
Run scripts/run-zap-validation.py --profile pr
-> security/reports/zap-report.json 생성
Run scripts/run-nuclei-validation.py
-> 기본 Nuclei 검사
-> Trivy High/Critical CVE 추출과 템플릿 사전 확인
-> 매칭 템플릿이 있을 때 CVE 우선 검사
-> security/reports/nuclei-report.jsonl 생성
-> security/reports/nuclei-cve-coverage.json 생성
Fixed Staging이면 fetch-dynatrace-problems.py 실행
-> security/reports/dynatrace-problems.json 생성
-> python scripts/runtime-validation.py 실행
-> security/reports/runtime-report.json 생성
-> Artifact 업로드
```

---

## 환경 변수

| 변수 | 설명 | 기본값 |
| --- | --- | --- |
| `ZAP_TARGET_URL` | ZAP Baseline 대상 URL. 앱 루트가 404이면 `/posts` 같은 진입 화면을 지정 | 없음 |
| `ZAP_SCAN_PROFILE` | `pr` Baseline 또는 `post-merge` Full Scan | `pr` |
| `ZAP_DOCKER_NETWORK` | PR localhost는 `host`, 외부 Staging은 `none`으로 Docker 기본 bridge 사용 | 프로필 기본값 |
| `ZAP_SPIDER_MINUTES` | Spider 경로 탐색 시간 | PR 1분 / Post-merge 5분 |
| `ZAP_PASSIVE_WAIT_MINUTES` | ZAP 시작과 Passive Scan 최대 대기 | PR 5분 / Post-merge 10분 |
| `ZAP_SCAN_TIMEOUT` | ZAP 전체 실행 제한 | PR 10분 / Post-merge 30분 |
| `ZAP_AJAX_SPIDER` | Ajax Spider 사용 여부 | PR false / Post-merge true |
| `NUCLEI_TARGET_URL` | Nuclei 대상 URL. 미설정 시 `ZAP_TARGET_URL`, `RUNTIME_BASE_URL`, `STAGING_URL` 순서로 사용 | 없음 |
| `NUCLEI_SEVERITIES` | 실행할 Nuclei 템플릿 severity 범위. PR 단계에서도 필수 탐지 범위인 Medium 이상은 포함 | `medium,high,critical` |
| `NUCLEI_TAGS` | PR 단계에서 실행할 Nuclei 템플릿 태그 범위 | `xss` |
| `NUCLEI_RATE_LIMIT` | 초당 요청 제한. PR 단계에서 시간과 부하를 함께 조절 | `10` |
| `NUCLEI_CONCURRENCY` | 동시 실행 템플릿 수. 임시 앱 부하를 고려해 과도하게 올리지 않음 | `5` |
| `NUCLEI_RETRIES` | 실패 요청 재시도 횟수. PR 단계에서는 지연을 줄이기 위해 재시도하지 않음 | `0` |
| `NUCLEI_TIMEOUT_SECONDS` | Nuclei 요청 timeout | `5` |
| `NUCLEI_SCAN_TIMEOUT` | PR 단계 Nuclei 전체 실행 제한 시간 | `5m` |
| `NUCLEI_TEMPLATE_LIST_TIMEOUT` | CVE 대응 템플릿 목록 확인 제한 시간 | `2m` |
| `NUCLEI_DOCKER_NETWORK` | Nuclei Docker 네트워크. PR은 `host`, Post-merge 외부 URL은 Docker 기본 bridge 사용 | 프로필 기본값 |
| `NUCLEI_TEMPLATE_VOLUME` | 다운로드한 Nuclei 템플릿을 재사용할 Docker volume. `none`이면 비활성화 | `secure-gate-nuclei-templates` |
| `TRIVY_REPORT_PATH` | C파트 Trivy 원본 JSON 경로 | `security/reports/dependency-report.json` |
| `TRIVY_NUCLEI_SEVERITIES` | CVE 우선 검사 후보로 추출할 Trivy severity | `HIGH,CRITICAL` |
| `SECURITY_REPORTS_DIR` | ZAP/Nuclei 중간·통합 결과 파일을 저장할 디렉터리 | `security/reports` |
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
| `NUCLEI_COVERAGE_PATH` | Nuclei 실행/CVE coverage 상태 경로 | `security/reports/nuclei-cve-coverage.json` |
| `RUNTIME_REQUIRED_REPORTS` | 반드시 생성되어야 할 원본 결과. Post-merge에서는 `zap,nuclei,nuclei-coverage,dynatrace` | `none` |
| `DYNATRACE_ENV_URL` | Dynatrace SaaS Environment URL | 없음 |
| `DYNATRACE_API_TOKEN` | Problems API 토큰. GitHub에는 `DYNATRACE_TOKEN` Secret으로 저장하고 실행할 때 매핑 | 없음 |
| `DYNATRACE_FROM` | Problems API 조회 시작 시각 | `now-30m` |
| `DYNATRACE_TO` | Problems API 조회 종료 시각 | 없음 |
| `DYNATRACE_PROBLEM_SELECTOR` | 열린 문제와 Staging 태그 범위 지정 | `status("open")` |
| `DYNATRACE_ENTITY_SELECTOR` | 필요할 때 Dynatrace entity 범위를 추가 제한 | 없음 |
| `DYNATRACE_API_TIMEOUT_SECONDS` | Problems API 요청 timeout | `20` |
| `DYNATRACE_PROBLEMS_PATH` | Dynatrace 원본 문제 리포트 경로 | `security/reports/dynatrace-problems.json` |
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
security/reports/nuclei-base-report.jsonl
security/reports/nuclei-cve-report.jsonl
security/reports/nuclei-report.jsonl
security/reports/nuclei-cve-ids.txt
security/reports/nuclei-cve-matched-templates.txt
security/reports/nuclei-cve-coverage.json
security/reports/dynatrace-problems.json
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
| Dynatrace | `AVAILABILITY`, `ERROR`, `MONITORING_UNAVAILABLE` | High |
| Dynatrace | `PERFORMANCE`, `RESOURCE_CONTENTION`, `CUSTOM_ALERT` | Medium |
| Dynatrace | `INFO` 또는 알 수 없는 severity | Low |
| Dynatrace JSON | 파싱 실패 또는 API warning | Medium |

초기 정책상 Critical/High/Secret은 Merge 차단, Medium은 PR 댓글 경고로 처리된다. 최종 차단 여부는 E파트 Policy Evaluator 기준에 따른다.

---

## OWASP ZAP 연동

ZAP Baseline은 GitHub Actions에서 Docker로 실행하고, JSON 결과를 아래 경로에 저장한다.

```text
security/reports/zap-report.json
```

권장 실행 명령:

```bash
python3 scripts/run-zap-validation.py \
  --profile pr \
  --target-url "${ZAP_TARGET_URL:-$RUNTIME_BASE_URL}" \
  --reports-dir security/reports
```

실행기는 ZAP finding 종료 코드 `1`, `2`를 정상 처리하고 스캐너 자체 오류만 종료 코드 `2`로 반환한다. 따라서 Workflow에서 `|| true`나 `continue-on-error`로 실행 오류를 숨기지 않는다. `runtime-validation.py`는 생성된 JSON을 읽어 `runtime.zap.<pluginid>` finding으로 변환하고 최종 차단 판단은 Aggregator와 Policy Evaluator가 담당한다.

B파트 취약 웹 앱처럼 `/`가 404이고 `/posts`가 실제 진입 화면인 경우, `RUNTIME_BASE_URL`은 루트 URL로 두고 `ZAP_TARGET_URL`만 `/posts`까지 포함해서 지정한다.

---

## Nuclei 연동

Nuclei는 GitHub Actions에서 Docker로 실행하고, JSONL 결과를 아래 경로에 저장한다.

```text
security/reports/nuclei-report.jsonl
```

권장 실행 명령:

```bash
python3 scripts/run-nuclei-validation.py \
  --target-url "${NUCLEI_TARGET_URL:-${ZAP_TARGET_URL:-$RUNTIME_BASE_URL}}" \
  --trivy-report "${TRIVY_REPORT_PATH:-security/reports/dependency-report.json}" \
  --reports-dir "${SECURITY_REPORTS_DIR:-security/reports}"
```

실행기는 기본 검사, Trivy CVE 추출, 템플릿 사전 확인, 조건부 CVE 검사와 JSONL 통합을 한 번에 처리한다. `runtime-validation.py`는 통합 JSONL을 한 줄씩 읽어 `runtime.nuclei.<template-id>` finding으로 변환한다. Nuclei의 `critical/high/medium/low`는 그대로 매핑하고, `info/unknown`은 팀 공통 schema에 맞춰 `low`로 기록한다. PR 단계 기본값은 `medium,high,critical`, `xss`, 전체 timeout 5분, 요청 timeout 5초, `rate-limit 10`, concurrency 5, retries 0, Interactsh 비활성화다. 원본 HTTP 요청·응답은 `-omit-raw`로 제외해 Artifact 크기와 민감정보 노출 가능성을 줄인다.

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

D파트는 실행 중인 애플리케이션을 대상으로 Health Check, Smoke Test, Security Header Check, Custom Runtime Check를 수행하고 OWASP ZAP, Nuclei, Dynatrace 결과를 공통 스키마의 `runtime-report.json`으로 통합하도록 구현했다.
