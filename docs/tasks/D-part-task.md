---
문서명: D파트 Runtime Validation 작업 체크리스트
최신화: 2026-07-24
작성자: D파트
Version: 1.12.0
---

# D파트 Runtime Validation 작업 체크리스트

## 담당 범위

D파트는 실행 중인 테스트/Staging 환경을 대상으로 런타임 보안 검증을 수행하고, 결과를 `security/reports/runtime-report.json`으로 생성한다.

---

## 구현 완료

- [x] Runtime Validation 제출용 스크립트 생성: `scripts/runtime-validation.py`
- [x] Health Check 구현
- [x] Smoke Test 구현
- [x] Security Header Check 구현
- [x] Custom Runtime Check 구현
- [x] OWASP ZAP JSON 결과 파싱 구현
- [x] ZAP `pr` Baseline / `post-merge` Full Scan 실행기 구현: `scripts/run-zap-validation.py`
- [x] Nuclei JSONL 결과 파싱 구현
- [x] Trivy High/Critical CVE를 Nuclei template ID 입력으로 변환하는 스크립트 구현
- [x] Nuclei `-tl` 기반 CVE 템플릿 사전 확인 및 템플릿 0개 처리 기준 작성
- [x] Nuclei 기본 검사, Trivy CVE 조건부 검사와 결과 통합 실행기 구현: `scripts/run-nuclei-validation.py`
- [x] 외부 Next.js 포트폴리오로 Trivy-Nuclei 수동 연동 검증
- [x] 공용 Staging에서 통합 실행기 검증: 기본 XSS 2건, CVE 후보 8개, 매칭 템플릿 0개
- [x] Dynatrace Problems API v2와 Service entities 결과 수집 스크립트 구현
- [x] Dynatrace 열린 문제를 공통 Runtime finding으로 변환
- [x] Dynatrace 서비스 엔티티 미탐지를 High Runtime finding으로 변환
- [x] 공통 결과 스키마 그대로 출력 구현
- [x] PR Workflow에 전달할 Runtime Validation 실행 기준 작성
- [x] PR Workflow에 전달할 ZAP Baseline 실행 기준 작성
- [x] PR Workflow에 전달할 Nuclei 실행 기준 작성
- [x] CD/Post-deploy Validation에 전달할 실행 기준 작성
- [x] Merge 이후 ZAP Full Scan 실행 기준 작성
- [x] Merge 이후 Nuclei 광범위 스캔 실행 기준 작성
- [x] Nuclei `pr` / `post-merge` 실행 프로필 구현
- [x] Post-merge 필수 원본 결과 누락과 Nuclei 실행 실패 검증 구현
- [x] Runtime Validation 운영 가이드 작성
- [x] v4 코드 설명 txt 작성: `docs/runtime-validation-v4-explanation.txt`

---

## 팀 확정 필요

- [x] 실제 Staging URL 확정: `http://www.securegate.n-e.kr`
- [x] Health Check Endpoint 확정: `GET /posts`, 기대 상태 `200`
- [x] Staging 실행 환경 확정: ECS Fargate / ALB
- [x] Smoke Test 대상 경로와 기대 상태 확정: `/login=200,/posts=200,/upload=200|303,/docs=200,/redoc=200`
- [ ] 필수 보안 헤더 목록 확정
- [ ] 인증이 필요한 Smoke Test 처리 방식 확정
- [ ] ZAP 인증 스캔 필요 여부 확정
- [x] Merge 이후 Nuclei 기본 범위 확정: 태그 제한 없음, `low,medium,high,critical`, 전체 timeout 30분
- [ ] Nuclei OAST, Headless, Fuzzing 별도 정밀 검사 사용 여부 확정
- [x] C파트 Trivy 원본 JSON 경로 확정: `security/reports/dependency-report.json`
- [ ] A파트의 `dependency-report` Artifact 다운로드와 D파트 Job 연결 확인
- [ ] A파트의 PR ZAP 직접 Docker 명령을 `run-zap-validation.py --profile pr`로 교체
- [ ] A파트의 `run-nuclei-validation.py` 실행 step 연결 확인
- [ ] A파트의 임시 `runtime-report.json` 직접 작성을 `runtime-validation.py` 실행으로 교체
- [ ] Trivy High/Critical finding이 Nuclei 결과와 관계없이 Aggregator에 유지되는지 확인
- [x] 기존 ECS Service가 OneAgent 없는 `secure-gate-dast:1`을 사용한 상태 확인
- [x] ECS Fargate OneAgent application-only 연동 방식 확정
- [x] OneAgent 설정이 포함된 `secure-gate-dast:4` 등록 확인
- [x] AWS Secret 생성과 Task Execution Role 읽기 권한 추가 확인
- [x] PaaS Token 생성과 Connection Info 조회 완료
- [x] AWS Secret의 세 필수 Key 실제 값 등록 확인
- [x] ECS Service를 `secure-gate-dast:4`로 배포
- [x] `initoneagent` exit code `0`, `web` RUNNING, ALB Target healthy 확인
- [x] Uvicorn 프로세스의 `liboneagentproc.so` 로드 확인
- [x] CloudWatch에서 Python Agent 로드와 Dynatrace endpoint 연결 성공 확인
- [x] Staging `GET /posts` HTTP `200` 확인
- [x] Dynatrace `Services`에서 `OWASP practice board DAST` 서비스와 `/posts` 트레이스 확인
- [x] Dynatrace Synthetic HTTP Monitor 생성: `secure-gate-staging-health`
- [x] Synthetic Monitor 실행 결과 확인: `Success`, Availability `100%`, HTTP `200`
- [x] A파트의 Dynatrace Repository Variable/Secret 및 실행 step 연결
- [x] A파트의 CD Placeholder를 ZAP/Nuclei `post-merge` 프로필과 Dynatrace 수집 순서로 교체
- [x] A파트 Workflow YAML 연결

---

## GitHub Actions 설정 값

| 변수 | 예시 |
| --- | --- |
| `ZAP_TARGET_URL` | `http://www.securegate.n-e.kr/posts` |
| `NUCLEI_TARGET_URL` | `http://www.securegate.n-e.kr/posts` |
| `NUCLEI_SEVERITIES` | `medium,high,critical` |
| `NUCLEI_TAGS` | `xss` |
| `NUCLEI_RATE_LIMIT` | `10` |
| `NUCLEI_CONCURRENCY` | `5` |
| `NUCLEI_RETRIES` | `0` |
| `NUCLEI_TIMEOUT_SECONDS` | `5` |
| `NUCLEI_SCAN_TIMEOUT` | `5m` |
| `NUCLEI_TEMPLATE_LIST_TIMEOUT` | `2m` |
| `NUCLEI_TEMPLATE_VOLUME` | `secure-gate-nuclei-templates` |
| Merge 이후 ZAP | `run-zap-validation.py --profile post-merge`, Spider 5분, Ajax Spider 포함, 전체 timeout 30분 |
| Merge 이후 Nuclei | `--profile post-merge`, 태그 제한 없음, `low,medium,high,critical`, `rate-limit=20`, `c=10`, 전체 timeout 30분 |
| `RUNTIME_BASE_URL` | PR 임시 환경: `http://127.0.0.1:8000` |
| `STAGING_URL` | 공용 Staging: `http://www.securegate.n-e.kr` |
| Staging 실행 환경 | ECS Cluster/Service `secure-gate-dast`, Launch Type `FARGATE` |
| 현재 Staging Task | Task Definition `secure-gate-dast:4`, container `web:8000`, process `uvicorn` |
| OneAgent 배포 상태 | `initoneagent` exit code `0`, `web` RUNNING, 새 ALB Target healthy, Agent 주입·endpoint 통신 확인 |
| `HEALTH_CHECK_PATH` | `/posts` |
| `HEALTH_EXPECTED_STATUS` | `200` |
| `SMOKE_TEST_PATHS` | `/login=200,/posts=200,/upload=200|303,/docs=200,/redoc=200` |
| `REQUIRED_SECURITY_HEADERS` | `x-content-type-options,x-frame-options,content-security-policy` |
| `CUSTOM_RUNTIME_CHECKS` | `debug-exposure,docs-exposure,reflected-xss,search-sqli,admin-access,idor` |
| `CUSTOM_RUNTIME_USERNAME` | `user1` |
| `CUSTOM_RUNTIME_PASSWORD` | `password123` |
| `CUSTOM_RUNTIME_PRIVATE_POST_ID` | `4` |
| `CUSTOM_RUNTIME_SQLI_PAYLOAD` | `') OR '1'='1' --` |
| `ZAP_REPORT_PATH` | `security/reports/zap-report.json` |
| `ZAP_SCAN_PROFILE` | PR: `pr`, Merge 이후: `post-merge` |
| `NUCLEI_REPORT_PATH` | `security/reports/nuclei-report.jsonl` |
| `NUCLEI_COVERAGE_PATH` | `security/reports/nuclei-cve-coverage.json` |
| `RUNTIME_REQUIRED_REPORTS` | Post-merge: `zap,nuclei,nuclei-coverage,dynatrace` |
| `DYNATRACE_ENV_URL` | `https://xlj20734.live.dynatrace.com` |
| `DYNATRACE_PROBLEM_SELECTOR` | `status("open")` |
| `DYNATRACE_ENTITY_SELECTOR` | `type("SERVICE"),entityName.equals("OWASP practice board DAST")` |
| `DYNATRACE_SERVICE_ENTITY_SELECTOR` | `type("SERVICE"),entityName.equals("OWASP practice board DAST")` |
| Dynatrace Synthetic Monitor | `secure-gate-staging-health` / `HTTP_CHECK-D9507A08C7F0DC5E` / Busan / 5분 |
| `DYNATRACE_FROM` | `now-30m` |
| `DYNATRACE_PROBLEMS_PATH` | `security/reports/dynatrace-problems.json` |
| GitHub Secret `DYNATRACE_TOKEN` | `problems.read`, `entities.read` 범위의 읽기 전용 토큰. 코드에는 저장하지 않음 |
| ECS OneAgent Secret | `secure-gate/dynatrace/fargate`. 실제 값과 전체 ARN은 문서에 저장하지 않음 |
| ECS OneAgent Secret Key | `DT_PAAS_TOKEN`, `DT_TENANT`, `DT_TENANTTOKEN`, `DT_CONNECTION_POINT` |
| Trivy 원본 JSON | `security/reports/dependency-report.json`, Artifact `dependency-report` |
| Nuclei CVE ID 입력 | `security/reports/nuclei-cve-ids.txt` |
| Nuclei CVE 매칭 템플릿 | `security/reports/nuclei-cve-matched-templates.txt` |
| Nuclei CVE 결과 | `security/reports/nuclei-cve-report.jsonl` |
| Nuclei CVE 실행 상태 | `security/reports/nuclei-cve-coverage.json` |

---

## A파트 전달 필요

D파트는 실행 중인 PR 임시 환경 또는 Staging URL을 검사하는 명령어와 결과 파일 기준을 제공한다. 실제 앱 실행 자동화, GitHub Secrets/Variables 등록, PR/CD Workflow YAML 연결, Artifact 업로드는 A파트 또는 CI/CD 담당과 확정이 필요하다.

전달 항목:

- Staging URL
- Health Check Endpoint
- Smoke Test 실행 경로
- ZAP 실행 명령어와 결과 파일 경로
- ZAP 실행은 `run-zap-validation.py`를 사용하고 `|| true` / `continue-on-error`로 스캐너 오류를 숨기지 않는 기준
- Nuclei 실행 명령어와 결과 파일 경로
- Merge 이후 ZAP Full Scan과 Nuclei 광범위 스캔의 순차 실행 명령어
- Post-deploy 실패 시 Production 승격 차단 또는 rollback 연결 기준
- Trivy `dependency-report` Artifact 다운로드 후 `scripts/run-nuclei-validation.py` 실행 명령어
- Nuclei `-tl` 템플릿 사전 확인, 템플릿 0개 시 `skipped` 처리 기준
- Trivy finding을 Nuclei 탐지 여부와 관계없이 Aggregator에 유지하는 기준
- Dynatrace Environment URL, selector, Secret 이름과 Problems API 수집 명령어
- Dynatrace 원본 결과 파일 경로와 severity 매핑 기준
- Runtime Validation 실행 명령어와 결과 파일 경로
- 보안 헤더 검증 기준
- Runtime Validation 실패 기준
- Custom Runtime Check 설정값

---

## 로컬 검증 명령어

ZAP PR Baseline을 실행한다.

```bash
python3 scripts/run-zap-validation.py \
  --profile pr \
  --target-url http://127.0.0.1:8000/posts \
  --reports-dir security/reports
```

Nuclei 기본 검사와 Trivy CVE 우선 검사를 함께 실행한다.

```bash
python3 scripts/run-nuclei-validation.py \
  --profile pr \
  --target-url http://127.0.0.1:8000/posts \
  --trivy-report security/reports/dependency-report.json \
  --reports-dir security/reports
```

이후 통합 Runtime Validation을 실행한다.

```bash
RUNTIME_BASE_URL=http://127.0.0.1:8000 \
HEALTH_CHECK_PATH=/posts \
HEALTH_EXPECTED_STATUS=200 \
SMOKE_TEST_PATHS="/login=200,/posts=200,/upload=200|303,/docs=200,/redoc=200" \
CUSTOM_RUNTIME_CHECKS="debug-exposure,docs-exposure,reflected-xss,search-sqli,admin-access,idor" \
ZAP_REPORT_PATH=security/reports/zap-report.json \
NUCLEI_REPORT_PATH=security/reports/nuclei-report.jsonl \
DYNATRACE_PROBLEMS_PATH=security/reports/dynatrace-problems.json \
python3 scripts/runtime-validation.py
```

결과 파일:

```text
security/reports/runtime-report.json
```

---

## 제출 시 설명 포인트

- `runtime-validation.py`는 결과 JSON을 직접 손으로 만드는 파일이 아니라, 검증을 실행한 뒤 `security/reports/runtime-report.json`을 자동 생성하는 스크립트다.
- 최종 결과 파일의 top-level 필드는 `status`, `tool`, `findings`만 사용한다.
- Health/Smoke 실패는 `high`로 기록되어 Merge 차단 대상이 되고, Header 누락은 `medium`으로 기록되어 경고 대상이 된다.
- Custom Runtime Check는 debug/docs 노출, reflected XSS, 검색 SQLi, 일반 사용자 admin 접근, IDOR를 PR 단계에서 추가 검증한다.
- Nuclei는 PR 단계에서도 `medium,high,critical`을 유지하고, `timeout 5m`, `retries=0`, 요청 timeout 5초, concurrency 5로 실행 시간을 제어한다.
- Merge 이후에는 `run-zap-validation.py --profile post-merge`가 `zap-full-scan.py` Active Scan을 실행하고, Nuclei는 `--profile post-merge`로 태그 제한 없이 `low,medium,high,critical` 기본 템플릿을 실행한다.
- Merge 이후 Runtime Validation은 `RUNTIME_REQUIRED_REPORTS=zap,nuclei,nuclei-coverage,dynatrace`를 사용해 스캐너 결과 누락을 High finding으로 처리한다.
- Merge 이후 두 스캐너는 Staging 부하를 고려해 ZAP 다음 Nuclei 순서로 실행하고 각 스캔의 전체 timeout을 30분으로 제한한다.
- 배포 후 finding은 이미 완료된 Merge를 취소하지 않고, Post-deploy Job 실패와 다음 환경 승격 차단 또는 rollback 판단에 사용한다.
- `trivy-to-nuclei.py`는 Trivy 원본 JSON에서 High/Critical CVE만 중복 제거하여 Nuclei `-id` 입력 파일로 만든다.
- `run-nuclei-validation.py`는 기본 검사, Trivy CVE 추출, 템플릿 사전 확인, 조건부 CVE 검사, JSONL 통합과 coverage 상태 생성을 수행한다.
- C파트 결과는 `dependency-report` Artifact로 전달되므로 A파트가 D파트 Job에서 다운로드한 뒤 `run-nuclei-validation.py`를 실행해야 한다.
- Trivy-Nuclei 연동 결과는 `Trivy 후보 CVE 수`, `Nuclei 매칭 템플릿 수`, `Nuclei 실제 finding 수`로 나누어 설명한다.
- Nuclei 매칭 템플릿이 0개이면 취약점이 없거나 검사를 통과한 것이 아니라 `skipped: no-matching-nuclei-template`로 처리한다.
- Next.js 포트폴리오 수동 검증에서 Trivy 22건, High 8건, CVE 후보 5개, 매칭 템플릿 1개, 실제 finding 0개를 확인했다.
- 공용 Staging 검증에서 Trivy CVE 후보 8개, 매칭 템플릿 0개, 기본 Nuclei XSS finding 2개를 확인했다.
- CVE 우선 검사는 일반 XSS 등 CVE 번호가 없는 취약점을 대신하지 않으므로 기존 Nuclei 기본 검사와 함께 실행한다.
- ZAP 결과는 `security/reports/zap-report.json`을 읽어 `runtime.zap.<pluginid>` finding으로 변환한다.
- Nuclei 결과는 `security/reports/nuclei-report.jsonl`을 읽어 `runtime.nuclei.<template-id>` finding으로 변환한다.
- `fetch-dynatrace-problems.py`는 `problems.read`, `entities.read` 토큰으로 열린 문제와 최근 서비스 엔티티를 `security/reports/dynatrace-problems.json`에 저장한다.
- `serviceCoverage.status`가 `not_detected`이면 OneAgent 통신 여부와 별개로 APM 서비스가 생성되지 않은 상태이므로 High finding으로 기록한다.
- Dynatrace `AVAILABILITY`, `ERROR`, `MONITORING_UNAVAILABLE`은 High, 성능·리소스·Custom Alert는 Medium, Info는 Low로 변환한다.
- ECS Service는 OneAgent Code Module이 포함된 revision 4로 배포됐고 `initoneagent`, `web`, ALB Health Check는 정상이다.
- Python 전역 모니터링과 FastAPI 계측 활성화 후 ECS Service를 강제 재배포했으며, Dynatrace `Services`에서 `OWASP practice board DAST` 서비스와 `/posts` HTTP 200 트레이스 수집을 확인했다.
- 최종 Merge 차단 여부는 E파트 Policy Evaluator의 정책 기준에 따른다.
