---
문서명: D파트 Runtime Validation 작업 체크리스트
최신화: 2026-07-15
작성자: D파트
Version: 1.1.0
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
- [x] Nuclei JSONL 결과 파싱 구현
- [x] 공통 결과 스키마 그대로 출력 구현
- [x] PR Workflow에 전달할 Runtime Validation 실행 기준 작성
- [x] PR Workflow에 전달할 ZAP Baseline 실행 기준 작성
- [x] PR Workflow에 전달할 Nuclei 실행 기준 작성
- [x] CD/Post-deploy Validation에 전달할 실행 기준 작성
- [x] Runtime Validation 운영 가이드 작성
- [x] v4 코드 설명 txt 작성: `docs/runtime-validation-v4-explanation.txt`

---

## 팀 확정 필요

- [ ] 실제 Staging URL 확정
- [ ] Health Check Endpoint 확정
- [ ] Smoke Test 대상 경로 확정
- [ ] 필수 보안 헤더 목록 확정
- [ ] 인증이 필요한 Smoke Test 처리 방식 확정
- [ ] ZAP 인증 스캔 필요 여부 확정
- [ ] Nuclei 템플릿 범위와 severity 기준 확정
- [ ] A파트 Workflow YAML 연결 여부 확인

---

## GitHub Actions 설정 값

| 변수 | 예시 |
| --- | --- |
| `ZAP_TARGET_URL` | `https://pr-123.example.com/posts` |
| `NUCLEI_TARGET_URL` | `https://pr-123.example.com/posts` |
| `NUCLEI_SEVERITIES` | `medium,high,critical` |
| `NUCLEI_TAGS` | `xss` |
| `NUCLEI_RATE_LIMIT` | `10` |
| `NUCLEI_CONCURRENCY` | `5` |
| `NUCLEI_RETRIES` | `0` |
| `NUCLEI_TIMEOUT_SECONDS` | `5` |
| `NUCLEI_SCAN_TIMEOUT` | `5m` |
| `RUNTIME_BASE_URL` | `https://pr-123.example.com` |
| `STAGING_URL` | `https://staging.example.com` |
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
| `NUCLEI_REPORT_PATH` | `security/reports/nuclei-report.jsonl` |

---

## A파트 전달 필요

D파트는 실행 중인 PR 임시 환경 또는 Staging URL을 검사하는 명령어와 결과 파일 기준을 제공한다. 실제 앱 실행 자동화, GitHub Secrets/Variables 등록, PR/CD Workflow YAML 연결, Artifact 업로드는 A파트 또는 CI/CD 담당과 확정이 필요하다.

전달 항목:

- Staging URL
- Health Check Endpoint
- Smoke Test 실행 경로
- ZAP 실행 명령어와 결과 파일 경로
- Nuclei 실행 명령어와 결과 파일 경로
- Runtime Validation 실행 명령어와 결과 파일 경로
- 보안 헤더 검증 기준
- Runtime Validation 실패 기준
- Custom Runtime Check 설정값

---

## 로컬 검증 명령어

```bash
RUNTIME_BASE_URL=http://127.0.0.1:8000 \
HEALTH_CHECK_PATH=/posts \
HEALTH_EXPECTED_STATUS=200 \
SMOKE_TEST_PATHS="/login=200,/posts=200,/upload=200|303,/docs=200,/redoc=200" \
CUSTOM_RUNTIME_CHECKS="debug-exposure,docs-exposure,reflected-xss,search-sqli,admin-access,idor" \
python scripts/runtime-validation.py
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
- ZAP 결과는 `security/reports/zap-report.json`을 읽어 `runtime.zap.<pluginid>` finding으로 변환한다.
- Nuclei 결과는 `security/reports/nuclei-report.jsonl`을 읽어 `runtime.nuclei.<template-id>` finding으로 변환한다.
- 최종 Merge 차단 여부는 E파트 Policy Evaluator의 정책 기준에 따른다.
