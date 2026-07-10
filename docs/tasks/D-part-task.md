---
문서명: D파트 Runtime Validation 작업 체크리스트
최신화: 2026-07-07
작성자: D파트
Version: 1.0.0
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
- [x] OWASP ZAP JSON 결과 파싱 구현
- [x] Nuclei JSONL 결과 파싱 구현
- [x] 공통 결과 스키마 그대로 출력 구현
- [x] PR Workflow `runtime-validation` Job 연결
- [x] PR Workflow ZAP Baseline 실행 단계 연결
- [x] PR Workflow Nuclei 실행 단계 연결
- [x] CD Workflow `post-deploy-validation` Job 연결
- [x] CD Workflow ZAP Baseline 실행 단계 연결
- [x] CD Workflow Nuclei 실행 단계 연결
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

---

## GitHub Actions 설정 값

| 변수 | 예시 |
| --- | --- |
| `ZAP_TARGET_URL` | `https://pr-123.example.com/posts` |
| `NUCLEI_TARGET_URL` | `https://pr-123.example.com/posts` |
| `NUCLEI_SEVERITIES` | `medium,high,critical` |
| `RUNTIME_BASE_URL` | `https://pr-123.example.com` |
| `STAGING_URL` | `https://staging.example.com` |
| `HEALTH_CHECK_PATH` | `/posts` |
| `HEALTH_EXPECTED_STATUS` | `200` |
| `SMOKE_TEST_PATHS` | `/login=200,/posts=200,/upload=200|303,/docs=200,/redoc=200` |
| `REQUIRED_SECURITY_HEADERS` | `x-content-type-options,x-frame-options,content-security-policy` |
| `ZAP_REPORT_PATH` | `security/reports/zap-report.json` |
| `NUCLEI_REPORT_PATH` | `security/reports/nuclei-report.jsonl` |

---

## 로컬 검증 명령어

```bash
RUNTIME_BASE_URL=http://127.0.0.1:8000 \
HEALTH_CHECK_PATH=/posts \
HEALTH_EXPECTED_STATUS=200 \
SMOKE_TEST_PATHS="/login=200,/posts=200,/upload=200|303,/docs=200,/redoc=200" \
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
- ZAP 결과는 `security/reports/zap-report.json`을 읽어 `runtime.zap.<pluginid>` finding으로 변환한다.
- Nuclei 결과는 `security/reports/nuclei-report.jsonl`을 읽어 `runtime.nuclei.<template-id>` finding으로 변환한다.
- 최종 Merge 차단 여부는 E파트 Policy Evaluator의 정책 기준에 따른다.
