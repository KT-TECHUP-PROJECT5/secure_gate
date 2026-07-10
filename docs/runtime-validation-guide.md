---
문서명: Runtime Validation 가이드
최신화: 2026-07-07
작성자: D파트
Version: 1.0.0
---

# Runtime Validation Guide

## 개요

D파트 Runtime Validation은 실행 중인 테스트/Staging 환경을 대상으로 런타임 보안 검증을 수행하고, A파트 공통 스키마 그대로 `security/reports/runtime-report.json`을 생성한다.

검증 범위:

- Health Check
- Smoke Test
- Security Header Check
- OWASP ZAP JSON 결과 연동
- Nuclei JSONL 결과 연동

최종 제출용 실행 파일:

```text
scripts/runtime-validation.py
```

학습용 v3 파일:

```text
scripts/runtime-validation-v3.py
```

---

## 실행 명령어

로컬 실행 예시:

```bash
RUNTIME_BASE_URL=http://127.0.0.1:8000 \
HEALTH_CHECK_PATH=/posts \
HEALTH_EXPECTED_STATUS=200 \
SMOKE_TEST_PATHS="/login=200,/posts=200,/upload=200|303,/docs=200,/redoc=200" \
REQUIRED_SECURITY_HEADERS="x-content-type-options,x-frame-options,content-security-policy" \
python scripts/runtime-validation.py
```

GitHub Actions에서는 `.github/workflows/pr-security-gate.yml`의 `runtime-validation` Job에서 실행된다.

Workflow 흐름:

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
| `NUCLEI_SEVERITIES` | 실행할 Nuclei 템플릿 severity 범위 | `medium,high,critical` |
| `RUNTIME_BASE_URL` | PR 단계 Runtime Validation 대상 URL | 없음 |
| `STAGING_URL` | `RUNTIME_BASE_URL`이 없을 때 사용할 Staging URL | 없음 |
| `HEALTH_CHECK_PATH` | Health Check 경로 | `/health` |
| `HEALTH_EXPECTED_STATUS` | Health Check 기대 HTTP Status. `200|204` 형식 가능 | `200` |
| `SMOKE_TEST_PATHS` | 쉼표 구분 Smoke Test 경로. `/login=200,/posts=200` 형식 가능 | `/` |
| `REQUIRED_SECURITY_HEADERS` | 쉼표 구분 필수 보안 헤더. `none`이면 비활성화 | `x-content-type-options,x-frame-options,content-security-policy` |
| `ZAP_REPORT_PATH` | OWASP ZAP JSON 리포트 경로 | `security/reports/zap-report.json` |
| `NUCLEI_REPORT_PATH` | Nuclei JSONL 리포트 경로 | `security/reports/nuclei-report.jsonl` |
| `RUNTIME_TIMEOUT_SECONDS` | HTTP 요청 timeout | `10` |

HTTPS 대상이면 `strict-transport-security`가 필수 헤더 목록에 자동 추가된다.

---

## 결과 파일

출력 경로:

```text
security/reports/runtime-report.json
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
docker run --rm \
  -v "$GITHUB_WORKSPACE/security/reports:/app/reports:rw" \
  projectdiscovery/nuclei:latest \
  -u "${NUCLEI_TARGET_URL:-${ZAP_TARGET_URL:-$RUNTIME_BASE_URL}}" \
  -severity "${NUCLEI_SEVERITIES:-medium,high,critical}" \
  -jsonl \
  -o /app/reports/nuclei-report.jsonl \
  -silent || true
```

`runtime-validation.py`는 이 JSONL을 한 줄씩 읽어 `runtime.nuclei.<template-id>` finding으로 변환한다. Nuclei의 `critical/high/medium/low`는 그대로 매핑하고, `info/unknown`은 팀 공통 schema에 맞춰 `low`로 기록한다. CI 기본값은 Merge 차단과 경고 판단에 필요한 `medium,high,critical`이며, Low까지 보고 싶으면 `NUCLEI_SEVERITIES=low,medium,high,critical`로 넓힌다.

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

D파트는 배포된 애플리케이션을 대상으로 Health Check, Smoke Test, Security Header Check, OWASP ZAP/Nuclei 결과 파싱을 수행하고, 공통 스키마의 `runtime-report.json`을 생성하도록 구현했다.
