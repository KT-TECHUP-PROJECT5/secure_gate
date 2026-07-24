---
문서명: 정책 검증 매트릭스 (PoC ↔ 정책 판정 교차검증)
최신화: 2026-07-24
작성자: 이정빈 (E파트)
Version: 0.1.0 (틀 — 도구 탐지 결과 미기입)
---

# 정책 검증 매트릭스

B파트(김재헌) 교육용 취약앱(`web/`)에 의도적으로 심은 취약점과, 그에 대한
스캐너 탐지 결과 및 **내 게이트 정책의 최종 판정**을 교차검증한다.

- Ground truth: `security/baselines/redteam-expected-findings.json` (B파트, 11건)
- PoC 실행: `scripts/run-redteam-poc.sh`, `docs/red-team/poc-guide.md` (B파트)
- 도구 기대치: `docs/red-team/detection-baseline.md` (B파트)
- 대상 브랜치: 취약앱은 `origin/feat/b-vulnerable-app`. 아직 main·E파트 브랜치
  미통합 — 도구 탐지 축은 **B+C+D 통합 시점**에 채운다.

---

## 1. 검증 목적

1. **미탐 없음**: 실제 악용 가능한 취약점이 게이트를 통과하지 않는가.
2. **오탐 억제**: 취약하지 않은 코드를 불필요하게 차단하지 않는가.
3. **판정 적정성**: 탐지된 finding의 심각도에 맞는 판정(차단/경고)을 내리는가.

이 매트릭스는 **두 축을 분리**한다:
- **탐지 축 (C·D 파트 책임)**: SAST/DAST/Dependency 도구가 취약점을 잡는가.
- **정책 축 (E 파트 책임)**: 탐지된 finding을 게이트가 올바르게 판정하는가.

미탐이 "도구가 못 잡음(탐지 축)"인지 "정책이 통과시킴(정책 축)"인지 구분해
책임 경계를 명확히 한다.

---

## 2. 검증 방법

각 PoC(B-01…B-12)에 대해:

- **(a) 실제 악용 가능 여부**: `run-redteam-poc.sh` 또는 수동 PoC로 재현
  (PASS = 악용 성공 = 실제 취약).
- **(b) 각 도구 탐지 결과**: C·D 파트 산출물에서 확인
  (`sast-report.json` / `dependency-report.json` / `runtime-report.json`).
- **(c) 내 정책의 최종 판정**: 탐지된 finding을 `evaluate-gate.py`가
  `gateRules`(blockOnSeverity=[critical, high, secret], warnOnSeverity=[medium])로
  판정 → block / warn / pass.
- **(d) 정탐/오탐/미탐/적정통과 분류**: (a)와 (b)+(c)를 대조.

### 정책 판정 규칙 (결정론적, E파트 소유)
`security/policies/security-gate-policy.json` 기준:

| 탐지 심각도 | 게이트 판정 |
| --- | --- |
| critical / high / secret | **block** (Merge 차단) |
| medium | **warn** (경고, 통과) |
| low | pass (기록만) |

> 주의: 정책은 **도구가 매긴 심각도**로 판정한다. Ground truth 심각도와 도구
> 출력 심각도가 다를 수 있다(예: SQLi를 semgrep이 ERROR→high로 매핑). 아래
> "정책 판정(예상)"은 ground truth 심각도가 그대로 탐지된다는 가정의 기대값이다.

---

## 3. 판정 기준 정의

| 분류 | 정의 | 조건 |
| --- | --- | --- |
| **정탐 (True Positive)** | 실제 취약 + 차단됨 | PoC PASS **그리고** 도구 탐지 → 정책 block |
| **오탐 (False Positive)** | 취약하지 않음 + 차단됨 | PoC FAIL(재현 불가) **그리고** 차단됨 |
| **미탐 (False Negative)** | 실제 취약 + 통과됨 | PoC PASS **그러나** 게이트 통과(미탐지 또는 정책 pass/warn만) |
| **적정통과 (True Negative)** | 취약하지 않음 + 통과됨 | PoC FAIL **그리고** 통과됨 |

- red-team 세트는 **전부 실제 취약(PoC PASS 기대)**이므로 정상 결과는 **정탐**이다.
  통과되면 **미탐**(탐지 축 또는 정책 축 어디서 샜는지 (b)/(c)로 구분).
- **오탐/적정통과**는 취약하지 않은 코드가 있어야 측정된다 → red-team 세트만으로는
  불가. 별도 **클린 베이스라인**(정상 코드 스냅샷)이 필요하며 후속 과제로 둔다.

---

## 4. 교차검증 표

범례: 도구 열 — `기대`=탐지 기대 / `일부`=부분 탐지 기대 / `미탐가능`=도구 성격상
어려움 / `비대상` / `?`=미측정. 정책 판정·분류의 빈칸은 도구 탐지 결과 확정 후 기입.

| ID | 취약점 | 위치 | GT 심각도 | 악용(PoC) | SAST | DAST | Dep | 정책 판정(예상) | 분류 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| B-01 | Login SQL Injection | `routers/auth.py` | critical | ? | 기대 | 기대 | 비대상 | **block** | |
| B-02 | Search SQL Injection | `routers/posts.py` | high | ? | 기대 | 기대 | 비대상 | **block** | |
| B-03 | Stored/Reflected XSS | `templates/` | high | ? | 기대 | 기대 | 비대상 | **block** | |
| B-05 | Private Post IDOR | `GET /posts/private/{id}` | high | ? | 미탐가능 | 미탐가능 | 비대상 | **block** | |
| B-06 | Missing Admin Role Check | `GET /admin` | high | ? | 미탐가능 | 미탐가능 | 비대상 | **block** | |
| B-07 | Unauthorized Post Deletion | `POST /posts/{id}/delete` | high | ? | 미탐가능 | 미탐가능 | 비대상 | **block** | |
| B-08 | Unrestricted File Upload | `POST /upload` | high | ? | 일부 | 일부 | 비대상 | **block** | |
| B-09 | Auth Failure Controls Missing | `routers/auth.py` | medium | ? | 미탐가능 | 미탐가능 | 비대상 | **warn** | |
| B-10 | Security Events Not Recorded | `GET /admin/security-events` | medium | ? | 미탐가능 | 미탐가능 | 비대상 | **warn** | |
| B-11 | Error Info Exposure | `GET /debug/*` | medium | ? | 일부 | 기대 | 비대상 | **warn** | |
| B-12 | Security Headers Missing | `http://127.0.0.1:8000` | medium | ? | 비대상 | 기대 | 비대상 | **warn** | |

### 정책 축 요약 (✅ 실측 — evaluate-gate.py 실행, 2026-07-24)
GT 11건을 실제 `evaluate-gate.py`(실 정책, runtime-validation 항등 매핑)로 태운 결과:
`gate_status=FAILED`, `blocked=True`, `rc=1`.

- **block 7건** (critical 1 + high 6) → Merge 차단. B-01,02,03,05,06,07,08.
- **warn 4건** (medium) → 경고만(통과). B-09,10,11,12.
- 즉 finding 이 **GT 심각도 그대로 탐지되기만 하면** 정책은 정확히 판정한다
  (정책 축 무결). 남은 변수는 **탐지 축**(도구가 그 심각도로 실제 잡는가)이다.
- **정책은 medium 4건을 차단하지 않는다** — 정책상 의도된 동작이나, 이들이
  "실제 악용 가능"이면 정책 축의 미탐 여지다(§5 참고).

---

## 5. 열린 질문 · 후속

- **medium 4건의 warn 처리**: B-09~B-12는 medium이라 정책상 warn(통과)이다.
  이 중 실제 악용 영향이 큰 항목(예: 에러 노출 B-11)을 high로 재평가할지,
  아니면 medium=warn 정책을 유지할지 — ground truth 대조 후 정책 조정 검토.
- **도구 심각도 ↔ GT 심각도 편차**: 정책은 도구 심각도로 판정하므로, 도구가
  GT보다 낮게 매기면 정책 축에서 미탐이 날 수 있다. 탐지 결과 확정 시
  "도구 심각도" 열을 추가해 편차를 기록한다.
- **클린 베이스라인**: 오탐/적정통과 측정용 정상 코드 세트(후속).
- **의존성 CVE PoC**: `requirements-legacy.txt`(A03)는 CVE 트랙 직접 대상이나
  red-team baseline에 없음 — 별도 픽스처로 CVE 트랙 교차검증 추가 검토.

---

## 6. 실행 절차 (도구 탐지 축 채우기 — B+C+D 통합 시)

```bash
# 1) 취약앱 기동 (B파트)
cd web && docker compose up -d postgres && alembic upgrade head
python -m app.seed && uvicorn app.main:app &

# 2) 악용 재현 (PoC PASS/FAIL → (a) 열)
bash scripts/run-redteam-poc.sh

# 3) 스캐너 실행 → security/reports/*.json (C·D 파트) → (b) 열

# 4) 게이트 판정 (E파트) → gate-decision.json → (c) 열
python scripts/evaluate-gate.py

# 5) 위 표의 빈칸 기입 후 (d) 분류 확정
```
