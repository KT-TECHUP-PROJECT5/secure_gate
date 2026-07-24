---
문서명: 정책 검증 매트릭스 (PoC ↔ 정책 판정 교차검증)
최신화: 2026-07-24
작성자: 이정빈 (E파트)
Version: 0.2.0 (정책 축 실측 + medium 재평가 결론 / 탐지 축 미기입)
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

## 5. medium 4건(B-09~B-12) 재평가 — 결론

**결론: 4건 모두 medium 유지, 일괄 승격하지 않는다.** 아래는 각 건에 대해
"왜 안 올렸는지"의 근거다 — 등급을 올리는 것보다, 올리지 않는 판단에 근거가
있는 것이 더 나은 정책 결정이다. 일괄 승격은 오탐을 늘리고 게이트 신뢰를 깎는다.

### B-11 Error Info Exposure — medium 유지 + 개별 판단 절차
노출 "내용"에 따라 실제 위험이 크게 갈리는 항목이다:
- 스택 트레이스만 노출 → 정보성(낮음)
- DB 스키마/쿼리 노출 → 구조 유출(중간)
- 자격증명/시크릿 포함 → 즉시 critical

SAST 는 "에러 핸들러가 상세를 노출한다"는 **패턴**은 잡아도, 실제 응답에 **무엇이
새는지**(내용)를 구분하지 못한다. 따라서 일괄 severity 승격은 스택 트레이스만
노출되는 경우까지 high 로 차단해 **오탐을 늘린다**. → **medium 유지**하되, 아래
운영 절차로 DAST 실측 내용과 교차 확인 후 개별 승격한다.

### B-09 Authentication Failure Controls — medium 적정
약한 비밀번호·무제한 재시도·계정 잠금 부재는 인증 강도 미비다. 직접적 데이터
유출이 아니라 brute-force 를 "가능하게 하는 조건"이며, 실제 침해는 다른 요소(비밀
번호 정책·rate limit 인프라)와 결합해야 실현된다 → **단독 악용 영향 중간, medium
적정**. rate limit 완전 부재 + 민감 계정이 확인되면 그때 개별 재평가.

### B-10 Security Events Not Recorded — medium 적정 (비기능 요구)
로깅·알림 누락은 취약점 자체가 아니라 **탐지·대응 실패**(2차 영향)다. 공격을
가능하게 하지는 않으나 사고 시 추적을 어렵게 한다. 직접 악용 불가 →
**medium 적정**. 감사·컴플라이언스 요건상 상향할 수 있으나, Merge 게이트의 차단
대상으로 삼기엔 과하다.

### B-12 Security Headers Missing — medium 적정 (심층방어 보완재)
CSP/X-Frame-Options/X-Content-Type-Options 부재는 **심층방어 약화**(clickjacking·
XSS 완화 부재)이지 단독 취약점이 아니다. 실제 XSS(B-03)는 이미 별도 high 로
차단되므로 헤더는 보완재 → **medium 적정**. 다만 CSP 부재가 XSS 영향을 증폭하므로
XSS 와 묶어 우선 수정 권고.

### 운영 절차 — medium 개별 판단 (특히 B-11)
정책을 바꾸지 않고 medium 의 실제 위험을 잡아내는 흐름:

1. medium finding 은 게이트에서 warn(통과)이나, PR 댓글에 **"DAST 교차확인 권장"**
   맥락을 남긴다.
2. **DAST(runtime-report) 실제 응답 본문**에서 민감정보(시크릿·자격증명·쿼리·
   스키마) 노출 여부를 확인한다 — SAST 가 못 보는 "내용"을 여기서 본다.
3. 확인되면 리뷰어가 수동으로 차단하거나, 다음 정책 개정에서 **해당 패턴만**
   승격한다(일괄 승격 금지).
4. 판단 근거를 본 매트릭스 (d) 분류 열에 기록한다.

> 이 절차는 IR 플레이북의 대응 흐름과 연동한다(에러 노출 사고 시 노출 내용
> 등급화 → 대응). 상세: [Incident Response 플레이북](./incident-response-playbook.md)

---

## 6. 열린 질문 · 후속

- **도구 심각도 ↔ GT 심각도 편차**: 정책은 도구 심각도로 판정하므로, 도구가
  GT보다 낮게 매기면 정책 축에서 미탐이 날 수 있다. 탐지 결과 확정 시
  "도구 심각도" 열을 추가해 편차를 기록한다.
- **클린 베이스라인**: 오탐/적정통과 측정용 정상 코드 세트(후속).
- **의존성 CVE PoC**: `requirements-legacy.txt`(A03)는 CVE 트랙 직접 대상이나
  red-team baseline에 없음 — 별도 픽스처로 CVE 트랙 교차검증 추가 검토.

---

## 7. 탐지 축 검증 (B+C+D 통합 시)

### 7.1 실행 절차 (표의 SAST/DAST/Dep 열 채우기)

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

### 7.2 탐지 축 검증 완료 시 확인할 것 (체크리스트)

통합 후 이 순서로 점검하면 정책 축(이미 검증됨)과 합쳐 결론을 낼 수 있다.

- [ ] **PoC 재현 (a)**: `run-redteam-poc.sh` 11건 PASS 확인. FAIL 있으면 앱/시드
      문제인지 취약점 미구현인지 먼저 규명(오탐 판정의 전제).
- [ ] **탐지 결과 수집 (b)**: `sast-report.json`·`dependency-report.json`·
      `runtime-report.json` 을 caller cwd `security/reports/` 에 배치.
- [ ] **도구 심각도 편차**: 각 finding 의 **도구 출력 심각도**를 GT 심각도와
      대조해 "도구 심각도" 열에 기록. GT high 를 도구가 medium 으로 매기면
      정책이 warn 처리 → 정책 축이 아닌 **탐지 축 미탐**임을 구분.
- [ ] **게이트 판정 (c)**: `evaluate-gate.py` 실행 → `gate-decision.json` 의
      `findings[].blocking/warning` 로 실제 판정 확인(§4 실측과 일치하는지).
- [ ] **미탐 분류**: PASS 인데 게이트 통과한 건에 대해 원인이
      (1) 도구가 못 잡음(탐지 축) 인지 (2) 잡았으나 정책이 warn/pass(정책 축) 인지
      (b)/(c) 로 구분해 (d) 열에 기입.
- [ ] **IDOR/BAC/로직 취약(B-05,06,07,09,10)**: SAST/DAST 미탐가능 항목 →
      수동 PoC 만으로 확인되면 "도구 미탐, 수동 확인"으로 명시(도구 한계 기록).
- [ ] **medium 4건 개별 판단**: §5 운영 절차대로 DAST 실제 응답 내용
      교차확인(특히 B-11 노출 내용 등급화).
- [ ] **의존성 CVE 축**: `requirements-legacy.txt` → Trivy → CVE 트랙 경로가
      별도로 도는지 확인(red-team baseline 밖 항목).
- [ ] **최종 결론**: 미탐 0 목표 대비 실측, 미탐이 있으면 탐지 축(C/D 개선) vs
      정책 축(E 조정) 책임 배분 명시.
