---
문서명: 취약점 등급 기준 및 Security Gate 정책
최신화: 2026-07-14
작성자: E파트
Version: 1.0.0
---

# 취약점 등급 기준 및 Security Gate 정책

각 보안 도구가 생성한 탐지 결과를 **어떤 기준으로 해석하고 처리할지**를 정의한다.
OWASP Top 10과 CVSS v3.1을 기준으로 공통 위험도 체계를 세우고, 도구별 등급을
공통 등급으로 매핑한 뒤, 공통 등급에 따라 Merge 차단 / 경고 / 허용을 결정한다.

이 문서는 아래 정책 파일의 **근거이자 사람이 읽는 설명서**다. 실제 판정 로직은
정책 파일을 데이터로 읽어 동작하므로, 기준이 바뀌면 이 문서와 정책 파일을 함께 갱신한다.

| 구분 | 파일 |
| --- | --- |
| 등급 매핑 · Gate 룰 (기계용) | `security/policies/security-gate-policy.json` |
| 카테고리별 수정 가이드 | `security/policies/remediation-guide.json` |
| CVE 위험도 판정 정책 | `scripts/cve-policy-evaluate.py` |
| 판정 엔진 | `scripts/evaluate-gate.py` |

---

## 1. 공통 위험도 등급 체계

모든 도구의 결과는 아래 5개 **공통 등급** 중 하나로 정규화된다.
`secret`은 CVSS 점수와 무관하게 "노출 즉시 악용 가능"이라는 성격 때문에 별도 등급으로 둔다.

| 공통 등급 | 의미 | CVSS v3.1 기준 점수 | 기본 처리 |
| --- | --- | --- | --- |
| `critical` | 즉시 악용 가능하고 영향이 치명적 | 9.0 – 10.0 | **Merge 차단** |
| `high` | 악용 가능성이 높고 영향이 큼 | 7.0 – 8.9 | **Merge 차단** |
| `medium` | 조건부 악용 가능, 영향 제한적 | 4.0 – 6.9 | PR 경고 (Warning) |
| `low` | 악용 난도 높거나 영향 미미 | 0.1 – 3.9 | 기록만 |
| `secret` | 자격증명·키 등 민감정보 노출 | 해당 없음 (성격상 즉시 차단) | **Merge 차단** |

> CVSS 0.0(None)은 취약점으로 취급하지 않는다.
> 도구가 CVSS 점수를 직접 제공하지 않는 경우(2절)의 등급 산정 방식을 따른다.

---

## 2. OWASP Top 10 기준 취약점 분류

도구 카테고리별로 주로 탐지하는 OWASP Top 10 (2021) 항목과, 그 결과가 매핑되는
수정 가이드 카테고리를 정리한다. 수정 가이드는 `remediation-guide.json`의 키와 1:1 대응한다.

| 도구 카테고리 | 주요 OWASP Top 10 (2021) | 가이드 키 |
| --- | --- | --- |
| SAST (Semgrep) | A03 Injection, A01 Broken Access Control, A02 Cryptographic Failures, A08 Data Integrity Failures | `sast` |
| Secret (Gitleaks) | A07 Identification & Authentication Failures, A02 Cryptographic Failures (하드코딩 자격증명) | `secret` |
| Dependency (Trivy) | A06 Vulnerable and Outdated Components | `dependency` |
| DAST (ZAP) | A05 Security Misconfiguration, A03 Injection, 보안 헤더 미설정 | `dast` |

---

## 3. 도구별 Severity 매핑 기준

각 도구의 원본 등급은 도구마다 스케일이 다르므로, 아래 표대로 공통 등급으로 변환한다.
이 표는 `security-gate-policy.json`의 `severityMapping`과 **정확히 일치**해야 한다.

### 3-1. Semgrep (SAST)

| Semgrep 원본 | 공통 등급 | 근거 |
| --- | --- | --- |
| `ERROR` | `high` | Semgrep이 확실한 취약 패턴으로 판단한 경우 |
| `WARNING` | `medium` | 잠재적 위험, 문맥에 따라 오탐 가능 |
| `INFO` | `low` | 정보성 · 코드 품질 수준 |

### 3-2. Gitleaks (Secret)

| Gitleaks 원본 | 공통 등급 | 근거 |
| --- | --- | --- |
| (등급 개념 없음) | `secret` | 탐지 = 노출. 원본 severity 값과 무관하게 항상 `secret`으로 고정 |

> Gitleaks는 "심각도" 개념이 없는 도구다. `evaluate-gate.py`는 finding에 어떤 값이
> 들어있든 무시하고 `severityMapping.gitleaks.default` 키만 조회한다.

### 3-3. Trivy (Dependency / CVE)

| Trivy 원본 | 공통 등급 |
| --- | --- |
| `CRITICAL` | `critical` |
| `HIGH` | `high` |
| `MEDIUM` | `medium` |
| `LOW` | `low` |
| `UNKNOWN` | `medium` (안전한 쪽으로) |

### 3-4. ZAP (DAST)

| ZAP Alert 등급 | 공통 등급 |
| --- | --- |
| `High` | `high` |
| `Medium` | `medium` |
| `Low` | `low` |
| `Informational` | `low` |

### 3-5. 매핑 실패 시 처리 (Fail-safe)

매핑 테이블에 없는 원본 등급이 들어오면 조용히 통과시키지 않고,
`unknownSeverityFallback`(현재 `medium`)으로 대체한 뒤 해당 finding에 `severity_fallback`
표시를 남긴다. PR 댓글에도 "정책 갱신이 필요하다"는 경고가 함께 노출된다.

> 원칙: **위험도를 모르면 안전한 쪽으로 처리한다(fail-safe).**

---

## 4. Gate 정책 (Merge 차단 / 경고 / 허용)

공통 등급이 정규화되면 아래 규칙으로 최종 판정한다.
`security-gate-policy.json`의 `gateRules`가 이 표의 근거다.

| 공통 등급 | 정책 | Gate 결과 |
| --- | --- | --- |
| `critical` | Merge 차단 | `FAILED` → `exit 1` |
| `high` | Merge 차단 | `FAILED` → `exit 1` |
| `secret` | Merge 차단 | `FAILED` → `exit 1` |
| `medium` | PR 경고 | `PASSED` (Merge 허용, 경고 표시) |
| `low` | 기록만 | `PASSED` |
| 탐지 없음 | 통과 | `PASSED` (Merge 허용) |

```text
blockOnSeverity : ["critical", "high", "secret"]
warnOnSeverity  : ["medium"]
```

### Merge 차단 메커니즘

1. `evaluate-gate.py`가 차단 대상 등급을 발견하면 `exit 1`
2. `aggregate-and-gate` Job 실패 → GitHub Check 실패
3. Branch Protection Rule에서 해당 Check를 **Required**로 지정 → Merge 버튼 비활성화

> Branch Protection Rule 설정은 레포지터리 관리자가 수행한다.
> Settings → Branches → Branch protection rules → Require status checks

---

## 5. CVE 심화 정책 (SBOM 기반 CVSS/EPSS/KEV)

Trivy 단일 등급만으로는 "실제로 악용되고 있는가"를 반영하지 못한다.
SBOM에서 추출한 패키지를 OSV로 조회하고, CVE별로 **실제 악용 여부(KEV)** 와
**악용 예측치(EPSS)** 를 함께 보고 판정하는 별도 파이프라인을 둔다.

| 단계 | 스크립트 | 역할 |
| --- | --- | --- |
| 1 | `sbom-extract-purls.py` | SBOM에서 패키지(purl) 추출 |
| 2 | `osv-query.py` | OSV로 취약점 조회 |
| 3 | `cve-risk-assess.py` | CVE dedup + EPSS/KEV 데이터 수집 |
| 4 | `cve-policy-evaluate.py` | 정책 우선순위로 최종 차단/경고/통과 판정 |

### 판정 우선순위 (위에서부터 먼저 걸리는 규칙 적용)

| 순위 | 조건 | 판정 | 근거 |
| --- | --- | --- | --- |
| 1 | KEV 등재 (`kev_listed = true`) | **차단** | 실제 악용 중 |
| 2 | `epss_score ≥ 0.1` 또는 `epss_percentile ≥ 0.95` | **차단** | 악용 예측 높음 |
| 3 | severity = CRITICAL | **차단** | 심각도 |
| 4 | severity = HIGH | 경고 | 심각도 |
| 5 | `undetermined_risk = true` | 경고 | 등급 정보 없음 |
| 6 | 그 외 | 통과 | — |

### 조회 실패 처리 (지표별 차등)

| 실패 지표 | 처리 방향 | 이유 |
| --- | --- | --- |
| OSV 조회 실패 (패키지) | **fail-closed (차단)** | CVE 자체를 못 봤으므로 판단 불가 |
| KEV 조회 실패 (CVE) | 다른 규칙으로 이미 판정됐으면 유지, 아니면 fail-closed | KEV는 차단을 '추가'하는 규칙 |
| EPSS 조회 실패 (CVE) | fail-open (해당 규칙만 건너뜀) | 예측치라 없어도 CVSS로 판정 가능 |

각 판정에는 걸린 규칙 번호, 근거 지표값(evidence), NVD/OSV 참고 링크를 남겨
**"왜 막혔는지"를 지표와 출처로 설명**한다.

---

## 6. 처리 기준 요약 (등급별 개발자 관점)

| 등급 | 개발자가 해야 할 일 | Merge |
| --- | --- | --- |
| Critical | 즉시 수정. 임시 방편 금지 | ❌ 불가 |
| High | 수정 후 재검사 통과 필요 | ❌ 불가 |
| Secret | **키 즉시 폐기·재발급 → 코드에서 제거 → git history 정리** | ❌ 불가 |
| Medium | PR 경고 확인, 가능하면 이번 PR에서 수정, 아니면 이슈 등록 | ⚠️ 허용 |
| Low | 기록만. 백로그로 관리 | ✅ 허용 |

Secret 노출은 코드 정리보다 **키 폐기가 항상 최우선**이다. 상세 대응은
[Incident Response 플레이북](./incident-response-playbook.md) SEC-01을 따른다.

---

## 7. 정책 변경 방법

기준을 바꾸려면 아래 두 파일만 수정하면 되고, 판정 스크립트는 손대지 않아도 된다.

1. `security/policies/security-gate-policy.json` — 등급 매핑 · Gate 룰
2. `security/policies/remediation-guide.json` — 카테고리별 수정 가이드
3. 그리고 **이 문서(`docs/severity-policy.md`)를 함께 갱신**해 근거를 최신 상태로 유지한다.

CVE 심화 정책의 임계값(EPSS 0.1 등)을 바꿀 때는 `cve-policy-evaluate.py`의
우선순위 규칙과 5절 표를 함께 갱신한다.
