---
문서명: AI 보고서 참고 자료
최신화: 2026-07-26
작성자: A파트
Version: 0.1.0
---

# AI-reference — Security Gate 보고서용 입력 계약

AI 상세 보고서(PR soft gate)를 만들 때 읽어야 할 산출물, 정책 해석, 기본 조치 문구를 정리한다.
이 문서는 **프롬프트/후처리 참고용**이며, Gate 판정 로직을 대체하지 않는다.

사고 대응(SLA·키 폐기 순서·담당자)은 `docs/incident-response-playbook.md`에서 다룬다.
Gate/AI 경로에는 포함하지 않고, 필요 시 링크만 안내한다.

---

## 1. 역할 분리

| 레이어 | 담당 | AI 사용 방식 |
| --- | --- | --- |
| Category Policy (`gate_policy` + `evaluate-gate`) | Block / Warn / Pass | 최종 판정 근거로 인용 |
| CVE Track (`cve_track`) | dependency CVE promote/demote 보정 | `cve_adjustments` / `cve_track` 메타 설명 |
| remediation 기본 가이드 | 카테고리별 일반 조치 | 초안 골격. 그대로 복붙하지 말 것 |
| AI 보고서 | 코드 위치·구체 수정안 | location + 코드 컨텍스트로 구체화 |
| IR 플레이북 | 사람 운영 대응 | 링크/언급만. 본문에 절차 복제 금지 |

한 줄:

> Gate가 “막는지”를 정하고, AI는 “어떻게 고칠지”를 설명한다.

---

## 2. 필수 입력 파일 (runner-local)

AI는 Artifact UI가 아니라 워크플로 runner의 파일을 읽는다.

| 파일 | 용도 |
| --- | --- |
| `security/reports/gate-decision.json` | 최종 판정, block/warn 사유, 리포트별 findings, CVE 보정 |
| `security/reports/security-summary.json` | 집계 요약, 도구별 원본 findings |
| `security/reports/cve-policy-decision.json` | (있으면) KEV/EPSS/CVSS evidence |
| `security/policies/security-gate-policy.json` | Block/Warn 토글 + `cveTrack` 모드 |

선택 입력:

- `security/sbom/generated/cve-risk-assessment.json` — CVE 상세 디버깅
- 앱 소스 트리 — `location` 기준 코드 발췌

---

## 3. `gate-decision.json` 해석 포인트

```json
{
  "gate_status": "PASSED | FAILED",
  "blocked": true,
  "block_reasons": ["..."],
  "warnings": ["..."],
  "suppressed": [],
  "reports": {
    "dependency_scan": {
      "tool": "trivy",
      "findings": [
        {
          "id": "CVE-…",
          "severity": "high",
          "category": "vuln",
          "title": "…",
          "description": "…",
          "location": "requirements.txt:PyYAML",
          "purl": "pkg:pypi/pyyaml@5.3.1",
          "fixedVersion": "5.4"
        }
      ]
    }
  },
  "cve_track": {
    "mode": "monitor | enforce | off",
    "annotate_only": true,
    "promoted": 0,
    "demoted": 0,
    "applied": 0,
    "top_findings": []
  },
  "cve_adjustments": [
    {
      "cve": "CVE-…",
      "purl": "pkg:…",
      "action": "promote | demote",
      "from": "block | warn | pass",
      "to": "block | warn",
      "reason": "…",
      "applied": false
    }
  ]
}
```

보고서 작성 규칙:

1. **최종 판정은 `gate_status` / `blocked`를 따른다.**
   `cve_adjustments[].applied=false` 또는 `annotate_only=true`면 “보정 후보”이지 실제 판정 변경이 아니다.
2. finding의 `category`를 구분해 서술한다.
   - `vuln` / `secret` / `availability` / `scanner-error` → 차단 후보
   - `misconfig` → 경고(헤더/캐시 등). XSS와 혼동하지 말 것
3. dependency finding은 `purl`, `fixedVersion`, CVE adjustment를 함께 설명한다.
4. `suppressed`는 예외 승인된 항목이다. “무시된 버그”로 쓰지 말고 승인 사유/만료일을 적는다.

---

## 4. Category 정책 (차단 철학)

PR soft / Post-merge hard는 **검사 깊이만 다르고 Block 기준은 동일**하다.

| category | 기본 처우 | AI 톤 |
| --- | --- | --- |
| `secret` | Block | 즉시 키 폐기 우선. 코드 정리보다 revoke 먼저 |
| `vuln` critical/high | Block | 실제 도달 경로·패치/우회책 제시 |
| `availability` high/critical | Block | 헬스/스모크/모니터링 장애로 설명 |
| `scanner-error` | Block | 앱 취약점이 아니라 파이프라인 신뢰성 문제 |
| `misconfig` | Warn | 헤더/캐시 등 위생 이슈. 서비스 장애로 과장하지 말 것 |
| medium (비차단) | Warn | 수정 권고. merge 차단 사유로 쓰지 말 것 |

근거 문서: `docs/aggregator-policy-baseline.md`

---

## 5. CVE 보정 레이어 (dependency only)

CVE 트랙은 전체 Gate를 대체하지 않는다.
`dependency_scan` / Trivy / `CVE-*` finding에만 적용한다.

| action | 의미 | AI 서술 |
| --- | --- | --- |
| promote | KEV 등재 등으로 차단 강화 | “실제 악용 중(KEV) — 우선 패치” |
| demote | 저EPSS·no-fix·CVSS 가드 통과 시 차단→경고 | “당장 악용 가능성 낮음. 계획적 업그레이드” |
| keep | Trivy/category 판정 유지 | 보정 없음 |

기본 운영 모드(`security-gate-policy.json`):

- `cveTrack.enabled = monitor`
- `adjustment.annotateOnly = true`

즉 초기에는 보정 내역을 기록만 하고 판정은 category 정책을 따른다.
상세: `docs/cve-track-integration.md`

---

## 6. 카테고리별 기본 조치 문구 (초안 골격)

아래는 E파트 `remediation-guide.json` 계열을 category 정책에 맞게 정리한 **기본 골격**이다.
AI는 이를 출발점으로 쓰고, `location`의 실제 코드/패키지에 맞게 다시 써야 한다.

### secret

- 요약: 코드에 API 키·비밀번호·토큰 등 자격증명이 하드코딩됨
- 조치: **먼저 revoke/재발급** → 코드에서 제거 → env/Secret Manager로 이전 → 필요 시 git history 정리
- 참고: https://github.com/gitleaks/gitleaks

### vuln (SAST)

- 요약: 정적 분석이 코드에서 위험 패턴을 발견
- 조치: `location` 코드를 확인하고 입력 검증/이스케이프, 안전한 API, 위험 함수 대체, 접근 제어 보강
- 참고: https://owasp.org/www-project-top-ten/

### vuln (dependency / CVE)

- 요약: 사용 패키지에서 알려진 CVE가 발견됨
- 조치: `fixedVersion`이 있으면 해당 버전 이상으로 업그레이드. 없으면 완화책·업그레이드 계획 수립. KEV면 최우선
- 참고: https://nvd.nist.gov/ , OSV/KEV evidence(`cve-policy-decision.json`)

### misconfig (runtime headers 등)

- 요약: 보안 헤더 미설정, HTTP Only, cacheable 등 설정 위생 이슈
- 조치: 응답 헤더(CSP, HSTS, X-Frame-Options 등)와 쿠키 플래그를 점검. **confirmed XSS/SQLi와 동일 심각도로 쓰지 말 것**
- 참고: https://owasp.org/www-project-secure-headers/

### availability

- 요약: health/smoke 실패 또는 모니터링상 서비스 미검출
- 조치: 배포/엔드포인트/의존 서비스 상태를 확인하고 게이트 재실행

### scanner-error

- 요약: 필수 보고서 누락, 파싱 실패, 스캐너 실행 실패
- 조치: 앱 취약점 수정이 아니라 워크플로/스캐너/Artifact 경로를 복구

---

## 7. PR 댓글 / AI 보고서 권장 구조

PR soft gate 댓글·AI 보고서는 같은 뼈대를 공유한다.

```text
1. 최종 판단 (PASSED / FAILED)
2. 검사 요약 표 (도구별)
3. 차단 사유 (block_reasons + 대표 finding)
4. 경고 (warnings / misconfig / medium)
5. CVE 보정 요약 (있으면: promoted/demoted/applied, top_findings)
6. finding별 수정 가이드
   - 위치
   - 왜 위험한지 (1~2문장)
   - 구체 수정안 (코드/버전)
   - 참고 링크
7. 다음 행동 (재push / Artifact 확인)
```

그룹핑 권장 키:

1. `category` (+ dependency면 CVE ID)
2. 동일 `location` prefix
3. 동일 패키지(`purl` / 패키지명)

길이 제한 권장:

- PR 댓글: 상위 이슈 중심(차단 이슈 우선, 경고는 요약)
- AI 상세 보고서: Artifact/별도 문서에 전체 finding

---

## 8. AI 프롬프트에 넣을 최소 지시

```text
당신은 Secure Gate 결과를 설명하는 보안 리뷰어다.
- 최종 Block/Warn은 gate-decision.json을 따른다.
- misconfig를 XSS/RCE처럼 과장하지 않는다.
- secret은 코드 수정보다 키 폐기를 먼저 안내한다.
- dependency CVE는 purl, fixedVersion, cve_adjustments를 반영한다.
- annotate_only/monitor 보정은 "후보"로만 언급하고 실제 판정 변경으로 쓰지 않는다.
- remediation 기본 문구를 복붙하지 말고 location 기준으로 구체화한다.
- 출력은 한국어, 실행 가능한 수정 단계 위주.
```

---

## 9. 관련 문서

- `docs/aggregator-policy-baseline.md` — Block/Warn 기준선
- `docs/cve-track-integration.md` — CVE 보정 설계
- `docs/team-interface.md` — 공통 finding 스키마 / 파트 연동
- `security/templates/pr-comment-template.md` — PR 댓글 뼈대
- `docs/incident-response-playbook.md` — 사고/이슈 대응 운영 플레이북
