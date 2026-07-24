---
문서명: Known Issue — 아티팩트 다운로드 경로 불일치 (게이트 댓글 fallback)
최신화: 2026-07-24
작성자: 이정빈 (E파트)
상태: 임시 해소 적용됨(스크립트 방어 탐색) / 정식 해소 대기 (A파트 워크플로)
---

# Known Issue: 아티팩트 다운로드 경로 ↔ 스크립트 읽기 경로 불일치

## 요약
reusable workflow 에서 리포트 아티팩트를 `download-artifact` 로 caller 루트(`path: .`)
에 풀면, upload 시 공통 접두어(`security/reports/`)가 벗겨져 리포트가
**루트 또는 아티팩트명 하위폴더**에 떨어진다. 반면 스크립트는
`security/reports/<name>.json` 을 읽어 **경로가 어긋난다.**

증상: PR 게이트 댓글이 실제 판정 대신 **"결과 파일을 불러오지 못했습니다"
fallback** 으로 나온다(게이트 잡은 성공으로 보이는 속 빈 초록).

## 발견 경위 · 근본 원인 (A파트 워크플로 소유)
개인 repo Actions 실환경 검증(run `30070338471`, PR #3)에서 확인.

| 단계 | 사실(로그) |
| --- | --- |
| 생성 | `security/reports/gate-decision.json` → 아티팩트 `gate-decision`(926B) |
| 업로드 | `upload-artifact` 가 공통 접두어를 벗겨 아티팩트 내부엔 `gate-decision.json` 만 |
| 다운로드 | PR Comment 잡 `download-artifact name:gate-decision path:.` → **`<root>/gate-decision.json`** |
| 읽기 | `create-pr-comment.py` 는 `security/reports/gate-decision.json` 을 봄 → **불일치** |

두 가지 다운로드 패턴이 있다:
- **단일 named 다운로드**(`name:` 지정, `path:.`) → 파일이 **루트**(`./gate-decision.json`).
- **전체 다운로드**(`name:` 없음, `path:.`) → 아티팩트명 **하위폴더**
  (`./gate-decision/gate-decision.json`). Aggregate 잡의 리포트들이 이 케이스라
  `aggregate-results.py` 가 `[WARN] Report not found: …` 를 냈다.

**근본 원인은 워크플로의 download-artifact 경로 설정(A파트 소유)이다.** 스크립트가
아니라 아티팩트 레이아웃 계약의 문제다.

## 임시 해소 (스크립트 방어 탐색, E파트)
정식 해소 전까지 스크립트가 여러 후보 경로를 우선순위로 탐색한다.
공통 헬퍼: `scripts/paths.py` 의 `resolve_report()`.

우선순위:
1. `SECURE_GATE_DECISION` 등 **환경변수**(명시 지정) — 최우선
2. `security/reports/<file>` — 로컬/직접 실행 기본
3. `./<file>` — 단일 named 다운로드(루트 배치)
4. `**/<file>` glob(깊이 제한) — 전체 다운로드(하위폴더 배치) 최후 수단

- 찾은 경로를 stderr 에 로그(`[INFO] … found at: <path>`), 다중 매칭 시 경고.
- 전부 실패면 탐색한 경로 목록을 로그로 남기고 fallback(다음 디버깅 대비).

적용 위치:
- `create-pr-comment.py` → `gate-decision.json` (`SECURE_GATE_DECISION`)
- `evaluate-gate.py` → `security-summary.json`(`SECURE_GATE_SUMMARY`),
  `dependency-report.json`(`SECURE_GATE_DEP_REPORT`),
  `cve-policy-decision.json`(`SECURE_GATE_CVE_DECISION`)

테스트: `tests/test_cve_gate.py::ReportPathResolutionTests`
(후보별 로드·우선순위·glob·fallback).

## 정식 해소 시 (A파트)
워크플로에서 `download-artifact` 의 `path:` 를 `security/reports` 로 지정하거나
아티팩트 업로드 구조를 `security/reports/` 접두어 유지로 바꾸면 경로가 고정된다.
그러면 **이 방어 탐색 로직(후보 3·4, glob)은 불필요**해지고, `resolve_report`
후보를 `security/reports/<file>` 하나로 줄여도 된다. 스크립트는 A파트 워크플로에
어떤 변경도 요구하지 않는다 — 방어선일 뿐이다.

관련: [reusable workflow 경로 모델](../cve-track-integration.md) §1
