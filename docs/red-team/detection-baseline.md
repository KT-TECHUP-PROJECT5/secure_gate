# Red Team 탐지 기준선

## 목적

`web/`에 실제로 구현된 취약점과 C·D 파트 자동 스캔 결과를 교차검증한다.

## 도구별 기대치

| 취약점 | SAST | DAST | Dependency | 수동 PoC | 비고 |
| --- | --- | --- | --- | --- | --- |
| 로그인/검색 SQLi | 기대 | 기대 | 비대상 | 필수 | Raw SQL 문자열 조합 |
| Stored/Reflected XSS | 기대 | 기대 | 비대상 | 필수 | Jinja `safe` 사용 |
| IDOR/관리자/삭제 권한 우회 | 미탐 가능 | 미탐 가능 | 비대상 | 필수 | 상태·권한 문맥 필요 |
| 무제한 파일 업로드 | 일부 기대 | 일부 기대 | 비대상 | 필수 | 확장자·MIME·크기 |
| 약한 비밀번호/잠금 미구현 | 미탐 가능 | 미탐 가능 | 비대상 | 필수 | 반복 시도 필요 |
| 보안 로그·알림 누락 | 미탐 가능 | 미탐 가능 | 비대상 | 필수 | 비기능성 요구사항 |
| 예외/DB/경로 노출 | 일부 기대 | 기대 | 비대상 | 필수 | `/debug/*` |
| 보안 헤더 누락 | 비대상 | 기대 | 비대상 | 필수 | CSP, XFO, XCTO |
| 구버전 의존성 | 비대상 | 비대상 | 기대 | 확인 | `requirements-legacy.txt` |

## 판정 기준

### 정상 탐지

- 탐지 결과가 실제 취약 코드 또는 URL과 일치한다.
- 제공된 페이로드로 재현하였을 때 기대한 보안 영향이 발생한다.

### 미탐

- `web/docs/vulnerability-matrix.md`에 `O`로 표시된 취약점이 수동 PoC로 성공하지만
  해당 도구 결과에 없다.
- 도구 성격상 탐지가 어려운 IDOR·비즈니스 로직은 일반 미탐과 구분해 기록한다.

### 오탐

- 도구가 지정한 코드·URL에 해당 취약점이 존재하지 않고 페이로드로도 재현되지 않는다.
- 단순 키워드 일치나 실행되지 않는 테스트 문서 탐지는 별도로 표시한다.

## 교차검증 표 양식

| ID | 취약점 | 수동 PoC | SAST | DAST | Dependency | 판정 | 원인 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| B-01 | Login SQLi | Pass |  |  | N/A |  |  |
| B-02 | Search SQLi | Pass |  |  | N/A |  |  |
| B-05 | IDOR | Pass |  |  | N/A |  |  |

## 결과 연동

- C 파트: `security/reports/sast-report.json`, `secret-report.json`, `dependency-report.json`
- D 파트: `security/reports/runtime-report.json`
- B 파트 기대치: `security/baselines/redteam-expected-findings.json`
