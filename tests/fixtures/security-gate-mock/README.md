# Security Gate Mock Fixtures

C/D파트(Semgrep/Gitleaks/Trivy/ZAP) 실제 연동 전, `evaluate-gate.py`의
severity 매핑·차단/경고 판정 로직을 검증하기 위한 더미 결과 파일입니다.
`docs/team-interface.md`의 공통 결과 스키마를 따르되, 각 도구의 실제 원본
severity 표기(Semgrep: ERROR/WARNING, Trivy: CRITICAL 등)를 그대로 흉내냅니다.

## 포함된 케이스

| 파일 | 도구 | 케이스 | 기대 결과 |
| --- | --- | --- | --- |
| `dependency-report.json` | Trivy | `CRITICAL` | critical → 차단 |
| `sast-report.json` | Semgrep | `ERROR` | high → 차단 |
| `secret-report.json` | Gitleaks | severity 필드 없음 | secret(고정) → 차단 |
| `sast-report.json` | Semgrep | `WARNING` | medium → 경고만 |
| `dependency-report.json` | Trivy | `SUPER_BAD` (매핑표 미등록 가짜 값) | fallback medium + `severity_fallback` 표시 + 경고 |
| `build-report.json`, `runtime-report.json` | - | findings 없음 | 영향 없음 (Job placeholder 상태 재현용) |

## 재현 방법

레포 루트에서 실행:

```bash
cp tests/fixtures/security-gate-mock/*.json security/reports/
python3 scripts/aggregate-results.py
python3 scripts/evaluate-gate.py; echo "EXIT_CODE=$?"
```

`security/reports/gate-decision.json`에서 `blocked: true`, `EXIT_CODE=1`,
`findings` 배열의 각 항목 `severity`/`blocking`/`severity_fallback` 값을 확인하면 됩니다.
(`security/reports/*.json`은 `.gitignore` 대상이라 실행 후 생성물은 커밋되지 않습니다.)
