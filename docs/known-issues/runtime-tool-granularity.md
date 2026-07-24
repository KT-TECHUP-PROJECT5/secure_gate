# Known issue: runtime-report.json 의 도구 구분 불가

## 증상
`runtime-validation.py` 는 ZAP·Nuclei·Dynatrace 결과를 하나의 공통 스키마
리포트(`security/reports/runtime-report.json`)로 병합하면서 리포트 레벨
`tool` 필드를 **단일 값 `"runtime-validation"`** 으로 고정한다
(scripts/runtime-validation.py, `"tool": "runtime-validation"`).

`aggregate-results.py` 는 이를 `reports["runtime_validation"]` 로 싣고,
`evaluate-gate.py` 의 `build_findings()` 는 **리포트 레벨 `tool` 하나로**
severityMapping / toolCategoryMap 을 조회한다. 개별 finding 이 어느 스캐너에서
왔는지는 이 시점에 이미 사라져 있다.

## 영향
- **도구별 차등 정책 불가.** "Nuclei critical 은 차단하되 ZAP informational 은
  무시" 같은 스캐너별 규칙을 세울 수 없다. 세 도구가 같은 매핑을 공유한다.
- severityMapping 에 `runtime-validation` 키가 없으면 모든 런타임 finding 이
  `unknownSeverityFallback`(medium/warn)으로 떨어져, 런타임 critical 이
  조용히 warn 으로 새는 fail-open 이 발생한다.

## 현재 대응 (임시 해소책)
`security-gate-policy.json` 에 통합 매핑을 추가했다:
- `severityMapping["runtime-validation"]`: 공통 소문자 severity 항등 매핑 +
  `info`/`informational` → `low`, `unknown` → `medium`.
  (`info` 를 fallback(medium)으로 흘리면 ZAP/Nuclei informational 이 전부
  warn 이 되어 노이즈가 폭발하므로 명시적으로 `low` 로 내린다.)
- `toolCategoryMap["runtime-validation"]` = `dast` (기존 카테고리 재사용).
  `runtime` 신규 카테고리는 만들지 않는다 — 만들면 기존 게이트 룰과 PR 댓글
  렌더링을 전부 손봐야 한다.

이는 **임시 해소책**이다. 세 도구를 한 severity 밴드로 뭉뚱그리는 한계를
그대로 안고 간다.

## 향후 필요한 것
`runtime-report.json` 의 각 finding 에 **`source` 필드**(예: `"zap"` /
`"nuclei"` / `"dynatrace"`)를 추가하고, 게이트가 리포트 레벨 `tool` 이 아니라
finding 레벨 `source` 로 매핑/정책을 적용하도록 확장한다. 그래야 스캐너별
차등 정책이 가능해진다. (소유: D파트 runtime-validation + E파트 게이트 공동)
