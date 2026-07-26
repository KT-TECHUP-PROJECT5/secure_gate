---
문서명: E파트(5단계) 작업 공유 — Security Gate 판정/정책/CVE 트랙
최신화: 2026-07-24
작성자: 이정빈 (E파트)
대상: 같은 팀 다른 파트 담당자
---

# E파트(5단계) 작업 공유

E파트는 각 스캐너(SAST/Secret/Dependency/DAST)의 탐지 결과를 받아 **Merge를
차단할지 말지 최종 판정**하고, 그 근거를 PR 댓글로 돌려주는 판정 계층을 담당한다.
아래는 산출물 하나하나가 무엇을 하고 어떤 값으로 어떻게 동작하는지, 그리고 현재
코드가 서로 맞물리는 지점과 검증 상태·미해결 이슈를 정리한 것이다.

---

## 1. 산출물 상세

### (a) 정책 파일

판정 로직은 코드에 하드코딩하지 않고 **정책 JSON을 데이터로 읽어** 동작한다.
기준을 바꾸려면 아래 JSON만 고치면 되고 스크립트는 손대지 않는다.

#### `security/policies/security-gate-policy.json` — 게이트 정책의 단일 출처

버전 `2.1`. 5개 섹션으로 게이트 전체 동작을 제어한다.

**① `severityMapping` — 도구 원본 등급 → 공통 등급 변환표**

각 도구가 쓰는 스케일이 달라서 공통 등급(critical/high/medium/low/secret)으로
정규화한다. 실제 값:

| 도구 | 원본 → 공통 |
| --- | --- |
| `semgrep` | ERROR→high, WARNING→medium, INFO→low |
| `gitleaks` | `default`→secret (원본 severity 무시, 탐지=노출이므로 항상 secret) |
| `trivy` | CRITICAL→critical, HIGH→high, MEDIUM→medium, LOW→low, **UNKNOWN→medium** |
| `zap` | High→high, Medium→medium, Low→low, **Informational→low** |
| `runtime-validation` | critical/high/medium/low 항등, **info·informational→low, unknown→medium** |

- `trivy.UNKNOWN→medium`, `runtime-validation.unknown→medium`은 "위험도 모르면
  안전한 쪽으로(fail-safe)" 원칙. 조용히 통과시키지 않는다.
- `zap.Informational→low`, `runtime-validation.info→low`는 반대로 노이즈 억제.
  info를 fallback(medium)으로 흘리면 informational이 전부 경고가 되어 폭발한다.
  그래서 명시적으로 low로 내린다.

**② `toolCategoryMap` — 도구 → 수정 가이드 카테고리**

`semgrep→sast`, `gitleaks→secret`, `trivy→dependency`, `zap→dast`,
`runtime-validation→dast`. 이 카테고리로 `remediation-guide.json`의 가이드를
finding에 주입한다. `runtime-validation`을 신규 `runtime` 카테고리로 만들지
않고 기존 `dast`를 재사용한 이유는 (c)의 known-issue 참고.

**③ `gateRules` — 차단/경고 규칙 (판정의 핵심)**

```json
"blockOnSeverity": ["critical", "high", "secret"],
"warnOnSeverity":  ["medium"]
```

blockOnSeverity에 하나라도 걸리면 `FAILED`(exit 1) → Merge 차단.
warnOnSeverity는 통과시키되 경고 표시. low는 어디에도 없어 기록만 된다.

**④ `unknownSeverityFallback`: `medium`** — severityMapping에 없는 원본 등급이
들어오면 조용히 통과 대신 medium으로 대체하고 finding에 `severity_fallback`
표시 + "정책 갱신 필요" 경고를 남긴다.

**⑤ `cveTrack` — CVE 심화 신호(KEV/EPSS/CVSS) 보정 레이어 제어**

이 섹션이 E파트에서 가장 설계 판단이 많이 들어간 부분이다. 주요 값:

```json
"enabled": "monitor",              // off / monitor / enforce
"decisionFile": "security/reports/cve-policy-decision.json",
"runner": { "runnerId": "cve-policy-evaluate", "allowSelfInvoke": true },
"timeoutSeconds": 120,
"onTrackFailure": {                // 실패 유형별 차등
  "scriptError":     "failClosed", // 실행했으나 산출물 없음 → 안전하게 차단
  "dataUnavailable": "failOpen",   // 앞단 미실행(SBOM 없음) → 통과
  "timeout":         "failOpen"
},
"bypass": { "enabled": true, "signalEnv": "CVE_TRACK_BYPASS",
            "scope": "trackFailureOnly" },
"adjustment": {
  "annotateOnly": true,            // 표시만, 판정 미변경 (초기 운영 기본값)
  "promote": { "kev": true },      // KEV 등재 → severity 무관 차단
  "demote": {                      // 저위험 강등 (다중 조건 AND)
    "requireNotKev": true,
    "maxEpss": 0.1,
    "minSeverity": "high",
    "demoteOnlyWhenNoFix": true,
    "neverDemoteAtOrAboveCvss": 9.0
  }
}
```

- `enabled: monitor` — 현재 기본값. 트랙을 실행·기록하되 blocked에는 반영하지
  않는다(dry-run). 앞단(SBOM→OSV→CVE) 연결 검증 전이라 보수적으로 monitor.
- `onTrackFailure`가 실패를 **유형별로** 다르게 처리하는 게 핵심 설계. 스크립트가
  깨진 것(scriptError)은 차단하고, 애초에 앞단이 안 돌아 데이터가 없는 것
  (dataUnavailable)은 통과시킨다 — "앞단 미가동"으로 전체 파이프라인이 막히지
  않게 한다.
- `bypass.scope: trackFailureOnly` — 우회는 **트랙 실패의 fail-closed만** 열고,
  유효한 CVE block 판정은 절대 못 연다. 게이트 무력화 방지. 코드로 강제한다.
- `adjustment`는 **추가 차단 레이어가 아니다.** Trivy 판정을 promote/demote/keep
  으로 보정할 뿐이다(판정 기준은 §2.3).

**⑥ `decisionMerge`**: `strategy: fail-closed`. `cveVerdictActions`(block→block,
warn→warn, pass→pass)는 non-dependency 카테고리용으로만 예약. 의존성 CVE는
adjustment가 담당하고 여기서 이중 차단하지 않는다.

#### `security/policies/cve-policy.json` — 독립 CVE 리포트 임계값

버전 `1.1.0`. `cve-policy-evaluate.py`가 verdict를 산정할 때 쓰는 임계값만 담는다.

```json
"reportThresholds": {
  "epss": { "blockThreshold": 0.1, "percentileBlockThreshold": 0.95 },
  "cvss": { "severityVerdicts": { "CRITICAL": "block", "HIGH": "warn" } }
}
```

- **왜 게이트 정책과 분리했나**: 여기 `epss.blockThreshold(0.1)`은 독립 CVE
  리포트의 차단 임계값이고, `security-gate-policy.json`의
  `adjustment.demote.maxEpss(0.1)`는 게이트 강등 판단이다. **숫자는 같아도 의미가
  다르므로** 네임스페이스를 분리해 "같은 값이 다른 곳에서 다른 의미로" 보이는
  혼란을 막았다.

#### `security/policies/policy-schema.json` — 정책 검증 스키마

- **검증 범위**: `evaluate-gate.py`가 시작 시 이 스키마를 파싱해 required/type/enum
  을 해석한다(규칙을 코드에 하드코딩하지 않는다). 검증 실패 시 정책 무결성이
  불확실하다고 보고 **fail-closed로 차단**한다.
- draft/2020-12 형식이되 검증기는 stdlib만으로 구현한 경량 검증기(§b 참고).
- **현재 한계**: `type`/`required`/`enum`/`properties`/`items`만 해석한다.
  `$comment`는 사람이 읽는 계약 설명일 뿐 검증에 쓰이지 않고, `minimum`/`maximum`
  /`pattern`/조건부 스키마는 미지원. 예를 들어 `maxEpss`가 음수여도 스키마는 통과
  한다(값 범위 검증은 소비 스크립트가 따로 한다 — cve-policy-evaluate는 0~1 범위를
  fail-hard로 검사).

#### `security/policies/profiles/{strict,balanced,monitor}.json` — 운영 강도 오버레이

full 정책이 아니라 **`cveTrack` 노브만 담은 오버레이**다. base 정책 위에 깊은
병합된다. caller가 `SECURE_GATE_PROFILE=strict`처럼 **이름만** 지정한다.

| 프로파일 | enabled | annotateOnly | demote | 효과 | 용도 |
| --- | --- | --- | --- | --- | --- |
| **strict** | enforce | false | **off** (`demote.enabled:false`) | 승격(KEV)만, **강등 없음 — 모든 차단 유지** | 규제·릴리스 브랜치 |
| **balanced** | enforce | false | on | 승격 + 저위험 강등 **판정 반영** | 앞단 연결 후 정상 운영 |
| **monitor** | monitor | — | 기록만 | 보정·실패차단 blocked 미반영(dry-run) | 앞단 연결 전 관찰 |

실제 파일 내용(오버레이라 매우 짧다):
- `strict.json`: `cveTrack.enabled=enforce`, `adjustment.annotateOnly=false`,
  `adjustment.demote.enabled=false`
- `balanced.json`: `cveTrack.enabled=enforce`, `adjustment.annotateOnly=false`
- `monitor.json`: `cveTrack.enabled=monitor`

설계 판단: `strict`의 강등 비활성을 `annotateOnly`가 아니라 `demote.enabled=false`
로 구현한 이유는, 승격은 유지하면서 강등만 끄기 위해서다(차단은 늘 뿐 줄지
않으므로 안전). 프로파일 이름은 화이트리스트로만 해석하고 알 수 없는 이름은
**fail-hard**(오타로 의도한 정책이 안 걸리는 사고 방지).

#### `security/policies/remediation-guide.json` — 카테고리별 수정 가이드

`sast/secret/dependency/dast` 4개 카테고리 각각에 `label`, `summary`,
`recommendation`, `reference`(OWASP/gitleaks/NVD/ZAP 링크). PR 댓글의 수정 가이드
블록에 자동 주입된다. `secret` 항목은 "코드 정리보다 **키 즉시 폐기·재발급이
최우선**"을 명시해 대응 순서를 강제한다.

---

### (b) 판정 엔진

#### `scripts/evaluate-gate.py` — 유일한 판정 진입점

실행 흐름을 단계별로:

1. **정책 로드** (`resolve_policy_file`) — `SECURE_GATE_POLICY` env 우선(caller
   override 허용), 없으면 툴링 기본. 프로파일(`SECURE_GATE_PROFILE`)이 지정되면
   `_deep_merge`로 base에 오버레이.
2. **스키마 검증** (`validate_policy`) — `policy-schema.json`을 파싱해 병합된 정책을
   검증. 실패 시 fail-closed(exit 1). 스키마 자체를 못 읽어도 fail-closed.
3. **findings 구성** (`evaluate` → `maybe_inject_trivy` → `build_findings`) —
   - `maybe_inject_trivy`: `dependency_scan`에 findings가 없으면 raw Trivy
     (`dependency-report.json`)를 `normalize-trivy.py`로 in-process 정규화해 채운다.
     **cveTrack 상태와 무관하게 항상** 동작 → cveTrack=off여도 Trivy 판정은 생존.
   - `build_findings`: 각 finding의 severity를 정규화하고 blocking/warning 계산,
     카테고리별 guide 주입. 보정 레이어용 optional 필드 `purl`,`fixedVersion`도 실음.
4. **CVE 트랙 로드** (`load_cve_decision`) — 이중 경로:
   - 먼저 `cve-policy-decision.json`이 있으면 읽는다(필수 키 5개로 유효성 판정:
     total_cves, block_count, warn_count, package_failures, cves).
   - 없으면 화이트리스트 runner(`cve-policy-evaluate`)를 직접 실행(allowSelfInvoke).
   - 실패는 유형 분류: timeout / scriptError(SBOM 있음+산출 없음) /
     dataUnavailable(SBOM 없음).
5. **보정 적용 + 병합** (`apply_cve_track`) — dependency finding을 (purl,CVE)로
   evidence와 매칭해 promote/demote/keep 결정. `annotateOnly`거나 monitor면 표시만
   하고 판정은 안 바꾼다. 트랙 실패는 `onTrackFailure` 정책대로 처리. 이 전체를
   `try/except`로 감싸 **어떤 예외도 게이트를 조용히 무너뜨리지 못하게** 하고,
   예외 시 산출물을 반드시 쓰고 fail-closed 차단한다.
6. **판정 + 산출** — `gate-decision.json`에 결과 저장. blocked면 exit 1.

경로 모델(신뢰 경계) — 파일별 소유권을 다르게 잡는다:

| 파일 | 위치 | caller override |
| --- | --- | --- |
| POLICY | `SECURE_GATE_POLICY` env 우선 | **허용** (프로젝트별 조정) |
| GUIDE | caller cwd 우선 | **허용** |
| SCHEMA | 툴링 루트 고정(`__file__` 역산) | **불허** |
| RUNNER | 툴링 루트 고정 | **불허** |
| 리포트 산출물 | caller cwd | — |

SCHEMA/RUNNER를 불허하는 이유: caller가 느슨한 자기 스키마로 검증을 무력화하거나
runner를 임의 스크립트로 바꿔치기하는 신뢰 경계 침범을 막기 위해서다. 정책 JSON은
실행 명령을 담지 않고 `runnerId`만 지정하며, 실제 argv/입력경로는 코드
(`RUNNER_WHITELIST`)가 소유한다.

내장 경량 스키마 검증기(`_schema_validate`): 외부 라이브러리 없이 stdlib만으로
type/required/enum/properties/items를 재귀 해석한다. 의존성 없이 돌리기 위한 선택.

#### `scripts/normalize-trivy.py` — raw Trivy → 공통 스키마 변환

핵심 함수 `normalize(raw)`: raw Trivy JSON(SchemaVersion 2)의
`Results[].Vulnerabilities[]`를 순회하며 각 취약점을 공통 스키마 finding으로 변환.

- 매핑: `VulnerabilityID→id`, `Severity→severity`(CRITICAL/HIGH/...), `Title→title`,
  `PkgName@InstalledVersion→location`.
- optional 2개: `PkgIdentifier.PURL→purl`, `FixedVersion→fixedVersion`. 보정
  레이어가 (purl,CVE) 매칭과 fix 여부 판단에 쓴다. 기존 소비자는 무시하므로 무해.
- findings가 하나라도 있으면 `status: failed`, 없으면 `passed`.
- **왜 별도 스크립트인가**: C파트 Trivy는 raw JSON을 쓰는데 A파트 aggregator는
  공통 스키마를 기대해 그 사이가 비어 있다(§3, known-issue). 이 스크립트는 그
  갭의 임시 해소책이며 `evaluate-gate.py`가 in-process로 호출한다. 워크플로 YAML/
  aggregate-results.py는 건드리지 않는다.

#### CVE 트랙 4단계 (`scripts/`)

Trivy 단일 등급만으로는 "실제로 악용되는가"를 반영 못 하므로, SBOM 기반으로
KEV(실제 악용)·EPSS(악용 예측)·CVSS를 조회하는 별도 파이프라인.

| 단계 | 스크립트 | 역할 |
| --- | --- | --- |
| 1 | `sbom-extract-purls.py` | CycloneDX SBOM에서 purl 추출 |
| 2 | `osv-query.py` | OSV.dev로 취약점 조회 → CVE 정규화 |
| 3 | `cve-risk-assess.py` | CVE dedup + EPSS/KEV 조회 |
| 4 | `cve-policy-evaluate.py` | 정책 우선순위로 차단/경고/통과 판정 |

**1) `sbom-extract-purls.py`** — `extract_components(sbom)`가 `components`를 **재귀**
순회(CycloneDX는 transitive dep를 중첩시킨다). purl 없는 노드(앱/OS 그룹 노드)는
`[WARN]`으로 건너뛴다(정상). 입력은 `security/reports/sbom.cdx.json`(C파트 계약).

**2) `osv-query.py`** — `POST /v1/querybatch`로 purl별 취약점 ID를 받고,
`GET /v1/vulns/{id}`로 상세를 조회해 `aliases`에서 `CVE-` 값을 추출. GHSA/PYSEC는
그 자체로 CVE가 아니므로 CVE로 정규화되는 것과 안 되는 것(`cve_status: no_cve`)을
모두 남긴다. 네트워크 실패 시 파이프라인을 죽이지 않고 `_osv_lookup_failed`로
표시해 뒤 단계가 "판단 불가"로 처리하게 한다.

**3) `cve-risk-assess.py`** — `dedup_by_cve`로 같은 CVE의 여러 osv_id를 합치고,
`resolve_severity`로 등급 여러 개 중 최고를 채택(없으면 `severity_available=false`).
EPSS는 FIRST.org에서 100개씩 배치 조회, KEV는 CISA 카탈로그 통째로 받아 cveID
집합. **조회 실패를 지표별로 다르게** 남긴다:
- OSV 실패 패키지 → `osv_failed_packages`로 따로 실어 4단계가 fail-closed.
- EPSS 실패 → `epss_lookup_failed=true`(CVSS로 판정 가능하므로 계속).
- KEV 실패 → `kev_lookup_failed=true`.
- 등급도 KEV도 EPSS 신호도 없으면 `undetermined_risk=true`.

**4) `cve-policy-evaluate.py`** — 3단계 데이터를 **정책 우선순위**로 판정. 규칙은
위에서부터 먼저 걸리는 것 적용:

| 순위 | 조건 | 판정 |
| --- | --- | --- |
| 1-KEV | `kev_listed=true` | block (실제 악용) |
| 2-EPSS | `epss_score≥0.1` 또는 `epss_percentile≥0.95` | block (악용 예측) |
| 3-CVSS | severity=CRITICAL→block, HIGH→warn | (라벨 `3-CRITICAL`/`3-HIGH`로 세분) |
| 5-UNDETERMINED | `undetermined_risk=true` | warn |
| 6-DEFAULT | 그 외 | pass |

- 임계값(EPSS 0.1/0.95, CVSS verdict)은 `cve-policy.json`에서 읽고, 값이 0~1 범위
  float가 아니면 **fail-hard**. 조용히 기본값으로 넘어가지 않는다.
- 조회 실패 후처리: OSV 실패는 `package_failures`(rule `0-OSV-UNAVAILABLE`/block)로
  cves[]와 분리(cve/severity가 없어 성격이 다르다). KEV 실패는 이미 block/warn이면
  유지하고 pass인 것만 `1F-KEV-UNAVAILABLE`/block으로 올린다. EPSS 실패는 규칙만
  건너뛰고 경고.
- 각 판정에 걸린 규칙 번호 + evidence(kev/epss/severity) + NVD/OSV 링크를 남겨
  "왜 막혔는지"를 지표와 출처로 설명. 패키지 단위 요약(업그레이드 대상 버전 추천)도
  함께 만든다.
- 산출: `cve-policy-decision.json`. 이게 게이트 보정의 evidence 공급원이다.

#### `scripts/severity.py` — 등급 상수의 단일 출처 (세 축 분리)

이번 리팩터링의 핵심은 "심각도"라는 한 단어에 섞여 있던 **세 축을 분리**한 것:

| 상수 | 값 | 용도 |
| --- | --- | --- |
| `SEVERITY_RANK` | critical=4, high=3, medium=2, low=1 | 강등 판정(minSeverity 비교·가드). **secret 제외** |
| `DISPLAY_ORDER` | secret, critical, high, medium, low, info | PR 댓글 표시 우선순위 |
| `CVSS_BAND_FLOOR` | critical=9.0, high=7.0, medium=4.0, low=0.1 | 강등 가드(`neverDemoteAtOrAboveCvss`) |
| `OSV_GRADE_RANK` | CRITICAL=4, HIGH=3, MODERATE=2, LOW=1 | OSV 외부 어휘 순위(여러 등급 중 최고 선택) |

- **`SEVERITY_RANK`에서 secret을 뺀 이유**: secret은 CVSS/EPSS 축이 없다. 같은 축에
  0으로 끼우면 "가장 안 심각"이라는 잘못된 의미가 되고 minSeverity 비교에서 우연히
  제외되는 것에 의존하게 된다. 그래서 보정 로직 진입 시점에 명시적으로 제외한다.
- **`DISPLAY_ORDER`에서 secret이 최상단인 이유**: 자격증명 노출은 수정 긴급도가
  가장 높아 개발자가 댓글을 열었을 때 제일 먼저 봐야 한다. 심각도 등급 축과는
  별개의 "표시" 축이다.
- `OSV_GRADE_RANK`는 키가 다르다(MODERATE 존재, secret 없음) — 내부 어휘와 섞지
  않으려고 별도 유지.

#### `scripts/paths.py` — 리포트 경로 방어 탐색

`resolve_report(filename, env_var=...)`가 리포트를 우선순위로 탐색: ①env 명시
경로 → ②`security/reports/<file>` → ③`./<file>` → ④glob(깊이 제한). 첫 존재 경로를
쓰고 다중 매칭 시 경고, 전부 실패면 탐색한 경로 목록을 로그로 남긴다. 배경은
§3·(e)의 아티팩트 경로 불일치 이슈.

---

### (c) 리포트

#### `scripts/create-pr-comment.py` — PR 댓글 생성

`gate-decision.json`을 읽어 GitHub API(urllib, 외부 의존성 0)로 PR 댓글을 단다.
비-PR 이벤트(push 등)에서는 `PR_NUMBER`가 비어 조용히 스킵한다.

**댓글 구조** (해당 데이터가 있을 때만 각 섹션 표시):
1. 최종 판단 (항상) — `Gate Status: ✅ PASSED` / `❌ FAILED`
2. **CVE 트랙 배너** (조건부, 아래)
3. 검사 요약 표 (항상) — Build/SAST/Secret/Dependency/Runtime 5행, 각
   `✅ Passed`/`❌ Failed`/`⚠️ Warning`/`⚠️ Not Run`
4. 차단 사유 / 경고 (있을 때만)
5. CVE 보정 내역 표 (보정이 있을 때만) — CVE/패키지/조치(🔺승격·🔻강등)/변화/
   반영·표시만/근거
6. 수정 가이드 (차단·경고 finding이 있을 때만)
7. 푸터 (항상)

**배너 3종** (`build_banner`, 한 곳에서 결정 — 조용한 fail-open이 가장 위험하므로
최종 판단 바로 아래 blockquote로 눈에 띄게 렌더). 우선순위: bypass > 트랙 실패 >
monitor 정상:

| 배너 | 색 | 조건 |
| --- | --- | --- |
| 우회 적용 | 🟠 | `suppression.active` — CVE 검증 없이 통과, 사유 요청 |
| 트랙 실패(monitor) | 🔵 | source=failed, mode=monitor — 기록만 |
| 트랙 실패(fail-closed) | 🔴 | source=failed, would_block — Merge 차단 |
| 트랙 실패(fail-open) | 🟡 | source=failed, 차단 안 함 — CVE 트랙 없이 판정 |
| monitor 정상 | 🔵 | mode=monitor, 정상 — 차단후보 N건 기록만 |

배너가 판정을 **재추론하지 않도록** 게이트가 `cve_track.would_block`,`block`,`warn`
같은 사실을 산출물에 그대로 실어 준다.

**그룹화 규칙** (`guide_group_block`): 같은 카테고리 finding은 가이드를 한 번만
쓰고 위치는 그룹당 최대 `MAX_LOCATIONS_PER_GROUP=10`개만. 취약점이 많아도 댓글이
GitHub 한계(65536자)를 넘지 않게 한다. 그룹 내부는 `DISPLAY_ORDER`로 정렬(secret
최상단). 그래도 넘치면 `MAX_COMMENT_CHARS=60000`에서 잘라내고 "아티팩트 확인" 안내.

#### `security/templates/pr-comment-template.md`

위 스크립트가 실제로 만드는 댓글 구조의 사람용 설명서. 스크립트 출력과
동기화되어 있으며 스크립트를 바꾸면 이 문서도 함께 갱신한다.

---

### (d) 검증

#### `tests/test_cve_gate.py` — 게이트 판정 회귀 (44건)

> 프롬프트에 37건으로 적혀 있었으나, 이후 커밋(monitor+bypass 조합,
> runtime-validation e2e 등)으로 늘어 **현재 실측 44건**이다.

주요 케이스(클래스별):
- `CveGateTests`(18) — 판정 코어: cve dep block/pass, 트랙 실패 유형별
  (scriptError→failClosed / dataUnavailable→failOpen / timeout), bypass가 트랙
  실패는 강등하되 **유효 block은 못 여는지**, KEV medium 승격, critical 가드가
  강등 막는지, high 저위험 강등, annotateOnly 시 판정 불변, 매칭 실패 시 Trivy
  유지, fix 있으면 강등 안 함, cveTrack=off여도 Trivy 생존, CVE-only KEV 표면화,
  would_block 사실 반영, 문자열/쓰레기 EPSS가 크래시 안 내는지, 손상된 의존성
  리포트가 조용히 fail-open 안 되는지, runtime-validation 매핑 e2e.
- `LoadClassifyUnitTests` — timeout 분류, 보정 예외 시에도 산출물 쓰고 차단.
- `BannerRenderTests` — fail-closed는 🔴(🟡 아님), fail-open은 🟡, monitor는 건수.
- `ProfileTests` — deep-merge 비파괴, 알 수 없는 프로파일 fail-hard, strict가
  차단 유지, balanced가 보정 반영, monitor가 enforce를 dry-run으로 덮음.
- `MonitorBypassTests` — monitor+bypass 조합.
- `ReportPathResolutionTests` — 경로 후보/우선순위/glob/fallback.
- `SeverityConstantsTests` — SEVERITY_RANK가 secret 제외, DISPLAY_ORDER 순서,
  secret finding은 보정 대상 아님.

#### `tests/test_cve_policy.py` — CVE 정책 판정 회귀 (32건)

`cve-policy-evaluate.py`의 판정 레이어를 검증: KEV/EPSS/CVSS 우선순위, 조회 실패
지표별 처리(OSV fail-closed / KEV 조건부 / EPSS fail-open), 임계값 fail-hard,
패키지 요약·업그레이드 추천, 규칙 라벨/evidence. **합계 44+32 = 76건 전부 통과.**

#### `docs/policy-validation-matrix.md` — 탐지 축/정책 축 분리 실측

두 축을 분리한다: **탐지 축**(도구가 취약점을 잡는가 — C·D 책임)과 **정책 축**
(잡힌 finding을 게이트가 올바르게 판정하는가 — E 책임). B파트 red-team PoC 11종을
ground truth로 삼는다.
- **정책 축 실측(2026-07-24)**: GT 11건을 실제 `evaluate-gate.py`로 태운 결과
  `FAILED`/`blocked=True`. block 7건(critical 1+high 6: B-01,02,03,05,06,07,08),
  warn 4건(medium: B-09,10,11,12). 즉 **GT 심각도대로 탐지되기만 하면 정책은
  정확히 판정**한다(정책 축 무결).
- medium 4건은 재평가 후 **전부 medium 유지**(일괄 승격 안 함) 결론. 근거는 각
  건별로 기록(B-11은 노출 "내용"에 따라 위험이 갈리므로 DAST 실측과 교차확인 후
  개별 승격, B-09/10/12는 심층방어·비기능 성격이라 단독 차단 과함).
- **탐지 축**은 B+C+D 통합 시점에 채우는 체크리스트로 남겨 둠(아직 미통합).

---

### (e) 문서

| 문서 | 내용 |
| --- | --- |
| `docs/severity-policy.md` | 등급 체계·도구별 매핑·Gate 룰의 사람용 근거. 정책 JSON과 1:1 동기화 |
| `docs/incident-response-playbook.md` | 사고 대응 SLA(P1 즉시/P2 당일/P3 스프린트) + SEC-01~05 절차. Secret 노출은 키 폐기 최우선 |
| `docs/cve-track-integration.md` | CVE 트랙 통합 설계(경로 모델·보정 레이어·네임스페이스·프로파일·결정 기록) |
| `docs/known-issues/*` | 아티팩트 경로 불일치 / Trivy 노멀라이저 갭 / runtime 도구 구분 불가 (§5) |

결정 기록(`cve-track-integration.md` §6): 악용 신뢰도를 별도 "Confidence 축"으로
두지 **않고** EPSS/KEV 실증 지표를 채택(중복 축 회피). 보류 항목은 설계 방향만
기록: per-finding suppression(승인자·만료 필수), 정책 효과 측정 지표
(gate-decision 이력 집계).

---

## 2. 판정 기준

### 2.1 도구별 severity 매핑 (실제 값)

| 도구 | 원본 → 공통 등급 |
| --- | --- |
| Semgrep | ERROR→high · WARNING→medium · INFO→low |
| Gitleaks | (원본 무시) → **secret 고정** |
| Trivy | CRITICAL→critical · HIGH→high · MEDIUM→medium · LOW→low · UNKNOWN→**medium** |
| ZAP | High→high · Medium→medium · Low→low · Informational→**low** |
| runtime-validation | critical/high/medium/low 항등 · info·informational→**low** · unknown→**medium** |
| (매핑 없음) | → `unknownSeverityFallback`=**medium** + `severity_fallback` 경고 |

### 2.2 차단 / 경고 / 기록 규칙

| 공통 등급 | 판정 | Gate 결과 |
| --- | --- | --- |
| critical / high / secret | **차단** | FAILED → exit 1 → Merge 불가 |
| medium | 경고 | PASSED (통과, 경고 표시) |
| low | 기록만 | PASSED |
| 탐지 없음 | 통과 | PASSED |

차단 메커니즘: `evaluate-gate.py` exit 1 → Job 실패 → GitHub Check 실패 → Branch
Protection의 Required Check로 Merge 버튼 비활성화(관리자 설정).

### 2.3 CVE 보정 로직 (promote / demote / keep)

**추가 차단이 아니라 Trivy 판정을 보정**한다.

| 조치 | 조건 | 결과 |
| --- | --- | --- |
| **promote** | KEV 등재 | severity 무관 `block` |
| **demote** | 아래 5조건 **AND** | `block` → `warn` |
| **keep** | 그 외(매칭 실패 포함) | Trivy 판정 유지 |

demote 5조건(전부 만족해야 강등): `requireNotKev`(KEV 아님) · `epss < maxEpss(0.1)`
· `severity ≥ minSeverity(high)` · `demoteOnlyWhenNoFix`(fix 없음) ·
CVSS 밴드 < `neverDemoteAtOrAboveCvss(9.0)`.

**안전장치(왜 강등을 이렇게 조심하나)**:
- `demoteOnlyWhenNoFix` — 고칠 수 있는 취약점은 차단 유지해 값싼 업그레이드를
  강제하고, 못 고치는 저위험만 강등해 마찰을 줄인다.
- `neverDemoteAtOrAboveCvss=9.0` — EPSS는 30일 악용 "예측"이라 갓 나온 critical은
  EPSS가 낮다. CVSS critical(≥9.0)은 EPSS와 무관하게 강등 금지. 가드는 Trivy와 CVE
  트랙 severity 중 **더 심각한 쪽**으로 평가.
- 매칭 키는 (정규화 purl, CVE). 실패하면 Trivy 판정 유지(안전 — 강등을 못 하면
  차단이 유지된다).
- evidence의 EPSS가 문자열('0.05')이나 엉뚱한 타입이어도 `_coerce_epss`가 흡수해
  게이트가 크래시하지 않는다(caller-cwd 산출물이라 스키마 검증을 안 거친다).

### 2.4 현재 monitor + annotateOnly인 이유

- **monitor**: 앞단(SBOM→OSV→CVE) 연결·검증이 끝나기 전이라, 보정과 트랙 실패
  차단을 모두 blocked에 반영하지 않고 **기록만** 한다(dry-run). 앞단이 안정적으로
  연결되면 `balanced`(enforce)로 전환한다.
- **annotateOnly=true**: 초기 운영에는 승격/강등을 **표시만** 하고 판정은 안 바꾼다.
  보정 로직이 실제 판정을 바꾸기 전에 "무엇을 왜 바꾸려 하는지"를 PR 댓글로 충분히
  관찰·검증한 뒤 `false`로 전환한다.

즉 지금은 **Trivy baseline 판정은 그대로 살아 있고**(cveTrack과 무관하게 항상
동작), CVE 심화 신호는 옆에서 관찰만 하는 상태다. 안전을 깎지 않으면서 보정
레이어를 검증하는 단계.

---

## 3. 현재 코드에 맞춘 연동 지점

요구사항이 아니라 **현재 코드가 이렇게 되어 있어서 이렇게 맞췄다**는 기록.

### 3.1 dependency-report.json이 raw Trivy 형식

C파트 Trivy 스텝은 `dependency-report.json`에 raw Trivy JSON(SchemaVersion 2)을
쓰는데, A파트 aggregator는 공통 스키마를 기대한다. 그 사이 노멀라이저가 없어 Trivy
CVE가 게이트 finding으로 안 잡혔다.
- **대응**: `scripts/normalize-trivy.py`(신규)를 `evaluate-gate.py`가 in-process로
  호출(`maybe_inject_trivy`). 이미 정규화된 findings가 있으면 건드리지 않는
  이중화 방지 가드 포함. 워크플로 YAML/aggregate-results.py는 미수정.
- **커밋/파일**: `79af139`(normalize-trivy 신규), `630fa86`(게이트 통합),
  `scripts/normalize-trivy.py` · `evaluate-gate.py:maybe_inject_trivy`.

### 3.2 runtime-report.json이 tool="runtime-validation" 단일값

`runtime-validation.py`가 ZAP·Nuclei·Dynatrace 결과를 하나로 병합하며 리포트 레벨
`tool`을 단일 값 `"runtime-validation"`으로 고정한다. 게이트는 리포트 레벨 tool
하나로 매핑을 조회하므로 개별 finding이 어느 스캐너에서 왔는지 이 시점에 이미
사라져 있다.
- **대응**: `security-gate-policy.json`에 `severityMapping["runtime-validation"]`
  통합 매핑(항등 + info→low + unknown→medium)과 `toolCategoryMap["runtime-validation"]
  =dast`를 추가. 신규 `runtime` 카테고리는 안 만든다(만들면 게이트 룰·댓글 렌더링을
  전부 손봐야 함). 매핑이 없으면 런타임 critical이 조용히 medium/warn으로 새는
  fail-open이 나므로 명시 매핑이 필요했다.
- **커밋/파일**: `d58ab34`(known-issue 문서화), `security-gate-policy.json` ·
  `docs/known-issues/runtime-tool-granularity.md`.

### 3.3 reusable workflow의 SECURE_GATE_POLICY / 경로 해석

파이프라인이 reusable workflow로 분리되며 툴링 저장소와 caller 저장소가 나뉜다.
- **대응**: `evaluate-gate.py`가 파일별 소유권을 다르게 잡도록 경로 해석을 변경.
  POLICY는 `SECURE_GATE_POLICY` env override 허용, SCHEMA/RUNNER는 툴링 루트 고정
  (신뢰 경계). 리포트 산출물은 caller cwd.
- **커밋/파일**: `630fa86`(경로 모델+스키마 검증), `evaluate-gate.py` ·
  `docs/cve-track-integration.md` §1.

### 3.4 아티팩트 다운로드 경로 편차

reusable workflow의 `download-artifact`가 caller 루트에 풀면 `security/reports/`
접두어가 벗겨져 리포트가 루트나 하위폴더에 떨어진다. 스크립트는
`security/reports/<name>.json`을 봐서 어긋난다.
- **대응**: `scripts/paths.py`의 `resolve_report()`로 여러 후보 경로를 우선순위
  탐색(env → reports_dir → root → glob). `evaluate-gate.py`·`create-pr-comment.py`
  에 적용.
- **커밋/파일**: `d18ba06`(경로 방어 탐색), `scripts/paths.py` ·
  `docs/known-issues/artifact-path-mismatch.md`.

---

## 4. 검증 결과

- **회귀 테스트 76건 전부 통과** (게이트 44 + CVE 정책 32). 커버 범위: 판정 코어,
  보정 promote/demote/keep + 안전장치, 트랙 실패 유형별 처리, bypass 경계, 배너
  3종, 프로파일 3종, 경로 해석, severity 세 축, 임계값 fail-hard, 예외 시 산출물
  보장 등.
- **정책 축 실측(PoC 11종)**: B파트 red-team GT 11건을 실제 `evaluate-gate.py`로
  판정 → block 7 / warn 4로 GT 심각도대로 정확히 판정(정책 축 무결). 상세는
  `policy-validation-matrix.md`.
- **미검증 영역과 이유**:
  - **탐지 축(도구가 실제로 잡는가)**: 취약앱이 `origin/feat/b-vulnerable-app`에
    있고 아직 main·E 브랜치와 미통합이라, SAST/DAST/Dep 실제 탐지 결과는 B+C+D
    통합 시점에 채운다(매트릭스에 체크리스트로 준비됨).
  - **오탐/적정통과율**: 취약하지 않은 정상 코드(클린 베이스라인)가 있어야 측정
    가능. red-team 세트만으로는 불가 → 후속 과제.
  - **CVE 트랙 실환경 e2e**: monitor라 아직 판정 미반영. 앞단 연결 후 enforce
    전환 시점에 실데이터로 검증 예정. 현재는 mock 픽스처(Log4Shell 등 KEV CVE
    주입, `CVE_INCLUDE_TEST_FIXTURES=1`)로만 1·2순위 규칙을 검증.

---

## 5. 발견한 이슈 (정보 공유)

각각 임시 해소는 적용돼 있고 정식 해소는 소유 파트에 달려 있다.

### 5.1 아티팩트 다운로드 경로 불일치
- **증상**: PR 게이트 댓글이 실제 판정 대신 "결과 파일을 불러오지 못했습니다"
  fallback으로 나옴(성공처럼 보이는 속 빈 초록).
- **영향**: 판정 결과가 개발자에게 전달 안 됨.
- **현재 대응**: `resolve_report()` 방어 탐색(적용됨). 정식 해소는 워크플로에서
  `download-artifact`의 `path:`를 `security/reports`로 고정(A파트). 고정되면 방어
  탐색 후보를 하나로 줄여도 된다.

### 5.2 Trivy 노멀라이저 갭
- **증상**: raw Trivy(`findings` 키 없음)를 aggregator가 0건으로 집계.
- **영향**: Trivy 의존성 CVE가 게이트 판정에 반영 안 될 수 있음(mock은 공통
  스키마라 가려져 있었다).
- **현재 대응**: `normalize-trivy.py`를 게이트가 in-process 호출(적용됨). 정식
  해소는 aggregator에서 공통 스키마로 변환하되 raw 파일은 DT 업로드용으로
  보존(A파트). 정식 노멀라이저가 붙으면 게이트 가드가 자동으로 자기 정규화를 생략.

### 5.3 runtime 도구 구분 불가
- **증상**: runtime-report의 리포트 레벨 tool이 단일값이라 finding이 ZAP/Nuclei/
  Dynatrace 중 어디서 왔는지 게이트 시점에 사라짐.
- **영향**: "Nuclei critical은 차단, ZAP informational은 무시" 같은 **도구별 차등
  정책 불가**. 세 도구가 한 severity 밴드를 공유.
- **현재 대응**: 통합 매핑으로 fail-open은 막음(적용됨). 정식 해소는 finding마다
  `source` 필드(zap/nuclei/dynatrace)를 추가하고 게이트가 finding 레벨로 매핑하도록
  확장(D파트 runtime-validation + E파트 게이트 공동).

### 5.4 origin 리포에 브랜치 보호가 없어 게이트가 Merge를 막지 못함
- **증상**: `KT-TECHUP-PROJECT5/secure_gate`의 `main`이 `"protected": false`이고
  rulesets도 비어 있다(`[]`). **required status check가 0개다.**
- **영향**: 게이트 판정이 아무리 정확해도 **강제력이 0이다.** `blocked=true` / `rc=1`
  로 정확히 차단해도 Merge 버튼은 그대로 열려 있다. 1회차 실측에서 4개 영역이
  Not Run인 채 Merge가 허용된 것도 이 조건과 겹친다 — 판정 로직을 고쳐도 이건
  안 고쳐진다. **코드로 해결할 수 없는 항목**이라 ADR-008과 같은 성격의 팀 공유 건이다.
- **현재 대응**: 없음(리포 설정 영역). 리포 관리자가 브랜치 보호 + required check를
  등록해야 한다. 켤 때 **함께** 처리할 것 — `needs` 실패로 스킵된 잡은 conclusion이
  `skipped`이고, required status check 평가는 이를 **통과로 취급**한다. 스캔 잡이
  깨져 `aggregate-and-gate`가 스킵되면 게이트 없이 Merge가 허용돼 1회차와 같은
  결과가 된다. 게이트 잡에 `if: always()` + `needs.*.result` 명시 평가가 필요하다.
- **검증 한계**: 개인 fork(`9vin9/secure-gate-test`)는 private + 개인 무료 플랜이라
  브랜치 보호 기능 자체를 못 켠다(API 403). 스킵 취급 동작은 **실측하지 못했고**
  문서화된 GitHub 동작에 근거한 것이다.

### 5.5 PR 체크 이름에 `secure-pr-gate / ` 접두어가 붙음
- **증상**: `pr-security-gate.yml`은 reusable workflow이고 `call-pr-security-gate.yml`의
  `secure-pr-gate` 잡이 호출한다. 그래서 PR에 뜨는 체크 이름은 잡 이름 그대로가
  아니라 caller 잡 id가 접두어로 붙은 형태다.
- **영향**: required check를 `Aggregate & Gate Evaluation`처럼 **잡 이름 그대로 등록하면
  영원히 매칭되지 않는다.** 등록은 됐는데 강제가 안 되거나 영구 pending으로 남는다.
  5.4를 실행할 때 바로 밟는 함정이다.
- **현재 대응**: 등록해야 할 7개 전체 이름은 아래와 같다.
  ```
  secure-pr-gate / Build / Test
  secure-pr-gate / SAST (Semgrep)
  secure-pr-gate / Secret Scan (Gitleaks)
  secure-pr-gate / Dependency Scan (Trivy)
  secure-pr-gate / Runtime Validation
  secure-pr-gate / Aggregate & Gate Evaluation
  secure-pr-gate / PR Comment
  ```
  caller의 잡 id(`secure-pr-gate`)를 바꾸면 7개 이름이 전부 바뀌므로, 보호 규칙을
  켠 뒤에는 caller 잡 id를 함부로 바꾸지 말 것.

### 5.6 `gate_status` enum이 팀 계약에 정의돼 있지 않음
- **증상**: `docs/team-interface.md`의 공통 스키마에 `gate_status` **정의 자체가 없다.**
  리포에서 값을 언급하는 곳은 `policy-validation-matrix.md:101`의 `gate_status=FAILED`
  하나뿐이다. 여기에 산출물 보장(fail-blind 해소)으로 **`ERROR`가 새로 추가됐다.**
  현재 값은 `PASSED` / `FAILED` / `ERROR` 셋이다.
- **영향**: 팀에 다른 소비자(대시보드·알림·집계)가 생겼을 때 `PASSED`/`FAILED`만
  가정하고 분기하면 `ERROR`를 오독한다. "FAILED가 아니니 통과"로 처리하는 코드가
  하나라도 있으면 **판단 불가 상태가 통과로 뒤집힌다** — 조용한 통과 금지 원칙 위반.
- **현재 대응**: `create-pr-comment.py`는 `PASSED`만 ✅이고 나머지는 전부 ❌로 떨어져
  안전하다(fail-closed 렌더). 정식 해소는 `team-interface.md` 공통 스키마에 세 값을
  enum으로 명시하는 것(A파트 계약 문서). **팀 공유 대상.**

---

## 6. 남은 작업

- **앞단 연결 후 프로파일 전환**: SBOM→OSV→CVE 파이프라인 실환경 연결·검증 →
  `monitor` → `balanced`(enforce) 전환, `annotateOnly` → `false`.
- **탐지 축 검증**: B+C+D 통합 시 `policy-validation-matrix.md`의 SAST/DAST/Dep 열을
  실측으로 채우고, 도구 심각도 ↔ GT 심각도 편차를 기록. 미탐 발생 시 탐지 축(C/D)
  vs 정책 축(E) 책임 배분 명시.
- **클린 베이스라인**: 오탐/적정통과율 측정용 정상 코드 스냅샷 확보.
- **의존성 CVE 실 픽스처**: `requirements-legacy.txt`(A03)로 CVE 트랙 경로 교차검증
  (red-team baseline 밖 항목).
- **정식 해소 대기 3건**: 아티팩트 경로 고정(A) / Trivy 정식 노멀라이저(A) /
  runtime finding source 필드(D+E).
- **보류 설계(착수 대기)**: per-finding suppression(승인자·만료 필수), 정책 효과
  측정 지표(차단율·강등율·재바이패스율을 gate-decision 이력에서 집계).

---

*작성: E파트(이정빈) · 판정 엔진 진입점 `scripts/evaluate-gate.py` · 상세 설계
`docs/cve-track-integration.md`*
