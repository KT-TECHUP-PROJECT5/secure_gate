
   ## 한 장 요약

   | 등급 | 판정 | 한 줄 이유 |
   | --- | --- | --- |
   | critical / high / secret | **차단** (exit 1) | 악용 가능성·영향이 크거나(critical/high), 발견 즉시 유출(secret) |
   | medium | **경고**(통과) | 조건부 위험. 매번 차단하면 마찰이 커 게이트 신뢰가 깎임 |
   | low | **기록만** | 백로그 관리 대상. 차단·경고 모두 과함 |

   **핵심 원칙 3줄**
   1. **fail-safe** — 위험도를 모르면 항상 더 안전한(더 심각한/차단하는) 쪽으로 판정한다.
   2. **조용한 통과 금지** — 미매핑·손상·실패를 소리 없이 넘기지 않고, 차단하거나 최소한 경고를 남긴다.
   3. **신뢰 경계** — caller가 게이트 안전성을 무력화할 수 있는 부분(스키마·runner·강등)은 코드/툴링이 소유한다.

   > 용어: **fail-closed**=실패 시 차단 · **fail-open**=실패 시 통과 · **fail-hard**=설정
   > 오류 시 즉시 중단(exit) · **fail-safe**=불확실하면 안전한 쪽으로.

---

## A. 등급 정규화

### A-1. 공통 5단계로 번역하는 이유
① 각 도구의 원본 등급(Semgrep ERROR/WARNING, ZAP High/Informational 등)을
공통 5단계(critical/high/medium/low/secret)로 매핑한다.
② 판정 규칙(`gateRules`)을 공통 등급 **한 축**으로만 쓰기 위해서다. 도구별 어휘로
직접 판정하면 판정 코드에 `if tool == "semgrep" and sev == "ERROR"` 식 분기가 도구
수만큼 늘어난다.
③ 다르게 하면: 도구가 추가될 때마다 판정 로직을 고쳐야 하고, "ERROR가 High보다
심한가?" 같은 교차 도구 비교가 불가능해진다.

### A-2. Gitleaks는 원본 severity를 버리고 무조건 secret
① `severityMapping.gitleaks`는 `{"default": "secret"}` 하나뿐. finding에 어떤 값이
있어도 무시하고 `default`만 조회한다.
② 키 노출은 **발견 시점 = 이미 유출**이다. "이 키가 얼마나 위험한가"를 등급으로
논쟁하는 것 자체가 무의미하다 — 노출된 키는 즉시 폐기 대상이다.
③ 다르게 하면: 도구가 매긴 임의 점수에 따라 어떤 노출 키는 medium으로 통과할 수
있다. 유출된 자격증명이 경고만 뜨고 머지되는 사고가 난다.

### A-3. Trivy UNKNOWN → medium (올림, fail-safe)
① Trivy가 등급을 모르는(`UNKNOWN`) CVE를 medium으로 올린다.
② **fail-safe 원칙**: 위험도를 모르면 안전한 쪽으로. low로 내리면 조용히 통과하지만
medium이면 최소한 경고로 표면화된다.
③ 다르게 하면(low): 등급 미상 CVE가 기록만 되고 개발자 눈에 안 띈다.

### A-4. ZAP Informational → low (내림, 노이즈 억제)
① ZAP `Informational`과 runtime `info/informational`은 low로 **내린다**.
② A-3과 방향이 반대인 이유: `Informational`은 "위험 미상"이 아니라 **명시적으로
정보성**이라는 신호다. 불확실이 아니므로 fail-safe 대상이 아니다. fallback(medium)
으로 흘리면 ZAP/Nuclei가 쏟아내는 informational이 전부 경고가 되어 노이즈가 폭발한다.
③ 다르게 하면(medium): 경고 목록이 정보성 항목으로 가득 차 진짜 medium이 묻힌다.
→ **불확실은 올리고(A-3), 확실한 정보성은 내린다(A-4). 판단 근거가 반대라 방향도 반대.**

### A-5. 미매핑 값 → medium + 경고
① `severityMapping`에 없는 원본 등급은 `unknownSeverityFallback`(=medium)으로
대체하고 finding에 `severity_fallback` 표시 + "정책 갱신 필요" 경고를 남긴다.
② A-3과 같은 fail-safe + **조용한 통과 금지 원칙**. 모르는 값을 그냥 버리면
새 도구/새 등급이 게이트를 소리 없이 빠져나간다.
③ 다르게 하면: 오타나 신규 등급 하나로 취약점이 통째로 누락되는데 아무도 모른다.

---

## B. 차단선

### B-6. blockOnSeverity = critical / high / secret
① 이 셋만 Merge를 차단한다.
② critical(CVSS 9.0–10.0)·high(7.0–8.9)는 악용 가능성이 높고 영향이 크다 —
머지 전에 반드시 막아야 하는 선. secret은 B-9 참고.
③ 다르게 하면(medium 포함): B-7 참고.

### B-7. medium은 차단이 아닌 경고
① medium(CVSS 4.0–6.9)은 `warnOnSeverity`에만 있어 통과시키되 경고한다.
② **마찰 vs 안전 트레이드오프**. medium은 조건부 악용이라 대부분 즉시 위험은
아니다. 전부 차단하면 개발 흐름이 자주 막히고, 개발자가 게이트를 "매번 우는 늑대"로
여겨 신뢰가 깎인다. 게이트는 **막을 때 확실히 막혀야** 존중받는다.
③ 다르게 하면(차단): 오탐·저위험까지 머지를 막아 우회 요청이 늘고, 진짜 차단의
무게가 가벼워진다. (medium 개별 승격은 정책 매트릭스의 운영 절차로 처리한다.)

### B-8. low는 기록만
① low(CVSS 0.1–3.9)는 block/warn 어디에도 없다.
② 악용 난도가 높거나 영향이 미미하다. 경고로도 띄우면 B-7의 노이즈 문제가 low
규모로 다시 생긴다. 백로그로 관리하는 게 맞다.
③ 다르게 하면(경고): 경고 섹션이 low로 채워져 medium 경고가 묻힌다.

### B-9. secret은 등급이 아닌데 차단 목록에 있다
① `secret`은 CVSS 점수축이 없는 별도 등급인데 `blockOnSeverity`에 들어 있다.
② 자격증명 노출은 CVSS로 점수 매길 성질이 아니다(A-2). 하지만 "발견 즉시 유출"이라
차단 필요성은 critical급이다. 그래서 점수축과 무관하게 **차단 목록에 명시**한다.
③ 다르게 하면: secret을 점수축에 억지로 끼우면 C-11 문제가 생긴다.

---

## C. severity.py — 세 축 분리

### C-10. 네 상수를 별개로 두는 이유
① `severity.py`에 네 상수가 있다. 값은 아래.

| 상수 | 값 | 쓰는 곳 |
| --- | --- | --- |
| `SEVERITY_RANK` | critical=4, high=3, medium=2, low=1 | 강등 판정(minSeverity 비교·가드). **secret 없음** |
| `DISPLAY_ORDER` | secret, critical, high, medium, low, info | PR 댓글 표시 순서 |
| `CVSS_BAND_FLOOR` | critical=9.0, high=7.0, medium=4.0, low=0.1 | 강등 가드(수치 CVSS 밴드 하한) |
| `OSV_GRADE_RANK` | CRITICAL=4, HIGH=3, MODERATE=2, LOW=1 | OSV 외부 어휘 순위(등급 여럿 중 최고 선택) |

② "심각도"라는 한 단어에 **심각도 순위 / 표시 순서 / 수치 밴드 / 외부 어휘** 네
개념이 섞여 있었다. 한 상수로 합치면 한 용도의 요구가 다른 용도를 오염시킨다
(C-11·C-12가 실제 사례). `OSV_GRADE_RANK`는 키 자체가 다르다(MODERATE 존재, secret
없음) — 내부 어휘와 섞으면 매핑이 깨진다.
③ 다르게 하면(단일 상수): 아래 두 사고가 난다.

### C-11. SEVERITY_RANK에서 secret을 뺀 이유
① `SEVERITY_RANK`에 secret 키가 없다. 강등 로직은 진입 시점에 secret을 명시 제외한다.
② secret은 CVSS/EPSS 축이 없다(A-2·B-9). 0으로 끼우면 순위상 **"가장 안 심각"**
이 되어, `severity ≥ minSeverity` 비교에서 우연히 걸러지는 것에 의존하게 된다.
③ 다르게 하면(0으로 포함): minSeverity 기준이 바뀌는 순간 secret이 강등 대상으로
잘못 빨려들 수 있다. 명시 제외가 안전하다.

### C-12. DISPLAY_ORDER에서 secret이 최상단인 이유
① 표시 순서에서 secret이 맨 앞, 그다음 심각도순.
② **긴급도 ≠ 심각도**. secret은 CVSS 점수는 없지만 수정 긴급도는 최고다 — 개발자가
댓글을 열었을 때 제일 먼저 봐야 한다. 이건 심각도 순위(C-11)와 **다른 축**이라
DISPLAY_ORDER로 따로 둔다.
③ 다르게 하면(SEVERITY_RANK로 정렬): secret은 순위축에 없으니 맨 뒤로 밀려, 가장
급한 항목이 목록 바닥에 깔린다.

---

## D. CVE 보정 숫자

보정은 **추가 차단이 아니라 Trivy 판정의 promote/demote/keep**이다. 아래 값은
`security-gate-policy.json`의 `cveTrack.adjustment`와 `cve-policy.json`에 있다.

### D-13. EPSS 0.1 / percentile 0.95
① CVE 리포트에서 `epss_score ≥ 0.1` **또는** `epss_percentile ≥ 0.95`면 block.
② EPSS score는 정의상 **향후 30일 악용 확률**이라 0.1 = 10% 확률, percentile 0.95 =
상위 5%를 뜻한다. 확률·백분위 **두 축을 OR**로 걸어, 절대 확률이 낮아도 상대적으로
극단(상위 5%)이면 잡는다.
③ 다르게 하면(확률만): 아직 확률은 낮지만 이미 상위권으로 올라오는 신흥 위협을 놓친다.
> 근거 미기록: 왜 0.05/0.9가 아니라 정확히 0.1/0.95인지 **구체 캘리브레이션 근거는
> 리포에 없다.** 두 값은 EPSS의 통상 임계로 채택된 상태.

### D-14. neverDemoteAtOrAboveCvss = 9.0
① CVSS 밴드 하한이 9.0 이상(=critical)인 finding은 **강등 금지**.
② EPSS는 30일 악용 "예측"이라 **갓 나온 critical은 아직 EPSS가 낮다.** EPSS만 보고
강등하면 신규 critical이 경고로 새어나간다. 그래서 EPSS와 무관하게 critical 밴드는
차단을 고정한다. 가드는 Trivy·CVE 트랙 severity 중 **더 심각한 쪽**으로 평가한다.
③ 다르게 하면(가드 없음): 공개 직후 아직 악용 관측이 없는 critical CVE가
"EPSS 낮음"만으로 강등된다 — 정확히 가장 위험한 타이밍에.

### D-15. demote 5조건을 전부 AND로
① 강등은 `requireNotKev`(KEV 아님) **AND** `epss < 0.1` **AND** `severity ≥ high`
**AND** fix 없음 **AND** CVSS 밴드 < 9.0 — 전부 만족해야 발동한다.
② 강등은 **차단을 푸는** 유일한 조치라 가장 보수적이어야 한다. 하나라도 위험 신호가
있으면(KEV거나, EPSS 높거나, 고칠 수 있거나, critical이면) 강등하지 않는다.
③ 다르게 하면(OR): 조건 하나만 맞아도 차단이 풀려, 강등이 게이트의 구멍이 된다.

### D-16. demoteOnlyWhenNoFix — 고칠 수 있으면 차단 유지
① fix 버전이 있는 취약점은 강등하지 않고 차단을 유지한다.
② 고칠 수 있는 건 **값싼 업그레이드로 해결**되므로 차단을 유지해 강제하는 게 낫다.
강등(마찰 완화)은 **못 고치는** 저위험에만 쓴다 — 고칠 방법이 없는데 계속 막으면
개발자가 할 수 있는 게 없기 때문.
③ 다르게 하면(fix 있어도 강등): 그냥 올리면 될 취약점이 경고로 남아 방치된다.

### D-17. KEV promote가 severity를 무시
① KEV(CISA 실제 악용 목록) 등재 CVE는 Trivy severity와 무관하게 block으로 승격.
② KEV는 **실제로 악용되고 있다**는 관측 사실이다. CVSS 점수(이론적 심각도)보다 강한
신호다. Trivy가 low로 봤든 medium으로 봤든, 현실에서 악용 중이면 차단이 맞다.
③ 다르게 하면(severity 존중): Trivy가 낮게 매긴 실제 악용 CVE가 통과한다.

### D-18. cve-policy.json epss 0.1 ≠ security-gate-policy maxEpss 0.1
① 두 파일에 똑같이 0.1이 있지만 의미가 다르다.

| 위치 | 이름 | 의미 |
| --- | --- | --- |
| `cve-policy.json` | `reportThresholds.epss.blockThreshold` | 독립 CVE 리포트에서 **차단(block)** 판정 |
| `security-gate-policy.json` | `adjustment.demote.maxEpss` | 게이트 **강등(demote)** 판단 |

② 하나는 "차단할 만큼 위험한가", 다른 하나는 "강등해도 될 만큼 안전한가"로
**질문이 반대**다. 우연히 지금 같은 숫자일 뿐 서로 독립적으로 조정돼야 한다.
③ 다르게 하면(한 곳 공유): 한쪽 튜닝이 반대 의미의 다른 쪽을 의도치 않게 바꾼다.

### D-19. 매칭 실패 시 keep(Trivy 유지)
① (정규화 purl, CVE)로 evidence 매칭에 실패하면 보정 없이 Trivy 판정을 유지한다.
② 매칭 실패의 위험은 **비대칭**이다. 강등을 못 하면 차단이 유지돼(안전) 최악이
"안 풀림"이고, 승격을 못 하는 손실은 두 소스 모두 Trivy 기반이라 매칭 신뢰도가
높아 드물다.
③ 다르게 하면(실패 시 통과): 매칭 실패 하나로 Trivy가 잡은 차단이 사라진다.

---

## E. 실패했을 때의 판정

### E-20. onTrackFailure를 유형별로 나눔
① 트랙 실패를 셋으로 나눠 다르게 처리한다.

| 유형 | 상황 | 동작 |
| --- | --- | --- |
| `scriptError` | 실행했으나(또는 SBOM 있는데) 유효 산출 없음 | **failClosed** |
| `dataUnavailable` | SBOM 없음 = 앞단 미실행 | **failOpen** |
| `timeout` | 시간 초과 | **failOpen** |

② "우리 것이 깨진 것"과 "앞단이 안 돈 것"을 구분한다. 스크립트가 깨졌으면(scriptError)
결과를 신뢰할 수 없으니 차단(fail-closed). 반대로 앞단이 아직 연결 안 돼 데이터가
없는 것(dataUnavailable)까지 차단하면, CVE 트랙 하나 때문에 **전체 파이프라인이
막힌다** — 아직 monitor 단계라 과하다.
③ 다르게 하면(전부 failClosed): 앞단 미가동만으로 모든 PR이 막혀 게이트가 무력화된다.

### E-21. 스키마 검증 실패 = fail-closed
① 정책이 `policy-schema.json` 검증을 통과 못 하면 exit 1로 차단(스키마 자체를 못
읽어도 차단).
② 정책이 깨졌다는 건 **판정 기준 자체를 믿을 수 없다**는 뜻이다. 그 상태로 내린
어떤 판정도 신뢰 불가 → 안전하게 차단.
③ 다르게 하면(통과): 손상된/조작된 정책으로 게이트가 계속 돌며 잘못된 통과를 낸다.

### E-22. bypass.scope = trackFailureOnly
① 우회(`CVE_TRACK_BYPASS`)는 트랙 **실패의 fail-closed만** fail-open으로 낮춘다.
유효한 CVE block verdict은 절대 못 연다 — 코드로 강제(enum도 이 값 하나뿐).
② 우회의 목적은 "앞단 장애로 막힌 걸 임시로 뚫는 것"이지 "진짜 취약점을 무시하는
것"이 아니다. 후자를 허용하면 라벨 하나로 게이트가 무력화된다.
③ 다르게 하면(전체 우회): `security-gate-bypass-cve` 라벨만 붙이면 실제 악용 CVE도
통과 — 게이트의 존재 이유가 사라진다.

### E-23. 알 수 없는 프로파일 이름 = fail-hard
① `SECURE_GATE_PROFILE`이 화이트리스트(strict/balanced/monitor) 밖이면 즉시 exit 1.
② 조용히 무시하면 **오타(`stirct`)로 의도한 정책이 안 걸린 채** base 기본값(monitor)
으로 돌아버린다 — 가장 엄격하게 돌리려던 릴리스가 dry-run으로 통과하는 사고.
③ 다르게 하면(무시): 정책이 안 걸렸는데 아무 경고 없이 통과한다.

### E-24. 임계값이 0~1 밖이면 fail-hard
① `cve-policy.json`의 EPSS 임계값이 0~1 float가 아니면 `cve-policy-evaluate.py`가
즉시 exit 1(파일 없음/JSON 오류/키 누락도 동일).
② EPSS는 확률이라 0~1을 벗어나면 오설정이 확실하다. `5.0` 같은 값을 조용히 쓰면
어떤 CVE도 임계에 안 걸려 **전부 통과**한다.
③ 다르게 하면(기본값으로 폴백): 오타 임계값이 소리 없이 게이트를 무력화한다.

---

## F. 신뢰 경계

### F-25. POLICY/GUIDE는 override 허용, SCHEMA/RUNNER는 불허
① reusable workflow에서 파일별 소유권이 다르다.

| 파일 | caller override | 이유 |
| --- | --- | --- |
| POLICY, GUIDE | **허용** | 무력화해도 게이트 **안전성**을 못 깬다. 프로젝트별 조정 필요 |
| SCHEMA, RUNNER | **불허**(툴링 루트 고정) | 아래 |

② SCHEMA를 열어주면 caller가 **느슨한 자기 스키마로 검증을 무력화**하고, RUNNER를
열어주면 **runner를 임의 스크립트로 바꿔치기**할 수 있다. 둘 다 게이트 안전성을
직접 깨는 신뢰 경계 침범이다.
③ 다르게 하면(전부 허용): caller가 정책+느슨한 스키마를 함께 넣어 검증을 우회한다.

### F-26. 정책 JSON은 실행 명령 대신 runnerId만
① 정책은 `runner.runnerId: "cve-policy-evaluate"`만 담고, 실제 argv·입력 경로는
코드의 `RUNNER_WHITELIST`가 소유한다.
② 정책 파일(override 가능)에 실행할 명령을 담으면, 그게 곧 **임의 명령 실행 통로**가
된다. "무엇을 부를지"는 데이터로 두되 "어떻게 부를지"는 코드에 가둔다.
③ 다르게 하면(정책에 argv): override된 정책으로 원하는 명령을 게이트 권한으로 실행.

---

## G. 현재 상태

### G-27. cveTrack=monitor + annotateOnly=true (해제 조건 포함)
① 현재 base는 `enabled: monitor` + `adjustment.annotateOnly: true`. 보정·트랙실패를
blocked에 반영하지 않고 **기록만** 한다(dry-run).
② 앞단(SBOM→OSV→CVE) 실환경 연결·검증이 아직 안 끝났다. 검증 전에 enforce로 켜면
설익은 보정이 오판(특히 잘못된 강등)을 낼 수 있어, 우선 **관찰**한다. 이 동안에도
Trivy baseline 판정은 그대로 살아 있다(cveTrack과 무관하게 항상 동작).
③ **해제 조건**: 앞단이 안정적으로 `cve-policy-decision.json`을 산출하고, PR 댓글로
"무엇을 왜 승격/강등하려는지"를 충분히 관찰한 뒤 → `balanced`(enforce, annotateOnly
false)로 전환.

### G-28. 프로파일 3종 용도 구분

| 프로파일 | 언제 쓰나 |
| --- | --- |
| **monitor** | 앞단 연결 전 관찰·정책 튜닝(현재 base 기본). 아무것도 blocked에 반영 안 함 |
| **balanced** | 앞단 연결·검증 후 정상 운영. 승격 + 저위험 강등을 실제 반영 |
| **strict** | 규제·릴리스 브랜치. 마찰보다 안전이 우선 — 강등 없이 모든 차단 유지 |

용도를 나눈 이유: 운영 강도는 브랜치·시점마다 다르다. caller가 정책 전체를
복사·수정하지 않고 **이름 하나**로 강도를 고르게 해, 공통부(severityMapping 등)는
base 단일 출처로 유지한다.

### G-29. strict는 annotateOnly가 아니라 demote.enabled=false로 강등을 끔
① `strict.json`은 `annotateOnly: false`로 두되 `demote.enabled: false`로 강등만 끈다.
② `annotateOnly: true`로 끄면 **승격(promote)까지 표시만** 되어버린다. strict가 원하는
건 "강등은 막되 KEV 승격은 살려 차단을 더하는 것"이다. 강등만 정확히 꺼야 한다.
차단은 늘 뿐 줄지 않으므로 항상 안전하다.
③ 다르게 하면(annotateOnly로 끔): 실제 악용(KEV) CVE 승격까지 무력화돼, 가장 엄격
해야 할 프로파일이 오히려 차단을 못 더한다.

---

## H. 그 외 판단이 들어간 값

### H-30a. toolCategoryMap에서 runtime-validation을 dast로 재사용
① 신규 `runtime` 카테고리를 안 만들고 기존 `dast`에 매핑했다.
② `runtime` 카테고리를 새로 만들면 gateRules·PR 댓글 렌더링·remediation-guide를
전부 손봐야 한다. runtime(ZAP/Nuclei/Dynatrace)은 성격상 DAST라 재사용이 자연스럽다.
③ 다르게 하면: 카테고리 하나 늘리려고 판정·렌더 경로 전체를 수정. (한계는 known-issue
runtime-tool-granularity 참고 — 세 도구를 한 밴드로 뭉친다.)

### H-30b. MAX_LOCATIONS_PER_GROUP=10, MAX_COMMENT_CHARS=60000
① 같은 카테고리는 위치를 그룹당 10개까지만, 최종 본문은 60000자에서 자른다.
② GitHub PR 댓글 본문 한계가 **65536자**다. 취약점이 폭증해도 댓글 작성이 실패하지
않게 안전 여유(약 5500자)를 두고 자른다. 잘릴 땐 "아티팩트 확인" 안내를 남긴다.
③ 다르게 하면(상한 없음): 대량 finding에서 댓글 POST가 400으로 실패해 판정 결과가
개발자에게 아예 전달 안 된다.

### H-30c. decisionMerge.strategy = fail-closed
① 병합 전략이 `fail-closed` 하나로 고정(enum도 이 값뿐).
② 판정 병합 과정에서 애매하면 차단 쪽으로 — 전체 문서의 fail-safe 원칙(§요약)을
병합 단계에도 적용한다.

### H-30d. CVE 트랙 4단계의 조회 실패 차등 (OSV/KEV/EPSS)
① `cve-policy-evaluate.py`가 조회 실패를 지표별로 다르게 처리한다.

| 실패 | 처리 | 이유 |
| --- | --- | --- |
| OSV(패키지) | fail-closed | CVE 자체를 못 봄 = 판단 불가 |
| KEV(CVE) | 이미 block/warn이면 유지, pass면 fail-closed | KEV는 차단을 '추가'하는 규칙 |
| EPSS(CVE) | fail-open(그 규칙만 스킵) | 예측치라 없어도 CVSS로 판정 가능 |

② "그 지표가 없으면 판정이 불가능한가"로 나눈다. OSV가 없으면 아무것도 모르니 차단,
EPSS는 보조 예측치라 없어도 CVSS로 판정된다. E-20과 같은 "판단 가능성" 기준.

### H-30e. timeoutSeconds = 120
① CVE runner 직접 실행 시 타임아웃 120초, 초과 시 timeout(→failOpen, E-20).
> 근거 미기록: **정확히 120초인 이유**는 리포에 없다. timeout이 failOpen인 근거는
> E-20에 있으나 값 자체의 캘리브레이션 기록은 없음.

---

## 불일치 발견

코드/정책과 문서 사이, 또는 리포에 근거가 없는 값 목록.

1. **`docs/severity-policy.md`에 `runtime-validation`이 없음.** 정책 JSON은
   `severityMapping["runtime-validation"]`와 `toolCategoryMap["runtime-validation"]=dast`
   를 정의하는데, severity-policy.md §2·§3 도구 표에는 빠져 있다. 같은 문서 §3이
   "이 표는 severityMapping과 **정확히 일치**해야 한다"고 명시하므로 문서가 정책보다
   뒤처진 상태다. (runtime-validation은 known-issue 대응으로 나중에 추가돼 severity-
   policy.md에 반영 안 됨.)

2. **CVE 규칙 번호 4번 부재.** `docs/severity-policy.md` §5는 판정 우선순위를
   1~6으로 나열(3=CRITICAL block, 4=HIGH warn)하지만, `cve-policy-evaluate.py`의
   `RULES`는 3·4를 `3-CVSS` 하나로 통합했다(라벨은 `3-CRITICAL`/`3-HIGH`로 세분,
   코드에 `4-` 규칙 없음, `5-UNDETERMINED`로 건너뜀). 동작은 동일하나 번호 체계가
   문서와 코드가 다르다.

3. **EPSS 0.1 / percentile 0.95의 구체 캘리브레이션 근거 미기록** (D-13). 값은
   일치하나 "왜 정확히 이 값"인지는 리포 어디에도 없다.

4. **`timeoutSeconds=120`의 값 근거 미기록** (H-30e). 실패 시 동작(failOpen) 근거는
   있으나 120초라는 수치 자체의 근거는 없다.
