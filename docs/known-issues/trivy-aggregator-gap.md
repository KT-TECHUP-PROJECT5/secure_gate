---
문서명: Known Issue — Trivy raw 리포트가 aggregator에 잡히지 않음
최신화: 2026-07-24
작성자: 이정빈 (E파트)
상태: 임시 해소 적용됨 / 정식 해소 대기 (A파트)
---

# Known Issue: raw Trivy 리포트 ↔ aggregate-results.py 계약 갭

## 요약
C파트 Trivy 스텝은 `dependency-report.json` 에 **raw Trivy JSON**(SchemaVersion 2)을
쓰는데, A파트 `aggregate-results.py` 는 **공통 스키마**(`{status, tool, findings[]}`)를
기대한다. 그 사이를 잇는 노멀라이저가 없어 **의존성 CVE 가 게이트 finding 으로
집계되지 않는다.**

## 발견 경위
`feature/trivy-sbom` 브랜치 통합 검토 중, E파트 CVE 보정 레이어가 소비할 의존성
finding 을 추적하다 확인. mock 픽스처(`tests/fixtures/security-gate-mock/
dependency-report.json`)는 공통 스키마라 이 갭이 가려져 있었다.

## 재현 조건
1. `dependency-scan` job 이 raw Trivy JSON 을 `security/reports/dependency-report.json`
   에 생성 (`SchemaVersion == 2`, `Results[].Vulnerabilities[]`).
2. `aggregate-results.py` 가 이를 읽어 `report.get("findings", [])` 를 참조.
3. raw Trivy 에는 `findings` 키가 없음 → **0건으로 집계**.

## 영향 범위
- **현재 Trivy 의존성 CVE 가 게이트 판정(Pass/Fail)에 반영되지 않음.**
- Trivy CVE JSON 자체는 artifact 로 업로드되고 DT 대시보드로도 가지만, PR 머지
  차단 로직에는 들어가지 않는다.
- mock 기반 테스트에서는 드러나지 않는다(공통 스키마라서).

## 임시 해소 (적용됨 — E파트)
`scripts/normalize-trivy.py`(신규)가 raw Trivy → 공통 스키마 findings 로 변환한다.
`evaluate-gate.py` 가 이를 **in-process 로 호출**해, `dependency_scan` 리포트에
정규화된 findings 가 없을 때만 채운다.

- 호출 주체: `evaluate-gate.py` (워크플로 YAML / `aggregate-results.py` 미수정).
- 공통 스키마에 optional 필드 `purl`, `fixedVersion` 을 채워 보정 레이어가 쓴다.
- **이중화 방지 가드**: `dependency_scan` 에 이미 findings 가 있으면 그대로 둔다.
  → 나중에 A파트가 정식 노멀라이저를 붙여도 판정이 이중 집계되지 않는다.
- `cveTrack.enabled` 상태와 무관하게 항상 동작 → CVE 트랙을 off 로 둬도 Trivy
  의존성 판정은 살아 있다.

## 정식 해소 제안 (A파트)
1. `aggregate-results.py`(또는 전용 노멀라이즈 스텝)에서 raw Trivy → 공통 스키마
   변환을 수행하고, `dependency-report.json` 과 **별개 경로**(예:
   `dependency-normalized.json`)에 저장하거나 summary 에 직접 반영한다.
   - `dependency-report.json`(raw) 자체는 DT 업로드/스냅샷/검증이 SchemaVersion 2
     를 요구하므로 **덮어쓰지 말 것**.
2. 공통 스키마에 `purl`, `fixedVersion` optional 필드를 유지한다(보정 레이어 의존).
3. 정식 노멀라이저가 summary 에 findings 를 채우면, `evaluate-gate.py` 의 가드가
   자동으로 자기 정규화를 생략한다 → `normalize-trivy.py` 는 제거하거나 폴백으로만
   남긴다.
4. 계약을 `docs/team-interface.md` C파트 표에 명문화한다.

## 관련 파일
- `scripts/normalize-trivy.py` (임시 해소)
- `scripts/evaluate-gate.py` (`maybe_inject_trivy`)
- `docs/cve-track-integration.md` (보정 레이어 설계)
