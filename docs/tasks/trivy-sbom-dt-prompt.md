---
문서명: Trivy + SBOM + Dependency-Track 구현 프롬프트
최신화: 2026-07-23
작성자: 이윤재
Version: 3.1.0
---

# Secure PR Gate: Trivy → SBOM → Dependency-Track (UUID)

에이전트/구현 담당자가 그대로 실행할 수 있는 작업 프롬프트다.
DAST(Nuclei/ZAP) 및 `runtime-validation` Job 변경은 범위 밖이다.

| 항목 | 값 |
| --- | --- |
| 작업 브랜치 | `feature/trivy-sbom` |
| 기준 브랜치 | `main` |
| 기준 커밋 | `7250c67` |

---

## 목표

Secure PR Gate Reusable Workflow(`.github/workflows/pr-security-gate.yml`)의 `dependency-scan` Job에 아래 플로우를 구현한다.

```text
dependency-scan (Trivy)
  ├─ CVE 보고서 → security/reports/dependency-report.json (Gate용)
  ├─ CycloneDX SBOM → security/reports/sbom.cdx.json
  └─ SBOM 업로드 → Dependency-Track (기존 프로젝트 UUID에 BOM 업로드)
```

Dependency-Track 서버·프로젝트를 **생성하지 않는다**.
호출자가 제공한 **기존 프로젝트 UUID**에 CycloneDX BOM만 업로드한다.
`autoCreate`는 사용하지 않는다.

---

## 현재 상태 (반드시 읽고 시작) — main@7250c67

### 코드에 이미 있는 것

- `pr-security-gate.yml`은 `workflow_call` 기반 Reusable Workflow
  - caller: `call-pr-security-gate.yml`
  - 예시: `examples/caller-security-gate.yml`
- `sast`(Semgrep 1.168.0), `secret-scan`(Gitleaks 8.30.1) 연동됨
- `dependency-scan`에 Trivy **0.70.0** pin + checksum 검증됨
- 현재는 `trivy fs` CVE만 수행 (SBOM/DT 없음):

```bash
trivy fs \
  --scanners vuln \
  --file-patterns "pip:requirements-legacy.txt" \
  --format json \
  --output security/reports/dependency-report.json \
  --exit-code 0 \
  --no-progress \
  .
```

- `dependency-report` artifact + `SchemaVersion == 2` 검증 있음
- `Run Trivy`에 `continue-on-error: true` 있음 → **제거** (finding은 `--exit-code 0`, 기술 실패는 Job fail)
- secrets는 `DYNATRACE_TOKEN`만 선언됨
- `aggregate-and-gate`만 Secure Gate tooling을 `.secure-gate/`에 checkout
  → DT 업로드 스크립트 사용 시 `dependency-scan`에도 tooling checkout 추가

### 문서와 코드 불일치 (구현과 함께 갱신)

- `docs/pipeline-guide.md`: dependency-scan Placeholder 표기
- `docs/tasks/C-part-task.md`: Trivy 체크리스트 미완료
- `docs/team-interface.md`: 현재 `trivy fs` 명령을 확정 계약으로 기록
- `docs/project.md` §10.3: CVE vs CycloneDX 역할 분리 이미 정의 → 유지·확장

### Gate 계약

- `security/reports/dependency-report.json` / artifact `dependency-report` 유지
- C파트는 Trivy 원본 JSON. Aggregator 공통 스키마 전면 개편은 비범위
- SBOM·DT upload report는 **별도 artifact**. Gate 판정 흐름을 바꾸지 않는다

---

## 요구사항

### 1) Reusable Workflow inputs / secrets

| input | 타입 | 필수 | 기본값 | 용도 |
| --- | --- | --- | --- | --- |
| `dockerfile_path` | string | 아니오 | `""` | Dockerfile의 caller 저장소 기준 경로 |
| `docker_build_context` | string | 아니오 | `"."` | Docker build context |
| `dependency_track_project_uuid` | string | 아니오 | `""` | 기존 Dependency-Track 프로젝트 UUID |

| secret | 필수 | 용도 |
| --- | --- | --- |
| `DEPENDENCY_TRACK_URL` | 아니오 | Dependency-Track **Backend API** base URL |
| `DEPENDENCY_TRACK_API_KEY` | 아니오 | Dependency-Track API Key |

- `DEPENDENCY_TRACK_URL`은 `/api/v1/bom` 요청을 처리하는 Dependency-Track **Backend API**의 base URL이다.
  UI 전용 주소가 아니라 API에 접근 가능한 주소를 설정한다.
  (Docker Compose 환경에서는 frontend와 API backend 포트가 다를 수 있다. 공식 REST API/CI 문서를 참고한다.)
- `dependency_track_project_uuid`는 비밀값이 아니므로 **input**으로 관리한다.
- URL, API Key, Project UUID 중 **하나라도 없으면** Dependency-Track 업로드만 skip한다 (`not-configured`).
- Project UUID로 기존 프로젝트를 지정한다. **프로젝트 자동 생성·name/version 식별은 하지 않는다.**
- caller 갱신: `examples/caller-security-gate.yml`, (권장) `call-pr-security-gate.yml` 주석 예시

### 2) Dockerfile 감지 및 검사 대상 분기

1. `dockerfile_path` input이 있으면 해당 경로를 사용한다.
2. 없으면 caller 저장소 **루트**의 `Dockerfile`, 그다음 `dockerfile`만 자동 탐색한다.
3. **하위 경로 Dockerfile은 자동 선택하지 않는다.** 모노레포는 caller가 `dockerfile_path` / `docker_build_context`를 명시한다.
4. 선택한 Dockerfile 경로와 `image` / `fs` 분기를 로그에 출력한다.

#### Dockerfile이 있는 경우

- `docker build -f <dockerfile> -t secure-gate-scan:${{ github.sha }} <context>`
- 동일 이미지에 대해 CVE JSON과 CycloneDX SBOM을 **분리 실행**:

```bash
trivy image \
  --scanners vuln \
  --format json \
  --output security/reports/dependency-report.json \
  --exit-code 0 \
  --no-progress \
  <local-image-tag>

trivy image \
  --format cyclonedx \
  --output security/reports/sbom.cdx.json \
  --no-progress \
  <local-image-tag>
```

#### Dockerfile이 없는 경우

```bash
trivy fs \
  --scanners vuln \
  --file-patterns "pip:requirements-legacy.txt" \
  --format json \
  --output security/reports/dependency-report.json \
  --exit-code 0 \
  --no-progress \
  .

trivy fs \
  --file-patterns "pip:requirements-legacy.txt" \
  --format cyclonedx \
  --output security/reports/sbom.cdx.json \
  --no-progress \
  .
```

#### 공통 규칙

- CVE 보고서와 SBOM은 **별도 명령·별도 파일**
- `sbom.cdx.json`의 빈 `vulnerabilities[]`는 취약점 없음 근거가 아님. Gate는 `dependency-report.json`만 사용
- `--exit-code 0`: finding으로 Job 실패 방지
- Docker build / Trivy CVE / Trivy SBOM 생성 / **`bomFormat == "CycloneDX"` 검증**은 핵심 산출물 단계다.
  기술 실패면 **Job 실패** → 해당 step에 `continue-on-error` **사용 금지**
- `bomFormat` 검증은 DT 업로드 step이 아니라 **SBOM 생성 직후 독립 step**에서 수행한다.
  `bomFormat != "CycloneDX"`이면 DT 문제가 아니라 SBOM 생성 실패로 본다.
- artifact 업로드는 `if: always()`로 시도하되 존재하는 파일만
- `dependency-report.json`은 어느 분기에서든 `SchemaVersion == 2` 검증 통과

### 3) SBOM artifact 및 Dependency-Track 업로드 (UUID)

1. SBOM 생성 직후 `bomFormat == "CycloneDX"` 검증. 실패 시 **Job 실패** (DT 업로드로 넘기지 않음)
2. `security/reports/sbom.cdx.json` → artifact `sbom` (`if: always()` 권장, 파일 있을 때)
3. 아래 세 값이 **모두** 있을 때만 DT 업로드:
   - `DEPENDENCY_TRACK_URL` (Backend API base URL — UI 주소 아님)
   - `DEPENDENCY_TRACK_API_KEY`
   - `dependency_track_project_uuid`
4. API:

```http
POST /api/v1/bom
Content-Type: multipart/form-data

project=<uuid>
bom=@security/reports/sbom.cdx.json
```

- **`autoCreate` 사용 금지**
- Header: `X-Api-Key` (값은 로그·리포트·artifact에 출력 금지)

5. 필수 값 부족 시 warning + 업로드만 skip. SBOM artifact·Trivy Gate는 계속 진행
6. DT API 응답 실패 / 업로드 스크립트 예외는 숨기지 않되 Job 전체를 막지 않는다 (아래 실패 정책)
7. Fork PR 등 secret 미제공 환경은 안전하게 skip
8. `scripts/upload-sbom-to-dependency-track.py`에 URL 정규화, multipart 업로드, 리포트 작성 분리
   (CycloneDX `bomFormat` 검증은 업로드 스크립트 책임이 아니라 **앞선 Job-fail step**의 책임. 업로드 스크립트는 정상 CycloneDX가 이미 있다고 가정하거나, 방어적으로 재검증하되 형식 오류면 스크립트 전에 Job이 이미 실패한 상태를 전제로 한다.)
9. `dependency-scan`에 Secure Gate tooling checkout 추가 후 스크립트 실행

```yaml
- uses: actions/checkout@v4
  with:
    repository: ${{ inputs.gate_repository }}
    ref: ${{ inputs.gate_ref }}
    path: .secure-gate
```

권장 CLI:

```bash
python .secure-gate/scripts/upload-sbom-to-dependency-track.py \
  --sbom security/reports/sbom.cdx.json \
  --project-uuid "<uuid>" \
  --report security/reports/dependency-track-upload-report.json
```

URL/API Key는 **env**로 전달 (`DEPENDENCY_TRACK_URL`, `DEPENDENCY_TRACK_API_KEY`). CLI에 API Key를 넣지 않는다.

#### DT upload report artifact (필수)

| 항목 | 값 |
| --- | --- |
| artifact 이름 | `dependency-track-upload-report` |
| 경로 | `security/reports/dependency-track-upload-report.json` |
| 업로드 조건 | `if: always()` |

`aggregate-and-gate`가 이 artifact를 읽도록 강제하지 않는다. 추후 리포트·디버깅 근거로 보관한다.

### 4) 실패 및 Skip 정책 (확정)

DT는 **선택 연동**이다. DT 미설정·업로드 실패 때문에 Trivy Gate를 막지 않는다.
다만 SBOM 자체 생성·형식 검증은 핵심 산출물이므로 Job 실패로 분리한다.
리포트와 step outcome에는 분명히 남긴다.

| 상황 | 리포트 | 어댑터 exit | Gate / Job 영향 |
| --- | --- | --- | --- |
| Trivy가 SBOM 파일 생성 실패 | (DT 이전) | n/a | **Job 실패** |
| `bomFormat != "CycloneDX"` | (DT 이전 검증 step) | n/a | **Job 실패** |
| URL / API Key / UUID 중 하나라도 없음 | `status=skipped`, `reason=not-configured` | `0` | Job 비차단, Trivy Gate 유지 |
| Fork PR 등 GitHub가 secret을 주지 않은 것이 명확한 경우 | `status=skipped`, `reason=secrets-unavailable` | `0` | Job 비차단 |
| DT가 BOM 업로드 요청을 **수신** 성공 | `status=succeeded` | `0` | Job 비차단 |
| 정상 CycloneDX인데 DT API 401/403/5xx·네트워크 오류 | `status=failed`, `reason=http-401` 등 | `1` | Job 비차단 (`continue-on-error`) |
| DT 업로드 스크립트 실행 예외 | `status=failed` (+ fallback report) | `1` | Job 비차단 (`continue-on-error`) |
| Docker / Trivy CVE 생성 실패 | (DT 이전) | n/a | **Job 실패** |

리포트 필드: `status`, `project_uuid`, `reason`
(필요 시 `tool`/`target` 정도 추가 가능. **URL·API Key·Authorization 절대 기록 금지**)
`status`: `succeeded` | `skipped` | `failed`

**`status=succeeded` 의미:**
Dependency-Track이 BOM 업로드 요청을 **성공적으로 수신**했다는 의미이며,
Dependency-Track 내부 취약점 **분석 완료를 보장하지 않는다**.

리포트 예시:

```json
{
  "status": "skipped",
  "project_uuid": "",
  "reason": "not-configured"
}
```

#### workflow step 정책

- **Docker / Trivy CVE / Trivy SBOM 생성 / `bomFormat` 검증:** `continue-on-error` **사용 금지** → 실패 시 Job 실패
- **DT 업로드 step만** `continue-on-error: true`

```yaml
- name: Validate CycloneDX SBOM
  run: |
    python -c 'import json; d=json.load(open("security/reports/sbom.cdx.json")); assert d.get("bomFormat")=="CycloneDX"'

- name: Upload SBOM to Dependency-Track
  id: dependency_track_upload
  continue-on-error: true
  env:
    DEPENDENCY_TRACK_URL: ${{ secrets.DEPENDENCY_TRACK_URL }}
    DEPENDENCY_TRACK_API_KEY: ${{ secrets.DEPENDENCY_TRACK_API_KEY }}
  run: |
    python .secure-gate/scripts/upload-sbom-to-dependency-track.py \
      --sbom security/reports/sbom.cdx.json \
      --project-uuid "${{ inputs.dependency_track_project_uuid }}" \
      --report security/reports/dependency-track-upload-report.json

- name: Ensure Dependency-Track upload report
  if: always()
  run: |
    # 리포트 파일이 없을 때만 fallback 실패 리포트를 생성한다.
    # 기존 succeeded/skipped/failed 리포트를 덮어쓰지 않는다.

- name: Upload Dependency-Track upload report
  if: always()
  uses: actions/upload-artifact@v4
  with:
    name: dependency-track-upload-report
    path: security/reports/dependency-track-upload-report.json
```

어댑터 exit (DT 업로드 step 한정):

| 결과 | exit | status |
| --- | --- | --- |
| BOM 수신 성공 (`succeeded`) | `0` | `succeeded` |
| 미설정 / Fork skip | `0` | `skipped` |
| DT API·네트워크 오류 | `1` | `failed` |
| 업로드 스크립트 실행 예외 | `1` | `failed` |

### 5) Job 그래프 / 문서 계약

- `aggregate-and-gate`는 기존처럼 `dependency-report`를 수집한다. DT upload report를 읽도록 강제하지 않는다.
- `runtime-validation` / Nuclei / ZAP / `needs`는 **수정하지 않는다**.
- 문서 갱신:
  - `docs/pipeline-guide.md`
  - `docs/team-interface.md`
  - `docs/tasks/C-part-task.md`
  - `examples/caller-security-gate.yml`
- 문서에 기록:
  - Dockerfile 탐색 우선순위와 모노레포 명시 input
  - image/fs 분기별 Trivy 명령
  - `dependency-report` / `sbom` / `dependency-track-upload-report` artifact 경로·역할
  - DT secrets/inputs(`dependency_track_project_uuid`)와 skip 조건
  - `DEPENDENCY_TRACK_URL`은 Backend API base URL (UI 주소 아님)
  - DT는 Gate 판정기가 아니라 SBOM/SCA 추적 대시보드
  - `status=succeeded`는 BOM **수신 성공**이며 분석 완료를 의미하지 않음
  - 사용자는 DT에서 프로젝트를 미리 만들고 UUID를 caller에 넣는다
  - image/fs 검증 방법
  - `bomFormat` 검증 실패는 Job 실패, DT API 실패는 Job 비차단

### 6) 비범위

- Semgrep/Gitleaks 로직 변경
- DAST(Nuclei, ZAP) 및 `runtime-validation` 변경
- Trivy CVE → Nuclei 필터링 / Job 순서 변경
- Dependency-Track 서버·프로젝트 프로비저닝 / `autoCreate`
- 저장소명 기반 프로젝트 자동 식별 (`secure-gate/github/...`, `pr-gate`)
- managed/byo 중앙 DT 어댑터 모드
- A파트 Aggregator 공통 스키마 전면 재작성
- `cd-staging.yml` 전체 구현

---

## 구현 원칙

- 기존 YAML 스타일, Trivy `0.70.0` pin·checksum 유지
- image build는 Dockerfile 분기에서만
- 셸이 복잡해지면 `scripts/` 헬퍼로 분리
- DT는 선택 기능. 미설정은 Gate 실패 사유가 아님
- finding(`--exit-code 0`)과 기술 실패(Job fail)를 구분
- DT 업로드 실패는 `continue-on-error: true`로 Job만 비차단, step outcome·report로 가시화

---

## 완료 기준

- [x] Dockerfile 존재/부재 각각에서 Trivy CVE + CycloneDX SBOM 생성
- [x] 두 분기 모두 `dependency-report.json` `SchemaVersion == 2` 유지
- [x] `sbom` artifact (`bomFormat == "CycloneDX"`), 형식 검증 실패 시 Job 실패
- [x] URL + API Key + Project UUID가 모두 있을 때 기존 프로젝트에 BOM **수신** 성공 (`autoCreate` 없음)
- [x] 설정값 부족 / Fork secret 부재 시 `skipped` + `not-configured` / `secrets-unavailable`, Gate 유지
- [x] DT API 실패 시 `failed` + exit 1 + report, Job은 `continue-on-error`로 비차단
- [x] `dependency-track-upload-report` artifact를 `if: always()`로 업로드
- [x] report 파일이 **없을 때만** `if: always()` fallback 리포트 생성 (기존 리포트 덮어쓰기 금지)
- [x] Docker / Trivy / `bomFormat` 검증 단계는 `continue-on-error` 미사용
- [x] docs에 Backend API URL 안내 및 `succeeded`=수신 성공 정의 포함
- [x] 관련 docs·caller 예시 업데이트

---

## 작업 후 산출물

1. 코드/워크플로 변경
2. 변경 요약:

```text
dependency-scan
  ├─ Dockerfile 감지
  │   ├─ 있음: build → trivy image (CVE JSON + CycloneDX SBOM)
  │   └─ 없음: trivy fs (CVE JSON + CycloneDX SBOM)
  ├─ bomFormat 검증 (실패 시 Job 실패)
  ├─ dependency-report artifact → 기존 Aggregator/Gate
  ├─ sbom artifact
  └─ DT 업로드 (project=<uuid>, autoCreate 없음, continue-on-error)
        └─ dependency-track-upload-report artifact (if: always())
```

3. inputs/secrets 목록

| 구분 | 이름 |
| --- | --- |
| input | `dockerfile_path`, `docker_build_context`, `dependency_track_project_uuid` |
| secret | `DEPENDENCY_TRACK_URL` (Backend API), `DEPENDENCY_TRACK_API_KEY` |

4. artifacts

| 이름 | 경로 |
| --- | --- |
| `dependency-report` | `security/reports/dependency-report.json` |
| `sbom` | `security/reports/sbom.cdx.json` |
| `dependency-track-upload-report` | `security/reports/dependency-track-upload-report.json` |

5. 남은 리스크
   - DT 미설정 시 업로드 skip
   - Dockerfile 빌드로 PR 시간 증가
   - 모노레포는 caller 명시 input 필요
   - 사용자는 DT 프로젝트를 미리 생성하고 UUID를 관리해야 함
   - UI URL을 `DEPENDENCY_TRACK_URL`에 넣으면 업로드 실패 가능 → 문서에 Backend API 명시
   - `succeeded`는 분석 완료가 아님 → DT UI/후속 모니터링 필요
   - `gate_ref`가 옛 태그면 새 업로드 스크립트가 없을 수 있음 → 이 저장소 caller는 `gate_ref: ${{ github.sha }}` 유지
