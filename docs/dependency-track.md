---
문서명: Dependency-Track 연동 가이드
최신화: 2026-07-23
작성자: 이윤재
Version: 1.0.0
---

# Dependency-Track 연동 가이드

Secure PR Gate에서 CycloneDX SBOM을 Dependency-Track(DT)에 올리는 방식과 운영 규칙을 정리한다.

## 역할 분리

| 단계 | 도구 | 역할 |
| --- | --- | --- |
| PR Gate | Trivy CVE (`dependency-report.json`) | **즉시** Merge 판단 입력 |
| SBOM | Trivy CycloneDX 1.6 (`sbom.cdx.json`) | 구성품 목록 |
| DT | Dependency-Track | SBOM/SCA **추적 대시보드** (Gate 판정기 아님) |

- PR에서는 Trivy 결과로 Gate를 판단한다.
- DT 업로드 `status=succeeded`는 BOM **수신 성공**이며, DT 내부 취약점 분석 완료를 의미하지 않는다.
- DT 히스토리/추이 판단은 **`main`(또는 Staging)** 기준으로 강화하는 것을 권장한다.

## 식별 규칙 (UUID 대신 이름)

미리 만든 UUID를 caller에 넣지 않는다.
GitHub 저장소(및 모노레포 서비스명)로 Project를 찾고, 없으면 생성한다.

### Project 이름

```text
secure-gate/github/<owner>/<repo>
secure-gate/github/<owner>/<repo>/<service-name>
```

예:

```text
secure-gate/github/KT-TECHUP-PROJECT5/web
secure-gate/github/gatekeepers/secure-gate/frontend
secure-gate/github/gatekeepers/secure-gate/backend
```

### Version

기본값: **`main`**

브랜치마다 DT version을 늘리지 않는다. DT는 main 궤적의 SBOM/SCA 이력을 쌓는 용도다.

## 단일 레포 vs 모노레포

### 단일 배포 단위

```text
APPLICATION  secure-gate/github/<owner>/<repo> @ main
```

caller에서 `dependency_track_service_name`을 비운다.

### 모노레포 (독립 배포 단위 분리)

프론트·백엔드는 **모두** DT 관리 대상이다.
레포 전체를 한 덩어리로 올리기보다 **독립 배포 단위별 Project**로 분리한다.

```text
COLLECTION   secure-gate/github/<owner>/<repo>            @ main   (합산 리포트)
├─ APPLICATION  .../<repo>/frontend                        @ main
└─ APPLICATION  .../<repo>/backend                         @ main
```

| 단위 | SBOM 출처 | DT Project |
| --- | --- | --- |
| frontend | frontend 최종 Docker 이미지 → Trivy SBOM | `.../frontend` |
| backend | backend 최종 Docker 이미지 → Trivy SBOM | `.../backend` |

- 상위 Collection Project는 자식의 취약점·정책 위반을 **합쳐 보여주는 리포트용**이다.
- 프론트와 백엔드가 **정말 같은 이미지로 함께 배포**될 때만 하나의 Project로 합친다.
- 모노레포 Dockerfile/context는 caller가 명시한다 (`dockerfile_path`, `docker_build_context`).

## 업로드 정책

| `dependency_track_upload_mode` | 동작 |
| --- | --- |
| `main-only` (기본) | `push` + `refs/heads/main` 일 때만 업로드 |
| `always` | ref와 무관하게 업로드 (디버그/임시) |
| `never` | 업로드하지 않음 |

PR Security Gate는 보통 `pull_request`로 돌므로, 기본값(`main-only`)이면 DT는 `not-main-branch`로 **skip**된다.
main에 merge된 뒤 `push` to `main` workflow(또는 CD)에서 업로드하는 구성을 권장한다.

## Secrets / Inputs

### Secrets

| Secret | 설명 |
| --- | --- |
| `DEPENDENCY_TRACK_URL` | DT **Backend API** base URL (UI 포트 아님) |
| `DEPENDENCY_TRACK_API_KEY` | BOM 업로드·프로젝트 생성 권한이 있는 API Key |

Docker Compose 예시:

| 서비스 | 흔한 포트 | 용도 |
| --- | --- | --- |
| apiserver | `8080` | `DEPENDENCY_TRACK_URL` |
| frontend | `8081` | 브라우저 UI |

LAN에서 쓰려면 API가 `0.0.0.0:8080`으로 publish 되어야 한다 (`127.0.0.1`만이면 외부 불가).

### Inputs

| Input | 기본값 | 설명 |
| --- | --- | --- |
| `dependency_track_service_name` | `""` | 모노레포 서비스명. 비우면 레포 단위 Project |
| `dependency_track_project_version` | `main` | DT version |
| `dependency_track_upload_mode` | `main-only` | 업로드 시기 |
| `dockerfile_path` / `docker_build_context` | 자동/`.` | 이미지 분기·모노레포 경로 |

## API 흐름 (구현)

스크립트: `scripts/upload-sbom-to-dependency-track.py`

```text
1) secrets / repository / upload_mode 검사 → skip 가능
2) SBOM 검증 (bomFormat=CycloneDX, specVersion=1.6)
3) service가 있으면 Collection 상위 Project lookup/생성
4) POST /api/v1/bom
     autoCreate=true
     projectName / projectVersion
     (optional) parentName / parentVersion
     bom=<CycloneDX JSON>
5) upload report 기록
```

- UUID input / `project`+`projectName` 동시 지정은 사용하지 않는다 (DT 400 유발).
- CycloneDX는 Secure Gate에서 **1.6으로 고정**한다 (DT 5.0.x 호환).

## Skip / 실패 정책

| reason | 의미 | Job |
| --- | --- | --- |
| `not-configured` | URL/API Key/repository 부족 | 비차단 |
| `secrets-unavailable` | repo는 있으나 secret 없음 (Fork 등) | 비차단 |
| `not-main-branch` | main-only 정책에서 main push가 아님 | 비차단 |
| `upload-disabled` | mode=never | 비차단 |
| `bom-received` | 수신 성공 (`status=succeeded`) | 비차단 |
| `http-*` / `network-error` | API/네트워크 실패 | 비차단 (`continue-on-error`) |

Gate(Aggregator)는 DT report를 필수로 읽지 않는다.

## 산출물

| 파일 / Artifact | 역할 |
| --- | --- |
| `security/reports/sbom.cdx.json` (`sbom`) | CycloneDX 1.6 SBOM |
| `security/reports/dependency-track-upload-report.json` | 업로드 결과 |
| `security/reports/history/<run_id>/` | latest 스냅샷 + `meta.json` |

### upload report 예시

```json
{
  "status": "succeeded",
  "reason": "bom-received",
  "project_name": "secure-gate/github/KT-TECHUP-PROJECT5/web",
  "project_version": "main",
  "project_uuid": "...",
  "parent_name": "",
  "service_name": "",
  "upload_mode": "main-only",
  "created": true,
  "tool": "dependency-track",
  "target": "bom-upload"
}
```

## Caller 예시

### 단일 앱 (PR Gate — DT는 기본 skip)

```yaml
jobs:
  secure-pr-gate:
    uses: KT-TECHUP-PROJECT5/secure_gate/.github/workflows/pr-security-gate.yml@v1
    with:
      gate_repository: KT-TECHUP-PROJECT5/secure_gate
      gate_ref: v1
    secrets: inherit
```

### 모노레포 backend 이미지 → DT backend Project

```yaml
with:
  dockerfile_path: apps/backend/Dockerfile
  docker_build_context: apps/backend
  dependency_track_service_name: backend
  dependency_track_project_version: main
  dependency_track_upload_mode: main-only
```

main push/CD에서 동일 input으로 올리면
`secure-gate/github/<owner>/<repo>/backend @ main` 에 SBOM이 쌓인다.

## 운영 체크리스트

- [ ] DT Backend API URL / API Key를 GitHub Secrets에 등록
- [ ] API Key에 Project 생성·BOM 업로드 권한 부여
- [ ] 모노레포면 서비스별 caller(또는 matrix)와 Dockerfile 경로 명시
- [ ] PR Gate와 main DT 업로드 workflow를 구분해 이해
- [ ] UI URL이 아닌 API 포트를 `DEPENDENCY_TRACK_URL`에 넣었는지 확인
