---
문서명: AI Security Report 가이드
최신화: 2026-07-26
상태: 스크립트 구현 완료 / Workflow 연결은 A파트 전달 필요
---

# AI Security Report 가이드

## 1. 목적

AI는 여러 보안 보고서를 사람이 읽기 쉽게 설명하는 보조 계층이다.

- 전체 Gate 결과를 짧게 요약
- 심각도별 결과를 읽는 방법 설명
- 실제 Finding 중 우선 확인할 항목 제시
- 각 취약점의 간단한 개선 방향 제시

AI는 취약점 탐지기나 정책 판정기가 아니다. Merge/배포 판정은 항상
`scripts/evaluate-gate.py`가 만든 `security/reports/gate-decision.json`을 따른다.

## 2. 처리 흐름

```text
Scanner 원본 결과
-> aggregate-results.py
-> security-summary.json
-> evaluate-gate.py
-> gate-decision.json                 # 확정 판정
-> generate-ai-security-summary.py    # 설명만 생성
-> ai-security-summary.json
-> ai-security-summary.md
-> create-pr-comment.py               # AI 파일이 있을 때 요약 추가
```

AI 호출 실패, API Key 누락, 모델 오류는 Gate 상태를 바꾸지 않는다.

## 3. API로 보내는 입력

AI에는 ZAP, Nuclei, Gitleaks, Trivy 원본 파일을 직접 보내지 않는다.
`gate-decision.json`에서 다음 정규화된 필드만 추려 전송한다.

- 확정 Gate 상태와 정책 프로필
- 차단 사유와 경고
- 심각도별 건수
- Finding ID, 심각도, 제목, 설명, 위치

보호 기준:

- Secret finding의 실제 값과 설명은 전송하지 않음
- URL query와 URL 사용자정보 제거
- API Key, token, password 형태의 문자열 추가 마스킹
- 기본 최대 80개 Finding만 전송
- OpenAI Responses API 요청에 `store=false` 적용
- 입력에 없는 Finding을 AI가 제시하면 결과에서 제거

## 4. 실행 방법

GitHub Repository Secret 또는 로컬 환경변수에 `OPENAI_API_KEY`를 설정한다.
키를 명령행 인자로 넘기거나 파일에 기록하지 않는다.

```bash
export OPENAI_API_KEY="<OpenAI API Key>"
python3 scripts/generate-ai-security-summary.py
unset OPENAI_API_KEY
```

기본 모델은 보고서 요약 비용을 고려한 `gpt-5.6-luna`다.
다른 모델을 검증하려면 다음 환경변수를 사용한다.

```bash
OPENAI_MODEL=gpt-5.6-terra \
python3 scripts/generate-ai-security-summary.py
```

API Key가 없으면 `status=skipped` 보고서와 확정 Gate 판정이 들어간 Markdown을
생성하고 정상 종료한다.

## 5. 결과 파일

### `security/reports/ai-security-summary.json`

프로그램에서 다시 읽을 수 있는 구조화 결과다.

```json
{
  "status": "succeeded",
  "tool": "openai-security-report",
  "model": "gpt-5.6-luna",
  "source": "security/reports/gate-decision.json",
  "authoritative_gate": {
    "gate_status": "PASSED",
    "policy_profile": "training"
  },
  "source_coverage": {
    "reports": [
      {
        "report": "sast",
        "tool": "semgrep",
        "status": "failed",
        "finding_count": 34,
        "error_count": 0,
        "warning_count": 12
      }
    ],
    "findings_sent_to_ai": 78,
    "findings_omitted_from_ai": 0
  },
  "analysis": {
    "executive_summary": "전체 요약",
    "key_observations": [],
    "prioritized_findings": [],
    "report_reading_guide": [],
    "limitations": []
  }
}
```

### `security/reports/ai-security-summary.md`

개발자와 리뷰어가 바로 읽는 보고서다.

- 확정 Gate 판정
- 심각도별 건수
- 차단 사유와 경고
- AI 전체 요약
- 우선 개선 항목
- 취약점별 간단한 개선 방향
- 리포트 해석 한계

두 파일은 공통 Finding 보고서가 아니며 Aggregator 입력으로 사용하지 않는다.

## 6. 교육용 취약 앱 정책

기본 정책은 계속 `pr`로 유지한다. 기본값을 `training`으로 바꾸면 실제 사용자
저장소까지 취약점이 통과할 수 있으므로 사용하지 않는다.

교육용 검증에서만 다음과 같이 프로필을 명시한다.

```bash
SECURE_GATE_PROFILE=training \
python3 scripts/evaluate-gate.py
```

`training` 기준:

- Critical, High, Medium: 경고로 기록하고 통과
- Low: 기록
- Secret: 차단
- 필수 보고서 누락, 파싱 오류, Scanner 기술 실패: 차단

이 설정은 취약점을 안전하다고 판단하는 것이 아니다. 고의로 취약한 테스트 앱에서
탐지 결과와 Merge 이후 단계를 끝까지 검증하기 위한 실행 모드다.

## 7. A파트 Workflow 연결 계약

Workflow 파일은 이 변경에서 수정하지 않는다. A파트는 다음 연결만 추가한다.

1. PR/Post-merge reusable workflow에 `policy_profile` 입력 추가
2. 기본값은 각각 `pr`, `post_merge`
3. 교육용 호출자만 `training` 전달
4. Evaluator 실행 환경변수로 `SECURE_GATE_PROFILE` 전달
5. Gate Evaluator 뒤에서 AI 스크립트 실행
6. `OPENAI_API_KEY`는 GitHub Secret으로 전달
7. AI JSON/Markdown을 Artifact와 PR 댓글 단계에 전달

개념적인 실행 순서는 다음과 같다.

```yaml
- name: Generate AI security explanation
  env:
    OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
    OPENAI_MODEL: ${{ vars.OPENAI_MODEL }}
  run: python3 .secure-gate/scripts/generate-ai-security-summary.py
```

Fork PR처럼 Secret을 사용할 수 없는 실행에서는 AI가 `skipped`가 되지만,
기존 Gate 검사는 그대로 동작한다.

## 8. 운영 원칙

- AI 결과로 Severity, 예외, Gate 상태를 변경하지 않음
- AI가 제안한 수정 버전과 설정은 담당자가 공식 문서로 재검증
- API 응답 원문과 API Key를 Artifact에 저장하지 않음
- 실제 운영 전 대표 보고서로 정확성, 비용, 응답시간을 평가
- 교육용 `training` 프로필은 운영 저장소에서 사용하지 않음
