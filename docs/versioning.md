---
문서명: Reusable Workflow 버전 배포
최신화: 2026-07-15
Version: 1.0.0
---

# Reusable Workflow 버전 배포

Secure PR Gate는 서버에 배포하는 서비스가 아니라, GitHub Actions Reusable Workflow를 **Git 태그**로 배포한다.

## 사용자 측

```yaml
jobs:
  secure-pr-gate:
    uses: KT-TECHUP-PROJECT5/secure_gate/.github/workflows/pr-security-gate.yml@v1
    with:
      gate_repository: KT-TECHUP-PROJECT5/secure_gate
      gate_ref: v1
```

- `@v1` — major 이동 태그. 호환되는 최신 1.x를 따라감 (권장)
- `@v1.0.0` — 완전 고정. 재현성이 중요할 때 사용

`uses:`의 ref와 `gate_ref`는 같게 맞춘다.  
Workflow YAML과 `scripts/`가 서로 다른 커밋이면 Aggregator/Evaluator 동작이 어긋날 수 있다.

## Maintainer 측 릴리즈

```bash
# 1) 변경 merge 후 annotated/lightweight 태그 생성
git tag v1.0.0
git push origin v1.0.0

# 2) major 이동 태그 갱신 (사용자가 @v1 로 따라오도록)
git tag -f v1 v1.0.0
git push origin v1 --force
```

이후 패치:

```bash
git tag v1.0.1
git push origin v1.0.1
git tag -f v1 v1.0.1
git push origin v1 --force
```

## 이 저장소 자체 검증

`call-pr-security-gate.yml`은 태그에 의존하지 않는다.

```yaml
uses: ./.github/workflows/pr-security-gate.yml
with:
  gate_repository: ${{ github.repository }}
  gate_ref: ${{ github.sha }}
```

PR 커밋의 workflow와 scripts를 그대로 검증한다.

## 체크리스트

- [ ] `pr-security-gate.yml`이 `on: workflow_call`만 사용하는지
- [ ] `examples/caller-security-gate.yml`이 최신 inputs와 일치하는지
- [ ] `v1.x.y` 태그 push
- [ ] `v1` 이동 태그 갱신
- [ ] 샘플 외부 저장소에서 `@v1` caller 스모크 테스트
