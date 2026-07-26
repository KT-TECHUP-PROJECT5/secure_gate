#!/usr/bin/env python3
"""severity.py — severity 순위/표시 상수의 단일 출처.

두 개념을 명확히 분리한다(이번 리팩터링의 핵심):

  - SEVERITY_RANK : CVSS 기반 '심각도 등급' 순위(높을수록 심각). 게이트 강등
                    판정의 minSeverity 비교·가드에 쓴다. secret 은 CVSS/EPSS
                    축이 없어 **여기 포함하지 않는다** — 같은 축에 0 으로 끼우면
                    "가장 안 심각"이라는 잘못된 의미가 되고, minSeverity 비교에서
                    우연히 제외되는 것에 의존하게 된다. secret 은 보정 로직
                    진입 시점에 명시적으로 제외한다(evaluate-gate._decide_adjustment).

  - DISPLAY_ORDER : PR 댓글 '표시 우선순위'(등급 심각도와 별개 축). secret 이
                    최상단 — 자격증명 노출은 수정 긴급도가 가장 높고, 개발자가
                    댓글을 열었을 때 제일 먼저 봐야 한다. 목록에 없는 등급은 맨 뒤.

  - CVSS_BAND_FLOOR: CVSS v3 등급 밴드 하한(강등 가드 neverDemoteAtOrAboveCvss).

  - OSV_GRADE_RANK : OSV 외부 어휘(CRITICAL/HIGH/MODERATE/LOW) 순위. 내부 어휘와
                     키가 달라(MODERATE, secret 없음) 별도 유지.

소비 스크립트는 자기 디렉터리를 sys.path 에 넣은 뒤 `from severity import ...`
로 가져온다(직접 실행·서브프로세스·importlib 모두에서 동작).
"""

# CVSS 기반 심각도 등급 순위 — 높을수록 심각. secret 은 의도적으로 제외한다.
SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1}

# PR 댓글 표시 우선순위(심각도 등급과 다른 축). secret 최상단, 미지정 등급 최하.
DISPLAY_ORDER = ["secret", "critical", "high", "medium", "low", "info"]

# CVSS v3 등급 밴드 하한 (neverDemoteAtOrAboveCvss 가드용).
CVSS_BAND_FLOOR = {"critical": 9.0, "high": 7.0, "medium": 4.0, "low": 0.1}

# OSV database_specific.severity 외부 어휘 순위(여러 등급 중 최고 선택용).
OSV_GRADE_RANK = {"CRITICAL": 4, "HIGH": 3, "MODERATE": 2, "LOW": 1}


def display_key(severity):
    """PR 댓글 표시 정렬 키. DISPLAY_ORDER 순서, 목록에 없는 등급은 맨 뒤로."""
    try:
        return DISPLAY_ORDER.index(severity)
    except ValueError:
        return len(DISPLAY_ORDER)
