#!/usr/bin/env python3
"""paths.py — 리포트 산출물 경로 해석 (reusable workflow 다운로드 경로 편차 방어).

reusable workflow 에서 `download-artifact` 가 아티팩트를 caller 루트(`path: .`)에
풀면, upload 시 공통 접두어(`security/reports/`)가 벗겨져 리포트가
`<root>/<name>.json` 에 떨어진다. 반면 로컬/직접 실행에선
`security/reports/<name>.json` 이다. 단일 하드코딩 경로는 둘 중 하나에서 깨지므로
여러 후보를 우선순위로 탐색한다.

정식 해소는 워크플로 쪽에서 `download-artifact` 의 `path:` 를 `security/reports`
로 지정하는 것이다(A파트 소유). 이 헬퍼는 그 전까지의 방어선이며, 워크플로가
경로를 고정하면 후보 목록을 줄여도 된다. (docs/known-issues/artifact-path-mismatch.md)
"""

import os
import sys
from pathlib import Path


def resolve_report(filename, *, env_var=None, reports_dir="security/reports",
                   search_root=".", max_glob_depth=4, log=True):
    """리포트 파일을 후보 경로에서 우선순위로 탐색. 첫 존재 경로(Path) 반환, 없으면 None.

    우선순위:
      1) env_var 환경변수(설정 + 파일 존재)              — 명시 지정 최우선
      2) <reports_dir>/<filename> (security/reports/…)    — 로컬/직접 실행 기본
      3) <search_root>/<filename> (./…)                   — reusable workflow 루트 배치
      4) glob <search_root>/**/<filename> (깊이 제한)      — 최후 수단

    여러 개 발견 시 우선순위 첫 번째 사용, 나머지는 경고 로그. 전부 실패면 탐색한
    경로 목록을 로그로 남기고 None(다음 디버깅할 사람이 알 수 있게).
    """
    def _log(msg):
        if log:
            print(msg, file=sys.stderr)

    candidates = []   # (라벨, Path) 우선순위 순
    tried = []        # 탐색한 위치(디버깅용)

    # 1) 환경변수 명시 경로
    if env_var:
        val = os.environ.get(env_var, "").strip()
        tried.append(f"${env_var}={val or '(unset)'}")
        if val and Path(val).is_file():
            candidates.append(("env", Path(val)))

    # 2) security/reports/<filename>
    p_reports = Path(reports_dir) / filename
    tried.append(str(p_reports))
    if p_reports.is_file():
        candidates.append(("reports_dir", p_reports))

    # 3) <root>/<filename>
    p_root = Path(search_root) / filename
    tried.append(str(p_root))
    if p_root.is_file():
        candidates.append(("root", p_root))

    # 4) glob 최후 수단 (깊이 제한)
    seen = {c[1].resolve() for c in candidates}
    root = Path(search_root)
    tried.append(f"{search_root}/**/{filename} (glob, depth<={max_glob_depth})")
    glob_hits = []
    for hit in root.glob("**/" + filename):
        if not hit.is_file() or hit.resolve() in seen:
            continue
        try:
            depth = len(hit.relative_to(root).parts)
        except ValueError:
            depth = max_glob_depth + 1
        if depth <= max_glob_depth:
            glob_hits.append(hit)
    for hit in sorted(glob_hits, key=lambda h: len(h.parts)):
        candidates.append(("glob", hit))

    if not candidates:
        _log(f"[WARN] {filename} 를 찾지 못했습니다. 탐색한 위치: " + " | ".join(tried))
        return None

    label, chosen = candidates[0]
    _log(f"[INFO] gate report found — {filename} at: {chosen} (via {label})")
    if len(candidates) > 1:
        others = ", ".join(f"{c[1]}({c[0]})" for c in candidates[1:])
        _log(f"[WARN] {filename} 다중 매칭 — 우선순위상 첫 번째 사용. 그 외: {others}")
    return chosen
