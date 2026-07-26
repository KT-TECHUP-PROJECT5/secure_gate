#!/usr/bin/env python3
"""
normalize-reports.py

각 스캐너의 '네이티브 JSON' 출력을 파이프라인 공통 스키마로 변환한다.
스캔 Job과 aggregate-results.py 사이에 끼워, 도구가 무엇이든
aggregate/evaluate가 손대지 않고도 동작하게 만드는 어댑터다.

변환 대상 (security/reports/ 안의 파일):
  - sast-report.json        : Semgrep  {version, results, errors, ...}
  - secret-report.json      : Gitleaks [ {...}, ... ]  (배열)

Trivy(dependency-report.json)는 대상이 아니다. evaluate-gate.py 가
normalize-trivy.py 를 in-process 로 호출해 메모리에서만 변환한다. 여기서
제자리 덮어쓰기를 하면 raw Trivy JSON 이 사라져 purl·fixedVersion 이 소실되고,
CVE 보정 레이어의 강등 가드(D-16)가 무력화된다. TARGETS 에 다시 넣지 말 것.
(근거: docs/gate-decision-rationale.md H-30f)

이미 공통 스키마({"tool","findings"})인 파일(build/runtime placeholder 등)은
그대로 통과시킨다. 파일이 없으면 건너뛴다.

공통 스키마:
{
  "status": "passed" | "failed",
  "tool":   "semgrep" | "gitleaks" | "trivy",
  "findings": [
    {"id","severity","title","description","location"}
  ]
}

severity는 각 도구의 '원본 값'을 그대로 싣는다(Semgrep: ERROR/WARNING/INFO,
Trivy: CRITICAL/HIGH/...). 공통 등급으로의 매핑은 evaluate-gate.py가
security-gate-policy.json의 severityMapping으로 처리한다. Gitleaks는 원본
등급 개념이 없어 "secret"으로 고정하지만, 매핑 단계에서도 default로 처리된다.
"""

import json
from pathlib import Path

REPORTS_DIR = Path("security/reports")

TARGETS = {
    "sast-report.json":       "semgrep",
    "secret-report.json":     "gitleaks",
}


def _first_line(text: str, limit: int = 120) -> str:
    line = (text or "").strip().splitlines()[0] if (text or "").strip() else ""
    return line[:limit]


def normalize_semgrep(data: dict) -> list:
    findings = []
    for r in data.get("results", []):
        extra = r.get("extra", {})
        path  = r.get("path", "?")
        line  = r.get("start", {}).get("line", "?")
        findings.append({
            "id":          r.get("check_id"),
            "severity":    extra.get("severity"),  # ERROR / WARNING / INFO
            "title":       _first_line(extra.get("message")) or r.get("check_id"),
            "description": extra.get("message", ""),
            "location":    f"{path}:{line}",
        })
    return findings


def normalize_gitleaks(data: list) -> list:
    findings = []
    for g in data:
        file  = g.get("File", "?")
        line  = g.get("StartLine", "?")
        findings.append({
            "id":          g.get("RuleID"),
            "severity":    "secret",  # gitleaks는 등급 개념 없음 → 고정
            "title":       g.get("Description") or g.get("RuleID") or "Secret detected",
            "description": g.get("Description", ""),
            "location":    f"{file}:{line}",
        })
    return findings


def normalize_trivy(data: dict) -> list:
    findings = []
    for res in data.get("Results", []) or []:
        target = res.get("Target", "?")
        for v in res.get("Vulnerabilities", []) or []:
            pkg = f"{v.get('PkgName','?')} {v.get('InstalledVersion','')}".strip()
            findings.append({
                "id":          v.get("VulnerabilityID"),
                "severity":    v.get("Severity"),  # CRITICAL / HIGH / MEDIUM / LOW / UNKNOWN
                "title":       v.get("Title") or v.get("VulnerabilityID"),
                "description": v.get("Description", ""),
                "location":    f"{target} ({pkg})",
            })
    return findings


NORMALIZERS = {
    "semgrep":  normalize_semgrep,
    "gitleaks": normalize_gitleaks,
    "trivy":    normalize_trivy,
}


def is_common_schema(data) -> bool:
    return isinstance(data, dict) and "tool" in data and "findings" in data


def normalize_file(filename: str, tool: str) -> None:
    path = REPORTS_DIR / filename
    if not path.exists():
        print(f"[SKIP] {filename} 없음 — 건너뜀")
        return

    try:
        with open(path) as f:
            data = json.load(f)

        if is_common_schema(data):
            print(f"[PASS] {filename} 이미 공통 스키마 — 변환 생략")
            return

        findings = NORMALIZERS[tool](data)
        normalized = {
            "status":   "failed" if findings else "passed",
            "tool":     tool,
            "findings": findings,
        }

        with open(path, "w") as f:
            json.dump(normalized, f, indent=2, ensure_ascii=False)

        print(f"[OK] {filename} ({tool}) 변환 완료 — findings {len(findings)}건")
    except Exception as e:
        # 손상 JSON·예상 밖 구조로 여기서 죽으면 aggregate/evaluate 가 아예 실행되지
        # 않아 gate-decision.json 이 없다(fail-blind). 예외를 삼키는 대신 공통 스키마
        # error 리포트로 남겨, 하류가 dict 를 받고 status 로 "검사 실패"를 판정한다.
        summary = f"{type(e).__name__}: {e}"
        print(f"[ERROR] {filename} ({tool}) 변환 실패 — {summary}")
        error_report = {
            "status":   "error",
            "tool":     tool,
            "findings": [],
            "error":    summary,
        }
        try:
            with open(path, "w") as f:
                json.dump(error_report, f, indent=2, ensure_ascii=False)
        except OSError as write_err:
            # 기록마저 실패해도 죽지 않는다. 파일 부재는 aggregate 가 not_found 로 잡는다.
            print(f"[ERROR] {filename} error 리포트 기록 실패 — {write_err}")


def main():
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    for filename, tool in TARGETS.items():
        normalize_file(filename, tool)


if __name__ == "__main__":
    main()
