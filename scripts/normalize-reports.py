#!/usr/bin/env python3
"""
normalize-reports.py

각 스캐너의 '네이티브 JSON' 출력을 파이프라인 공통 스키마로 변환한다.
스캔 Job과 aggregate-results.py 사이에 끼워, 도구가 무엇이든
aggregate/evaluate가 손대지 않고도 동작하게 만드는 어댑터다.

변환 대상 (security/reports/ 안의 파일):
  - sast-report.json        : Semgrep  {version, results, errors, ...}
  - secret-report.json      : Gitleaks [ {...}, ... ]  (배열)
  - dependency-report.json  : Trivy    {SchemaVersion, Results, ...}

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
    "dependency-report.json": "trivy",
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


def main():
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    for filename, tool in TARGETS.items():
        normalize_file(filename, tool)


if __name__ == "__main__":
    main()
