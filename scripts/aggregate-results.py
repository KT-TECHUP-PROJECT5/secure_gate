#!/usr/bin/env python3
"""
aggregate-results.py

각 보안 검사 Job의 결과 파일을 읽어 하나의 security-summary.json으로 통합한다.
각 파트에서 실제 결과 파일이 연결되면 REPORT_FILES 매핑만 유지하면 된다.

결과 파일 형식 (각 파트가 준수해야 하는 공통 스키마):
{
  "status": "passed" | "failed" | "warning",
  "tool": "<tool-name>",
  "findings": [
    {
      "id": "<finding-id>",
      "severity": "critical" | "high" | "medium" | "low" | "secret",
      "title": "<title>",
      "description": "<description>",
      "location": "<file:line or url>"
    }
  ]
}
"""

import json
import sys
from pathlib import Path

REPORTS_DIR = Path("security/reports")
SUMMARY_FILE = REPORTS_DIR / "security-summary.json"

REPORT_FILES = {
    "build":              "build-report.json",
    "sast":               "sast-report.json",
    "secret_scan":        "secret-report.json",
    "dependency_scan":    "dependency-report.json",
    "runtime_validation": "runtime-report.json",
}


def load_report(filename: str) -> dict:
    path = REPORTS_DIR / filename
    if not path.exists():
        print(f"[WARN] Report not found: {filename} — treated as not_run")
        return {"status": "not_found", "tool": filename, "findings": []}
    try:
        with open(path) as f:
            return json.load(f)
    except json.JSONDecodeError as e:
        print(f"[ERROR] Failed to parse {filename}: {e}")
        return {"status": "error", "tool": filename, "findings": []}


def main():
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    summary = {
        "reports": {},
        "total_findings": 0,
        "has_critical": False,
        "has_high": False,
        "has_secret": False,
        "has_medium": False,
    }

    for key, filename in REPORT_FILES.items():
        report = load_report(filename)
        summary["reports"][key] = report

        for finding in report.get("findings", []):
            summary["total_findings"] += 1
            severity = finding.get("severity", "").lower()
            if severity == "critical":
                summary["has_critical"] = True
            elif severity == "high":
                summary["has_high"] = True
            elif severity == "secret":
                summary["has_secret"] = True
            elif severity == "medium":
                summary["has_medium"] = True

    with open(SUMMARY_FILE, "w") as f:
        json.dump(summary, f, indent=2)

    print(f"[OK] Security summary → {SUMMARY_FILE}")
    print(f"     Total findings : {summary['total_findings']}")
    print(f"     Critical       : {summary['has_critical']}")
    print(f"     High           : {summary['has_high']}")
    print(f"     Secret         : {summary['has_secret']}")
    print(f"     Medium         : {summary['has_medium']}")


if __name__ == "__main__":
    main()
