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
      "category": "vuln" | "misconfig" | "secret" | "availability" | "scanner-error",
      "title": "<title>",
      "description": "<description>",
      "location": "<file:line or url>"
    }
  ]
}
"""

import argparse
import json
import os
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import gate_policy

REPORTS_DIR = Path("security/reports")
SUMMARY_FILE = REPORTS_DIR / "security-summary.json"
DEFAULT_POLICY = {
    "blockOnSecret": True,
    "blockOnScannerError": True,
    "blockOnAvailability": True,
    "blockOnVulnCritical": True,
    "blockOnVulnHigh": True,
    "warnOnMedium": True,
    "warnOnMisconfig": True,
}

REPORT_FILES = {
    "build": "build-report.json",
    "sast": "sast-report.json",
    "secret_scan": "secret-report.json",
    "dependency_scan": "dependency-report.json",
    "dependency_track": "dependency-track-upload-report.json",
    "runtime_validation": "runtime-report.json",
}


def select_report_files(raw_value: str) -> dict[str, str]:
    if not raw_value.strip():
        return dict(REPORT_FILES)

    keys = [key.strip() for key in raw_value.split(",") if key.strip()]
    unknown = [key for key in keys if key not in REPORT_FILES]
    if unknown:
        raise ValueError(f"Unknown report key(s): {', '.join(unknown)}")
    return {key: REPORT_FILES[key] for key in keys}


def finding_status(findings: list[dict]) -> str:
    return gate_policy.finding_report_status(findings, DEFAULT_POLICY)


def normalize_semgrep(data: dict) -> dict:
    findings = []
    severity_map = {"ERROR": "high", "WARNING": "medium", "INFO": "low"}
    for result in data.get("results", []):
        if not isinstance(result, dict):
            continue
        extra = result.get("extra") if isinstance(result.get("extra"), dict) else {}
        start = result.get("start") if isinstance(result.get("start"), dict) else {}
        path = str(result.get("path") or "semgrep")
        line = start.get("line")
        findings.append(
            gate_policy.with_category(
                {
                    "id": str(result.get("check_id") or "semgrep.finding"),
                    "severity": severity_map.get(
                        str(extra.get("severity") or "WARNING").upper(), "medium"
                    ),
                    "category": "vuln",
                    "title": str(result.get("check_id") or "Semgrep finding"),
                    "description": str(
                        extra.get("message") or "Semgrep reported a finding."
                    ),
                    "location": f"{path}:{line}" if line else path,
                }
            )
        )

    scanner_errors = data.get("errors")
    has_scanner_errors = isinstance(scanner_errors, list) and bool(scanner_errors)
    return {
        "status": "error" if has_scanner_errors else finding_status(findings),
        "tool": "semgrep",
        "findings": findings,
        "errors": scanner_errors if has_scanner_errors else [],
    }


def normalize_gitleaks(data: list) -> dict:
    findings = []
    for result in data:
        if not isinstance(result, dict):
            continue
        path = str(result.get("File") or result.get("file") or "gitleaks")
        line = result.get("StartLine") or result.get("startLine")
        findings.append(
            gate_policy.with_category(
                {
                    "id": str(
                        result.get("RuleID")
                        or result.get("RuleId")
                        or result.get("ruleID")
                        or "gitleaks.secret"
                    ),
                    "severity": "secret",
                    "category": "secret",
                    "title": str(
                        result.get("Description")
                        or result.get("description")
                        or "Potential secret detected"
                    ),
                    "description": (
                        "Gitleaks detected a potential secret. The value is redacted."
                    ),
                    "location": f"{path}:{line}" if line else path,
                }
            )
        )
    return {
        "status": finding_status(findings),
        "tool": "gitleaks",
        "findings": findings,
    }


def normalize_trivy(data: dict) -> dict:
    findings = []
    for result in data.get("Results", []):
        if not isinstance(result, dict):
            continue
        target = str(result.get("Target") or "trivy")
        vulnerabilities = result.get("Vulnerabilities") or []
        if not isinstance(vulnerabilities, list):
            continue
        for vulnerability in vulnerabilities:
            if not isinstance(vulnerability, dict):
                continue
            package = str(vulnerability.get("PkgName") or "unknown-package")
            installed = str(vulnerability.get("InstalledVersion") or "unknown")
            fixed = str(vulnerability.get("FixedVersion") or "")
            description = (
                f"{package}@{installed} is affected."
                + (f" Fixed version: {fixed}." if fixed else "")
            )
            findings.append(
                gate_policy.with_category(
                    {
                        "id": str(
                            vulnerability.get("VulnerabilityID")
                            or "trivy.vulnerability"
                        ),
                        "severity": str(
                            vulnerability.get("Severity") or "UNKNOWN"
                        ).lower(),
                        "category": "vuln",
                        "title": str(
                            vulnerability.get("Title")
                            or vulnerability.get("VulnerabilityID")
                            or "Trivy vulnerability"
                        ),
                        "description": description,
                        "location": f"{target}:{package}",
                    }
                )
            )
    return {
        "status": finding_status(findings),
        "tool": "trivy",
        "findings": findings,
    }


def normalize_dependency_track(data: dict) -> dict:
    status = str(data.get("status") or "").lower()
    reason = str(data.get("reason") or "unknown")
    succeeded = status == "succeeded"
    return {
        "status": "passed" if succeeded else "error",
        "tool": "dependency-track",
        "findings": [],
        "errors": [] if succeeded else [f"dependency-track-upload-{status}:{reason}"],
    }


def normalize_common_report(data: dict) -> dict:
    findings = gate_policy.annotate_findings(data.get("findings") or [])
    status = str(data.get("status") or "").lower()
    if status not in {"passed", "warning", "failed", "error", "not_found"}:
        status = finding_status(findings)
    elif status == "failed" and findings:
        # Recompute so misconfig-only reports do not stay hard-failed.
        status = finding_status(findings)
    return {
        "status": status,
        "tool": data.get("tool") or "unknown",
        "findings": findings,
        "errors": data.get("errors") or [],
    }


def normalize_report(key: str, data: object) -> dict:
    if key == "sast" and isinstance(data, dict) and isinstance(data.get("results"), list):
        return normalize_semgrep(data)
    if key == "secret_scan" and isinstance(data, list):
        return normalize_gitleaks(data)
    if (
        key == "dependency_scan"
        and isinstance(data, dict)
        and data.get("SchemaVersion") == 2
        and isinstance(data.get("Results"), list)
    ):
        return normalize_trivy(data)
    if key == "dependency_track" and isinstance(data, dict):
        return normalize_dependency_track(data)
    if isinstance(data, dict) and isinstance(data.get("findings"), list):
        return normalize_common_report(data)
    return {
        "status": "error",
        "tool": key,
        "findings": [],
        "errors": ["unsupported-report-schema"],
    }


def load_report(key: str, filename: str) -> dict:
    path = REPORTS_DIR / filename
    if not path.exists():
        print(f"[ERROR] Required report not found: {filename}")
        return {"status": "not_found", "tool": filename, "findings": []}
    try:
        with open(path) as f:
            data = json.load(f)
        return normalize_report(key, data)
    except (json.JSONDecodeError, OSError) as e:
        print(f"[ERROR] Failed to parse {filename}: {e}")
        return {"status": "error", "tool": filename, "findings": []}


def main():
    parser = argparse.ArgumentParser(description="Aggregate Secure Gate reports.")
    parser.add_argument(
        "--reports",
        default=os.environ.get("SECURE_GATE_REPORTS", ""),
        help=(
            "Comma-separated report keys to require. "
            "Default: build,sast,secret_scan,dependency_scan,runtime_validation"
        ),
    )
    args = parser.parse_args()
    try:
        report_files = select_report_files(args.reports)
    except ValueError as error:
        parser.error(str(error))

    REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    summary = {
        "reports": {},
        "total_findings": 0,
        "has_critical": False,
        "has_high": False,
        "has_secret": False,
        "has_medium": False,
        "has_error": False,
        "has_blockable": False,
        "has_warning_only": False,
        "categories": {
            "vuln": 0,
            "misconfig": 0,
            "secret": 0,
            "availability": 0,
            "scanner-error": 0,
        },
    }

    for key, filename in report_files.items():
        report = load_report(key, filename)
        summary["reports"][key] = report
        if report.get("status") in {"error", "not_found"} or report.get("errors"):
            summary["has_error"] = True
            summary["has_blockable"] = True

        for finding in report.get("findings", []):
            summary["total_findings"] += 1
            finding = gate_policy.with_category(finding)
            category = finding["category"]
            if category in summary["categories"]:
                summary["categories"][category] += 1

            severity = str(finding.get("severity", "")).lower()
            if severity == "critical":
                summary["has_critical"] = True
            elif severity == "high":
                summary["has_high"] = True
            elif severity == "secret":
                summary["has_secret"] = True
            elif severity == "medium":
                summary["has_medium"] = True

            if gate_policy.should_block_finding(finding, DEFAULT_POLICY):
                summary["has_blockable"] = True
            elif gate_policy.should_warn_finding(finding, DEFAULT_POLICY):
                summary["has_warning_only"] = True

    with open(SUMMARY_FILE, "w") as f:
        json.dump(summary, f, indent=2)

    print(f"[OK] Security summary → {SUMMARY_FILE}")
    print(f"     Total findings : {summary['total_findings']}")
    print(f"     Critical       : {summary['has_critical']}")
    print(f"     High           : {summary['has_high']}")
    print(f"     Secret         : {summary['has_secret']}")
    print(f"     Medium         : {summary['has_medium']}")
    print(f"     Blockable      : {summary['has_blockable']}")
    print(f"     Report error   : {summary['has_error']}")


if __name__ == "__main__":
    main()
