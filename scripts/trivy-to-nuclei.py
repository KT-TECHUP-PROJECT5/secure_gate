#!/usr/bin/env python3
"""
Extract CVE template IDs from a raw Trivy JSON report for a targeted Nuclei scan.

The output is one CVE ID per line. Nuclei accepts this file directly through
its --template-id/-id option.
"""

import argparse
import json
import re
import sys
from pathlib import Path


DEFAULT_OUTPUT_PATH = Path("security/reports/nuclei-cve-ids.txt")
DEFAULT_SEVERITIES = {"CRITICAL", "HIGH"}
SUPPORTED_SEVERITIES = {"UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"}
CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)


def parse_severities(raw_value):
    severities = {item.strip().upper() for item in raw_value.split(",") if item.strip()}
    unknown = severities - SUPPORTED_SEVERITIES

    if unknown:
        values = ", ".join(sorted(unknown))
        raise ValueError(f"Unsupported Trivy severity: {values}")
    if not severities:
        raise ValueError("At least one Trivy severity is required")

    return severities


def load_trivy_report(path):
    try:
        with path.open(encoding="utf-8") as file:
            report = json.load(file)
    except FileNotFoundError as error:
        raise ValueError(f"Trivy report not found: {path}") from error
    except json.JSONDecodeError as error:
        raise ValueError(f"Invalid JSON in Trivy report {path}: {error}") from error
    except OSError as error:
        raise ValueError(f"Could not read Trivy report {path}: {error}") from error

    if not isinstance(report, dict):
        raise ValueError("Trivy report root must be a JSON object")
    if not isinstance(report.get("Results"), list):
        raise ValueError("Trivy report must contain a Results array")

    return report


def iter_trivy_vulnerabilities(report):
    for result in report["Results"]:
        if not isinstance(result, dict):
            continue

        vulnerabilities = result.get("Vulnerabilities") or []
        if not isinstance(vulnerabilities, list):
            continue

        for vulnerability in vulnerabilities:
            if isinstance(vulnerability, dict):
                yield vulnerability


def extract_cve_ids(report, severities):
    cve_ids = set()

    for vulnerability in iter_trivy_vulnerabilities(report):
        severity = str(vulnerability.get("Severity") or "").strip().upper()
        vulnerability_id = str(vulnerability.get("VulnerabilityID") or "").strip().upper()

        if severity in severities and CVE_PATTERN.fullmatch(vulnerability_id):
            cve_ids.add(vulnerability_id)

    return sorted(cve_ids)


def write_nuclei_ids(path, cve_ids):
    path.parent.mkdir(parents=True, exist_ok=True)
    content = "\n".join(cve_ids)
    if content:
        content += "\n"
    path.write_text(content, encoding="utf-8")


def parse_args():
    parser = argparse.ArgumentParser(
        description="Convert raw Trivy JSON CVEs into a Nuclei template ID input file."
    )
    parser.add_argument("trivy_report", type=Path, help="Path to the raw Trivy JSON report")
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT_PATH,
        help=f"Nuclei template ID output path (default: {DEFAULT_OUTPUT_PATH})",
    )
    parser.add_argument(
        "--severities",
        default=",".join(sorted(DEFAULT_SEVERITIES)),
        help="Comma-separated Trivy severities to include (default: CRITICAL,HIGH)",
    )
    return parser.parse_args()


def main():
    args = parse_args()

    try:
        severities = parse_severities(args.severities)
        report = load_trivy_report(args.trivy_report)
        cve_ids = extract_cve_ids(report, severities)
        write_nuclei_ids(args.output, cve_ids)
    except ValueError as error:
        print(f"[ERROR] {error}", file=sys.stderr)
        return 2

    print(f"[OK] Extracted {len(cve_ids)} unique CVE IDs to {args.output}")
    if not cve_ids:
        print("[INFO] No matching CVEs. Skip the targeted Nuclei scan.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
