#!/usr/bin/env python3
"""
normalize-trivy.py

raw Trivy CVE JSON(dependency-report.json, SchemaVersion 2)을 Secure Gate 공통
스키마 findings 로 변환한다.

배경: raw Trivy JSON(dependency-report.json)을 공통 스키마
({status, tool, findings[]})로 변환한다. 운영 경로의 정규화는
aggregate-results.py 가 담당하며, 이 모듈은 동일한 optional 필드
(purl, fixedVersion)를 채우는 공유 구현/CLI 로 유지한다.

공통 스키마에 optional 필드 2개(purl, fixedVersion)를 채워, CVE 보정
레이어가 (purl, CVE) 매칭과 fix 여부 판단에 쓸 수 있게 한다.

CLI (독립 실행):
  python normalize-trivy.py --in dependency-report.json --out normalized.json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def _first_cvss_purl(vuln: dict) -> str | None:
    ident = vuln.get("PkgIdentifier") or {}
    purl = ident.get("PURL")
    return purl or None


def normalize(raw: dict) -> dict:
    """raw Trivy dict → 공통 스키마 report dict."""
    findings: list[dict] = []

    for result in raw.get("Results", []) or []:
        target = result.get("Target", "")
        for vuln in result.get("Vulnerabilities", []) or []:
            cve = vuln.get("VulnerabilityID")
            if not cve:
                continue
            pkg = vuln.get("PkgName", "")
            installed = vuln.get("InstalledVersion", "")
            fixed = vuln.get("FixedVersion") or None
            severity = vuln.get("Severity")  # CRITICAL/HIGH/MEDIUM/LOW/UNKNOWN
            title = vuln.get("Title") or vuln.get("VulnerabilityID")
            desc = vuln.get("Description") or ""
            purl = _first_cvss_purl(vuln)

            location = f"{pkg}@{installed}" if pkg else target

            findings.append({
                "id": cve,
                "severity": severity,
                "title": title,
                "description": desc,
                "location": location,
                # optional (보정 레이어용)
                "purl": purl,
                "fixedVersion": fixed,
            })

    status = "failed" if findings else "passed"
    return {"status": status, "tool": "trivy", "findings": findings}


def main() -> int:
    parser = argparse.ArgumentParser(description="Normalize raw Trivy CVE JSON to Secure Gate common schema")
    parser.add_argument("--in", dest="infile", required=True, help="raw Trivy dependency-report.json")
    parser.add_argument("--out", dest="outfile", required=True, help="normalized common-schema output")
    args = parser.parse_args()

    inpath = Path(args.infile)
    if not inpath.is_file():
        print(f"[ERROR] input not found: {inpath}", file=sys.stderr)
        return 1
    try:
        raw = json.loads(inpath.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        print(f"[ERROR] invalid JSON: {e}", file=sys.stderr)
        return 1
    if raw.get("SchemaVersion") is None:
        print("[ERROR] not a raw Trivy report (missing SchemaVersion)", file=sys.stderr)
        return 1

    report = normalize(raw)
    Path(args.outfile).write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"[OK] normalized {len(report['findings'])} findings -> {args.outfile}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
