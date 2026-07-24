#!/usr/bin/env python3
"""
normalize-trivy.py

raw Trivy CVE JSON(dependency-report.json, SchemaVersion 2)을 Secure Gate 공통
스키마 findings 로 변환한다.

배경: C파트 Trivy 스텝은 dependency-report.json 에 raw Trivy JSON 을 쓰지만,
A파트 aggregate-results.py 는 공통 스키마({status, tool, findings[]})를 기대한다.
그 사이 노멀라이저가 없어 Trivy CVE 가 게이트 finding 으로 잡히지 않는다.
(상세: docs/known-issues/trivy-aggregator-gap.md)

이 스크립트는 그 갭의 임시 해소책이며, evaluate-gate.py 가 in-process 로 호출한다.
aggregate-results.py / 워크플로 YAML 은 건드리지 않는다.

공통 스키마에 optional 필드 2개(purl, fixedVersion)를 채워, 보정 레이어가
(purl, CVE) 매칭과 fix 여부 판단에 쓸 수 있게 한다. 기존 소비자는 이 필드를
무시하므로 영향 없음.

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
