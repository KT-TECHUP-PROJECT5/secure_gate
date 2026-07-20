#!/usr/bin/env python3
"""
osv-query.py

1단계(sbom-extract-purls.py)가 추출한 purl 목록을 OSV.dev에 조회해
각 패키지의 취약점 ID를 받아오고, CVE 번호로 정규화한다.

- POST /v1/querybatch : purl 목록 -> 패키지별 취약점 ID(osv id) 목록
- GET  /v1/vulns/{id} : 취약점 ID 상세 -> aliases에서 "CVE-" 접두사 값 추출

OSV가 주는 취약점 ID(GHSA-, PYSEC- 등)는 그 자체로 CVE가 아닌 경우가
많다. 다음 단계(EPSS/KEV)는 CVE 번호로만 조회되므로, 이 스크립트는
CVE로 정규화되는 것과 안 되는 것을 모두 남긴다. CVE가 없는 취약점도
버리지 않고 cve_status: "no_cve"로 표시해 뒤 단계가 최소한 CVSS만으로
판단하거나 기록할 수 있게 한다.
"""

import importlib.util
import json
import sys
import urllib.error
import urllib.request
from pathlib import Path

SBOM_FILE = Path("security/sbom/mock-sbom.json")
OUTPUT_FILE = Path("security/sbom/generated/osv-vulnerabilities.json")

OSV_QUERYBATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/{}"
REQUEST_TIMEOUT = 10


def _load_purl_extractor():
    """파일명에 하이픈이 있어 일반 import가 안 되므로 경로로 직접 로드한다."""
    module_path = Path(__file__).parent / "sbom-extract-purls.py"
    spec = importlib.util.spec_from_file_location("sbom_extract_purls", module_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _post_json(url: str, payload: dict) -> dict:
    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        url, data=data, headers={"Content-Type": "application/json"}, method="POST"
    )
    with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as resp:
        return json.loads(resp.read())


def _get_json(url: str) -> dict:
    with urllib.request.urlopen(url, timeout=REQUEST_TIMEOUT) as resp:
        return json.loads(resp.read())


def query_osv_batch(purls: list[str]) -> list[dict]:
    """purl 목록을 OSV querybatch에 던져 패키지별 취약점 ID 목록을 받는다.

    요청 자체가 실패하면(네트워크/timeout) 빈 결과로 대체해 파이프라인이
    죽지 않고 "조회 실패"로 계속 진행되게 한다.
    """
    queries = [{"package": {"purl": purl}} for purl in purls]
    try:
        result = _post_json(OSV_QUERYBATCH_URL, {"queries": queries})
    except (urllib.error.URLError, TimeoutError) as e:
        print(f"[ERROR] OSV querybatch 요청 실패: {e}")
        return [{"vulns": [], "_osv_lookup_failed": True} for _ in purls]
    return result.get("results", [])


def fetch_vuln_detail(vuln_id: str) -> dict | None:
    """취약점 ID 상세 조회. 실패하면 None을 반환하고 호출부에서 표시한다."""
    try:
        return _get_json(OSV_VULN_URL.format(vuln_id))
    except (urllib.error.URLError, TimeoutError) as e:
        print(f"[WARN] {vuln_id} 상세 조회 실패: {e}")
        return None


def extract_cve(detail: dict) -> str | None:
    for alias in detail.get("aliases", []):
        if alias.startswith("CVE-"):
            return alias
    return None


def extract_cvss(detail: dict) -> str | None:
    """OSV severity 배열에서 CVSS_V3 벡터를 찾는다. 없으면 다른 타입이라도 반환."""
    severities = detail.get("severity", [])
    for s in severities:
        if s.get("type") == "CVSS_V3":
            return s.get("score")
    if severities:
        return severities[0].get("score")
    return None


def extract_severity_grade(detail: dict) -> str | None:
    """database_specific.severity(CRITICAL/HIGH/MODERATE/LOW)를 추출한다.

    GitHub이 리뷰한 GHSA 항목에만 있고, PYSEC 등 다른 출처 항목에는
    없는 경우가 많다. 없으면 None을 반환해 "등급 없음"으로 남긴다.
    """
    return detail.get("database_specific", {}).get("severity")


def extract_fixed_versions(detail: dict, package_name: str) -> list[str]:
    """affected[].ranges[].events[].fixed 에서 수정된 버전을 모두 모은다.

    같은 취약점 상세에 다른 패키지의 affected 항목이 섞여 있을 수 있어
    package_name이 일치하는 항목만 본다.
    """
    fixed = set()
    for affected in detail.get("affected", []):
        if affected.get("package", {}).get("name", "").lower() != package_name.lower():
            continue
        for r in affected.get("ranges", []):
            for event in r.get("events", []):
                if "fixed" in event:
                    fixed.add(event["fixed"])
    return sorted(fixed)


def resolve_vulnerabilities(vuln_stubs: list[dict], osv_lookup_failed: bool, package_name: str) -> list[dict]:
    vulnerabilities = []

    if osv_lookup_failed:
        return vulnerabilities

    for stub in vuln_stubs:
        osv_id = stub.get("id")
        detail = fetch_vuln_detail(osv_id)

        if detail is None:
            vulnerabilities.append({
                "osv_id": osv_id,
                "cve": None,
                "cve_status": "detail_lookup_failed",
                "summary": None,
                "cvss": None,
                "severity_grade": None,
                "fixed_versions": [],
            })
            continue

        cve = extract_cve(detail)
        vulnerabilities.append({
            "osv_id": osv_id,
            "cve": cve,
            "cve_status": "mapped" if cve else "no_cve",
            "summary": detail.get("summary"),
            "cvss": extract_cvss(detail),
            "severity_grade": extract_severity_grade(detail),
            "fixed_versions": extract_fixed_versions(detail, package_name),
        })

    return vulnerabilities


def main():
    sbom_module = _load_purl_extractor()
    sbom = sbom_module.load_sbom(SBOM_FILE)
    components = sbom_module.extract_components(sbom)
    purls = sbom_module.extract_purls(components)

    print(f"[INFO] OSV querybatch 요청: {len(purls)}개 purl")
    batch_results = query_osv_batch(purls)

    package_reports = []
    total_vulns = 0
    total_cve_mapped = 0
    total_no_cve = 0
    osv_failed_packages = 0

    for component, batch_result in zip(components, batch_results):
        osv_lookup_failed = batch_result.get("_osv_lookup_failed", False)
        if osv_lookup_failed:
            osv_failed_packages += 1

        vulnerabilities = resolve_vulnerabilities(
            batch_result.get("vulns", []),
            osv_lookup_failed,
            component["name"],
        )

        for v in vulnerabilities:
            total_vulns += 1
            if v["cve_status"] == "mapped":
                total_cve_mapped += 1
            elif v["cve_status"] == "no_cve":
                total_no_cve += 1

        package_reports.append({
            "name": component["name"],
            "version": component["version"],
            "purl": component["purl"],
            "osv_lookup_failed": osv_lookup_failed,
            "vulnerabilities": vulnerabilities,
        })

    output = {
        "source_sbom": str(SBOM_FILE),
        "total_packages": len(package_reports),
        "osv_lookup_failed_packages": osv_failed_packages,
        "total_vulnerabilities": total_vulns,
        "cve_mapped": total_cve_mapped,
        "no_cve": total_no_cve,
        "packages": package_reports,
    }

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT_FILE, "w") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)

    print(f"\n[OK] OSV 조회 결과 -> {OUTPUT_FILE}")
    for pkg in package_reports:
        if pkg["osv_lookup_failed"]:
            print(f"  - {pkg['name']}@{pkg['version']}: [조회 실패] OSV 응답 없음 — 판단 불가")
            continue
        if not pkg["vulnerabilities"]:
            print(f"  - {pkg['name']}@{pkg['version']}: 취약점 없음")
            continue
        print(f"  - {pkg['name']}@{pkg['version']}: {len(pkg['vulnerabilities'])}개 취약점")
        for v in pkg["vulnerabilities"]:
            cve_display = v["cve"] or f"CVE 없음 ({v['cve_status']})"
            print(f"      {v['osv_id']} -> {cve_display}")

    print(
        f"\n[SUMMARY] 총 {total_vulns}개 취약점 / "
        f"CVE 매핑 {total_cve_mapped}개 / CVE 없음 {total_no_cve}개 / "
        f"OSV 조회 실패 패키지 {osv_failed_packages}개"
    )

    return output


if __name__ == "__main__":
    main()
