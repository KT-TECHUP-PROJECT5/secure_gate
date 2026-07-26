#!/usr/bin/env python3
"""
sbom-extract-purls.py

CycloneDX SBOM을 읽어 각 컴포넌트의 purl(package URL)을 추출한다.
이번 단계는 OSV/EPSS/KEV 조회 없이 "SBOM -> purl 목록" 변환까지만 검증한다.

SBOM 소스는 C파트가 산출하는 정식 CycloneDX 계약 파일
(security/reports/sbom.cdx.json, specVersion 1.6, caller cwd)이다.
extract_components() 이하 로직은 mock/실제 SBOM 모두에서 동일하게 동작한다.

CycloneDX는 components 하위에 transitive dependency를 다시
components 배열로 중첩시키는 경우가 있어, extract_components()는
재귀적으로 순회한다. Trivy SBOM은 앱/OS 그룹 노드에 purl이 없을 수 있고,
그런 노드는 [WARN]로 건너뛴다(정상 동작).
"""

import json
import sys
from pathlib import Path

SBOM_FILE = Path("security/reports/sbom.cdx.json")


def load_sbom(path: Path) -> dict:
    if not path.exists():
        print(f"[ERROR] SBOM file not found: {path}")
        sys.exit(1)
    with open(path) as f:
        return json.load(f)


def extract_components(sbom: dict) -> list[dict]:
    """SBOM에서 purl이 있는 컴포넌트만 {name, version, purl} 형태로 추출한다."""
    components = []

    def walk(nodes: list) -> None:
        for node in nodes:
            purl = node.get("purl")
            if purl:
                components.append({
                    "name": node.get("name"),
                    "version": node.get("version"),
                    "purl": purl,
                })
            else:
                print(f"[WARN] purl 없는 컴포넌트 건너뜀: {node.get('name')}")

            nested = node.get("components")
            if nested:
                walk(nested)

    walk(sbom.get("components", []))
    return components


def extract_purls(components: list[dict]) -> list[str]:
    """OSV querybatch 등 다음 단계에서 바로 쓸 수 있도록 purl 문자열만 뽑는다."""
    return [c["purl"] for c in components]


def main():
    sbom = load_sbom(SBOM_FILE)
    components = extract_components(sbom)
    purls = extract_purls(components)

    print(f"[OK] {len(components)}개 컴포넌트에서 purl 추출")
    for c in components:
        print(f"  - {c['name']}@{c['version']} -> {c['purl']}")

    return purls


if __name__ == "__main__":
    main()
