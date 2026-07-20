#!/usr/bin/env python3
"""
sbom-extract-purls.py

CycloneDX SBOM을 읽어 각 컴포넌트의 purl(package URL)을 추출한다.
이번 단계는 OSV/EPSS/KEV 조회 없이 "SBOM -> purl 목록" 변환까지만 검증한다.

지금은 security/sbom/mock-sbom.json(mock)을 읽지만, 나중에 실제 SBOM
(syft/trivy가 생성한 CycloneDX 파일)으로 SBOM_FILE 경로만 바꿔 끼우면
extract_components() 이하 로직은 그대로 재사용 가능하도록 구성했다.

CycloneDX는 components 하위에 transitive dependency를 다시
components 배열로 중첩시키는 경우가 있어, extract_components()는
재귀적으로 순회한다.
"""

import json
import sys
from pathlib import Path

SBOM_FILE = Path("security/sbom/mock-sbom.json")


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
