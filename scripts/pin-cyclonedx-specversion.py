#!/usr/bin/env python3
"""
pin-cyclonedx-specversion.py

Trivy 등 도구가 만든 CycloneDX SBOM의 specVersion을 프로젝트 계약 버전으로 고정한다.
Dependency-Track 5.0.x는 CycloneDX 1.7을 거부하므로 Secure Gate 기본값은 1.6이다.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

DEFAULT_SPEC_VERSION = "1.6"
SCHEMA_BY_VERSION = {
    "1.5": "http://cyclonedx.org/schema/bom-1.5.schema.json",
    "1.6": "http://cyclonedx.org/schema/bom-1.6.schema.json",
}


def pin_spec_version(path: Path, spec_version: str) -> str:
    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("bomFormat") != "CycloneDX":
        raise ValueError(f"bomFormat is not CycloneDX: {data.get('bomFormat')!r}")

    previous = str(data.get("specVersion") or "")
    data["specVersion"] = spec_version
    schema = SCHEMA_BY_VERSION.get(spec_version)
    if schema:
        data["$schema"] = schema

    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    return previous


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Pin CycloneDX SBOM specVersion for Secure Gate / Dependency-Track"
    )
    parser.add_argument("--sbom", required=True, help="Path to sbom.cdx.json")
    parser.add_argument(
        "--spec-version",
        default=DEFAULT_SPEC_VERSION,
        help=f"Target CycloneDX specVersion (default: {DEFAULT_SPEC_VERSION})",
    )
    args = parser.parse_args()

    path = Path(args.sbom)
    if not path.is_file():
        print(f"[ERROR] SBOM file not found: {path}", file=sys.stderr)
        return 1

    try:
        previous = pin_spec_version(path, args.spec_version)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"[ERROR] Failed to pin CycloneDX specVersion: {exc}", file=sys.stderr)
        return 1

    print(
        f"[INFO] CycloneDX specVersion pinned: {previous or '<missing>'} -> {args.spec_version} ({path})"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
