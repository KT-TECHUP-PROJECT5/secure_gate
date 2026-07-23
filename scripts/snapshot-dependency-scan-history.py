#!/usr/bin/env python3
"""
snapshot-dependency-scan-history.py

dependency-scan latest 산출물을 history/<run_id>/ 에 스냅샷으로 복사한다.
Gate/DAST 계약 경로(security/reports/*.json)는 그대로 두고, 히스토리만 추가한다.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path

LATEST_FILES = (
    "dependency-report.json",
    "sbom.cdx.json",
    "dependency-track-upload-report.json",
)


def build_run_id() -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    sha = (os.environ.get("GITHUB_SHA") or "local").strip()[:7] or "local"
    run_id = f"{stamp}_{sha}"
    gh_run = (os.environ.get("GITHUB_RUN_ID") or "").strip()
    if gh_run:
        run_id = f"{run_id}_run{gh_run}"
    return run_id


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Snapshot dependency-scan latest reports into history/<run_id>/"
    )
    parser.add_argument(
        "--reports-dir",
        default="security/reports",
        help="Latest reports directory (contract paths)",
    )
    parser.add_argument(
        "--mode",
        default="",
        help="Trivy scan mode (fs|image)",
    )
    parser.add_argument(
        "--trivy-version",
        default="",
        help="Trivy version string",
    )
    parser.add_argument(
        "--cyclonedx-spec",
        default="1.6",
        help="Pinned CycloneDX specVersion",
    )
    args = parser.parse_args()

    reports_dir = Path(args.reports_dir)
    history_root = reports_dir / "history"
    run_id = build_run_id()
    dest = history_root / run_id
    dest.mkdir(parents=True, exist_ok=True)

    copied: list[str] = []
    missing: list[str] = []
    for name in LATEST_FILES:
        src = reports_dir / name
        if src.is_file():
            shutil.copy2(src, dest / name)
            copied.append(name)
        else:
            missing.append(name)

    meta = {
        "run_id": run_id,
        "github_run_id": os.environ.get("GITHUB_RUN_ID", ""),
        "github_run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT", ""),
        "commit": os.environ.get("GITHUB_SHA", ""),
        "ref": os.environ.get("GITHUB_REF", ""),
        "repository": os.environ.get("GITHUB_REPOSITORY", ""),
        "mode": args.mode,
        "trivy_version": args.trivy_version,
        "cyclonedx_spec": args.cyclonedx_spec,
        "copied_files": copied,
        "missing_files": missing,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    (dest / "meta.json").write_text(json.dumps(meta, indent=2) + "\n", encoding="utf-8")

    # Expose for GitHub Actions when available.
    output_file = os.environ.get("GITHUB_OUTPUT")
    if output_file:
        with open(output_file, "a", encoding="utf-8") as fh:
            fh.write(f"run_id={run_id}\n")
            fh.write(f"path={dest.as_posix()}\n")

    print(f"[INFO] dependency-scan history snapshot: {dest}")
    print(f"[INFO] copied={copied} missing={missing}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
