#!/usr/bin/env python3
"""
upload-sbom-to-dependency-track.py

CycloneDX SBOM을 기존 Dependency-Track 프로젝트(UUID)에 업로드한다.
프로젝트 자동 생성(autoCreate)은 하지 않는다.

환경변수:
  DEPENDENCY_TRACK_URL      Backend API base URL (UI 주소 아님)
  DEPENDENCY_TRACK_API_KEY  API Key (로그·리포트에 기록 금지)

CLI:
  --sbom PATH
  --project-uuid UUID
  --report PATH

Exit:
  0  succeeded | skipped
  1  failed (API/네트워크/스크립트 예외)
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import uuid
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


def write_report(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    # Never persist secrets.
    safe = {
        "status": payload.get("status", "failed"),
        "project_uuid": payload.get("project_uuid", ""),
        "reason": payload.get("reason", ""),
    }
    if "tool" in payload:
        safe["tool"] = payload["tool"]
    if "target" in payload:
        safe["target"] = payload["target"]
    with open(path, "w", encoding="utf-8") as f:
        json.dump(safe, f, indent=2)
        f.write("\n")


def normalize_bom_url(base_url: str) -> str:
    """Normalize Backend API base URL to .../api/v1/bom."""
    url = base_url.strip().rstrip("/")
    if url.endswith("/api/v1/bom"):
        return url
    if url.endswith("/api/v1"):
        return f"{url}/bom"
    if url.endswith("/api"):
        return f"{url}/v1/bom"
    return f"{url}/api/v1/bom"


def encode_multipart(
    fields: dict[str, str],
    files: dict[str, tuple[str, bytes, str]] | None = None,
) -> tuple[bytes, str]:
    boundary = f"----SecureGateBoundary{uuid.uuid4().hex}"
    body = bytearray()

    for name, value in fields.items():
        body.extend(f"--{boundary}\r\n".encode("utf-8"))
        body.extend(
            f'Content-Disposition: form-data; name="{name}"\r\n\r\n'.encode("utf-8")
        )
        body.extend(value.encode("utf-8"))
        body.extend(b"\r\n")

    for name, (filename, content, content_type) in (files or {}).items():
        body.extend(f"--{boundary}\r\n".encode("utf-8"))
        body.extend(
            (
                f'Content-Disposition: form-data; name="{name}"; '
                f'filename="{filename}"\r\n'
            ).encode("utf-8")
        )
        body.extend(f"Content-Type: {content_type}\r\n\r\n".encode("utf-8"))
        body.extend(content)
        body.extend(b"\r\n")

    body.extend(f"--{boundary}--\r\n".encode("utf-8"))
    return bytes(body), f"multipart/form-data; boundary={boundary}"


def read_http_error_body(exc: HTTPError) -> str:
    try:
        raw = exc.read().decode("utf-8", errors="replace")
    except Exception:  # noqa: BLE001
        return ""
    # Never echo secrets; body should be DT error JSON/text only.
    return raw.strip()


def resolve_skip_reason(url: str, api_key: str, project_uuid: str) -> str | None:
    """Return skip reason if upload should not run, else None."""
    if url and api_key and project_uuid:
        return None
    # Caller set project UUID but secrets were not injected (e.g. fork PR).
    if project_uuid and (not url or not api_key):
        return "secrets-unavailable"
    return "not-configured"


def upload_bom(url: str, api_key: str, project_uuid: str, sbom_path: Path) -> None:
    # Official CI docs accept bom as a multipart form field (file or inline content).
    # Prefer form-field content; DT is picky about some file-part encodings.
    bom_text = sbom_path.read_text(encoding="utf-8")
    body, content_type = encode_multipart(
        fields={
            "project": project_uuid,
            "bom": bom_text,
        },
    )
    endpoint = normalize_bom_url(url)
    request = Request(
        endpoint,
        data=body,
        method="POST",
        headers={
            "X-Api-Key": api_key,
            "Content-Type": content_type,
            "Accept": "application/json",
        },
    )
    with urlopen(request, timeout=60) as response:
        # Dependency-Track returns 200 with a token on successful BOM receipt.
        status = getattr(response, "status", None) or response.getcode()
        if status < 200 or status >= 300:
            raise RuntimeError(f"Unexpected HTTP status: {status}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Upload CycloneDX SBOM to an existing Dependency-Track project UUID"
    )
    parser.add_argument("--sbom", required=True, help="Path to CycloneDX SBOM JSON")
    parser.add_argument(
        "--project-uuid",
        default="",
        help="Existing Dependency-Track project UUID (no autoCreate)",
    )
    parser.add_argument(
        "--report",
        required=True,
        help="Path to write dependency-track-upload-report.json",
    )
    args = parser.parse_args()

    report_path = Path(args.report)
    sbom_path = Path(args.sbom)
    project_uuid = (args.project_uuid or "").strip()
    url = os.environ.get("DEPENDENCY_TRACK_URL", "").strip()
    api_key = os.environ.get("DEPENDENCY_TRACK_API_KEY", "").strip()

    base_payload: dict[str, Any] = {
        "project_uuid": project_uuid,
        "tool": "dependency-track",
        "target": "bom-upload",
    }

    try:
        skip_reason = resolve_skip_reason(url, api_key, project_uuid)
        if skip_reason:
            print(f"[WARN] Dependency-Track upload skipped: {skip_reason}")
            write_report(
                report_path,
                {**base_payload, "status": "skipped", "reason": skip_reason},
            )
            return 0

        if not sbom_path.is_file():
            write_report(
                report_path,
                {
                    **base_payload,
                    "status": "failed",
                    "reason": "sbom-missing",
                },
            )
            print(f"[ERROR] SBOM file not found: {sbom_path}", file=sys.stderr)
            return 1

        # Defensive check only — Job already validates bomFormat/specVersion before this step.
        try:
            sbom = json.loads(sbom_path.read_text(encoding="utf-8"))
            if sbom.get("bomFormat") != "CycloneDX":
                write_report(
                    report_path,
                    {
                        **base_payload,
                        "status": "failed",
                        "reason": "invalid-bom-format",
                    },
                )
                print("[ERROR] SBOM bomFormat is not CycloneDX", file=sys.stderr)
                return 1
            if sbom.get("specVersion") != "1.6":
                write_report(
                    report_path,
                    {
                        **base_payload,
                        "status": "failed",
                        "reason": "unsupported-spec-version",
                    },
                )
                print(
                    f"[ERROR] SBOM specVersion must be 1.6 (got {sbom.get('specVersion')!r})",
                    file=sys.stderr,
                )
                return 1
        except json.JSONDecodeError:
            write_report(
                report_path,
                {
                    **base_payload,
                    "status": "failed",
                    "reason": "invalid-sbom-json",
                },
            )
            print("[ERROR] SBOM is not valid JSON", file=sys.stderr)
            return 1

        upload_bom(url, api_key, project_uuid, sbom_path)
        write_report(
            report_path,
            {**base_payload, "status": "succeeded", "reason": "bom-received"},
        )
        print("[INFO] Dependency-Track accepted BOM upload (analysis may still be pending)")
        return 0

    except HTTPError as exc:
        reason = f"http-{exc.code}"
        detail = read_http_error_body(exc)
        write_report(
            report_path,
            {**base_payload, "status": "failed", "reason": reason},
        )
        print(f"[ERROR] Dependency-Track API error: HTTP {exc.code}", file=sys.stderr)
        if detail:
            print(f"[ERROR] Response body: {detail}", file=sys.stderr)
        return 1
    except URLError as exc:
        write_report(
            report_path,
            {**base_payload, "status": "failed", "reason": "network-error"},
        )
        print(f"[ERROR] Dependency-Track network error: {exc.reason}", file=sys.stderr)
        return 1
    except Exception as exc:  # noqa: BLE001 — surface as failed report, non-blocking step
        write_report(
            report_path,
            {
                **base_payload,
                "status": "failed",
                "reason": "script-exception",
            },
        )
        print(f"[ERROR] Dependency-Track upload exception: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
