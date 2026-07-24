#!/usr/bin/env python3
"""
upload-sbom-to-dependency-track.py

CycloneDX SBOM을 Dependency-Track에 업로드한다.

식별 규칙:
  projectName = secure-gate/github/<owner>/<repo>[/<service>]
  projectVersion = main   (기본; DT는 main 기준 관리)

모노레포:
  service가 있으면 Collection 상위 프로젝트(레포) 아래 APPLICATION 자식으로 올린다.
  없으면 레포 단위 APPLICATION 하나로 올린다.

업로드 정책(기본 main-only):
  push + refs/heads/main 일 때만 실제 업로드.
  PR Gate는 Trivy로 즉시 판단하고, DT는 main/Staging 추적용.

환경변수:
  DEPENDENCY_TRACK_URL, DEPENDENCY_TRACK_API_KEY
  GITHUB_REPOSITORY, GITHUB_REF, GITHUB_EVENT_NAME (선택)
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
from urllib.parse import quote
from urllib.request import Request, urlopen

PROJECT_NAME_PREFIX = "secure-gate/github"
DEFAULT_VERSION = "main"


def write_report(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    safe = {
        "status": payload.get("status", "failed"),
        "reason": payload.get("reason", ""),
        "tool": payload.get("tool", "dependency-track"),
        "target": payload.get("target", "bom-upload"),
        "project_name": payload.get("project_name", ""),
        "project_version": payload.get("project_version", ""),
        "project_uuid": payload.get("project_uuid", ""),
        "parent_name": payload.get("parent_name", ""),
        "service_name": payload.get("service_name", ""),
        "upload_mode": payload.get("upload_mode", ""),
        "created": payload.get("created", False),
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(safe, f, indent=2)
        f.write("\n")


def api_base(url: str) -> str:
    base = url.strip().rstrip("/")
    if base.endswith("/api/v1"):
        return base
    if base.endswith("/api"):
        return f"{base}/v1"
    return f"{base}/api/v1"


def encode_multipart(fields: dict[str, str]) -> tuple[bytes, str]:
    boundary = f"----SecureGateBoundary{uuid.uuid4().hex}"
    body = bytearray()
    for name, value in fields.items():
        body.extend(f"--{boundary}\r\n".encode("utf-8"))
        body.extend(
            f'Content-Disposition: form-data; name="{name}"\r\n\r\n'.encode("utf-8")
        )
        body.extend(value.encode("utf-8"))
        body.extend(b"\r\n")
    body.extend(f"--{boundary}--\r\n".encode("utf-8"))
    return bytes(body), f"multipart/form-data; boundary={boundary}"


def read_http_error_body(exc: HTTPError) -> str:
    try:
        return exc.read().decode("utf-8", errors="replace").strip()
    except Exception:  # noqa: BLE001
        return ""


def http_json(
    method: str,
    url: str,
    api_key: str,
    data: bytes | None = None,
    content_type: str | None = None,
) -> tuple[int, Any]:
    headers = {
        "X-Api-Key": api_key,
        "Accept": "application/json",
    }
    if content_type:
        headers["Content-Type"] = content_type
    request = Request(url, data=data, method=method, headers=headers)
    try:
        with urlopen(request, timeout=60) as response:
            status = getattr(response, "status", None) or response.getcode()
            raw = response.read().decode("utf-8", errors="replace")
            if not raw:
                return status, None
            try:
                return status, json.loads(raw)
            except json.JSONDecodeError:
                return status, raw
    except HTTPError as exc:
        raise


def build_project_names(repository: str, service_name: str) -> tuple[str, str]:
    """Return (project_name, parent_name). parent_name empty when no service."""
    repo = repository.strip().strip("/")
    if not repo or "/" not in repo:
        raise ValueError(
            "repository must look like owner/repo "
            f"(got {repository!r})"
        )
    service = service_name.strip().strip("/")
    parent = f"{PROJECT_NAME_PREFIX}/{repo}"
    if service:
        return f"{parent}/{service}", parent
    return parent, ""


def should_skip_for_upload_mode(upload_mode: str) -> str | None:
    mode = (upload_mode or "main-only").strip().lower()
    if mode == "always":
        return None
    if mode == "never":
        return "upload-disabled"
    # main-only
    event = os.environ.get("GITHUB_EVENT_NAME", "").strip()
    ref = os.environ.get("GITHUB_REF", "").strip()
    if event == "push" and ref == "refs/heads/main":
        return None
    return "not-main-branch"


def resolve_config_skip(url: str, api_key: str, repository: str) -> str | None:
    if url and api_key and repository:
        return None
    if repository and (not url or not api_key):
        return "secrets-unavailable"
    return "not-configured"


def lookup_project(
    base: str, api_key: str, name: str, version: str
) -> dict[str, Any] | None:
    # GET /api/v1/project/lookup?name=&version=
    q = f"name={quote(name)}&version={quote(version)}"
    url = f"{base}/project/lookup?{q}"
    try:
        status, body = http_json("GET", url, api_key)
        if status == 200 and isinstance(body, dict) and body.get("uuid"):
            return body
        return None
    except HTTPError as exc:
        if exc.code == 404:
            return None
        raise


def ensure_collection_parent(
    base: str, api_key: str, parent_name: str, version: str
) -> dict[str, Any]:
    existing = lookup_project(base, api_key, parent_name, version)
    if existing:
        return existing
    payload = {
        "name": parent_name,
        "version": version,
        "classifier": "COLLECTION",
        "collectionLogic": "AGGREGATE_DIRECT_CHILDREN",
        "active": True,
    }
    status, body = http_json(
        "PUT",
        f"{base}/project",
        api_key,
        data=json.dumps(payload).encode("utf-8"),
        content_type="application/json",
    )
    if status not in (200, 201) or not isinstance(body, dict) or not body.get("uuid"):
        raise RuntimeError(f"Failed to create collection project HTTP {status}: {body}")
    return body


def upload_bom_auto_create(
    base: str,
    api_key: str,
    *,
    project_name: str,
    project_version: str,
    parent_name: str,
    sbom_path: Path,
) -> None:
    fields = {
        "autoCreate": "true",
        "projectName": project_name,
        "projectVersion": project_version,
        "isLatest": "true",
        "bom": sbom_path.read_text(encoding="utf-8"),
    }
    if parent_name:
        fields["parentName"] = parent_name
        fields["parentVersion"] = project_version
    body, content_type = encode_multipart(fields)
    status, _ = http_json(
        "POST",
        f"{base}/bom",
        api_key,
        data=body,
        content_type=content_type,
    )
    if status < 200 or status >= 300:
        raise RuntimeError(f"Unexpected HTTP status: {status}")


def validate_sbom(sbom_path: Path) -> str | None:
    if not sbom_path.is_file():
        return "sbom-missing"
    try:
        sbom = json.loads(sbom_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return "invalid-sbom-json"
    if sbom.get("bomFormat") != "CycloneDX":
        return "invalid-bom-format"
    if sbom.get("specVersion") != "1.6":
        return "unsupported-spec-version"
    return None


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Upload CycloneDX SBOM to Dependency-Track by GitHub repo/service name"
    )
    parser.add_argument("--sbom", required=True, help="Path to CycloneDX SBOM JSON")
    parser.add_argument(
        "--repository",
        default="",
        help="GitHub repository owner/repo (default: GITHUB_REPOSITORY)",
    )
    parser.add_argument(
        "--service-name",
        default="",
        help="Monorepo deployable unit name (frontend/backend). Empty = whole repo project",
    )
    parser.add_argument(
        "--project-version",
        default=DEFAULT_VERSION,
        help=f"DT project version (default: {DEFAULT_VERSION})",
    )
    parser.add_argument(
        "--upload-mode",
        default="main-only",
        choices=("main-only", "always", "never"),
        help="When to upload (default: main-only)",
    )
    parser.add_argument(
        "--report",
        required=True,
        help="Path to write dependency-track-upload-report.json",
    )
    args = parser.parse_args()

    report_path = Path(args.report)
    sbom_path = Path(args.sbom)
    repository = (args.repository or os.environ.get("GITHUB_REPOSITORY", "")).strip()
    service_name = (args.service_name or "").strip()
    project_version = (args.project_version or DEFAULT_VERSION).strip() or DEFAULT_VERSION
    upload_mode = (args.upload_mode or "main-only").strip().lower()
    url = os.environ.get("DEPENDENCY_TRACK_URL", "").strip()
    api_key = os.environ.get("DEPENDENCY_TRACK_API_KEY", "").strip()

    project_name = ""
    parent_name = ""
    try:
        if repository:
            project_name, parent_name = build_project_names(repository, service_name)
    except ValueError as exc:
        write_report(
            report_path,
            {
                "status": "failed",
                "reason": "invalid-repository",
                "upload_mode": upload_mode,
                "service_name": service_name,
            },
        )
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 1

    base_payload: dict[str, Any] = {
        "tool": "dependency-track",
        "target": "bom-upload",
        "project_name": project_name,
        "project_version": project_version,
        "parent_name": parent_name,
        "service_name": service_name,
        "upload_mode": upload_mode,
        "project_uuid": "",
        "created": False,
    }

    try:
        cfg_skip = resolve_config_skip(url, api_key, repository)
        if cfg_skip:
            print(f"[WARN] Dependency-Track upload skipped: {cfg_skip}")
            write_report(
                report_path, {**base_payload, "status": "skipped", "reason": cfg_skip}
            )
            return 0

        mode_skip = should_skip_for_upload_mode(upload_mode)
        if mode_skip:
            print(f"[WARN] Dependency-Track upload skipped: {mode_skip}")
            write_report(
                report_path, {**base_payload, "status": "skipped", "reason": mode_skip}
            )
            return 0

        sbom_err = validate_sbom(sbom_path)
        if sbom_err:
            write_report(
                report_path, {**base_payload, "status": "failed", "reason": sbom_err}
            )
            print(f"[ERROR] SBOM validation failed: {sbom_err}", file=sys.stderr)
            return 1

        base = api_base(url)
        existed = lookup_project(base, api_key, project_name, project_version)
        created = existed is None

        if parent_name:
            ensure_collection_parent(base, api_key, parent_name, project_version)

        upload_bom_auto_create(
            base,
            api_key,
            project_name=project_name,
            project_version=project_version,
            parent_name=parent_name,
            sbom_path=sbom_path,
        )

        # Re-lookup UUID after upload/create for the report.
        after = lookup_project(base, api_key, project_name, project_version) or {}
        write_report(
            report_path,
            {
                **base_payload,
                "status": "succeeded",
                "reason": "bom-received",
                "project_uuid": after.get("uuid", ""),
                "created": created,
            },
        )
        print(
            "[INFO] Dependency-Track accepted BOM upload "
            f"(project={project_name}@{project_version}, created={created}; "
            "analysis may still be pending)"
        )
        return 0

    except HTTPError as exc:
        reason = f"http-{exc.code}"
        detail = read_http_error_body(exc)
        write_report(
            report_path, {**base_payload, "status": "failed", "reason": reason}
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
    except Exception as exc:  # noqa: BLE001
        write_report(
            report_path,
            {**base_payload, "status": "failed", "reason": "script-exception"},
        )
        print(f"[ERROR] Dependency-Track upload exception: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
