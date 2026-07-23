#!/usr/bin/env python3
"""
Run the D-part Nuclei baseline scan and optional Trivy CVE-targeted scan.

The script keeps pipeline orchestration thin:
1. Convert Trivy High/Critical CVEs to Nuclei template IDs.
2. Run the bounded PR baseline profile.
3. List matching installed templates before starting the targeted scan.
4. Skip the targeted scan when no template matches.
5. Merge both JSONL reports and write coverage metadata.
"""

import argparse
import json
import os
import re
import subprocess
import sys
import uuid
from pathlib import Path
from urllib.parse import urlparse


DEFAULT_REPORTS_DIR = Path("security/reports")
DEFAULT_TRIVY_REPORT = DEFAULT_REPORTS_DIR / "dependency-report.json"
DEFAULT_NUCLEI_IMAGE = "projectdiscovery/nuclei:latest"
DEFAULT_TEMPLATE_VOLUME = "secure-gate-nuclei-templates"
DISABLED_VALUES = {"", "none", "off", "false", "disable", "disabled"}
ANSI_ESCAPE_PATTERN = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")


class NucleiExecutionError(RuntimeError):
    """Raised when Docker, Nuclei, or the Trivy converter cannot complete."""


def env_or_default(name, default):
    return os.environ.get(name) or default


def parse_duration(raw_value):
    value = str(raw_value).strip().lower()
    match = re.fullmatch(r"(\d+)([smh]?)", value)
    if not match:
        raise argparse.ArgumentTypeError(
            f"Invalid duration '{raw_value}'. Use seconds or a value such as 5m."
        )

    amount = int(match.group(1))
    unit = match.group(2)
    multiplier = {"": 1, "s": 1, "m": 60, "h": 3600}[unit]
    seconds = amount * multiplier
    if seconds <= 0:
        raise argparse.ArgumentTypeError("Duration must be greater than zero")
    return seconds


def is_disabled(value):
    return str(value).strip().lower() in DISABLED_VALUES


def validate_target_url(target_url):
    parsed = urlparse(target_url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("Nuclei target URL must be an absolute HTTP(S) URL")


def cleanup_container(container_name):
    if not container_name:
        return
    try:
        subprocess.run(
            ["docker", "rm", "--force", container_name],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=15,
        )
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
        pass


def run_process(
    command,
    timeout_seconds,
    capture_output=False,
    suppress_stdout=False,
    cleanup_container_name=None,
):
    stdout_target = None
    if capture_output:
        stdout_target = subprocess.PIPE
    elif suppress_stdout:
        stdout_target = subprocess.DEVNULL

    try:
        result = subprocess.run(
            command,
            check=False,
            text=True,
            stdout=stdout_target,
            stderr=subprocess.PIPE if capture_output else None,
            timeout=timeout_seconds,
        )
    except FileNotFoundError as error:
        raise NucleiExecutionError(f"Command not found: {command[0]}") from error
    except subprocess.TimeoutExpired as error:
        cleanup_container(cleanup_container_name)
        raise NucleiExecutionError(
            f"Command timed out after {timeout_seconds} seconds: {command[0]}"
        ) from error
    except OSError as error:
        raise NucleiExecutionError(f"Could not execute {command[0]}: {error}") from error

    if result.returncode != 0:
        details = (result.stderr or result.stdout or "").strip()
        if details:
            details = f": {details[-1000:]}"
        raise NucleiExecutionError(
            f"Command failed with exit code {result.returncode}{details}"
        )

    return result


def docker_nuclei_command(
    reports_dir,
    image,
    network,
    template_volume,
    nuclei_arguments,
    reports_read_only=False,
    container_name=None,
):
    mount_mode = "ro" if reports_read_only else "rw"
    command = ["docker", "run", "--rm"]

    if container_name:
        command.extend(["--name", container_name])
    if not is_disabled(network):
        command.extend(["--network", network])
    if not is_disabled(template_volume):
        command.extend(
            ["-v", f"{template_volume}:/root/nuclei-templates"]
        )

    command.extend(
        [
            "-v",
            f"{reports_dir.resolve()}:/app/reports:{mount_mode}",
            image,
        ]
    )
    command.extend(nuclei_arguments)
    return command


def unique_container_name(scan_name):
    suffix = uuid.uuid4().hex[:12]
    return f"secure-gate-nuclei-{scan_name}-{suffix}"


def touch_empty(path):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("", encoding="utf-8")


def run_trivy_converter(converter_path, trivy_report, output_path, severities):
    command = [
        sys.executable,
        str(converter_path),
        str(trivy_report),
        "--output",
        str(output_path),
        "--severities",
        severities,
    ]
    run_process(command, timeout_seconds=60)


def nonempty_lines(path):
    if not path.exists():
        return []
    return [
        line.strip()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def parse_template_paths(raw_output):
    paths = []
    for raw_line in raw_output.splitlines():
        line = ANSI_ESCAPE_PATTERN.sub("", raw_line).strip()
        if not line.endswith((".yaml", ".yml")):
            continue
        if line not in paths:
            paths.append(line)
    return paths


def combine_jsonl(input_paths, output_path):
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("wb") as output_file:
        for input_path in input_paths:
            if not input_path.exists():
                continue
            content = input_path.read_bytes()
            if not content:
                continue
            output_file.write(content)
            if not content.endswith(b"\n"):
                output_file.write(b"\n")


def count_jsonl_records(path):
    count = 0
    if not path.exists():
        return count

    with path.open(encoding="utf-8") as report_file:
        for line_number, raw_line in enumerate(report_file, start=1):
            line = raw_line.strip()
            if not line:
                continue
            try:
                json.loads(line)
            except json.JSONDecodeError as error:
                raise NucleiExecutionError(
                    f"Invalid Nuclei JSONL at {path}:{line_number}: {error}"
                ) from error
            count += 1
    return count


def write_coverage_report(path, payload):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def add_common_scan_arguments(arguments, args):
    arguments.extend(
        [
            "-rate-limit",
            str(args.rate_limit),
            "-c",
            str(args.concurrency),
            "-retries",
            str(args.retries),
            "-timeout",
            str(args.request_timeout),
        ]
    )
    if not args.enable_interactsh:
        arguments.append("-ni")


def build_baseline_arguments(args):
    arguments = ["-u", args.target_url]
    if not is_disabled(args.severities):
        arguments.extend(["-severity", args.severities])
    if not is_disabled(args.tags):
        arguments.extend(["-tags", args.tags])

    add_common_scan_arguments(arguments, args)
    arguments.extend(
        [
            "-jsonl",
            "-omit-raw",
            "-o",
            "/app/reports/nuclei-base-report.jsonl",
            "-silent",
        ]
    )
    return arguments


def build_targeted_arguments(args):
    arguments = [
        "-u",
        args.target_url,
        "-id",
        "/app/reports/nuclei-cve-ids.txt",
    ]
    add_common_scan_arguments(arguments, args)
    arguments.extend(
        [
            "-jsonl",
            "-omit-raw",
            "-o",
            "/app/reports/nuclei-cve-report.jsonl",
            "-silent",
        ]
    )
    return arguments


def parse_args():
    script_dir = Path(__file__).resolve().parent
    default_target = (
        os.environ.get("NUCLEI_TARGET_URL")
        or os.environ.get("ZAP_TARGET_URL")
        or os.environ.get("RUNTIME_BASE_URL")
        or os.environ.get("STAGING_URL")
        or ""
    )

    parser = argparse.ArgumentParser(
        description="Run bounded baseline and Trivy CVE-targeted Nuclei scans."
    )
    parser.add_argument("--target-url", default=default_target)
    parser.add_argument(
        "--trivy-report",
        type=Path,
        default=Path(env_or_default("TRIVY_REPORT_PATH", str(DEFAULT_TRIVY_REPORT))),
    )
    parser.add_argument(
        "--reports-dir",
        type=Path,
        default=Path(env_or_default("SECURITY_REPORTS_DIR", str(DEFAULT_REPORTS_DIR))),
    )
    parser.add_argument(
        "--converter",
        type=Path,
        default=script_dir / "trivy-to-nuclei.py",
    )
    parser.add_argument(
        "--nuclei-image",
        default=env_or_default("NUCLEI_IMAGE", DEFAULT_NUCLEI_IMAGE),
    )
    parser.add_argument(
        "--docker-network",
        default=env_or_default("NUCLEI_DOCKER_NETWORK", "host"),
        help="Docker network name. Use 'none' to omit --network.",
    )
    parser.add_argument(
        "--template-volume",
        default=env_or_default("NUCLEI_TEMPLATE_VOLUME", DEFAULT_TEMPLATE_VOLUME),
        help="Docker volume used to reuse downloaded Nuclei templates.",
    )
    parser.add_argument(
        "--severities",
        default=env_or_default("NUCLEI_SEVERITIES", "medium,high,critical"),
    )
    parser.add_argument(
        "--tags",
        default=env_or_default("NUCLEI_TAGS", "xss"),
    )
    parser.add_argument(
        "--trivy-severities",
        default=env_or_default("TRIVY_NUCLEI_SEVERITIES", "HIGH,CRITICAL"),
    )
    parser.add_argument(
        "--rate-limit",
        type=int,
        default=int(env_or_default("NUCLEI_RATE_LIMIT", "10")),
    )
    parser.add_argument(
        "--concurrency",
        type=int,
        default=int(env_or_default("NUCLEI_CONCURRENCY", "5")),
    )
    parser.add_argument(
        "--retries",
        type=int,
        default=int(env_or_default("NUCLEI_RETRIES", "0")),
    )
    parser.add_argument(
        "--request-timeout",
        type=int,
        default=int(env_or_default("NUCLEI_TIMEOUT_SECONDS", "5")),
    )
    parser.add_argument(
        "--scan-timeout",
        type=parse_duration,
        default=parse_duration(env_or_default("NUCLEI_SCAN_TIMEOUT", "5m")),
    )
    parser.add_argument(
        "--template-list-timeout",
        type=parse_duration,
        default=parse_duration(
            env_or_default("NUCLEI_TEMPLATE_LIST_TIMEOUT", "2m")
        ),
    )
    parser.add_argument(
        "--enable-interactsh",
        action="store_true",
        default=False,
        help="Enable Interactsh. PR scans disable it by default.",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    reports_dir = args.reports_dir.resolve()
    reports_dir.mkdir(parents=True, exist_ok=True)

    candidate_path = reports_dir / "nuclei-cve-ids.txt"
    matched_path = reports_dir / "nuclei-cve-matched-templates.txt"
    baseline_path = reports_dir / "nuclei-base-report.jsonl"
    targeted_path = reports_dir / "nuclei-cve-report.jsonl"
    combined_path = reports_dir / "nuclei-report.jsonl"
    coverage_path = reports_dir / "nuclei-cve-coverage.json"

    candidate_count = 0
    matched_count = 0
    baseline_findings = 0
    targeted_findings = 0

    for output_path in (candidate_path, matched_path, baseline_path, targeted_path):
        touch_empty(output_path)

    try:
        validate_target_url(args.target_url)
        if not args.trivy_report.is_file():
            raise NucleiExecutionError(
                f"Trivy report not found: {args.trivy_report}"
            )
        if not args.converter.is_file():
            raise NucleiExecutionError(
                f"Trivy converter not found: {args.converter}"
            )

        print("[INFO] Extracting Trivy High/Critical CVE candidates", flush=True)
        run_trivy_converter(
            args.converter,
            args.trivy_report,
            candidate_path,
            args.trivy_severities,
        )
        candidate_count = len(nonempty_lines(candidate_path))

        print("[INFO] Running bounded Nuclei baseline scan", flush=True)
        baseline_container = unique_container_name("baseline")
        baseline_command = docker_nuclei_command(
            reports_dir,
            args.nuclei_image,
            args.docker_network,
            args.template_volume,
            build_baseline_arguments(args),
            container_name=baseline_container,
        )
        run_process(
            baseline_command,
            timeout_seconds=args.scan_timeout,
            suppress_stdout=True,
            cleanup_container_name=baseline_container,
        )

        coverage_status = "skipped"
        coverage_reason = "no-high-critical-cve-candidate"

        if candidate_count:
            print("[INFO] Listing matching Nuclei templates", flush=True)
            list_container = unique_container_name("template-list")
            list_command = docker_nuclei_command(
                reports_dir,
                args.nuclei_image,
                args.docker_network,
                args.template_volume,
                [
                    "-id",
                    "/app/reports/nuclei-cve-ids.txt",
                    "-tl",
                    "-silent",
                ],
                reports_read_only=True,
                container_name=list_container,
            )
            list_result = run_process(
                list_command,
                timeout_seconds=args.template_list_timeout,
                capture_output=True,
                cleanup_container_name=list_container,
            )
            matched_templates = parse_template_paths(list_result.stdout or "")
            matched_path.write_text(
                "\n".join(matched_templates) + ("\n" if matched_templates else ""),
                encoding="utf-8",
            )
            matched_count = len(matched_templates)

            if matched_count:
                print(
                    f"[INFO] Running {matched_count} matching CVE-targeted template(s)",
                    flush=True,
                )
                targeted_container = unique_container_name("targeted")
                targeted_command = docker_nuclei_command(
                    reports_dir,
                    args.nuclei_image,
                    args.docker_network,
                    args.template_volume,
                    build_targeted_arguments(args),
                    container_name=targeted_container,
                )
                run_process(
                    targeted_command,
                    timeout_seconds=args.scan_timeout,
                    suppress_stdout=True,
                    cleanup_container_name=targeted_container,
                )
                coverage_status = "completed"
                coverage_reason = "matching-templates-executed"
            else:
                coverage_reason = "no-matching-nuclei-template"
                print(
                    "[INFO] CVE-targeted scan skipped: no matching template",
                    flush=True,
                )
        else:
            print(
                "[INFO] CVE-targeted scan skipped: no High/Critical CVE",
                flush=True,
            )

        combine_jsonl([baseline_path, targeted_path], combined_path)
        baseline_findings = count_jsonl_records(baseline_path)
        targeted_findings = count_jsonl_records(targeted_path)

        write_coverage_report(
            coverage_path,
            {
                "status": coverage_status,
                "reason": coverage_reason,
                "tool": "nuclei-cve-validation",
                "target": args.target_url,
                "trivy_candidates": candidate_count,
                "matched_templates": matched_count,
                "baseline_findings": baseline_findings,
                "cve_findings": targeted_findings,
                "combined_findings": baseline_findings + targeted_findings,
            },
        )
    except (NucleiExecutionError, ValueError) as error:
        combine_jsonl([baseline_path, targeted_path], combined_path)
        write_coverage_report(
            coverage_path,
            {
                "status": "failed",
                "reason": str(error),
                "tool": "nuclei-cve-validation",
                "target": args.target_url,
                "trivy_candidates": candidate_count,
                "matched_templates": matched_count,
                "baseline_findings": baseline_findings,
                "cve_findings": targeted_findings,
                "combined_findings": baseline_findings + targeted_findings,
            },
        )
        print(f"[ERROR] {error}", file=sys.stderr)
        return 2

    print(
        "[OK] Nuclei validation completed: "
        f"candidates={candidate_count}, matched={matched_count}, "
        f"findings={baseline_findings + targeted_findings}"
    )
    print(f"[OK] Combined report: {combined_path}")
    print(f"[OK] Coverage report: {coverage_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
