#!/usr/bin/env python3
"""
Run OWASP ZAP with a bounded PR profile or a post-merge full-scan profile.

ZAP exit codes 1 and 2 mean security findings were reported, so this wrapper
keeps the pipeline running and lets runtime-validation.py apply the team policy.
Scanner errors, timeouts, missing reports, and invalid JSON return exit code 2.
"""

import argparse
import json
import os
import stat
import subprocess
import sys
import uuid
from pathlib import Path
from urllib.parse import urlparse


DEFAULT_REPORTS_DIR = Path("security/reports")
DEFAULT_ZAP_IMAGE = "ghcr.io/zaproxy/zaproxy:stable"
DISABLED_VALUES = {"", "none", "off", "false", "disable", "disabled"}
PROFILE_DEFAULTS = {
    "pr": {
        "scanner": "zap-baseline.py",
        "docker_network": "host",
        "spider_minutes": 1,
        "passive_wait_minutes": 5,
        "scan_timeout": 10 * 60,
        "ajax_spider": False,
    },
    "post-merge": {
        "scanner": "zap-full-scan.py",
        "docker_network": "none",
        "spider_minutes": 5,
        "passive_wait_minutes": 10,
        "scan_timeout": 30 * 60,
        "ajax_spider": True,
    },
}
FINDING_EXIT_CODES = {0, 1, 2}


class ZapExecutionError(RuntimeError):
    """Raised when Docker or ZAP cannot complete and produce a valid report."""


def env_or_default(name, default):
    return os.environ.get(name) or default


def parse_duration(raw_value):
    value = str(raw_value).strip().lower()
    multiplier = 1
    if value.endswith("m"):
        multiplier = 60
        value = value[:-1]
    elif value.endswith("h"):
        multiplier = 60 * 60
        value = value[:-1]
    elif value.endswith("s"):
        value = value[:-1]

    try:
        seconds = int(value) * multiplier
    except ValueError as error:
        raise argparse.ArgumentTypeError(
            f"Invalid duration '{raw_value}'. Use seconds or a value such as 30m."
        ) from error

    if seconds <= 0:
        raise argparse.ArgumentTypeError("Duration must be greater than zero")
    return seconds


def parse_optional_bool(raw_value, setting_name):
    if raw_value is None:
        return None

    value = str(raw_value).strip().lower()
    if value in {"1", "true", "yes", "on"}:
        return True
    if value in {"0", "false", "no", "off"}:
        return False
    raise ValueError(f"{setting_name} must be true or false")


def environment_bool(parser, setting_name):
    try:
        return parse_optional_bool(os.environ.get(setting_name), setting_name)
    except ValueError as error:
        parser.error(str(error))


def is_disabled(value):
    return str(value).strip().lower() in DISABLED_VALUES


def apply_profile_defaults(args):
    defaults = PROFILE_DEFAULTS[args.profile]
    for setting_name, default_value in defaults.items():
        if getattr(args, setting_name, None) is None:
            setattr(args, setting_name, default_value)
    return args


def validate_target_url(target_url):
    parsed = urlparse(target_url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("ZAP target URL must be an absolute HTTP(S) URL")


def unique_container_name():
    return f"secure-gate-zap-{uuid.uuid4().hex[:12]}"


def prepare_reports_directory(reports_dir):
    reports_dir.mkdir(parents=True, exist_ok=True)
    try:
        mode = stat.S_IMODE(reports_dir.stat().st_mode)
        reports_dir.chmod(mode | stat.S_IWOTH)
    except OSError as error:
        raise ZapExecutionError(
            f"Could not make ZAP reports directory container-writable: {error}"
        ) from error


def cleanup_container(container_name):
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


def build_zap_command(args, reports_dir, container_name):
    command = ["docker", "run", "--rm", "--name", container_name]
    if not is_disabled(args.docker_network):
        command.extend(["--network", args.docker_network])

    command.extend(
        [
            "-v",
            f"{reports_dir.resolve()}:/zap/wrk:rw",
            args.zap_image,
            args.scanner,
            "-t",
            args.target_url,
            "-m",
            str(args.spider_minutes),
            "-T",
            str(args.passive_wait_minutes),
        ]
    )
    if args.ajax_spider:
        command.append("-j")
    command.extend(["-J", "zap-report.json"])
    return command


def run_zap(command, timeout_seconds, container_name):
    try:
        result = subprocess.run(
            command,
            check=False,
            timeout=timeout_seconds,
        )
    except FileNotFoundError as error:
        raise ZapExecutionError("Docker command was not found") from error
    except subprocess.TimeoutExpired as error:
        cleanup_container(container_name)
        raise ZapExecutionError(
            f"ZAP scan timed out after {timeout_seconds} seconds"
        ) from error
    except OSError as error:
        raise ZapExecutionError(f"Could not execute Docker: {error}") from error

    if result.returncode not in FINDING_EXIT_CODES:
        raise ZapExecutionError(
            f"ZAP scanner failed with exit code {result.returncode}"
        )
    return result.returncode


def validate_report(report_path):
    if not report_path.is_file():
        raise ZapExecutionError(f"ZAP report was not created: {report_path}")

    try:
        with report_path.open(encoding="utf-8") as report_file:
            report = json.load(report_file)
    except json.JSONDecodeError as error:
        raise ZapExecutionError(f"ZAP report contains invalid JSON: {error}") from error
    except OSError as error:
        raise ZapExecutionError(f"Could not read ZAP report: {error}") from error

    if not isinstance(report, dict):
        raise ZapExecutionError("ZAP report root must be a JSON object")


def parse_args():
    default_target = (
        os.environ.get("ZAP_TARGET_URL")
        or os.environ.get("RUNTIME_BASE_URL")
        or os.environ.get("STAGING_URL")
        or ""
    )
    parser = argparse.ArgumentParser(
        description="Run OWASP ZAP with a PR baseline or post-merge full-scan profile."
    )
    parser.add_argument(
        "--profile",
        choices=sorted(PROFILE_DEFAULTS),
        default=env_or_default("ZAP_SCAN_PROFILE", "pr"),
    )
    parser.add_argument("--target-url", default=default_target)
    parser.add_argument(
        "--reports-dir",
        type=Path,
        default=Path(env_or_default("SECURITY_REPORTS_DIR", str(DEFAULT_REPORTS_DIR))),
    )
    parser.add_argument(
        "--zap-image",
        default=env_or_default("ZAP_IMAGE", DEFAULT_ZAP_IMAGE),
    )
    parser.add_argument(
        "--docker-network",
        default=os.environ.get("ZAP_DOCKER_NETWORK"),
        help="Docker network. Use 'none' to keep Docker's default bridge network.",
    )
    parser.add_argument(
        "--spider-minutes",
        type=int,
        default=os.environ.get("ZAP_SPIDER_MINUTES"),
    )
    parser.add_argument(
        "--passive-wait-minutes",
        type=int,
        default=os.environ.get("ZAP_PASSIVE_WAIT_MINUTES"),
    )
    parser.add_argument(
        "--scan-timeout",
        type=parse_duration,
        default=os.environ.get("ZAP_SCAN_TIMEOUT"),
    )
    ajax_group = parser.add_mutually_exclusive_group()
    ajax_group.add_argument(
        "--ajax-spider",
        dest="ajax_spider",
        action="store_true",
    )
    ajax_group.add_argument(
        "--no-ajax-spider",
        dest="ajax_spider",
        action="store_false",
    )
    parser.set_defaults(
        ajax_spider=environment_bool(parser, "ZAP_AJAX_SPIDER")
    )
    args = apply_profile_defaults(parser.parse_args())
    if args.spider_minutes <= 0 or args.passive_wait_minutes <= 0:
        parser.error("ZAP minute settings must be greater than zero")
    return args


def main():
    args = parse_args()
    reports_dir = args.reports_dir.resolve()

    try:
        prepare_reports_directory(reports_dir)
        report_path = reports_dir / "zap-report.json"
        report_path.unlink(missing_ok=True)
        validate_target_url(args.target_url)
        container_name = unique_container_name()
        command = build_zap_command(args, reports_dir, container_name)
        print(
            f"[INFO] Running ZAP {args.profile} profile with {args.scanner}",
            flush=True,
        )
        zap_exit_code = run_zap(command, args.scan_timeout, container_name)
        validate_report(report_path)
    except (ValueError, ZapExecutionError) as error:
        print(f"[ERROR] {error}", file=sys.stderr)
        return 2

    print(f"[OK] ZAP completed with scanner exit code {zap_exit_code}")
    print(f"[OK] Report: {report_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
