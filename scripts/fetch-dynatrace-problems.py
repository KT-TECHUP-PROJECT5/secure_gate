#!/usr/bin/env python3
"""
Fetch Dynatrace Problems API v2 results and service coverage for Runtime Validation.

The API token is read only from DYNATRACE_API_TOKEN so it is not exposed in
command arguments or stored in the generated JSON report.
"""

import argparse
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from urllib.parse import urlparse


DEFAULT_OUTPUT_PATH = Path("security/reports/dynatrace-problems.json")
DEFAULT_PAGE_SIZE = 500


def env_or_default(name, default):
    return os.environ.get(name) or default


def positive_float(value):
    try:
        parsed_value = float(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("must be a number") from error

    if parsed_value <= 0:
        raise argparse.ArgumentTypeError("must be greater than 0")
    return parsed_value


def normalize_environment_url(value):
    environment_url = value.strip().rstrip("/")
    parsed_url = urlparse(environment_url)

    if parsed_url.scheme != "https" or not parsed_url.netloc:
        raise ValueError("DYNATRACE_ENV_URL must be a valid https:// URL")

    return environment_url


def read_api_token():
    api_token = os.environ.get("DYNATRACE_API_TOKEN", "").strip()
    if not api_token:
        raise ValueError("DYNATRACE_API_TOKEN is required")
    return api_token


def read_json_response(url, api_token, timeout):
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/json",
            "Authorization": f"Api-Token {api_token}",
            "User-Agent": "secure-gate-runtime-validation/1.0",
        },
    )

    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return json.load(response)
    except urllib.error.HTTPError as error:
        response_body = error.read().decode("utf-8", errors="replace")
        try:
            error_data = json.loads(response_body)
            message = error_data.get("error", {}).get("message") or response_body
        except json.JSONDecodeError:
            message = response_body
        raise RuntimeError(f"Dynatrace API returned HTTP {error.code}: {message}") from error
    except urllib.error.URLError as error:
        raise RuntimeError(f"Could not reach Dynatrace API: {error}") from error
    except (OSError, TimeoutError, json.JSONDecodeError) as error:
        raise RuntimeError(f"Could not read Dynatrace API response: {error}") from error


def first_page_parameters(args):
    parameters = {
        "from": args.from_time,
        "pageSize": str(args.page_size),
        "problemSelector": args.problem_selector,
        "sort": "-startTime",
    }

    if args.to_time:
        parameters["to"] = args.to_time
    if args.entity_selector:
        parameters["entitySelector"] = args.entity_selector

    return parameters


def fetch_problems(args, api_token):
    endpoint = f"{normalize_environment_url(args.environment_url)}/api/v2/problems"
    parameters = first_page_parameters(args)
    problems = []
    warnings = []

    while True:
        request_url = f"{endpoint}?{urllib.parse.urlencode(parameters)}"
        page = read_json_response(request_url, api_token, args.timeout)

        if not isinstance(page, dict) or not isinstance(page.get("problems"), list):
            raise RuntimeError("Dynatrace API response must contain a problems array")

        problems.extend(problem for problem in page["problems"] if isinstance(problem, dict))
        page_warnings = page.get("warnings") or []
        if isinstance(page_warnings, list):
            warnings.extend(str(warning) for warning in page_warnings)

        next_page_key = page.get("nextPageKey")
        if not next_page_key:
            break

        parameters = {"nextPageKey": next_page_key}

    return {
        "totalCount": len(problems),
        "pageSize": args.page_size,
        "problems": problems,
        "warnings": warnings,
    }


def fetch_service_coverage(args, api_token):
    endpoint = f"{normalize_environment_url(args.environment_url)}/api/v2/entities"
    parameters = {
        "entitySelector": args.service_entity_selector,
        "from": args.from_time,
        "pageSize": str(args.page_size),
    }
    if args.to_time:
        parameters["to"] = args.to_time

    services = []
    while True:
        request_url = f"{endpoint}?{urllib.parse.urlencode(parameters)}"
        page = read_json_response(request_url, api_token, args.timeout)

        if not isinstance(page, dict) or not isinstance(page.get("entities"), list):
            raise RuntimeError("Dynatrace API response must contain an entities array")

        for entity in page["entities"]:
            if not isinstance(entity, dict):
                continue
            services.append(
                {
                    "entityId": entity.get("entityId"),
                    "displayName": entity.get("displayName"),
                    "firstSeenTms": entity.get("firstSeenTms"),
                    "lastSeenTms": entity.get("lastSeenTms"),
                }
            )

        next_page_key = page.get("nextPageKey")
        if not next_page_key:
            break

        parameters = {"nextPageKey": next_page_key}

    return {
        "status": "detected" if services else "not_detected",
        "totalCount": len(services),
        "entitySelector": args.service_entity_selector,
        "from": args.from_time,
        "services": services,
    }


def parse_args():
    parser = argparse.ArgumentParser(
        description="Fetch Dynatrace Problems API v2 results and service coverage."
    )
    parser.add_argument(
        "--environment-url",
        default=env_or_default("DYNATRACE_ENV_URL", ""),
        help="Dynatrace environment URL, for example https://abc123.live.dynatrace.com",
    )
    parser.add_argument(
        "--from-time",
        default=env_or_default("DYNATRACE_FROM", "now-30m"),
        help="Dynatrace query start time (default: now-30m)",
    )
    parser.add_argument(
        "--to-time",
        default=env_or_default("DYNATRACE_TO", ""),
        help="Optional Dynatrace query end time",
    )
    parser.add_argument(
        "--problem-selector",
        default=env_or_default("DYNATRACE_PROBLEM_SELECTOR", 'status("open")'),
        help='Dynatrace problem selector (default: status("open"))',
    )
    parser.add_argument(
        "--entity-selector",
        default=env_or_default("DYNATRACE_ENTITY_SELECTOR", ""),
        help="Optional Dynatrace entity selector",
    )
    parser.add_argument(
        "--service-entity-selector",
        default=env_or_default("DYNATRACE_SERVICE_ENTITY_SELECTOR", 'type("SERVICE")'),
        help='Service entity selector (default: type("SERVICE"))',
    )
    parser.add_argument(
        "--skip-service-check",
        action="store_true",
        default=env_or_default("DYNATRACE_SKIP_SERVICE_CHECK", "").lower()
        in {"1", "true", "yes"},
        help="Fetch problems without checking whether Dynatrace detected a service",
    )
    parser.add_argument(
        "--page-size",
        type=int,
        default=DEFAULT_PAGE_SIZE,
        choices=range(1, DEFAULT_PAGE_SIZE + 1),
        metavar="1..500",
    )
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT_PATH)
    parser.add_argument(
        "--timeout",
        type=positive_float,
        default=env_or_default("DYNATRACE_API_TIMEOUT_SECONDS", "20"),
    )
    return parser.parse_args()


def main():
    args = parse_args()

    try:
        if not args.environment_url:
            raise ValueError("DYNATRACE_ENV_URL is required")
        api_token = read_api_token()
        report = fetch_problems(args, api_token)
        if not args.skip_service_check:
            report["serviceCoverage"] = fetch_service_coverage(args, api_token)
    except (ValueError, RuntimeError) as error:
        print(f"[ERROR] {error}", file=sys.stderr)
        return 2

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8") as file:
        json.dump(report, file, indent=2)

    print(f"[OK] Dynatrace problems: {report['totalCount']}")
    if "serviceCoverage" in report:
        print(f"[OK] Dynatrace services: {report['serviceCoverage']['totalCount']}")
    print(f"[OK] Report written to: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
