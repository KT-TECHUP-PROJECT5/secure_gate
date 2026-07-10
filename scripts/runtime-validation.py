#!/usr/bin/env python3
"""
runtime-validation.py

D part Runtime Validation submission script.

It checks a running application, converts optional OWASP ZAP and Nuclei reports,
and writes the team common schema to security/reports/runtime-report.json.
"""

import argparse
import html
import json
import os
import re
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urlparse

OUTPUT_PATH = Path("security/reports/runtime-report.json")
DEFAULT_ZAP_REPORT_PATH = Path("security/reports/zap-report.json")
DEFAULT_NUCLEI_REPORT_PATH = Path("security/reports/nuclei-report.jsonl")
DEFAULT_REQUIRED_HEADERS = [
    "x-content-type-options",
    "x-frame-options",
    "content-security-policy",
]
DISABLED_VALUES = {"none", "off", "false", "disable", "disabled"}


def make_finding(finding_id, severity, title, description, location):
    return {
        "id": finding_id,
        "severity": severity,
        "title": title,
        "description": description,
        "location": location,
    }


def env_or_default(name, default):
    return os.environ.get(name) or default


def env_base_url():
    return os.environ.get("RUNTIME_BASE_URL") or os.environ.get("STAGING_URL") or ""


def split_csv(value):
    return [item.strip() for item in value.split(",") if item.strip()]


def join_url(base_url, path):
    path = path.strip()
    if path.startswith(("http://", "https://")):
        return path
    if not path.startswith("/"):
        path = "/" + path
    return base_url.rstrip("/") + path


def parse_status_set(raw_value, field_name):
    statuses = []
    for token in split_csv(raw_value.replace("|", ",")):
        try:
            statuses.append(int(token))
        except ValueError as error:
            raise ValueError(f"{field_name} contains invalid status: {token}") from error

    if not statuses:
        raise ValueError(f"{field_name} must contain at least one HTTP status")

    return set(statuses)


def format_statuses(statuses):
    return ", ".join(str(status) for status in sorted(statuses))


def parse_smoke_tests(raw_value):
    tests = []

    for item in split_csv(raw_value):
        path = item
        expected_statuses = {200}

        if "=" in item:
            path, raw_status = item.rsplit("=", 1)
            path = path.strip()
            expected_statuses = parse_status_set(raw_status, "SMOKE_TEST_PATHS")

        tests.append((path or "/", expected_statuses))

    return tests or [("/", {200})]


def parse_required_headers(raw_value, base_url):
    normalized = raw_value.strip().lower()
    if normalized in DISABLED_VALUES:
        return []

    headers = split_csv(normalized)
    if not headers:
        headers = list(DEFAULT_REQUIRED_HEADERS)

    parsed_url = urlparse(base_url)
    if parsed_url.scheme == "https" and "strict-transport-security" not in headers:
        headers.append("strict-transport-security")

    unique_headers = []
    for header in headers:
        if header not in unique_headers:
            unique_headers.append(header)

    return unique_headers


def is_valid_http_url(url):
    parsed_url = urlparse(url)
    return parsed_url.scheme in {"http", "https"} and bool(parsed_url.netloc)


def normalize_headers(headers):
    normalized = {}
    for key, value in headers.items():
        normalized[key.lower()] = value
    return normalized


def request_url(url, method, timeout):
    try:
        request = urllib.request.Request(
            url,
            method=method,
            headers={"User-Agent": "secure-gate-runtime-validation/1.0"},
        )
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.status, normalize_headers(response.headers)

    except urllib.error.HTTPError as error:
        return error.code, normalize_headers(error.headers)

    except (urllib.error.URLError, TimeoutError, OSError, ValueError) as error:
        raise RuntimeError(str(error)) from error


def check_health(base_url, health_path, expected_statuses, timeout):
    health_url = join_url(base_url, health_path)

    try:
        status_code, _ = request_url(health_url, "GET", timeout)
    except RuntimeError as error:
        return [
            make_finding(
                "runtime.health.unreachable",
                "high",
                "Health check request failed",
                f"Could not reach health endpoint: {error}",
                health_url,
            )
        ]

    if status_code not in expected_statuses:
        return [
            make_finding(
                "runtime.health.bad-status",
                "high",
                "Health check returned unexpected status",
                f"Expected [{format_statuses(expected_statuses)}], got HTTP {status_code}.",
                health_url,
            )
        ]

    return []


def check_smoke(base_url, smoke_tests, timeout):
    findings = []

    for path, expected_statuses in smoke_tests:
        smoke_url = join_url(base_url, path)

        try:
            status_code, _ = request_url(smoke_url, "GET", timeout)
        except RuntimeError as error:
            findings.append(
                make_finding(
                    "runtime.smoke.unreachable",
                    "high",
                    "Smoke test request failed",
                    f"Could not reach smoke test endpoint: {error}",
                    smoke_url,
                )
            )
            continue

        if status_code not in expected_statuses:
            findings.append(
                make_finding(
                    "runtime.smoke.bad-status",
                    "high",
                    "Smoke test returned unexpected status",
                    f"Expected [{format_statuses(expected_statuses)}], got HTTP {status_code}.",
                    smoke_url,
                )
            )

    return findings


def get_response_headers(base_url, timeout):
    try:
        status_code, headers = request_url(base_url, "HEAD", timeout)
    except RuntimeError:
        status_code, headers = request_url(base_url, "GET", timeout)

    if status_code in {405, 501}:
        status_code, headers = request_url(base_url, "GET", timeout)

    return headers


def check_headers(base_url, required_headers, timeout):
    try:
        headers = get_response_headers(base_url, timeout)
    except RuntimeError as error:
        return [
            make_finding(
                "runtime.headers.unreachable",
                "high",
                "Security header check failed",
                f"Could not reach target URL: {error}",
                base_url,
            )
        ]

    findings = []
    for header in required_headers:
        if header not in headers:
            findings.append(
                make_finding(
                    f"runtime.headers.missing.{header}",
                    "medium",
                    f"Missing security header: {header}",
                    "Required security header was not present in the response.",
                    base_url,
                )
            )

    return findings


def strip_html(value):
    if not value:
        return ""
    without_tags = re.sub(r"<[^>]+>", " ", str(value))
    return " ".join(html.unescape(without_tags).split())


def map_zap_severity(alert):
    riskcode = str(alert.get("riskcode", "0")).strip()
    if riskcode == "4":
        return "critical"
    if riskcode == "3":
        return "high"
    if riskcode == "2":
        return "medium"
    return "low"


def as_list(value):
    if isinstance(value, list):
        return value
    if isinstance(value, dict):
        return [value]
    return []


def iter_zap_alerts(zap_data):
    for site in as_list(zap_data.get("site", [])):
        if not isinstance(site, dict):
            continue
        for alert in as_list(site.get("alerts", [])):
            if isinstance(alert, dict):
                yield alert

    for alert in as_list(zap_data.get("alerts", [])):
        if isinstance(alert, dict):
            yield alert


def zap_alert_location(alert):
    instances = as_list(alert.get("instances", []))
    if instances:
        first_instance = instances[0]
        if isinstance(first_instance, dict):
            return first_instance.get("uri") or first_instance.get("url") or "zap-report"
    return alert.get("uri") or alert.get("url") or "zap-report"


def zap_alert_description(alert):
    description = strip_html(alert.get("desc"))
    solution = strip_html(alert.get("solution"))
    risk = strip_html(alert.get("riskdesc"))

    parts = []
    if risk:
        parts.append(f"Risk: {risk}.")
    if description:
        parts.append(description)
    if solution:
        parts.append(f"Solution: {solution}")

    return " ".join(parts) or "OWASP ZAP reported a runtime security finding."


def parse_zap_report(zap_report_path):
    path = Path(zap_report_path)
    if not path.exists():
        return []

    try:
        with open(path, encoding="utf-8") as file:
            zap_data = json.load(file)
    except json.JSONDecodeError as error:
        return [
            make_finding(
                "runtime.zap.parse-error",
                "medium",
                "OWASP ZAP report could not be parsed",
                f"Invalid JSON in {path}: {error}",
                str(path),
            )
        ]
    except OSError as error:
        return [
            make_finding(
                "runtime.zap.read-error",
                "medium",
                "OWASP ZAP report could not be read",
                f"Could not read {path}: {error}",
                str(path),
            )
        ]

    if not isinstance(zap_data, dict):
        return [
            make_finding(
                "runtime.zap.parse-error",
                "medium",
                "OWASP ZAP report has unexpected structure",
                "Expected a JSON object containing site alerts.",
                str(path),
            )
        ]

    findings = []
    for alert in iter_zap_alerts(zap_data):
        plugin_id = str(alert.get("pluginid") or alert.get("pluginId") or "alert")
        title = alert.get("alert") or alert.get("name") or "OWASP ZAP finding"

        findings.append(
            make_finding(
                f"runtime.zap.{plugin_id}",
                map_zap_severity(alert),
                str(title),
                zap_alert_description(alert),
                zap_alert_location(alert),
            )
        )

    return findings


def map_nuclei_severity(value):
    severity = str(value or "").strip().lower()
    if severity in {"critical", "high", "medium", "low"}:
        return severity
    return "low"


def finding_id_component(value):
    cleaned = re.sub(r"[^a-zA-Z0-9_.-]+", "-", str(value or "").strip())
    return cleaned.strip("-") or "finding"


def nuclei_record_info(record):
    info = record.get("info", {})
    if isinstance(info, dict):
        return info
    return {}


def nuclei_record_location(record):
    return (
        record.get("matched-at")
        or record.get("matched")
        or record.get("url")
        or record.get("host")
        or "nuclei-report"
    )


def nuclei_record_description(record):
    info = nuclei_record_info(record)
    parts = []

    description = info.get("description")
    if description:
        parts.append(str(description))

    tags = info.get("tags")
    if isinstance(tags, list) and tags:
        parts.append("Tags: " + ", ".join(str(tag) for tag in tags))
    elif tags:
        parts.append(f"Tags: {tags}")

    matcher_name = record.get("matcher-name") or record.get("matcher_name")
    if matcher_name:
        parts.append(f"Matcher: {matcher_name}")

    return " ".join(parts) or "Nuclei reported a runtime security finding."


def make_nuclei_finding(record):
    info = nuclei_record_info(record)
    template_id = record.get("template-id") or record.get("template_id") or record.get("id")
    severity = info.get("severity") or record.get("severity")
    title = info.get("name") or record.get("name") or template_id or "Nuclei finding"

    return make_finding(
        f"runtime.nuclei.{finding_id_component(template_id)}",
        map_nuclei_severity(severity),
        str(title),
        nuclei_record_description(record),
        nuclei_record_location(record),
    )


def parse_nuclei_json_value(value, source):
    if isinstance(value, list):
        findings = []
        for item in value:
            if isinstance(item, dict):
                findings.append(make_nuclei_finding(item))
        return findings

    if isinstance(value, dict):
        if isinstance(value.get("results"), list):
            return parse_nuclei_json_value(value["results"], source)
        return [make_nuclei_finding(value)]

    return [
        make_finding(
            "runtime.nuclei.parse-error",
            "medium",
            "Nuclei report has unexpected structure",
            "Expected each Nuclei JSONL line to be a JSON object.",
            source,
        )
    ]


def parse_nuclei_report(nuclei_report_path):
    path = Path(nuclei_report_path)
    if not path.exists():
        return []

    findings = []
    try:
        with open(path, encoding="utf-8") as file:
            for line_number, line in enumerate(file, start=1):
                stripped_line = line.strip()
                if not stripped_line:
                    continue

                source = f"{path}:{line_number}"
                try:
                    nuclei_data = json.loads(stripped_line)
                except json.JSONDecodeError as error:
                    findings.append(
                        make_finding(
                            "runtime.nuclei.parse-error",
                            "medium",
                            "Nuclei report could not be parsed",
                            f"Invalid JSONL in {source}: {error}",
                            source,
                        )
                    )
                    continue

                findings.extend(parse_nuclei_json_value(nuclei_data, source))

    except OSError as error:
        return [
            make_finding(
                "runtime.nuclei.read-error",
                "medium",
                "Nuclei report could not be read",
                f"Could not read {path}: {error}",
                str(path),
            )
        ]

    return findings


def decide_status(findings):
    severities = [finding["severity"] for finding in findings]

    if "critical" in severities or "high" in severities or "secret" in severities:
        return "failed"

    if findings:
        return "warning"

    return "passed"


def make_config_finding(setting_name, message):
    return make_finding(
        f"runtime.config.invalid.{setting_name.lower().replace('_', '-')}",
        "medium",
        f"Invalid Runtime Validation setting: {setting_name}",
        message,
        setting_name,
    )


def build_report(args):
    findings = []
    base_url = args.base_url.strip()

    if not base_url:
        findings.append(
            make_finding(
                "runtime.target-url.missing",
                "medium",
                "Runtime target URL is not configured",
                "Set RUNTIME_BASE_URL or STAGING_URL to enable runtime validation.",
                "runtime-validation",
            )
        )
    elif not is_valid_http_url(base_url):
        findings.append(
            make_finding(
                "runtime.target-url.invalid",
                "medium",
                "Runtime target URL is invalid",
                "RUNTIME_BASE_URL or STAGING_URL must start with http:// or https://.",
                base_url,
            )
        )
    else:
        try:
            health_expected_statuses = parse_status_set(
                args.health_expected_status,
                "HEALTH_EXPECTED_STATUS",
            )
        except ValueError as error:
            health_expected_statuses = {200}
            findings.append(make_config_finding("HEALTH_EXPECTED_STATUS", str(error)))

        try:
            smoke_tests = parse_smoke_tests(args.smoke_paths)
        except ValueError as error:
            smoke_tests = [("/", {200})]
            findings.append(make_config_finding("SMOKE_TEST_PATHS", str(error)))

        required_headers = parse_required_headers(args.required_headers, base_url)
        findings.extend(
            check_health(
                base_url,
                args.health_path,
                health_expected_statuses,
                args.timeout,
            )
        )
        findings.extend(check_smoke(base_url, smoke_tests, args.timeout))
        findings.extend(check_headers(base_url, required_headers, args.timeout))

    findings.extend(parse_zap_report(args.zap_report))
    findings.extend(parse_nuclei_report(args.nuclei_report))

    return {
        "status": decide_status(findings),
        "tool": "runtime-validation",
        "findings": findings,
    }


def env_timeout():
    try:
        return float(env_or_default("RUNTIME_TIMEOUT_SECONDS", "10"))
    except ValueError:
        return 10.0


def parse_args():
    parser = argparse.ArgumentParser(description="Generate Runtime Validation report.")
    parser.add_argument("--base-url", default=env_base_url())
    parser.add_argument("--health-path", default=env_or_default("HEALTH_CHECK_PATH", "/health"))
    parser.add_argument(
        "--health-expected-status",
        default=env_or_default("HEALTH_EXPECTED_STATUS", "200"),
    )
    parser.add_argument("--smoke-paths", default=env_or_default("SMOKE_TEST_PATHS", "/"))
    parser.add_argument(
        "--required-headers",
        default=env_or_default(
            "REQUIRED_SECURITY_HEADERS",
            ",".join(DEFAULT_REQUIRED_HEADERS),
        ),
    )
    parser.add_argument(
        "--zap-report",
        default=env_or_default("ZAP_REPORT_PATH", str(DEFAULT_ZAP_REPORT_PATH)),
    )
    parser.add_argument(
        "--nuclei-report",
        default=env_or_default("NUCLEI_REPORT_PATH", str(DEFAULT_NUCLEI_REPORT_PATH)),
    )
    parser.add_argument("--output", default=str(OUTPUT_PATH))
    parser.add_argument("--timeout", type=float, default=env_timeout())
    parser.add_argument(
        "--fail-on-failed",
        action="store_true",
        help="Exit with code 1 when the generated report status is failed.",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    report = build_report(args)
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with open(output_path, "w", encoding="utf-8") as file:
        json.dump(report, file, indent=2)

    print(f"Runtime Validation status: {report['status']}")
    print(f"Findings: {len(report['findings'])}")
    print(f"Report written to: {output_path}")

    if args.fail_on_failed and report["status"] == "failed":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
