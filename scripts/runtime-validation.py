#!/usr/bin/env python3
"""
runtime-validation.py

D part Runtime Validation submission script.

It checks a running application, converts optional OWASP ZAP and Nuclei reports,
converts optional Dynatrace Problems API results, and writes the team common
schema to security/reports/runtime-report.json.
"""

import argparse
import http.cookiejar
import html
import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from urllib.parse import urlparse

OUTPUT_PATH = Path("security/reports/runtime-report.json")
DEFAULT_ZAP_REPORT_PATH = Path("security/reports/zap-report.json")
DEFAULT_NUCLEI_REPORT_PATH = Path("security/reports/nuclei-report.jsonl")
DEFAULT_DYNATRACE_PROBLEMS_PATH = Path("security/reports/dynatrace-problems.json")
DEFAULT_REQUIRED_HEADERS = [
    "x-content-type-options",
    "x-frame-options",
    "content-security-policy",
]
DEFAULT_CUSTOM_CHECKS = [
    "debug-exposure",
    "docs-exposure",
    "reflected-xss",
    "search-sqli",
    "admin-access",
    "idor",
]
SUPPORTED_CUSTOM_CHECKS = set(DEFAULT_CUSTOM_CHECKS)
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


def request_text(url, method, timeout, data=None, headers=None, opener=None):
    request_headers = {"User-Agent": "secure-gate-runtime-validation/1.0"}
    if headers:
        request_headers.update(headers)

    body = None
    if data is not None:
        body = urllib.parse.urlencode(data).encode("utf-8")
        request_headers.setdefault("Content-Type", "application/x-www-form-urlencoded")

    request = urllib.request.Request(url, data=body, method=method, headers=request_headers)
    open_request = opener.open if opener is not None else urllib.request.urlopen

    try:
        with open_request(request, timeout=timeout) as response:
            raw_body = response.read()
            charset = response.headers.get_content_charset() or "utf-8"
            return response.status, normalize_headers(response.headers), raw_body.decode(
                charset,
                errors="replace",
            )

    except urllib.error.HTTPError as error:
        raw_body = error.read()
        charset = error.headers.get_content_charset() or "utf-8"
        return error.code, normalize_headers(error.headers), raw_body.decode(
            charset,
            errors="replace",
        )

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


def parse_custom_checks(raw_value):
    normalized = raw_value.strip().lower()
    if normalized in DISABLED_VALUES:
        return [], []

    requested_checks = split_csv(normalized)
    if not requested_checks or "all" in requested_checks:
        requested_checks = list(DEFAULT_CUSTOM_CHECKS)

    checks = []
    unknown_checks = []
    for check in requested_checks:
        if check in SUPPORTED_CUSTOM_CHECKS:
            if check not in checks:
                checks.append(check)
        else:
            unknown_checks.append(check)

    return checks, unknown_checks


def check_debug_exposure(base_url, timeout):
    checks = {
        "/debug/error": ["Debug Information", "Internal Hint", "app/routers/errors.py"],
        "/debug/db-error": [
            "Debug Information",
            "Internal Hint",
            "SELECT * FROM not_existing_table",
        ],
        "/debug/path-error": ["Debug Information", "Internal Hint", "/app/routers/errors.py"],
    }
    findings = []

    for path, indicators in checks.items():
        debug_url = join_url(base_url, path)
        try:
            status_code, _, response_body = request_text(debug_url, "GET", timeout)
        except RuntimeError as error:
            findings.append(
                make_finding(
                    "runtime.custom.debug.unreachable",
                    "medium",
                    "Debug exposure check request failed",
                    f"Could not reach debug endpoint: {error}",
                    debug_url,
                )
            )
            continue

        if status_code == 200 and any(indicator in response_body for indicator in indicators):
            findings.append(
                make_finding(
                    f"runtime.custom.debug-exposure.{finding_id_component(path)}",
                    "medium",
                    "Debug endpoint exposes internal information",
                    "A debug endpoint returned internal error details or implementation hints.",
                    debug_url,
                )
            )

    return findings


def check_docs_exposure(base_url, timeout):
    checks = {
        "/docs": ["Swagger UI", "openapi.json"],
        "/redoc": ["ReDoc", "openapi.json"],
    }
    findings = []

    for path, indicators in checks.items():
        docs_url = join_url(base_url, path)
        try:
            status_code, _, response_body = request_text(docs_url, "GET", timeout)
        except RuntimeError as error:
            findings.append(
                make_finding(
                    "runtime.custom.docs.unreachable",
                    "medium",
                    "API documentation exposure check request failed",
                    f"Could not reach documentation endpoint: {error}",
                    docs_url,
                )
            )
            continue

        if status_code == 200 and any(indicator in response_body for indicator in indicators):
            findings.append(
                make_finding(
                    f"runtime.custom.docs-exposure.{finding_id_component(path)}",
                    "medium",
                    "API documentation endpoint is exposed",
                    "FastAPI interactive API documentation was reachable in the runtime target.",
                    docs_url,
                )
            )

    return findings


def check_reflected_xss(base_url, timeout):
    marker = "runtime-validation-xss"
    payload = f'"><script>alert("{marker}")</script>'
    query = urllib.parse.urlencode({"keyword": payload})
    target_url = join_url(base_url, f"/posts?{query}")

    try:
        status_code, _, response_body = request_text(target_url, "GET", timeout)
    except RuntimeError as error:
        return [
            make_finding(
                "runtime.custom.reflected-xss.unreachable",
                "medium",
                "Reflected XSS check request failed",
                f"Could not reach reflected XSS target: {error}",
                target_url,
            )
        ]

    if status_code == 200 and payload in response_body:
        return [
            make_finding(
                "runtime.custom.reflected-xss.keyword",
                "high",
                "Search keyword is reflected without escaping",
                "A script payload submitted through the keyword parameter was reflected in the HTML response without escaping.",
                target_url,
            )
        ]

    return []


def check_search_sqli(base_url, timeout, payload):
    query = urllib.parse.urlencode({"keyword": payload})
    target_url = join_url(base_url, f"/posts?{query}")
    private_post_markers = ["user1 비공개 게시글", "user2 비공개 게시글", "IDOR 확인용 비공개 글"]

    try:
        status_code, _, response_body = request_text(target_url, "GET", timeout)
    except RuntimeError as error:
        return [
            make_finding(
                "runtime.custom.search-sqli.unreachable",
                "medium",
                "Search SQL injection check request failed",
                f"Could not reach search endpoint: {error}",
                target_url,
            )
        ]

    if status_code == 200 and any(marker in response_body for marker in private_post_markers):
        return [
            make_finding(
                "runtime.custom.search-sqli.private-posts",
                "high",
                "Search query exposes private posts",
                "A SQL injection payload submitted through the keyword parameter returned private post content in the public search response.",
                target_url,
            )
        ]

    return []


def create_session_opener():
    cookie_jar = http.cookiejar.CookieJar()
    return urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cookie_jar))


def login(base_url, username, password, timeout):
    opener = create_session_opener()
    login_url = join_url(base_url, "/login")
    status_code, _, response_body = request_text(
        login_url,
        "POST",
        timeout,
        data={"username": username, "password": password},
        opener=opener,
    )
    return opener, status_code, response_body


def check_admin_access(base_url, timeout, username, password):
    try:
        opener, _, _ = login(base_url, username, password, timeout)
        admin_url = join_url(base_url, "/admin")
        status_code, _, response_body = request_text(admin_url, "GET", timeout, opener=opener)
    except RuntimeError as error:
        return [
            make_finding(
                "runtime.custom.admin-access.unreachable",
                "medium",
                "Admin access check request failed",
                f"Could not complete authenticated admin access check: {error}",
                join_url(base_url, "/admin"),
            )
        ]

    admin_markers = ["운영 관리", "회원 목록", "게시글 관리"]
    if status_code == 200 and any(marker in response_body for marker in admin_markers):
        return [
            make_finding(
                "runtime.custom.admin-access.user-role",
                "high",
                "Non-admin user can access administrator page",
                f"User '{username}' reached the administrator page without an admin role check.",
                join_url(base_url, "/admin"),
            )
        ]

    return []


def check_idor(base_url, timeout, username, password, private_post_id):
    try:
        opener, _, _ = login(base_url, username, password, timeout)
        idor_url = join_url(base_url, f"/posts/private/{private_post_id}")
        status_code, _, response_body = request_text(idor_url, "GET", timeout, opener=opener)
    except RuntimeError as error:
        return [
            make_finding(
                "runtime.custom.idor.unreachable",
                "medium",
                "IDOR check request failed",
                f"Could not complete authenticated IDOR check: {error}",
                join_url(base_url, f"/posts/private/{private_post_id}"),
            )
        ]

    private_markers = ["비공개", "다른 계정에서 직접 접근", "private"]
    if status_code == 200 and any(marker in response_body for marker in private_markers):
        return [
            make_finding(
                "runtime.custom.idor.private-post",
                "high",
                "User can access another user's private post",
                f"User '{username}' reached private post id {private_post_id}.",
                idor_url,
            )
        ]

    return []


def check_custom_runtime(base_url, args):
    checks, unknown_checks = parse_custom_checks(args.custom_checks)
    findings = []

    for unknown_check in unknown_checks:
        findings.append(
            make_config_finding(
                "CUSTOM_RUNTIME_CHECKS",
                f"Unsupported custom runtime check: {unknown_check}",
            )
        )

    if "debug-exposure" in checks:
        findings.extend(check_debug_exposure(base_url, args.timeout))
    if "docs-exposure" in checks:
        findings.extend(check_docs_exposure(base_url, args.timeout))
    if "reflected-xss" in checks:
        findings.extend(check_reflected_xss(base_url, args.timeout))
    if "search-sqli" in checks:
        findings.extend(check_search_sqli(base_url, args.timeout, args.custom_sqli_payload))
    if "admin-access" in checks:
        findings.extend(
            check_admin_access(
                base_url,
                args.timeout,
                args.custom_username,
                args.custom_password,
            )
        )
    if "idor" in checks:
        findings.extend(
            check_idor(
                base_url,
                args.timeout,
                args.custom_username,
                args.custom_password,
                args.custom_private_post_id,
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


def map_dynatrace_severity(value):
    severity_level = str(value or "").strip().upper()
    if severity_level in {"AVAILABILITY", "ERROR", "MONITORING_UNAVAILABLE"}:
        return "high"
    if severity_level in {"PERFORMANCE", "RESOURCE_CONTENTION", "CUSTOM_ALERT"}:
        return "medium"
    return "low"


def dynatrace_entity_location(problem):
    entities = []
    root_cause = problem.get("rootCauseEntity")
    if isinstance(root_cause, dict):
        entities.append(root_cause)

    affected_entities = problem.get("affectedEntities")
    if isinstance(affected_entities, list):
        entities.extend(entity for entity in affected_entities if isinstance(entity, dict))

    for entity in entities:
        name = entity.get("name")
        if name:
            return str(name)

        entity_id = entity.get("entityId")
        if isinstance(entity_id, dict):
            entity_type = entity_id.get("type")
            identifier = entity_id.get("id")
            if entity_type and identifier:
                return f"{entity_type}:{identifier}"
            if identifier:
                return str(identifier)

    return "dynatrace"


def dynatrace_problem_description(problem):
    parts = []
    status = problem.get("status")
    severity_level = problem.get("severityLevel")
    impact_level = problem.get("impactLevel")
    display_id = problem.get("displayId")

    if display_id:
        parts.append(f"Problem: {display_id}.")
    if status:
        parts.append(f"Status: {status}.")
    if severity_level:
        parts.append(f"Dynatrace severity: {severity_level}.")
    if impact_level:
        parts.append(f"Impact: {impact_level}.")

    return " ".join(parts) or "Dynatrace reported an open runtime problem."


def make_dynatrace_finding(problem):
    problem_id = problem.get("displayId") or problem.get("problemId") or "problem"
    title = problem.get("title") or "Dynatrace runtime problem"

    return make_finding(
        f"runtime.dynatrace.{finding_id_component(problem_id).lower()}",
        map_dynatrace_severity(problem.get("severityLevel")),
        str(title),
        dynatrace_problem_description(problem),
        dynatrace_entity_location(problem),
    )


def parse_dynatrace_problems(dynatrace_problems_path):
    path = Path(dynatrace_problems_path)
    if not path.exists():
        return []

    try:
        with path.open(encoding="utf-8") as file:
            data = json.load(file)
    except json.JSONDecodeError as error:
        return [
            make_finding(
                "runtime.dynatrace.parse-error",
                "medium",
                "Dynatrace problems report could not be parsed",
                f"Invalid JSON in {path}: {error}",
                str(path),
            )
        ]
    except OSError as error:
        return [
            make_finding(
                "runtime.dynatrace.read-error",
                "medium",
                "Dynatrace problems report could not be read",
                f"Could not read {path}: {error}",
                str(path),
            )
        ]

    if not isinstance(data, dict) or not isinstance(data.get("problems"), list):
        return [
            make_finding(
                "runtime.dynatrace.parse-error",
                "medium",
                "Dynatrace problems report has unexpected structure",
                "Expected a JSON object containing a problems array.",
                str(path),
            )
        ]

    findings = []
    warnings = data.get("warnings") or []
    if isinstance(warnings, list):
        for index, warning in enumerate(warnings, start=1):
            findings.append(
                make_finding(
                    f"runtime.dynatrace.api-warning.{index}",
                    "medium",
                    "Dynatrace Problems API returned a warning",
                    str(warning),
                    str(path),
                )
            )

    for problem in data["problems"]:
        if not isinstance(problem, dict):
            continue
        if str(problem.get("status") or "").strip().upper() == "CLOSED":
            continue
        findings.append(make_dynatrace_finding(problem))

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
        findings.extend(check_custom_runtime(base_url, args))

    findings.extend(parse_zap_report(args.zap_report))
    findings.extend(parse_nuclei_report(args.nuclei_report))
    findings.extend(parse_dynatrace_problems(args.dynatrace_problems))

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
    parser.add_argument(
        "--dynatrace-problems",
        default=env_or_default(
            "DYNATRACE_PROBLEMS_PATH",
            str(DEFAULT_DYNATRACE_PROBLEMS_PATH),
        ),
    )
    parser.add_argument(
        "--custom-checks",
        default=env_or_default("CUSTOM_RUNTIME_CHECKS", ",".join(DEFAULT_CUSTOM_CHECKS)),
        help="Comma-separated custom runtime checks. Use 'none' to disable.",
    )
    parser.add_argument(
        "--custom-username",
        default=env_or_default("CUSTOM_RUNTIME_USERNAME", "user1"),
    )
    parser.add_argument(
        "--custom-password",
        default=env_or_default("CUSTOM_RUNTIME_PASSWORD", "password123"),
    )
    parser.add_argument(
        "--custom-private-post-id",
        default=env_or_default("CUSTOM_RUNTIME_PRIVATE_POST_ID", "4"),
    )
    parser.add_argument(
        "--custom-sqli-payload",
        default=env_or_default("CUSTOM_RUNTIME_SQLI_PAYLOAD", "') OR '1'='1' --"),
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
