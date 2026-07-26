#!/usr/bin/env python3
"""Shared finding classification and Block/Warn helpers for Secure Gate."""

from __future__ import annotations

from datetime import date
from typing import Any


CATEGORIES = {
    "vuln",
    "misconfig",
    "secret",
    "availability",
    "scanner-error",
}

ZAP_MISCONFIG_PLUGIN_IDS = {
    "10016",  # Web Browser XSS Protection
    "10020",  # X-Frame-Options Header Not Set
    "10021",  # X-Content-Type-Options Header Missing
    "10035",  # Strict-Transport-Security Header Not Set
    "10036",  # HTTP Server Response Header
    "10038",  # Content Security Policy Header Not Set
    "10049",  # Storable and Cacheable Content
    "10063",  # Permissions Policy Header Not Set
    "10106",  # HTTP Only Site
    "10109",  # Modern Web Application
}

MISCONFIG_KEYWORDS = (
    "missing security header",
    "header not set",
    "header missing",
    "content security policy",
    "x-frame-options",
    "x-content-type-options",
    "strict-transport-security",
    "http only site",
    "storable and cacheable",
    "cacheable content",
    "cookie without",
    "secure flag",
    "httponly",
)


def _text(value: Any) -> str:
    return str(value or "").strip()


def _lower(value: Any) -> str:
    return _text(value).lower()


def infer_category(finding: dict) -> str:
    explicit = _lower(finding.get("category"))
    if explicit in CATEGORIES:
        return explicit

    finding_id = _lower(finding.get("id"))
    title = _lower(finding.get("title"))
    description = _lower(finding.get("description"))
    severity = _lower(finding.get("severity"))
    blob = f"{finding_id} {title} {description}"

    if severity == "secret" or "gitleaks" in finding_id or "secret" in finding_id:
        return "secret"

    if any(
        token in finding_id
        for token in (
            "report-missing",
            "parse-error",
            "read-error",
            "execution-failed",
            "unsupported",
            "coverage-parse-error",
            "coverage-read-error",
        )
    ):
        return "scanner-error"

    if any(
        token in finding_id
        for token in (
            "runtime.health.",
            "runtime.smoke.",
            "service-not-detected",
        )
    ):
        return "availability"

    if "headers.missing" in finding_id or "headers.unreachable" in finding_id:
        return "misconfig" if "missing" in finding_id else "availability"

    if finding_id.startswith("runtime.zap."):
        plugin_id = finding_id.rsplit(".", 1)[-1]
        if plugin_id in ZAP_MISCONFIG_PLUGIN_IDS:
            return "misconfig"

    if any(keyword in blob for keyword in MISCONFIG_KEYWORDS):
        return "misconfig"

    if any(
        token in blob
        for token in (
            "availability",
            "monitoring unavailable",
            "service unavailable",
        )
    ):
        return "availability"

    return "vuln"


def with_category(finding: dict) -> dict:
    normalized = dict(finding)
    normalized["category"] = infer_category(normalized)
    return normalized


def annotate_findings(findings: list) -> list[dict]:
    annotated = []
    for finding in findings:
        if isinstance(finding, dict):
            annotated.append(with_category(finding))
    return annotated


def suppression_matches(finding: dict, rule: dict) -> bool:
    if not isinstance(rule, dict):
        return False

    expires_on = _text(rule.get("expires_on"))
    if expires_on:
        try:
            if date.fromisoformat(expires_on) < date.today():
                return False
        except ValueError:
            return False

    finding_id = _text(finding.get("id"))
    rule_id = _text(rule.get("id"))
    if rule_id and finding_id != rule_id:
        return False

    location = _text(finding.get("location"))
    location_contains = _text(rule.get("location_contains"))
    if location_contains and location_contains not in location:
        return False

    category = _text(rule.get("category"))
    if category and infer_category(finding) != category.lower():
        return False

    return bool(rule_id or location_contains or category)


def is_suppressed(finding: dict, suppressions: list) -> dict | None:
    for rule in suppressions or []:
        if suppression_matches(finding, rule):
            return rule
    return None


def should_block_finding(finding: dict, policy: dict) -> bool:
    category = infer_category(finding)
    severity = _lower(finding.get("severity"))

    if category == "secret" and policy.get("blockOnSecret", True):
        return True
    if category == "scanner-error" and policy.get("blockOnScannerError", True):
        return True
    if category == "availability" and policy.get("blockOnAvailability", True):
        if severity in {"critical", "high"}:
            return True
        return policy.get("blockOnAvailabilityMedium", False) and severity == "medium"
    if category == "vuln":
        if severity == "critical" and policy.get("blockOnVulnCritical", True):
            return True
        if severity == "high" and policy.get("blockOnVulnHigh", True):
            return True
        if severity == "secret" and policy.get("blockOnSecret", True):
            return True
    return False


def should_warn_finding(finding: dict, policy: dict) -> bool:
    if should_block_finding(finding, policy):
        return False

    category = infer_category(finding)
    severity = _lower(finding.get("severity"))

    if category == "misconfig" and policy.get("warnOnMisconfig", True):
        return True
    if severity == "medium" and policy.get("warnOnMedium", True):
        return True
    return False


def block_reason_for_finding(finding: dict) -> str:
    category = infer_category(finding)
    severity = _lower(finding.get("severity")) or "unknown"
    title = _text(finding.get("title")) or _text(finding.get("id")) or "finding"

    if category == "secret":
        return f"Secret 노출이 탐지되었습니다: {title}"
    if category == "scanner-error":
        return f"보안 검사 결과를 신뢰할 수 없습니다: {title}"
    if category == "availability":
        return f"서비스 가용성 문제가 탐지되었습니다: {title}"
    return f"{severity.upper()} 등급 보안 이슈가 탐지되었습니다: {title}"


def warn_reason_for_finding(finding: dict) -> str:
    category = infer_category(finding)
    title = _text(finding.get("title")) or _text(finding.get("id")) or "finding"
    if category == "misconfig":
        return f"설정/헤더 이슈(경고): {title}"
    return f"수정 권고(경고): {title}"


def finding_report_status(findings: list[dict], policy: dict | None = None) -> str:
    policy = policy or {}
    has_warning = False
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        if should_block_finding(finding, policy):
            return "failed"
        if should_warn_finding(finding, policy):
            has_warning = True
    return "warning" if has_warning else "passed"
