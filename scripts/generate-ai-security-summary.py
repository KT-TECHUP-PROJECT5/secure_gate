#!/usr/bin/env python3
"""
Generate a non-authoritative AI explanation of gate-decision.json.

The deterministic Policy Evaluator remains the only source of the Gate result.
This script sends a bounded, redacted view of normalized findings to the OpenAI
Responses API and writes separate JSON and Markdown reports for people to read.

Environment variables:
  OPENAI_API_KEY  Required for AI generation. Never written to reports.
  OPENAI_MODEL    Optional model override. Default: gpt-5.6-luna.
"""

import argparse
import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path


DEFAULT_DECISION_PATH = Path("security/reports/gate-decision.json")
DEFAULT_JSON_OUTPUT = Path("security/reports/ai-security-summary.json")
DEFAULT_MARKDOWN_OUTPUT = Path("security/reports/ai-security-summary.md")
DEFAULT_MODEL = "gpt-5.6-luna"
OPENAI_RESPONSES_URL = "https://api.openai.com/v1/responses"
SEVERITY_ORDER = {
    "critical": 0,
    "secret": 1,
    "high": 2,
    "medium": 3,
    "low": 4,
}
SECRET_ASSIGNMENT_PATTERN = re.compile(
    r"(?i)\b(api[-_ ]?key|token|password|secret)\s*[:=]\s*[^\s,;]+"
)
OPENAI_KEY_PATTERN = re.compile(r"\bsk-[A-Za-z0-9_-]{12,}\b")
SOURCE_PATH_PATTERN = re.compile(
    r"(?i)(?:^|/)[^/\s]+\.(?:py|js|jsx|ts|tsx|java|kt|go|rb|php|cs|"
    r"c|cc|cpp|h|hpp|vue|svelte|html|jinja|j2|yaml|yml|json|toml|xml)"
    r"(?::\d+(?::\d+)?)?$"
)

REMEDIATION_GROUPS = {
    "scanner-error": ("검사 신뢰성 복구", 0),
    "availability": ("서비스 가용성 복구", 1),
    "secret": ("노출 자격증명 폐기·교체", 2),
    "access-control": ("권한 검증·IDOR 차단", 3),
    "sql-injection": ("SQL Injection 제거", 4),
    "command-injection": ("명령·코드 Injection 제거", 5),
    "xss": ("XSS 공통 출력 경로 수정", 6),
    "dependency": ("취약 의존성 업데이트", 7),
    "exposure": ("Debug·Docs 노출 축소", 8),
    "security-headers": ("보안 헤더·전송 설정 보완", 9),
}

AI_ANALYSIS_SCHEMA = {
    "type": "object",
    "properties": {
        "executive_summary": {"type": "string"},
        "key_observations": {
            "type": "array",
            "items": {"type": "string"},
        },
        "prioritized_findings": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "finding_id": {"type": "string"},
                    "location": {"type": "string"},
                    "risk": {"type": "string"},
                    "remediation": {"type": "string"},
                },
                "required": [
                    "finding_id",
                    "location",
                    "risk",
                    "remediation",
                ],
                "additionalProperties": False,
            },
        },
        "report_reading_guide": {
            "type": "array",
            "items": {"type": "string"},
        },
        "limitations": {
            "type": "array",
            "items": {"type": "string"},
        },
    },
    "required": [
        "executive_summary",
        "key_observations",
        "prioritized_findings",
        "report_reading_guide",
        "limitations",
    ],
    "additionalProperties": False,
}


class AiSummaryError(RuntimeError):
    """Raised when an AI explanation cannot be generated safely."""


def positive_int(value):
    try:
        parsed = int(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("must be an integer") from error
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be greater than 0")
    return parsed


def load_decision(path):
    if not path.is_file():
        raise AiSummaryError(f"Gate decision file not found: {path}")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise AiSummaryError(f"Could not read Gate decision: {error}") from error
    if not isinstance(data, dict):
        raise AiSummaryError("Gate decision must be a JSON object")
    return data


def redact_text(value, limit=1200):
    text = str(value or "")
    text = OPENAI_KEY_PATTERN.sub("[REDACTED]", text)
    text = SECRET_ASSIGNMENT_PATTERN.sub(
        lambda match: f"{match.group(1)}=[REDACTED]",
        text,
    )
    if len(text) > limit:
        return text[:limit] + "...[truncated]"
    return text


def sanitize_location(value):
    location = redact_text(value, limit=500)
    parsed = urllib.parse.urlsplit(location)
    if parsed.scheme in {"http", "https"} and parsed.netloc:
        hostname = parsed.hostname or ""
        try:
            port = parsed.port
        except ValueError:
            return "[invalid URL removed]"
        if port:
            hostname = f"{hostname}:{port}"
        return urllib.parse.urlunsplit(
            (parsed.scheme, hostname, parsed.path, "", "")
        )
    return location


def source_location_from(location):
    if not isinstance(location, str):
        return ""
    sanitized = sanitize_location(location)
    parsed = urllib.parse.urlsplit(sanitized)
    if parsed.scheme in {"http", "https"} and parsed.netloc:
        return ""
    if SOURCE_PATH_PATTERN.search(sanitized):
        return sanitized
    return ""


def classify_remediation_group(finding):
    severity = str(finding.get("severity") or "").lower()
    category = str(finding.get("category") or "").lower()
    finding_id = str(finding.get("id") or "").lower()
    text = " ".join(
        str(finding.get(field) or "").lower()
        for field in ("id", "title", "description")
    )

    if category == "scanner-error":
        key = "scanner-error"
    elif category == "availability":
        key = "availability"
    elif severity == "secret" or category == "secret":
        key = "secret"
    elif any(
        token in text
        for token in (
            "idor",
            "admin-access",
            "administrator page",
            "authorization",
            "access control",
            "권한",
            "관리자 접근",
        )
    ):
        key = "access-control"
    elif any(
        token in text
        for token in (
            "sql injection",
            "search-sqli",
            "sqli",
            "sql 인젝션",
            "search query exposes private posts",
        )
    ):
        key = "sql-injection"
    elif any(
        token in text
        for token in ("private post", "private object", "타인 비공개")
    ):
        key = "access-control"
    elif any(
        token in text
        for token in (
            "command injection",
            "code injection",
            "rce",
            "remote code execution",
        )
    ):
        key = "command-injection"
    elif any(
        token in text
        for token in (
            "cross site scripting",
            "cross-site scripting",
            "xss",
            "reflected without escaping",
        )
    ):
        key = "xss"
    elif any(
        token in text
        for token in ("cve-", "dependency", "vulnerable package", "취약 의존성")
    ):
        key = "dependency"
    elif any(
        token in text
        for token in (
            "debug-exposure",
            "docs-exposure",
            "debug endpoint",
            "documentation endpoint",
            "/docs",
            "/redoc",
        )
    ):
        key = "exposure"
    elif any(
        token in text
        for token in (
            "security header",
            "content security policy",
            "content-security-policy",
            "x-frame-options",
            "x-content-type-options",
            "clickjacking header",
            "http only site",
            "보안 헤더",
        )
    ):
        key = "security-headers"
    else:
        key = f"finding:{finding_id or 'unknown'}"

    label, priority = REMEDIATION_GROUPS.get(
        key,
        (str(finding.get("title") or finding.get("id") or "기타 보안 이슈"), 50),
    )
    return key, label, priority


def safe_finding(report_key, finding):
    severity = str(finding.get("severity") or "unknown").strip().lower()
    description = finding.get("description", "")
    if severity == "secret":
        description = "Secret value omitted. Rotate or revoke the credential."

    safe = {
        "report": str(report_key),
        "id": redact_text(finding.get("id", "unknown"), limit=300),
        "severity": severity,
        "category": redact_text(finding.get("category", "unknown"), limit=100),
        "title": redact_text(finding.get("title", "Untitled finding"), limit=500),
        "description": redact_text(description),
        "location": sanitize_location(finding.get("location", "unknown")),
        "source_location": source_location_from(finding.get("location", "")),
    }
    group_key, group_label, group_priority = classify_remediation_group(safe)
    safe["remediation_group"] = group_key
    safe["remediation_group_label"] = group_label
    safe["remediation_priority"] = group_priority
    return safe


def severity_counts_from(decision, findings):
    counts = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "secret": 0,
    }
    decision_counts = decision.get("severity_counts")
    if isinstance(decision_counts, dict):
        for severity in counts:
            value = decision_counts.get(severity, 0)
            if isinstance(value, int):
                counts[severity] = value
        return counts

    for finding in findings:
        severity = finding.get("severity")
        if severity in counts:
            counts[severity] += 1
    return counts


def category_counts_from(decision, findings):
    counts = {
        "vuln": 0,
        "misconfig": 0,
        "secret": 0,
        "availability": 0,
        "scanner-error": 0,
    }
    decision_counts = decision.get("category_counts")
    if isinstance(decision_counts, dict):
        for category in counts:
            value = decision_counts.get(category, 0)
            if isinstance(value, int):
                counts[category] = value
        return counts

    for finding in findings:
        category = finding.get("category")
        if category in counts:
            counts[category] += 1
    return counts


def build_source_payload(decision, max_findings):
    findings = []
    report_statuses = []
    reports = decision.get("reports")
    if isinstance(reports, dict):
        for report_key, report in reports.items():
            if not isinstance(report, dict):
                continue
            report_findings = report.get("findings")
            if not isinstance(report_findings, list):
                report_findings = []
            report_statuses.append(
                {
                    "report": str(report_key),
                    "tool": redact_text(report.get("tool", report_key), limit=300),
                    "status": redact_text(report.get("status", "unknown"), limit=100),
                    "finding_count": sum(
                        1 for finding in report_findings if isinstance(finding, dict)
                    ),
                    "error_count": len(report.get("errors") or []),
                    "warning_count": (
                        len(report.get("warnings") or [])
                        + len(report.get("scanner_warnings") or [])
                    ),
                }
            )
            for finding in report_findings:
                if isinstance(finding, dict):
                    findings.append(safe_finding(report_key, finding))

    findings.sort(
        key=lambda item: (
            item["remediation_priority"],
            SEVERITY_ORDER.get(item["severity"], 99),
            item["id"],
            item["location"],
        )
    )
    selected_findings = findings[:max_findings]
    severity_counts = severity_counts_from(decision, findings)
    category_counts = category_counts_from(decision, findings)

    return {
        "gate_status": str(decision.get("gate_status", "UNKNOWN")),
        "policy_profile": str(decision.get("policy_profile", "unknown")),
        "blocked": bool(decision.get("blocked", False)),
        "block_reasons": [
            redact_text(item, limit=500)
            for item in decision.get("block_reasons", [])
            if isinstance(item, str)
        ],
        "warnings": [
            redact_text(item, limit=500)
            for item in decision.get("warnings", [])
            if isinstance(item, str)
        ],
        "severity_counts": severity_counts,
        "category_counts": category_counts,
        "total_findings": int(decision.get("total_findings", len(findings)) or 0),
        "effective_findings": int(
            decision.get("effective_findings", len(findings)) or 0
        ),
        "findings_in_prompt": len(selected_findings),
        "findings_omitted_from_prompt": max(0, len(findings) - max_findings),
        "accepted_risks_count": len(decision.get("accepted_risks", []) or []),
        "expired_risks_count": len(decision.get("expired_risks", []) or []),
        "report_statuses": report_statuses,
        "findings": selected_findings,
    }


def build_openai_request(model, source_payload):
    system_prompt = (
        "You are a defensive application security report assistant. "
        "Write in clear Korean for developers who are not security experts. "
        "Use only the supplied normalized findings. The deterministic Gate status "
        "is authoritative: never change, override, or recalculate it. "
        "Summarize the whole report, explain how to read it, and provide short, "
        "practical remediation directions. Prioritize remediation groups rather "
        "than listing every scanner alert. Return at most one representative "
        "finding per remediation_group. Treat findings from multiple scanners in "
        "the same remediation_group as corroborating evidence, not separate fixes. "
        "Use this default action order when present: credentials and scanner "
        "failures, authorization/IDOR, SQL injection, shared XSS output paths, "
        "debug/docs exposure, then headers and lower-risk misconfiguration. "
        "Prioritize at most 10 real findings. "
        "Do not invent finding IDs, locations, exploit evidence, or fixed versions. "
        "Use source_location only when it is supplied. When it is empty, state "
        "that runtime evidence cannot identify a source file; never guess one. "
        "Keep warning discussion compact and avoid repeating header findings. "
        "State uncertainty and scanner limitations explicitly."
    )
    user_prompt = (
        "Create a readable security report explanation from this normalized "
        "Gate decision JSON:\n"
        + json.dumps(source_payload, ensure_ascii=False, separators=(",", ":"))
    )

    return {
        "model": model,
        "store": False,
        "input": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        "text": {
            "verbosity": "medium",
            "format": {
                "type": "json_schema",
                "name": "secure_gate_ai_summary",
                "schema": AI_ANALYSIS_SCHEMA,
                "strict": True,
            },
        },
        "max_output_tokens": 5000,
    }


def format_openai_http_error(status, raw_body):
    error_code = ""
    message = ""
    try:
        body = json.loads(raw_body.decode("utf-8"))
        error_detail = body.get("error", {})
        if isinstance(error_detail, dict):
            error_code = str(
                error_detail.get("code") or error_detail.get("type") or ""
            )
            message = str(error_detail.get("message") or "")
    except (AttributeError, UnicodeDecodeError, json.JSONDecodeError):
        pass

    error_code = re.sub(r"[^A-Za-z0-9_.-]", "", error_code)[:120]
    message = redact_text(message, limit=500)
    details = [f"OpenAI API returned HTTP {status}"]
    if error_code:
        details.append(f"code={error_code}")
    if message:
        details.append(message)
    return ": ".join(details)


def call_openai(payload, api_key, timeout):
    request = urllib.request.Request(
        OPENAI_RESPONSES_URL,
        data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "secure-gate-ai-report/1.0",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return json.load(response)
    except urllib.error.HTTPError as error:
        raise AiSummaryError(
            format_openai_http_error(error.code, error.read())
        ) from error
    except urllib.error.URLError as error:
        raise AiSummaryError("Could not reach the OpenAI API") from error
    except (OSError, TimeoutError, json.JSONDecodeError) as error:
        raise AiSummaryError("Could not read the OpenAI API response") from error


def extract_analysis(response):
    if not isinstance(response, dict):
        raise AiSummaryError("OpenAI response must be a JSON object")
    if response.get("status") == "incomplete":
        raise AiSummaryError("OpenAI response was incomplete")

    output = response.get("output")
    if not isinstance(output, list):
        raise AiSummaryError("OpenAI response did not contain output items")

    for item in output:
        if not isinstance(item, dict) or item.get("type") != "message":
            continue
        content = item.get("content")
        if not isinstance(content, list):
            continue
        for part in content:
            if not isinstance(part, dict):
                continue
            if part.get("type") == "refusal":
                raise AiSummaryError("OpenAI refused to generate the explanation")
            if part.get("type") == "output_text":
                try:
                    analysis = json.loads(part.get("text", ""))
                except json.JSONDecodeError as error:
                    raise AiSummaryError(
                        "OpenAI output was not valid JSON"
                    ) from error
                validate_analysis_shape(analysis)
                return analysis

    raise AiSummaryError("OpenAI response did not contain output text")


def validate_analysis_shape(analysis):
    if not isinstance(analysis, dict):
        raise AiSummaryError("AI analysis must be a JSON object")

    string_fields = ("executive_summary",)
    list_fields = (
        "key_observations",
        "prioritized_findings",
        "report_reading_guide",
        "limitations",
    )
    for field in string_fields:
        if not isinstance(analysis.get(field), str):
            raise AiSummaryError(f"AI analysis field {field} must be a string")
    for field in list_fields:
        if not isinstance(analysis.get(field), list):
            raise AiSummaryError(f"AI analysis field {field} must be an array")


def normalize_prioritized_findings(analysis, source_payload):
    findings_by_key = {
        (finding["id"], finding["location"]): finding
        for finding in source_payload["findings"]
    }
    findings_by_id = {}
    findings_by_group = {}
    for finding in source_payload["findings"]:
        findings_by_id.setdefault(finding["id"], []).append(finding)
        findings_by_group.setdefault(finding["remediation_group"], []).append(finding)

    normalized = []
    rejected = 0
    duplicate_groups = 0
    selected_groups = set()
    for recommendation in analysis["prioritized_findings"][:10]:
        if not isinstance(recommendation, dict):
            rejected += 1
            continue
        finding_id = str(recommendation.get("finding_id", ""))
        location = sanitize_location(recommendation.get("location", ""))
        source_finding = findings_by_key.get((finding_id, location))
        if source_finding is None:
            candidates = findings_by_id.get(finding_id, [])
            if len(candidates) == 1:
                source_finding = candidates[0]
            elif candidates and len(
                {candidate["remediation_group"] for candidate in candidates}
            ) == 1:
                source_finding = min(
                    candidates,
                    key=lambda candidate: (
                        candidate["location"],
                        candidate["report"],
                    ),
                )
            else:
                rejected += 1
                continue

        group_key = source_finding["remediation_group"]
        if group_key in selected_groups:
            duplicate_groups += 1
            continue
        selected_groups.add(group_key)
        related = findings_by_group.get(group_key, [source_finding])
        related_findings = []
        seen_related = set()
        source_locations = []
        runtime_locations = []
        for item in related:
            related_key = (item["id"], item["location"])
            if related_key not in seen_related:
                seen_related.add(related_key)
                related_findings.append(
                    {
                        "id": item["id"],
                        "title": item["title"],
                        "location": item["location"],
                        "report": item["report"],
                    }
                )
            if item["source_location"] and item["source_location"] not in source_locations:
                source_locations.append(item["source_location"])
            elif (
                not item["source_location"]
                and item["location"] not in {"", "unknown"}
                and item["location"] not in runtime_locations
            ):
                runtime_locations.append(item["location"])

        normalized.append(
            {
                "finding_id": source_finding["id"],
                "title": source_finding["title"],
                "severity": source_finding["severity"],
                "location": source_finding["location"],
                "remediation_group": group_key,
                "remediation_group_label": source_finding[
                    "remediation_group_label"
                ],
                "remediation_priority": source_finding["remediation_priority"],
                "related_findings": related_findings,
                "source_locations": source_locations[:10],
                "runtime_locations": runtime_locations[:10],
                "risk": redact_text(recommendation.get("risk", ""), limit=1000),
                "remediation": redact_text(
                    recommendation.get("remediation", ""),
                    limit=1200,
                ),
            }
        )

    normalized.sort(
        key=lambda item: (
            item["remediation_priority"],
            SEVERITY_ORDER.get(item["severity"], 99),
            item["finding_id"],
        )
    )
    analysis = dict(analysis)
    analysis["executive_summary"] = redact_text(
        analysis["executive_summary"],
        limit=2000,
    )
    analysis["prioritized_findings"] = normalized
    analysis["key_observations"] = [
        redact_text(item, limit=1000)
        for item in analysis["key_observations"]
        if isinstance(item, str)
    ]
    analysis["report_reading_guide"] = [
        redact_text(item, limit=1000)
        for item in analysis["report_reading_guide"]
        if isinstance(item, str)
    ]
    analysis["limitations"] = [
        redact_text(item, limit=1000)
        for item in analysis["limitations"]
        if isinstance(item, str)
    ]
    if rejected:
        analysis["limitations"].append(
            f"입력에 없는 finding 참조 {rejected}건을 결과에서 제외했습니다."
        )
    if duplicate_groups:
        analysis["report_reading_guide"].append(
            f"동일 수정 그룹의 중복 우선순위 항목 {duplicate_groups}건을 통합했습니다."
        )
    return analysis


def authoritative_gate(decision):
    source = build_source_payload(decision, max_findings=1)
    return {
        "gate_status": decision.get("gate_status", "UNKNOWN"),
        "blocked": bool(decision.get("blocked", False)),
        "policy_profile": decision.get("policy_profile", "unknown"),
        "block_reasons": decision.get("block_reasons", []),
        "warnings": decision.get("warnings", []),
        "severity_counts": source["severity_counts"],
        "category_counts": source["category_counts"],
        "total_findings": source["total_findings"],
        "effective_findings": source["effective_findings"],
    }


def result_payload(
    status,
    model,
    decision_path,
    decision,
    analysis=None,
    reason=None,
    source_payload=None,
):
    payload = {
        "status": status,
        "tool": "openai-security-report",
        "model": model,
        "source": str(decision_path),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "authoritative_gate": authoritative_gate(decision),
        "analysis": analysis,
    }
    if source_payload is not None:
        payload["source_coverage"] = {
            "reports": source_payload["report_statuses"],
            "findings_sent_to_ai": source_payload["findings_in_prompt"],
            "findings_omitted_from_ai": source_payload[
                "findings_omitted_from_prompt"
            ],
        }
    if reason:
        payload["reason"] = reason
    return payload


def markdown_list(items, empty_text="- 없음"):
    if not items:
        return empty_text
    return "\n".join(f"- {item}" for item in items)


def markdown_cell(value):
    return str(value).replace("|", "\\|").replace("\n", " ")


def compact_gate_messages(messages):
    grouped = {}
    for message in messages or []:
        if not isinstance(message, str):
            continue
        key, label, priority = classify_remediation_group(
            {
                "id": message,
                "title": message,
                "description": message,
            }
        )
        if key.startswith("finding:"):
            group_key = "other"
            label = "기타 보안 이슈"
            priority = 90
        else:
            group_key = key
        grouped.setdefault(
            group_key,
            {"label": label, "priority": priority, "count": 0},
        )
        grouped[group_key]["count"] += 1

    if not grouped:
        return "- 없음"
    ordered = sorted(
        grouped.values(),
        key=lambda item: (item["priority"], item["label"]),
    )
    return "\n".join(
        f"- {item['label']}: `{item['count']}건`" for item in ordered
    )


def render_markdown(result):
    gate = result["authoritative_gate"]
    analysis = result.get("analysis")
    coverage = result.get("source_coverage") or {}
    counts = gate.get("severity_counts") or {}
    category_counts = gate.get("category_counts") or {}
    count_rows = "\n".join(
        f"| {severity} | {counts.get(severity, 0)} |"
        for severity in ("critical", "high", "medium", "low", "secret")
    )
    category_rows = "\n".join(
        f"| {category} | {category_counts.get(category, 0)} |"
        for category in (
            "vuln",
            "misconfig",
            "secret",
            "availability",
            "scanner-error",
        )
    )
    report_rows = []
    for report in coverage.get("reports") or []:
        report_rows.append(
            "| {report} | {tool} | {status} | {findings} | {warnings} | {errors} |".format(
                report=markdown_cell(report.get("report", "unknown")),
                tool=markdown_cell(report.get("tool", "unknown")),
                status=markdown_cell(report.get("status", "unknown")),
                findings=report.get("finding_count", 0),
                warnings=report.get("warning_count", 0),
                errors=report.get("error_count", 0),
            )
        )

    lines = [
        "# AI Security Report",
        "",
        "## 확정 Gate 판정",
        "",
        f"- 상태: `{gate.get('gate_status', 'UNKNOWN')}`",
        f"- 정책 프로필: `{gate.get('policy_profile', 'unknown')}`",
        f"- 전체 Finding: `{gate.get('total_findings', 0)}`",
        f"- 예외 적용 후 Finding: `{gate.get('effective_findings', 0)}`",
        "",
        "| 심각도 | 건수 |",
        "| --- | ---: |",
        count_rows,
        "",
        "| 카테고리 | 건수 |",
        "| --- | ---: |",
        category_rows,
        "",
        "### 입력 보고서 범위",
        "",
        "| 영역 | 도구 | 상태 | Finding | 경고 | 오류 |",
        "| --- | --- | --- | ---: | ---: | ---: |",
        "\n".join(report_rows) if report_rows else "| 없음 | - | - | 0 | 0 | 0 |",
        "",
        f"- AI 전달 Finding: `{coverage.get('findings_sent_to_ai', 0)}`",
        f"- AI 전달 제외 Finding: `{coverage.get('findings_omitted_from_ai', 0)}`",
        "",
        "### 차단 사유 요약",
        "",
        compact_gate_messages(gate.get("block_reasons", [])),
        "",
        "### 경고 요약",
        "",
        compact_gate_messages(gate.get("warnings", [])),
        "",
        "전체 원문은 `gate-decision.json`의 `block_reasons`와 `warnings`에서 확인합니다.",
        "",
        "## AI 설명",
        "",
    ]

    if result["status"] != "succeeded" or not isinstance(analysis, dict):
        lines.extend(
            [
                f"AI 설명 상태: `{result['status']}`",
                "",
                f"사유: {result.get('reason', 'unknown')}",
            ]
        )
    else:
        lines.extend(
            [
                analysis["executive_summary"],
                "",
                "### 핵심 관찰",
                "",
                markdown_list(analysis["key_observations"]),
                "",
                "### 우선 개선 항목",
                "",
            ]
        )
        if analysis["prioritized_findings"]:
            for index, finding in enumerate(
                analysis["prioritized_findings"],
                start=1,
            ):
                lines.extend(
                    [
                        f"#### {index}. {finding['remediation_group_label']}",
                        "",
                        f"- 대표 Finding: `{finding['finding_id']}`",
                        f"- 심각도: `{finding['severity']}`",
                        f"- 관련 탐지: `{len(finding['related_findings'])}건`",
                        "- 런타임 위치: "
                        + (
                            ", ".join(
                                f"`{location}`"
                                for location in finding["runtime_locations"]
                            )
                            if finding["runtime_locations"]
                            else "`없음`"
                        ),
                        "- 소스 위치: "
                        + (
                            ", ".join(
                                f"`{location}`"
                                for location in finding["source_locations"]
                            )
                            if finding["source_locations"]
                            else "런타임 결과만으로 특정 불가"
                        ),
                        f"- 위험: {finding['risk']}",
                        f"- 개선 방향: {finding['remediation']}",
                        "",
                    ]
                )
        else:
            lines.extend(["- 제안할 Finding이 없습니다.", ""])

        lines.extend(
            [
                "### 리포트 읽는 법",
                "",
                markdown_list(analysis["report_reading_guide"]),
                "",
                "### 한계",
                "",
                markdown_list(analysis["limitations"]),
            ]
        )

    lines.extend(
        [
            "",
            "---",
            "AI 내용은 설명과 개선 방향 제안이며, Merge/배포 판정은 "
            "`gate-decision.json`만 기준으로 합니다.",
            "",
        ]
    )
    return "\n".join(lines)


def write_reports(json_path, markdown_path, result):
    json_path.parent.mkdir(parents=True, exist_ok=True)
    markdown_path.parent.mkdir(parents=True, exist_ok=True)
    json_path.write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    markdown_path.write_text(render_markdown(result), encoding="utf-8")


def parse_args():
    parser = argparse.ArgumentParser(
        description="Generate a non-blocking AI explanation of Gate results."
    )
    parser.add_argument(
        "--decision",
        type=Path,
        default=DEFAULT_DECISION_PATH,
        help="Input gate-decision.json path.",
    )
    parser.add_argument(
        "--output-json",
        type=Path,
        default=DEFAULT_JSON_OUTPUT,
        help="Structured AI report path.",
    )
    parser.add_argument(
        "--output-markdown",
        type=Path,
        default=DEFAULT_MARKDOWN_OUTPUT,
        help="Human-readable AI report path.",
    )
    parser.add_argument(
        "--model",
        default=os.environ.get("OPENAI_MODEL", DEFAULT_MODEL),
        help="OpenAI model ID.",
    )
    parser.add_argument(
        "--timeout",
        type=positive_int,
        default=90,
        help="OpenAI API timeout in seconds.",
    )
    parser.add_argument(
        "--max-findings",
        type=positive_int,
        default=80,
        help="Maximum normalized findings sent to the API.",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    try:
        decision = load_decision(args.decision)
    except AiSummaryError as error:
        decision = {}
        result = result_payload(
            "failed",
            args.model,
            args.decision,
            decision,
            reason=str(error),
        )
        write_reports(args.output_json, args.output_markdown, result)
        print(f"[WARN] {error}")
        return

    source_payload = build_source_payload(decision, args.max_findings)
    api_key = os.environ.get("OPENAI_API_KEY", "").strip()
    if not api_key:
        result = result_payload(
            "skipped",
            args.model,
            args.decision,
            decision,
            reason="OPENAI_API_KEY is not configured",
            source_payload=source_payload,
        )
        write_reports(args.output_json, args.output_markdown, result)
        print("[WARN] OPENAI_API_KEY is not configured; AI report skipped.")
        return

    request_payload = build_openai_request(args.model, source_payload)
    try:
        response = call_openai(request_payload, api_key, args.timeout)
        analysis = extract_analysis(response)
        analysis = normalize_prioritized_findings(analysis, source_payload)
        result = result_payload(
            "succeeded",
            args.model,
            args.decision,
            decision,
            analysis=analysis,
            source_payload=source_payload,
        )
        print("[OK] AI security report generated.")
    except AiSummaryError as error:
        result = result_payload(
            "failed",
            args.model,
            args.decision,
            decision,
            reason=str(error),
            source_payload=source_payload,
        )
        print(f"[WARN] AI report generation failed: {error}")

    write_reports(args.output_json, args.output_markdown, result)
    print(f"[OK] JSON report: {args.output_json}")
    print(f"[OK] Markdown report: {args.output_markdown}")


if __name__ == "__main__":
    main()
