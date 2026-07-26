#!/usr/bin/env python3
"""
Evaluate normalized security findings against the Secure Gate policy.

The team category policy is authoritative. Policy profiles only change how
those categories are handled for PR, post-merge, and training workflows.
"""

import argparse
import json
import os
import sys
from datetime import date
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import gate_policy

REPORTS_DIR = Path("security/reports")
SUMMARY_FILE = REPORTS_DIR / "security-summary.json"
POLICY_FILE = Path(
    os.environ.get(
        "SECURE_GATE_POLICY",
        "security/policies/security-gate-policy.json",
    )
)
DEFAULT_SUPPRESSIONS_FILE = Path(
    os.environ.get(
        "SECURE_GATE_SUPPRESSIONS",
        "security/policies/suppressions.json",
    )
)
DECISION_FILE = REPORTS_DIR / "gate-decision.json"
SUPPORTED_SEVERITIES = ("critical", "high", "medium", "low", "secret")


def load_json(path: Path) -> dict:
    if not path.exists():
        print(f"[ERROR] File not found: {path}")
        sys.exit(1)
    try:
        with open(path, encoding="utf-8") as source:
            data = json.load(source)
    except (json.JSONDecodeError, OSError) as error:
        print(f"[ERROR] Failed to read {path}: {error}")
        sys.exit(1)
    if not isinstance(data, dict):
        print(f"[ERROR] JSON root must be an object: {path}")
        sys.exit(1)
    return data


def load_suppressions(path: Path | None) -> tuple[list, list[str]]:
    if path is None or not path.exists():
        return [], []
    try:
        with open(path, encoding="utf-8") as source:
            data = json.load(source)
    except (json.JSONDecodeError, OSError) as error:
        return [], [f"Could not read suppression file {path}: {error}"]

    if isinstance(data, list):
        return data, []
    if isinstance(data, dict) and isinstance(data.get("suppressions"), list):
        return data["suppressions"], []
    return [], [f'{path} must be a list or contain a "suppressions" array.']


def _legacy_severity_profile(profile: dict) -> dict:
    block = {
        str(item).strip().lower()
        for item in profile.get("blockSeverities", [])
        if str(item).strip()
    }
    warn = {
        str(item).strip().lower()
        for item in profile.get("warnSeverities", [])
        if str(item).strip()
    }
    return {
        "blockOnSecret": "secret" in block,
        "blockOnScannerError": bool(profile.get("blockOnReportError", True)),
        "blockOnAvailability": bool({"critical", "high"} & block),
        "blockOnAvailabilityMedium": "medium" in block,
        "blockOnVulnCritical": "critical" in block,
        "blockOnVulnHigh": "high" in block,
        "warnOnVulnCritical": "critical" in warn,
        "warnOnVulnHigh": "high" in warn,
        "warnOnAvailability": bool({"critical", "high"} & warn),
        "warnOnMedium": "medium" in warn,
        "warnOnMisconfig": True,
        "unknownSeverity": str(profile.get("unknownSeverity", "block")).lower(),
    }


def resolve_profile(
    policy: dict,
    requested_profile: str | None = None,
) -> tuple[str, dict, list[str]]:
    profiles = policy.get("profiles")
    if not isinstance(profiles, dict):
        profile = dict(policy)
        profile.setdefault("unknownSeverity", "block")
        return "legacy", profile, []

    profile_name = (
        requested_profile
        or os.environ.get("SECURE_GATE_PROFILE")
        or policy.get("defaultProfile")
        or "pr"
    )
    raw_profile = profiles.get(profile_name)
    if not isinstance(raw_profile, dict):
        return (
            str(profile_name),
            {},
            [f"Unknown or invalid policy profile: {profile_name}"],
        )

    profile = dict(raw_profile)
    if "blockSeverities" in profile or "warnSeverities" in profile:
        profile = _legacy_severity_profile(profile)

    unknown_action = str(profile.get("unknownSeverity", "block")).lower()
    errors = []
    if unknown_action not in {"block", "warn", "ignore"}:
        errors.append(
            f"profiles.{profile_name}.unknownSeverity must be block, warn, or ignore."
        )
        unknown_action = "block"
    profile["unknownSeverity"] = unknown_action
    return str(profile_name), profile, errors


def infer_profile_name(
    summary: dict,
    policy: dict,
    requested_profile: str | None,
) -> str | None:
    if requested_profile or os.environ.get("SECURE_GATE_PROFILE"):
        return requested_profile

    reports = summary.get("reports")
    if isinstance(reports, dict):
        report_keys = set(reports)
        if "dependency_track" in report_keys and "build" not in report_keys:
            return "post_merge"
    return policy.get("defaultProfile") or "pr"


def _canonical_suppression(entry: dict) -> dict:
    normalized = dict(entry)
    aliases = {
        "approvedBy": "approved_by",
        "expiresAt": "expires_on",
        "location": "location",
    }
    for source, destination in aliases.items():
        if source in normalized and destination not in normalized:
            normalized[destination] = normalized[source]
    if normalized.get("location") and not normalized.get("location_contains"):
        normalized["location_contains"] = normalized["location"]
    return normalized


def validate_suppressions(
    suppressions: list,
    today: date,
) -> tuple[list[dict], list[dict], list[str]]:
    active = []
    expired = []
    errors = []

    for index, raw_entry in enumerate(suppressions, start=1):
        prefix = f"suppressions[{index}]"
        if not isinstance(raw_entry, dict):
            errors.append(f"{prefix} must be an object.")
            continue

        entry = _canonical_suppression(raw_entry)
        for field in ("reason", "owner", "approved_by", "expires_on"):
            value = entry.get(field)
            if not isinstance(value, str) or not value.strip():
                errors.append(f"{prefix}.{field} is required.")

        selectors = (
            entry.get("id"),
            entry.get("location_contains"),
            entry.get("category"),
        )
        if not any(isinstance(value, str) and value.strip() for value in selectors):
            errors.append(
                f"{prefix} requires id, location_contains, or category."
            )

        profiles = entry.get("profiles", [])
        if profiles and (
            not isinstance(profiles, list)
            or not all(isinstance(item, str) and item.strip() for item in profiles)
        ):
            errors.append(f"{prefix}.profiles must be an array of profile names.")

        try:
            expires_on = date.fromisoformat(str(entry.get("expires_on", "")))
        except ValueError:
            errors.append(f"{prefix}.expires_on must use YYYY-MM-DD.")
            continue

        public_entry = public_suppression(entry)
        if expires_on < today:
            expired.append(public_entry)
        else:
            active.append(entry)

    return active, expired, errors


def public_suppression(entry: dict) -> dict:
    return {
        key: entry.get(key)
        for key in (
            "id",
            "location",
            "location_contains",
            "category",
            "reason",
            "owner",
            "approved_by",
            "expires_on",
            "profiles",
        )
        if entry.get(key) not in (None, "", [])
    }


def profile_matches(entry: dict, profile_name: str) -> bool:
    profiles = entry.get("profiles") or []
    return not profiles or profile_name in profiles


def add_unique(items: list[str], value: str) -> None:
    if value not in items:
        items.append(value)


def iter_findings(summary: dict):
    reports = summary.get("reports")
    if not isinstance(reports, dict):
        return
    for report_name, report in reports.items():
        if not isinstance(report, dict):
            continue
        findings = report.get("findings")
        if not isinstance(findings, list):
            continue
        for finding in findings:
            if isinstance(finding, dict):
                yield report_name, finding


def evaluate(
    summary: dict,
    policy: dict,
    suppressions: list | None = None,
    profile_name: str | None = None,
    accepted_risks: list | None = None,
    policy_errors: list[str] | None = None,
    today: date | None = None,
) -> dict:
    selected = infer_profile_name(summary, policy, profile_name)
    resolved_name, profile, profile_errors = resolve_profile(policy, selected)
    evaluation_date = today or date.today()
    raw_suppressions = list(suppressions or accepted_risks or [])
    active_suppressions, expired_suppressions, suppression_errors = (
        validate_suppressions(raw_suppressions, evaluation_date)
    )
    all_policy_errors = (
        list(policy_errors or []) + profile_errors + suppression_errors
    )

    blocked = False
    block_reasons = []
    warnings = []
    applied_suppressions = []
    severity_counts = {severity: 0 for severity in SUPPORTED_SEVERITIES}
    category_counts = {category: 0 for category in sorted(gate_policy.CATEGORIES)}
    unknown_findings = 0
    structured_findings = False
    annotated_reports = {}

    if all_policy_errors:
        blocked = True
        add_unique(block_reasons, "보안 정책 파일이 올바르지 않습니다.")
        warnings.extend(all_policy_errors)

    if summary.get("has_error") and profile.get("blockOnScannerError", True):
        blocked = True
        add_unique(
            block_reasons,
            "필수 보안 보고서가 누락되었거나 올바르게 처리되지 않았습니다.",
        )

    for report_name, report in (summary.get("reports") or {}).items():
        if not isinstance(report, dict):
            annotated_reports[report_name] = report
            continue

        effective_report_findings = []
        for finding in report.get("findings") or []:
            if not isinstance(finding, dict):
                continue
            structured_findings = True
            annotated = gate_policy.with_category(finding)
            severity = str(annotated.get("severity") or "").strip().lower()
            category = annotated["category"]

            matching_rule = next(
                (
                    rule
                    for rule in active_suppressions
                    if profile_matches(rule, resolved_name)
                    and gate_policy.suppression_matches(annotated, rule)
                ),
                None,
            )
            if matching_rule is not None and category != "secret":
                applied_suppressions.append(public_suppression(matching_rule))
                continue
            if matching_rule is not None and category == "secret":
                add_unique(
                    warnings,
                    "Secret finding에는 예외 승인을 적용할 수 없습니다.",
                )

            effective_report_findings.append(annotated)
            category_counts[category] += 1
            if severity in severity_counts:
                severity_counts[severity] += 1
            else:
                unknown_findings += 1

            if gate_policy.should_block_finding(annotated, profile):
                blocked = True
                add_unique(
                    block_reasons,
                    gate_policy.block_reason_for_finding(annotated),
                )
            elif gate_policy.should_warn_finding(annotated, profile):
                add_unique(
                    warnings,
                    gate_policy.warn_reason_for_finding(annotated),
                )

        annotated_report = dict(report)
        annotated_report["findings"] = effective_report_findings
        annotated_reports[report_name] = annotated_report

    if not structured_findings:
        fallback_flags = {
            "critical": "has_critical",
            "high": "has_high",
            "secret": "has_secret",
            "medium": "has_medium",
        }
        for severity, flag in fallback_flags.items():
            if not summary.get(flag):
                continue
            severity_counts[severity] = 1
            fallback = {
                "id": f"summary.{severity}",
                "severity": severity,
                "category": "secret" if severity == "secret" else "vuln",
                "title": f"{severity.title()} finding",
            }
            category_counts[fallback["category"]] += 1
            if gate_policy.should_block_finding(fallback, profile):
                blocked = True
                add_unique(
                    block_reasons,
                    gate_policy.block_reason_for_finding(fallback),
                )
            elif gate_policy.should_warn_finding(fallback, profile):
                add_unique(
                    warnings,
                    gate_policy.warn_reason_for_finding(fallback),
                )

    if unknown_findings:
        message = f"알 수 없는 severity finding이 {unknown_findings}건 탐지되었습니다."
        unknown_action = profile.get("unknownSeverity", "block")
        if unknown_action == "block":
            blocked = True
            add_unique(block_reasons, message)
        elif unknown_action == "warn":
            add_unique(warnings, message)

    if applied_suppressions:
        add_unique(
            warnings,
            f"승인된 예외 {len(applied_suppressions)}건을 Gate 판정에서 제외했습니다.",
        )
    if expired_suppressions:
        add_unique(
            warnings,
            f"만료된 예외 {len(expired_suppressions)}건은 적용하지 않았습니다.",
        )

    effective_findings = sum(severity_counts.values()) + unknown_findings
    return {
        "policy_version": policy.get("version", "legacy"),
        "policy_profile": resolved_name,
        "gate_status": "FAILED" if blocked else "PASSED",
        "blocked": blocked,
        "block_reasons": block_reasons,
        "warnings": warnings,
        "total_findings": summary.get("total_findings", 0),
        "effective_findings": effective_findings,
        "severity_counts": severity_counts,
        "category_counts": category_counts,
        "accepted_risks": applied_suppressions,
        "expired_risks": expired_suppressions,
        "suppressed": applied_suppressions,
        "reports": annotated_reports or summary.get("reports", {}),
    }


def resolve_suppressions_path(
    policy_path: Path,
    policy: dict,
    command_line_value: str | None,
) -> Path | None:
    raw_value = command_line_value
    if raw_value is None:
        exception_policy = policy.get("exceptionPolicy")
        if isinstance(exception_policy, dict):
            raw_value = exception_policy.get("file")
    if raw_value is None:
        return DEFAULT_SUPPRESSIONS_FILE
    if not str(raw_value).strip() or str(raw_value).strip().lower() == "none":
        return None

    path = Path(str(raw_value))
    if path.is_absolute():
        return path
    return policy_path.parent / path


def parse_args():
    parser = argparse.ArgumentParser(description="Evaluate Secure Gate policy.")
    parser.add_argument(
        "--profile",
        default=os.environ.get("SECURE_GATE_PROFILE"),
        help="Policy profile name. Default: inferred from the selected reports.",
    )
    parser.add_argument(
        "--suppressions",
        "--exceptions",
        dest="suppressions",
        default=os.environ.get("SECURE_GATE_SUPPRESSIONS"),
        help="Suppression JSON path. Use 'none' to disable.",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    summary = load_json(SUMMARY_FILE)
    policy = load_json(POLICY_FILE)
    suppressions_path = resolve_suppressions_path(
        POLICY_FILE,
        policy,
        args.suppressions,
    )
    suppressions, suppression_errors = load_suppressions(suppressions_path)
    decision = evaluate(
        summary,
        policy,
        suppressions=suppressions,
        profile_name=args.profile,
        policy_errors=suppression_errors,
    )

    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    with open(DECISION_FILE, "w", encoding="utf-8") as destination:
        json.dump(decision, destination, ensure_ascii=False, indent=2)
        destination.write("\n")

    print(f"[Policy Profile] {decision['policy_profile']}")
    print(f"[Gate Status] {decision['gate_status']}")
    for reason in decision["block_reasons"]:
        print(f"  [BLOCK] {reason}")
    for warning in decision["warnings"]:
        print(f"  [WARN]  {warning}")
    for item in decision["suppressed"]:
        print(
            "  [SUPPRESS] "
            f"{item.get('id', 'unknown')} "
            f"({item.get('expires_on', 'n/a')}): "
            f"{item.get('reason', 'suppressed')}"
        )
    print(f"  Total findings: {decision['total_findings']}")

    if decision["blocked"]:
        print("\nMerge is BLOCKED by Security Gate.")
        sys.exit(1)
    print("\nSecurity Gate PASSED. Merge is allowed.")


if __name__ == "__main__":
    main()
