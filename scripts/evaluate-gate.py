#!/usr/bin/env python3
"""
evaluate-gate.py

security-summary.json과 security-gate-policy.json을 읽어
Merge 차단 여부를 판단하고 gate-decision.json을 생성한다.

- 정책 프로필별 차단/경고 심각도 적용
- 필수 보고서 오류는 Fail Closed
- 승인자, 사유, 만료일이 유효한 Accepted Risk 적용
- Secret finding은 예외 적용 금지

차단 기준은 security/policies/security-gate-policy.json에서 관리한다.
기존 Boolean 정책 파일도 하위 호환으로 지원한다.
"""

import argparse
import json
import os
import sys
from datetime import date
from pathlib import Path

REPORTS_DIR   = Path("security/reports")
SUMMARY_FILE  = REPORTS_DIR / "security-summary.json"
# Caller may override via SECURE_GATE_POLICY (absolute or relative path).
POLICY_FILE   = Path(
    os.environ.get(
        "SECURE_GATE_POLICY",
        "security/policies/security-gate-policy.json",
    )
)
DECISION_FILE = REPORTS_DIR / "gate-decision.json"
SUPPORTED_SEVERITIES = {"critical", "high", "medium", "low", "secret"}
SEVERITY_LABELS = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "secret": "Secret",
}


def load_json(path: Path) -> dict:
    if not path.exists():
        print(f"[ERROR] File not found: {path}")
        sys.exit(1)
    with open(path) as f:
        return json.load(f)


def normalize_severity_list(value, setting_name, errors):
    if not isinstance(value, list):
        errors.append(f"{setting_name} must be an array.")
        return set()

    severities = {
        str(severity).strip().lower()
        for severity in value
        if str(severity).strip()
    }
    unknown = sorted(severities - SUPPORTED_SEVERITIES)
    if unknown:
        errors.append(
            f"{setting_name} contains unsupported severities: {', '.join(unknown)}"
        )
    return severities & SUPPORTED_SEVERITIES


def legacy_profile(policy):
    block_severities = set()
    if policy.get("blockOnCritical"):
        block_severities.add("critical")
    if policy.get("blockOnHigh"):
        block_severities.add("high")
    if policy.get("blockOnSecret"):
        block_severities.add("secret")

    warn_severities = {"medium"} if policy.get("warnOnMedium") else set()
    return {
        "block_severities": block_severities,
        "warn_severities": warn_severities,
        "block_on_report_error": True,
        "unknown_severity": "block",
    }


def resolve_profile(policy, requested_profile=None):
    profiles = policy.get("profiles")
    if not isinstance(profiles, dict):
        return "legacy", legacy_profile(policy), []

    errors = []
    profile_name = (
        requested_profile
        or os.environ.get("SECURE_GATE_PROFILE")
        or policy.get("defaultProfile")
        or "pr"
    )
    profile = profiles.get(profile_name)
    if not isinstance(profile, dict):
        errors.append(f"Unknown or invalid policy profile: {profile_name}")
        profile = {}

    block_severities = normalize_severity_list(
        profile.get("blockSeverities", []),
        f"profiles.{profile_name}.blockSeverities",
        errors,
    )
    warn_severities = normalize_severity_list(
        profile.get("warnSeverities", []),
        f"profiles.{profile_name}.warnSeverities",
        errors,
    )
    overlap = sorted(block_severities & warn_severities)
    if overlap:
        errors.append(
            f"Profile {profile_name} has severities in both block and warn: "
            f"{', '.join(overlap)}"
        )

    unknown_severity = str(profile.get("unknownSeverity", "block")).lower()
    if unknown_severity not in {"block", "warn", "ignore"}:
        errors.append(
            f"profiles.{profile_name}.unknownSeverity must be block, warn, or ignore."
        )
        unknown_severity = "block"

    return (
        str(profile_name),
        {
            "block_severities": block_severities,
            "warn_severities": warn_severities,
            "block_on_report_error": bool(
                profile.get("blockOnReportError", True)
            ),
            "unknown_severity": unknown_severity,
        },
        errors,
    )


def load_accepted_risks(path):
    if path is None or not path.exists():
        return [], []

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as error:
        return [], [f"Could not read accepted risk file {path}: {error}"]

    if not isinstance(data, dict) or not isinstance(data.get("exceptions"), list):
        return [], [f"Accepted risk file {path} must contain an exceptions array."]

    accepted_risks = []
    errors = []
    for index, entry in enumerate(data["exceptions"], start=1):
        prefix = f"exceptions[{index}]"
        if not isinstance(entry, dict):
            errors.append(f"{prefix} must be an object.")
            continue

        normalized = dict(entry)
        for field in ("id", "reason", "owner", "approvedBy", "expiresAt"):
            value = normalized.get(field)
            if not isinstance(value, str) or not value.strip():
                errors.append(f"{prefix}.{field} is required.")

        profiles = normalized.get("profiles", [])
        if profiles and (
            not isinstance(profiles, list)
            or not all(isinstance(item, str) and item.strip() for item in profiles)
        ):
            errors.append(f"{prefix}.profiles must be an array of profile names.")

        try:
            date.fromisoformat(str(normalized.get("expiresAt", "")))
        except ValueError:
            errors.append(f"{prefix}.expiresAt must use YYYY-MM-DD.")

        accepted_risks.append(normalized)

    return accepted_risks, errors


def exception_matches(entry, finding, profile_name):
    if entry.get("id") != finding.get("id"):
        return False
    if entry.get("location") and entry.get("location") != finding.get("location"):
        return False

    profiles = entry.get("profiles") or []
    return not profiles or profile_name in profiles


def public_exception(entry):
    return {
        key: entry.get(key)
        for key in (
            "id",
            "location",
            "reason",
            "owner",
            "approvedBy",
            "expiresAt",
            "profiles",
        )
        if entry.get(key) not in (None, "", [])
    }


def iter_findings(summary):
    reports = summary.get("reports")
    if not isinstance(reports, dict):
        return

    for report_key, report in reports.items():
        if not isinstance(report, dict):
            continue
        findings = report.get("findings")
        if not isinstance(findings, list):
            continue
        for finding in findings:
            if isinstance(finding, dict):
                yield report_key, finding


def infer_profile_name(summary, policy, requested_profile):
    if requested_profile or os.environ.get("SECURE_GATE_PROFILE"):
        return requested_profile

    reports = summary.get("reports")
    if isinstance(reports, dict):
        report_keys = set(reports)
        if "dependency_track" in report_keys and "build" not in report_keys:
            return "post_merge"

    return policy.get("defaultProfile") or "pr"


def evaluate(
    summary,
    policy,
    profile_name=None,
    accepted_risks=None,
    policy_errors=None,
    today=None,
):
    selected_profile = infer_profile_name(summary, policy, profile_name)
    resolved_profile, profile, profile_errors = resolve_profile(policy, selected_profile)
    all_policy_errors = list(policy_errors or []) + profile_errors
    accepted_risks = list(accepted_risks or [])
    today = today or date.today()

    blocked       = False
    block_reasons = []
    warnings      = []
    applied_exceptions = []
    expired_exceptions = []
    severity_counts = {severity: 0 for severity in sorted(SUPPORTED_SEVERITIES)}
    unknown_findings = 0
    found_structured_findings = False

    if all_policy_errors:
        blocked = True
        block_reasons.append("보안 정책 파일이 올바르지 않습니다.")
        warnings.extend(all_policy_errors)

    if profile["block_on_report_error"] and summary.get("has_error"):
        blocked = True
        block_reasons.append(
            "필수 보안 보고서가 누락되었거나 올바르게 처리되지 않았습니다."
        )

    for _, finding in iter_findings(summary):
        found_structured_findings = True
        severity = str(finding.get("severity") or "").strip().lower()
        matching_exception = next(
            (
                entry
                for entry in accepted_risks
                if exception_matches(entry, finding, resolved_profile)
            ),
            None,
        )

        if matching_exception is not None:
            try:
                expires_at = date.fromisoformat(
                    str(matching_exception.get("expiresAt", ""))
                )
            except ValueError:
                expires_at = date.min

            if expires_at < today:
                expired_exceptions.append(public_exception(matching_exception))
            elif severity == "secret":
                warnings.append(
                    "Secret finding에는 Accepted Risk 예외를 적용할 수 없습니다."
                )
            else:
                applied_exceptions.append(public_exception(matching_exception))
                continue

        if severity in SUPPORTED_SEVERITIES:
            severity_counts[severity] += 1
        else:
            unknown_findings += 1

    if not found_structured_findings:
        fallback_flags = {
            "critical": "has_critical",
            "high": "has_high",
            "secret": "has_secret",
            "medium": "has_medium",
        }
        for severity, flag in fallback_flags.items():
            if summary.get(flag):
                severity_counts[severity] = 1

    for severity in profile["block_severities"]:
        if severity_counts[severity]:
            blocked = True
            block_reasons.append(
                f"{SEVERITY_LABELS[severity]} 등급 취약점이 탐지되었습니다."
            )

    for severity in profile["warn_severities"]:
        if severity_counts[severity]:
            warnings.append(
                f"{SEVERITY_LABELS[severity]} 등급 취약점이 탐지되었습니다. "
                "수정을 권장합니다."
            )

    if unknown_findings:
        message = f"알 수 없는 severity finding이 {unknown_findings}건 탐지되었습니다."
        if profile["unknown_severity"] == "block":
            blocked = True
            block_reasons.append(message)
        elif profile["unknown_severity"] == "warn":
            warnings.append(message)

    if applied_exceptions:
        warnings.append(
            f"승인된 Accepted Risk {len(applied_exceptions)}건을 Gate 판정에서 제외했습니다."
        )
    if expired_exceptions:
        warnings.append(
            f"만료된 Accepted Risk {len(expired_exceptions)}건은 예외로 적용하지 않았습니다."
        )

    return {
        "policy_version": policy.get("version", "legacy"),
        "policy_profile": resolved_profile,
        "gate_status":    "FAILED" if blocked else "PASSED",
        "blocked":        blocked,
        "block_reasons":  block_reasons,
        "warnings":       warnings,
        "total_findings": summary.get("total_findings", 0),
        "effective_findings": sum(severity_counts.values()) + unknown_findings,
        "severity_counts": severity_counts,
        "accepted_risks": applied_exceptions,
        "expired_risks": expired_exceptions,
        "reports":        summary.get("reports", {}),
    }


def resolve_exceptions_path(policy_path, policy, command_line_value):
    raw_value = command_line_value
    if raw_value is None:
        exception_policy = policy.get("exceptionPolicy")
        if isinstance(exception_policy, dict):
            raw_value = exception_policy.get("file")

    if not raw_value or str(raw_value).strip().lower() == "none":
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
        help="Policy profile name. Default: policy defaultProfile.",
    )
    parser.add_argument(
        "--exceptions",
        default=os.environ.get("SECURE_GATE_EXCEPTIONS"),
        help=(
            "Accepted Risk JSON path. Relative paths are resolved from the policy "
            "directory. Use 'none' to disable."
        ),
    )
    return parser.parse_args()


def main():
    args = parse_args()
    summary  = load_json(SUMMARY_FILE)
    policy   = load_json(POLICY_FILE)
    exceptions_path = resolve_exceptions_path(POLICY_FILE, policy, args.exceptions)
    accepted_risks, exception_errors = load_accepted_risks(exceptions_path)
    decision = evaluate(
        summary,
        policy,
        profile_name=args.profile,
        accepted_risks=accepted_risks,
        policy_errors=exception_errors,
    )

    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    with open(DECISION_FILE, "w") as f:
        json.dump(decision, f, indent=2)

    print(f"[Policy Profile] {decision['policy_profile']}")
    print(f"[Gate Status] {decision['gate_status']}")
    for reason in decision["block_reasons"]:
        print(f"  [BLOCK] {reason}")
    for warning in decision["warnings"]:
        print(f"  [WARN]  {warning}")
    print(f"  Total findings: {decision['total_findings']}")

    if decision["blocked"]:
        print("\nMerge is BLOCKED by Security Gate.")
        sys.exit(1)
    else:
        print("\nSecurity Gate PASSED. Merge is allowed.")


if __name__ == "__main__":
    main()
