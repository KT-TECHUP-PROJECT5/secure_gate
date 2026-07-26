import importlib.util
import unittest
from datetime import date
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


def load_script_module(name, relative_path):
    spec = importlib.util.spec_from_file_location(name, REPOSITORY_ROOT / relative_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


aggregate_results = load_script_module(
    "aggregate_results",
    "scripts/aggregate-results.py",
)
evaluate_gate = load_script_module(
    "evaluate_gate_for_aggregate_tests",
    "scripts/evaluate-gate.py",
)


class ScannerNormalizationTests(unittest.TestCase):
    def test_default_reports_exclude_dependency_track(self):
        selected = aggregate_results.select_report_files("")

        self.assertEqual(
            {
                "build": "build-report.json",
                "sast": "sast-report.json",
                "secret_scan": "secret-report.json",
                "dependency_scan": "dependency-report.json",
                "runtime_validation": "runtime-report.json",
            },
            selected,
        )

    def test_post_merge_can_require_only_runtime_report(self):
        selected = aggregate_results.select_report_files("runtime_validation")

        self.assertEqual(
            {"runtime_validation": "runtime-report.json"},
            selected,
        )

    def test_semgrep_results_and_scanner_errors_are_preserved(self):
        report = aggregate_results.normalize_report(
            "sast",
            {
                "results": [
                    {
                        "check_id": "python.security.test",
                        "path": "app.py",
                        "start": {"line": 12},
                        "extra": {
                            "severity": "ERROR",
                            "message": "Unsafe operation",
                        },
                    }
                ],
                "errors": [{"message": "partial parse"}],
            },
        )

        self.assertEqual("error", report["status"])
        self.assertEqual("high", report["findings"][0]["severity"])
        self.assertEqual("vuln", report["findings"][0]["category"])
        self.assertEqual("app.py:12", report["findings"][0]["location"])
        self.assertTrue(report["errors"])

    def test_semgrep_partial_parse_warning_does_not_become_report_error(self):
        report = aggregate_results.normalize_report(
            "sast",
            {
                "results": [],
                "errors": [
                    {
                        "level": "warn",
                        "type": "PartialParsing",
                        "message": "Template was only partially parsed",
                    }
                ],
            },
        )

        self.assertEqual("passed", report["status"])
        self.assertEqual([], report["errors"])
        self.assertEqual(1, len(report["warnings"]))

    def test_gitleaks_array_becomes_secret_findings(self):
        report = aggregate_results.normalize_report(
            "secret_scan",
            [
                {
                    "RuleID": "generic-api-key",
                    "Description": "Generic API key",
                    "File": "settings.py",
                    "StartLine": 7,
                }
            ],
        )

        self.assertEqual("failed", report["status"])
        self.assertEqual("secret", report["findings"][0]["severity"])
        self.assertEqual("secret", report["findings"][0]["category"])
        self.assertEqual("settings.py:7", report["findings"][0]["location"])

    def test_trivy_vulnerabilities_become_policy_findings(self):
        report = aggregate_results.normalize_report(
            "dependency_scan",
            {
                "SchemaVersion": 2,
                "Results": [
                    {
                        "Target": "package-lock.json",
                        "Vulnerabilities": [
                            {
                                "VulnerabilityID": "CVE-2026-0001",
                                "PkgName": "example",
                                "InstalledVersion": "1.0.0",
                                "FixedVersion": "1.0.1",
                                "Severity": "CRITICAL",
                                "Title": "Example vulnerability",
                            }
                        ],
                    }
                ],
            },
        )

        self.assertEqual("failed", report["status"])
        self.assertEqual("critical", report["findings"][0]["severity"])
        self.assertEqual("vuln", report["findings"][0]["category"])
        self.assertEqual(
            "package-lock.json:example",
            report["findings"][0]["location"],
        )

    def test_runtime_misconfig_findings_become_warning_status(self):
        report = aggregate_results.normalize_report(
            "runtime_validation",
            {
                "status": "failed",
                "tool": "runtime-validation",
                "findings": [
                    {
                        "id": "runtime.headers.missing.x-frame-options",
                        "severity": "medium",
                        "title": "Missing security header: x-frame-options",
                        "location": "http://example.test",
                    }
                ],
            },
        )

        self.assertEqual("warning", report["status"])
        self.assertEqual("misconfig", report["findings"][0]["category"])

    def test_dependency_track_upload_must_succeed(self):
        succeeded = aggregate_results.normalize_report(
            "dependency_track",
            {"status": "succeeded", "reason": "bom-received"},
        )
        failed = aggregate_results.normalize_report(
            "dependency_track",
            {"status": "failed", "reason": "network-error"},
        )

        self.assertEqual("passed", succeeded["status"])
        self.assertEqual("error", failed["status"])
        self.assertTrue(failed["errors"])

    def test_unsupported_schema_is_a_report_error(self):
        report = aggregate_results.normalize_report("sast", {"unexpected": []})

        self.assertEqual("error", report["status"])
        self.assertTrue(report["errors"])


class TechnicalFailurePolicyTests(unittest.TestCase):
    def test_missing_or_invalid_report_blocks_gate(self):
        decision = evaluate_gate.evaluate(
            {
                "has_error": True,
                "has_critical": False,
                "has_high": False,
                "has_secret": False,
                "has_medium": False,
                "total_findings": 0,
                "reports": {},
            },
            {
                "blockOnSecret": True,
                "blockOnScannerError": True,
                "blockOnAvailability": True,
                "blockOnVulnCritical": True,
                "blockOnVulnHigh": True,
                "warnOnMedium": True,
                "warnOnMisconfig": True,
            },
        )

        self.assertTrue(decision["blocked"])
        self.assertEqual("FAILED", decision["gate_status"])


class PolicyProfileTests(unittest.TestCase):
    def setUp(self):
        self.policy = {
            "version": 2,
            "defaultProfile": "pr",
            "profiles": {
                "pr": {
                    "blockOnSecret": True,
                    "blockOnScannerError": True,
                    "blockOnAvailability": True,
                    "blockOnVulnCritical": True,
                    "blockOnVulnHigh": True,
                    "warnOnMedium": True,
                    "warnOnMisconfig": True,
                    "unknownSeverity": "block",
                },
                "training": {
                    "blockOnSecret": True,
                    "blockOnScannerError": True,
                    "blockOnAvailability": False,
                    "blockOnVulnCritical": False,
                    "blockOnVulnHigh": False,
                    "warnOnVulnCritical": True,
                    "warnOnVulnHigh": True,
                    "warnOnAvailability": True,
                    "warnOnMedium": True,
                    "warnOnMisconfig": True,
                    "unknownSeverity": "warn",
                },
                "post_merge": {
                    "blockOnSecret": True,
                    "blockOnScannerError": True,
                    "blockOnAvailability": True,
                    "blockOnVulnCritical": True,
                    "blockOnVulnHigh": True,
                    "warnOnMedium": True,
                    "warnOnMisconfig": True,
                    "unknownSeverity": "block",
                },
            },
        }

    @staticmethod
    def summary_with_finding(severity, finding_id="test.finding"):
        return {
            "has_error": False,
            "has_critical": severity == "critical",
            "has_high": severity == "high",
            "has_secret": severity == "secret",
            "has_medium": severity == "medium",
            "total_findings": 1,
            "reports": {
                "runtime_validation": {
                    "status": "failed",
                    "tool": "runtime-validation",
                    "findings": [
                        {
                            "id": finding_id,
                            "severity": severity,
                            "title": "Test finding",
                            "description": "Test description",
                            "location": "/test",
                        }
                    ],
                }
            },
        }

    def test_pr_profile_blocks_high(self):
        decision = evaluate_gate.evaluate(
            self.summary_with_finding("high"),
            self.policy,
            profile_name="pr",
        )

        self.assertTrue(decision["blocked"])
        self.assertEqual("pr", decision["policy_profile"])

    def test_training_profile_warns_on_high(self):
        decision = evaluate_gate.evaluate(
            self.summary_with_finding("high"),
            self.policy,
            profile_name="training",
        )

        self.assertFalse(decision["blocked"])
        self.assertTrue(decision["warnings"])

    def test_training_profile_still_blocks_secret(self):
        decision = evaluate_gate.evaluate(
            self.summary_with_finding("secret"),
            self.policy,
            profile_name="training",
        )

        self.assertTrue(decision["blocked"])
        self.assertIn("Secret", decision["block_reasons"][0])

    def test_training_profile_still_blocks_report_errors(self):
        summary = self.summary_with_finding("medium")
        summary["has_error"] = True

        decision = evaluate_gate.evaluate(
            summary,
            self.policy,
            profile_name="training",
        )

        self.assertTrue(decision["blocked"])
        self.assertIn("보고서", decision["block_reasons"][0])

    def test_pr_profile_warns_without_blocking_on_medium(self):
        decision = evaluate_gate.evaluate(
            self.summary_with_finding("medium"),
            self.policy,
            profile_name="pr",
        )

        self.assertFalse(decision["blocked"])
        self.assertTrue(decision["warnings"])

    def test_post_merge_profile_blocks_high(self):
        decision = evaluate_gate.evaluate(
            self.summary_with_finding("high"),
            self.policy,
            profile_name="post_merge",
        )

        self.assertTrue(decision["blocked"])

    def test_post_merge_profile_is_inferred_from_reports(self):
        summary = self.summary_with_finding("medium")
        summary["reports"] = {
            "dependency_scan": {"status": "passed", "findings": []},
            "dependency_track": {"status": "passed", "findings": []},
            "runtime_validation": summary["reports"]["runtime_validation"],
        }

        decision = evaluate_gate.evaluate(summary, self.policy)

        self.assertEqual("post_merge", decision["policy_profile"])
        self.assertFalse(decision["blocked"])

    def test_active_accepted_risk_excludes_high_finding(self):
        decision = evaluate_gate.evaluate(
            self.summary_with_finding("high"),
            self.policy,
            profile_name="pr",
            accepted_risks=[
                {
                    "id": "test.finding",
                    "location": "/test",
                    "reason": "Approved test case",
                    "owner": "security-team",
                    "approved_by": "security-lead",
                    "expires_on": "2026-08-31",
                    "profiles": ["pr"],
                }
            ],
            today=date(2026, 7, 26),
        )

        self.assertFalse(decision["blocked"])
        self.assertEqual(1, len(decision["accepted_risks"]))
        self.assertEqual(0, decision["effective_findings"])

    def test_expired_accepted_risk_does_not_exclude_finding(self):
        decision = evaluate_gate.evaluate(
            self.summary_with_finding("high"),
            self.policy,
            profile_name="pr",
            accepted_risks=[
                {
                    "id": "test.finding",
                    "reason": "Expired approval",
                    "owner": "security-team",
                    "approved_by": "security-lead",
                    "expires_on": "2026-07-01",
                }
            ],
            today=date(2026, 7, 26),
        )

        self.assertTrue(decision["blocked"])
        self.assertEqual(1, len(decision["expired_risks"]))

    def test_secret_finding_cannot_be_excluded(self):
        decision = evaluate_gate.evaluate(
            self.summary_with_finding("secret", "gitleaks.secret"),
            self.policy,
            profile_name="pr",
            accepted_risks=[
                {
                    "id": "gitleaks.secret",
                    "reason": "Secret exception must be rejected",
                    "owner": "security-team",
                    "approved_by": "security-lead",
                    "expires_on": "2026-08-31",
                }
            ],
            today=date(2026, 7, 26),
        )

        self.assertTrue(decision["blocked"])
        self.assertEqual([], decision["accepted_risks"])

    def test_unknown_severity_blocks_pr(self):
        decision = evaluate_gate.evaluate(
            self.summary_with_finding("unknown"),
            self.policy,
            profile_name="pr",
        )

        self.assertTrue(decision["blocked"])
        self.assertIn("알 수 없는 severity", decision["block_reasons"][0])


if __name__ == "__main__":
    unittest.main()
