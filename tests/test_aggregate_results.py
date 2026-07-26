import importlib.util
import unittest
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
                                "PkgIdentifier": {
                                    "PURL": "pkg:npm/example@1.0.0"
                                },
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
        self.assertEqual("pkg:npm/example@1.0.0", report["findings"][0]["purl"])
        self.assertEqual("1.0.1", report["findings"][0]["fixedVersion"])

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


if __name__ == "__main__":
    unittest.main()
