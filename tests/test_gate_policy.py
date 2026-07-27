import importlib.util
import unittest
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


def load_script_module(name, relative_path):
    spec = importlib.util.spec_from_file_location(name, REPOSITORY_ROOT / relative_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


gate_policy = load_script_module("gate_policy", "scripts/gate_policy.py")
evaluate_gate = load_script_module("evaluate_gate_policy_tests", "scripts/evaluate-gate.py")


POLICY = {
    "blockOnSecret": True,
    "blockOnScannerError": True,
    "blockOnAvailability": True,
    "blockOnVulnCritical": True,
    "blockOnVulnHigh": True,
    "warnOnMedium": True,
    "warnOnMisconfig": True,
}


class GatePolicyClassificationTests(unittest.TestCase):
    def test_headers_and_http_only_are_misconfig(self):
        header = gate_policy.infer_category(
            {
                "id": "runtime.headers.missing.content-security-policy",
                "severity": "medium",
                "title": "Missing security header: content-security-policy",
            }
        )
        http_only = gate_policy.infer_category(
            {
                "id": "runtime.zap.10106",
                "severity": "medium",
                "title": "HTTP Only Site",
            }
        )
        self.assertEqual("misconfig", header)
        self.assertEqual("misconfig", http_only)

    def test_xss_and_cve_are_vuln(self):
        xss = gate_policy.infer_category(
            {
                "id": "runtime.custom.reflected-xss.keyword",
                "severity": "high",
                "title": "Search keyword is reflected without escaping",
            }
        )
        cve = gate_policy.infer_category(
            {
                "id": "CVE-2020-1747",
                "severity": "critical",
                "title": "PyYAML arbitrary command execution",
                "category": "vuln",
            }
        )
        self.assertEqual("vuln", xss)
        self.assertEqual("vuln", cve)

    def test_zap_xss_is_not_downgraded_by_csp_remediation_text(self):
        finding = {
            "id": "runtime.zap.40012",
            "severity": "high",
            "title": "Cross Site Scripting (Reflected)",
            "description": "Use output encoding and a Content Security Policy.",
        }

        self.assertEqual("vuln", gate_policy.infer_category(finding))
        self.assertTrue(gate_policy.should_block_finding(finding, POLICY))

    def test_misconfig_warns_but_does_not_block(self):
        finding = {
            "id": "runtime.zap.10106",
            "severity": "medium",
            "title": "HTTP Only Site",
        }
        self.assertFalse(gate_policy.should_block_finding(finding, POLICY))
        self.assertTrue(gate_policy.should_warn_finding(finding, POLICY))

    def test_high_vuln_blocks(self):
        finding = {
            "id": "runtime.custom.reflected-xss.keyword",
            "severity": "high",
            "title": "Reflected XSS",
            "category": "vuln",
        }
        self.assertTrue(gate_policy.should_block_finding(finding, POLICY))


class EvaluateGatePolicyTests(unittest.TestCase):
    def test_misconfig_only_passes_with_warnings(self):
        decision = evaluate_gate.evaluate(
            {
                "has_error": False,
                "total_findings": 2,
                "reports": {
                    "runtime_validation": {
                        "status": "warning",
                        "tool": "runtime-validation",
                        "findings": [
                            {
                                "id": "runtime.headers.missing.x-frame-options",
                                "severity": "medium",
                                "title": "Missing security header: x-frame-options",
                                "location": "http://example.test",
                            },
                            {
                                "id": "runtime.zap.10106",
                                "severity": "medium",
                                "title": "HTTP Only Site",
                                "location": "http://example.test/",
                            },
                        ],
                    }
                },
            },
            POLICY,
        )

        self.assertFalse(decision["blocked"])
        self.assertEqual("PASSED", decision["gate_status"])
        self.assertTrue(decision["warnings"])

    def test_critical_vuln_blocks(self):
        decision = evaluate_gate.evaluate(
            {
                "has_error": False,
                "total_findings": 1,
                "reports": {
                    "dependency_scan": {
                        "status": "failed",
                        "tool": "trivy",
                        "findings": [
                            {
                                "id": "CVE-2020-1747",
                                "severity": "critical",
                                "category": "vuln",
                                "title": "PyYAML RCE",
                                "location": "requirements-legacy.txt:PyYAML",
                            }
                        ],
                    }
                },
            },
            POLICY,
        )

        self.assertTrue(decision["blocked"])
        self.assertEqual("FAILED", decision["gate_status"])

    def test_suppression_allows_known_issue_until_expiry(self):
        decision = evaluate_gate.evaluate(
            {
                "has_error": False,
                "total_findings": 1,
                "reports": {
                    "dependency_scan": {
                        "status": "failed",
                        "tool": "trivy",
                        "findings": [
                            {
                                "id": "CVE-2020-1747",
                                "severity": "critical",
                                "category": "vuln",
                                "title": "PyYAML RCE",
                                "location": "requirements-legacy.txt:PyYAML",
                            }
                        ],
                    }
                },
            },
            POLICY,
            suppressions=[
                {
                    "id": "CVE-2020-1747",
                    "location_contains": "requirements-legacy.txt:PyYAML",
                    "reason": "lab fixture accepted risk",
                    "owner": "security-team",
                    "approved_by": "policy-owner",
                    "expires_on": "2099-01-01",
                }
            ],
        )

        self.assertFalse(decision["blocked"])
        self.assertEqual("PASSED", decision["gate_status"])
        self.assertEqual(1, len(decision["suppressed"]))

    def test_scanner_error_still_blocks(self):
        decision = evaluate_gate.evaluate(
            {
                "has_error": True,
                "total_findings": 0,
                "reports": {
                    "sast": {
                        "status": "error",
                        "tool": "semgrep",
                        "findings": [],
                        "errors": ["fatal scanner failure"],
                    }
                },
            },
            POLICY,
        )

        self.assertTrue(decision["blocked"])
        self.assertEqual("FAILED", decision["gate_status"])
        self.assertTrue(
            any("보안 보고서 처리 실패: sast" in reason for reason in decision["block_reasons"])
        )

    def test_missing_report_reason_is_specific(self):
        decision = evaluate_gate.evaluate(
            {
                "has_error": True,
                "total_findings": 0,
                "reports": {
                    "dependency_track": {
                        "status": "not_found",
                        "tool": "dependency-track-upload-report.json",
                        "findings": [],
                    }
                },
            },
            POLICY,
        )

        self.assertTrue(decision["blocked"])
        self.assertIn(
            "필수 보안 보고서 누락: dependency_track",
            decision["block_reasons"],
        )


if __name__ == "__main__":
    unittest.main()
