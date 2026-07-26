import importlib.util
import json
import unittest
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


def load_script_module(name, relative_path):
    spec = importlib.util.spec_from_file_location(name, REPOSITORY_ROOT / relative_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


ai_summary = load_script_module(
    "generate_ai_security_summary",
    "scripts/generate-ai-security-summary.py",
)
create_pr_comment = load_script_module(
    "create_pr_comment_for_ai_tests",
    "scripts/create-pr-comment.py",
)


class AiSecuritySummaryTests(unittest.TestCase):
    def make_decision(self):
        return {
            "gate_status": "FAILED",
            "blocked": True,
            "policy_profile": "pr",
            "block_reasons": ["High finding detected"],
            "warnings": ["Medium finding detected"],
            "severity_counts": {
                "critical": 0,
                "high": 1,
                "medium": 1,
                "low": 0,
                "secret": 1,
            },
            "total_findings": 3,
            "effective_findings": 3,
            "reports": {
                "runtime_validation": {
                    "status": "failed",
                    "warnings": ["partial coverage"],
                    "findings": [
                        {
                            "id": "runtime.test.high",
                            "severity": "high",
                            "title": "High runtime finding",
                            "description": "token=visible-value",
                            "location": "https://user:pass@example.test/login?token=abc",
                        }
                    ],
                },
                "secret_scan": {
                    "status": "failed",
                    "findings": [
                        {
                            "id": "gitleaks.generic-api-key",
                            "severity": "secret",
                            "title": "Secret detected",
                            "description": "synthetic secret fixture value",
                            "location": "settings.py:10",
                        }
                    ],
                },
            },
        }

    def test_source_payload_is_bounded_and_redacted(self):
        source = ai_summary.build_source_payload(self.make_decision(), max_findings=1)

        self.assertEqual(1, source["findings_in_prompt"])
        self.assertEqual(1, source["findings_omitted_from_prompt"])
        self.assertEqual(2, len(source["report_statuses"]))
        runtime_status = next(
            status
            for status in source["report_statuses"]
            if status["report"] == "runtime_validation"
        )
        self.assertEqual(1, runtime_status["warning_count"])
        self.assertEqual("secret", source["findings"][0]["severity"])
        self.assertNotIn("synthetic secret fixture", source["findings"][0]["description"])

    def test_legacy_decision_derives_severity_counts(self):
        decision = self.make_decision()
        decision.pop("severity_counts")

        source = ai_summary.build_source_payload(decision, max_findings=10)

        self.assertEqual(1, source["severity_counts"]["high"])
        self.assertEqual(1, source["severity_counts"]["secret"])

    def test_url_query_and_credentials_are_removed(self):
        source = ai_summary.build_source_payload(self.make_decision(), max_findings=10)
        runtime_finding = next(
            finding
            for finding in source["findings"]
            if finding["id"] == "runtime.test.high"
        )

        self.assertEqual(
            "https://example.test/login",
            runtime_finding["location"],
        )
        self.assertIn("[REDACTED]", runtime_finding["description"])

    def test_request_uses_structured_output_and_does_not_store_response(self):
        source = ai_summary.build_source_payload(self.make_decision(), max_findings=10)
        request = ai_summary.build_openai_request("test-model", source)

        self.assertFalse(request["store"])
        self.assertEqual("json_schema", request["text"]["format"]["type"])
        self.assertTrue(request["text"]["format"]["strict"])

    def test_http_error_includes_safe_api_error_code(self):
        body = json.dumps(
            {
                "error": {
                    "message": "You exceeded your current quota.",
                    "type": "insufficient_quota",
                    "code": "insufficient_quota",
                }
            }
        ).encode()

        message = ai_summary.format_openai_http_error(429, body)

        self.assertIn("HTTP 429", message)
        self.assertIn("code=insufficient_quota", message)
        self.assertIn("exceeded your current quota", message)

    def test_http_error_does_not_include_secret_assignment(self):
        body = json.dumps(
            {
                "error": {
                    "message": "token=private-value",
                    "type": "rate_limit_exceeded",
                }
            }
        ).encode()

        message = ai_summary.format_openai_http_error(429, body)

        self.assertIn("code=rate_limit_exceeded", message)
        self.assertNotIn("private-value", message)

    def test_extracts_structured_response(self):
        expected = {
            "executive_summary": "요약",
            "key_observations": ["관찰"],
            "prioritized_findings": [],
            "report_reading_guide": ["가이드"],
            "limitations": ["한계"],
        }
        response = {
            "status": "completed",
            "output": [
                {
                    "type": "message",
                    "content": [
                        {
                            "type": "output_text",
                            "text": json.dumps(expected),
                        }
                    ],
                }
            ],
        }

        self.assertEqual(expected, ai_summary.extract_analysis(response))

    def test_unknown_ai_finding_is_removed(self):
        source = ai_summary.build_source_payload(self.make_decision(), max_findings=10)
        analysis = {
            "executive_summary": "요약",
            "key_observations": [],
            "prioritized_findings": [
                {
                    "finding_id": "invented.finding",
                    "location": "/invented",
                    "risk": "위험",
                    "remediation": "수정",
                }
            ],
            "report_reading_guide": [],
            "limitations": [],
        }

        normalized = ai_summary.normalize_prioritized_findings(analysis, source)

        self.assertEqual([], normalized["prioritized_findings"])
        self.assertIn("입력에 없는 finding", normalized["limitations"][0])

    def test_markdown_keeps_authoritative_gate_separate(self):
        decision = self.make_decision()
        source = ai_summary.build_source_payload(decision, max_findings=10)
        result = ai_summary.result_payload(
            "skipped",
            "test-model",
            Path("gate-decision.json"),
            decision,
            reason="OPENAI_API_KEY is not configured",
            source_payload=source,
        )

        markdown = ai_summary.render_markdown(result)

        self.assertIn("확정 Gate 판정", markdown)
        self.assertIn("`FAILED`", markdown)
        self.assertIn("Merge/배포 판정", markdown)
        self.assertIn("입력 보고서 범위", markdown)
        self.assertIn("| runtime_validation | runtime_validation | failed | 1 | 1 | 0 |", markdown)
        self.assertEqual(
            2,
            len(result["source_coverage"]["reports"]),
        )
        self.assertEqual(
            2,
            result["source_coverage"]["findings_sent_to_ai"],
        )

    def test_pr_comment_includes_ai_remediation_when_available(self):
        analysis = {
            "executive_summary": "High 취약점 수정이 필요합니다.",
            "key_observations": [],
            "prioritized_findings": [
                {
                    "finding_id": "runtime.test.high",
                    "title": "High runtime finding",
                    "severity": "high",
                    "location": "/login",
                    "risk": "인증 우회 가능성",
                    "remediation": "입력값 검증과 파라미터 바인딩을 적용합니다.",
                }
            ],
            "report_reading_guide": [],
            "limitations": [],
        }
        ai_report = {"status": "succeeded", "analysis": analysis}

        comment = create_pr_comment.build_comment(self.make_decision(), ai_report)

        self.assertIn("AI 요약", comment)
        self.assertIn("파라미터 바인딩", comment)
        self.assertIn("최종 판정은 Gate Evaluator", comment)


if __name__ == "__main__":
    unittest.main()
