import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


def load_script_module(name, relative_path):
    spec = importlib.util.spec_from_file_location(name, REPOSITORY_ROOT / relative_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


runtime_validation = load_script_module(
    "runtime_validation",
    "scripts/runtime-validation.py",
)
fetch_dynatrace = load_script_module(
    "fetch_dynatrace",
    "scripts/fetch-dynatrace-problems.py",
)


class DynatraceRuntimeReportTests(unittest.TestCase):
    def write_report(self, report):
        temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(temporary_directory.cleanup)
        report_path = Path(temporary_directory.name) / "dynatrace-problems.json"
        report_path.write_text(json.dumps(report), encoding="utf-8")
        return report_path

    def test_missing_service_is_high_finding(self):
        report_path = self.write_report(
            {
                "problems": [],
                "warnings": [],
                "serviceCoverage": {
                    "status": "not_detected",
                    "totalCount": 0,
                    "from": "now-30m",
                    "services": [],
                },
            }
        )

        findings = runtime_validation.parse_dynatrace_problems(report_path)

        self.assertEqual(1, len(findings))
        self.assertEqual("runtime.dynatrace.service-not-detected", findings[0]["id"])
        self.assertEqual("high", findings[0]["severity"])

    def test_detected_service_does_not_create_coverage_finding(self):
        report_path = self.write_report(
            {
                "problems": [],
                "warnings": [],
                "serviceCoverage": {
                    "status": "detected",
                    "totalCount": 1,
                    "from": "now-30m",
                    "services": [
                        {
                            "entityId": "SERVICE-123",
                            "displayName": "secure-gate",
                        }
                    ],
                },
            }
        )

        findings = runtime_validation.parse_dynatrace_problems(report_path)

        self.assertEqual([], findings)

    def test_legacy_report_without_coverage_remains_supported(self):
        report_path = self.write_report({"problems": [], "warnings": []})

        findings = runtime_validation.parse_dynatrace_problems(report_path)

        self.assertEqual([], findings)


class DynatraceServiceCoverageTests(unittest.TestCase):
    def make_args(self):
        return SimpleNamespace(
            environment_url="https://example.live.dynatrace.com",
            service_entity_selector='type("SERVICE")',
            from_time="now-30m",
            to_time="",
            page_size=500,
            timeout=20,
        )

    def test_service_entity_is_recorded(self):
        api_response = {
            "entities": [
                {
                    "entityId": "SERVICE-123",
                    "displayName": "secure-gate",
                    "firstSeenTms": 1,
                    "lastSeenTms": 2,
                }
            ]
        }

        with mock.patch.object(
            fetch_dynatrace,
            "read_json_response",
            return_value=api_response,
        ):
            coverage = fetch_dynatrace.fetch_service_coverage(self.make_args(), "token")

        self.assertEqual("detected", coverage["status"])
        self.assertEqual(1, coverage["totalCount"])
        self.assertEqual("secure-gate", coverage["services"][0]["displayName"])

    def test_empty_entity_response_is_not_detected(self):
        with mock.patch.object(
            fetch_dynatrace,
            "read_json_response",
            return_value={"entities": []},
        ):
            coverage = fetch_dynatrace.fetch_service_coverage(self.make_args(), "token")

        self.assertEqual("not_detected", coverage["status"])
        self.assertEqual(0, coverage["totalCount"])


if __name__ == "__main__":
    unittest.main()
