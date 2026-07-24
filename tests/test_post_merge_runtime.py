import importlib.util
import json
import stat
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
    "runtime_validation_post_merge",
    "scripts/runtime-validation.py",
)
nuclei_validation = load_script_module(
    "nuclei_validation_post_merge",
    "scripts/run-nuclei-validation.py",
)
zap_validation = load_script_module(
    "zap_validation_post_merge",
    "scripts/run-zap-validation.py",
)


def profile_args(profile):
    return SimpleNamespace(
        profile=profile,
        docker_network=None,
        severities=None,
        tags=None,
        rate_limit=None,
        concurrency=None,
        bulk_size=None,
        retries=None,
        request_timeout=None,
        scan_timeout=None,
        template_list_timeout=None,
        enable_interactsh=None,
        show_stats=None,
        require_trivy_report=None,
    )


def zap_profile_args(profile):
    return SimpleNamespace(
        profile=profile,
        scanner=None,
        docker_network=None,
        spider_minutes=None,
        passive_wait_minutes=None,
        scan_timeout=None,
        ajax_spider=None,
    )


class NucleiProfileTests(unittest.TestCase):
    def test_pr_profile_keeps_bounded_defaults(self):
        args = nuclei_validation.apply_profile_defaults(profile_args("pr"))

        self.assertEqual("medium,high,critical", args.severities)
        self.assertEqual("xss", args.tags)
        self.assertEqual("host", args.docker_network)
        self.assertEqual(5 * 60, args.scan_timeout)
        self.assertFalse(args.enable_interactsh)
        self.assertTrue(args.require_trivy_report)

    def test_post_merge_profile_uses_broad_defaults(self):
        args = nuclei_validation.apply_profile_defaults(profile_args("post-merge"))

        self.assertEqual("low,medium,high,critical", args.severities)
        self.assertEqual("none", args.tags)
        self.assertEqual("none", args.docker_network)
        self.assertEqual(30 * 60, args.scan_timeout)
        self.assertEqual(20, args.rate_limit)
        self.assertEqual(10, args.concurrency)
        self.assertTrue(args.enable_interactsh)
        self.assertFalse(args.require_trivy_report)

        args.target_url = "https://staging.example.com"
        arguments = nuclei_validation.build_baseline_arguments(args)

        self.assertNotIn("-tags", arguments)
        self.assertNotIn("-ni", arguments)
        self.assertIn("-stats", arguments)
        self.assertIn("-bulk-size", arguments)

    def test_post_merge_cli_resolves_profile_defaults(self):
        argv = [
            "run-nuclei-validation.py",
            "--profile",
            "post-merge",
            "--target-url",
            "https://staging.example.com/posts",
        ]
        with mock.patch.object(nuclei_validation.sys, "argv", argv):
            with mock.patch.dict(nuclei_validation.os.environ, {}, clear=True):
                args = nuclei_validation.parse_args()

        self.assertEqual("none", args.tags)
        self.assertEqual("none", args.docker_network)
        self.assertEqual(30 * 60, args.scan_timeout)


class ZapProfileTests(unittest.TestCase):
    def test_reports_directory_is_writable_by_zap_container_user(self):
        with tempfile.TemporaryDirectory() as temp_directory:
            reports_dir = Path(temp_directory) / "reports"

            zap_validation.prepare_reports_directory(reports_dir)

            mode = stat.S_IMODE(reports_dir.stat().st_mode)
            self.assertTrue(mode & stat.S_IWOTH)

    def test_pr_profile_uses_baseline_scan(self):
        args = zap_validation.apply_profile_defaults(zap_profile_args("pr"))

        self.assertEqual("zap-baseline.py", args.scanner)
        self.assertEqual("host", args.docker_network)
        self.assertEqual(10 * 60, args.scan_timeout)
        self.assertFalse(args.ajax_spider)

    def test_post_merge_profile_uses_full_scan(self):
        args = zap_validation.apply_profile_defaults(zap_profile_args("post-merge"))
        args.target_url = "https://staging.example.com/posts"
        args.zap_image = "zap:test"

        command = zap_validation.build_zap_command(
            args,
            Path("/tmp/reports"),
            "zap-container",
        )

        self.assertEqual("zap-full-scan.py", args.scanner)
        self.assertEqual(30 * 60, args.scan_timeout)
        self.assertIn("-j", command)
        self.assertNotIn("--network", command)

    def test_post_merge_cli_resolves_profile_defaults(self):
        argv = [
            "run-zap-validation.py",
            "--profile",
            "post-merge",
            "--target-url",
            "https://staging.example.com/posts",
        ]
        with mock.patch.object(zap_validation.sys, "argv", argv):
            with mock.patch.dict(zap_validation.os.environ, {}, clear=True):
                args = zap_validation.parse_args()

        self.assertEqual("zap-full-scan.py", args.scanner)
        self.assertEqual("none", args.docker_network)
        self.assertEqual(30 * 60, args.scan_timeout)

    def test_security_finding_exit_codes_do_not_fail_the_runner(self):
        for exit_code in (0, 1, 2):
            with self.subTest(exit_code=exit_code):
                with mock.patch.object(
                    zap_validation.subprocess,
                    "run",
                    return_value=SimpleNamespace(returncode=exit_code),
                ):
                    result = zap_validation.run_zap(
                        ["docker", "run"],
                        timeout_seconds=10,
                        container_name="zap-container",
                    )

                self.assertEqual(exit_code, result)

    def test_scanner_error_exit_code_fails_the_runner(self):
        with mock.patch.object(
            zap_validation.subprocess,
            "run",
            return_value=SimpleNamespace(returncode=3),
        ):
            with self.assertRaises(zap_validation.ZapExecutionError):
                zap_validation.run_zap(
                    ["docker", "run"],
                    timeout_seconds=10,
                    container_name="zap-container",
                )


class RequiredRuntimeReportTests(unittest.TestCase):
    def test_missing_required_reports_create_high_findings(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            reports_dir = Path(temporary_directory)
            args = SimpleNamespace(
                required_reports="zap,nuclei,nuclei-coverage,dynatrace",
                zap_report=reports_dir / "zap-report.json",
                nuclei_report=reports_dir / "nuclei-report.jsonl",
                nuclei_coverage=reports_dir / "nuclei-cve-coverage.json",
                dynatrace_problems=reports_dir / "dynatrace-problems.json",
            )

            findings = runtime_validation.check_required_reports(args)

        self.assertEqual(4, len(findings))
        self.assertTrue(all(finding["severity"] == "high" for finding in findings))

    def test_failed_nuclei_execution_is_high_finding(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            coverage_path = Path(temporary_directory) / "nuclei-cve-coverage.json"
            coverage_path.write_text(
                json.dumps(
                    {
                        "status": "failed",
                        "reason": "Command timed out after 1800 seconds",
                    }
                ),
                encoding="utf-8",
            )

            findings = runtime_validation.parse_nuclei_coverage(coverage_path)

        self.assertEqual(1, len(findings))
        self.assertEqual("runtime.nuclei.execution-failed", findings[0]["id"])
        self.assertEqual("high", findings[0]["severity"])


if __name__ == "__main__":
    unittest.main()
