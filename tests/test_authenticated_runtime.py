import importlib.util
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
    "runtime_validation_authenticated",
    "scripts/runtime-validation.py",
)
zap_validation = load_script_module(
    "zap_validation_authenticated",
    "scripts/run-zap-validation.py",
)


class AuthenticatedCustomCheckTests(unittest.TestCase):
    def test_login_returns_session_after_marker_is_verified(self):
        opener = SimpleNamespace()
        responses = [
            (200, {}, "login response"),
            (200, {}, '<a href="/logout">로그아웃</a>'),
        ]

        with mock.patch.object(
            runtime_validation,
            "create_session_opener",
            return_value=opener,
        ):
            with mock.patch.object(
                runtime_validation,
                "request_text",
                side_effect=responses,
            ) as request_text:
                result = runtime_validation.login(
                    "https://staging.example.com",
                    "user1",
                    "password123",
                    10,
                    "/posts",
                    ["로그아웃", "/logout"],
                )

        self.assertIs(opener, result)
        self.assertEqual(2, request_text.call_count)
        self.assertEqual(
            "https://staging.example.com/posts",
            request_text.call_args_list[1].args[0],
        )

    def test_login_rejects_response_without_authenticated_marker(self):
        responses = [
            (200, {}, "invalid credentials"),
            (200, {}, '<form action="/login">로그인</form>'),
        ]

        with mock.patch.object(
            runtime_validation,
            "create_session_opener",
            return_value=SimpleNamespace(),
        ):
            with mock.patch.object(
                runtime_validation,
                "request_text",
                side_effect=responses,
            ):
                with self.assertRaises(runtime_validation.AuthenticationError):
                    runtime_validation.login(
                        "https://staging.example.com",
                        "user1",
                        "wrong-password",
                        10,
                        "/posts",
                        ["로그아웃", "/logout"],
                    )

    def test_authentication_failure_is_one_high_scanner_error(self):
        args = SimpleNamespace(
            custom_checks="admin-access,idor",
            timeout=10,
            custom_username="user1",
            custom_password="wrong-password",
            custom_login_verify_path="/posts",
            custom_logged_in_markers="로그아웃,/logout",
            custom_private_post_id="4",
            custom_sqli_payload="unused",
        )

        with mock.patch.object(
            runtime_validation,
            "login",
            side_effect=runtime_validation.AuthenticationError(
                "login verification failed"
            ),
        ):
            with mock.patch.object(
                runtime_validation,
                "check_admin_access",
            ) as check_admin:
                with mock.patch.object(
                    runtime_validation,
                    "check_idor",
                ) as check_idor:
                    findings = runtime_validation.check_custom_runtime(
                        "https://staging.example.com",
                        args,
                    )

        self.assertEqual(1, len(findings))
        self.assertEqual(
            "runtime.custom.authentication.failed",
            findings[0]["id"],
        )
        self.assertEqual("high", findings[0]["severity"])
        self.assertEqual("scanner-error", findings[0]["category"])
        check_admin.assert_not_called()
        check_idor.assert_not_called()

    def test_authenticated_checks_share_one_verified_session(self):
        opener = SimpleNamespace()
        args = SimpleNamespace(
            custom_checks="admin-access,idor",
            timeout=10,
            custom_username="user1",
            custom_password="password123",
            custom_login_verify_path="/posts",
            custom_logged_in_markers="로그아웃,/logout",
            custom_private_post_id="4",
            custom_sqli_payload="unused",
        )

        with mock.patch.object(
            runtime_validation,
            "login",
            return_value=opener,
        ) as login:
            with mock.patch.object(
                runtime_validation,
                "check_admin_access",
                return_value=[],
            ) as check_admin:
                with mock.patch.object(
                    runtime_validation,
                    "check_idor",
                    return_value=[],
                ) as check_idor:
                    findings = runtime_validation.check_custom_runtime(
                        "https://staging.example.com",
                        args,
                    )

        self.assertEqual([], findings)
        login.assert_called_once()
        self.assertIs(opener, check_admin.call_args.args[-1])
        self.assertIs(opener, check_idor.call_args.args[-1])


class AuthenticatedZapPlanTests(unittest.TestCase):
    def make_args(self, auth_plan):
        return SimpleNamespace(
            profile="post-merge",
            scanner="zap-full-scan.py",
            target_url="https://staging.example.com/posts",
            zap_image="zap:test",
            docker_network="none",
            spider_minutes=5,
            passive_wait_minutes=10,
            scan_timeout=30 * 60,
            ajax_spider=True,
            auth_plan=auth_plan,
            auth_context_url="https://staging.example.com",
            auth_username="user1",
            auth_password="password123",
        )

    def test_authenticated_command_uses_environment_names_not_secret_values(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            reports_dir = Path(temporary_directory)
            plan = reports_dir / "source-plan.yaml"
            plan.write_text("env: {}\njobs: []\n", encoding="utf-8")
            args = self.make_args(plan)

            command = zap_validation.build_zap_command(
                args,
                reports_dir,
                "zap-container",
                auth_plan_path=plan,
            )
            environment = zap_validation.build_zap_environment(args)

        self.assertIn("zap.sh", command)
        self.assertIn("-autorun", command)
        self.assertIn(f"{plan.resolve()}:/zap/auth-plan.yaml:ro", command)
        self.assertIn("ZAP_AUTH_PASSWORD", command)
        self.assertNotIn("password123", command)
        self.assertEqual("password123", environment["ZAP_AUTH_PASSWORD"])
        self.assertEqual(
            "https://staging.example.com",
            environment["ZAP_CONTEXT_URL"],
        )

    def test_authenticated_plan_requires_credentials(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            plan = Path(temporary_directory) / "auth-plan.yaml"
            plan.write_text("env: {}\njobs: []\n", encoding="utf-8")
            args = self.make_args(plan)
            args.auth_password = ""

            with self.assertRaises(ValueError):
                zap_validation.validate_auth_configuration(args)

    def test_automation_warning_or_error_fails_authenticated_scan(self):
        with mock.patch.object(
            zap_validation.subprocess,
            "run",
            return_value=SimpleNamespace(returncode=2),
        ):
            with self.assertRaises(zap_validation.ZapExecutionError):
                zap_validation.run_zap(
                    ["docker", "run"],
                    timeout_seconds=10,
                    container_name="zap-container",
                    allowed_exit_codes={0},
                )

    def test_repository_plan_scans_as_authenticated_user_and_writes_json(self):
        plan = (
            REPOSITORY_ROOT
            / "security"
            / "zap"
            / "secure-gate-auth-plan.yaml"
        ).read_text(encoding="utf-8")

        self.assertIn("authentication:", plan)
        self.assertIn("sessionManagement:", plan)
        self.assertGreaterEqual(plan.count("user: secure-gate-user"), 2)
        self.assertIn("template: traditional-json", plan)
        self.assertIn("reportFile: zap-report.json", plan)
        self.assertNotIn("password123", plan)


if __name__ == "__main__":
    unittest.main()
