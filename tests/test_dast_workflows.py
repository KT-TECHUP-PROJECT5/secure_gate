import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def read_text(relative_path):
    return (ROOT / relative_path).read_text(encoding="utf-8")


class DastWorkflowTests(unittest.TestCase):
    def test_post_merge_nuclei_runs_broad_scan_without_trivy_input(self):
        workflow = read_text(".github/workflows/post-merge-security-gate.yml")
        nuclei_step = workflow.split(
            "- name: Run Nuclei post-merge validation", 1
        )[1].split("- name: Fetch Dynatrace runtime results", 1)[0]

        self.assertIn("--profile post-merge", nuclei_step)
        self.assertIn("steps.runtime-target.outputs.scan_url", nuclei_step)
        self.assertNotIn("--trivy-report", nuclei_step)
        self.assertNotIn("dependency-report", nuclei_step)

    def test_post_merge_workflow_maps_authenticated_runtime_secrets(self):
        workflow = read_text(".github/workflows/post-merge-security-gate.yml")

        self.assertIn("ZAP_AUTH_PASSWORD:", workflow)
        self.assertIn("CUSTOM_RUNTIME_PASSWORD:", workflow)
        self.assertIn("inputs.zap_auth_plan", workflow)
        self.assertIn("inputs.zap_auth_username", workflow)
        self.assertIn("inputs.custom_username", workflow)
        self.assertIn("steps.runtime-target.outputs.scan_url", workflow)

    def test_zap_auth_context_starts_at_scan_target_without_root_request(self):
        plan = read_text("security/zap/secure-gate-auth-plan.yaml")

        self.assertIn("- ${ZAP_TARGET_URL}", plan)
        self.assertIn("includePaths:", plan)
        self.assertIn("- ${ZAP_CONTEXT_URL}/.*", plan)
        self.assertIn("loginPageUrl: ${ZAP_CONTEXT_URL}/login", plan)

    def test_pr_workflow_uses_scan_path_and_keeps_pr_trivy_targeting(self):
        workflow = read_text(".github/workflows/pr-security-gate.yml")

        self.assertIn("dast_scan_path:", workflow)
        self.assertIn("steps.dast-target.outputs.scan_url", workflow)
        self.assertIn(
            "--trivy-report security/reports/dependency-report.json",
            workflow,
        )

    def test_staging_caller_maps_secure_gate_authentication(self):
        workflow = read_text(".github/workflows/cd-staging.yml")

        self.assertIn("scan_path: /posts", workflow)
        self.assertIn(
            "zap_auth_plan: .secure-gate/security/zap/secure-gate-auth-plan.yaml",
            workflow,
        )
        self.assertIn(
            "ZAP_AUTH_PASSWORD: ${{ secrets.ZAP_AUTH_PASSWORD }}",
            workflow,
        )
        self.assertIn(
            "CUSTOM_RUNTIME_PASSWORD: ${{ secrets.CUSTOM_RUNTIME_PASSWORD }}",
            workflow,
        )

    def test_pr_workflow_generates_and_publishes_non_blocking_ai_report(self):
        workflow = read_text(".github/workflows/pr-security-gate.yml")
        ai_step = workflow.split(
            "- name: Generate AI security summary", 1
        )[1].split("- name: Upload gate results", 1)[0]

        self.assertIn("OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}", ai_step)
        self.assertIn("generate-ai-security-summary.py", ai_step)
        self.assertIn("if: always()", ai_step)
        self.assertIn("continue-on-error: true", ai_step)
        self.assertIn("timeout-minutes: 3", ai_step)
        self.assertIn("security/reports/ai-security-summary.json", workflow)
        self.assertIn("security/reports/ai-security-summary.md", workflow)

    def test_post_merge_workflow_generates_and_publishes_ai_report(self):
        workflow = read_text(".github/workflows/post-merge-security-gate.yml")
        ai_step = workflow.split(
            "- name: Generate post-merge AI security summary", 1
        )[1].split("- name: Upload post-merge gate results", 1)[0]

        self.assertIn("OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}", ai_step)
        self.assertIn("generate-ai-security-summary.py", ai_step)
        self.assertIn("if: always()", ai_step)
        self.assertIn("continue-on-error: true", ai_step)
        self.assertIn("timeout-minutes: 3", ai_step)
        self.assertIn("security/reports/ai-security-summary.json", workflow)
        self.assertIn("security/reports/ai-security-summary.md", workflow)

    def test_callers_pass_optional_openai_secret(self):
        caller_files = (
            ".github/workflows/call-pr-security-gate.yml",
            ".github/workflows/cd-staging.yml",
            "examples/caller-security-gate.yml",
            "examples/caller-post-merge-security-gate.yml",
        )

        for caller_file in caller_files:
            with self.subTest(caller_file=caller_file):
                workflow = read_text(caller_file)
                self.assertIn(
                    "OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}",
                    workflow,
                )

    def test_callers_pass_optional_discord_secret(self):
        caller_files = (
            ".github/workflows/call-pr-security-gate.yml",
            ".github/workflows/cd-staging.yml",
            "examples/caller-security-gate.yml",
            "examples/caller-post-merge-security-gate.yml",
        )

        for caller_file in caller_files:
            with self.subTest(caller_file=caller_file):
                workflow = read_text(caller_file)
                self.assertIn(
                    "DISCORD_WEBHOOK_URL: ${{ secrets.DISCORD_WEBHOOK_URL }}",
                    workflow,
                )


if __name__ == "__main__":
    unittest.main()
