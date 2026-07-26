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


if __name__ == "__main__":
    unittest.main()
