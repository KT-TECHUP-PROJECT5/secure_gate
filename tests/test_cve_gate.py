#!/usr/bin/env python3
"""Category gate + CVE correction layer tests (stdlib unittest)."""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
EG_PATH = REPO / "scripts" / "evaluate-gate.py"
REAL_POLICY = REPO / "security" / "policies" / "security-gate-policy.json"


def load_module(name: str, relative: str):
    spec = importlib.util.spec_from_file_location(name, REPO / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


cve_track = load_module("cve_track_under_test", "scripts/cve_track.py")
severity = load_module("severity_under_test", "scripts/severity.py")
paths = load_module("paths_under_test", "scripts/paths.py")


def trivy_finding(
    cve: str,
    *,
    pkg: str = "pkg",
    ver: str = "1.0.0",
    severity: str = "high",
    fixed: str | None = None,
    purl: str | None = None,
) -> dict:
    finding = {
        "id": cve,
        "severity": severity,
        "category": "vuln",
        "title": cve,
        "description": f"{pkg}@{ver}",
        "location": f"requirements.txt:{pkg}",
        "purl": purl or f"pkg:pypi/{pkg}@{ver}",
    }
    if fixed:
        finding["fixedVersion"] = fixed
    return finding


def cve_decision(entries: list[dict]) -> dict:
    cves = []
    for entry in entries:
        cves.append(
            {
                "cve": entry["cve"],
                "verdict": entry.get("verdict", "warn"),
                "evidence": {
                    "kev": entry["kev"],
                    "epss": entry["epss"],
                    "severity": entry["severity"],
                },
                "packages": [
                    {
                        "name": entry.get("pkg", "pkg"),
                        "version": entry.get("ver", "1.0.0"),
                        "purl": entry["purl"],
                        "fixed_versions": entry.get("fixed_versions", []),
                    }
                ],
            }
        )
    return {
        "policy_version": "1.1.0",
        "total_cves": len(entries),
        "block_count": sum(1 for entry in entries if entry.get("verdict") == "block"),
        "warn_count": sum(1 for entry in entries if entry.get("verdict") == "warn"),
        "package_failures": [],
        "cves": cves,
    }


def base_policy(**overrides) -> dict:
    policy = json.loads(REAL_POLICY.read_text(encoding="utf-8"))
    track = policy.setdefault("cveTrack", {})
    track["enabled"] = overrides.get("enabled", "monitor")
    adjustment = track.setdefault("adjustment", {})
    adjustment["annotateOnly"] = overrides.get("annotateOnly", True)
    if "demote_enabled" in overrides:
        adjustment.setdefault("demote", {})["enabled"] = overrides["demote_enabled"]
    if "onTrackFailure" in overrides:
        track["onTrackFailure"] = overrides["onTrackFailure"]
    return policy


def summary_with_deps(findings: list[dict], *, sast_high: bool = False) -> dict:
    reports = {
        "dependency_scan": {
            "status": "failed" if findings else "passed",
            "tool": "trivy",
            "findings": findings,
        }
    }
    if sast_high:
        reports["sast"] = {
            "status": "failed",
            "tool": "semgrep",
            "findings": [
                {
                    "id": "python.security.sqli",
                    "severity": "high",
                    "category": "vuln",
                    "title": "SQL injection",
                    "location": "app.py:1",
                }
            ],
        }
    return {
        "reports": reports,
        "total_findings": sum(len(report.get("findings") or []) for report in reports.values()),
        "has_error": False,
    }


def run_gate(*, policy: dict, summary: dict, decision: dict | None = None, sbom: bool = False):
    with tempfile.TemporaryDirectory() as temp_dir:
        root = Path(temp_dir)
        reports = root / "security" / "reports"
        reports.mkdir(parents=True)
        (reports / "security-summary.json").write_text(
            json.dumps(summary), encoding="utf-8"
        )
        policy_path = root / "policy.json"
        policy_path.write_text(json.dumps(policy), encoding="utf-8")
        if decision is not None:
            (reports / "cve-policy-decision.json").write_text(
                json.dumps(decision), encoding="utf-8"
            )
        if sbom:
            (reports / "sbom.cdx.json").write_text(
                json.dumps(
                    {
                        "bomFormat": "CycloneDX",
                        "specVersion": "1.6",
                        "components": [],
                    }
                ),
                encoding="utf-8",
            )

        env = dict(os.environ)
        env["SECURE_GATE_POLICY"] = str(policy_path)
        env.pop("CVE_TRACK_BYPASS", None)
        completed = subprocess.run(
            [sys.executable, str(EG_PATH)],
            cwd=root,
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )
        decision_path = reports / "gate-decision.json"
        payload = (
            json.loads(decision_path.read_text(encoding="utf-8"))
            if decision_path.exists()
            else {}
        )
        return completed.returncode, payload, completed.stderr


class CveTrackUnitTests(unittest.TestCase):
    def test_is_cve_adjustable_only_for_dependency_cves(self):
        self.assertTrue(
            cve_track.is_cve_adjustable_finding(
                trivy_finding("CVE-2024-1"),
                report_key="dependency_scan",
                tool="trivy",
            )
        )
        self.assertFalse(
            cve_track.is_cve_adjustable_finding(
                {
                    "id": "python.security.sqli",
                    "severity": "high",
                    "category": "vuln",
                },
                report_key="sast",
                tool="semgrep",
            )
        )
        self.assertFalse(
            cve_track.is_cve_adjustable_finding(
                {
                    "id": "gitleaks.secret",
                    "severity": "secret",
                    "category": "secret",
                },
                report_key="secret_scan",
                tool="gitleaks",
            )
        )

    def test_promote_kev_medium(self):
        finding = cve_track.annotate_verdicts(
            trivy_finding("CVE-2024-KEV", severity="medium"),
            base_policy(),
        )
        action, _, target = cve_track._decide_adjustment(
            finding,
            {"kev": True, "epss": 0.01, "severity": "medium"},
            base_policy()["cveTrack"]["adjustment"],
        )
        self.assertEqual("promote", action)
        self.assertEqual("block", target)

    def test_demote_high_low_epss_no_fix(self):
        finding = cve_track.annotate_verdicts(
            trivy_finding("CVE-2024-LOW", severity="high"),
            base_policy(),
        )
        action, _, target = cve_track._decide_adjustment(
            finding,
            {"kev": False, "epss": 0.01, "severity": "high"},
            base_policy()["cveTrack"]["adjustment"],
        )
        self.assertEqual("demote", action)
        self.assertEqual("warn", target)

    def test_critical_guard_blocks_demote(self):
        finding = cve_track.annotate_verdicts(
            trivy_finding("CVE-2024-CRIT", severity="critical"),
            base_policy(),
        )
        action, _, _ = cve_track._decide_adjustment(
            finding,
            {"kev": False, "epss": 0.01, "severity": "critical"},
            base_policy()["cveTrack"]["adjustment"],
        )
        self.assertEqual("keep", action)

    def test_fix_available_not_demoted(self):
        finding = cve_track.annotate_verdicts(
            trivy_finding("CVE-2024-FIX", severity="high", fixed="2.0.0"),
            base_policy(),
        )
        action, _, _ = cve_track._decide_adjustment(
            finding,
            {"kev": False, "epss": 0.01, "severity": "high"},
            base_policy()["cveTrack"]["adjustment"],
        )
        self.assertEqual("keep", action)


class CveGateIntegrationTests(unittest.TestCase):
    def test_monitor_annotate_only_keeps_category_block(self):
        finding = trivy_finding(
            "CVE-2024-0001",
            severity="high",
            purl="pkg:pypi/pkg@1.0.0",
        )
        rc, decision, _ = run_gate(
            policy=base_policy(enabled="monitor", annotateOnly=True),
            summary=summary_with_deps([finding]),
            decision=cve_decision(
                [
                    {
                        "cve": "CVE-2024-0001",
                        "purl": "pkg:pypi/pkg@1.0.0",
                        "kev": False,
                        "epss": 0.01,
                        "severity": "high",
                        "verdict": "warn",
                    }
                ]
            ),
        )
        self.assertEqual(1, rc)
        self.assertTrue(decision["blocked"])
        self.assertEqual("monitor", decision["cve_track"]["mode"])
        self.assertTrue(decision["cve_track"]["annotate_only"])
        self.assertEqual(1, decision["cve_track"]["demoted"])
        self.assertEqual(0, decision["cve_track"]["applied"])
        self.assertTrue(
            any("미반영" in warning for warning in decision["warnings"])
        )

    def test_enforce_demote_unblocks_when_applied(self):
        finding = trivy_finding(
            "CVE-2024-0002",
            severity="high",
            purl="pkg:pypi/pkg@1.0.0",
        )
        rc, decision, _ = run_gate(
            policy=base_policy(enabled="enforce", annotateOnly=False),
            summary=summary_with_deps([finding]),
            decision=cve_decision(
                [
                    {
                        "cve": "CVE-2024-0002",
                        "purl": "pkg:pypi/pkg@1.0.0",
                        "kev": False,
                        "epss": 0.01,
                        "severity": "high",
                        "verdict": "warn",
                    }
                ]
            ),
        )
        self.assertEqual(0, rc)
        self.assertFalse(decision["blocked"])
        self.assertEqual(1, decision["cve_track"]["demoted"])
        self.assertEqual(1, decision["cve_track"]["applied"])

    def test_enforce_promote_blocks_medium_kev(self):
        finding = trivy_finding(
            "CVE-2024-0003",
            severity="medium",
            purl="pkg:pypi/pkg@1.0.0",
        )
        rc, decision, _ = run_gate(
            policy=base_policy(enabled="enforce", annotateOnly=False),
            summary=summary_with_deps([finding]),
            decision=cve_decision(
                [
                    {
                        "cve": "CVE-2024-0003",
                        "purl": "pkg:pypi/pkg@1.0.0",
                        "kev": True,
                        "epss": 0.9,
                        "severity": "medium",
                        "verdict": "block",
                    }
                ]
            ),
        )
        self.assertEqual(1, rc)
        self.assertTrue(decision["blocked"])
        self.assertEqual(1, decision["cve_track"]["promoted"])
        self.assertEqual(1, decision["cve_track"]["applied"])

    def test_sast_findings_are_not_adjusted(self):
        rc, decision, _ = run_gate(
            policy=base_policy(enabled="enforce", annotateOnly=False),
            summary=summary_with_deps([], sast_high=True),
            decision=cve_decision([]),
        )
        self.assertEqual(1, rc)
        self.assertTrue(decision["blocked"])
        self.assertEqual([], decision.get("cve_adjustments") or [])

    def test_monitor_track_failure_is_warning_only(self):
        rc, decision, _ = run_gate(
            policy=base_policy(enabled="monitor", annotateOnly=True),
            summary=summary_with_deps([]),
            decision=None,
            sbom=False,
        )
        self.assertEqual(0, rc)
        self.assertFalse(decision["blocked"])
        self.assertEqual("failed", decision["cve_track"]["source"])
        self.assertTrue(
            any("CVE 검증 미수행" in warning for warning in decision["warnings"])
        )

    def test_cve_track_off_skips_layer(self):
        finding = trivy_finding("CVE-2024-0004", severity="high")
        policy = base_policy()
        policy["cveTrack"]["enabled"] = "off"
        rc, decision, _ = run_gate(
            policy=policy,
            summary=summary_with_deps([finding]),
            decision=None,
        )
        self.assertEqual(1, rc)
        self.assertEqual("off", decision["cve_track"]["mode"])


class SeverityAndPathTests(unittest.TestCase):
    def test_severity_rank_excludes_secret(self):
        self.assertNotIn("secret", severity.SEVERITY_RANK)

    def test_resolve_report_prefers_reports_dir(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            reports = root / "security" / "reports"
            reports.mkdir(parents=True)
            target = reports / "gate-decision.json"
            target.write_text("{}", encoding="utf-8")
            (root / "gate-decision.json").write_text("{}", encoding="utf-8")
            resolved = paths.resolve_report(
                "gate-decision.json",
                reports_dir=str(reports),
                search_root=str(root),
                log=False,
            )
            self.assertEqual(target.resolve(), resolved.resolve())


if __name__ == "__main__":
    unittest.main()
