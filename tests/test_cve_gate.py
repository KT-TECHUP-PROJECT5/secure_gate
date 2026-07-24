#!/usr/bin/env python3
"""CVE 트랙 통합 게이트 검증 (stdlib unittest, 무의존성).

이 테스트들은 검증이자 정책 명세다. 각 test 의 docstring 한 줄이 "무엇을
검증하는지"를 규정한다. evaluate-gate.py 를 reusable workflow 경로 모델대로
(SECURE_GATE_POLICY env + 툴링 스키마) 실제 서브프로세스로 실행한다.

실행: python -m unittest tests.test_cve_gate    (repo 루트에서)
"""

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
PC_PATH = REPO / "scripts" / "create-pr-comment.py"
REAL_POLICY = REPO / "security" / "policies" / "security-gate-policy.json"
FIXTURES = REPO / "tests" / "fixtures" / "cve-gate"


# ── 입력 빌더 ──────────────────────────────────────────────────────
def trivy_raw(vulns):
    """vulns: list of (cve, pkg, version, severity, fixed_or_None) → raw Trivy dict."""
    out = []
    for cve, pkg, ver, sev, fixed in vulns:
        v = {
            "VulnerabilityID": cve, "PkgName": pkg, "InstalledVersion": ver,
            "Severity": sev, "PkgIdentifier": {"PURL": f"pkg:pypi/{pkg}@{ver}"},
            "Title": cve,
        }
        if fixed:
            v["FixedVersion"] = fixed
        out.append(v)
    return {"SchemaVersion": 2, "Results": [
        {"Target": "requirements.txt", "Class": "lang-pkgs", "Type": "pip", "Vulnerabilities": out}
    ]}


def cve_decision(entries):
    """entries: list of dict(cve, purl, kev, epss, severity, verdict) → decision dict."""
    cves = [{
        "cve": e["cve"], "verdict": e.get("verdict", "warn"),
        "evidence": {"kev": e["kev"], "epss": e["epss"], "severity": e["severity"]},
        "packages": [{"name": e.get("pkg", "p"), "version": e.get("ver", "1"),
                      "purl": e["purl"], "fixed_versions": e.get("fixed_versions", [])}],
    } for e in entries]
    block = sum(1 for e in entries if e.get("verdict") == "block")
    warn = sum(1 for e in entries if e.get("verdict") == "warn")
    return {"policy_version": "1.1.0", "total_cves": len(entries),
            "block_count": block, "warn_count": warn, "package_failures": [], "cves": cves}


def summary(dep_raw_in_file=False, sast_block=False):
    reports = {}
    reports["sast"] = {"tool": "semgrep", "status": "passed",
                       "findings": ([{"id": "S1", "severity": "ERROR", "title": "SQLi",
                                      "location": "a.py:1"}] if sast_block else [])}
    # dependency_scan 은 findings 비움 → evaluate 가 dependency-report.json(raw)을 정규화
    reports["dependency_scan"] = {"tool": "trivy", "findings": []}
    return {"reports": reports, "total_findings": 0}


def policy(**overrides):
    """실 정책을 로드해 per-test 오버라이드 적용."""
    p = json.loads(REAL_POLICY.read_text())
    p["cveTrack"]["enabled"] = overrides.get("enabled", "enforce")
    p["cveTrack"]["adjustment"]["annotateOnly"] = overrides.get("annotateOnly", False)
    return p


def run_gate(*, pol, summ, dep_raw=None, dep_raw_text=None, decision=None,
             sbom=False, env_extra=None, return_stderr=False):
    """임시 caller cwd 구성 후 evaluate-gate.py 실행.
    기본 반환 (rc, decision_json). return_stderr=True 면 (rc, decision_json, stderr).
    dep_raw_text 는 손상 JSON 등 리터럴 문자열을 그대로 쓸 때 사용한다."""
    with tempfile.TemporaryDirectory() as d:
        tmp = Path(d)
        (tmp / "security" / "reports").mkdir(parents=True)
        (tmp / "security" / "reports" / "security-summary.json").write_text(json.dumps(summ))
        pol_path = tmp / "policy.json"
        pol_path.write_text(json.dumps(pol))
        dep_path = tmp / "security" / "reports" / "dependency-report.json"
        if dep_raw_text is not None:
            dep_path.write_text(dep_raw_text)
        elif dep_raw is not None:
            dep_path.write_text(json.dumps(dep_raw))
        if decision is not None:
            (tmp / "security" / "reports" / "cve-policy-decision.json").write_text(json.dumps(decision))
        if sbom:
            (tmp / "security" / "reports" / "sbom.cdx.json").write_text(
                json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.6", "components": []}))
        env = dict(os.environ)
        env["SECURE_GATE_POLICY"] = str(pol_path)
        if env_extra:
            env.update(env_extra)
        proc = subprocess.run([sys.executable, str(EG_PATH)], cwd=tmp, env=env,
                              capture_output=True, text=True)
        dec = json.loads((tmp / "security" / "reports" / "gate-decision.json").read_text())
        if return_stderr:
            return proc.returncode, dec, proc.stderr
        return proc.returncode, dec


class CveGateTests(unittest.TestCase):

    def test_01_gate_pass_cve_dep_block(self):
        """(1) SAST 통과 + 의존성 CRITICAL(강등 불가) → 차단."""
        rc, dec = run_gate(
            pol=policy(),
            summ=summary(),
            dep_raw=trivy_raw([("CVE-A", "pyyaml", "5.3", "CRITICAL", None)]),
            decision=cve_decision([{"cve": "CVE-A", "purl": "pkg:pypi/pyyaml@5.3",
                                    "kev": False, "epss": 0.5, "severity": "CRITICAL", "verdict": "block"}]),
        )
        self.assertTrue(dec["blocked"]); self.assertEqual(rc, 1)

    def test_02_gate_fail_cve_pass(self):
        """(2) SAST high 차단 + 의존성 없음/통과 → SAST 로 차단."""
        rc, dec = run_gate(
            pol=policy(), summ=summary(sast_block=True),
            decision=cve_decision([]),
        )
        self.assertTrue(dec["blocked"]); self.assertEqual(rc, 1)

    def test_03a_track_scripterror_failclosed(self):
        """(3-scriptError) SBOM 있음 + 트랙 산출 없음 → failClosed 차단."""
        rc, dec = run_gate(pol=policy(), summ=summary(), sbom=True)
        self.assertEqual(dec["cve_track"]["failure_type"], "scriptError")
        self.assertTrue(dec["blocked"]); self.assertEqual(rc, 1)

    def test_03b_track_dataunavailable_failopen(self):
        """(3-dataUnavailable) SBOM 없음 → failOpen, 미차단 + 필수 경고 2건."""
        rc, dec = run_gate(pol=policy(), summ=summary(), sbom=False)
        self.assertEqual(dec["cve_track"]["failure_type"], "dataUnavailable")
        self.assertFalse(dec["blocked"]); self.assertEqual(rc, 0)
        self.assertTrue(any("CVE 검증 미수행" in w for w in dec["warnings"]))
        self.assertTrue(any("앞단 실행 여부" in w for w in dec["warnings"]))

    def test_04_bypass_track_failure_downgraded(self):
        """(4) bypass + 트랙 실패(scriptError) → failOpen 강등, 미차단 + suppression."""
        rc, dec = run_gate(pol=policy(), summ=summary(), sbom=True,
                           env_extra={"CVE_TRACK_BYPASS": "1", "GITHUB_ACTOR": "tester"})
        self.assertFalse(dec["blocked"]); self.assertEqual(rc, 0)
        self.assertTrue(dec.get("suppression", {}).get("active"))
        self.assertEqual(dec["suppression"]["actor"], "tester")

    def test_05_bypass_cannot_unblock_valid(self):
        """(5) bypass + 유효 CVE block(트랙 성공) → 우회 불가, 차단 유지."""
        rc, dec = run_gate(
            pol=policy(), summ=summary(),
            dep_raw=trivy_raw([("CVE-A", "pyyaml", "5.3", "CRITICAL", None)]),
            decision=cve_decision([{"cve": "CVE-A", "purl": "pkg:pypi/pyyaml@5.3",
                                    "kev": False, "epss": 0.5, "severity": "CRITICAL", "verdict": "block"}]),
            env_extra={"CVE_TRACK_BYPASS": "1", "GITHUB_ACTOR": "tester"},
        )
        self.assertTrue(dec["blocked"]); self.assertEqual(rc, 1)
        self.assertNotIn("suppression", dec)

    def test_06_kev_medium_promoted(self):
        """(6) KEV 등재 medium → 승격되어 차단."""
        rc, dec = run_gate(
            pol=policy(), summ=summary(),
            dep_raw=trivy_raw([("CVE-K", "widget", "1.0", "MEDIUM", None)]),
            decision=cve_decision([{"cve": "CVE-K", "purl": "pkg:pypi/widget@1.0",
                                    "kev": True, "epss": 0.02, "severity": "MEDIUM", "verdict": "block"}]),
        )
        self.assertTrue(dec["blocked"]); self.assertEqual(rc, 1)
        self.assertEqual(dec["cve_track"]["promoted"], 1)

    def test_07a_critical_guard_blocks_demote(self):
        """(7a) critical(CVSS≥9.0) + EPSS0.001 + fix없음 → 가드로 강등 차단(차단 유지)."""
        rc, dec = run_gate(
            pol=policy(), summ=summary(),
            dep_raw=trivy_raw([("CVE-C", "pyyaml", "5.3", "CRITICAL", None)]),
            decision=cve_decision([{"cve": "CVE-C", "purl": "pkg:pypi/pyyaml@5.3",
                                    "kev": False, "epss": 0.001, "severity": "CRITICAL", "verdict": "block"}]),
        )
        self.assertTrue(dec["blocked"]); self.assertEqual(rc, 1)
        self.assertEqual(dec["cve_track"]["demoted"], 0)

    def test_07b_high_lowrisk_demoted(self):
        """(7b) high(CVSS<9.0) + EPSS0.001 + fix없음 → 강등되어 미차단."""
        rc, dec = run_gate(
            pol=policy(), summ=summary(),
            dep_raw=trivy_raw([("CVE-H", "widget", "1.0", "HIGH", None)]),
            decision=cve_decision([{"cve": "CVE-H", "purl": "pkg:pypi/widget@1.0",
                                    "kev": False, "epss": 0.001, "severity": "HIGH", "verdict": "warn"}]),
        )
        self.assertFalse(dec["blocked"]); self.assertEqual(rc, 0)
        self.assertEqual(dec["cve_track"]["demoted"], 1)

    def test_08_annotate_only_no_verdict_change(self):
        """(8) annotateOnly=true → 강등 대상이어도 판정 불변(차단 유지)."""
        rc, dec = run_gate(
            pol=policy(annotateOnly=True), summ=summary(),
            dep_raw=trivy_raw([("CVE-H", "widget", "1.0", "HIGH", None)]),
            decision=cve_decision([{"cve": "CVE-H", "purl": "pkg:pypi/widget@1.0",
                                    "kev": False, "epss": 0.001, "severity": "HIGH", "verdict": "warn"}]),
        )
        self.assertTrue(dec["blocked"]); self.assertEqual(rc, 1)
        self.assertEqual(dec["cve_track"]["applied"], 0)

    def test_09_match_failure_keeps_trivy(self):
        """(9) 매칭 실패(CVE 불일치) → Trivy 판정 유지, 보정 없음."""
        rc, dec = run_gate(
            pol=policy(), summ=summary(),
            dep_raw=trivy_raw([("CVE-X", "widget", "1.0", "HIGH", None)]),
            decision=cve_decision([{"cve": "CVE-Y", "purl": "pkg:pypi/widget@1.0",
                                    "kev": False, "epss": 0.001, "severity": "HIGH", "verdict": "warn"}]),
        )
        self.assertTrue(dec["blocked"]); self.assertEqual(rc, 1)
        self.assertEqual(dec["cve_adjustments"], [])

    def test_10_high_with_fix_not_demoted(self):
        """(10) fix 있는 high + 저EPSS → demoteOnlyWhenNoFix 로 강등 안 됨."""
        rc, dec = run_gate(
            pol=policy(), summ=summary(),
            dep_raw=trivy_raw([("CVE-F", "widget", "1.0", "HIGH", "1.1")]),
            decision=cve_decision([{"cve": "CVE-F", "purl": "pkg:pypi/widget@1.0",
                                    "kev": False, "epss": 0.001, "severity": "HIGH", "verdict": "warn"}]),
        )
        self.assertTrue(dec["blocked"]); self.assertEqual(rc, 1)
        self.assertEqual(dec["cve_track"]["demoted"], 0)

    def test_11_annotate_only_shows_adjustment(self):
        """(11) annotateOnly=true 라도 승격/강등 '표시'는 기록된다(미반영)."""
        rc, dec = run_gate(
            pol=policy(annotateOnly=True), summ=summary(),
            dep_raw=trivy_raw([("CVE-K", "widget", "1.0", "MEDIUM", None)]),
            decision=cve_decision([{"cve": "CVE-K", "purl": "pkg:pypi/widget@1.0",
                                    "kev": True, "epss": 0.02, "severity": "MEDIUM", "verdict": "block"}]),
        )
        self.assertEqual(dec["cve_track"]["promoted"], 1)
        self.assertEqual(dec["cve_track"]["applied"], 0)
        self.assertTrue(dec["cve_adjustments"])
        self.assertFalse(dec["cve_adjustments"][0]["applied"])

    def test_12_cvetrack_off_trivy_survives(self):
        """(12) cveTrack.enabled=off → normalize-trivy 로 Trivy 판정 생존."""
        raw = json.loads((FIXTURES / "raw-trivy-sample.json").read_text())
        rc, dec = run_gate(pol=policy(enabled="off"), summ=summary(), dep_raw=raw)
        self.assertTrue(dec["blocked"]); self.assertEqual(rc, 1)
        self.assertEqual(dec["cve_track"]["mode"], "off")

    def test_13_cve_only_kev_surfaced(self):
        """(13) Trivy 에 없는 KEV CVE → warning 으로 표면화(차단 아님)."""
        rc, dec = run_gate(
            pol=policy(), summ=summary(),
            dep_raw=trivy_raw([("CVE-M", "widget", "1.0", "MEDIUM", None)]),
            decision=cve_decision([
                {"cve": "CVE-M", "purl": "pkg:pypi/widget@1.0", "kev": False,
                 "epss": 0.01, "severity": "MEDIUM", "verdict": "warn"},
                {"cve": "CVE-KEVONLY", "purl": "pkg:pypi/ghost@9.9", "kev": True,
                 "epss": 0.9, "severity": "HIGH", "verdict": "block"},
            ]),
        )
        self.assertTrue(any("CVE-KEVONLY" in w and "Trivy 결과에 없" in w for w in dec["warnings"]))

    # ── P0-1: would_block 을 게이트가 사실대로 실어 주는가 ──
    def test_14_would_block_reflects_failclosed(self):
        """(14/P0-1) enforce+scriptError=failClosed → would_block True,
        enforce+dataUnavailable=failOpen → would_block False."""
        _, dec_fc = run_gate(pol=policy(), summ=summary(), sbom=True)     # scriptError
        self.assertTrue(dec_fc["cve_track"]["would_block"])
        self.assertTrue(dec_fc["blocked"])
        _, dec_fo = run_gate(pol=policy(), summ=summary(), sbom=False)    # dataUnavailable
        self.assertFalse(dec_fo["cve_track"]["would_block"])
        self.assertFalse(dec_fo["blocked"])

    # ── P0-2: evidence 타입 오염이 게이트를 크래시시키지 않는가 ──
    def test_15_string_epss_coerced_no_crash(self):
        """(15/P0-2) epss가 문자열 '0.001' 이어도 크래시 없이 float 로 해석,
        HIGH+저EPSS+fix없음 → 강등되어 미차단."""
        rc, dec = run_gate(
            pol=policy(), summ=summary(),
            dep_raw=trivy_raw([("CVE-H", "widget", "1.0", "HIGH", None)]),
            decision=cve_decision([{"cve": "CVE-H", "purl": "pkg:pypi/widget@1.0",
                                    "kev": False, "epss": "0.001", "severity": "HIGH",
                                    "verdict": "warn"}]),
        )
        self.assertFalse(dec["blocked"]); self.assertEqual(rc, 0)
        self.assertEqual(dec["cve_track"]["demoted"], 1)

    def test_16_garbage_epss_keeps_block(self):
        """(16/P0-2) epss가 숫자로 해석 불가('not-a-number') → None 처리되어
        maxEpss 조건에서 강등 보류, 차단 유지(안전측)."""
        rc, dec = run_gate(
            pol=policy(), summ=summary(),
            dep_raw=trivy_raw([("CVE-H", "widget", "1.0", "HIGH", None)]),
            decision=cve_decision([{"cve": "CVE-H", "purl": "pkg:pypi/widget@1.0",
                                    "kev": False, "epss": "not-a-number", "severity": "HIGH",
                                    "verdict": "warn"}]),
        )
        self.assertTrue(dec["blocked"]); self.assertEqual(rc, 1)
        self.assertEqual(dec["cve_track"]["demoted"], 0)

    # ── P0-3: 손상/비-Trivy 의존성 리포트가 조용히 fail-open 되지 않는가 ──
    def test_17_corrupt_dep_report_warns(self):
        """(17/P0-3) 손상 JSON → _read_json_safe 경고, 유효하나 Trivy 아님 →
        maybe_inject_trivy 경고. 둘 다 stderr 로 표면화되어야 한다."""
        _, _, err_corrupt = run_gate(pol=policy(enabled="off"), summ=summary(),
                                     dep_raw_text="{ not valid json ", return_stderr=True)
        self.assertIn("dependency-report.json", err_corrupt)
        _, _, err_nottrivy = run_gate(pol=policy(enabled="off"), summ=summary(),
                                      dep_raw={"not": "trivy"}, return_stderr=True)
        self.assertIn("raw Trivy 형식이 아닙니다", err_nottrivy)

    # ── 신규 발견 건: runtime-validation 매핑 e2e ──
    def test_18_runtime_validation_mapping(self):
        """(18) runtime-report(tool=runtime-validation) critical 은 차단되고
        info 는 low 로 매핑되어 warn 을 만들지 않는다(fallback 폭발 방지)."""
        summ = summary()
        summ["reports"]["runtime_validation"] = {
            "tool": "runtime-validation", "status": "failed",
            "findings": [
                {"id": "N1", "severity": "critical", "title": "rce", "location": "http://x"},
                {"id": "N2", "severity": "info", "title": "banner", "location": "http://y"},
            ],
        }
        rc, dec = run_gate(pol=policy(enabled="off"), summ=summ)
        self.assertTrue(dec["blocked"]); self.assertEqual(rc, 1)   # critical 차단
        byid = {f["id"]: f for f in dec["findings"]}
        self.assertEqual(byid["N1"]["severity"], "critical")
        self.assertTrue(byid["N1"]["blocking"])
        self.assertEqual(byid["N2"]["severity"], "low")            # info → low
        self.assertFalse(byid["N2"]["warning"])
        self.assertFalse(byid["N2"]["blocking"])
        # fallback 이 발동하지 않았어야 한다
        self.assertNotIn("severity_fallback", byid["N1"])
        self.assertNotIn("severity_fallback", byid["N2"])
        self.assertFalse(any("매핑되지 않은 severity" in w for w in dec["warnings"]))


class LoadClassifyUnitTests(unittest.TestCase):
    """서브프로세스로 재현 어려운 분류(timeout)를 in-process 로 검증."""

    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location("evaluate_gate", EG_PATH)
        cls.eg = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.eg)

    def test_03c_timeout_classified(self):
        """(3-timeout) self-invoke runner 가 timeout → failure_type=timeout."""
        eg = self.eg
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            (tmp / "security" / "reports").mkdir(parents=True)
            (tmp / "security" / "sbom" / "generated").mkdir(parents=True)
            (tmp / "security" / "sbom" / "generated" / "cve-risk-assessment.json").write_text('{"cves":[]}')
            sleeper = tmp / "sleeper.py"
            sleeper.write_text("import time; time.sleep(5)\n")
            saved = dict(eg.RUNNER_WHITELIST["cve-policy-evaluate"])
            eg.RUNNER_WHITELIST["cve-policy-evaluate"] = {
                "script": str(sleeper),
                "input_probe": "security/sbom/generated/cve-risk-assessment.json",
            }
            cwd = os.getcwd()
            try:
                os.chdir(tmp)
                pol = {"cveTrack": {"enabled": "enforce",
                                    "decisionFile": "security/reports/cve-policy-decision.json",
                                    "runner": {"runnerId": "cve-policy-evaluate", "allowSelfInvoke": True},
                                    "timeoutSeconds": 1}}
                res = eg.load_cve_decision(pol)
            finally:
                os.chdir(cwd)
                eg.RUNNER_WHITELIST["cve-policy-evaluate"] = saved
        self.assertEqual(res["source"], "failed")
        self.assertEqual(res["failure_type"], "timeout")

    def test_p0_2_apply_exception_still_writes_and_blocks(self):
        """(P0-2) apply_cve_track 이 예외를 던져도 gate-decision.json 은 반드시
        쓰이고, 게이트는 fail-closed(blocked=True, exit 1)여야 한다."""
        eg = self.eg
        orig = eg.apply_cve_track
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            (tmp / "security" / "reports").mkdir(parents=True)
            (tmp / "security" / "policies").mkdir(parents=True)
            (tmp / "security" / "reports" / "security-summary.json").write_text(json.dumps(summary()))
            (tmp / "security" / "policies" / "remediation-guide.json").write_text("{}")
            pol_path = tmp / "pol.json"
            pol_path.write_text(json.dumps(policy()))
            cwd = os.getcwd()
            prev_env = os.environ.get("SECURE_GATE_POLICY")
            try:
                os.chdir(tmp)
                os.environ["SECURE_GATE_POLICY"] = str(pol_path)
                eg.apply_cve_track = lambda *a, **k: (_ for _ in ()).throw(RuntimeError("synthetic"))
                with self.assertRaises(SystemExit) as cm:
                    eg.main()
                self.assertEqual(cm.exception.code, 1)
                dec = json.loads((tmp / "security" / "reports" / "gate-decision.json").read_text())
                self.assertTrue(dec["blocked"])
                self.assertIn("error", dec["cve_track"])
            finally:
                os.chdir(cwd)
                eg.apply_cve_track = orig
                if prev_env is None:
                    os.environ.pop("SECURE_GATE_POLICY", None)
                else:
                    os.environ["SECURE_GATE_POLICY"] = prev_env


class BannerRenderTests(unittest.TestCase):
    """P0-1: create-pr-comment.build_banner 가 판정을 정확히 렌더하는가."""

    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location("create_pr_comment", PC_PATH)
        cls.pc = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.pc)

    def test_failclosed_banner_is_red_not_yellow(self):
        """enforce+fail-closed(would_block True) → 빨강(차단) 배너, 노랑(fail-open) 아님."""
        dec = {"blocked": True, "cve_track": {
            "mode": "enforce", "source": "failed",
            "failure_type": "scriptError", "would_block": True}}
        banner = self.pc.build_banner(dec)
        self.assertIn("🔴", banner)
        self.assertNotIn("🟡", banner)

    def test_failopen_banner_is_yellow(self):
        """enforce+fail-open(would_block False) → 노랑(미수행) 배너."""
        dec = {"blocked": False, "cve_track": {
            "mode": "enforce", "source": "failed",
            "failure_type": "dataUnavailable", "would_block": False}}
        banner = self.pc.build_banner(dec)
        self.assertIn("🟡", banner)
        self.assertNotIn("🔴", banner)

    def test_monitor_banner_shows_counts(self):
        """monitor 정상 → 후보 건수(block/warn)가 0/0 이 아니라 실제값으로 표시."""
        dec = {"blocked": False, "cve_track": {
            "mode": "monitor", "source": "file", "block": 3, "warn": 2}}
        banner = self.pc.build_banner(dec)
        self.assertIn("3", banner)
        self.assertIn("2", banner)


class ProfileTests(unittest.TestCase):
    """SECURE_GATE_PROFILE 오버레이가 base 정책 위에 cveTrack 노브만 덮어써
    strict/balanced/monitor 를 caller 이름 지정만으로 전환한다."""

    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location("evaluate_gate_prof", EG_PATH)
        cls.eg = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.eg)

    # ── 오버레이 병합 / 선택 (유닛) ──
    def test_deep_merge_recursive_nondestructive(self):
        """_deep_merge: 중첩 dict 재귀 병합, 미지정 키 보존, base 원본 불변."""
        base = {"cveTrack": {"enabled": "monitor",
                             "adjustment": {"annotateOnly": True, "demote": {"maxEpss": 0.1}}}}
        overlay = {"cveTrack": {"enabled": "enforce",
                                "adjustment": {"demote": {"enabled": False}}}}
        merged = self.eg._deep_merge(base, overlay)
        self.assertEqual(merged["cveTrack"]["enabled"], "enforce")
        self.assertFalse(merged["cveTrack"]["adjustment"]["demote"]["enabled"])
        self.assertEqual(merged["cveTrack"]["adjustment"]["demote"]["maxEpss"], 0.1)
        self.assertTrue(merged["cveTrack"]["adjustment"]["annotateOnly"])
        self.assertEqual(base["cveTrack"]["enabled"], "monitor")

    def test_unknown_profile_fails_hard(self):
        """알 수 없는 프로파일 이름 → 조용히 무시하지 않고 SystemExit."""
        prev = os.environ.get("SECURE_GATE_PROFILE")
        os.environ["SECURE_GATE_PROFILE"] = "bogus"
        try:
            with self.assertRaises(SystemExit):
                self.eg.resolve_profile_file()
        finally:
            if prev is None:
                os.environ.pop("SECURE_GATE_PROFILE", None)
            else:
                os.environ["SECURE_GATE_PROFILE"] = prev

    def test_no_profile_returns_none(self):
        """SECURE_GATE_PROFILE 미설정 → None(오버레이 없음)."""
        prev = os.environ.get("SECURE_GATE_PROFILE")
        os.environ.pop("SECURE_GATE_PROFILE", None)
        try:
            self.assertIsNone(self.eg.resolve_profile_file())
        finally:
            if prev is not None:
                os.environ["SECURE_GATE_PROFILE"] = prev

    # ── 프로파일별 게이트 동작 (통합, 동일 강등대상 입력) ──
    _DEMOTABLE_DEP = [("CVE-H", "widget", "1.0", "HIGH", None)]
    _DEMOTABLE_DEC = [{"cve": "CVE-H", "purl": "pkg:pypi/widget@1.0",
                       "kev": False, "epss": 0.001, "severity": "HIGH", "verdict": "warn"}]

    def test_strict_enforces_but_keeps_blocks(self):
        """strict: base(monitor)를 enforce 로 켜되 demote 비활성 → 강등대상도 차단 유지."""
        base = json.loads(REAL_POLICY.read_text())
        rc, dec = run_gate(pol=base, summ=summary(),
                           dep_raw=trivy_raw(self._DEMOTABLE_DEP),
                           decision=cve_decision(self._DEMOTABLE_DEC),
                           env_extra={"SECURE_GATE_PROFILE": "strict"})
        self.assertEqual(dec["cve_track"]["mode"], "enforce")
        self.assertEqual(dec["cve_track"]["demoted"], 0)
        self.assertTrue(dec["blocked"]); self.assertEqual(rc, 1)

    def test_balanced_enforces_corrections(self):
        """balanced: enforce + demote 활성 → 저위험 high 강등되어 미차단."""
        base = json.loads(REAL_POLICY.read_text())
        rc, dec = run_gate(pol=base, summ=summary(),
                           dep_raw=trivy_raw(self._DEMOTABLE_DEP),
                           decision=cve_decision(self._DEMOTABLE_DEC),
                           env_extra={"SECURE_GATE_PROFILE": "balanced"})
        self.assertEqual(dec["cve_track"]["mode"], "enforce")
        self.assertEqual(dec["cve_track"]["demoted"], 1)
        self.assertFalse(dec["blocked"]); self.assertEqual(rc, 0)

    def test_monitor_overrides_enforce_to_dryrun(self):
        """monitor: base 가 enforce 여도 기록만 — applied 0, 차단 유지."""
        base = policy()  # enforce / annotateOnly=false
        rc, dec = run_gate(pol=base, summ=summary(),
                           dep_raw=trivy_raw(self._DEMOTABLE_DEP),
                           decision=cve_decision(self._DEMOTABLE_DEC),
                           env_extra={"SECURE_GATE_PROFILE": "monitor"})
        self.assertEqual(dec["cve_track"]["mode"], "monitor")
        self.assertEqual(dec["cve_track"]["applied"], 0)
        self.assertTrue(dec["blocked"]); self.assertEqual(rc, 1)


class MonitorBypassTests(unittest.TestCase):
    """monitor 모드 + bypass 조합: bypass 다운그레이드/suppression 은 mode 와
    무관하게 계산되지만(=_handle_track_failure), monitor 는 어차피 차단하지
    않으므로 두 신호가 충돌 없이 공존한다."""

    def test_monitor_with_bypass_records_suppression_no_block(self):
        """monitor + 트랙실패(scriptError) + bypass: 미차단 + suppression 기록.
        monitor 라 would_block 은 False 지만 bypass 우회 기록은 그대로 남는다."""
        rc, dec = run_gate(pol=policy(enabled="monitor"), summ=summary(), sbom=True,
                           env_extra={"CVE_TRACK_BYPASS": "1", "GITHUB_ACTOR": "tester"})
        self.assertEqual(dec["cve_track"]["mode"], "monitor")
        self.assertFalse(dec["blocked"]); self.assertEqual(rc, 0)
        self.assertFalse(dec["cve_track"]["would_block"])
        self.assertTrue(dec.get("suppression", {}).get("active"))
        self.assertEqual(dec["suppression"]["actor"], "tester")

    def test_monitor_track_failure_without_bypass_is_monitor_warning(self):
        """monitor + 트랙실패 + bypass 없음: 차단 안 하고 fail-closed 사유를
        '[monitor]' 경고로 기록, suppression 없음(=bypass 미적용)."""
        rc, dec = run_gate(pol=policy(enabled="monitor"), summ=summary(), sbom=True)
        self.assertEqual(dec["cve_track"]["mode"], "monitor")
        self.assertFalse(dec["blocked"]); self.assertEqual(rc, 0)
        self.assertFalse(dec["cve_track"]["would_block"])
        self.assertNotIn("suppression", dec)
        self.assertTrue(any("[monitor]" in w and "트랙 실패" in w for w in dec["warnings"]))


class ReportPathResolutionTests(unittest.TestCase):
    """paths.resolve_report: reusable workflow 다운로드 경로 편차를 후보 탐색으로 흡수."""

    @classmethod
    def setUpClass(cls):
        p = REPO / "scripts" / "paths.py"
        spec = importlib.util.spec_from_file_location("paths_mod", p)
        cls.paths = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.paths)

    def _resolve(self, tmp, **kw):
        return self.paths.resolve_report(
            "gate-decision.json",
            reports_dir=str(Path(tmp) / "security" / "reports"),
            search_root=str(tmp), log=False, **kw)

    def test_finds_in_reports_dir(self):
        """후보2: security/reports/<file>."""
        with tempfile.TemporaryDirectory() as d:
            f = Path(d) / "security" / "reports" / "gate-decision.json"
            f.parent.mkdir(parents=True); f.write_text("{}")
            self.assertEqual(self._resolve(d).resolve(), f.resolve())

    def test_finds_in_root(self):
        """후보3: ./<file> (단일 named 아티팩트가 루트에 풀린 케이스)."""
        with tempfile.TemporaryDirectory() as d:
            f = Path(d) / "gate-decision.json"; f.write_text("{}")
            self.assertEqual(self._resolve(d).resolve(), f.resolve())

    def test_finds_via_glob_subdir(self):
        """후보4: **/<file> (download-all 이 아티팩트명 하위폴더에 푼 케이스)."""
        with tempfile.TemporaryDirectory() as d:
            f = Path(d) / "gate-decision" / "gate-decision.json"
            f.parent.mkdir(parents=True); f.write_text("{}")
            got = self._resolve(d)
            self.assertIsNotNone(got)
            self.assertEqual(got.resolve(), f.resolve())

    def test_priority_reports_over_root(self):
        """우선순위: security/reports(2) 가 ./(3) 보다 먼저."""
        with tempfile.TemporaryDirectory() as d:
            rf = Path(d) / "security" / "reports" / "gate-decision.json"
            rf.parent.mkdir(parents=True); rf.write_text("{}")
            (Path(d) / "gate-decision.json").write_text("{}")
            self.assertEqual(self._resolve(d).resolve(), rf.resolve())

    def test_env_var_highest_priority(self):
        """우선순위: env(1) 가 security/reports(2) 보다 먼저."""
        with tempfile.TemporaryDirectory() as d:
            envf = Path(d) / "custom-decision.json"; envf.write_text("{}")
            rf = Path(d) / "security" / "reports" / "gate-decision.json"
            rf.parent.mkdir(parents=True); rf.write_text("{}")
            os.environ["TEST_GD_ENV"] = str(envf)
            try:
                got = self._resolve(d, env_var="TEST_GD_ENV")
                self.assertEqual(got.resolve(), envf.resolve())
            finally:
                os.environ.pop("TEST_GD_ENV", None)

    def test_none_when_absent(self):
        """전부 없으면 None(호출부는 fallback)."""
        with tempfile.TemporaryDirectory() as d:
            self.assertIsNone(self._resolve(d))

    def test_create_pr_comment_uses_resolver(self):
        """create-pr-comment.load_decision 가 ./gate-decision.json(루트 배치)도 로드."""
        spec = importlib.util.spec_from_file_location("cpc_mod", PC_PATH)
        cpc = importlib.util.module_from_spec(spec); spec.loader.exec_module(cpc)
        cwd0 = os.getcwd()
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "gate-decision.json").write_text(
                json.dumps({"gate_status": "PASSED", "reports": {}}))
            os.chdir(d)
            try:
                dec = cpc.load_decision()
            finally:
                os.chdir(cwd0)
        self.assertIsNotNone(dec)
        self.assertEqual(dec["gate_status"], "PASSED")


class SeverityConstantsTests(unittest.TestCase):
    """severity.py 단일 출처 + '심각도 등급'과 '표시 우선순위' 두 축 분리 검증."""

    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location("evaluate_gate_sev", EG_PATH)
        cls.eg = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.eg)          # import severity → sys.modules
        cls.sev = sys.modules["severity"]

    def test_severity_rank_excludes_secret(self):
        """SEVERITY_RANK 은 순수 CVSS 등급만 — secret 키 없음(0으로 끼우지 않음)."""
        self.assertNotIn("secret", self.sev.SEVERITY_RANK)
        self.assertEqual(set(self.sev.SEVERITY_RANK),
                         {"critical", "high", "medium", "low"})

    def test_gate_imports_shared_rank(self):
        """evaluate-gate 의 SEV_RANK 는 severity.py 를 import 한 동일 객체(단일 출처)."""
        self.assertIs(self.eg.SEV_RANK, self.sev.SEVERITY_RANK)
        self.assertIs(self.eg.CVSS_BAND_FLOOR, self.sev.CVSS_BAND_FLOOR)

    def test_display_order_secret_first_unknown_last(self):
        """표시 우선순위(등급과 별개 축): secret 최상단, 미지정 등급은 맨 뒤."""
        self.assertEqual(self.sev.display_key("secret"), 0)
        self.assertLess(self.sev.display_key("secret"), self.sev.display_key("critical"))
        self.assertLess(self.sev.display_key("critical"), self.sev.display_key("low"))
        self.assertEqual(self.sev.display_key("nonsense"), len(self.sev.DISPLAY_ORDER))

    def test_secret_finding_not_adjusted(self):
        """_decide_adjustment: secret severity → keep(보정 대상 아님, 명시 제외)."""
        f = {"severity": "secret", "blocking": True, "id": "S1"}
        ev = {"kev": False, "epss": None, "severity": "high"}
        adj = {"promote": {"kev": True}, "demote": {"minSeverity": "high"}}
        self.assertEqual(self.eg._decide_adjustment(f, ev, adj), ("keep", "", None))


if __name__ == "__main__":
    unittest.main(verbosity=2)
