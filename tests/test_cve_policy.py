#!/usr/bin/env python3
"""CVE 정책 판정 레이어 검증 (cve-policy-evaluate.py, stdlib unittest, 무의존성).

이 테스트들은 검증이자 정책 명세다. 각 test 의 docstring 한 줄이 "무엇을
검증하는지"를 규정한다. 판정 레이어(evaluate_cve / build_cve_decision /
recommend_action / 정책 로더 fail-hard / OSV 실패 처리)를 직접 import 해서 태운다.

임계값·CVSS 매핑은 하드코딩하지 않고 모듈이 실제 cve-policy.json 에서 로드한
상수(EPSS_BLOCK_THRESHOLD 등)를 참조한다 — 정책 값이 바뀌어도 테스트가 깨지지
않고 '규칙'을 검증한다.

실행: python -m unittest tests.test_cve_policy    (repo 루트에서)
"""

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
CP_PATH = REPO / "scripts" / "cve-policy-evaluate.py"


def _load_module():
    """모듈 import = 실제 cve-policy.json 으로 로더가 1회 실행된다(정상 정책 전제)."""
    spec = importlib.util.spec_from_file_location("cve_policy_evaluate", CP_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


cp = _load_module()


# ── 입력 빌더 ──────────────────────────────────────────────────────
def cve_record(**overrides):
    """cve-risk-assessment.json 의 CVE 레코드 하나. 기본은 '아무 신호 없음(pass)'."""
    base = {
        "cve": "CVE-2024-0001",
        "kev_listed": False,
        "epss_score": 0.0,
        "epss_percentile": 0.0,
        "epss_lookup_failed": False,
        "kev_lookup_failed": False,
        "undetermined_risk": False,
        "severity": None,
        "severity_available": False,
        "osv_ids": [],
        "summary": "test",
        "packages": [],
    }
    base.update(overrides)
    return base


def _cvss_severity_for(verdict):
    """정책의 severityVerdicts 에서 주어진 verdict('block'/'warn')을 내는 severity 키."""
    for sev, v in cp.CVSS_SEVERITY_VERDICTS.items():
        if v == verdict:
            return sev
    return None


# ── 1. RULES 우선순위 (KEV → EPSS → CVSS → undetermined → pass) ──────
class RuleEvaluationTests(unittest.TestCase):
    """evaluate_cve 가 정책 우선순위대로 (verdict, rule)을 낸다."""

    def test_kev_wins_over_everything(self):
        """KEV 등재면 EPSS·CVSS 신호가 겹쳐도 최우선 1-KEV block."""
        crit = _cvss_severity_for("block")
        r = cve_record(kev_listed=True, epss_score=0.99, epss_percentile=0.99,
                       severity=crit, severity_available=True)
        self.assertEqual(cp.evaluate_cve(r), ("block", "1-KEV"))

    def test_epss_score_over_threshold_blocks(self):
        """KEV 아님 + epss_score ≥ blockThreshold → 2-EPSS block."""
        r = cve_record(epss_score=cp.EPSS_BLOCK_THRESHOLD)
        self.assertEqual(cp.evaluate_cve(r), ("block", "2-EPSS"))

    def test_epss_percentile_over_threshold_blocks(self):
        """epss_score 는 낮아도 percentile ≥ 임계값이면 2-EPSS block."""
        r = cve_record(epss_score=0.0,
                       epss_percentile=cp.EPSS_PERCENTILE_BLOCK_THRESHOLD)
        self.assertEqual(cp.evaluate_cve(r), ("block", "2-EPSS"))

    def test_epss_wins_over_cvss(self):
        """EPSS(2순위)가 CVSS(3순위)보다 먼저 — high(warn) severity라도 block."""
        high = _cvss_severity_for("warn")
        r = cve_record(epss_score=cp.EPSS_BLOCK_THRESHOLD,
                       severity=high, severity_available=True)
        self.assertEqual(cp.evaluate_cve(r), ("block", "2-EPSS"))

    def test_cvss_block_severity(self):
        """block 매핑 severity(CRITICAL) → 3-{severity} block, 라벨에 severity 세분."""
        crit = _cvss_severity_for("block")
        r = cve_record(severity=crit, severity_available=True)
        self.assertEqual(cp.evaluate_cve(r), ("block", f"3-{crit}"))

    def test_cvss_warn_severity(self):
        """warn 매핑 severity(HIGH) → 3-{severity} warn."""
        high = _cvss_severity_for("warn")
        r = cve_record(severity=high, severity_available=True)
        self.assertEqual(cp.evaluate_cve(r), ("warn", f"3-{high}"))

    def test_cvss_wins_over_undetermined(self):
        """CVSS(3순위)가 undetermined(5순위)보다 먼저."""
        crit = _cvss_severity_for("block")
        r = cve_record(severity=crit, severity_available=True, undetermined_risk=True)
        self.assertEqual(cp.evaluate_cve(r), ("block", f"3-{crit}"))

    def test_undetermined_warns(self):
        """어떤 위험 규칙도 안 걸리고 undetermined_risk=true → 5-UNDETERMINED warn."""
        r = cve_record(undetermined_risk=True)
        self.assertEqual(cp.evaluate_cve(r), ("warn", "5-UNDETERMINED"))

    def test_default_pass(self):
        """아무 신호 없음 → 6-DEFAULT pass."""
        self.assertEqual(cp.evaluate_cve(cve_record()), ("pass", "6-DEFAULT"))

    def test_unmapped_severity_does_not_block(self):
        """severityVerdicts 에 없는 등급(MEDIUM)은 3-CVSS 규칙을 통과 → pass."""
        r = cve_record(severity="MEDIUM", severity_available=True)
        self.assertEqual(cp.evaluate_cve(r), ("pass", "6-DEFAULT"))


# ── 2. 조회 실패 분기 (build_cve_decision) ─────────────────────────
class LookupFailureTests(unittest.TestCase):
    """EPSS/KEV 조회 실패 시 fail-open/fail-closed 가 명세대로 갈린다."""

    def test_epss_lookup_failed_is_failopen(self):
        """EPSS 미조회(fail-open): 높은 epss_score라도 2-EPSS 발동 안 함, 경고만."""
        r = cve_record(epss_lookup_failed=True, epss_score=0.99, epss_percentile=0.99)
        d = cp.build_cve_decision(r)
        self.assertEqual(d["verdict"], "pass")          # EPSS로 차단 안 됨
        self.assertTrue(any("EPSS 미조회" in w for w in d["evidence"]["warnings"]))

    def test_epss_lookup_failed_still_judged_by_cvss(self):
        """EPSS 미조회여도 CVSS로 판정 계속 — CRITICAL이면 block 유지."""
        crit = _cvss_severity_for("block")
        r = cve_record(epss_lookup_failed=True, severity=crit, severity_available=True)
        d = cp.build_cve_decision(r)
        self.assertEqual(d["verdict"], "block")
        self.assertEqual(d["rule"], f"3-{crit}")

    def test_kev_lookup_failed_promotes_pass_to_block(self):
        """KEV 미조회 + 다른 규칙 없음(pass) → 1F-KEV-UNAVAILABLE block(fail-closed)."""
        r = cve_record(kev_lookup_failed=True)
        d = cp.build_cve_decision(r)
        self.assertEqual(d["verdict"], "block")
        self.assertEqual(d["rule"], "1F-KEV-UNAVAILABLE")
        self.assertTrue(any("KEV 판단 불가" in w for w in d["evidence"]["warnings"]))

    def test_kev_lookup_failed_keeps_existing_block(self):
        """KEV 미조회지만 CVSS로 이미 block이면 1F로 덮지 않고 유지 + 경고."""
        crit = _cvss_severity_for("block")
        r = cve_record(kev_lookup_failed=True, severity=crit, severity_available=True)
        d = cp.build_cve_decision(r)
        self.assertEqual(d["rule"], f"3-{crit}")          # 1F 로 안 바뀜
        self.assertTrue(any("KEV 미조회" in w for w in d["evidence"]["warnings"]))

    def test_kev_lookup_failed_keeps_existing_warn(self):
        """KEV 미조회 + 기존 warn(HIGH)이면 승격 안 함(pass 아닐 때는 유지)."""
        high = _cvss_severity_for("warn")
        r = cve_record(kev_lookup_failed=True, severity=high, severity_available=True)
        d = cp.build_cve_decision(r)
        self.assertEqual(d["verdict"], "warn")
        self.assertEqual(d["rule"], f"3-{high}")

    def test_both_lookups_failed_pass_becomes_block(self):
        """EPSS+KEV 둘 다 미조회 + 다른 신호 없음 → 1F block, 경고 2종."""
        r = cve_record(epss_lookup_failed=True, kev_lookup_failed=True)
        d = cp.build_cve_decision(r)
        self.assertEqual(d["rule"], "1F-KEV-UNAVAILABLE")
        warns = d["evidence"]["warnings"]
        self.assertTrue(any("EPSS 미조회" in w for w in warns))
        self.assertTrue(any("KEV 판단 불가" in w for w in warns))


# ── 3. recommend_action 버전 비교 ──────────────────────────────────
class RecommendActionTests(unittest.TestCase):
    """설치 버전 ↔ fixed_versions 비교로 최소 업그레이드를 추천한다."""

    def test_no_fixed_versions_fallback(self):
        """fixed_versions 없음 → (None, 패치 없음 폴백 문구)."""
        target, action = cp.recommend_action("1.0.0", [])
        self.assertIsNone(target)
        self.assertEqual(action, cp.NO_FIX_FALLBACK)

    def test_recommends_minimum_upgrade_above_installed(self):
        """설치보다 높은 fixed 중 가장 낮은(최소 업그레이드) 버전 추천."""
        target, action = cp.recommend_action("1.2.0", ["2.0.0", "1.3.0", "1.5.0"])
        self.assertEqual(target, "1.3.0")
        self.assertIn("1.3.0", action)

    def test_all_fixed_below_installed_returns_highest(self):
        """모든 fixed 가 설치 이하(데이터 이상)면 가장 높은 fixed 를 그대로."""
        target, _ = cp.recommend_action("3.0.0", ["1.0.0", "2.0.0"])
        self.assertEqual(target, "2.0.0")

    def test_equal_version_not_treated_as_greater(self):
        """설치와 같은 fixed 뿐이면 '더 높음' 후보 없음 → 최고 fixed(=동일) 반환."""
        target, _ = cp.recommend_action("1.2.0", ["1.2.0"])
        self.assertEqual(target, "1.2.0")

    def test_version_suffix_parsing(self):
        """distro suffix(-1ubuntu2)가 섞여도 숫자 파싱으로 비교 가능."""
        target, _ = cp.recommend_action("1.2.0-1ubuntu2", ["1.2.1", "1.1.9"])
        self.assertEqual(target, "1.2.1")


# ── 4. 정책 로더 fail-hard (_load_epss_thresholds / _load_cvss_...) ──
class PolicyLoaderFailHardTests(unittest.TestCase):
    """정책이 깨졌으면 조용히 기본값으로 넘어가지 않고 즉시 exit 1."""

    def _with_policy(self, obj_or_text, loader):
        """임시 정책 파일로 POLICY_FILE 을 바꿔치기하고 loader 를 호출."""
        original = cp.POLICY_FILE
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "cve-policy.json"
            if isinstance(obj_or_text, str):
                p.write_text(obj_or_text)
            else:
                p.write_text(json.dumps(obj_or_text))
            cp.POLICY_FILE = p
            try:
                return loader()
            finally:
                cp.POLICY_FILE = original

    # --- EPSS ---
    def test_epss_missing_key_exits(self):
        """reportThresholds.epss 키 누락 → SystemExit."""
        with self.assertRaises(SystemExit):
            self._with_policy({"reportThresholds": {}}, cp._load_epss_thresholds)

    def test_epss_out_of_range_exits(self):
        """blockThreshold 가 0~1 밖 → SystemExit."""
        pol = {"reportThresholds": {"epss": {"blockThreshold": 5.0,
                                             "percentileBlockThreshold": 0.9}}}
        with self.assertRaises(SystemExit):
            self._with_policy(pol, cp._load_epss_thresholds)

    def test_epss_bool_value_exits(self):
        """blockThreshold 가 bool(True==1 함정) → SystemExit."""
        pol = {"reportThresholds": {"epss": {"blockThreshold": True,
                                             "percentileBlockThreshold": 0.9}}}
        with self.assertRaises(SystemExit):
            self._with_policy(pol, cp._load_epss_thresholds)

    def test_epss_file_missing_exits(self):
        """정책 파일 자체가 없으면 → SystemExit."""
        original = cp.POLICY_FILE
        cp.POLICY_FILE = Path("/nonexistent/cve-policy.json")
        try:
            with self.assertRaises(SystemExit):
                cp._load_epss_thresholds()
        finally:
            cp.POLICY_FILE = original

    def test_epss_malformed_json_exits(self):
        """JSON 파싱 실패 → SystemExit."""
        with self.assertRaises(SystemExit):
            self._with_policy("{not valid json", cp._load_epss_thresholds)

    # --- CVSS ---
    def test_cvss_invalid_verdict_value_exits(self):
        """severityVerdicts 값이 'block'/'warn' 외(대문자 BLOCK 등) → SystemExit."""
        pol = {"reportThresholds": {"cvss": {"severityVerdicts": {"CRITICAL": "BLOCK"}}}}
        with self.assertRaises(SystemExit):
            self._with_policy(pol, cp._load_cvss_severity_verdicts)

    def test_cvss_not_a_dict_exits(self):
        """severityVerdicts 가 객체가 아니면 → SystemExit."""
        pol = {"reportThresholds": {"cvss": {"severityVerdicts": []}}}
        with self.assertRaises(SystemExit):
            self._with_policy(pol, cp._load_cvss_severity_verdicts)

    def test_cvss_empty_map_allowed(self):
        """빈 severityVerdicts 는 '등급 판정 끄기'로 허용 — exit 하지 않고 {} 반환."""
        pol = {"reportThresholds": {"cvss": {"severityVerdicts": {}}}}
        result = self._with_policy(pol, cp._load_cvss_severity_verdicts)
        self.assertEqual(result, {})


# ── 5. OSV 실패 처리 + 최종 차단 (main 통합, in-process) ────────────
class OsvFailureAndMainTests(unittest.TestCase):
    """main 이 osv_failed_packages 를 0-OSV-UNAVAILABLE block 으로 싣고 종료코드에 반영."""

    def _run_main(self, assessment):
        """INPUT/OUTPUT 을 임시 경로로 바꿔 main 을 in-process 실행, (exit_code, output) 반환."""
        orig_in, orig_out = cp.INPUT_FILE, cp.OUTPUT_FILE
        with tempfile.TemporaryDirectory() as d:
            inp = Path(d) / "in.json"
            out = Path(d) / "out.json"
            inp.write_text(json.dumps(assessment))
            cp.INPUT_FILE, cp.OUTPUT_FILE = inp, out
            code = 0
            try:
                cp.main()
            except SystemExit as e:
                code = e.code or 0
            finally:
                cp.INPUT_FILE, cp.OUTPUT_FILE = orig_in, orig_out
            return code, json.loads(out.read_text())

    def test_osv_failed_package_blocks(self):
        """osv_failed_packages → package_failures[0].rule=0-OSV-UNAVAILABLE, exit 1."""
        assessment = {
            "cves": [],
            "osv_failed_packages": [{"name": "leftpad", "version": "1.0.0"}],
        }
        code, out = self._run_main(assessment)
        self.assertEqual(code, 1)
        self.assertEqual(len(out["package_failures"]), 1)
        self.assertEqual(out["package_failures"][0]["rule"], "0-OSV-UNAVAILABLE")
        self.assertEqual(out["package_failures"][0]["verdict"], "block")

    def test_block_cve_causes_exit_1(self):
        """block CVE 하나면 exit 1 + block_count 반영."""
        assessment = {"cves": [cve_record(cve="CVE-2021-44228", kev_listed=True)],
                      "osv_failed_packages": []}
        code, out = self._run_main(assessment)
        self.assertEqual(code, 1)
        self.assertEqual(out["block_count"], 1)
        self.assertEqual(out["cves"][0]["rule"], "1-KEV")

    def test_all_pass_no_failures_exits_0(self):
        """차단·OSV실패 없으면 exit 0(정상 종료)."""
        assessment = {"cves": [cve_record()], "osv_failed_packages": []}
        code, out = self._run_main(assessment)
        self.assertEqual(code, 0)
        self.assertEqual(out["block_count"], 0)
        self.assertEqual(out["pass_count"], 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
