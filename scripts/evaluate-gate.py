#!/usr/bin/env python3
"""
evaluate-gate.py

Secure Gate 의 유일한 판정 진입점.

경로 모델 (reusable workflow):
  - 툴링(scripts/policy/schema)은 이 파일 기준(__file__)의 툴링 루트에서 찾는다.
  - 리포트 산출물(security/reports/*)은 caller cwd 기준으로 읽고 쓴다.
  - POLICY  : env SECURE_GATE_POLICY 우선(caller override 허용), 없으면 툴링 기본
  - GUIDE   : caller override(cwd) 허용, 없으면 툴링 기본
  - SCHEMA  : 툴링 루트 고정 (caller override 불허 — 신뢰 경계)
  - RUNNER  : 툴링 루트 고정 (caller override 불허 — 신뢰 경계)
  자세한 근거는 docs/cve-track-integration.md 참조.

CVE 트랙은 "추가 차단 레이어"가 아니라 Trivy 판정을 보정(promote/demote/keep)하는
레이어다. 의존성 CVE의 baseline(severity·fix·purl)은 raw Trivy 를 공통 스키마로
정규화(normalize-trivy.py)해 확보하고, KEV/EPSS 보정 신호는 cve-policy-decision.json
에서 가져와 (purl, CVE)로 매칭한다. 상세는 docs/cve-track-integration.md 참조.
"""

import importlib.util
import json
import os
import subprocess
import sys
import time
import traceback
from pathlib import Path

# ── 툴링 루트 (이 파일: <root>/scripts/evaluate-gate.py) ──
TOOLING_ROOT     = Path(__file__).resolve().parent.parent
TOOLING_POLICIES = TOOLING_ROOT / "security" / "policies"
TOOLING_SCRIPTS  = TOOLING_ROOT / "scripts"
sys.path.insert(0, str(TOOLING_SCRIPTS))
from severity import SEVERITY_RANK as SEV_RANK, CVSS_BAND_FLOOR
from paths import resolve_report

# ── 리포트 산출물: caller cwd 기준 ──
REPORTS_DIR   = Path("security/reports")
SUMMARY_FILE  = REPORTS_DIR / "security-summary.json"
DECISION_FILE = REPORTS_DIR / "gate-decision.json"
DEP_REPORT_FILE = REPORTS_DIR / "dependency-report.json"     # raw Trivy
SBOM_FILE       = REPORTS_DIR / "sbom.cdx.json"              # C파트 SBOM 계약

# SCHEMA/RUNNER 는 툴링 고정 (caller override 불허)
SCHEMA_FILE = TOOLING_POLICIES / "policy-schema.json"

RUNNER_WHITELIST = {
    "cve-policy-evaluate": {
        "script":      str(TOOLING_SCRIPTS / "cve-policy-evaluate.py"),
        "input_probe": "security/sbom/generated/cve-risk-assessment.json",   # caller cwd
    },
}

# cve-policy-decision.json 유효성 최소 키 (exit code가 아니라 산출물로 성공 판정)
CVE_DECISION_REQUIRED_KEYS = {
    "total_cves", "block_count", "warn_count", "package_failures", "cves",
}

SEVERITY_ORDER  = ["critical", "high", "secret", "medium", "low"]
SEVERITY_LABELS = {
    "critical": "Critical",
    "high":     "High",
    "medium":   "Medium",
    "low":      "Low",
    "secret":   "Secret",
}

# SEV_RANK · CVSS_BAND_FLOOR 는 scripts/severity.py 단일 출처에서 import.


# ──────────────────────────────────────────────────────────────────
# 경로 해석
# ──────────────────────────────────────────────────────────────────
def resolve_policy_file() -> Path:
    """POLICY: SECURE_GATE_POLICY env 우선(caller override), 없으면 툴링 기본."""
    env_path = os.environ.get("SECURE_GATE_POLICY", "").strip()
    if env_path and Path(env_path).is_file():
        return Path(env_path)
    return TOOLING_POLICIES / "security-gate-policy.json"


def resolve_guide_file() -> Path:
    """GUIDE: caller override(cwd) 허용, 없으면 툴링 기본."""
    caller = Path("security/policies/remediation-guide.json")
    if caller.is_file():
        return caller
    return TOOLING_POLICIES / "remediation-guide.json"


# 프로파일: cveTrack 노브만 담은 오버레이를 base 정책에 병합한다. caller 는
# SECURE_GATE_PROFILE 로 '이름만' 지정한다. 경로 주입(traversal)을 막기 위해
# 이름은 화이트리스트로만 해석하고 파일 위치는 툴링 루트에 고정한다(신뢰 경계).
VALID_PROFILES = {"strict", "balanced", "monitor"}


def resolve_profile_file():
    """SECURE_GATE_PROFILE 이 유효 이름이면 profiles/<name>.json 경로, 없으면 None.

    미지의 이름은 조용히 무시하지 않고 fail-hard — 오타로 의도한 정책이 안
    걸리는 사고를 막는다.
    """
    name = os.environ.get("SECURE_GATE_PROFILE", "").strip().lower()
    if not name:
        return None
    if name not in VALID_PROFILES:
        print(
            f"[ERROR] 알 수 없는 SECURE_GATE_PROFILE: {name!r}. "
            f"허용: {', '.join(sorted(VALID_PROFILES))}",
            file=sys.stderr,
        )
        sys.exit(1)
    return TOOLING_POLICIES / "profiles" / f"{name}.json"


def _deep_merge(base: dict, overlay: dict) -> dict:
    """overlay 를 base 위에 깊은 병합(dict 는 재귀, 그 외는 overlay 우선). 원본 불변."""
    out = dict(base)
    for k, v in overlay.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = v
    return out


def load_json(path: Path) -> dict:
    if not path.exists():
        print(f"[ERROR] File not found: {path}")
        sys.exit(1)
    with open(path) as f:
        return json.load(f)


def _read_json_safe(path, *, label=None):
    """파일을 조용히 읽되, '없음'과 '손상'을 구분한다.
    - FileNotFoundError: 정상적으로 없을 수 있는 경우가 많아 조용히 None.
    - JSONDecodeError/IsADirectoryError: 존재하나 못 읽음 = 조용한 fail-open의
      원인이므로 반드시 stderr 경고를 남긴다."""
    if path is None:
        return None
    try:
        with open(path) as f:
            return json.load(f)
    except FileNotFoundError:
        return None
    except (json.JSONDecodeError, IsADirectoryError) as e:
        print(
            f"[WARN] {label or path} 읽기 실패 — 무시하고 진행합니다: "
            f"{type(e).__name__}: {e}",
            file=sys.stderr,
        )
        return None


# ──────────────────────────────────────────────────────────────────
# stdlib JSON Schema 경량 검증기 — policy-schema.json 을 파싱해 해석
# (규칙 하드코딩 금지). 검증 실패 = 정책 무결성 불확실 = fail-closed.
# ──────────────────────────────────────────────────────────────────
_JSON_SIMPLE_TYPES = {"object": dict, "array": list, "string": str, "null": type(None)}


def _type_ok(value, tname: str) -> bool:
    if tname == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if tname == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if tname == "boolean":
        return isinstance(value, bool)
    py = _JSON_SIMPLE_TYPES.get(tname)
    if py is None:
        return True
    return isinstance(value, py)


def _schema_validate(instance, schema: dict, path: str, errors: list) -> None:
    t = schema.get("type")
    if t is not None:
        types = t if isinstance(t, list) else [t]
        if not any(_type_ok(instance, tn) for tn in types):
            errors.append(f"{path or '<root>'}: 타입 {types} 아님 (실제 {type(instance).__name__})")
            return

    if "enum" in schema and instance not in schema["enum"]:
        errors.append(f"{path or '<root>'}: 허용값 {schema['enum']} 아님 (실제 {instance!r})")

    if isinstance(instance, dict):
        for req in schema.get("required", []):
            if req not in instance:
                errors.append(f"{path or '<root>'}: 필수 키 '{req}' 누락")
        for key, subschema in schema.get("properties", {}).items():
            if key in instance:
                child = f"{path}.{key}" if path else key
                _schema_validate(instance[key], subschema, child, errors)

    if isinstance(instance, list):
        items = schema.get("items")
        if isinstance(items, dict):
            for i, el in enumerate(instance):
                _schema_validate(el, items, f"{path}[{i}]", errors)


def validate_policy(policy: dict) -> None:
    schema = _read_json_safe(SCHEMA_FILE)
    if not isinstance(schema, dict):
        print(f"[ERROR] 정책 스키마를 읽을 수 없습니다: {SCHEMA_FILE}. 무결성 검증 불가 → fail-closed.")
        sys.exit(1)
    errors: list = []
    _schema_validate(policy, schema, "", errors)
    if errors:
        print("[ERROR] security-gate-policy.json 스키마 검증 실패 (fail-closed):")
        for e in errors:
            print(f"  - {e}")
        sys.exit(1)


# ──────────────────────────────────────────────────────────────────
# 정규화(Severity) + 공통 스키마 findings 빌드
# ──────────────────────────────────────────────────────────────────
def normalize_severity(tool: str, raw_severity, severity_mapping: dict, fallback: str):
    tool_mapping = severity_mapping.get(tool, {})
    if tool == "gitleaks":
        if "default" in tool_mapping:
            return tool_mapping["default"], False
        return fallback, True
    normalized = tool_mapping.get(raw_severity)
    if normalized is None:
        return fallback, True
    return normalized, False


def _load_normalizer():
    """normalize-trivy.py 를 in-process 로 로드 (subprocess/임시파일 없음)."""
    path = TOOLING_SCRIPTS / "normalize-trivy.py"
    if not path.is_file():
        return None
    spec = importlib.util.spec_from_file_location("normalize_trivy", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def maybe_inject_trivy(reports: dict) -> None:
    """의존성 baseline 확보. 이중화 방지 가드:
      - summary 의 dependency_scan 이 이미 findings 를 가지면(미래 aggregator) 그대로 둔다.
      - 아니면 raw Trivy(dependency-report.json)를 공통 스키마로 정규화해 채운다.
    cveTrack 상태와 무관하게 항상 동작 → cveTrack=off 여도 Trivy 판정은 생존.
    """
    dep = reports.get("dependency_scan") or {}
    if dep.get("findings"):
        return  # 이미 정규화됨 (mock 또는 미래 aggregator)
    dep_path = resolve_report(DEP_REPORT_FILE.name,
                              env_var="SECURE_GATE_DEP_REPORT") or DEP_REPORT_FILE
    raw = _read_json_safe(dep_path, label="dependency-report.json")
    if raw is None:
        return  # 파일 없음(정상) 또는 손상(_read_json_safe가 이미 경고) → baseline 없음
    if not isinstance(raw, dict) or "SchemaVersion" not in raw:
        # 존재하나 raw Trivy 형식이 아님 → 조용히 스킵하면 의존성 검사가 통째로
        # fail-open 된다. 반드시 경고를 남긴다.
        print(
            "[WARN] dependency-report.json이 raw Trivy 형식이 아닙니다 "
            "(SchemaVersion 없음) — 의존성 baseline 정규화를 생략합니다. "
            "의존성 취약점이 게이트에 반영되지 않을 수 있습니다.",
            file=sys.stderr,
        )
        return
    normalizer = _load_normalizer()
    if normalizer is None:
        print("[WARN] normalize-trivy.py 로드 실패 — 의존성 baseline 정규화 생략")
        return
    reports["dependency_scan"] = normalizer.normalize(raw)


def build_findings(reports: dict, policy: dict, guides: dict) -> list:
    severity_mapping = policy.get("severityMapping", {})
    category_map     = policy.get("toolCategoryMap", {})
    fallback         = policy.get("unknownSeverityFallback", "medium")
    block_set        = set(policy.get("gateRules", {}).get("blockOnSeverity", []))
    warn_set         = set(policy.get("gateRules", {}).get("warnOnSeverity", []))

    findings = []
    for report in reports.values():
        tool = report.get("tool", "")
        for finding in report.get("findings", []):
            raw_severity = finding.get("severity")
            normalized, used_fallback = normalize_severity(tool, raw_severity, severity_mapping, fallback)
            if used_fallback:
                print(
                    f"[WARN] Unknown severity '{raw_severity}' from tool '{tool}' "
                    f"-> falling back to '{fallback}'."
                )
            category = category_map.get(tool)
            guide    = guides.get(category) if category else None
            blocking = normalized in block_set
            warning  = (not blocking) and normalized in warn_set

            record = {
                "id":                finding.get("id"),
                "tool":              tool,
                "category":          category,
                "title":             finding.get("title"),
                "location":          finding.get("location"),
                "original_severity": raw_severity,
                "severity":          normalized,
                "blocking":          blocking,
                "warning":           warning,
                "guide":             guide,
                # 보정 레이어용 optional 필드 (없으면 None)
                "purl":              finding.get("purl"),
                "fixedVersion":      finding.get("fixedVersion"),
            }
            if used_fallback:
                record["severity_fallback"] = True
            findings.append(record)
    return findings


def _sorted_by_severity(severities: set) -> list:
    return sorted(
        severities,
        key=lambda s: SEVERITY_ORDER.index(s) if s in SEVERITY_ORDER else len(SEVERITY_ORDER),
    )


def build_reasons(findings: list) -> tuple:
    blocking_severities = {f["severity"] for f in findings if f["blocking"]}
    warning_severities  = {f["severity"] for f in findings if f["warning"]}

    block_reasons = [
        f"{SEVERITY_LABELS.get(sev, sev)} 등급 취약점이 탐지되었습니다."
        for sev in _sorted_by_severity(blocking_severities)
    ]
    warnings = [
        f"{SEVERITY_LABELS.get(sev, sev)} 등급 취약점이 탐지되었습니다. 수정을 권장합니다."
        for sev in _sorted_by_severity(warning_severities)
    ]
    for f in findings:
        if f.get("severity_fallback"):
            warnings.append(
                f"매핑되지 않은 severity '{f['original_severity']}' (도구: {f['tool']}) 이(가) "
                f"발견되어 '{f['severity']}'로 대체 처리되었습니다. security-gate-policy.json 갱신이 필요합니다."
            )
    return block_reasons, warnings


def evaluate(summary: dict, policy: dict, guides: dict) -> dict:
    reports = summary.get("reports", {})
    maybe_inject_trivy(reports)          # 의존성 baseline (cveTrack 무관, 항상)
    findings = build_findings(reports, policy, guides)

    blocked = any(f["blocking"] for f in findings)
    block_reasons, warnings = build_reasons(findings)
    return {
        "gate_status":    "FAILED" if blocked else "PASSED",
        "blocked":        blocked,
        "block_reasons":  block_reasons,
        "warnings":       warnings,
        "total_findings": len(findings),
        "reports":        reports,
        "findings":       findings,
    }


# ──────────────────────────────────────────────────────────────────
# CVE 트랙 로드 (이중 경로 + 실패 유형 분류)
# ──────────────────────────────────────────────────────────────────
def _cve_decision_valid(data) -> bool:
    return isinstance(data, dict) and CVE_DECISION_REQUIRED_KEYS.issubset(data.keys())


def load_cve_decision(policy: dict) -> dict:
    """반환: { source: file|executed|failed|skipped,
              failure_type: None|scriptError|dataUnavailable|timeout,
              decision: <dict|None>, duration_ms: <int|None> }"""
    ct = policy.get("cveTrack", {})
    mode = ct.get("enabled", "off")

    result = {"source": "skipped", "failure_type": None, "decision": None, "duration_ms": None}
    if mode == "off":
        return result

    # reusable workflow 다운로드 편차 흡수: env → security/reports → ./ → glob.
    _decision_default = Path(ct["decisionFile"])
    decision_file = resolve_report(_decision_default.name,
                                   env_var="SECURE_GATE_CVE_DECISION") or _decision_default

    # 1) 파일 있으면 읽는다
    data = _read_json_safe(decision_file)
    if _cve_decision_valid(data):
        result["source"] = "file"
        result["decision"] = data
        return result

    runner = ct.get("runner", {})
    spec = RUNNER_WHITELIST.get(runner.get("runnerId"))
    allow = bool(runner.get("allowSelfInvoke"))
    input_present = bool(spec) and Path(spec["input_probe"]).exists()

    # 2) 없으면 화이트리스트 runner 로 직접 실행
    if allow and spec and input_present:
        argv = [sys.executable, spec["script"]]
        start = time.monotonic()
        try:
            subprocess.run(argv, timeout=ct.get("timeoutSeconds", 120),
                           capture_output=True, text=True)
        except subprocess.TimeoutExpired:
            result["source"] = "failed"
            result["failure_type"] = "timeout"
            result["duration_ms"] = int((time.monotonic() - start) * 1000)
            return result
        result["duration_ms"] = int((time.monotonic() - start) * 1000)
        data = _read_json_safe(decision_file)
        if _cve_decision_valid(data):
            result["source"] = "executed"
            result["decision"] = data
            return result
        result["source"] = "failed"
        result["failure_type"] = "scriptError"    # 실행했으나 유효 산출물 없음
        return result

    # 3) 실행 불가/미실행 → SBOM 존재로 '앞단 미실행 vs 장애' 구분
    #    (cve-track-status.json 폐기: C파트가 SBOM 검증 실패 시 job 실패시키므로
    #     SBOM 존재 = 앞단 정상의 신호로 충분)
    result["source"] = "failed"
    if SBOM_FILE.exists():
        result["failure_type"] = "scriptError"      # SBOM 있음(앞단 정상) but 트랙 산출 없음
    else:
        result["failure_type"] = "dataUnavailable"  # SBOM 없음 → 앞단 미실행
    return result


def _bypass_active(policy: dict) -> bool:
    bypass = policy.get("cveTrack", {}).get("bypass", {})
    if not bypass.get("enabled"):
        return False
    env_name = bypass.get("signalEnv", "CVE_TRACK_BYPASS")
    return os.environ.get(env_name, "").strip().lower() not in ("", "0", "false")


def _cve_top_findings(decision: dict, n: int = 3) -> list:
    def sort_key(c):
        ev = c.get("evidence", {})
        return (1 if ev.get("kev") else 0, ev.get("epss") or 0.0)
    relevant = [c for c in decision.get("cves", []) if c.get("verdict") in ("block", "warn")]
    top = sorted(relevant, key=sort_key, reverse=True)[:n]
    return [{
        "cve": c.get("cve"),
        "epss": c.get("evidence", {}).get("epss"),
        "kev": c.get("evidence", {}).get("kev"),
        "verdict": c.get("verdict"),
    } for c in top]


# ──────────────────────────────────────────────────────────────────
# 보정 레이어 (promote / demote / keep)
# ──────────────────────────────────────────────────────────────────
def _norm_purl(purl):
    if not purl:
        return None
    p = purl.split("?")[0].strip().lower()
    return p or None


def _norm_sev(s):
    if not isinstance(s, str):
        return None
    s = s.lower()
    return {"moderate": "medium"}.get(s, s)


def _coerce_epss(v):
    """evidence 의 epss 를 float 또는 None 으로 정규화한다.
    cve-policy-decision.json 은 스키마 검증을 안 거친 caller-cwd 산출물이라
    epss 가 문자열 '0.05' 나 엉뚱한 타입일 수 있다. 그대로 두면 강등 판정의
    `epss >= maxEpss` 비교에서 TypeError 로 게이트가 크래시한다."""
    if isinstance(v, bool):
        return None
    if isinstance(v, (int, float)):
        return float(v)
    if isinstance(v, str):
        try:
            return float(v.strip())
        except ValueError:
            return None
    return None


def _more_severe(a, b):
    ra, rb = SEV_RANK.get(a, 0), SEV_RANK.get(b, 0)
    return a if ra >= rb else b


def _verdict_of(f) -> str:
    if f.get("blocking"):
        return "block"
    if f.get("warning"):
        return "warn"
    return "pass"


def _build_evidence_index(cve_decision: dict):
    """(purl_norm, cve) -> evidence, 그리고 cve -> evidence (폴백/KEV 스캔용)."""
    by_key, by_cve = {}, {}
    cve_purls = {}
    for c in cve_decision.get("cves", []):
        cve = c.get("cve")
        ev_raw = c.get("evidence", {})
        entry = {
            "cve": cve,
            "kev": ev_raw.get("kev") is True,
            "epss": _coerce_epss(ev_raw.get("epss")),
            "severity": _norm_sev(ev_raw.get("severity")),
        }
        for pkg in c.get("packages", []):
            purl_norm = _norm_purl(pkg.get("purl"))
            by_key[(purl_norm, cve)] = entry
            cve_purls.setdefault(cve, set()).add(purl_norm)
        by_cve.setdefault(cve, entry)
    # purl 없는 finding 의 CVE 단독 폴백 유일성 판정용. 레코드가 여러 개로
    # 쪼개져 있어도 CVE 기준으로 합산한다. packages 가 아예 없는 CVE 는 키가
    # 생기지 않아 폴백 불가(= 유일하지 않음)로 취급된다.
    for cve, purls in cve_purls.items():
        if cve in by_cve:
            by_cve[cve]["package_count"] = len(purls)
    return by_key, by_cve


def _match_evidence(f, by_key, by_cve):
    """매칭 키: (정규화 purl, CVE). purl 없으면 CVE 단독은 evidence 상 패키지가
    유일할 때만 폴백 허용. 실패 시 None → Trivy 판정 유지."""
    cve = f.get("id")
    purl = _norm_purl(f.get("purl"))
    if purl is not None:
        return by_key.get((purl, cve))
    ev = by_cve.get(cve)
    # purl 없는 finding: evidence 상 패키지가 유일할 때만 CVE 단독 폴백을 허용한다.
    # 한 CVE 가 여러 패키지에 걸쳐 있으면 어느 패키지의 신호인지 특정할 수 없고,
    # 엉뚱한 패키지의 낮은 신호로 차단이 풀릴 수 있다. 매칭 실패로 두면 Trivy
    # 판정이 유지돼 안전하다(D-19 — 매칭 실패의 위험은 비대칭).
    if ev is None or ev.get("package_count") != 1:
        return None
    return ev


def _decide_adjustment(f, ev, adj_cfg):
    """(action, reason, target_verdict) 반환. action ∈ {promote, demote, keep}."""
    promote = adj_cfg.get("promote", {})
    demote = adj_cfg.get("demote", {})
    sev = f.get("severity")

    # secret 은 CVSS/EPSS 축이 없어 CVE 보정(promote/demote) 대상이 아니다.
    # 정상 경로에선 category!=dependency 로 이미 걸러지지만, 등급 순위(SEVERITY_RANK)
    # 에서 secret 을 뺀 만큼 minSeverity 비교의 우연한 제외에 기대지 않고 명시 제외.
    if sev == "secret":
        return "keep", "", None

    # PROMOTE: KEV → severity 무관 block
    if promote.get("kev") and ev["kev"]:
        if not f.get("blocking"):
            return "promote", "KEV 등재 — severity 무관 차단", "block"
        return "keep", "", None

    # DEMOTE: 차단 중인 finding 만 대상. demote.enabled=false(strict 프로파일)면
    # 강등 자체를 끈다 — annotateOnly 와 무관하게 모든 차단을 유지한다.
    if f.get("blocking") and demote.get("enabled", True):
        require_not_kev = demote.get("requireNotKev", True)
        max_epss = demote.get("maxEpss")
        min_sev = demote.get("minSeverity", "high")
        only_no_fix = demote.get("demoteOnlyWhenNoFix", True)
        guard = demote.get("neverDemoteAtOrAboveCvss")

        if require_not_kev and ev["kev"]:
            return "keep", "", None
        if max_epss is not None and (ev["epss"] is None or ev["epss"] >= max_epss):
            return "keep", "", None
        if SEV_RANK.get(sev, 0) < SEV_RANK.get(min_sev, 0):
            return "keep", "", None
        if only_no_fix and f.get("fixedVersion"):
            return "keep", "", None
        if guard is not None:
            guard_sev = _more_severe(sev, ev["severity"])
            if CVSS_BAND_FLOOR.get(guard_sev, 0.0) >= guard:
                return "keep", "", None   # 가드 발동 → 강등 금지
        epss_txt = f"EPSS={ev['epss']}" if ev["epss"] is not None else "EPSS=?"
        return "demote", f"KEV 아님 · {epss_txt} < {max_epss} · fix 없음 → 차단→경고 강등", "warn"

    return "keep", "", None


def _apply_verdict(f, target_verdict):
    if target_verdict == "block":
        f["blocking"], f["warning"] = True, False
    elif target_verdict == "warn":
        f["blocking"], f["warning"] = False, True


def _cve_only_kev_warnings(by_cve, findings):
    """KEV 등재인데 Trivy findings 에 없는 CVE → warning 표면화 (차단 아님)."""
    dep_cves = {f.get("id") for f in findings if f.get("category") == "dependency"}
    out = []
    for cve, ev in by_cve.items():
        if ev["kev"] and cve not in dep_cves:
            out.append(f"KEV 등재 CVE {cve}가 Trivy 결과에 없습니다 — 확인 필요(보정 대상 아님).")
    return out


def _handle_track_failure(cve_result, ct, policy):
    """트랙 실패 시 (block_reasons, warnings, suppression, failed_closed).
    findings 는 건드리지 않음.

    failed_closed 는 '이 트랙 실패가 fail-closed 판정이었나'를 그대로 전달하는
    플래그다. 호출부가 block_reasons 문구를 문자열 매칭해 차단 여부를 되짚으면,
    아래 문구를 고치는 순간 blocked 가 조용히 False 로 바뀐다."""
    on_fail = ct.get("onTrackFailure", {})
    bypass_cfg = ct.get("bypass", {})
    ftype = cve_result.get("failure_type") or "scriptError"
    behavior = on_fail.get(ftype, "failClosed")

    warnings = ["CVE 입력 미생성 — 앞단 실행 여부 확인 필요"]
    block_reasons, suppression = [], None

    if (behavior == "failClosed" and bypass_cfg.get("enabled")
            and bypass_cfg.get("scope") == "trackFailureOnly" and _bypass_active(policy)):
        behavior = "failOpen"
        actor = os.environ.get("GITHUB_ACTOR", "unknown")
        suppression = {
            "active": True, "type": "cve-track-failure",
            "source": "label:security-gate-bypass-cve", "actor": actor, "reason": None,
            "note": "coarse track-level bypass; 향후 per-finding suppression으로 확장",
        }
        warnings.append(
            f"⚠️ CVE 트랙 실패가 우회(bypass)되었습니다 — actor:{actor}. "
            f"이 PR은 CVE 검증 없이 통과됩니다. 우회 사유를 PR 코멘트로 남겨 주세요."
        )

    failed_closed = behavior == "failClosed"
    if failed_closed:
        block_reasons.append(f"CVE 보정 트랙 실패({ftype}) — 안전하게 차단합니다(fail-closed).")
    else:
        warnings.append("CVE 검증 미수행")
    return block_reasons, warnings, suppression, failed_closed


def apply_cve_track(decision: dict, cve_result: dict, policy: dict) -> dict:
    """CVE 트랙을 게이트에 반영. 성공=보정(promote/demote/keep), 실패=onTrackFailure.
    monitor 또는 adjustment.annotateOnly=true 면 판정 불변(표시만)."""
    ct = policy.get("cveTrack", {})
    mode = ct.get("enabled", "off")
    findings = decision.get("findings", [])

    if mode == "off" or cve_result["source"] == "skipped":
        # 의존성은 이미 Trivy baseline 으로 게이트됨. 트랙 반영 없음.
        if mode != "off":
            return decision
        decision["cve_track"] = {"mode": "off", "source": cve_result["source"]}
        return decision

    adj_cfg = ct.get("adjustment", {})
    annotate_only = bool(adj_cfg.get("annotateOnly", True))
    apply_changes = (mode == "enforce") and not annotate_only

    adjustments, cve_only_kev = [], []
    decision_cve = cve_result.get("decision")

    if decision_cve is not None:
        by_key, by_cve = _build_evidence_index(decision_cve)
        for f in findings:
            if f.get("category") != "dependency":
                continue
            ev = _match_evidence(f, by_key, by_cve)
            if ev is None:
                continue   # 매칭 실패 → Trivy 판정 유지
            action, reason, target = _decide_adjustment(f, ev, adj_cfg)
            if action == "keep":
                continue
            adjustments.append({
                "cve": f.get("id"), "purl": f.get("purl"),
                "action": action, "from": _verdict_of(f), "to": target,
                "reason": reason, "applied": apply_changes,
            })
            if apply_changes:
                _apply_verdict(f, target)
        cve_only_kev = _cve_only_kev_warnings(by_cve, findings)

    # findings 반영 후 재계산
    block_reasons, warnings = build_reasons(findings)
    findings_blocked = any(f["blocking"] for f in findings)

    # 보정 주석을 경고로도 표면화 (무엇을 왜)
    for a in adjustments:
        tag = "" if a["applied"] else " [미반영]"
        warnings.append(f"CVE 보정{tag}: {a['cve']} {a['from']}→{a['to']} ({a['reason']})")
    warnings.extend(cve_only_kev)

    # 트랙 실패 처리
    suppression = None
    track_failed_closed = False
    if decision_cve is None:
        fb_reasons, fb_warnings, suppression, track_failed_closed = _handle_track_failure(
            cve_result, ct, policy)
        warnings.extend(fb_warnings)
        if mode == "enforce":
            block_reasons.extend(fb_reasons)
        else:  # monitor
            warnings.extend(f"[monitor] {r}" for r in fb_reasons)

    # blocked: findings 차단 OR (enforce 에서 트랙-실패가 fail-closed 였던 경우).
    # 판정 근거는 명시적 플래그로 전달받는다 — 사람이 읽는 문구에 의존하지 않는다.
    track_failure_block = mode == "enforce" and track_failed_closed
    blocked = findings_blocked or track_failure_block

    decision["blocked"] = blocked
    decision["block_reasons"] = block_reasons
    decision["warnings"] = warnings
    decision["gate_status"] = "FAILED" if blocked else "PASSED"
    decision["cve_adjustments"] = adjustments

    decision["cve_track"] = {
        "mode": mode,
        "source": cve_result["source"],
        "failure_type": cve_result.get("failure_type"),
        # 배너 렌더링(create-pr-comment)이 판정을 재추론하지 않도록 게이트가
        # 사실을 그대로 실어 준다: 이 트랙 실패가 실제 차단을 유발했는지,
        # monitor 후보 건수는 몇 건인지.
        "would_block": track_failure_block,
        "block": decision_cve.get("block_count", 0) if decision_cve else 0,
        "warn": decision_cve.get("warn_count", 0) if decision_cve else 0,
        "policy_version": decision_cve.get("policy_version") if decision_cve else None,
        "annotate_only": annotate_only,
        "promoted": sum(1 for a in adjustments if a["action"] == "promote"),
        "demoted":  sum(1 for a in adjustments if a["action"] == "demote"),
        "applied":  sum(1 for a in adjustments if a["applied"]),
        "cve_only_kev": len(cve_only_kev),
        "top_findings": _cve_top_findings(decision_cve) if decision_cve else [],
        "duration_ms": cve_result.get("duration_ms"),
    }
    if suppression:
        decision["suppression"] = suppression
    return decision


# ──────────────────────────────────────────────────────────────────
def main():
    # 입력 로딩 ~ evaluate() 전체를 감싼다. 여기서 예외가 나면 산출물이 아예 없어
    # 잡은 빨갛지만 PR 댓글엔 아무 정보가 없다(리포팅 레벨 fail-blind). 예외를
    # 삼키지 않고 ERROR 산출물을 반드시 쓴 뒤 fail-closed 차단한다.
    # load_json/validate_policy 는 sys.exit(1) 로 fail-hard 하므로 SystemExit 도
    # 함께 잡는다 — 차단이라는 결과는 그대로 두고 산출물만 추가하는 것이다(E-21).
    summary = None
    try:
        summary  = load_json(resolve_report(SUMMARY_FILE.name,
                                            env_var="SECURE_GATE_SUMMARY") or SUMMARY_FILE)
        policy   = load_json(resolve_policy_file())
        profile_file = resolve_profile_file()
        if profile_file is not None:
            if not profile_file.is_file():
                print(f"[ERROR] 프로파일 파일 없음: {profile_file}", file=sys.stderr)
                sys.exit(1)
            policy = _deep_merge(policy, load_json(profile_file))
        validate_policy(policy)
        guides   = load_json(resolve_guide_file())

        decision = evaluate(summary, policy, guides)
    except (Exception, SystemExit) as e:
        if isinstance(e, SystemExit):
            err_txt = f"SystemExit(code={e.code}) — 입력·정책 로딩 단계의 fail-hard 종료"
        else:
            err_txt = f"{type(e).__name__}: {e}"
        traceback.print_exc()
        print(f"[ERROR] 게이트 실행 실패 — fail-closed 처리: {err_txt}", file=sys.stderr)

        # 검사 요약 표가 전부 'Not Run' 으로 보이지 않도록, 이미 메모리에 있는
        # aggregate 결과만 싣는다. 파일을 새로 읽지 않는다 — 그 로딩 실패가 바로
        # 이 예외의 원인일 수 있어, 재시도는 같은 실패를 반복할 뿐이다.
        reports = summary.get("reports", {}) if isinstance(summary, dict) else {}

        tb_last = traceback.extract_tb(e.__traceback__)
        where = (f"{tb_last[-1].filename}:{tb_last[-1].lineno} in {tb_last[-1].name}"
                 if tb_last else "위치 불명")
        decision = {
            "gate_status":    "ERROR",
            "blocked":        True,
            "block_reasons":  ["게이트 실행 실패 — 판단 불가로 차단", err_txt],
            "warnings":       [
                "게이트가 끝까지 실행되지 않아 검사 결과를 신뢰할 수 없습니다. "
                "Actions 로그를 확인하세요.",
                f"예외 발생 위치: {where}",
            ],
            "total_findings": 0,
            "reports":        reports,
            "findings":       [],
        }
    else:
        cve_result = load_cve_decision(policy)
        try:
            decision = apply_cve_track(decision, cve_result, policy)
        except Exception as e:
            # 보정 레이어의 어떤 예외도 게이트를 조용히 무너뜨리면 안 된다.
            # 산출물(gate-decision.json)은 반드시 쓰고, 안전하게 차단(fail-closed)한다.
            decision["blocked"] = True
            decision["gate_status"] = "FAILED"
            decision.setdefault("block_reasons", []).append(
                f"CVE 보정 트랙 처리 중 예외 발생({type(e).__name__}) — "
                f"안전하게 차단합니다(fail-closed)."
            )
            decision["cve_track"] = {
                "mode": policy.get("cveTrack", {}).get("enabled", "off"),
                "source": cve_result.get("source"),
                "failure_type": cve_result.get("failure_type"),
                "would_block": True,
                "error": f"{type(e).__name__}: {e}",
            }
            print(
                f"[ERROR] CVE 보정 트랙 예외 — fail-closed 처리: {type(e).__name__}: {e}",
                file=sys.stderr,
            )

    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    with open(DECISION_FILE, "w") as f:
        json.dump(decision, f, indent=2, ensure_ascii=False)

    print(f"[Gate Status] {decision['gate_status']}")
    for reason in decision["block_reasons"]:
        print(f"  [BLOCK] {reason}")
    for warning in decision["warnings"]:
        print(f"  [WARN]  {warning}")
    print(f"  Total findings: {decision['total_findings']}")

    ct_meta = decision.get("cve_track")
    if ct_meta and ct_meta.get("mode") != "off":
        print(
            f"  CVE track: mode={ct_meta['mode']} source={ct_meta['source']} "
            f"promoted={ct_meta.get('promoted')} demoted={ct_meta.get('demoted')} "
            f"applied={ct_meta.get('applied')} failure={ct_meta.get('failure_type')}"
        )
    if decision.get("suppression", {}).get("active"):
        print(f"  [BYPASS] CVE 트랙 우회 적용됨 — actor:{decision['suppression']['actor']}")

    if decision["blocked"]:
        print("\nMerge is BLOCKED by Security Gate.")
        sys.exit(1)
    else:
        print("\nSecurity Gate PASSED. Merge is allowed.")


if __name__ == "__main__":
    main()
