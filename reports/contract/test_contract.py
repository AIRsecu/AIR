"""정규 리포트 계약 스모크 테스트 (무의존, 표준 unittest).

실행:
  python reports/contract/test_contract.py
또는:
  python -m unittest discover -s reports/contract -p "test_*.py"
"""
from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import aggregate  # noqa: E402
from finding import Severity  # noqa: E402
from severity_map import normalize_severity  # noqa: E402

SAMPLES = Path(os.path.dirname(os.path.abspath(__file__))) / "samples"


class SeverityMapTest(unittest.TestCase):
    def test_three_vocabs_converge(self):
        # 3종 어휘 → 정규 taxonomy 1종
        self.assertEqual(normalize_severity("semgrep", "ERROR"), Severity.HIGH)
        self.assertEqual(normalize_severity("trivy", "CRITICAL"), Severity.CRITICAL)
        self.assertEqual(normalize_severity("zap", "High (Medium)"), Severity.HIGH)
        self.assertEqual(normalize_severity("ai", "Info"), Severity.INFO)
        self.assertEqual(normalize_severity("ir-runtime", "HIGH"), Severity.HIGH)

    def test_unknown_is_conservative_info(self):
        self.assertEqual(normalize_severity("semgrep", None), Severity.INFO)
        self.assertEqual(normalize_severity("zap", "bogus"), Severity.INFO)


class NormalizeCweTest(unittest.TestCase):
    """ZAP cweid 관용: 유효 CWE만, 0/-1/Unknown 은 None(상관 오염 방지)."""

    def test_valid_ids(self):
        from finding import normalize_cwe
        self.assertEqual(normalize_cwe("89"), "CWE-89")
        self.assertEqual(normalize_cwe("CWE-79"), "CWE-79")
        self.assertEqual(normalize_cwe("693"), "CWE-693")

    def test_zap_no_cwe_ids_become_none(self):
        from finding import normalize_cwe
        self.assertIsNone(normalize_cwe("0"))     # ← 회귀: 과거 'CWE-0'
        self.assertIsNone(normalize_cwe("-1"))
        self.assertIsNone(normalize_cwe("Unknown"))
        self.assertIsNone(normalize_cwe(None))


class AggregateTest(unittest.TestCase):
    def setUp(self):
        self.findings = aggregate.collect(SAMPLES)
        self.findings = aggregate.enrich_with_ai(self.findings, SAMPLES)
        self.report = aggregate.build_report(self.findings)

    def test_all_sources_collected(self):
        sources = self.report["totals"]["by_source"]
        for s in ("semgrep", "trivy", "zap", "ir-runtime"):
            self.assertIn(s, sources, f"{s} 소스가 통합에 누락됨")

    def test_cross_stage_correlation_on_sqli(self):
        # CWE-89: semgrep+zap(빌드)에서 발견 → ir-runtime(런타임)에서 대응
        cross = [c for c in self.report["correlations"] if c["cross_stage"]]
        self.assertTrue(cross, "빌드↔런타임 교차상관이 하나도 없음")
        keys = {c["correlation_key"] for c in cross}
        self.assertIn("CWE-89", keys)
        sqli = next(c for c in cross if c["correlation_key"] == "CWE-89")
        self.assertIn("ir-runtime", sqli["sources"])
        self.assertIn("semgrep", sqli["sources"])

    def test_ai_verdict_enriches_scanner_finding(self):
        # semgrep SQLi 는 AI 정탐 판정이 보강되어야 한다
        semgrep_sqli = next(
            f for f in self.report["findings"]
            if f["source"] == "semgrep" and f["cwe"] == "CWE-89"
        )
        self.assertIsNotNone(semgrep_sqli["verdict"])
        self.assertFalse(semgrep_sqli["verdict"]["is_false_positive"])

    def test_ai_false_positive_marked(self):
        # XSS 는 오탐으로 판정되어 verdict.is_false_positive=True
        xss = next(
            f for f in self.report["findings"]
            if f["source"] == "semgrep" and f["cwe"] == "CWE-79"
        )
        self.assertTrue(xss["verdict"]["is_false_positive"])

    def test_contract_shape_is_stable(self):
        f = self.report["findings"][0]
        for key in ("id", "source", "stage", "severity", "type", "location", "correlation_key"):
            self.assertIn(key, f)


class TrivyLocationTest(unittest.TestCase):
    """의존성 취약점 위치 회귀: 언어명 target('Java')이 위치를 덮으면 안 된다."""

    def _where(self, finding_contract: dict) -> str:
        loc = finding_contract.get("location") or {}
        return loc.get("file") or loc.get("endpoint") or loc.get("url") or loc.get("package") or "-"

    def test_language_target_does_not_pollute_location(self):
        from adapters import from_trivy
        # 이미지 스캔 jar 집계 → Target="Java" (언어명). 실제 위치는 패키지 좌표여야 한다.
        item = {
            "target": "Java", "cve_id": "CVE-2016-1000027", "severity": "CRITICAL",
            "package_name": "org.springframework:spring-web", "installed_version": "5.3.20",
            "fixed_version": "6.0.0", "title": "Spring deserialization",
        }
        f = from_trivy.to_findings([item])[0].to_contract()
        self.assertNotEqual(self._where(f), "Java")          # ← 회귀: 과거 위치='Java'
        self.assertEqual(f["location"].get("package"), "org.springframework:spring-web@5.3.20")

    def test_pkg_path_becomes_file_when_present(self):
        from adapters import from_trivy
        item = {
            "target": "Java", "cve_id": "CVE-2021-44228", "severity": "CRITICAL",
            "package_name": "org.apache.logging.log4j:log4j-core", "installed_version": "2.14.1",
            "pkg_path": "app/BOOT-INF/lib/log4j-core-2.14.1.jar",
        }
        f = from_trivy.to_findings([item])[0].to_contract()
        self.assertEqual(f["location"].get("file"), "app/BOOT-INF/lib/log4j-core-2.14.1.jar")
        self.assertEqual(self._where(f), "app/BOOT-INF/lib/log4j-core-2.14.1.jar")

    def test_real_path_target_is_kept_as_file(self):
        from adapters import from_trivy
        # OS/파일 스캔 등 target 이 실제 경로면 그대로 file 로 인정한다.
        item = {
            "target": "pom.xml", "cve_id": "CVE-0000-0001", "severity": "HIGH",
            "package_name": "com.example:lib", "installed_version": "1.0",
        }
        f = from_trivy.to_findings([item])[0].to_contract()
        self.assertEqual(f["location"].get("file"), "pom.xml")


class AiAdapterToleranceTest(unittest.TestCase):
    """Digrass 모델(model_dump)이 fp_reason/impact_reason 로 뱉어도 수용해야 한다."""

    def test_reason_key_tolerance(self):
        from adapters import from_ai
        rec = {
            "scan_tool": "SAST", "rule_id": "r1", "cwe": "CWE-89",
            "triage": {"is_false_positive": False, "fp_reason": "raw concat"},
            "assessment": {"final_risk": "High", "impact_reason": "internet-facing"},
        }
        f = from_ai.to_findings([rec])[0]
        self.assertFalse(f.verdict.is_false_positive)
        self.assertEqual(f.verdict.reason, "internet-facing")
        self.assertEqual(f.severity.value, "HIGH")


class EnrichRobustnessTest(unittest.TestCase):
    """ai_findings.json 이 없거나(무키/미배출) 형식이 어긋나도 통합이 죽으면 안 된다."""

    def test_absent_ai_findings_leaves_findings_unchanged(self):
        import tempfile
        findings = aggregate.collect(SAMPLES)
        before = len(findings)
        with tempfile.TemporaryDirectory() as d:
            # summary/ai_findings.json 이 없는 디렉터리 → 보강 없이 그대로 통과
            out = aggregate.enrich_with_ai(findings, Path(d))
        self.assertEqual(len(out), before)
        self.assertTrue(all(f.verdict is None for f in out))

    def test_malformed_ai_findings_is_ignored(self):
        import json as _json
        import tempfile
        findings = aggregate.collect(SAMPLES)
        before = len(findings)
        with tempfile.TemporaryDirectory() as d:
            summary = Path(d) / "summary"
            summary.mkdir()
            # list 가 아닌 형식(객체) → enrich_with_ai 가 방어적으로 무시해야 함
            (summary / "ai_findings.json").write_text(
                _json.dumps({"unexpected": "shape"}), encoding="utf-8"
            )
            out = aggregate.enrich_with_ai(findings, Path(d))
        self.assertEqual(len(out), before)


if __name__ == "__main__":
    unittest.main(verbosity=2)
