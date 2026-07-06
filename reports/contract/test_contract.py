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


if __name__ == "__main__":
    unittest.main(verbosity=2)
