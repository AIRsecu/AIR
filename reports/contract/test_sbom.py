"""SBOM 정규화 스모크 테스트 (무의존, stdlib). 실행: python reports/contract/test_sbom.py"""
from __future__ import annotations

import json
import os
import sys
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import sbom  # noqa: E402

_DIR = Path(os.path.dirname(os.path.abspath(__file__)))
_SBOM = _DIR / "samples" / "sbom" / "sbom.cyclonedx.json"
_TRIVY = _DIR / "samples" / "trivy" / "trivy_for_llm.json"


def _load(p: Path):
    with open(p, encoding="utf-8") as f:
        return json.load(f)


class NormalizeTest(unittest.TestCase):
    def setUp(self):
        self.sbom = _load(_SBOM)
        self.trivy = _load(_TRIVY)

    def test_all_components_normalized(self):
        comps = sbom.normalize(self.sbom, None)
        self.assertEqual(len(comps), 3)

    def test_maven_group_name_canonicalized(self):
        comps = {c.name: c for c in sbom.normalize(self.sbom, None)}
        # group + name → 'group:name' (Trivy package_name 규약과 일치)
        self.assertIn("org.yaml:snakeyaml", comps)
        self.assertEqual(comps["org.yaml:snakeyaml"].ecosystem, "maven")
        # group 없는 npm 패키지는 name 그대로
        self.assertIn("lodash", comps)
        self.assertEqual(comps["lodash"].ecosystem, "npm")

    def test_licenses_extracted(self):
        comps = {c.name: c for c in sbom.normalize(self.sbom, None)}
        self.assertEqual(comps["lodash"].licenses, ["MIT"])
        self.assertIn("Apache-2.0", comps["org.yaml:snakeyaml"].licenses)

    def test_trivy_crossref_marks_vulnerable(self):
        comps = {c.name: c for c in sbom.normalize(self.sbom, self.trivy)}
        snake = comps["org.yaml:snakeyaml"]
        self.assertTrue(snake.vulnerabilities)
        self.assertEqual(snake.vulnerabilities[0]["cve_id"], "CVE-2022-1471")
        # 취약점 없는 컴포넌트는 빈 리스트
        self.assertEqual(comps["lodash"].vulnerabilities, [])

    def test_manifest_totals(self):
        comps = sbom.normalize(self.sbom, self.trivy)
        manifest = sbom.build_manifest(self.sbom, comps)
        self.assertEqual(manifest["totals"]["components"], 3)
        self.assertEqual(manifest["totals"]["vulnerable"], 1)
        self.assertEqual(manifest["totals"]["by_ecosystem"]["maven"], 2)
        self.assertEqual(manifest["source_format"], "CycloneDX/1.5")

    def test_markdown_renders_and_flags_vuln(self):
        comps = sbom.normalize(self.sbom, self.trivy)
        md = sbom.render_markdown(sbom.build_manifest(self.sbom, comps))
        self.assertIn("SBOM", md)
        self.assertIn("CVE-2022-1471", md)

    def test_empty_sbom_is_safe(self):
        self.assertEqual(sbom.normalize({}, None), [])
        self.assertEqual(sbom.normalize({"components": []}, None), [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
