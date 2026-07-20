"""provider seam 스모크 테스트 (무의존, stdlib). 실행: python scripts/llm/test_provider.py

실제 LangChain 모델 생성 경로는 CI(공급자 패키지 설치 환경)에서 검증되고,
여기서는 키 없이도 검증 가능한 공급자 감지/모델명/휴리스틱 값 로직만 다룬다.
"""
from __future__ import annotations

import os
import sys
import unittest
from typing import List, Optional

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))  # scripts/

from llm import provider  # noqa: E402

_KEYS = [
    "AIR_LLM_PROVIDER", "ANTHROPIC_API_KEY", "GEMINI_API_KEY", "GROQ_API_KEY",
    "OPENAI_API_KEY", "OLLAMA_MODEL", "OLLAMA_BASE_URL",
]


class DetectProviderTest(unittest.TestCase):
    def setUp(self):
        self._saved = {k: os.environ.pop(k, None) for k in _KEYS}

    def tearDown(self):
        for k, v in self._saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

    def test_no_key_returns_none(self):
        self.assertIsNone(provider.detect_provider())

    def test_priority_anthropic_over_openai(self):
        os.environ["ANTHROPIC_API_KEY"] = "x"
        os.environ["OPENAI_API_KEY"] = "y"
        self.assertEqual(provider.detect_provider(), "anthropic")

    def test_openai_when_only_openai(self):
        os.environ["OPENAI_API_KEY"] = "y"
        self.assertEqual(provider.detect_provider(), "openai")

    def test_forced_provider_wins_if_key_present(self):
        os.environ["ANTHROPIC_API_KEY"] = "x"
        os.environ["GROQ_API_KEY"] = "z"
        os.environ["AIR_LLM_PROVIDER"] = "groq"
        self.assertEqual(provider.detect_provider(), "groq")

    def test_forced_heuristic_returns_none(self):
        os.environ["OPENAI_API_KEY"] = "y"
        os.environ["AIR_LLM_PROVIDER"] = "heuristic"
        self.assertIsNone(provider.detect_provider())

    def test_model_name_env_override(self):
        os.environ["GROQ_MODEL"] = "llama-3.1-8b-instant"
        try:
            self.assertEqual(provider.model_name("groq"), "llama-3.1-8b-instant")
        finally:
            os.environ.pop("GROQ_MODEL", None)
        self.assertEqual(provider.model_name("openai"), provider.DEFAULT_MODEL["openai"])

    def test_forced_ollama_needs_no_key(self):
        os.environ["AIR_LLM_PROVIDER"] = "ollama"
        self.assertEqual(provider.detect_provider(), "ollama")

    def test_forced_local_alias(self):
        os.environ["AIR_LLM_PROVIDER"] = "local"
        self.assertEqual(provider.detect_provider(), "ollama")

    def test_ollama_config_preferred_over_cloud_key(self):
        # 로컬이 설정돼 있으면(모델/엔드포인트) 클라우드 키가 있어도 로컬을 택한다.
        os.environ["OPENAI_API_KEY"] = "y"
        os.environ["OLLAMA_MODEL"] = "qwen2.5-coder:7b"
        self.assertEqual(provider.detect_provider(), "ollama")

    def test_forced_cloud_wins_over_ollama_config(self):
        # AIR_LLM_PROVIDER 명시 강제는 로컬 자동감지보다 우선.
        os.environ["OLLAMA_MODEL"] = "qwen2.5-coder:7b"
        os.environ["GROQ_API_KEY"] = "z"
        os.environ["AIR_LLM_PROVIDER"] = "groq"
        self.assertEqual(provider.detect_provider(), "groq")

    def test_ollama_default_and_override_model(self):
        self.assertEqual(provider.model_name("ollama"), provider.DEFAULT_MODEL["ollama"])
        os.environ["OLLAMA_MODEL"] = "deepseek-coder:6.7b"
        self.assertEqual(provider.model_name("ollama"), "deepseek-coder:6.7b")


class HeuristicValueTest(unittest.TestCase):
    def test_false_positive_conservative(self):
        self.assertFalse(provider.conservative_value("is_false_positive", bool))

    def test_final_risk_neutral(self):
        self.assertEqual(provider.conservative_value("final_risk", str), "Medium")

    def test_list_field_empty(self):
        self.assertEqual(provider.conservative_value("decorators", List[str]), [])
        self.assertEqual(provider.conservative_value("tags", Optional[List[str]]), [])

    def test_bool_default_false(self):
        self.assertFalse(provider.conservative_value("need_more_context", bool))

    def test_heuristic_model_has_structured_output(self):
        m = provider.HeuristicChatModel()
        so = m.with_structured_output(object)
        self.assertTrue(hasattr(so, "invoke"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
