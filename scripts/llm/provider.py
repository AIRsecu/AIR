"""LLM 공급자 seam — 키만 넣으면 언제든 전환 (defense llm_patcher 미러).

우선순위(defense 와 동일 정신):
    AIR_LLM_PROVIDER 명시 → ANTHROPIC_API_KEY → GEMINI_API_KEY → GROQ_API_KEY
    → OPENAI_API_KEY → (아무 키도 없음)
아무 키도 없으면 HeuristicChatModel 을 반환한다 → 무키 CI 에서도 파이프라인이 죽지 않는다
(defense 의 '--heuristic / 무LLM 템플릿' 폴백과 같은 역할).

■ AI 에이전트(scripts/ai_agent/nodes.py, Digrass 소유) 채택 — 핸드오프 1줄:
      # 기존:  llm = ChatOpenAI(model="gpt-4o-mini", temperature=0)
      from llm.provider import make_chat_llm
      llm = make_chat_llm()
  반환값은 LangChain BaseChatModel 호환(.with_structured_output().invoke() 지원)이라
  그래프/프롬프트 로직은 그대로다. 모델명은 <PROVIDER>_MODEL 환경변수로 오버라이드.

■ 왜 완전 무-변경(env만) 전환은 안 되나:
  현재 nodes.py 가 model="gpt-4o-mini" 를 하드코딩 → OpenAI 호환 게이트웨이가 아닌
  공급자로는 env 만으로 바꿀 수 없다. 위 1줄 채택이 견고한 다중공급자 전환의 최소 조건.

무의존 부분(detect_provider / model_name / 휴리스틱 값)은 stdlib 만 사용 → 로컬 테스트 가능.
실제 모델 생성은 해당 공급자 패키지를 lazy import(선택 의존, requirements-llm.txt).
"""
from __future__ import annotations

import os
from typing import Any, Optional, get_args, get_origin

# 공급자 → 키 환경변수
PROVIDER_KEY_ENV = {
    "anthropic": "ANTHROPIC_API_KEY",
    "gemini": "GEMINI_API_KEY",
    "groq": "GROQ_API_KEY",
    "openai": "OPENAI_API_KEY",
}
# 자동 감지 우선순위 (defense 순서 + openai 말미)
DETECT_ORDER = ["anthropic", "gemini", "groq", "openai"]
# 공급자별 기본 모델 (모두 <PROVIDER>_MODEL 로 오버라이드 가능)
DEFAULT_MODEL = {
    "anthropic": "claude-haiku-4-5-20251001",
    "gemini": "gemini-2.0-flash",
    "groq": "llama-3.3-70b-versatile",
    "openai": "gpt-4o-mini",
}


def detect_provider() -> Optional[str]:
    """사용할 공급자명을 결정. 어떤 키도 없으면 None(→ 휴리스틱)."""
    forced = (os.environ.get("AIR_LLM_PROVIDER") or "").strip().lower()
    if forced == "heuristic":
        return None
    if forced in PROVIDER_KEY_ENV and os.environ.get(PROVIDER_KEY_ENV[forced]):
        return forced
    for name in DETECT_ORDER:
        if os.environ.get(PROVIDER_KEY_ENV[name]):
            return name
    return None


def model_name(provider: str) -> str:
    return os.environ.get(f"{provider.upper()}_MODEL", DEFAULT_MODEL[provider])


def make_chat_llm(temperature: float = 0.0) -> Any:
    """감지된 공급자의 LangChain 채팅모델을 반환. 무키면 HeuristicChatModel."""
    provider = detect_provider()
    if provider is None:
        return HeuristicChatModel()

    model = model_name(provider)
    if provider == "openai":
        from langchain_openai import ChatOpenAI  # lazy
        return ChatOpenAI(model=model, temperature=temperature)
    if provider == "groq":
        from langchain_groq import ChatGroq
        return ChatGroq(model=model, temperature=temperature)
    if provider == "gemini":
        from langchain_google_genai import ChatGoogleGenerativeAI
        return ChatGoogleGenerativeAI(model=model, temperature=temperature)
    if provider == "anthropic":
        from langchain_anthropic import ChatAnthropic
        return ChatAnthropic(model=model, temperature=temperature)
    raise ValueError(f"지원하지 않는 공급자: {provider}")


# ──────────────────────────────────────────────────────────────
# 무키 폴백 — LangChain BaseChatModel 의 최소 인터페이스만 흉내낸다.
# nodes.py 는 llm.with_structured_output(Schema).invoke(msgs) 만 쓰므로 그 경로만 지원.
# ──────────────────────────────────────────────────────────────
def conservative_value(name: str, annotation: Any) -> Any:
    """필드명/타입 기반 보수적 기본값 (LLM 없이도 스키마 인스턴스를 채우기 위함)."""
    lname = name.lower()
    if "false_positive" in lname:
        return False                       # 무키일 땐 '정탐'으로 보수적 처리
    if "need_more_context" in lname:
        return False
    if "final_risk" in lname or lname == "risk" or "severity" in lname:
        return "Medium"                    # 중립 심각도
    if _is_listish(annotation):            # List[...] / Optional[List[...]] 포함
        return []
    if annotation is bool:
        return False
    if annotation is int:
        return 0
    return "heuristic-fallback (no LLM key)"


def _is_listish(annotation: Any) -> bool:
    """List/tuple 및 Optional[List[...]] 같은 Union 래핑까지 재귀 판별."""
    if annotation in (list, tuple):
        return True
    origin = get_origin(annotation)
    if origin in (list, tuple):
        return True
    if origin is not None:                 # Union[...] 등
        return any(_is_listish(a) for a in get_args(annotation))
    return False


def conservative_instance(schema: Any) -> Any:
    """pydantic v2 모델 스키마를 필수필드만 보수값으로 채워 인스턴스화."""
    fields = getattr(schema, "model_fields", None)
    if fields is None:
        raise TypeError(f"pydantic 모델이 아님: {schema!r}")
    kwargs = {}
    for fname, info in fields.items():
        required = getattr(info, "is_required", lambda: False)()
        if required:
            kwargs[fname] = conservative_value(fname, getattr(info, "annotation", str))
    return schema(**kwargs)


class _HeuristicStructured:
    def __init__(self, schema: Any) -> None:
        self._schema = schema

    def invoke(self, _messages: Any) -> Any:
        return conservative_instance(self._schema)


class HeuristicChatModel:
    """LLM 키가 없을 때 쓰는 규칙기반 스텁. 파이프라인을 죽이지 않는다."""

    def with_structured_output(self, schema: Any) -> _HeuristicStructured:
        return _HeuristicStructured(schema)

    def invoke(self, _messages: Any) -> str:
        return "[heuristic] LLM 키 없음(ANTHROPIC/GEMINI/GROQ/OPENAI) → 규칙 기반 폴백"
