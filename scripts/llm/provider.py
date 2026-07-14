"""LLM 공급자 seam — 키만 넣으면 언제든 전환 (defense llm_patcher 미러).

우선순위(defense 와 동일 정신 + 로컬 우선):
    AIR_LLM_PROVIDER 명시 → OLLAMA(로컬) 설정 감지 → ANTHROPIC_API_KEY
    → GEMINI_API_KEY → GROQ_API_KEY → OPENAI_API_KEY → (아무 것도 없음)
아무 것도 없으면 HeuristicChatModel 을 반환한다 → 무키 CI 에서도 파이프라인이 죽지 않는다
(defense 의 '--heuristic / 무LLM 템플릿' 폴백과 같은 역할).

■ 로컬 LLM(Ollama) — API 키 없이 자체 구동 (보안 과제 권장 경로):
  취약점·소스코드를 외부 API 로 보내지 않고 localhost 에서 추론한다. Ollama 의 OpenAI 호환
  엔드포인트(기본 http://localhost:11434/v1)를 통해 기존 ChatOpenAI 경로를 재사용한다.
  활성화 조건(둘 중 하나):
      AIR_LLM_PROVIDER=ollama   (명시)               또는
      OLLAMA_MODEL / OLLAMA_BASE_URL 를 설정          (설정만으로 클라우드 키보다 우선)
  모델 오버라이드: OLLAMA_MODEL (기본 qwen2.5-coder:7b — 코드 이해·구조화출력에 강함).
  엔드포인트 오버라이드: OLLAMA_BASE_URL.
  ※ CI(GitHub-hosted 러너)는 Ollama 구동이 비현실적이므로, CI 에서는 이 env 를 두지 말고
    무키 휴리스틱 폴백을 유지한다. 로컬 LLM 은 데모/EC2 등 실행 환경의 주 추론 경로다.

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
# 로컬(Ollama) 기본값
OLLAMA_DEFAULT_BASE_URL = "http://localhost:11434/v1"
# 공급자별 기본 모델 (모두 <PROVIDER>_MODEL 로 오버라이드 가능)
DEFAULT_MODEL = {
    "anthropic": "claude-haiku-4-5-20251001",
    "gemini": "gemini-2.0-flash",
    "groq": "llama-3.3-70b-versatile",
    "openai": "gpt-4o-mini",
    "ollama": "qwen2.5-coder:7b",
}


def _ollama_configured() -> bool:
    """OLLAMA_MODEL / OLLAMA_BASE_URL 중 하나라도 설정돼 있으면 로컬 사용 의사로 본다."""
    return bool(os.environ.get("OLLAMA_MODEL") or os.environ.get("OLLAMA_BASE_URL"))


def detect_provider() -> Optional[str]:
    """사용할 공급자명을 결정. 아무것도 없으면 None(→ 휴리스틱).

    우선순위: AIR_LLM_PROVIDER(명시) → OLLAMA 설정 감지 → 클라우드 키 → None.
    로컬(Ollama)은 '설정만으로' 클라우드 키보다 우선한다(멘토 권고: 키 대신 로컬).
    """
    forced = (os.environ.get("AIR_LLM_PROVIDER") or "").strip().lower()
    if forced == "heuristic":
        return None
    if forced in ("ollama", "local"):
        return "ollama"
    if forced in PROVIDER_KEY_ENV and os.environ.get(PROVIDER_KEY_ENV[forced]):
        return forced
    # 명시 강제가 없으면 로컬 설정을 클라우드 키보다 먼저 채택.
    if _ollama_configured():
        return "ollama"
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
    if provider == "ollama":
        # Ollama 는 OpenAI 호환 API 를 노출 → ChatOpenAI 를 로컬 엔드포인트로 재사용.
        # 키 검증을 하지 않으므로 더미 키를 넣는다(라이브러리 필수 인자 회피).
        from langchain_openai import ChatOpenAI  # lazy
        base_url = os.environ.get("OLLAMA_BASE_URL", OLLAMA_DEFAULT_BASE_URL)
        return ChatOpenAI(
            model=model, temperature=temperature,
            base_url=base_url, api_key="ollama",
        )
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
