# 핸드오프 → Digrass: AI 에이전트 LLM 공급자 seam 채택 (1줄)

병록이 `scripts/llm/provider.py`(공급자 자동감지 + 무키 휴리스틱 폴백)를 준비했습니다.
defense `air-orchestrator/llm_patcher` 와 같은 정신 — **키만 넣으면 언제든 공급자 전환**,
아무 키도 없으면 규칙기반 폴백으로 CI 가 죽지 않습니다.

## 바꿀 것 — `scripts/ai_agent/nodes.py` 단 1곳

```diff
- from langchain_openai import ChatOpenAI
- llm = ChatOpenAI(model="gpt-4o-mini", temperature=0)
+ from llm.provider import make_chat_llm
+ llm = make_chat_llm(temperature=0)   # 공급자/모델은 env 로 결정
```

- 반환값은 LangChain 모델(`.with_structured_output(...).invoke(...)`)이라 **그래프/프롬프트 로직 변경 0**.
- `run_ai_pipeline.py` 실행 시 `PYTHONPATH` 에 `scripts/` 가 있어야 `import llm.provider` 해석됨
  → 병록의 `scripts/llm/run-ai.sh` 가 이미 설정해 줍니다(CI 는 이 래퍼로 호출).

## 공급자 전환 방법 (코드 변경 없이 env 만)

| 공급자 | 필요 키(GitHub Secret) | 모델 오버라이드 | 비고 |
|---|---|---|---|
| OpenAI | `OPENAI_API_KEY` | `OPENAI_MODEL` | 현행 기본(gpt-4o-mini) |
| Groq | `GROQ_API_KEY` | `GROQ_MODEL` | 무료·빠름 |
| Gemini | `GEMINI_API_KEY` | `GEMINI_MODEL` | 무료 티어 |
| Anthropic | `ANTHROPIC_API_KEY` | `ANTHROPIC_MODEL` | 크레딧 |
| 강제 지정 | `AIR_LLM_PROVIDER=groq` 등 | — | 여러 키 있을 때 |
| 무키 | (없음) | — | 휴리스틱 폴백 |

우선순위: `AIR_LLM_PROVIDER` → ANTHROPIC → GEMINI → GROQ → OPENAI → 휴리스틱.

## 선택 의존

OpenAI 외 공급자로 전환할 때만 해당 패키지 설치(병록이 `scripts/llm/requirements-llm.txt` 준비):
```
pip install langchain-groq   # 또는 langchain-google-genai / langchain-anthropic
```

## 침해 경계

병록은 `scripts/llm/`(신규) 만 소유합니다. `nodes.py` 의 위 1줄 교체는 **Digrass 결정**이며,
채택 전에도 기존 `ChatOpenAI` 그대로 동작합니다(seam 은 옵트인).
