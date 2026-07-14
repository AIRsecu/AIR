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

| 공급자 | 필요 키/설정 | 모델 오버라이드 | 비고 |
|---|---|---|---|
| **로컬(Ollama)** | **키 불필요** — `AIR_LLM_PROVIDER=ollama` 또는 `OLLAMA_MODEL`/`OLLAMA_BASE_URL` | `OLLAMA_MODEL` | **★ 멘토 권고 기본**(아래) |
| OpenAI | `OPENAI_API_KEY` | `OPENAI_MODEL` | gpt-4o-mini |
| Groq | `GROQ_API_KEY` | `GROQ_MODEL` | 무료·빠름 |
| Gemini | `GEMINI_API_KEY` | `GEMINI_MODEL` | 무료 티어 |
| Anthropic | `ANTHROPIC_API_KEY` | `ANTHROPIC_MODEL` | 크레딧 |
| 강제 지정 | `AIR_LLM_PROVIDER=groq` 등 | — | 여러 키 있을 때 |
| 무키 | (없음) | — | 휴리스틱 폴백 |

우선순위: `AIR_LLM_PROVIDER` → **OLLAMA(설정 감지)** → ANTHROPIC → GEMINI → GROQ → OPENAI → 휴리스틱.

### ★ 로컬 LLM(Ollama) — 멘토 권고 기본 경로

API 키로 외부에 취약점·소스코드를 보내는 대신 localhost 에서 추론합니다(보안 과제 기밀성 + 키 rotate 부담 제거). Ollama 의 OpenAI 호환 엔드포인트를 재사용하므로 **추가 파이썬 패키지 불필요**.
```
ollama pull qwen2.5-coder:7b      # 코드 이해·구조화출력에 강한 모델
export AIR_LLM_PROVIDER=ollama    # 또는 export OLLAMA_MODEL=qwen2.5-coder:7b
python scripts/ai_agent/run_ai_pipeline.py   # 또는 bash scripts/llm/run-ai.sh
```
설정만 있으면 **클라우드 키보다 로컬을 우선**합니다. 주의: `.with_structured_output()` 안정성은 모델별로 다르니 코드계열 모델(`qwen2.5-coder`, `deepseek-coder`) 권장. **CI(GitHub 러너)는 Ollama 부재 → env 미설정으로 두고 휴리스틱/키 폴백 유지**(로컬은 데모/EC2 주 경로).

## 선택 의존

로컬(Ollama)은 별도 파이썬 패키지가 필요 없습니다. OpenAI 외 **클라우드** 공급자로 전환할 때만 설치(병록이 `scripts/llm/requirements-llm.txt` 준비):
```
pip install langchain-groq   # 또는 langchain-google-genai / langchain-anthropic
```

## 침해 경계

병록은 `scripts/llm/`(신규) 만 소유합니다. `nodes.py` 의 위 1줄 교체는 **Digrass 결정**이며,
채택 전에도 기존 `ChatOpenAI` 그대로 동작합니다(seam 은 옵트인).
