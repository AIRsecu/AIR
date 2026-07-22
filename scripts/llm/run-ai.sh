#!/usr/bin/env bash
# AI 위험재평가 파이프라인을 provider seam 경유로 실행 (병록 래퍼).
#
# - PYTHONPATH 에 scripts/ 를 추가해 nodes.py 가 `from llm.provider import make_chat_llm`
#   을 해석할 수 있게 한다(Digrass 채택 후 효력).
# - 공급자 우선순위: AIR_LLM_PROVIDER 명시 → OLLAMA(로컬) 설정 → *_API_KEY 자동감지 → 휴리스틱.
# - 로컬 LLM(Ollama, 키 불필요)은 데모/EC2 실행의 주 경로: `AIR_LLM_PROVIDER=ollama` 또는
#   OLLAMA_MODEL/OLLAMA_BASE_URL 설정 시 활성(클라우드 키보다 우선). CI 는 env 미설정→휴리스틱.
# - 무키/실패 시에도 통합 리포트는 스캔 결과만으로 생성돼야 하므로 non-blocking.
set -uo pipefail

export PYTHONPATH="$(pwd)/scripts:${PYTHONPATH:-}"

PROV=$(python -c "from llm.provider import detect_provider; print(detect_provider() or 'heuristic(no-key)')")
if [ "${PROV}" = "ollama" ]; then
  MODEL=$(python -c "from llm.provider import model_name; print(model_name('ollama'))")
  echo "[run-ai] provider=ollama(local) model=${MODEL} base=${OLLAMA_BASE_URL:-http://localhost:11434/v1}"
else
  echo "[run-ai] provider=${PROV}"
fi

if ! python scripts/ai_agent/run_ai_pipeline.py; then
  echo "[run-ai] AI 파이프라인 비정상 종료(무키/무설정 가능) — 계속 진행(non-blocking)."
fi
exit 0
