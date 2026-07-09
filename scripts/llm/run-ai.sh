#!/usr/bin/env bash
# AI 위험재평가 파이프라인을 provider seam 경유로 실행 (병록 래퍼).
#
# - PYTHONPATH 에 scripts/ 를 추가해 nodes.py 가 `from llm.provider import make_chat_llm`
#   을 해석할 수 있게 한다(Digrass 채택 후 효력).
# - 공급자는 존재하는 *_API_KEY 로 자동 감지. AIR_LLM_PROVIDER 로 강제 가능.
# - 무키/실패 시에도 통합 리포트는 스캔 결과만으로 생성돼야 하므로 non-blocking.
set -uo pipefail

export PYTHONPATH="$(pwd)/scripts:${PYTHONPATH:-}"

PROV=$(python -c "from llm.provider import detect_provider; print(detect_provider() or 'heuristic(no-key)')")
echo "[run-ai] provider=${PROV}"

if ! python scripts/ai_agent/run_ai_pipeline.py; then
  echo "[run-ai] AI 파이프라인 비정상 종료(무키/무설정 가능) — 계속 진행(non-blocking)."
fi
exit 0
