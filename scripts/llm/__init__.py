"""LLM 공급자 seam (병록 인프라 레인).

키만 넣으면 언제든 공급자를 전환할 수 있게 하는 config/infra 계층.
defense 의 air-orchestrator/llm_patcher._provider() 패턴을 CI 에이전트용으로 미러링한다.
AI 에이전트 로직(scripts/ai_agent/, Digrass 소유)은 건드리지 않는다 — import 로만 제공.
"""
