from langgraph.graph import StateGraph, START, END
from state import SecurityState

from nodes import (
    node_phase1_explorer,         #  탐색
    node_phase2_triage,           #  오탐 분류
    node_phase3_logic_validator,  #  사실/논리 검증
    node_phase4_root_cause,       #  원인 분석/해결책
    node_phase5_remediation_validator,   #  원인/해결책 무결성 검증
    node_phase6_risk_assessor,    #  위험도 재평가
    node_phase7_reporter          #  마크다운 리포트 작성
)
from routers import route_after_phase3, route_after_phase5

# 1. Initialize StateGraph with our Pydantic-driven State
workflow = StateGraph(SecurityState)

# 2. Register all Nodes (Phase 1 to 7)
workflow.add_node("Phase_1", node_phase1_explorer)
workflow.add_node("Phase_2", node_phase2_triage)
workflow.add_node("Phase_3", node_phase3_logic_validator)
workflow.add_node("Phase_4", node_phase4_root_cause)
workflow.add_node("Phase_5", node_phase5_remediation_validator)
workflow.add_node("Phase_6", node_phase6_risk_assessor)
workflow.add_node("Phase_7", node_phase7_reporter)

# 3. Define Edges and Conditional Routing

# [기본 흐름 1] 탐색 -> 판결 -> 1차 검증
workflow.add_edge(START, "Phase_1")
workflow.add_edge("Phase_1", "Phase_2")
workflow.add_edge("Phase_2", "Phase_3")

# [Routing 1] After Logic Validator (Phase 3) - 1차 타겟 회귀 엔진
workflow.add_conditional_edges(
    "Phase_3",
    route_after_phase3,
    {
        "Phase_1": "Phase_1",  # 팩트 오류 시 Phase 1로 타겟 회귀
        "Phase_2": "Phase_2",  # 논리 오류 시 Phase 2로 타겟 회귀
        "Phase_4": "Phase_4",  # 검증 성공 (TP) -> 원인 분석 및 코드 수정 진행
        "Phase_6": "Phase_6"   # 검증 성공 (FP) -> 코드 수정 스킵하고 위험도 평가로 직행
    }
)

# [기본 흐름 2] 원인 분석/코드 수정 -> 2차 검증
workflow.add_edge("Phase_4", "Phase_5")

# [Routing 2] After Code Validator (Phase 5) - 2차 회귀 엔진
workflow.add_conditional_edges(
    "Phase_5",
    route_after_phase5,
    {
        "Phase_4": "Phase_4",  # 코드 검증 실패 시 Phase 4로만 회귀
        "Phase_6": "Phase_6"   # 코드 검증 성공 시 위험도 평가로 진행
    }
)

# 위험도 평가 -> 리포트 생성 -> 종료
workflow.add_edge("Phase_6", "Phase_7")
workflow.add_edge("Phase_7", END)

# 4. Compile the Pipeline
security_pipeline = workflow.compile()