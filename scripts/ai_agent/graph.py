from langgraph.graph import StateGraph, START, END
from state import SecurityState
from nodes import (
    node_phase1_extractor,
    node_phase2_triage,
    node_phase3_assessor,
    node_phase4_reporter,
    route_after_triage
)

# 1. 그래프 초기화
workflow = StateGraph(SecurityState)

# 2. 노드 등록
workflow.add_node("Phase_1", node_phase1_extractor)
workflow.add_node("Phase_2", node_phase2_triage)
workflow.add_node("Phase_3", node_phase3_assessor)
workflow.add_node("Phase_4", node_phase4_reporter)

# 3. 엣지 연결
workflow.add_edge(START, "Phase_1")
workflow.add_edge("Phase_1", "Phase_2")

# 오탐 분류
workflow.add_conditional_edges(
    "Phase_2",
    route_after_triage,
    {
        "Phase_3": "Phase_3",
        "Phase_4": "Phase_4"
    }
)

workflow.add_edge("Phase_3", "Phase_4")
workflow.add_edge("Phase_4", END)

security_pipeline = workflow.compile()