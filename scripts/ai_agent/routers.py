from state import SecurityState

# 최대 재시도(Loop-back) 횟수 설정 (무한 루프 방지)
MAX_LOOPS = 2

def route_after_phase3(state: SecurityState) -> str:
    """
    [1차 검증 라우터: 논리/팩트 검증 후 흐름 제어]
    Routes traffic after Phase 3 (Logic Validator).
    - 실패 시: Validator가 지목한 노드(Phase_1 또는 Phase_2)로 타겟 회귀.
    - 성공 시 (FP): 코드 수정(Phase_4, 5)을 스킵하고 위험도 평가(Phase_6)로 직행.
    - 성공 시 (TP): 원인 분석 및 코드 수정(Phase_4)으로 진입.
    """
    validation = state.get("logic_validation")
    triage = state.get("triage")
    loop_count = state.get("loop_count", 0)

    # 1. Check if we need to loop back (Logic Validation Failed)
    if not validation.is_valid and loop_count < MAX_LOOPS:
        # Validator가 지목한 노드(Phase_1 or Phase_2)를 가져오되, 없으면 기본값 Phase_1 사용
        target_node = getattr(validation, "target_retry_node", "Phase_1") or "Phase_1"
        print(f"  [🔄 Logic Loop Back] Validation failed. Returning to {target_node}. (Attempt: {loop_count}/{MAX_LOOPS})")
        return target_node

    # 2. Proceed forward (Passed validation OR Max loops reached)
    if not validation.is_valid:
        print(f"  [⚠️ Circuit Breaker] Max logic loops ({MAX_LOOPS}) reached. Forcing progression despite logic validation failure.")
    else:
        print(f"  [✅ Passed] Logic validation successful on attempt {loop_count}.")

    # 3. Final branching based on Triage result
    if triage and triage.is_false_positive:
        # 오탐(FP)은 원인분석(Phase 4)과 코드검증(Phase 5)을 생략하고 위험도 평가(Phase 6)로 이동
        return "Phase_6"
    else:
        # 정탐(TP)은 코드를 고치기 위해 Phase 4로 이동
        return "Phase_4"


def route_after_phase5(state: SecurityState) -> str:
    """
    [2차 검증 라우터: 해결책/코드 검증 후 흐름 제어]
    Routes traffic after Phase 5 (Remediation Validator).
    - 실패 시: 무조건 Phase_4(원인 분석/수정 코드)로만 회귀.
    - 성공 시: 위험도 평가(Phase_6)로 진입.
    """
    validation = state.get("remediation_validation")
    remediation_loop_count = state.get("remediation_loop_count", 0)

    # 1. Check if we need to loop back (Remediation Validation Failed)
    if not validation.is_valid and remediation_loop_count < MAX_LOOPS:
        print(f"  [🔄 Remediation Loop Back] Remediation validation failed. Returning to Phase_4. (Attempt: {remediation_loop_count}/{MAX_LOOPS})")
        return "Phase_4"

    # 2. Proceed forward (Passed validation OR Max loops reached)
    if not validation.is_valid:
        print(f"  [⚠️ Circuit Breaker] Max remediation loops ({MAX_LOOPS}) reached. Forcing progression to Phase_6.")
    else:
        print(f"  [✅ Passed] Remediation remediation validation successful on attempt {remediation_loop_count}.")

    # 3. 코드 검증이 완료되었으므로 최종 위험도 평가(Phase_6)로 이동
    return "Phase_6"