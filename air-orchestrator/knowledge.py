#!/usr/bin/env python3
"""
AIR 취약점 지식베이스.
인시던트 유형 → (취약 파일, 방어 키, 검증 시나리오, 템플릿 폴백 패치, 패치 검증식)
템플릿은 LLM 실패 시 사용하는 결정적 폴백. vuln-lab 코드의 정확한 문자열에 의존.
"""

# ── 템플릿 폴백 패치 ───────────────────────────────────────────
def _template_order_qty(file_rel_path, original):
    """OrderService 의 방어 가드를 플래그 무관하게 영구 활성화."""
    if "OrderService.java" not in file_rel_path:
        return None
    needle = "boolean guard = defense.isEnabled(DefenseRegistry.ORDER_QTY_GUARD);"
    if needle not in original:
        return None
    return original.replace(
        needle,
        "boolean guard = true; // [AIR auto-patch/template] 음수수량 방어 영구 활성화(플래그 무관)",
    )

# ── 패치 검증식 (정적): 패치 결과가 취약 패턴을 제거했는지 ──────
def _validate_order_qty(file_rel_path, patched):
    if "OrderService.java" not in file_rel_path:
        return True  # 다른 파일은 이 검증 대상 아님
    # 취약 경로: 'if (guard)' 분기로 가드를 우회 가능한 상태가 남아있으면 실패로 간주.
    # 가드가 무조건 활성(guard=true)이거나 음수수량 거부가 무조건 실행되면 통과.
    if "boolean guard = true" in patched:
        return True
    # LLM 이 다른 방식(무조건 거부)으로 고쳤을 수도 있으니, 음수수량 거부 메시지가
    # 플래그 밖(무조건)에서 실행되는지 느슨히 확인: 'guard' 변수 자체가 사라졌으면 통과.
    if "defense.isEnabled(DefenseRegistry.ORDER_QTY_GUARD)" not in patched:
        return True
    return False

VULNS = {
    "ORDER_NEGATIVE_QTY": {
        "files": ["backend/src/main/java/com/shop/service/OrderService.java"],
        "defense_key": "order.qty-guard",
        "scenario": "negative-qty",          # air-attack/attack.py 시나리오
        "template": _template_order_qty,
        "validate": _validate_order_qty,
    },
}
