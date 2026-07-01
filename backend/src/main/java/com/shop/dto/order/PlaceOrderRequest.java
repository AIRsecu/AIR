package com.shop.dto.order;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;

import java.util.List;

// [취약/web] @Valid 캐스케이드·수량 제약(@Min/@Max/@Size) 제거 → 음수·과대 수량 주문 허용.
//           web = 방어 없는 공격 대상. (defense 는 order.qty-guard 플래그로 방어)
public record PlaceOrderRequest(
        @NotEmpty List<ItemLine> items
) {
    public record ItemLine(
            @NotBlank String productId,
            Integer quantity                 // 제약 없음: 음수/0/초대형 통과
    ) {}
}
