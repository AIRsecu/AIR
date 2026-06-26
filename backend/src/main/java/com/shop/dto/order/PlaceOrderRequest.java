package com.shop.dto.order;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;

import java.util.List;

// [AIR vuln-lab] @Valid 캐스케이드를 의도적으로 제거 → 수량 제약 미적용(취약).
//   방어는 OrderService 의 order.qty-guard 플래그로 런타임 토글된다.
public record PlaceOrderRequest(
        @NotEmpty List<ItemLine> items
) {
    public record ItemLine(
            @NotBlank String productId,
            @NotNull Integer quantity
    ) {}
}
