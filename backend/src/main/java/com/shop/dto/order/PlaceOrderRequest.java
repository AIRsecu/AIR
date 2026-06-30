package com.shop.dto.order;

import jakarta.validation.Valid;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

import java.util.List;

public record PlaceOrderRequest(
        @NotEmpty @Size(max = 100) List<@Valid ItemLine> items   // 중첩 제약 캐스케이드 검증
) {
    public record ItemLine(
            @NotBlank String productId,
            @NotNull @Min(1) @Max(100000) Integer quantity
    ) {}
}
