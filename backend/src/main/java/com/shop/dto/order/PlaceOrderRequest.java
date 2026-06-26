package com.shop.dto.order;

import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;

import java.util.List;

public record PlaceOrderRequest(
        @NotEmpty List<ItemLine> items
) {
    public record ItemLine(
            @NotBlank String productId,
            @NotNull @Min(1) Integer quantity
    ) {}
}
