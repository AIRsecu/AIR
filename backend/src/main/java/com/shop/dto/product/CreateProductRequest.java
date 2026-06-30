package com.shop.dto.product;

import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

public record CreateProductRequest(
        @NotBlank String name,
        String description,
        @NotNull @Min(0) Long price,
        @NotNull @Min(0) Integer stock,
        String category,
        String imageUrl
) {}
