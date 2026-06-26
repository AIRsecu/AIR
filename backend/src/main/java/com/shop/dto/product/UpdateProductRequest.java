package com.shop.dto.product;

import jakarta.validation.constraints.Min;

public record UpdateProductRequest(
        String name, String description,
        @Min(0) Long price, @Min(0) Integer stock,
        String category, String imageUrl, Boolean isActive
) {}
