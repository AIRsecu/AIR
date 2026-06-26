package com.shop.dto.product;

public record UpdateProductRequest(
        String name, String description, Long price, Integer stock,
        String category, String imageUrl, Boolean isActive
) {}
