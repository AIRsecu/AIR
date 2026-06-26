package com.shop.dto.auth;

public record LoginResponse(
        String accessToken,
        String refreshToken,
        String userId,
        String username,
        String role,
        String tenantId
) {}
