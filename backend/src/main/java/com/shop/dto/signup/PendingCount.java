package com.shop.dto.signup;

/** 테넌트별 대기 알림 개수 (주문 + 가입요청 + 충전요청) */
public record PendingCount(String tenantId, String tenantName,
                           int signupCount, int chargeCount, int orderCount) {}
