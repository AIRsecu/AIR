package com.shop.dto.charge;

import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotNull;

public record CreateChargeRequest(
        @NotNull @Min(1) @Max(1_000_000_000L) Long amount   // 1회 충전 상한 10억원
) {}
