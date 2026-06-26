package com.shop.dto.charge;

import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotNull;

public record CreateChargeRequest(
        @NotNull @Min(1) Long amount
) {}
