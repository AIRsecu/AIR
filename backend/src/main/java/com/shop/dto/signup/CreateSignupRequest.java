package com.shop.dto.signup;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record CreateSignupRequest(
        @NotBlank @Size(min = 3, max = 30) String username,
        @NotBlank @Size(min = 8, max = 72) String password,
        String displayName
) {}
