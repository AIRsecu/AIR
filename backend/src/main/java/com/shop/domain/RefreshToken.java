package com.shop.domain;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Getter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class RefreshToken {
    private String id;
    private String userId;
    private String tokenHash;
    private LocalDateTime expiresAt;
    private LocalDateTime revokedAt;
    private String replacedBy;
    private String userAgent;
    private LocalDateTime createdAt;

    public boolean isRevoked()           { return revokedAt != null; }
    public boolean isExpired(LocalDateTime now) { return now.isAfter(expiresAt); }
}
