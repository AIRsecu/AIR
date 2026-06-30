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
public class Tenant {
    private String id;
    private String name;
    private String slug;          // URL 식별자
    private String domain;        // 커스텀 접속 도메인 (선택)
    private String ownerId;       // admin user
    private String description;
    private String logoUrl;
    private boolean isActive;
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;
}
