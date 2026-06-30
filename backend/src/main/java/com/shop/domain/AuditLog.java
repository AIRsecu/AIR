package com.shop.domain;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

/**
 * 감사 로그 - 누가(actor), 어떤 리소스에(resource), 무엇을 했는지(action) 기록.
 * 삽입 전용(append-only), 수정/삭제 없음.
 */
@Getter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AuditLog {
    private String id;
    private String actorId;
    private String actorUsername;
    private String tenantId;
    private String action;          // CREATE_PRODUCT, DELETE_TENANT, LOGIN 등
    private String resourceType;    // user | tenant | product | order
    private String resourceId;
    private String detail;          // JSON 또는 자유 문자열
    private String ipAddress;
    private LocalDateTime createdAt;
}
