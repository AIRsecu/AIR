package com.shop.domain;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

/**
 * 잔액 충전 요청 - customer 가 제출, 해당 테넌트 admin 이 승인/반려.
 * 승인 시 users.balance 가 amount 만큼 증가한다.
 */
@Getter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ChargeRequest {

    public enum Status { pending, approved, rejected }

    private String id;
    private String tenantId;
    private String userId;
    private String username;      // 표시용
    private long   amount;
    private String status;        // pending | approved | rejected
    private String rejectReason;
    private String reviewedBy;
    private LocalDateTime reviewedAt;
    private LocalDateTime createdAt;
}
