package com.shop.domain;

import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

/**
 * 회원가입 요청 - customer 가 셀프로 제출, 해당 테넌트 admin 이 승인/반려.
 * 승인 시 users 테이블에 customer 계정이 생성된다.
 */
@Getter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class SignupRequest {

    public enum Status { pending, approved, rejected }

    private String id;
    private String tenantId;
    private String username;

    @JsonIgnore                 // 비밀번호 해시는 응답에 절대 노출하지 않음
    private String passwordHash;

    private String displayName;
    private String status;       // pending | approved | rejected
    private String rejectReason;
    private String reviewedBy;
    private LocalDateTime reviewedAt;
    private LocalDateTime createdAt;
}
