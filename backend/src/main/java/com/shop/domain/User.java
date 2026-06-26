package com.shop.domain;

import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.Set;

@Getter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class User {

    public enum Role { super_admin, admin, customer }

    private String id;
    private String username;
    private String passwordHash;
    private Role   role;
    private String displayName;
    private boolean isActive;
    private String tenantId;      // admin/customer → 소속(home) 테넌트 ID, super_admin → null
    private long   balance;       // 지갑 잔액(원)
    private LocalDateTime lastLoginAt;
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;

    /** 인증 시점에 로드되는 추가 관리 테넌트(다대다). DB 컬럼 아님. */
    @JsonIgnore
    private Set<String> managedTenantIds;

    public void setManagedTenantIds(Set<String> ids) { this.managedTenantIds = ids; }

    public boolean isSuperAdmin() { return role == Role.super_admin; }
    public boolean isAdmin()      { return role == Role.admin; }
    public boolean isCustomer()   { return role == Role.customer; }

    /** 같은 테넌트 소속인지 확인 (customer 단일 소속 판정용) */
    public boolean belongsTo(String tid) {
        return tid != null && tid.equals(this.tenantId);
    }

    /** 이 테넌트를 관리할 수 있는지 (super_admin 전체, admin은 home 또는 배정된 테넌트) */
    public boolean canManage(String tid) {
        if (isSuperAdmin()) return true;
        if (!isAdmin() || tid == null) return false;
        if (tid.equals(this.tenantId)) return true;
        return managedTenantIds != null && managedTenantIds.contains(tid);
    }
}
