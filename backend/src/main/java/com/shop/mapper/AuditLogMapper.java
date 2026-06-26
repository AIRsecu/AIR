package com.shop.mapper;

import com.shop.domain.AuditLog;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

import java.util.List;

@Mapper
public interface AuditLogMapper {
    void insert(AuditLog log);
    List<AuditLog> findByActorId(@Param("actorId") String actorId);
    List<AuditLog> findByTenantId(@Param("tenantId") String tenantId);
    List<AuditLog> findByResourceId(@Param("resourceId") String resourceId);
    /** 최근 N건 조회 (super_admin 대시보드용) */
    List<AuditLog> findRecent(@Param("limit") int limit);
}
