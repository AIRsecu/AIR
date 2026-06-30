package com.shop.mapper;

import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

import java.util.List;

@Mapper
public interface TenantAdminMapper {
    void insert(@Param("tenantId") String tenantId, @Param("userId") String userId);
    void delete(@Param("tenantId") String tenantId, @Param("userId") String userId);
    /** 해당 user 가 관리(배정)하는 테넌트 ID 목록 */
    List<String> findTenantIdsByUser(@Param("userId") String userId);
    /** 해당 테넌트에 배정된 admin user ID 목록 */
    List<String> findUserIdsByTenant(@Param("tenantId") String tenantId);
}
