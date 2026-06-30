package com.shop.mapper;

import com.shop.domain.ChargeRequest;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

import java.util.List;
import java.util.Optional;

@Mapper
public interface ChargeRequestMapper {
    void insert(ChargeRequest req);
    Optional<ChargeRequest> findById(@Param("id") String id);
    List<ChargeRequest> findByTenant(@Param("tenantId") String tenantId);
    List<ChargeRequest> findByTenantAndStatus(@Param("tenantId") String tenantId,
                                              @Param("status") String status);
    List<ChargeRequest> findByUser(@Param("userId") String userId);
    int countPendingByTenant(@Param("tenantId") String tenantId);
    void updateStatus(@Param("id") String id,
                      @Param("status") String status,
                      @Param("reviewedBy") String reviewedBy,
                      @Param("rejectReason") String rejectReason);
}
