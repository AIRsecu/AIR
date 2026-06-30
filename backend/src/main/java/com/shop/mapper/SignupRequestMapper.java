package com.shop.mapper;

import com.shop.domain.SignupRequest;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

import java.util.List;
import java.util.Optional;

@Mapper
public interface SignupRequestMapper {
    void insert(SignupRequest req);
    Optional<SignupRequest> findById(@Param("id") String id);
    List<SignupRequest> findByTenant(@Param("tenantId") String tenantId);
    List<SignupRequest> findByTenantAndStatus(@Param("tenantId") String tenantId,
                                              @Param("status") String status);
    int countPendingByUsername(@Param("username") String username);
    int countPendingByTenant(@Param("tenantId") String tenantId);
    void updateStatus(@Param("id") String id,
                      @Param("status") String status,
                      @Param("reviewedBy") String reviewedBy,
                      @Param("rejectReason") String rejectReason);
}
