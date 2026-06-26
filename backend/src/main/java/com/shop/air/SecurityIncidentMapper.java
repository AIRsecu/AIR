package com.shop.air;

import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

import java.util.List;

@Mapper
public interface SecurityIncidentMapper {
    void insert(SecurityIncident incident);
    void updateStatus(@Param("id") String id, @Param("status") String status,
                      @Param("actionTaken") String actionTaken);
    List<SecurityIncident> findRecent(@Param("limit") int limit);
}
