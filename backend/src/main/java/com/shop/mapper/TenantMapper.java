package com.shop.mapper;

import com.shop.domain.Tenant;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

import java.util.List;
import java.util.Optional;

@Mapper
public interface TenantMapper {
    void insert(Tenant tenant);
    Optional<Tenant> findById(@Param("id") String id);
    Optional<Tenant> findBySlug(@Param("slug") String slug);
    List<Tenant> findAll();
    List<Tenant> findAllActive();
    void update(Tenant tenant);
    void softDelete(@Param("id") String id);
    int countBySlug(@Param("slug") String slug);
    int countBySlugExcluding(@Param("slug") String slug, @Param("excludeId") String excludeId);
}
