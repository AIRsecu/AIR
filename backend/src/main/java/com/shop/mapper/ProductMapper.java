package com.shop.mapper;

import com.shop.domain.Product;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

import java.util.List;
import java.util.Optional;

@Mapper
public interface ProductMapper {
    void insert(Product product);
    Optional<Product> findById(@Param("id") String id);
    List<Product> findByTenantId(@Param("tenantId") String tenantId);
    List<Product> findActiveByTenantId(@Param("tenantId") String tenantId);
    void update(Product product);
    void softDelete(@Param("id") String id);
    int decreaseStock(@Param("id") String id, @Param("qty") int qty);
    void increaseStock(@Param("id") String id, @Param("qty") int qty);
}
