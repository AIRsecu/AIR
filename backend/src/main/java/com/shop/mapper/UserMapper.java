package com.shop.mapper;

import com.shop.domain.User;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

import java.util.List;
import java.util.Optional;

@Mapper
public interface UserMapper {
    void insert(User user);
    Optional<User> findById(@Param("id") String id);
    Optional<User> findByUsername(@Param("username") String username);
    List<User> findAll();
    List<User> findByTenantId(@Param("tenantId") String tenantId);
    void update(User user);
    void updatePasswordHash(@Param("id") String id, @Param("passwordHash") String passwordHash);
    void softDelete(@Param("id") String id);
    int countByUsername(@Param("username") String username);
    void updateLastLoginAt(@Param("id") String id);
    void addBalance(@Param("id") String id, @Param("amount") long amount);
    int  deductBalance(@Param("id") String id, @Param("amount") long amount);
}
