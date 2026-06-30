package com.shop.mapper;

import com.shop.domain.RefreshToken;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

import java.util.Optional;

@Mapper
public interface RefreshTokenMapper {
    void insert(RefreshToken token);
    Optional<RefreshToken> findByTokenHash(@Param("tokenHash") String tokenHash);
    void revoke(@Param("id") String id, @Param("replacedBy") String replacedBy);
    void revokeAllByUserId(@Param("userId") String userId);
}
