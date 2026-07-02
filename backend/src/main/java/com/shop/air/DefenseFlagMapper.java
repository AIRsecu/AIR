package com.shop.air;

import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

import java.util.List;

@Mapper
public interface DefenseFlagMapper {
    List<DefenseFlag> findAll();
    void upsert(@Param("flagKey") String flagKey, @Param("enabled") boolean enabled);
}
