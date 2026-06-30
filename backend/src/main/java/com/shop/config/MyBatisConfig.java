package com.shop.config;

import org.apache.ibatis.type.BaseTypeHandler;
import org.apache.ibatis.type.JdbcType;
import org.apache.ibatis.type.MappedTypes;
import org.mybatis.spring.boot.autoconfigure.ConfigurationCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.sql.*;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

@Configuration
public class MyBatisConfig {

    /**
     * SQLite는 DATETIME 컬럼을 문자열로 저장한다.
     * MyBatis 기본 핸들러가 Timestamp 변환에 실패하는 경우를 방지하기 위해
     * LocalDateTime ↔ String 변환 핸들러를 전역 등록한다.
     */
    @Bean
    public ConfigurationCustomizer mybatisCustomizer() {
        return config -> config.getTypeHandlerRegistry()
                .register(LocalDateTime.class, new LocalDateTimeTypeHandler());
    }

    @MappedTypes(LocalDateTime.class)
    public static class LocalDateTimeTypeHandler extends BaseTypeHandler<LocalDateTime> {

        private static final DateTimeFormatter FMT =
                DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

        @Override
        public void setNonNullParameter(PreparedStatement ps, int i,
                                        LocalDateTime param, JdbcType jdbcType) throws SQLException {
            ps.setString(i, param.format(FMT));
        }

        @Override
        public LocalDateTime getNullableResult(ResultSet rs, String col) throws SQLException {
            return parse(rs.getString(col));
        }

        @Override
        public LocalDateTime getNullableResult(ResultSet rs, int idx) throws SQLException {
            return parse(rs.getString(idx));
        }

        @Override
        public LocalDateTime getNullableResult(CallableStatement cs, int idx) throws SQLException {
            return parse(cs.getString(idx));
        }

        private LocalDateTime parse(String s) {
            if (s == null || s.isBlank()) return null;
            // SQLite가 'T' 구분자로 내려줄 수도 있음
            return LocalDateTime.parse(s.replace("T", " "), FMT);
        }
    }
}
