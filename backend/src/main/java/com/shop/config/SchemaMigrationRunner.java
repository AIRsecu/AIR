package com.shop.config;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.HashSet;
import java.util.Set;

/**
 * 기존 DB(볼륨)를 초기화(down -v)하지 않고도 새 컬럼을 자동 추가한다.
 * - 새 테이블은 schema.sql 의 CREATE TABLE IF NOT EXISTS 가 처리.
 * - 기존 테이블에 컬럼을 추가하는 것은 IF NOT EXISTS 가 없으므로 여기서 멱등 처리.
 * BootstrapRunner 보다 먼저 실행되도록 @Order 로 우선순위를 높인다.
 */
@Slf4j
@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
@RequiredArgsConstructor
public class SchemaMigrationRunner implements ApplicationRunner {

    private final DataSource dataSource;

    @Override
    public void run(ApplicationArguments args) {
        ensureColumn("tenants", "domain",  "ALTER TABLE tenants ADD COLUMN domain TEXT");
        ensureColumn("users",   "balance", "ALTER TABLE users ADD COLUMN balance INTEGER NOT NULL DEFAULT 0");
    }

    /** 해당 테이블에 컬럼이 없으면 ALTER 로 추가 (있으면 스킵). */
    private void ensureColumn(String table, String column, String alterSql) {
        try (Connection conn = dataSource.getConnection()) {
            Set<String> cols = new HashSet<>();
            try (Statement st = conn.createStatement();
                 ResultSet rs = st.executeQuery("PRAGMA table_info(" + table + ")")) {
                while (rs.next()) cols.add(rs.getString("name"));
            }
            if (cols.isEmpty()) {
                log.info("[Migration] '{}' 테이블이 아직 없음 → schema.sql 이 생성 (스킵)", table);
                return;
            }
            if (!cols.contains(column)) {
                try (Statement st = conn.createStatement()) {
                    st.executeUpdate(alterSql);
                    log.info("[Migration] {}.{} 컬럼 추가 완료", table, column);
                }
            } else {
                log.info("[Migration] {}.{} 이미 존재 (스킵)", table, column);
            }
        } catch (Exception e) {
            log.warn("[Migration] {}.{} 처리 실패: {}", table, column, e.getMessage());
        }
    }
}
