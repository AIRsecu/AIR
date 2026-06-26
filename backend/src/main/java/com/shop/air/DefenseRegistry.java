package com.shop.air;

import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.sql.init.dependency.DependsOnDatabaseInitialization;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.ConcurrentHashMap;

/**
 * AIR 방어 토글 레지스트리.
 * - 방어 가드는 코드에 존재하되 플래그로 ON/OFF (미존재=OFF=취약).
 * - 공격 탐지 시 enable() 로 즉시 ON → 런타임 차단.
 * - 인메모리 + DB 영속(재기동 보존).
 */
@Slf4j
@Component
@DependsOnDatabaseInitialization   // schema.sql(테이블 생성) 이후에 @PostConstruct 로드 보장
@RequiredArgsConstructor
public class DefenseRegistry {

    /** 알려진 키와 초기 기본값 */
    public static final String ORDER_QTY_GUARD = "order.qty-guard"; // 기본 OFF=취약
    public static final String DETECTION       = "air.detection";   // 기본 ON=탐지활성
    private static final Map<String, Boolean> KNOWN_DEFAULTS = Map.of(
            ORDER_QTY_GUARD, false,
            DETECTION,       true
    );

    private final DefenseFlagMapper mapper;
    private final Map<String, Boolean> cache = new ConcurrentHashMap<>();

    @PostConstruct
    void load() {
        for (DefenseFlag f : mapper.findAll()) cache.put(f.getFlagKey(), f.isEnabled());
        KNOWN_DEFAULTS.forEach((k, def) -> {
            if (!cache.containsKey(k)) { cache.put(k, def); mapper.upsert(k, def); }
        });
        log.info("[AIR] DefenseRegistry loaded: {}", new TreeMap<>(cache));
    }

    public boolean isEnabled(String key) { return Boolean.TRUE.equals(cache.get(key)); }

    public void enable(String key)  { set(key, true);  }
    public void disable(String key) { set(key, false); }

    private void set(String key, boolean enabled) {
        cache.put(key, enabled);
        mapper.upsert(key, enabled);
        log.warn("[AIR] defense '{}' -> {}", key, enabled ? "ENABLED(차단)" : "DISABLED(취약)");
    }

    public Map<String, Boolean> all() { return new TreeMap<>(cache); }
}
