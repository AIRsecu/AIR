package com.shop.air;

import com.shop.util.UlidUtil;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * 런타임 동적 차단 룰 레지스트리 (인메모리).
 *  - DetectionFilter 가 match() 로 매 요청 평가.
 *  - AirController(/air/rules) 또는 LLM 어드바이저가 add/remove.
 *  ※ MVP 는 인메모리(재기동 시 소멸). 영속이 필요하면 dynamic_rules 테이블로 확장.
 */
@Slf4j
@Component
public class DynamicRuleRegistry {

    private final List<DynamicRule> rules = new CopyOnWriteArrayList<>();

    public DynamicRule add(String method, String pathContains, String contains, String action, String source) {
        DynamicRule r = new DynamicRule(
                UlidUtil.generate(),
                method == null ? "*" : method,
                pathContains,
                contains,
                action == null ? "BLOCK" : action,
                source == null ? "manual" : source,
                System.currentTimeMillis());
        rules.add(r);
        log.warn("[AIR] 동적 룰 설치: {} {} contains='{}' -> {} ({})",
                r.getMethod(), r.getPathContains(), r.getContains(), r.getAction(), r.getSource());
        return r;
    }

    public boolean remove(String id) {
        return rules.removeIf(r -> r.getId().equals(id));
    }

    public List<DynamicRule> all() {
        return List.copyOf(rules);
    }

    /** 매칭되는 첫 룰 반환(없으면 null). */
    public DynamicRule match(String method, String uri, String query) {
        for (DynamicRule r : rules) {
            if (r.matches(method, uri, query)) return r;
        }
        return null;
    }
}
