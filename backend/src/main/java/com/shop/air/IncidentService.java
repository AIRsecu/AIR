package com.shop.air;

import com.shop.util.UlidUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Map;

/**
 * 공격 인시던트 대응 오케스트레이터.
 * 1) 즉시 토글: 인시던트 유형에 대응하는 방어 플래그를 ON → 런타임 차단.
 * 2) (다음 단계) 비동기 소스 패치: LLM 생성 → 검증 → 재배포.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class IncidentService {

    private final DefenseRegistry registry;
    private final SecurityIncidentMapper incidentMapper;

    /** 인시던트 유형 → 방어 키 매핑 */
    private static final Map<String, String> TYPE_TO_DEFENSE = Map.of(
            "ORDER_NEGATIVE_QTY", DefenseRegistry.ORDER_QTY_GUARD
    );

    public void report(String type, String endpoint, String clientIp, String actor, String payload) {
        String defenseKey = TYPE_TO_DEFENSE.get(type);
        String action;
        if (defenseKey != null && !registry.isEnabled(defenseKey)) {
            registry.enable(defenseKey);                 // ★ 즉시 차단
            action = "DEFENSE_ENABLED:" + defenseKey;
            log.warn("[AIR] 공격 탐지 '{}' → 방어 '{}' 즉시 활성화", type, defenseKey);
        } else {
            action = defenseKey != null ? "ALREADY_DEFENDED:" + defenseKey : "NO_DEFENSE_MAPPED";
        }

        SecurityIncident inc = SecurityIncident.builder()
                .id(UlidUtil.generate())
                .type(type).endpoint(endpoint).clientIp(clientIp).actor(actor)
                .payload(truncate(payload))
                .actionTaken(action)
                .status("MITIGATED")
                .build();
        incidentMapper.insert(inc);

        // TODO [5단계] 비동기 소스 패치 트리거: triggerAutoPatch(type, defenseKey, payload)
    }

    public List<SecurityIncident> recent(int limit) { return incidentMapper.findRecent(limit); }

    private static String truncate(String s) {
        if (s == null) return null;
        return s.length() > 2000 ? s.substring(0, 2000) + "…" : s;
    }
}
