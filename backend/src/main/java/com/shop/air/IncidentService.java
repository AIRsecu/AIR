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

    /** 인시던트 유형 → 방어 키 매핑 (알려진 시그니처) */
    private static final Map<String, String> TYPE_TO_DEFENSE = Map.ofEntries(
            Map.entry("ORDER_NEGATIVE_QTY",    DefenseRegistry.ORDER_QTY_GUARD),
            Map.entry("SQLI_ATTEMPT",          DefenseRegistry.SQL_INJECTION_GUARD),
            Map.entry("XSS_ATTEMPT",           DefenseRegistry.XSS_INPUT_GUARD),
            Map.entry("IDOR_ATTEMPT",          DefenseRegistry.AUTHZ_IDOR_GUARD),
            Map.entry("DDOS_FLOOD",            DefenseRegistry.DDOS_RATE_GUARD),
            Map.entry("RANSOM_MASSDELETE",     DefenseRegistry.RANSOM_MASSDELETE_GUARD),
            Map.entry("UPLOAD_MALICIOUS_FILE", DefenseRegistry.UPLOAD_FILE_GUARD),
            Map.entry("UPLOAD_PATH_TRAVERSAL", DefenseRegistry.UPLOAD_FILE_GUARD)
    );

    public void report(String type, String endpoint, String clientIp, String actor, String payload) {
        // [#1 적응형] 알려진 유형이면 전용 가드, 미지/이상(UNKNOWN_ANOMALY 등)이면 일반 shield 로 폴백.
        String defenseKey = TYPE_TO_DEFENSE.getOrDefault(type, DefenseRegistry.AIR_SHIELD);
        String action;
        if (!registry.isEnabled(defenseKey)) {
            registry.enable(defenseKey);                 // ★ 즉시 차단(전용 가드 또는 일반 shield)
            action = "DEFENSE_ENABLED:" + defenseKey;
            log.warn("[AIR] 탐지 '{}' → 방어 '{}' 즉시 활성화", type, defenseKey);
        } else {
            action = "ALREADY_DEFENDED:" + defenseKey;
        }

        SecurityIncident inc = SecurityIncident.builder()
                .id(UlidUtil.generate())
                .type(type).endpoint(endpoint).clientIp(clientIp).actor(actor)
                .payload(truncate(payload))
                .actionTaken(action)
                .status("MITIGATED")
                .build();
        incidentMapper.insert(inc);

        // [5단계] 비동기 소스 패치는 별도 오케스트레이터(air-orchestrator/responder.py)가
        // 이 인시던트를 폴링 → Claude API 패치 생성 → 검증 → 커밋 후
        // POST /air/incidents/{id}/status 로 PATCHED/FAILED 를 기록한다.
    }

    public List<SecurityIncident> recent(int limit) { return incidentMapper.findRecent(limit); }

    /** 외부 오케스트레이터가 자동 소스패치 결과를 반영 (PATCHED / FAILED). */
    public void updateStatus(String id, String status, String actionTaken) {
        incidentMapper.updateStatus(id, status, actionTaken);
        log.info("[AIR] incident {} -> {} ({})", id, status, actionTaken);
    }

    private static String truncate(String s) {
        if (s == null) return null;
        return s.length() > 2000 ? s.substring(0, 2000) + "…" : s;
    }
}
