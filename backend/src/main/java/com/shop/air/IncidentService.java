package com.shop.air;

import com.shop.util.UlidUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

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
    private final DiscordNotifier discordNotifier;
    private final IrForwarder irForwarder;

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

    // [플러딩 방지] (유형+출처)별 최근 보고 시각 — 창 내 중복 인시던트/Discord 억제
    private final Map<String, Long> lastReport = new ConcurrentHashMap<>();
    private static final long DEDUP_WINDOW_MS = 60_000L;

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

        // [플러딩 방지] 동일 (유형+출처) 반복은 60s 내 1회만 기록/알림. 방어 arming 은 위에서 이미 보장.
        String who = clientIp != null ? clientIp : (actor != null ? actor : (endpoint != null ? endpoint : "-"));
        String dedupKey = type + "|" + who;
        long now = System.currentTimeMillis();
        Long prev = lastReport.get(dedupKey);
        if (prev != null && now - prev < DEDUP_WINDOW_MS) return;   // 반복 억제(인시던트/Discord 스킵)
        lastReport.put(dedupKey, now);
        if (lastReport.size() > 4096)                              // 메모리 상한 정리
            lastReport.entrySet().removeIf(e -> now - e.getValue() > DEDUP_WINDOW_MS);

        SecurityIncident inc = SecurityIncident.builder()
                .id(UlidUtil.generate())
                .type(type).endpoint(endpoint).clientIp(clientIp).actor(actor)
                .payload(truncate(payload))
                .actionTaken(action)
                .status("MITIGATED")
                .severity(RiskScoring.severity(type))   // [A2] 탐지 시점 위험도 영속
                .score(RiskScoring.score(type))
                .build();
        incidentMapper.insert(inc);

        // [IR] 위험도 산정(유형 기반) + Discord 비동기 알림(웹훅 미설정 시 no-op)
        discordNotifier.notifyIncident(inc, RiskScoring.severity(type), RiskScoring.score(type));

        // [IR 유입] ir-automation(FastAPI /ingest)로 비동기 전달 → 지속형 IP차단/사후대응
        //  (dedup 통과분만 전달 → IR 쪽도 플러딩 방지. AIR_IR_INGEST_URL 미설정 시 no-op)
        irForwarder.forward(inc);

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
