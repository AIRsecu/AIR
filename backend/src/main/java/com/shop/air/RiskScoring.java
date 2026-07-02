package com.shop.air;

import java.util.Map;

/**
 * AIR 인시던트 위험도 스코어링(유형 기반, 결정적).
 *  score(0~100) → severity(CRITICAL/HIGH/MEDIUM/LOW). 미지 유형은 LOW(30).
 *  ※ 엔티티/DB 무변경 — 응답 enrich + Discord 알림 + 대시보드 표시에 사용.
 */
public final class RiskScoring {
    private RiskScoring() {}

    private static final Map<String, Integer> SCORE = Map.ofEntries(
            Map.entry("SQLI_ATTEMPT",          95),
            Map.entry("RANSOM_MASSDELETE",     95),
            Map.entry("UPLOAD_MALICIOUS_FILE", 90),
            Map.entry("ORDER_NEGATIVE_QTY",    85),
            Map.entry("UPLOAD_PATH_TRAVERSAL", 85),
            Map.entry("IDOR_ATTEMPT",          80),
            Map.entry("XSS_ATTEMPT",           75),
            Map.entry("DDOS_FLOOD",            70),
            Map.entry("ANOMALY_5XX_BURST",     60),
            Map.entry("ANOMALY_SCAN",          50)
    );

    public static int score(String type) {
        return SCORE.getOrDefault(type, 30);
    }

    public static String severity(String type) {
        int s = score(type);
        if (s >= 90) return "CRITICAL";
        if (s >= 70) return "HIGH";
        if (s >= 40) return "MEDIUM";
        return "LOW";
    }
}
