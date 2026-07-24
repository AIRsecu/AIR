package com.shop.air;

import java.util.Map;

/**
 * AIR 인시던트 위험도 스코어링(유형 기반, 결정적).
 *  score(0~100) → severity(CRITICAL/HIGH/MEDIUM/LOW). 미지 유형은 LOW(30).
 *  이 표가 위험도의 정본(SSOT). IR(analyzer/risk.py)은 이 값을 그대로 미러해야 하며,
 *  크로스언어 동일성 가드는 ir-automation/tests/test_ssot_risk_parity.py 가 강제한다
 *  (이 소스와 risk.py 를 각각 파싱해 대조 — 어느 한쪽만 바꾸면 CI 실패).
 *  [A2] 탐지 시점 값은 security_incidents.severity/score 에 영속(enrich 는 저장값 우선).
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
