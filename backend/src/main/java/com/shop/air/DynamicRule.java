package com.shop.air;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * 런타임 설치형 차단 룰 (코드 재배포 없이 적용).
 *  - LLM 어드바이저 또는 운영자가 POST /air/rules 로 설치.
 *  - DetectionFilter 가 매 요청에 평가 → 매칭 시 즉시 action.
 * 매칭 조건(모두 AND, 비어있으면 무시):
 *  - ip          : 출처 IP (LLM 이 공격 출처를 정밀 차단할 때)
 *  - method      : "GET"/"POST"/... 또는 "*"(전체)
 *  - pathContains : 요청 URI 에 포함돼야 하는 부분문자열
 *  - contains     : 쿼리스트링에 포함돼야 하는 부분문자열
 */
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class DynamicRule {
    private String id;
    private String ip;            // 출처 IP(옵션)
    private String method;        // "*" 또는 HTTP 메서드
    private String pathContains;  // URI 부분문자열
    private String contains;      // 쿼리스트링 부분문자열(옵션)
    private String action;        // BLOCK (현재 지원)
    private String source;        // LLM / manual
    private long   createdAt;     // epoch millis

    public boolean matches(String reqMethod, String uri, String query, String reqIp) {
        if (notBlank(ip) && !ip.equals(reqIp)) return false;
        if (method != null && !"*".equals(method) && !method.equalsIgnoreCase(reqMethod)) return false;
        if (notBlank(pathContains) && (uri == null || !uri.contains(pathContains))) return false;
        if (notBlank(contains) && (query == null || !query.contains(contains))) return false;
        // 조건이 하나도 없는 룰은 전체매칭 방지를 위해 무효 처리
        return notBlank(ip) || (method != null && !"*".equals(method)) || notBlank(pathContains) || notBlank(contains);
    }

    private static boolean notBlank(String s) { return s != null && !s.isBlank(); }
}
