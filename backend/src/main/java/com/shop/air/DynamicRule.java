package com.shop.air;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * 런타임 설치형 차단 룰 (코드 재배포 없이 적용).
 *  - LLM 어드바이저(향후) 또는 운영자가 POST /air/rules 로 설치.
 *  - DetectionFilter 가 매 요청에 평가 → 매칭 시 즉시 action.
 * 매칭 조건(모두 AND, 비어있으면 무시):
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
    private String method;        // "*" 또는 HTTP 메서드
    private String pathContains;  // URI 부분문자열
    private String contains;      // 쿼리스트링 부분문자열(옵션)
    private String action;        // BLOCK (현재 지원)
    private String source;        // LLM / manual
    private long   createdAt;     // epoch millis

    public boolean matches(String reqMethod, String uri, String query) {
        if (method != null && !"*".equals(method) && !method.equalsIgnoreCase(reqMethod)) return false;
        if (pathContains != null && !pathContains.isBlank() && (uri == null || !uri.contains(pathContains))) return false;
        if (contains != null && !contains.isBlank() && (query == null || !query.contains(contains))) return false;
        // 셋 다 비어있는 룰은 전체매칭 방지를 위해 무효 처리
        return !( (method == null || "*".equals(method))
                && (pathContains == null || pathContains.isBlank())
                && (contains == null || contains.isBlank()) );
    }
}
