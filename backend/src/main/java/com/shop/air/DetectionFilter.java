package com.shop.air;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;

/**
 * AIR 인라인 탐지 필터 (단일요청 시그니처).
 *  - 주문 생성 본문의 음수/0 수량(자금 증식 공격)을 탐지 → IncidentService 로 보고.
 *  - 보고 시 즉시 방어 플래그가 ON 되므로, 이 요청이 서비스에 도달할 땐 이미 차단된다.
 * 본문을 캐시 래퍼로 감싸 컨트롤러가 그대로 읽도록 한다.
 */
@Slf4j
@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
@RequiredArgsConstructor
public class DetectionFilter extends OncePerRequestFilter {

    private final IncidentService incidentService;
    private final DefenseRegistry registry;
    private final DynamicRuleRegistry ruleRegistry;
    private final ObjectMapper objectMapper = new ObjectMapper();

    // POST /api/v1/tenants/{tid}/orders  (하위경로 제외)
    private static final Pattern ORDER_CREATE =
            Pattern.compile("^/api/v1/tenants/[^/]+/orders/?$");

    // GET /api/v1/tenants/{tid}/products/search
    private static final Pattern PRODUCT_SEARCH =
            Pattern.compile("^/api/v1/tenants/[^/]+/products/search/?$");

    // POST/PATCH /api/v1/tenants/{tid}/products[/{id}]  (상품 생성/수정)
    private static final Pattern PRODUCT_WRITE =
            Pattern.compile("^/api/v1/tenants/[^/]+/products(/[^/]+)?/?$");

    // SQL Injection 시그니처(대소문자 무시): UNION SELECT / OR 1=1 / 주석 / 세미콜론 / DROP 등
    private static final Pattern SQLI_SIGNATURE = Pattern.compile(
            "(?i)(\\bunion\\b\\s+\\bselect\\b" +
            "|\\bor\\b\\s+['\"]?\\d+['\"]?\\s*=\\s*['\"]?\\d+" +
            "|';|--|/\\*|\\bdrop\\b\\s+\\btable\\b|\\bselect\\b.+\\bfrom\\b)");

    // XSS 시그니처(대소문자 무시): script/이벤트핸들러/javascript:/위험 태그
    private static final Pattern XSS_SIGNATURE = Pattern.compile(
            "(?i)(<\\s*script|<\\s*/\\s*script|onerror\\s*=|onload\\s*=|javascript:" +
            "|<\\s*img[^>]*onerror|<\\s*svg[^>]*onload|<\\s*iframe)");

    // ── IP별 슬라이딩 윈도우 카운터 (DDoS 전체요청 / 랜섬 DELETE) ──
    private static final long WINDOW_MS        = 10_000L;   // 10초 창
    private static final int  RATE_LIMIT       = 30;        // 창 내 허용 요청 수 (DDoS)
    private static final int  MASSDELETE_LIMIT = 5;         // 창 내 허용 DELETE 수 (랜섬)
    private final Map<String, Deque<Long>> hits    = new ConcurrentHashMap<>();  // 전체 요청
    private final Map<String, Deque<Long>> deletes = new ConcurrentHashMap<>();  // DELETE 만

    /** store 기준 IP의 최근 WINDOW_MS 내 횟수(현재 포함) 반환. */
    private int hit(Map<String, Deque<Long>> store, String ip) {
        long now = System.currentTimeMillis();
        Deque<Long> dq = store.computeIfAbsent(ip, k -> new ArrayDeque<>());
        synchronized (dq) {
            dq.addLast(now);
            while (!dq.isEmpty() && now - dq.peekFirst() > WINDOW_MS) dq.pollFirst();
            return dq.size();
        }
    }

    // ── #1 적응형: 이상탐지(응답 상태 기반) + 일반 shield 격리 ──
    private static final int  BURST_5XX     = 5;        // 창 내 5xx 임계(미처리 예외 연쇄=신종 익스플로잇 신호)
    private static final int  BURST_4XX     = 20;       // 창 내 4xx 임계(스캐닝/퍼징)
    private static final long QUARANTINE_MS = 30_000L;  // 의심 출처 격리(쿨다운)
    private final Map<String, Deque<Long>> err5xx = new ConcurrentHashMap<>();
    private final Map<String, Deque<Long>> err4xx = new ConcurrentHashMap<>();
    private final Map<String, Long> quarantine = new ConcurrentHashMap<>();  // ip → 만료 epoch

    private boolean isQuarantined(String ip) {
        Long until = quarantine.get(ip);
        return until != null && System.currentTimeMillis() < until;
    }

    /** 이상 신호 발생 → 출처 격리 + 인시던트 보고(폴백으로 air.shield 자동 ON). */
    private void raiseAnomaly(String type, String uri, String ip, int count) {
        quarantine.put(ip, System.currentTimeMillis() + QUARANTINE_MS);
        incidentService.report(type, uri, ip, null, "count=" + count + " in " + (WINDOW_MS / 1000) + "s");
    }

    /** 응답 상태를 관측해 이상(5xx 버스트 / 4xx 스캔)을 탐지. */
    private void observeStatus(String ip, String uri, int status) {
        if (status >= 500) {
            if (hit(err5xx, ip) > BURST_5XX) raiseAnomaly("ANOMALY_5XX_BURST", uri, ip, BURST_5XX);
        } else if (status == 400 || status == 401 || status == 403 || status == 404) {
            if (hit(err4xx, ip) > BURST_4XX) raiseAnomaly("ANOMALY_SCAN", uri, ip, BURST_4XX);
        }
    }

    private void block(HttpServletResponse res, int code, String errCode, String msg) throws IOException {
        res.setStatus(code);
        res.setContentType("application/json;charset=UTF-8");
        res.getWriter().write("{\"success\":false,\"code\":\"" + errCode + "\",\"message\":\"" + msg + "\"}");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain chain)
            throws ServletException, IOException {

        String uri = req.getRequestURI();
        String method = req.getMethod();
        String ip = clientIp(req);
        // 제어플레인(/api/v1/air/)은 모든 차단에서 제외 — 방어 토글/룰 관리 락아웃 방지.
        boolean controlPlane = uri.startsWith("/api/v1/air/");
        boolean apiReq = uri.startsWith("/api/v1/") && !controlPlane;

        // ── [Stage2] 런타임 동적 룰: 매칭 시 즉시 차단 (제어플레인 제외) ──
        if (!controlPlane) {
            DynamicRule rule = ruleRegistry.match(method, uri, req.getQueryString());
            if (rule != null) {
                block(res, 429, "RULE_BLOCKED", "동적 차단 룰에 의해 거부되었습니다.");
                return;
            }
        }

        // ── [Stage1] 일반 shield: 의심 출처(격리됨)면 차단 (제어플레인 제외) ──
        if (!controlPlane && registry.isEnabled(DefenseRegistry.AIR_SHIELD) && isQuarantined(ip)) {
            block(res, 429, "SHIELD_BLOCKED", "비정상 활동 감지로 일시 차단되었습니다.");
            return;
        }

        // ── DDoS: 제어플레인(/air/) 제외한 API 요청을 IP별로 카운트 ──
        if (apiReq) {
            int count = hit(hits, ip);
            if (count > RATE_LIMIT) {
                if (registry.isEnabled(DefenseRegistry.DETECTION)
                        && !registry.isEnabled(DefenseRegistry.DDOS_RATE_GUARD))
                    incidentService.report("DDOS_FLOOD", uri, ip, null,
                            "rate=" + count + " in " + (WINDOW_MS / 1000) + "s");
                if (registry.isEnabled(DefenseRegistry.DDOS_RATE_GUARD)) {
                    block(res, 429, "RATE_LIMITED", "요청이 너무 많습니다.");
                    return;
                }
            }
        }

        // ── 랜섬(유사): DELETE 빈도 폭주(대량 파괴) 탐지 → 차단 ──
        if (apiReq && "DELETE".equalsIgnoreCase(method)) {
            int dcount = hit(deletes, ip);
            if (dcount > MASSDELETE_LIMIT) {
                if (registry.isEnabled(DefenseRegistry.DETECTION)
                        && !registry.isEnabled(DefenseRegistry.RANSOM_MASSDELETE_GUARD))
                    incidentService.report("RANSOM_MASSDELETE", uri, ip, null,
                            "deletes=" + dcount + " in " + (WINDOW_MS / 1000) + "s");
                if (registry.isEnabled(DefenseRegistry.RANSOM_MASSDELETE_GUARD)) {
                    block(res, 429, "MASS_DELETE_BLOCKED", "비정상 대량 삭제가 차단되었습니다.");
                    return;
                }
            }
        }

        // ── 시그니처 탐지 (air.detection) — 본문 검사 시 캐시 래퍼로 교체 후 단일 chain 호출 ──
        HttpServletRequest fwd = req;
        if (registry.isEnabled(DefenseRegistry.DETECTION)) {
            try {
                if ("GET".equalsIgnoreCase(method) && PRODUCT_SEARCH.matcher(uri).matches()) {
                    String q = req.getParameter("q");
                    if (q != null && SQLI_SIGNATURE.matcher(q).find())
                        incidentService.report("SQLI_ATTEMPT", uri, ip, null, "q=" + q);
                } else if ("POST".equalsIgnoreCase(method) && ORDER_CREATE.matcher(uri).matches()) {
                    CachedBodyHttpServletRequest cached = new CachedBodyHttpServletRequest(req);
                    fwd = cached;
                    detectNegativeQty(cached);
                } else if (("POST".equalsIgnoreCase(method) || "PATCH".equalsIgnoreCase(method))
                        && PRODUCT_WRITE.matcher(uri).matches()) {
                    CachedBodyHttpServletRequest cached = new CachedBodyHttpServletRequest(req);
                    fwd = cached;
                    String body = cached.getBodyAsString();
                    if (body != null && XSS_SIGNATURE.matcher(body).find())
                        incidentService.report("XSS_ATTEMPT", uri, ip, null, body);
                }
            } catch (Exception e) {
                log.debug("[AIR] 시그니처 탐지 스킵: {}", e.getMessage());
            }
        }

        chain.doFilter(fwd, res);

        // ── [Stage1] 이상탐지: 응답 상태 관측(시그니처 무관, 행위/효과 기반) ──
        if (apiReq && registry.isEnabled(DefenseRegistry.ANOMALY_DETECTION)) {
            try {
                observeStatus(ip, uri, res.getStatus());
            } catch (Exception e) {
                log.debug("[AIR] 이상탐지 스킵: {}", e.getMessage());
            }
        }
    }

    private void detectNegativeQty(CachedBodyHttpServletRequest req) throws IOException {
        String body = req.getBodyAsString();
        if (body == null || body.isBlank()) return;
        JsonNode items = objectMapper.readTree(body).get("items");
        if (items == null || !items.isArray()) return;
        for (JsonNode item : items) {
            JsonNode q = item.get("quantity");
            if (q != null && q.isNumber() && q.asLong() <= 0) {
                incidentService.report("ORDER_NEGATIVE_QTY", req.getRequestURI(),
                        clientIp(req), null, body);
                return;
            }
        }
    }

    private static String clientIp(HttpServletRequest req) {
        String xff = req.getHeader("X-Forwarded-For");
        if (xff != null && !xff.isBlank()) {
            String[] p = xff.split(",");
            return p[p.length - 1].trim();
        }
        return req.getRemoteAddr();
    }
}
