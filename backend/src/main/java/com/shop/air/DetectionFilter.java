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

    @Override
    protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain chain)
            throws ServletException, IOException {

        if (!registry.isEnabled(DefenseRegistry.DETECTION)) { chain.doFilter(req, res); return; }

        String uri = req.getRequestURI();

        // ── SQL Injection: 상품 검색 q 파라미터 시그니처 검사 (GET, 본문 없음) ──
        if ("GET".equalsIgnoreCase(req.getMethod()) && PRODUCT_SEARCH.matcher(uri).matches()) {
            try {
                String q = req.getParameter("q");
                if (q != null && SQLI_SIGNATURE.matcher(q).find())
                    incidentService.report("SQLI_ATTEMPT", uri, clientIp(req), null, "q=" + q);
            } catch (Exception e) {
                log.debug("[AIR] SQLi 탐지 스킵: {}", e.getMessage());
            }
            chain.doFilter(req, res);
            return;
        }

        // ── 음수수량 자금증식: 주문 생성 본문 검사 (POST) ──
        if ("POST".equalsIgnoreCase(req.getMethod()) && ORDER_CREATE.matcher(uri).matches()) {
            CachedBodyHttpServletRequest cached = new CachedBodyHttpServletRequest(req);
            try {
                detectNegativeQty(cached);
            } catch (Exception e) {
                log.debug("[AIR] 탐지 파싱 스킵: {}", e.getMessage());
            }
            chain.doFilter(cached, res);
            return;
        }

        // ── XSS: 상품 생성/수정 본문 검사 (POST/PATCH) ──
        if (("POST".equalsIgnoreCase(req.getMethod()) || "PATCH".equalsIgnoreCase(req.getMethod()))
                && PRODUCT_WRITE.matcher(uri).matches()) {
            CachedBodyHttpServletRequest cached = new CachedBodyHttpServletRequest(req);
            try {
                String body = cached.getBodyAsString();
                if (body != null && XSS_SIGNATURE.matcher(body).find())
                    incidentService.report("XSS_ATTEMPT", uri, clientIp(req), null, body);
            } catch (Exception e) {
                log.debug("[AIR] XSS 탐지 스킵: {}", e.getMessage());
            }
            chain.doFilter(cached, res);
            return;
        }

        chain.doFilter(req, res);
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
