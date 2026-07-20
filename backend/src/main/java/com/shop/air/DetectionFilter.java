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
import java.net.InetAddress;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;
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

    // [R3] 시그니처 정규식 스캔 입력 상한. 대용량 본문/쿼리에 .+ 정규식을 통째로 돌려 CPU 를 태우는
    //      것(경미 ReDoS 표면)을 방지 — 스캔만 캡하고 인시던트 payload 원문은 그대로 보고한다.
    private static final int MAX_SCAN_CHARS = 65_536;

    private static String capForScan(String s) {
        if (s == null) return null;
        return s.length() > MAX_SCAN_CHARS ? s.substring(0, MAX_SCAN_CHARS) : s;
    }

    // ── IP별 슬라이딩 윈도우 카운터 (DDoS 전체요청 / 랜섬 DELETE) ──
    private static final long WINDOW_MS        = 10_000L;   // 10초 창
    private static final int  RATE_LIMIT       = 30;        // 창 내 허용 요청 수 (DDoS)
    private static final int  MASSDELETE_LIMIT = 5;         // 창 내 허용 DELETE 수 (랜섬)
    // [R1] IP별 카운터/격리 맵 상한. 초과 시 만료 엔트리 축출 → 회전 IP 공격에도 메모리 무한증가(OOM) 방지.
    private static final int  MAX_TRACKED_IPS  = 50_000;
    private final Map<String, Deque<Long>> hits    = new ConcurrentHashMap<>();  // 전체 요청
    private final Map<String, Deque<Long>> deletes = new ConcurrentHashMap<>();  // DELETE 만

    /** store 기준 IP의 최근 WINDOW_MS 내 횟수(현재 포함) 반환. */
    private int hit(Map<String, Deque<Long>> store, String ip) {
        long now = System.currentTimeMillis();
        Deque<Long> dq = store.computeIfAbsent(ip, k -> new ArrayDeque<>());
        int size;
        synchronized (dq) {
            dq.addLast(now);
            while (!dq.isEmpty() && now - dq.peekFirst() > WINDOW_MS) dq.pollFirst();
            size = dq.size();
        }
        // [R1] 상한 초과 시에만 스윕(핫패스 오버헤드 최소화): 윈도우가 비워진 IP 엔트리 제거.
        if (store.size() > MAX_TRACKED_IPS) evictStale(store, now);
        return size;
    }

    /** [R1] 윈도우가 만료돼 비어있는 IP 카운터 엔트리를 제거해 맵 크기를 제한한다. */
    private static void evictStale(Map<String, Deque<Long>> store, long now) {
        store.entrySet().removeIf(e -> {
            Deque<Long> dq = e.getValue();
            synchronized (dq) {
                while (!dq.isEmpty() && now - dq.peekFirst() > WINDOW_MS) dq.pollFirst();
                return dq.isEmpty();
            }
        });
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
        if (until == null) return false;
        if (System.currentTimeMillis() >= until) {
            quarantine.remove(ip, until);   // [R1] 만료 즉시 제거(값 일치 시에만 → 재격리 레이스 안전)
            return false;
        }
        return true;
    }

    /** 이상 신호 발생 → 출처 격리 + 인시던트 보고(폴백으로 air.shield 자동 ON). */
    private void raiseAnomaly(String type, String uri, String ip, int count) {
        long now = System.currentTimeMillis();
        quarantine.put(ip, now + QUARANTINE_MS);
        // [R1] 상한 초과 시 만료된 격리 엔트리 축출(메모리 무한증가 방지).
        if (quarantine.size() > MAX_TRACKED_IPS)
            quarantine.entrySet().removeIf(en -> en.getValue() <= now);
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
            DynamicRule rule = ruleRegistry.match(method, uri, req.getQueryString(), ip);
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
                    if (q != null && SQLI_SIGNATURE.matcher(capForScan(q)).find())  // [R3] 스캔 입력 캡
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
                    if (body != null && XSS_SIGNATURE.matcher(capForScan(body)).find())  // [R3] 스캔 입력 캡
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

    // ── [R2] 신뢰 프록시(리버스 프록시) 뒤에서만 X-Forwarded-For 실IP 를 채택 ──
    // XFF 는 클라이언트가 임의 조작 가능 → 무검증 신뢰 시 레이트리밋/격리 카운터를 IP별로 분산시켜
    // 우회하거나(위 R1 맵을 무한 팽창) 무고한 IP 를 차단시킬 수 있다. 직접 피어(remoteAddr)가
    // 신뢰 대역(리버스프록시)일 때만 XFF 를 신뢰하고, 그 외에는 remoteAddr 를 클라이언트로 본다.
    // 기본 신뢰 대역 = 루프백 + RFC1918 사설 + IPv6 사설(도커/nginx 동일망). AIR_TRUSTED_PROXIES 로 override.
    private static final List<CidrRange> TRUSTED_PROXIES = parseTrustedProxies(
            envOrDefault("AIR_TRUSTED_PROXIES",
                    "127.0.0.0/8,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,::1/128,fc00::/7"));

    private static String clientIp(HttpServletRequest req) {
        String remote = req.getRemoteAddr();
        if (isTrustedProxy(remote)) {
            String xff = req.getHeader("X-Forwarded-For");
            if (xff != null && !xff.isBlank()) {
                String[] p = xff.split(",");
                String cand = p[p.length - 1].trim();   // nginx 가 마지막에 실IP 를 덧붙인다($proxy_add_x_forwarded_for)
                if (isIpLiteral(cand)) return cand;
            }
        }
        return remote;
    }

    private static String envOrDefault(String key, String def) {
        String v = System.getenv(key);
        return (v == null || v.isBlank()) ? def : v;
    }

    private static boolean isTrustedProxy(String ip) {
        try {
            byte[] a = InetAddress.getByName(ip).getAddress();
            for (CidrRange r : TRUSTED_PROXIES) if (r.contains(a)) return true;
        } catch (Exception e) { /* 파싱 실패 → 미신뢰 */ }
        return false;
    }

    /** DNS 조회 없이 리터럴 IP(v4/v6) 인지 검사 — 호스트명 주입으로 인한 조회/오탐 방지. */
    private static boolean isIpLiteral(String s) {
        if (s == null || s.isBlank()) return false;
        boolean shape = s.chars().allMatch(c ->
                (c >= '0' && c <= '9') || c == '.' || c == ':' ||
                (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') || c == '%');
        if (!shape || (s.indexOf('.') < 0 && s.indexOf(':') < 0)) return false;
        try { InetAddress.getByName(s); return true; } catch (Exception e) { return false; }
    }

    private static List<CidrRange> parseTrustedProxies(String csv) {
        List<CidrRange> out = new ArrayList<>();
        for (String tok : csv.split(",")) {
            tok = tok.trim();
            if (tok.isEmpty()) continue;
            try {
                String[] parts = tok.split("/");
                byte[] a = InetAddress.getByName(parts[0].trim()).getAddress();
                int prefix = parts.length > 1 ? Integer.parseInt(parts[1].trim()) : a.length * 8;
                out.add(new CidrRange(a, prefix));
            } catch (Exception e) { /* 잘못된 항목 무시(안전 기본값 유지) */ }
        }
        return out;
    }

    /** CIDR 대역(주소+프리픽스) 포함 검사. v4/v6 길이 불일치는 미포함. */
    private record CidrRange(byte[] addr, int prefix) {
        boolean contains(byte[] target) {
            if (target.length != addr.length) return false;
            int fullBytes = prefix / 8;
            for (int i = 0; i < fullBytes; i++) if (addr[i] != target[i]) return false;
            int rem = prefix % 8;
            if (rem == 0) return true;
            int mask = (0xFF << (8 - rem)) & 0xFF;
            return (addr[fullBytes] & mask) == (target[fullBytes] & mask);
        }
    }
}
