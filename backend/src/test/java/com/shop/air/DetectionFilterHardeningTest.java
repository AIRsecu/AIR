package com.shop.air;

import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;

/**
 * DetectionFilter 하드닝(R1~R3) 런타임 실증 — 실제 컴파일된 필터를 MockHttpServletRequest 로 구동.
 *  R2: 미신뢰 피어의 위조 X-Forwarded-For 는 무시되어 레이트리밋 우회 불가(핵심 보안속성).
 *      신뢰 프록시 뒤에서는 XFF 실IP 를 개별 집계(기존 동작 보존).
 *  R3: 시그니처 스캔 입력이 64KB 로 캡됨(경계 실증).
 */
class DetectionFilterHardeningTest {

    private final IncidentService incident = Mockito.mock(IncidentService.class);

    private DetectionFilter newFilter() {
        DefenseRegistry reg = Mockito.mock(DefenseRegistry.class);
        // 탐지 ON + DDoS 레이트가드 ON(실제 차단). 나머지(shield/anomaly 등)는 Mockito 기본 false.
        Mockito.when(reg.isEnabled(DefenseRegistry.DETECTION)).thenReturn(true);
        Mockito.when(reg.isEnabled(DefenseRegistry.DDOS_RATE_GUARD)).thenReturn(true);
        DynamicRuleRegistry rules = Mockito.mock(DynamicRuleRegistry.class); // match() 기본 null → 룰 미매칭
        return new DetectionFilter(incident, reg, rules);
    }

    private MockHttpServletRequest apiGet(String uri, String remoteAddr, String xff) {
        MockHttpServletRequest req = new MockHttpServletRequest("GET", uri);
        req.setRemoteAddr(remoteAddr);
        if (xff != null) req.addHeader("X-Forwarded-For", xff);
        return req;
    }

    // ── R2: 미신뢰 피어(직접 접속 공격자)의 회전 위조 XFF → 레이트리밋 우회 실패 ──
    @Test
    void spoofedXff_fromUntrustedPeer_cannotBypassRateLimit() throws Exception {
        DetectionFilter f = newFilter();
        int firstBlocked = -1;
        for (int i = 1; i <= 35; i++) {
            // 매 요청 서로 다른 위조 XFF 를 붙이지만, remoteAddr(203.0.113.50)은 신뢰대역 밖 → XFF 무시
            MockHttpServletRequest req = apiGet("/api/v1/tenants/t1/products/1", "203.0.113.50", "9.9.9." + i);
            MockHttpServletResponse res = new MockHttpServletResponse();
            f.doFilter(req, res, new MockFilterChain());
            if (res.getStatus() == 429 && firstBlocked < 0) firstBlocked = i;
        }
        // XFF 가 무시되어 모두 remoteAddr 한 IP 로 집계 → RATE_LIMIT(30) 초과인 31번째부터 429
        assertEquals(31, firstBlocked,
                "위조 XFF 가 무시되고 remoteAddr 로 집계되어 31번째에 레이트리밋 차단되어야 함");
    }

    // ── R2 대조: 신뢰 프록시 뒤 서로 다른 실IP(XFF)는 개별 집계(기존 정상 동작 보존) ──
    @Test
    void trustedProxy_honorsPerClientIpFromXff() throws Exception {
        DetectionFilter f = newFilter();
        boolean anyBlocked = false;
        for (int i = 1; i <= 35; i++) {
            // remoteAddr(172.28.0.5)=신뢰 프록시 → XFF 실IP 채택. 매번 다른 실IP 이므로 단일 IP 임계 미도달
            MockHttpServletRequest req = apiGet("/api/v1/tenants/t1/products/1", "172.28.0.5", "9.9.9." + i);
            MockHttpServletResponse res = new MockHttpServletResponse();
            f.doFilter(req, res, new MockFilterChain());
            if (res.getStatus() == 429) anyBlocked = true;
        }
        assertFalse(anyBlocked,
                "신뢰 프록시 뒤 서로 다른 실IP(XFF)는 개별 집계되어 차단되지 않아야 함");
    }

    // ── R3: 시그니처 스캔 입력 64KB 캡 경계 실증 ──
    @Test
    void signatureScanInputIsCappedAt64K() throws Exception {
        DetectionFilter f = newFilter();

        // (a) XSS 시그니처를 64KB 이후에 배치 → 캡으로 스캔되지 않아 미탐지
        String beyond = "{\"name\":\"" + "A".repeat(70_000) + "<script>x</script>\"}";
        MockHttpServletRequest r1 = new MockHttpServletRequest("POST", "/api/v1/tenants/t1/products");
        r1.setRemoteAddr("172.28.0.5");
        r1.setContentType("application/json");
        r1.setContent(beyond.getBytes(StandardCharsets.UTF_8));
        f.doFilter(r1, new MockHttpServletResponse(), new MockFilterChain());
        Mockito.verify(incident, Mockito.never())
                .report(eq("XSS_ATTEMPT"), any(), any(), any(), any());

        // (b) 동일 시그니처를 선두(캡 이내)에 배치 → 정상 탐지
        String within = "{\"name\":\"<script>x</script>" + "A".repeat(1_000) + "\"}";
        MockHttpServletRequest r2 = new MockHttpServletRequest("POST", "/api/v1/tenants/t1/products");
        r2.setRemoteAddr("172.28.0.5");
        r2.setContentType("application/json");
        r2.setContent(within.getBytes(StandardCharsets.UTF_8));
        f.doFilter(r2, new MockHttpServletResponse(), new MockFilterChain());
        Mockito.verify(incident, Mockito.times(1))
                .report(eq("XSS_ATTEMPT"), any(), any(), any(), any());
    }
}
