package com.shop.service;

import com.shop.domain.Tenant;
import com.shop.domain.User;
import com.shop.dto.signup.PendingCount;
import com.shop.mapper.ChargeRequestMapper;
import com.shop.mapper.OrderMapper;
import com.shop.mapper.SignupRequestMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/** 관리자 알림 집계 - 관리하는 테넌트별 대기 주문 + 가입요청 + 충전요청 개수 */
@Service
@RequiredArgsConstructor
public class NotificationService {

    private final TenantService             tenantService;
    private final SignupRequestMapper       signupMapper;
    private final ChargeRequestMapper       chargeMapper;
    private final OrderMapper               orderMapper;
    private final NotificationStreamService stream;

    public List<PendingCount> pending(User actor) {
        if (!actor.isSuperAdmin() && !actor.isAdmin()) return List.of();
        List<PendingCount> out = new ArrayList<>();
        for (Tenant t : tenantService.listManagedBy(actor)) {
            int signups = signupMapper.countPendingByTenant(t.getId());
            int charges = chargeMapper.countPendingByTenant(t.getId());
            int orders  = orderMapper.countByTenantAndStatus(t.getId(), "pending");
            if (signups > 0 || charges > 0 || orders > 0)
                out.add(new PendingCount(t.getId(), t.getName(), signups, charges, orders));
        }
        return out;
    }

    // ── SSE 실시간 알림 ────────────────────────────────────────────

    /** SSE 구독 시작. 관리자라면 현재 대기 집계를 즉시 1회 푸시(첫 화면 동기화). */
    public SseEmitter subscribe(User actor) {
        SseEmitter emitter = stream.subscribe(actor);
        if (actor.isSuperAdmin() || actor.isAdmin())
            stream.send(actor.getId(), "pending", pending(actor));
        return emitter;
    }

    /**
     * 테넌트 활동(주문/가입/충전 발생·처리) 변동 → 그 테넌트를 관리하는
     * "접속 중" 관리자에게만 최신 대기 집계를 다시 푸시.
     */
    public void notifyTenantActivity(String tenantId) {
        if (tenantId == null) return;
        for (User u : stream.connectedPrincipals()) {
            if ((u.isSuperAdmin() || u.isAdmin()) && u.canManage(tenantId))
                stream.send(u.getId(), "pending", pending(u));
        }
    }

    /** 고객 본인의 주문 상태 변경 알림. */
    public void notifyOrder(String customerId, String orderId, String status) {
        if (customerId == null) return;
        stream.send(customerId, "order", Map.of("orderId", orderId, "status", status));
    }

    /** 고객 본인의 충전 요청 처리(승인/반려) 알림. */
    public void notifyCharge(String customerId, String chargeId, String status) {
        if (customerId == null) return;
        stream.send(customerId, "charge", Map.of("chargeId", chargeId, "status", status));
    }
}
