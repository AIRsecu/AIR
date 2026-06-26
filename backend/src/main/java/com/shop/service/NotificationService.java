package com.shop.service;

import com.shop.domain.Tenant;
import com.shop.domain.User;
import com.shop.dto.signup.PendingCount;
import com.shop.mapper.ChargeRequestMapper;
import com.shop.mapper.OrderMapper;
import com.shop.mapper.SignupRequestMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

/** 관리자 알림 집계 - 관리하는 테넌트별 대기 주문 + 가입요청 + 충전요청 개수 */
@Service
@RequiredArgsConstructor
public class NotificationService {

    private final TenantService         tenantService;
    private final SignupRequestMapper   signupMapper;
    private final ChargeRequestMapper   chargeMapper;
    private final OrderMapper           orderMapper;

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
}
