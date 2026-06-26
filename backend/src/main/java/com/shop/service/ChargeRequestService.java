package com.shop.service;

import com.shop.domain.ChargeRequest;
import com.shop.domain.User;
import com.shop.exception.AppException;
import com.shop.mapper.ChargeRequestMapper;
import com.shop.mapper.UserMapper;
import com.shop.util.UlidUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
@RequiredArgsConstructor
public class ChargeRequestService {

    private final ChargeRequestMapper reqMapper;
    private final UserMapper           userMapper;

    /** customer - 충전 요청 제출 */
    @Transactional
    public ChargeRequest submit(String tenantId, User actor, long amount) {
        if (!actor.isCustomer() || !actor.belongsTo(tenantId))
            throw AppException.forbidden("해당 상점의 고객만 충전 요청할 수 있습니다.");
        if (amount <= 0)
            throw AppException.badRequest("충전 금액은 1원 이상이어야 합니다.");

        ChargeRequest req = ChargeRequest.builder()
                .id(UlidUtil.generate())
                .tenantId(tenantId)
                .userId(actor.getId())
                .username(actor.getUsername())
                .amount(amount)
                .status(ChargeRequest.Status.pending.name())
                .build();
        reqMapper.insert(req);
        return req;
    }

    /** customer - 내 충전 요청 내역 */
    public List<ChargeRequest> listMine(User actor) {
        return reqMapper.findByUser(actor.getId());
    }

    /** admin/super_admin - 테넌트 충전 요청 목록 */
    public List<ChargeRequest> list(String tenantId, String status, User actor) {
        authorize(tenantId, actor);
        return (status == null || status.isBlank())
                ? reqMapper.findByTenant(tenantId)
                : reqMapper.findByTenantAndStatus(tenantId, status);
    }

    /** admin/super_admin - 승인 → 잔액 증가 */
    @Transactional
    public void approve(String tenantId, String requestId, User actor) {
        authorize(tenantId, actor);
        ChargeRequest req = loadPending(tenantId, requestId);
        userMapper.addBalance(req.getUserId(), req.getAmount());
        reqMapper.updateStatus(requestId, ChargeRequest.Status.approved.name(), actor.getId(), null);
    }

    /** admin/super_admin - 반려 (잔액 변동 없음) */
    @Transactional
    public void reject(String tenantId, String requestId, String reason, User actor) {
        authorize(tenantId, actor);
        loadPending(tenantId, requestId);
        reqMapper.updateStatus(requestId, ChargeRequest.Status.rejected.name(), actor.getId(), reason);
    }

    // ── 내부 ────────────────────────────────────────────────
    private ChargeRequest loadPending(String tenantId, String requestId) {
        ChargeRequest req = reqMapper.findById(requestId)
                .orElseThrow(() -> AppException.notFound("충전 요청을 찾을 수 없습니다."));
        if (!req.getTenantId().equals(tenantId))
            throw AppException.badRequest("해당 상점의 충전 요청이 아닙니다.");
        if (!ChargeRequest.Status.pending.name().equals(req.getStatus()))
            throw AppException.badRequest("이미 처리된 요청입니다.");
        return req;
    }

    private void authorize(String tenantId, User actor) {
        if (!actor.canManage(tenantId))
            throw AppException.forbidden("해당 상점의 관리자만 처리할 수 있습니다.");
    }
}
