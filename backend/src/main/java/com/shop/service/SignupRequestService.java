package com.shop.service;

import com.shop.domain.SignupRequest;
import com.shop.domain.Tenant;
import com.shop.domain.User;
import com.shop.exception.AppException;
import com.shop.mapper.SignupRequestMapper;
import com.shop.mapper.TenantMapper;
import com.shop.mapper.UserMapper;
import com.shop.util.UlidUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
@RequiredArgsConstructor
public class SignupRequestService {

    private final SignupRequestMapper reqMapper;
    private final UserMapper           userMapper;
    private final TenantMapper         tenantMapper;
    private final PasswordEncoder      encoder;

    /** 공개 - 회원가입 요청 제출 */
    @Transactional
    public SignupRequest submit(String tenantId, String username, String rawPassword, String displayName) {
        Tenant tenant = tenantMapper.findById(tenantId)
                .orElseThrow(() -> AppException.notFound("테넌트를 찾을 수 없습니다."));
        if (!tenant.isActive())
            throw AppException.badRequest("현재 가입을 받지 않는 상점입니다.");

        if (userMapper.countByUsername(username) > 0)
            throw AppException.conflict("이미 사용 중인 사용자명입니다.");
        if (reqMapper.countPendingByUsername(username) > 0)
            throw AppException.conflict("이미 처리 대기 중인 동일 사용자명 요청이 있습니다.");

        SignupRequest req = SignupRequest.builder()
                .id(UlidUtil.generate())
                .tenantId(tenantId)
                .username(username)
                .passwordHash(encoder.encode(rawPassword))
                .displayName(displayName)
                .status(SignupRequest.Status.pending.name())
                .build();

        reqMapper.insert(req);
        return req;
    }

    /** admin/super_admin - 테넌트의 가입요청 목록 */
    public List<SignupRequest> list(String tenantId, String status, User actor) {
        authorizeTenantAdmin(tenantId, actor);
        return (status == null || status.isBlank())
                ? reqMapper.findByTenant(tenantId)
                : reqMapper.findByTenantAndStatus(tenantId, status);
    }

    /** admin/super_admin - 승인 → customer 계정 생성 */
    @Transactional
    public User approve(String tenantId, String requestId, User actor) {
        authorizeTenantAdmin(tenantId, actor);
        SignupRequest req = loadPending(tenantId, requestId);

        if (userMapper.countByUsername(req.getUsername()) > 0)
            throw AppException.conflict("이미 사용 중인 사용자명입니다. 반려 처리하세요: " + req.getUsername());

        User user = User.builder()
                .id(UlidUtil.generate())
                .username(req.getUsername())
                .passwordHash(req.getPasswordHash())   // 요청 시 해시 저장한 값 그대로 사용
                .role(User.Role.customer)
                .displayName(req.getDisplayName())
                .isActive(true)
                .tenantId(tenantId)
                .build();
        userMapper.insert(user);

        reqMapper.updateStatus(requestId, SignupRequest.Status.approved.name(), actor.getId(), null);
        return user;
    }

    /** admin/super_admin - 반려 */
    @Transactional
    public void reject(String tenantId, String requestId, String reason, User actor) {
        authorizeTenantAdmin(tenantId, actor);
        loadPending(tenantId, requestId);
        reqMapper.updateStatus(requestId, SignupRequest.Status.rejected.name(), actor.getId(), reason);
    }

    // ── 내부 헬퍼 ───────────────────────────────────────────
    private SignupRequest loadPending(String tenantId, String requestId) {
        SignupRequest req = reqMapper.findById(requestId)
                .orElseThrow(() -> AppException.notFound("가입요청을 찾을 수 없습니다."));
        if (!req.getTenantId().equals(tenantId))
            throw AppException.badRequest("해당 상점의 가입요청이 아닙니다.");
        if (!SignupRequest.Status.pending.name().equals(req.getStatus()))
            throw AppException.badRequest("이미 처리된 요청입니다.");
        return req;
    }

    private void authorizeTenantAdmin(String tenantId, User actor) {
        if (!actor.canManage(tenantId))
            throw AppException.forbidden("해당 상점의 관리자만 처리할 수 있습니다.");
    }
}
