package com.shop.service;

import com.shop.domain.User;
import com.shop.exception.AppException;
import com.shop.mapper.UserMapper;
import com.shop.util.UlidUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
@RequiredArgsConstructor
public class UserService {

    private final UserMapper    userMapper;
    private final PasswordEncoder encoder;

    public User getById(String id) {
        return userMapper.findById(id)
                .orElseThrow(() -> AppException.notFound("사용자를 찾을 수 없습니다."));
    }

    public List<User> listAll() {
        return userMapper.findAll();
    }

    public List<User> listByTenant(String tenantId) {
        return userMapper.findByTenantId(tenantId);
    }

    @Transactional
    public User create(String username, String rawPassword,
                       User.Role role, String displayName,
                       String tenantId) {
        if (userMapper.countByUsername(username) > 0)
            throw AppException.conflict("이미 사용 중인 사용자명입니다: " + username);

        // super_admin 은 전역(null), admin/customer 는 소속 테넌트 필수
        String effectiveTenantId = tenantId;
        if (role == User.Role.super_admin) {
            effectiveTenantId = null;
        } else if (effectiveTenantId == null || effectiveTenantId.isBlank()) {
            throw AppException.badRequest("admin/customer 는 소속 테넌트가 필요합니다.");
        }

        User user = User.builder()
                .id(UlidUtil.generate())
                .username(username)
                .passwordHash(encoder.encode(rawPassword))
                .role(role)
                .displayName(displayName)
                .isActive(true)
                .tenantId(effectiveTenantId)
                .build();

        userMapper.insert(user);
        return user;
    }

    @Transactional
    public User update(String id, String displayName, Boolean isActive,
                       User.Role role, String tenantId, User actor) {
        User existing = getById(id);

        // 본인 또는 super_admin만 수정 가능
        if (!actor.isSuperAdmin() && !actor.getId().equals(id))
            throw AppException.forbidden("본인 계정만 수정할 수 있습니다.");

        // ── 역할 변경 처리 (super_admin 전용) ──
        User.Role newRole = existing.getRole();
        if (role != null && role != existing.getRole()) {
            if (!actor.isSuperAdmin())
                throw AppException.forbidden("역할 변경은 슈퍼관리자만 가능합니다.");
            if (actor.getId().equals(id))
                throw AppException.forbidden("본인의 역할은 변경할 수 없습니다.");
            newRole = role;
        }

        // ── 소속 테넌트 결정 ──
        //  super_admin → 전역(null) / 그 외 → 지정값 있으면 변경, 없으면 기존 유지
        String newTenantId;
        if (newRole == User.Role.super_admin) {
            newTenantId = null;
        } else if (tenantId != null && actor.isSuperAdmin()) {
            newTenantId = tenantId;
        } else {
            newTenantId = existing.getTenantId();
        }
        if (newRole != User.Role.super_admin && (newTenantId == null || newTenantId.isBlank()))
            throw AppException.badRequest("admin/customer 는 소속 테넌트가 필요합니다.");

        User updated = User.builder()
                .id(existing.getId())
                .username(existing.getUsername())
                .passwordHash(existing.getPasswordHash())
                .role(newRole)
                .displayName(displayName != null ? displayName : existing.getDisplayName())
                .isActive(isActive != null ? isActive : existing.isActive())
                .tenantId(newTenantId)
                .build();

        userMapper.update(updated);
        return updated;
    }

    @Transactional
    public void delete(String id, User actor) {
        if (!actor.isSuperAdmin())
            throw AppException.forbidden("사용자 삭제는 슈퍼관리자만 가능합니다.");
        getById(id); // 존재 확인
        userMapper.softDelete(id);
    }

    @Transactional
    public void changePassword(String id, String oldRaw, String newRaw, User actor) {
        User existing = getById(id);

        // 본인 또는 super_admin
        boolean isSelf = actor.getId().equals(id);
        if (!isSelf && !actor.isSuperAdmin())
            throw AppException.forbidden("권한이 없습니다.");

        // 본인이 바꾸는 경우 기존 비밀번호 검증
        if (isSelf && !encoder.matches(oldRaw, existing.getPasswordHash()))
            throw AppException.badRequest("현재 비밀번호가 일치하지 않습니다.");

        userMapper.updatePasswordHash(existing.getId(), encoder.encode(newRaw));
    }
}
