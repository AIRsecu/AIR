package com.shop.service;

import com.shop.domain.Tenant;
import com.shop.domain.User;
import com.shop.dto.tenant.*;
import com.shop.exception.AppException;
import com.shop.mapper.TenantAdminMapper;
import com.shop.mapper.TenantMapper;
import com.shop.mapper.UserMapper;
import com.shop.util.UlidUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;

@Service
@RequiredArgsConstructor
public class TenantService {

    private final TenantMapper      tenantMapper;
    private final UserMapper        userMapper;
    private final TenantAdminMapper tenantAdminMapper;

    public List<Tenant> listAll()    { return tenantMapper.findAll(); }
    public List<Tenant> listActive() { return tenantMapper.findAllActive(); }

    public Tenant getById(String id) {
        return tenantMapper.findById(id)
                .orElseThrow(() -> AppException.notFound("테넌트를 찾을 수 없습니다."));
    }

    public Tenant getBySlug(String slug) {
        return tenantMapper.findBySlug(slug)
                .orElseThrow(() -> AppException.notFound("테넌트를 찾을 수 없습니다."));
    }

    @Transactional
    public Tenant create(CreateTenantRequest req, String ownerUserId) {
        if (tenantMapper.countBySlug(req.slug()) > 0)
            throw AppException.conflict("이미 사용 중인 슬러그입니다: " + req.slug());

        Tenant tenant = Tenant.builder()
                .id(UlidUtil.generate())
                .name(req.name())
                .slug(req.slug())
                .domain(blankToNull(req.domain()))
                .ownerId(ownerUserId)
                .description(req.description())
                .logoUrl(req.logoUrl())
                .isActive(true)
                .build();

        tenantMapper.insert(tenant);

        // admin 이 직접 만든 경우 → 그 admin 을 이 테넌트의 관리자로 배정(다대다).
        //  (super_admin 은 전역 권한이라 별도 배정 불필요)
        User owner = userMapper.findById(ownerUserId)
                .orElseThrow(() -> AppException.notFound("소유자 사용자를 찾을 수 없습니다."));
        if (owner.isAdmin())
            tenantAdminMapper.insert(tenant.getId(), owner.getId());

        return tenant;
    }

    @Transactional
    public Tenant update(String id, UpdateTenantRequest req, User actor) {
        Tenant existing = getById(id);

        // super_admin 또는 이 테넌트를 관리하는 admin 만 수정 가능
        if (!actor.canManage(id))
            throw AppException.forbidden("테넌트 수정 권한이 없습니다.");

        // slug(접속 주소) 변경 — 형식/중복 검증
        String newSlug = existing.getSlug();
        if (req.slug() != null && !req.slug().equals(existing.getSlug())) {
            if (!req.slug().matches("^[a-z0-9-]+$"))
                throw AppException.badRequest("슬러그는 소문자/숫자/하이픈만 가능합니다.");
            if (tenantMapper.countBySlugExcluding(req.slug(), id) > 0)
                throw AppException.conflict("이미 사용 중인 슬러그입니다: " + req.slug());
            newSlug = req.slug();
        }

        // domain(커스텀 접속 도메인) — null=변경없음, 빈문자열=제거
        String newDomain = existing.getDomain();
        if (req.domain() != null)
            newDomain = blankToNull(req.domain());

        Tenant updated = Tenant.builder()
                .id(existing.getId())
                .name(req.name() != null ? req.name() : existing.getName())
                .slug(newSlug)
                .domain(newDomain)
                .ownerId(existing.getOwnerId())
                .description(req.description() != null ? req.description() : existing.getDescription())
                .logoUrl(req.logoUrl() != null ? req.logoUrl() : existing.getLogoUrl())
                .isActive(req.isActive() != null ? req.isActive() : existing.isActive())
                .build();

        tenantMapper.update(updated);
        return updated;
    }

    @Transactional
    public void delete(String id, User actor) {
        Tenant existing = getById(id);
        if (!actor.isSuperAdmin())
            throw AppException.forbidden("테넌트 삭제는 슈퍼관리자만 가능합니다.");
        tenantMapper.softDelete(existing.getId());
    }

    // ── 다중 테넌트 관리 (admin ↔ tenant) ───────────────────
    /** 액터가 관리하는 테넌트 목록 (super_admin=전체, admin=home+배정) */
    public List<Tenant> listManagedBy(User actor) {
        if (actor.isSuperAdmin()) return tenantMapper.findAll();
        LinkedHashMap<String, Tenant> map = new LinkedHashMap<>();
        if (actor.getTenantId() != null)
            tenantMapper.findById(actor.getTenantId()).ifPresent(t -> map.put(t.getId(), t));
        for (String tid : tenantAdminMapper.findTenantIdsByUser(actor.getId()))
            tenantMapper.findById(tid).ifPresent(t -> map.put(t.getId(), t));
        return new ArrayList<>(map.values());
    }

    /** 테넌트에 배정된 관리자 목록 (home 소속 admin + 다대다 배정 admin) */
    public List<User> listAdmins(String tenantId, User actor) {
        if (!actor.canManage(tenantId))
            throw AppException.forbidden("권한이 없습니다.");
        LinkedHashMap<String, User> map = new LinkedHashMap<>();
        for (User u : userMapper.findByTenantId(tenantId))
            if (u.isAdmin()) map.put(u.getId(), u);
        for (String uid : tenantAdminMapper.findUserIdsByTenant(tenantId))
            if (!map.containsKey(uid)) userMapper.findById(uid).ifPresent(u -> map.put(u.getId(), u));
        return new ArrayList<>(map.values());
    }

    @Transactional
    public void assignAdmin(String tenantId, String userId, User actor) {
        if (!actor.isSuperAdmin())
            throw AppException.forbidden("관리자 배정은 슈퍼관리자만 가능합니다.");
        getById(tenantId);
        User u = userMapper.findById(userId)
                .orElseThrow(() -> AppException.notFound("사용자를 찾을 수 없습니다."));
        if (!u.isAdmin())
            throw AppException.badRequest("admin 역할의 사용자만 테넌트 관리자로 배정할 수 있습니다.");
        tenantAdminMapper.insert(tenantId, userId);
    }

    @Transactional
    public void unassignAdmin(String tenantId, String userId, User actor) {
        if (!actor.isSuperAdmin())
            throw AppException.forbidden("관리자 배정 해제는 슈퍼관리자만 가능합니다.");
        tenantAdminMapper.delete(tenantId, userId);
    }

    private static String blankToNull(String s) {
        return (s == null || s.isBlank()) ? null : s;
    }
}
