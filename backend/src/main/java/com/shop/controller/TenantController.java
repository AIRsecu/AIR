package com.shop.controller;

import com.shop.domain.Tenant;
import com.shop.domain.User;
import com.shop.dto.ApiResponse;
import com.shop.dto.tenant.*;
import com.shop.service.TenantService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/v1/tenants")
@RequiredArgsConstructor
public class TenantController {

    private final TenantService tenantService;

    /** 공개 – 활성 테넌트 목록 */
    @GetMapping
    public ResponseEntity<ApiResponse<List<Tenant>>> listActive() {
        return ResponseEntity.ok(ApiResponse.ok(tenantService.listActive()));
    }

    /** super_admin – 전체 테넌트 목록 */
    @GetMapping("/all")
    public ResponseEntity<ApiResponse<List<Tenant>>> listAll(
            @AuthenticationPrincipal User actor) {
        if (!actor.isSuperAdmin())
            return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
        return ResponseEntity.ok(ApiResponse.ok(tenantService.listAll()));
    }

    /** 로그인 사용자가 관리하는 테넌트 목록 (super_admin=전체, admin=배정분) */
    @GetMapping("/managed")
    public ResponseEntity<ApiResponse<List<Tenant>>> listManaged(
            @AuthenticationPrincipal User actor) {
        return ResponseEntity.ok(ApiResponse.ok(tenantService.listManagedBy(actor)));
    }

    @GetMapping("/{id}")
    public ResponseEntity<ApiResponse<Tenant>> get(@PathVariable String id) {
        return ResponseEntity.ok(ApiResponse.ok(tenantService.getById(id)));
    }

    /** super_admin/admin – 테넌트 생성 (admin 은 생성 시 자동으로 관리자 배정) */
    @PostMapping
    public ResponseEntity<ApiResponse<Tenant>> create(
            @Valid @RequestBody CreateTenantRequest req,
            @AuthenticationPrincipal User actor) {
        if (!actor.isSuperAdmin() && !actor.isAdmin())
            return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
        Tenant t = tenantService.create(req, actor.getId());
        return ResponseEntity.status(HttpStatus.CREATED).body(ApiResponse.ok(t));
    }

    // ── 테넌트 관리자 배정 (super_admin) ──────────────────────
    /** 테넌트에 배정된 관리자 목록 */
    @GetMapping("/{id}/admins")
    public ResponseEntity<ApiResponse<List<User>>> listAdmins(
            @PathVariable String id, @AuthenticationPrincipal User actor) {
        return ResponseEntity.ok(ApiResponse.ok(tenantService.listAdmins(id, actor)));
    }

    /** 관리자 배정 */
    @PostMapping("/{id}/admins")
    public ResponseEntity<ApiResponse<Void>> assignAdmin(
            @PathVariable String id, @RequestBody Map<String, String> body,
            @AuthenticationPrincipal User actor) {
        tenantService.assignAdmin(id, body.get("userId"), actor);
        return ResponseEntity.ok(ApiResponse.ok());
    }

    /** 관리자 배정 해제 */
    @DeleteMapping("/{id}/admins/{userId}")
    public ResponseEntity<ApiResponse<Void>> unassignAdmin(
            @PathVariable String id, @PathVariable String userId,
            @AuthenticationPrincipal User actor) {
        tenantService.unassignAdmin(id, userId, actor);
        return ResponseEntity.ok(ApiResponse.ok());
    }

    @PatchMapping("/{id}")
    public ResponseEntity<ApiResponse<Tenant>> update(
            @PathVariable String id,
            @RequestBody UpdateTenantRequest req,
            @AuthenticationPrincipal User actor) {
        return ResponseEntity.ok(ApiResponse.ok(tenantService.update(id, req, actor)));
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<ApiResponse<Void>> delete(
            @PathVariable String id,
            @AuthenticationPrincipal User actor) {
        tenantService.delete(id, actor);
        return ResponseEntity.ok(ApiResponse.ok());
    }
}
