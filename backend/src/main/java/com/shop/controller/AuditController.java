package com.shop.controller;

import com.shop.domain.AuditLog;
import com.shop.domain.User;
import com.shop.dto.ApiResponse;
import com.shop.service.AuditService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/v1/audit")
@RequiredArgsConstructor
public class AuditController {

    private final AuditService auditService;

    /** super_admin – 전체 최근 로그 */
    @GetMapping("/recent")
    public ResponseEntity<ApiResponse<List<AuditLog>>> recent(
            @RequestParam(defaultValue = "100") int limit,
            @AuthenticationPrincipal User actor) {
        if (!actor.isSuperAdmin())
            return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
        return ResponseEntity.ok(ApiResponse.ok(auditService.findRecent(limit)));
    }

    /** super_admin – 테넌트별 로그 */
    @GetMapping("/tenant/{tenantId}")
    public ResponseEntity<ApiResponse<List<AuditLog>>> byTenant(
            @PathVariable String tenantId,
            @AuthenticationPrincipal User actor) {
        if (!actor.canManage(tenantId))
            return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
        return ResponseEntity.ok(ApiResponse.ok(auditService.findByTenant(tenantId)));
    }

    /** 본인 행위 로그 */
    @GetMapping("/me")
    public ResponseEntity<ApiResponse<List<AuditLog>>> mine(
            @AuthenticationPrincipal User actor) {
        return ResponseEntity.ok(ApiResponse.ok(auditService.findByActor(actor.getId())));
    }

    /** 특정 리소스 로그 (super_admin) */
    @GetMapping("/resource/{resourceId}")
    public ResponseEntity<ApiResponse<List<AuditLog>>> byResource(
            @PathVariable String resourceId,
            @AuthenticationPrincipal User actor) {
        if (!actor.isSuperAdmin())
            return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
        return ResponseEntity.ok(ApiResponse.ok(auditService.findByResource(resourceId)));
    }
}
