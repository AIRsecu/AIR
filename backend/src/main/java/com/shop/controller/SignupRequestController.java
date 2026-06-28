package com.shop.controller;

import com.shop.domain.SignupRequest;
import com.shop.domain.User;
import com.shop.dto.ApiResponse;
import com.shop.dto.signup.CreateSignupRequest;
import com.shop.service.NotificationService;
import com.shop.service.SignupRequestService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/v1/tenants/{tenantId}/signup-requests")
@RequiredArgsConstructor
public class SignupRequestController {

    private final SignupRequestService service;
    private final NotificationService notificationService;

    /** 공개 - 회원가입 요청 제출 */
    @PostMapping
    public ResponseEntity<ApiResponse<SignupRequest>> submit(
            @PathVariable String tenantId,
            @Valid @RequestBody CreateSignupRequest req) {
        SignupRequest r = service.submit(tenantId, req.username(), req.password(), req.displayName());
        notificationService.notifyTenantActivity(tenantId);   // 새 가입요청 → 관리자 실시간 알림
        return ResponseEntity.status(HttpStatus.CREATED).body(ApiResponse.ok(r));
    }

    /** admin/super_admin - 가입요청 목록 (status 필터 옵션) */
    @GetMapping
    public ResponseEntity<ApiResponse<List<SignupRequest>>> list(
            @PathVariable String tenantId,
            @RequestParam(required = false) String status,
            @AuthenticationPrincipal User actor) {
        return ResponseEntity.ok(ApiResponse.ok(service.list(tenantId, status, actor)));
    }

    /** admin/super_admin - 승인 */
    @PostMapping("/{id}/approve")
    public ResponseEntity<ApiResponse<User>> approve(
            @PathVariable String tenantId,
            @PathVariable String id,
            @AuthenticationPrincipal User actor) {
        User created = service.approve(tenantId, id, actor);
        notificationService.notifyTenantActivity(tenantId);   // 대기집계 갱신
        return ResponseEntity.ok(ApiResponse.ok(created));
    }

    /** admin/super_admin - 반려 */
    @PostMapping("/{id}/reject")
    public ResponseEntity<ApiResponse<Void>> reject(
            @PathVariable String tenantId,
            @PathVariable String id,
            @RequestBody(required = false) Map<String, String> body,
            @AuthenticationPrincipal User actor) {
        String reason = body != null ? body.get("reason") : null;
        service.reject(tenantId, id, reason, actor);
        notificationService.notifyTenantActivity(tenantId);   // 대기집계 갱신
        return ResponseEntity.ok(ApiResponse.ok());
    }
}
