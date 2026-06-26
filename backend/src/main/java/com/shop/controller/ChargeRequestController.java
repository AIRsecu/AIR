package com.shop.controller;

import com.shop.domain.ChargeRequest;
import com.shop.domain.User;
import com.shop.dto.ApiResponse;
import com.shop.dto.charge.CreateChargeRequest;
import com.shop.service.ChargeRequestService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/v1/tenants/{tenantId}/charge-requests")
@RequiredArgsConstructor
public class ChargeRequestController {

    private final ChargeRequestService service;

    /** customer - 충전 요청 제출 */
    @PostMapping
    public ResponseEntity<ApiResponse<ChargeRequest>> submit(
            @PathVariable String tenantId,
            @Valid @RequestBody CreateChargeRequest req,
            @AuthenticationPrincipal User actor) {
        ChargeRequest r = service.submit(tenantId, actor, req.amount());
        return ResponseEntity.status(HttpStatus.CREATED).body(ApiResponse.ok(r));
    }

    /** customer - 내 충전 요청 내역 */
    @GetMapping("/mine")
    public ResponseEntity<ApiResponse<List<ChargeRequest>>> mine(
            @AuthenticationPrincipal User actor) {
        return ResponseEntity.ok(ApiResponse.ok(service.listMine(actor)));
    }

    /** admin/super_admin - 충전 요청 목록 */
    @GetMapping
    public ResponseEntity<ApiResponse<List<ChargeRequest>>> list(
            @PathVariable String tenantId,
            @RequestParam(required = false) String status,
            @AuthenticationPrincipal User actor) {
        return ResponseEntity.ok(ApiResponse.ok(service.list(tenantId, status, actor)));
    }

    /** admin/super_admin - 승인 */
    @PostMapping("/{id}/approve")
    public ResponseEntity<ApiResponse<Void>> approve(
            @PathVariable String tenantId, @PathVariable String id,
            @AuthenticationPrincipal User actor) {
        service.approve(tenantId, id, actor);
        return ResponseEntity.ok(ApiResponse.ok());
    }

    /** admin/super_admin - 반려 */
    @PostMapping("/{id}/reject")
    public ResponseEntity<ApiResponse<Void>> reject(
            @PathVariable String tenantId, @PathVariable String id,
            @RequestBody(required = false) Map<String, String> body,
            @AuthenticationPrincipal User actor) {
        String reason = body != null ? body.get("reason") : null;
        service.reject(tenantId, id, reason, actor);
        return ResponseEntity.ok(ApiResponse.ok());
    }
}
