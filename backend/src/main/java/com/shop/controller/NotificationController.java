package com.shop.controller;

import com.shop.domain.User;
import com.shop.dto.ApiResponse;
import com.shop.dto.signup.PendingCount;
import com.shop.service.NotificationService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping("/api/v1/notifications")
@RequiredArgsConstructor
public class NotificationController {

    private final NotificationService notificationService;

    /** 관리하는 테넌트별 대기 알림(가입+충전) 개수 (super_admin/admin) */
    @GetMapping("/pending-signups")
    public ResponseEntity<ApiResponse<List<PendingCount>>> pending(
            @AuthenticationPrincipal User actor) {
        return ResponseEntity.ok(ApiResponse.ok(notificationService.pending(actor)));
    }
}
