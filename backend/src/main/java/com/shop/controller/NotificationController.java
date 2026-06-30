package com.shop.controller;

import com.shop.domain.User;
import com.shop.dto.ApiResponse;
import com.shop.dto.signup.PendingCount;
import com.shop.service.NotificationService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.http.MediaType;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

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

    /**
     * 실시간 알림 스트림(SSE). 변경 발생 시점에만 이벤트를 흘려보내 폴링을 대체.
     *  - 이벤트: "pending"(관리자 대기집계), "order"(고객 주문상태), "charge"(고객 충전처리)
     *  - 브라우저 EventSource 는 헤더를 못 보내므로 ?token= 쿼리로 인증(JwtAuthFilter 처리)
     */
    @GetMapping(value = "/stream", produces = MediaType.TEXT_EVENT_STREAM_VALUE)
    public SseEmitter stream(@AuthenticationPrincipal User actor) {
        return notificationService.subscribe(actor);
    }
}
