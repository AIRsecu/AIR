package com.shop.air;

import com.shop.domain.User;
import com.shop.dto.ApiResponse;
import com.shop.exception.AppException;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

/** AIR 제어/관측 API (super_admin 전용) — 방어 토글 + 인시던트 조회. */
@RestController
@RequestMapping("/api/v1/air")
@RequiredArgsConstructor
public class AirController {

    private final DefenseRegistry registry;
    private final IncidentService incidentService;

    @GetMapping("/defenses")
    public ResponseEntity<ApiResponse<Map<String, Boolean>>> defenses(@AuthenticationPrincipal User actor) {
        requireSuper(actor);
        return ResponseEntity.ok(ApiResponse.ok(registry.all()));
    }

    @PostMapping("/defenses/{key}/enable")
    public ResponseEntity<ApiResponse<Void>> enable(@PathVariable String key, @AuthenticationPrincipal User actor) {
        requireSuper(actor);
        registry.enable(key);
        return ResponseEntity.ok(ApiResponse.ok());
    }

    @PostMapping("/defenses/{key}/disable")
    public ResponseEntity<ApiResponse<Void>> disable(@PathVariable String key, @AuthenticationPrincipal User actor) {
        requireSuper(actor);
        registry.disable(key);   // 데모용: 일부러 취약 상태로 되돌리기
        return ResponseEntity.ok(ApiResponse.ok());
    }

    @GetMapping("/incidents")
    public ResponseEntity<ApiResponse<List<SecurityIncident>>> incidents(
            @RequestParam(defaultValue = "100") int limit, @AuthenticationPrincipal User actor) {
        requireSuper(actor);
        return ResponseEntity.ok(ApiResponse.ok(incidentService.recent(limit)));
    }

    /** 외부 오케스트레이터가 자동 소스패치 결과를 기록 — status=PATCHED|FAILED, action=설명 */
    @PostMapping("/incidents/{id}/status")
    public ResponseEntity<ApiResponse<Void>> incidentStatus(
            @PathVariable String id, @RequestParam String status,
            @RequestParam(required = false) String action, @AuthenticationPrincipal User actor) {
        requireSuper(actor);
        incidentService.updateStatus(id, status, action);
        return ResponseEntity.ok(ApiResponse.ok());
    }

    private static void requireSuper(User actor) {
        if (actor == null || !actor.isSuperAdmin())
            throw AppException.forbidden("super_admin 만 접근할 수 있습니다.");
    }
}
