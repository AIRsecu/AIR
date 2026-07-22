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
    private final DynamicRuleRegistry ruleRegistry;

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
    public ResponseEntity<ApiResponse<List<Map<String, Object>>>> incidents(
            @RequestParam(defaultValue = "100") int limit, @AuthenticationPrincipal User actor) {
        requireSuper(actor);
        List<Map<String, Object>> enriched = incidentService.recent(limit).stream()
                .map(AirController::enrich).toList();
        return ResponseEntity.ok(ApiResponse.ok(enriched));
    }

    /** [IR] 인시던트에 위험도(severity/riskScore) 를 덧붙여 반환.
     *  [A2] 저장된 시점 위험도 우선 — 과거 행(severity/score=null)은 유형기반 재계산 폴백. */
    private static Map<String, Object> enrich(SecurityIncident i) {
        Map<String, Object> m = new java.util.LinkedHashMap<>();
        m.put("id", i.getId());
        m.put("type", i.getType());
        m.put("severity", i.getSeverity() != null ? i.getSeverity() : RiskScoring.severity(i.getType()));
        m.put("riskScore", i.getScore() != null ? i.getScore() : RiskScoring.score(i.getType()));
        m.put("endpoint", i.getEndpoint());
        m.put("clientIp", i.getClientIp());
        m.put("actor", i.getActor());
        m.put("payload", i.getPayload());
        m.put("actionTaken", i.getActionTaken());
        m.put("status", i.getStatus());
        m.put("createdAt", i.getCreatedAt());
        return m;
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

    // ── [Stage2] 런타임 동적 차단 룰 (LLM 어드바이저/운영자가 설치) ──

    @GetMapping("/rules")
    public ResponseEntity<ApiResponse<List<DynamicRule>>> rules(@AuthenticationPrincipal User actor) {
        requireSuper(actor);
        return ResponseEntity.ok(ApiResponse.ok(ruleRegistry.all()));
    }

    /** body: { ip, method, pathContains, contains, action(BLOCK), source } — 즉시 적용(재배포 X) */
    @PostMapping("/rules")
    public ResponseEntity<ApiResponse<DynamicRule>> addRule(
            @RequestBody Map<String, String> body, @AuthenticationPrincipal User actor) {
        requireSuper(actor);
        DynamicRule r = ruleRegistry.add(
                body.get("ip"), body.get("method"), body.get("pathContains"),
                body.get("contains"), body.get("action"), body.getOrDefault("source", "manual"));
        return ResponseEntity.ok(ApiResponse.ok(r));
    }

    @DeleteMapping("/rules/{id}")
    public ResponseEntity<ApiResponse<Void>> deleteRule(
            @PathVariable String id, @AuthenticationPrincipal User actor) {
        requireSuper(actor);
        ruleRegistry.remove(id);
        return ResponseEntity.ok(ApiResponse.ok());
    }

    private static void requireSuper(User actor) {
        if (actor == null || !actor.isSuperAdmin())
            throw AppException.forbidden("super_admin 만 접근할 수 있습니다.");
    }
}
