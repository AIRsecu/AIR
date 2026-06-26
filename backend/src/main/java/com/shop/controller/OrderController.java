package com.shop.controller;

import com.shop.domain.Order;
import com.shop.domain.User;
import com.shop.dto.ApiResponse;
import com.shop.dto.order.PlaceOrderRequest;
import com.shop.service.OrderService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/v1/tenants/{tenantId}/orders")
@RequiredArgsConstructor
public class OrderController {

    private final OrderService orderService;

    /** admin – 해당 테넌트의 전체 주문 */
    @GetMapping
    public ResponseEntity<ApiResponse<List<Order>>> listByTenant(
            @PathVariable String tenantId,
            @AuthenticationPrincipal User actor) {
        if (!actor.canManage(tenantId))
            return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
        return ResponseEntity.ok(ApiResponse.ok(orderService.listByTenant(tenantId)));
    }

    /** customer – 내 주문 목록 */
    @GetMapping("/my")
    public ResponseEntity<ApiResponse<List<Order>>> listMine(
            @AuthenticationPrincipal User actor) {
        return ResponseEntity.ok(ApiResponse.ok(orderService.listByCustomer(actor.getId())));
    }

    @GetMapping("/{id}")
    public ResponseEntity<ApiResponse<Order>> get(@PathVariable String id) {
        return ResponseEntity.ok(ApiResponse.ok(orderService.getById(id)));
    }

    /** customer – 주문 생성 */
    @PostMapping
    public ResponseEntity<ApiResponse<Order>> place(
            @PathVariable String tenantId,
            @Valid @RequestBody PlaceOrderRequest req,
            @AuthenticationPrincipal User actor) {
        Order order = orderService.placeOrder(tenantId, req, actor);
        return ResponseEntity.status(HttpStatus.CREATED).body(ApiResponse.ok(order));
    }

    /** admin – 주문 상태 변경 */
    @PatchMapping("/{id}/status")
    public ResponseEntity<ApiResponse<Void>> updateStatus(
            @PathVariable String id,
            @RequestBody Map<String, String> body,
            @AuthenticationPrincipal User actor) {
        orderService.updateStatus(id, body.get("status"), actor);
        return ResponseEntity.ok(ApiResponse.ok());
    }
}
