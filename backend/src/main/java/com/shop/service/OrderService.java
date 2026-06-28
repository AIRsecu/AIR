package com.shop.service;

import com.shop.domain.Order;
import com.shop.domain.OrderItem;
import com.shop.domain.User;
import com.shop.dto.order.*;
import com.shop.exception.AppException;
import com.shop.air.DefenseRegistry;
import com.shop.mapper.OrderMapper;
import com.shop.mapper.ProductMapper;
import com.shop.mapper.TenantMapper;
import com.shop.mapper.UserMapper;
import com.shop.util.UlidUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.List;

@Service
@RequiredArgsConstructor
public class OrderService {

    private final OrderMapper   orderMapper;
    private final ProductMapper productMapper;
    private final UserMapper    userMapper;
    private final TenantMapper  tenantMapper;
    private final DefenseRegistry defense;   // [AIR] 방어 토글

    public List<Order> listByTenant(String tenantId) {
        return orderMapper.findByTenantId(tenantId);
    }

    public List<Order> listByCustomer(String customerId) {
        return orderMapper.findByCustomerId(customerId);
    }

    /** 소유 고객 또는 해당 테넌트 관리자만 단건 조회 가능 (IDOR 방지) */
    public Order getByIdAuthorized(String id, User actor) {
        Order order = getById(id);
        if (!actor.getId().equals(order.getCustomerId()) && !actor.canManage(order.getTenantId()))
            throw AppException.forbidden("해당 주문에 대한 권한이 없습니다.");
        return order;
    }

    public Order getById(String id) {
        Order order = orderMapper.findById(id)
                .orElseThrow(() -> AppException.notFound("주문을 찾을 수 없습니다."));
        List<OrderItem> items = orderMapper.findItemsByOrderId(id);
        return Order.builder()
                .id(order.getId())
                .tenantId(order.getTenantId())
                .customerId(order.getCustomerId())
                .status(order.getStatus())
                .totalAmount(order.getTotalAmount())
                .items(items)
                .createdAt(order.getCreatedAt())
                .updatedAt(order.getUpdatedAt())
                .build();
    }

    @Transactional
    public Order placeOrder(String tenantId, PlaceOrderRequest req, User customer) {
        if (!customer.isCustomer())
            throw AppException.forbidden("주문은 고객만 가능합니다.");
        if (!customer.belongsTo(tenantId))
            throw AppException.forbidden("해당 쇼핑몰의 고객이 아닙니다.");

        List<OrderItem> items = new ArrayList<>();
        long total = 0;
        String orderId = UlidUtil.generate();

        // [AIR] order.qty-guard 가 ON 이면 음수수량/오버플로 방어 활성, OFF 면 취약(공격 가능)
        boolean guard = defense.isEnabled(DefenseRegistry.ORDER_QTY_GUARD);

        for (PlaceOrderRequest.ItemLine line : req.items()) {
            if (guard && (line.quantity() == null || line.quantity() <= 0))
                throw AppException.badRequest("주문 수량은 1 이상이어야 합니다.");

            var product = productMapper.findById(line.productId())
                    .orElseThrow(() -> AppException.notFound("상품 없음: " + line.productId()));

            if (!product.getTenantId().equals(tenantId))
                throw AppException.badRequest("다른 쇼핑몰 상품은 주문할 수 없습니다.");
            if (guard && product.getPrice() < 0)
                throw AppException.badRequest("상품 가격이 올바르지 않습니다.");

            // 재고 차감 (XML에서 stock >= qty 조건으로 원자적 처리)
            int affected = productMapper.decreaseStock(product.getId(), line.quantity());
            if (affected == 0)
                throw AppException.badRequest("재고 부족: " + product.getName());

            OrderItem item = OrderItem.builder()
                    .id(UlidUtil.generate())
                    .orderId(orderId)
                    .productId(product.getId())
                    .quantity(line.quantity())
                    .unitPrice(product.getPrice())
                    .build();

            items.add(item);
            if (guard) {
                // 오버플로 방어 (음수 total 로 잔액 가드 우회 차단)
                try {
                    total = Math.addExact(total, Math.multiplyExact(product.getPrice(), (long) line.quantity()));
                } catch (ArithmeticException e) {
                    throw AppException.badRequest("주문 금액이 허용 범위를 초과했습니다.");
                }
            } else {
                total += product.getPrice() * line.quantity();   // 취약: 음수수량 → 음수 total
            }
        }
        if (guard && total < 0)
            throw AppException.badRequest("주문 금액이 올바르지 않습니다.");

        // 잔액 확인 + 차감 (원자적: 잔액 >= 주문금액일 때만 성공)
        int paid = userMapper.deductBalance(customer.getId(), total);
        if (paid == 0)
            throw AppException.badRequest("잔액이 부족합니다. 충전 후 다시 시도하세요. (주문 금액 "
                    + total + "원 / 현재 잔액 " + customer.getBalance() + "원)");

        Order order = Order.builder()
                .id(orderId)
                .tenantId(tenantId)
                .customerId(customer.getId())
                .status(Order.Status.pending)
                .totalAmount(total)
                .items(items)
                .build();

        orderMapper.insertOrder(order);
        items.forEach(orderMapper::insertOrderItem);

        return order;
    }

    @Transactional
    public Order updateStatus(String id, String status, User actor) {
        Order order = orderMapper.findById(id)
                .orElseThrow(() -> AppException.notFound("주문을 찾을 수 없습니다."));

        // admin은 자기가 관리하는 테넌트 주문만 수정
        if (!actor.canManage(order.getTenantId()))
            throw AppException.forbidden("해당 주문에 대한 권한이 없습니다.");

        Order.Status target;
        try { target = Order.Status.valueOf(status); }
        catch (IllegalArgumentException e) { throw AppException.badRequest("유효하지 않은 주문 상태: " + status); }

        boolean wasCancelled = order.getStatus() == Order.Status.cancelled;
        boolean willCancel   = target == Order.Status.cancelled;
        boolean wasShipped   = order.getStatus() == Order.Status.shipped;
        boolean willShip     = target == Order.Status.shipped;

        // ── 고객 잔액/재고: 취소 진입 시 환불·복원, 취소 해제 시 재차감·재차감 ──
        if (!wasCancelled && willCancel) {
            userMapper.addBalance(order.getCustomerId(), order.getTotalAmount());
            for (OrderItem it : orderMapper.findItemsByOrderId(id))
                productMapper.increaseStock(it.getProductId(), it.getQuantity());
        } else if (wasCancelled && !willCancel) {
            int paid = userMapper.deductBalance(order.getCustomerId(), order.getTotalAmount());
            if (paid == 0)
                throw AppException.badRequest("고객 잔액 부족으로 주문을 다시 활성화할 수 없습니다.");
            for (OrderItem it : orderMapper.findItemsByOrderId(id)) {
                int s = productMapper.decreaseStock(it.getProductId(), it.getQuantity());
                if (s == 0) throw AppException.badRequest("재고 부족으로 주문을 다시 활성화할 수 없습니다.");
            }
        }

        // ── 정산: 배송완료(shipped) 진입 시 테넌트 owner(admin) 잔액 +금액, 해제 시 -금액 ──
        if (wasShipped != willShip) {
            String ownerId = tenantMapper.findById(order.getTenantId())
                    .map(t -> t.getOwnerId()).orElse(null);
            if (ownerId != null)
                userMapper.addBalance(ownerId, willShip ? order.getTotalAmount() : -order.getTotalAmount());
        }

        orderMapper.updateStatus(id, status);
        return getById(id);
    }
}
