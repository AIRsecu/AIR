package com.shop.mapper;

import com.shop.domain.Order;
import com.shop.domain.OrderItem;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

import java.util.List;
import java.util.Optional;

@Mapper
public interface OrderMapper {
    void insertOrder(Order order);
    void insertOrderItem(OrderItem item);
    Optional<Order> findById(@Param("id") String id);
    List<Order> findByTenantId(@Param("tenantId") String tenantId);
    List<Order> findByCustomerId(@Param("customerId") String customerId);
    List<OrderItem> findItemsByOrderId(@Param("orderId") String orderId);
    void updateStatus(@Param("id") String id, @Param("status") String status);
    int countByTenantAndStatus(@Param("tenantId") String tenantId, @Param("status") String status);
}
