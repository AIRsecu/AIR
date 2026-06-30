package com.shop.service;

import com.shop.domain.Product;
import com.shop.domain.User;
import com.shop.dto.product.*;
import com.shop.exception.AppException;
import com.shop.mapper.ProductMapper;
import com.shop.util.UlidUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
@RequiredArgsConstructor
public class ProductService {

    private final ProductMapper productMapper;

    public List<Product> listByTenant(String tenantId, boolean activeOnly) {
        return activeOnly
                ? productMapper.findActiveByTenantId(tenantId)
                : productMapper.findByTenantId(tenantId);
    }

    public Product getById(String id) {
        return productMapper.findById(id)
                .orElseThrow(() -> AppException.notFound("상품을 찾을 수 없습니다."));
    }

    /** 요청자가 해당 테넌트 소속인지 검증 후 반환 */
    public Product getByIdForTenant(String id, String tenantId) {
        Product p = getById(id);
        if (!p.getTenantId().equals(tenantId))
            throw AppException.forbidden("해당 테넌트의 상품이 아닙니다.");
        return p;
    }

    @Transactional
    public Product create(String tenantId, CreateProductRequest req, User actor) {
        assertAdminOf(actor, tenantId);

        Product product = Product.builder()
                .id(UlidUtil.generate())
                .tenantId(tenantId)
                .name(req.name())
                .description(req.description())
                .price(req.price())
                .stock(req.stock())
                .category(req.category())
                .imageUrl(req.imageUrl())
                .isActive(true)
                .build();

        productMapper.insert(product);
        return product;
    }

    @Transactional
    public Product update(String id, UpdateProductRequest req, User actor) {
        Product existing = getById(id);
        assertAdminOf(actor, existing.getTenantId());

        Product updated = Product.builder()
                .id(existing.getId())
                .tenantId(existing.getTenantId())
                .name(req.name() != null ? req.name() : existing.getName())
                .description(req.description() != null ? req.description() : existing.getDescription())
                .price(req.price() != null ? req.price() : existing.getPrice())
                .stock(req.stock() != null ? req.stock() : existing.getStock())
                .category(req.category() != null ? req.category() : existing.getCategory())
                .imageUrl(req.imageUrl() != null ? req.imageUrl() : existing.getImageUrl())
                .isActive(req.isActive() != null ? req.isActive() : existing.isActive())
                .build();

        productMapper.update(updated);
        return updated;
    }

    @Transactional
    public void delete(String id, User actor) {
        Product existing = getById(id);
        assertAdminOf(actor, existing.getTenantId());
        productMapper.softDelete(id);
    }

    private void assertAdminOf(User actor, String tenantId) {
        if (!actor.canManage(tenantId))
            throw AppException.forbidden("해당 테넌트의 관리자만 가능합니다.");
    }
}
