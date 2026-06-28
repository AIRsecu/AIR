package com.shop.service;

import com.shop.domain.Product;
import com.shop.domain.User;
import com.shop.air.DefenseRegistry;
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
    private final DefenseRegistry defense;   // [AIR] 방어 토글

    /** [AIR 불변식] invariant.row-cap ON 이면 응답 행수 상한(데이터 대량유출을 벡터무관 차단). */
    private static final int ROW_CAP = 200;
    private List<Product> cap(List<Product> list) {
        if (list != null && list.size() > ROW_CAP
                && defense.isEnabled(DefenseRegistry.INVARIANT_ROW_CAP))
            return list.subList(0, ROW_CAP);
        return list;
    }

    public List<Product> listByTenant(String tenantId, boolean activeOnly) {
        return cap(activeOnly
                ? productMapper.findActiveByTenantId(tenantId)
                : productMapper.findByTenantId(tenantId));
    }

    /**
     * [AIR] 상품명 검색. sql.injection-guard ON 이면 안전 바인딩(#{}),
     * OFF 면 취약한 동적 SQL(${}) 을 사용 → SQL Injection 시연/방어 토글.
     */
    public List<Product> search(String tenantId, String q) {
        return cap(defense.isEnabled(DefenseRegistry.SQL_INJECTION_GUARD)
                ? productMapper.searchByNameSafe(tenantId, q)
                : productMapper.searchByNameVulnerable(tenantId, q));
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
                .name(xssGuard(req.name()))
                .description(xssGuard(req.description()))
                .price(req.price())
                .stock(req.stock())
                .category(xssGuard(req.category()))
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
                .name(req.name() != null ? xssGuard(req.name()) : existing.getName())
                .description(req.description() != null ? xssGuard(req.description()) : existing.getDescription())
                .price(req.price() != null ? req.price() : existing.getPrice())
                .stock(req.stock() != null ? req.stock() : existing.getStock())
                .category(req.category() != null ? xssGuard(req.category()) : existing.getCategory())
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

    /**
     * [AIR] xss.input-guard ON 이면 저장 입력의 위험 문자(&lt;,&gt;,&amp;,",')를
     * HTML 이스케이프해 스크립트 실행을 무력화. OFF 면 원문 저장(저장형 XSS 취약).
     */
    private String xssGuard(String s) {
        if (s == null || !defense.isEnabled(DefenseRegistry.XSS_INPUT_GUARD)) return s;
        return s.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;")
                .replace("'", "&#39;");
    }
}
