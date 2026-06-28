package com.shop.controller;

import com.shop.domain.Product;
import com.shop.domain.User;
import com.shop.dto.ApiResponse;
import com.shop.dto.product.*;
import com.shop.service.ProductService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/v1/tenants/{tenantId}/products")
@RequiredArgsConstructor
public class ProductController {

    private final ProductService productService;

    /** 공개 – 활성 상품 목록 */
    @GetMapping
    public ResponseEntity<ApiResponse<List<Product>>> list(
            @PathVariable String tenantId,
            @RequestParam(defaultValue = "true") boolean activeOnly,
            @AuthenticationPrincipal User actor) {

        // 비활성 상품은 해당 테넌트를 관리하는 관리자만 조회 가능
        boolean showAll = !activeOnly && actor != null && actor.canManage(tenantId);
        return ResponseEntity.ok(ApiResponse.ok(productService.listByTenant(tenantId, !showAll)));
    }

    /** 공개 – 상품명 검색 ([AIR] sql.injection-guard 로 취약/안전 전환되는 vuln-lab 표면) */
    @GetMapping("/search")
    public ResponseEntity<ApiResponse<List<Product>>> search(
            @PathVariable String tenantId,
            @RequestParam(defaultValue = "") String q) {
        return ResponseEntity.ok(ApiResponse.ok(productService.search(tenantId, q)));
    }

    @GetMapping("/{id}")
    public ResponseEntity<ApiResponse<Product>> get(
            @PathVariable String tenantId,
            @PathVariable String id,
            @AuthenticationPrincipal User actor) {
        Product p = productService.getByIdForTenant(id, tenantId);
        // 비활성 상품은 해당 테넌트 관리자에게만 (공개 목록 정책과 일치)
        if (!p.isActive() && (actor == null || !actor.canManage(tenantId)))
            return ResponseEntity.status(HttpStatus.NOT_FOUND).build();
        return ResponseEntity.ok(ApiResponse.ok(p));
    }

    @PostMapping
    public ResponseEntity<ApiResponse<Product>> create(
            @PathVariable String tenantId,
            @Valid @RequestBody CreateProductRequest req,
            @AuthenticationPrincipal User actor) {
        Product p = productService.create(tenantId, req, actor);
        return ResponseEntity.status(HttpStatus.CREATED).body(ApiResponse.ok(p));
    }

    @PatchMapping("/{id}")
    public ResponseEntity<ApiResponse<Product>> update(
            @PathVariable String tenantId,
            @PathVariable String id,
            @Valid @RequestBody UpdateProductRequest req,
            @AuthenticationPrincipal User actor) {
        return ResponseEntity.ok(ApiResponse.ok(productService.update(id, req, actor)));
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<ApiResponse<Void>> delete(
            @PathVariable String tenantId,
            @PathVariable String id,
            @AuthenticationPrincipal User actor) {
        productService.delete(id, actor);
        return ResponseEntity.ok(ApiResponse.ok());
    }
}
