package com.shop.controller;

import com.shop.domain.User;
import com.shop.dto.ApiResponse;
import com.shop.exception.AppException;
import com.shop.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/v1/users")
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;

    /** super_admin – 전체 사용자 목록 */
    @GetMapping
    public ResponseEntity<ApiResponse<List<User>>> listAll(
            @AuthenticationPrincipal User actor) {
        if (!actor.isSuperAdmin())
            return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
        return ResponseEntity.ok(ApiResponse.ok(userService.listAll()));
    }

    /** admin – 소속 테넌트 사용자 목록 */
    @GetMapping("/tenant/{tenantId}")
    public ResponseEntity<ApiResponse<List<User>>> listByTenant(
            @PathVariable String tenantId,
            @AuthenticationPrincipal User actor) {
        if (!actor.canManage(tenantId))
            return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
        return ResponseEntity.ok(ApiResponse.ok(userService.listByTenant(tenantId)));
    }

    /** 본인 프로필 조회 */
    @GetMapping("/me")
    public ResponseEntity<ApiResponse<User>> me(@AuthenticationPrincipal User actor) {
        return ResponseEntity.ok(ApiResponse.ok(actor));
    }

    @GetMapping("/{id}")
    public ResponseEntity<ApiResponse<User>> get(
            @PathVariable String id,
            @AuthenticationPrincipal User actor) {
        if (!actor.isSuperAdmin() && !actor.getId().equals(id))
            return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
        return ResponseEntity.ok(ApiResponse.ok(userService.getById(id)));
    }

    /** super_admin – 사용자 생성 */
    @PostMapping
    public ResponseEntity<ApiResponse<User>> create(
            @RequestBody Map<String, String> body,
            @AuthenticationPrincipal User actor) {
        if (!actor.isSuperAdmin())
            return ResponseEntity.status(HttpStatus.FORBIDDEN).build();

        User.Role role;
        try { role = User.Role.valueOf(body.getOrDefault("role", "customer")); }
        catch (IllegalArgumentException e) { throw AppException.badRequest("유효하지 않은 역할입니다."); }
        User user = userService.create(
                body.get("username"),
                body.get("password"),
                role,
                body.get("displayName"),
                body.get("tenantId")
        );
        return ResponseEntity.status(HttpStatus.CREATED).body(ApiResponse.ok(user));
    }

    @PatchMapping("/{id}")
    public ResponseEntity<ApiResponse<User>> update(
            @PathVariable String id,
            @RequestBody Map<String, Object> body,
            @AuthenticationPrincipal User actor) {
        String displayName = (String) body.get("displayName");
        Boolean isActive   = body.containsKey("isActive") ? (Boolean) body.get("isActive") : null;
        String tenantId    = body.get("tenantId") != null ? body.get("tenantId").toString() : null;

        User.Role role = null;
        Object r = body.get("role");
        if (r != null) {
            try { role = User.Role.valueOf(r.toString()); }
            catch (IllegalArgumentException e) { throw AppException.badRequest("유효하지 않은 역할: " + r); }
        }
        return ResponseEntity.ok(ApiResponse.ok(
                userService.update(id, displayName, isActive, role, tenantId, actor)));
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<ApiResponse<Void>> delete(
            @PathVariable String id,
            @AuthenticationPrincipal User actor) {
        userService.delete(id, actor);
        return ResponseEntity.ok(ApiResponse.ok());
    }

    @PutMapping("/{id}/password")
    public ResponseEntity<ApiResponse<Void>> changePassword(
            @PathVariable String id,
            @RequestBody Map<String, String> body,
            @AuthenticationPrincipal User actor) {
        userService.changePassword(
                id,
                body.get("oldPassword"),
                body.get("newPassword"),
                actor
        );
        return ResponseEntity.ok(ApiResponse.ok());
    }
}
