package com.shop.controller;

import com.shop.dto.ApiResponse;
import com.shop.dto.auth.*;
import com.shop.service.AuthService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    @PostMapping("/login")
    public ResponseEntity<ApiResponse<LoginResponse>> login(
            @Valid @RequestBody LoginRequest req,
            HttpServletRequest http) {
        String ua = http.getHeader("User-Agent");
        return ResponseEntity.ok(ApiResponse.ok(authService.login(req, ua)));
    }

    @PostMapping("/refresh")
    public ResponseEntity<ApiResponse<RefreshResponse>> refresh(
            @RequestBody(required = false) java.util.Map<String, String> body) {
        String token = body != null ? body.get("refreshToken") : null;
        if (token == null || token.isBlank())
            return ResponseEntity.badRequest().body(ApiResponse.error("BAD_REQUEST", "refreshToken 필드가 필요합니다."));
        return ResponseEntity.ok(ApiResponse.ok(authService.refresh(token)));
    }

    @PostMapping("/logout")
    public ResponseEntity<ApiResponse<Void>> logout(
            @RequestBody(required = false) java.util.Map<String, String> body) {
        if (body != null && body.containsKey("refreshToken"))
            authService.logout(body.get("refreshToken"));
        return ResponseEntity.ok(ApiResponse.ok());
    }
}
