package com.shop.controller;

import com.shop.domain.User;
import com.shop.dto.ApiResponse;
import com.shop.service.UploadService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.util.Map;

/**
 * [취약/web] 파일 업로드/조회 — 인증만 요구, 타입·경로 검증 없음.
 * POST /api/v1/tenants/{tenantId}/uploads            (multipart: file)
 * GET  /api/v1/tenants/{tenantId}/uploads/download?name=...
 */
@RestController
@RequestMapping("/api/v1/tenants/{tenantId}/uploads")
@RequiredArgsConstructor
public class UploadController {

    private final UploadService uploadService;

    @PostMapping
    public ResponseEntity<ApiResponse<Map<String, String>>> upload(
            @PathVariable String tenantId,
            @RequestParam("file") MultipartFile file,
            @AuthenticationPrincipal User actor) {
        String stored = uploadService.store(file);
        Map<String, String> res = Map.of(
                "storedName", stored,
                "url", "/api/v1/tenants/" + tenantId + "/uploads/download?name=" + stored);
        return ResponseEntity.status(HttpStatus.CREATED).body(ApiResponse.ok(res));
    }

    @GetMapping("/download")
    public ResponseEntity<byte[]> download(
            @PathVariable String tenantId,
            @RequestParam("name") String name,
            @AuthenticationPrincipal User actor) {
        byte[] data = uploadService.read(name);
        return ResponseEntity.ok()
                .header("Content-Disposition", "inline; filename=\"" + name + "\"")
                .body(data);
    }
}
