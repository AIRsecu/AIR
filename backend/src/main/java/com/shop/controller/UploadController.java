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

import java.util.Locale;
import java.util.Map;

/**
 * 파일 업로드/조회 — 인증 필요.
 * [AIR] upload.file-guard 플래그로 취약(무검증)/안전(basename+화이트리스트+랜덤명+크기제한) 전환.
 * POST /api/v1/tenants/{tenantId}/uploads            (multipart: file)
 * GET  /api/v1/tenants/{tenantId}/uploads/download?name=...
 */
@RestController
@RequestMapping("/api/v1/tenants/{tenantId}/uploads")
@RequiredArgsConstructor
public class UploadController {

    private final UploadService uploadService;

    /** [AIR] 서빙 안전 화이트리스트: 이미지 확장자 → Content-Type. 그 외는 octet-stream+attachment. */
    private static final Map<String, String> IMAGE_TYPES = Map.of(
            "png", "image/png",
            "jpg", "image/jpeg",
            "jpeg", "image/jpeg",
            "gif", "image/gif",
            "webp", "image/webp");

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
        // [AIR] #4 서빙 하드닝: 확장자 화이트리스트로 Content-Type 고정 + nosniff 로 스니핑 차단.
        //  이미지만 inline 렌더 허용, 그 외(HTML/SVG/스크립트 등)는 octet-stream + attachment 로 강제 다운로드.
        String base = baseName(name);
        String ext = extOf(base);
        boolean isImage = IMAGE_TYPES.containsKey(ext);
        String contentType = isImage ? IMAGE_TYPES.get(ext) : "application/octet-stream";
        String disposition = (isImage ? "inline" : "attachment") + "; filename=\"" + safeFilename(base) + "\"";
        return ResponseEntity.ok()
                .header("Content-Type", contentType)
                .header("X-Content-Type-Options", "nosniff")
                .header("Content-Disposition", disposition)
                .body(data);
    }

    private static String baseName(String n) {
        if (n == null) return "";
        int slash = Math.max(n.lastIndexOf('/'), n.lastIndexOf('\\'));
        return slash >= 0 ? n.substring(slash + 1) : n;
    }

    private static String extOf(String n) {
        int i = n.lastIndexOf('.');
        return (i < 0 ? "" : n.substring(i + 1)).toLowerCase(Locale.ROOT);
    }

    /** Content-Disposition 헤더 인젝션 방지: 따옴표·개행 제거. */
    private static String safeFilename(String n) {
        return n.replaceAll("[\"\\r\\n]", "_");
    }
}
