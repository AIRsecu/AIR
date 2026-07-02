package com.shop.service;

import com.shop.air.DefenseRegistry;
import com.shop.air.IncidentService;
import com.shop.exception.AppException;
import com.shop.util.UlidUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Locale;
import java.util.Set;

/**
 * 파일 업로드 — [AIR] 자동 탐지 + upload.file-guard 방어 폐루프.
 *  탐지: 악성 파일명(위험 확장자 .jsp/.php/.html 등 또는 경로조작 ../) 또는 조회 경로조작(name=../)
 *        → IncidentService.report → upload.file-guard 자동 ON → 같은 요청부터 즉시 방어.
 *  가드 OFF(기본)=취약(확장자무검증/경로조작 쓰기/LFI) / ON=안전(basename+화이트리스트+2MB+랜덤명+baseDir강제).
 *  ※ 멀티파트 파일명은 필터에서 스트림을 소비하지 않고 읽기 어려워, 탐지를 서비스(파싱된 파일명 접근 지점)에 배치.
 */
@Service
@RequiredArgsConstructor
public class UploadService {

    private final DefenseRegistry registry;
    private final IncidentService incidentService;

    private final Path baseDir =
            Paths.get(System.getenv().getOrDefault("APP_UPLOAD_DIR", "/data/uploads")).normalize();
    private static final Set<String> ALLOWED = Set.of("png", "jpg", "jpeg", "gif", "webp");
    private static final long MAX_BYTES = 2L * 1024 * 1024;
    /** 업로드 시 위험 확장자(웹셸/스크립트/실행/HTML) */
    private static final Set<String> DANGEROUS_EXT = Set.of(
            "jsp", "jspx", "php", "phtml", "php5", "asp", "aspx", "exe", "sh",
            "bat", "cmd", "jar", "war", "html", "htm", "xhtml", "svg");

    public String store(MultipartFile file) {
        String raw = file.getOriginalFilename();
        if (raw == null || raw.isBlank()) raw = "upload.bin";
        // [AIR] 자동 탐지 → 악성이면 upload.file-guard 즉시 ON (아래 분기에서 같은 요청부터 방어)
        autoDetect(raw, "UPLOAD_MALICIOUS_FILE", true);
        try {
            Files.createDirectories(baseDir);
            if (registry.isEnabled(DefenseRegistry.UPLOAD_FILE_GUARD)) {
                String base = baseName(raw);
                String ext = extOf(base);
                if (!ALLOWED.contains(ext))
                    throw AppException.badRequest("허용되지 않은 파일 형식입니다: " + ext);
                if (file.getSize() > MAX_BYTES)
                    throw AppException.badRequest("파일이 너무 큽니다(최대 2MB).");
                String safe = UlidUtil.generate() + "." + ext;
                Path target = baseDir.resolve(safe).normalize();
                if (!target.startsWith(baseDir))
                    throw AppException.badRequest("잘못된 저장 경로입니다.");
                file.transferTo(target);
                return safe;
            }
            // 취약(flag OFF): 원본 파일명 그대로 → 경로조작 쓰기/임의 확장자
            Path target = baseDir.resolve(raw).normalize();
            if (target.getParent() != null) Files.createDirectories(target.getParent());
            file.transferTo(target);
            return raw;
        } catch (IOException | IllegalStateException e) {
            throw AppException.badRequest("업로드 실패: " + e.getMessage());
        }
    }

    public byte[] read(String name) {
        // [AIR] 자동 탐지 → 경로조작이면 upload.file-guard 즉시 ON
        autoDetect(name, "UPLOAD_PATH_TRAVERSAL", false);
        try {
            if (registry.isEnabled(DefenseRegistry.UPLOAD_FILE_GUARD)) {
                Path target = baseDir.resolve(baseName(name)).normalize();
                if (!target.startsWith(baseDir))
                    throw AppException.notFound("파일을 찾을 수 없습니다.");
                return Files.readAllBytes(target);
            }
            // 취약(flag OFF): 파일명 무검증 → 경로조작 읽기(LFI)
            Path target = baseDir.resolve(name).normalize();
            return Files.readAllBytes(target);
        } catch (IOException e) {
            throw AppException.notFound("파일을 찾을 수 없습니다: " + name);
        }
    }

    /**
     * 악성 파일명/경로 탐지 → 인시던트 보고(=upload.file-guard 자동 ON).
     * @param checkExt true=위험 확장자도 검사(업로드), false=경로조작만(조회)
     */
    private void autoDetect(String name, String type, boolean checkExt) {
        if (name == null || name.isBlank()) return;
        if (!registry.isEnabled(DefenseRegistry.DETECTION)) return;      // 탐지 비활성 시 스킵
        if (registry.isEnabled(DefenseRegistry.UPLOAD_FILE_GUARD)) return; // 이미 방어중
        boolean traversal = name.contains("..") || name.contains("/") || name.contains("\\");
        boolean badExt = checkExt && DANGEROUS_EXT.contains(extOf(baseName(name)));
        if (traversal || badExt) {
            incidentService.report(type, "/api/v1/tenants/*/uploads", null, null, "name=" + name);
        }
    }

    private static String baseName(String n) {
        int slash = Math.max(n.lastIndexOf('/'), n.lastIndexOf('\\'));
        return slash >= 0 ? n.substring(slash + 1) : n;
    }

    private static String extOf(String n) {
        int i = n.lastIndexOf('.');
        return (i < 0 ? "" : n.substring(i + 1)).toLowerCase(Locale.ROOT);
    }
}
