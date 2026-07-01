package com.shop.service;

import com.shop.air.DefenseRegistry;
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
 * 파일 업로드 — [AIR] upload.file-guard 로 취약/안전 전환.
 *  guard OFF(기본) = 취약: 확장자 무검증 + 원본 파일명(경로조작) + 크기무제한 + 조회 경로조작(LFI).
 *  guard ON        = 안전: basename only + 확장자 화이트리스트 + 크기제한(2MB) + 랜덤 파일명 + baseDir 강제.
 */
@Service
@RequiredArgsConstructor
public class UploadService {

    private final DefenseRegistry registry;

    private final Path baseDir =
            Paths.get(System.getenv().getOrDefault("APP_UPLOAD_DIR", "/data/uploads")).normalize();
    private static final Set<String> ALLOWED = Set.of("png", "jpg", "jpeg", "gif", "webp");
    private static final long MAX_BYTES = 2L * 1024 * 1024;

    public String store(MultipartFile file) {
        try {
            Files.createDirectories(baseDir);
            String raw = file.getOriginalFilename();
            if (raw == null || raw.isBlank()) raw = "upload.bin";

            if (registry.isEnabled(DefenseRegistry.UPLOAD_FILE_GUARD)) {
                // 안전: 경로 제거(basename) + 확장자 화이트리스트 + 크기제한 + 랜덤 파일명
                String base = Paths.get(raw).getFileName().toString();
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
        try {
            if (registry.isEnabled(DefenseRegistry.UPLOAD_FILE_GUARD)) {
                // 안전: basename only + baseDir 내부 강제
                String base = Paths.get(name).getFileName().toString();
                Path target = baseDir.resolve(base).normalize();
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

    private static String extOf(String n) {
        int i = n.lastIndexOf('.');
        return (i < 0 ? "" : n.substring(i + 1)).toLowerCase(Locale.ROOT);
    }
}
