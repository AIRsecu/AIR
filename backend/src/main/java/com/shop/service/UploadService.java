package com.shop.service;

import com.shop.exception.AppException;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * [취약/web] 파일 업로드 — 방어 없는 공격 대상.
 *  - 확장자/컨텐츠 타입 화이트리스트 없음 (임의 .html/.jsp/.svg 업로드 = 웹셸/저장형 XSS 표면)
 *  - 원본 파일명 무검증 사용 → 경로조작(../) 쓰기
 *  - 크기 제한 없음
 *  - 조회 시 파일명 무검증 → 경로조작 읽기(LFI)
 *  (defense 는 upload.file-guard 플래그로 basename+화이트리스트+랜덤명+크기제한 방어)
 */
@Service
@RequiredArgsConstructor
public class UploadService {

    private final Path baseDir =
            Paths.get(System.getenv().getOrDefault("APP_UPLOAD_DIR", "/data/uploads"));

    /** [취약] 원본 파일명 그대로 저장 — 확장자/경로 무검증 */
    public String store(MultipartFile file) {
        try {
            Files.createDirectories(baseDir);
            String name = file.getOriginalFilename();
            if (name == null || name.isBlank()) name = "upload.bin";
            // resolve(../) → baseDir 밖으로 탈출 가능(경로조작 쓰기)
            Path target = baseDir.resolve(name).normalize();
            if (target.getParent() != null) Files.createDirectories(target.getParent());
            file.transferTo(target);
            return name;
        } catch (IOException | IllegalStateException e) {
            throw AppException.badRequest("업로드 실패: " + e.getMessage());
        }
    }

    /** [취약] 파일명 무검증 조회 → 경로조작 읽기(LFI) */
    public byte[] read(String name) {
        try {
            Path target = baseDir.resolve(name).normalize();
            return Files.readAllBytes(target);
        } catch (IOException e) {
            throw AppException.notFound("파일을 찾을 수 없습니다: " + name);
        }
    }
}
