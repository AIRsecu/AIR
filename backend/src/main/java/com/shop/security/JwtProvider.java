package com.shop.security;

import com.shop.domain.User;
import com.shop.exception.AppException;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;

@Component
public class JwtProvider {

    private final SecretKey accessKey;
    private final SecretKey refreshKey;
    private final long accessTtlMs;        // 일반 사용자(admin/customer)
    private final long superAccessTtlMs;   // super_admin 전용(더 길게)
    private final long refreshTtlMs;

    public JwtProvider(
            @Value("${jwt.access-secret}")           String accessSecret,
            @Value("${jwt.refresh-secret}")          String refreshSecret,
            @Value("${jwt.access-ttl-minutes}")      long accessMinutes,
            @Value("${jwt.super-access-ttl-hours}")  long superAccessHours,
            @Value("${jwt.refresh-ttl-hours}")       long refreshHours
    ) {
        requireStrongSecret("jwt.access-secret", accessSecret);
        requireStrongSecret("jwt.refresh-secret", refreshSecret);
        this.accessKey        = Keys.hmacShaKeyFor(accessSecret.getBytes(StandardCharsets.UTF_8));
        this.refreshKey       = Keys.hmacShaKeyFor(refreshSecret.getBytes(StandardCharsets.UTF_8));
        this.accessTtlMs      = accessMinutes    * 60   * 1000L;
        this.superAccessTtlMs = superAccessHours * 3600 * 1000L;
        this.refreshTtlMs     = refreshHours     * 3600 * 1000L;
    }

    /** 기본/약한 시크릿 거부 (fail-closed): "change-me" 포함 또는 32바이트 미만이면 기동 실패 */
    private static void requireStrongSecret(String name, String secret) {
        if (secret == null
                || secret.toLowerCase().contains("change-me")
                || secret.getBytes(StandardCharsets.UTF_8).length < 32) {
            throw new IllegalStateException(
                name + " 가 안전하지 않습니다(기본값/약한 값). 32바이트 이상의 랜덤 시크릿을 "
                + "환경변수로 설정하세요. 운영은 64바이트 이상 권장.");
        }
    }

    // ── Access Token ──────────────────────────────────────────────

    public String issueAccess(User user) {
        Instant now = Instant.now();
        long ttl = user.isSuperAdmin() ? superAccessTtlMs : accessTtlMs;
        return Jwts.builder()
                .subject(user.getId())
                .claim("role",     user.getRole().name())
                .claim("tenantId", user.getTenantId())
                .issuedAt(Date.from(now))
                .expiration(Date.from(now.plusMillis(ttl)))
                .signWith(accessKey)
                .compact();
    }

    public Claims verifyAccess(String token) {
        return parse(token, accessKey);
    }

    // ── Refresh Token (opaque raw + SHA-256 hash) ─────────────────

    public String generateRawRefresh() {
        byte[] buf = new byte[32];
        new SecureRandom().nextBytes(buf);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(buf);
    }

    public String hashRefresh(String raw) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(raw.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            for (byte b : digest) sb.append(String.format("%02x", b));
            return sb.toString();
        } catch (Exception e) {
            throw new RuntimeException("SHA-256 failed", e);
        }
    }

    public long refreshTtlMs() { return refreshTtlMs; }

    // ── 내부 파서 ──────────────────────────────────────────────────

    private Claims parse(String token, SecretKey key) {
        try {
            return Jwts.parser()
                    .verifyWith(key)
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();
        } catch (ExpiredJwtException e) {
            throw new AppException(HttpStatus.UNAUTHORIZED, "TOKEN_EXPIRED", "액세스 토큰이 만료되었습니다.");
        } catch (JwtException e) {
            throw new AppException(HttpStatus.UNAUTHORIZED, "TOKEN_INVALID", "유효하지 않은 토큰입니다.");
        }
    }
}
