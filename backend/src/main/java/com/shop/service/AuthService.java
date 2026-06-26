package com.shop.service;

import com.shop.domain.RefreshToken;
import com.shop.domain.User;
import com.shop.dto.auth.*;
import com.shop.exception.AppException;
import com.shop.mapper.RefreshTokenMapper;
import com.shop.mapper.UserMapper;
import com.shop.security.JwtProvider;
import com.shop.util.UlidUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserMapper         userMapper;
    private final RefreshTokenMapper tokenMapper;
    private final JwtProvider        jwt;
    private final PasswordEncoder    encoder;

    @Transactional
    public LoginResponse login(LoginRequest req, String userAgent) {
        User user = userMapper.findByUsername(req.username())
                .orElseThrow(() -> AppException.unauthorized("아이디 또는 비밀번호가 올바르지 않습니다."));

        if (!user.isActive())
            throw AppException.forbidden("비활성화된 계정입니다.");

        if (!encoder.matches(req.password(), user.getPasswordHash()))
            throw AppException.unauthorized("아이디 또는 비밀번호가 올바르지 않습니다.");

        userMapper.updateLastLoginAt(user.getId());

        String access  = jwt.issueAccess(user);
        String raw     = jwt.generateRawRefresh();
        String hash    = jwt.hashRefresh(raw);

        LocalDateTime exp = LocalDateTime.ofInstant(
                Instant.now().plusMillis(jwt.refreshTtlMs()), ZoneId.systemDefault());

        tokenMapper.insert(RefreshToken.builder()
                .id(UlidUtil.generate())
                .userId(user.getId())
                .tokenHash(hash)
                .expiresAt(exp)
                .userAgent(userAgent)
                .build());

        return new LoginResponse(access, raw,
                user.getId(), user.getUsername(), user.getRole().name(), user.getTenantId());
    }

    @Transactional
    public RefreshResponse refresh(String rawToken) {
        String hash = jwt.hashRefresh(rawToken);

        RefreshToken stored = tokenMapper.findByTokenHash(hash)
                .orElseThrow(() -> AppException.unauthorized("유효하지 않은 Refresh Token입니다."));

        if (stored.isRevoked()) {
            // Refresh Token Reuse → 전체 토큰 무효화 (도용 감지)
            tokenMapper.revokeAllByUserId(stored.getUserId());
            throw AppException.unauthorized("토큰 재사용이 감지되었습니다. 재로그인이 필요합니다.");
        }

        if (stored.isExpired(LocalDateTime.now()))
            throw AppException.unauthorized("Refresh Token이 만료되었습니다.");

        User user = userMapper.findById(stored.getUserId())
                .orElseThrow(() -> AppException.unauthorized("사용자를 찾을 수 없습니다."));

        // Rotation: 기존 토큰 폐기 → 새 토큰 발급
        String newRaw  = jwt.generateRawRefresh();
        String newHash = jwt.hashRefresh(newRaw);
        LocalDateTime exp = LocalDateTime.ofInstant(
                Instant.now().plusMillis(jwt.refreshTtlMs()), ZoneId.systemDefault());

        String newId = UlidUtil.generate();
        tokenMapper.revoke(stored.getId(), newId);
        tokenMapper.insert(RefreshToken.builder()
                .id(newId)
                .userId(user.getId())
                .tokenHash(newHash)
                .expiresAt(exp)
                .build());

        return new RefreshResponse(jwt.issueAccess(user), newRaw);
    }

    @Transactional
    public void logout(String rawToken) {
        String hash = jwt.hashRefresh(rawToken);
        tokenMapper.findByTokenHash(hash)
                .ifPresent(t -> tokenMapper.revoke(t.getId(), null));
    }
}
