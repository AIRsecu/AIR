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
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserMapper         userMapper;
    private final RefreshTokenMapper tokenMapper;
    private final JwtProvider        jwt;
    private final PasswordEncoder    encoder;

    // ── 로그인 brute-force 방어 (IP 기준 실패 카운트/잠금, 메모리 상한) ──
    //  username 이 아닌 클라이언트 IP 로 제한 → 표적 계정 잠금 DoS 방지
    private static final int  MAX_FAIL = 5;
    private static final long LOCK_SEC = 300;     // 5분
    private static final int  MAX_KEYS = 4096;    // 메모리 상한(초과 시 만료 엔트리 정리)
    // bcrypt 타이밍 평준화용 더미 해시(존재하지 않는 사용자에도 동일 비용 → timing enumeration 차단)
    private static final String DUMMY_HASH = "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy";
    private final Map<String, long[]> loginState = new ConcurrentHashMap<>(); // ip -> [failCount, lockUntilEpoch]

    @Transactional
    public LoginResponse login(LoginRequest req, String userAgent, String clientIp) {
        final String key = (clientIp == null || clientIp.isBlank()) ? "unknown" : clientIp;
        final long now = Instant.now().getEpochSecond();

        long[] st = loginState.get(key);
        if (st != null && st[1] > now)
            throw AppException.unauthorized("로그인 시도가 너무 많습니다. 잠시 후 다시 시도하세요.");

        User user = userMapper.findByUsername(req.username()).orElse(null);
        // 존재/비활성/비번오류를 동일 401 + 동일 비용(더미 bcrypt)으로 처리 (enumeration/timing 완화)
        boolean ok;
        if (user == null) { encoder.matches(req.password(), DUMMY_HASH); ok = false; }
        else ok = user.isActive() && encoder.matches(req.password(), user.getPasswordHash());

        if (!ok) {
            registerFailure(key, now);
            throw AppException.unauthorized("아이디 또는 비밀번호가 올바르지 않습니다.");
        }
        loginState.remove(key);   // 성공 시 해당 IP 카운터 초기화

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

    /** IP 단위 실패 누적(원자적 compute) + 메모리 상한 정리 */
    private void registerFailure(String key, long now) {
        if (loginState.size() > MAX_KEYS)
            loginState.entrySet().removeIf(e -> e.getValue()[1] < now); // 만료/비잠금 엔트리 정리
        loginState.compute(key, (k, s) -> {
            if (s == null) s = new long[]{0, 0};
            s[0] += 1;
            if (s[0] >= MAX_FAIL) { s[1] = now + LOCK_SEC; s[0] = 0; }
            return s;
        });
    }
}
