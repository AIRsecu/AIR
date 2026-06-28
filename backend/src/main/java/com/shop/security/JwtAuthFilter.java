package com.shop.security;

import com.shop.mapper.TenantAdminMapper;
import com.shop.mapper.UserMapper;
import io.jsonwebtoken.Claims;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.HashSet;
import java.util.List;

@Component
@RequiredArgsConstructor
public class JwtAuthFilter extends OncePerRequestFilter {

    private final JwtProvider        jwt;
    private final UserMapper         userMapper;
    private final TenantAdminMapper  tenantAdminMapper;

    @Override
    protected void doFilterInternal(HttpServletRequest req,
                                    HttpServletResponse res,
                                    FilterChain chain)
            throws ServletException, IOException {

        // 일반 요청은 Authorization 헤더 사용.
        // SSE(EventSource)는 헤더를 못 보내므로 ?token= 쿼리 파라미터를 폴백으로 허용.
        String header = req.getHeader("Authorization");
        String token = null;
        if (header != null && header.startsWith("Bearer ")) {
            token = header.substring(7);
        } else {
            String q = req.getParameter("token");
            if (q != null && !q.isBlank()) token = q;
        }

        if (token != null) {
            try {
                Claims claims = jwt.verifyAccess(token);
                String userId = claims.getSubject();
                String role   = claims.get("role", String.class);

                userMapper.findById(userId).ifPresent(user -> {
                    if (user.isActive()) {
                        // admin 이 관리(배정)하는 추가 테넌트들을 principal 에 로드
                        if (user.isAdmin())
                            user.setManagedTenantIds(new HashSet<>(
                                    tenantAdminMapper.findTenantIdsByUser(user.getId())));

                        var auth = new UsernamePasswordAuthenticationToken(
                                user, null,
                                List.of(new SimpleGrantedAuthority("ROLE_" + role.toUpperCase()))
                        );
                        SecurityContextHolder.getContext().setAuthentication(auth);
                    }
                });
            } catch (Exception ignored) {
                // 토큰 오류 → 인증 없이 진행 (SecurityConfig의 접근 제어에 맡김)
            }
        }
        chain.doFilter(req, res);
    }
}
