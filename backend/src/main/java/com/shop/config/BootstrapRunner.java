package com.shop.config;

import com.shop.domain.User;
import com.shop.mapper.UserMapper;
import com.shop.service.UserService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Component;

@Slf4j
@Component
@RequiredArgsConstructor
public class BootstrapRunner implements ApplicationRunner {

    private final UserService userService;
    private final UserMapper  userMapper;

    @Value("${app.bootstrap-admin-username}")
    private String adminUsername;

    @Value("${app.bootstrap-admin-password}")
    private String adminPassword;

    @Override
    public void run(ApplicationArguments args) {
        // 멱등: 이미 존재하면 스킵
        if (userMapper.countByUsername(adminUsername) > 0) {
            log.info("[Bootstrap] super_admin '{}' 이미 존재, 스킵", adminUsername);
            return;
        }

        if (adminPassword == null || adminPassword.isBlank()) {
            log.warn("[Bootstrap] BOOTSTRAP_ADMIN_PASSWORD 미설정, super_admin 생성 스킵");
            return;
        }

        userService.create(adminUsername, adminPassword,
                User.Role.super_admin, "Administrator", null);
        log.info("[Bootstrap] super_admin '{}' 생성 완료", adminUsername);
    }
}
