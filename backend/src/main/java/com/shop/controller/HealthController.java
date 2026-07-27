package com.shop.controller;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.util.Map;

@RestController
@RequestMapping("/api/v1")
public class HealthController {

    @Value("${spring.application.name:multitenant-shop}")
    private String appName;

    @GetMapping("/health")
    public ResponseEntity<Map<String, String>> health() {
        return ResponseEntity.ok(Map.of(
                "status", "UP",
                "app",    appName,
                "time",   ZonedDateTime.now(ZoneId.of("Asia/Seoul")).toString()
        ));
    }
}
