package com.shop.air;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

/** AIR 보안 인시던트 - 공격 탐지/대응 기록. */
@Getter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class SecurityIncident {
    private String id;
    private String type;          // ORDER_NEGATIVE_QTY ...
    private String endpoint;
    private String clientIp;
    private String actor;
    private String payload;
    private String actionTaken;   // DEFENSE_ENABLED:order.qty-guard ...
    private String status;        // DETECTED | MITIGATED | PATCHED | FAILED
    private String severity;      // CRITICAL|HIGH|MEDIUM|LOW (탐지 시점 위험도, 영속) [A2]
    private Integer score;        // 0~100 위험 점수(탐지 시점, 영속) [A2]
    private LocalDateTime createdAt;
}
