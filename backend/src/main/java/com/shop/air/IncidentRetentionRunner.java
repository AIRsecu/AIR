package com.shop.air;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

/**
 * [A1] 인시던트 보존정책 — created_at 이 retentionDays 를 초과한 security_incidents 를 주기 삭제.
 *  무한 증가 방지. retentionDays &lt;= 0 이면 비활성. 스케줄은 app.incident-retention-cron.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class IncidentRetentionRunner {

    private final SecurityIncidentMapper mapper;

    @Value("${app.incident-retention-days:90}")
    private int retentionDays;

    @Scheduled(cron = "${app.incident-retention-cron:0 15 3 * * *}")
    public void prune() {
        if (retentionDays <= 0) return;   // 비활성
        int deleted = mapper.deleteOlderThan(retentionDays);
        if (deleted > 0)
            log.info("[Retention] {}일 초과 보안 인시던트 {}건 삭제", retentionDays, deleted);
    }
}
