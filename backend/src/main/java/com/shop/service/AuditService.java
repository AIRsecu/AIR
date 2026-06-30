package com.shop.service;

import com.shop.domain.AuditLog;
import com.shop.domain.User;
import com.shop.mapper.AuditLogMapper;
import com.shop.util.UlidUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@RequiredArgsConstructor
public class AuditService {

    private final AuditLogMapper auditLogMapper;

    /**
     * 비동기 감사 로그 기록. 트랜잭션 밖에서 호출하므로 메인 흐름에 영향 없음.
     */
    @Async
    public void log(User actor, String action,
                    String resourceType, String resourceId,
                    String detail, String ipAddress) {
        AuditLog log = AuditLog.builder()
                .id(UlidUtil.generate())
                .actorId(actor != null ? actor.getId() : null)
                .actorUsername(actor != null ? actor.getUsername() : "system")
                .tenantId(actor != null ? actor.getTenantId() : null)
                .action(action)
                .resourceType(resourceType)
                .resourceId(resourceId)
                .detail(detail)
                .ipAddress(ipAddress)
                .build();
        auditLogMapper.insert(log);
    }

    /** 시스템 이벤트 (actor 없음) */
    @Async
    public void logSystem(String action, String resourceType,
                          String resourceId, String detail) {
        log(null, action, resourceType, resourceId, detail, null);
    }

    public List<AuditLog> findByActor(String actorId)       { return auditLogMapper.findByActorId(actorId); }
    public List<AuditLog> findByTenant(String tenantId)     { return auditLogMapper.findByTenantId(tenantId); }
    public List<AuditLog> findByResource(String resourceId) { return auditLogMapper.findByResourceId(resourceId); }
    public List<AuditLog> findRecent(int limit)             { return auditLogMapper.findRecent(Math.min(limit, 500)); }
}
