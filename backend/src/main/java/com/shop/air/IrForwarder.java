package com.shop.air;

import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Component;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.format.DateTimeFormatter;

/**
 * [IR 유입] 인시던트를 ir-automation(FastAPI POST /ingest)로 비동기 전달.
 *
 * 역할 분리: 앱은 1차 즉시 차단(가드 arming)만 담당하고, 지속형 IP 차단·사후 알림 등
 * 2차 대응은 IR 모듈이 수행한다. 이 전달기가 앱→IR 유입 경로다.
 *
 * 엔드포인트는 env AIR_IR_INGEST_URL 로 주입(미설정 시 no-op). 응답/빌드 비차단(@Async).
 * IR 이 죽어 있어도 앱 요청은 영향받지 않는다(best-effort, 짧은 타임아웃).
 */
@Slf4j
@Component
public class IrForwarder {

    private final String ingestUrl = System.getenv("AIR_IR_INGEST_URL");
    private final HttpClient http = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(3)).build();

    public boolean enabled() {
        return ingestUrl != null && !ingestUrl.isBlank();
    }

    @Async("auditExecutor")
    public void forward(SecurityIncident inc) {
        if (!enabled()) return;
        String body = toJson(inc);
        try {
            HttpRequest req = HttpRequest.newBuilder(URI.create(ingestUrl))
                    .timeout(Duration.ofSeconds(5))
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(body, StandardCharsets.UTF_8))
                    .build();
            HttpResponse<String> res = http.send(req, HttpResponse.BodyHandlers.ofString());
            if (res.statusCode() >= 300)
                log.warn("[AIR->IR] ingest 실패: {} {}", res.statusCode(), res.body());
            else
                log.info("[AIR->IR] ingest 전달: {} ({})", inc.getType(), inc.getClientIp());
        } catch (Exception e) {
            // IR 미기동/네트워크 오류 등은 앱에 영향 없도록 흡수(1차 차단은 이미 완료됨)
            log.warn("[AIR->IR] ingest 예외: {}", e.getMessage());
        }
    }

    /**
     * IR 계약(camelCase) JSON 을 수동 직렬화.
     *  Jackson 의 LocalDateTime 직렬화 설정(배열 vs ISO)에 의존하지 않도록 직접 만든다.
     *  payload 에는 공격자 입력이 들어오므로 제어문자까지 안전하게 이스케이프한다.
     */
    private static String toJson(SecurityIncident i) {
        String createdAt = i.getCreatedAt() == null ? null
                : i.getCreatedAt().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME);
        StringBuilder sb = new StringBuilder("{");
        field(sb, "id", i.getId(), true);
        field(sb, "type", i.getType(), false);
        field(sb, "endpoint", i.getEndpoint(), false);
        field(sb, "clientIp", i.getClientIp(), false);
        field(sb, "actor", i.getActor(), false);
        field(sb, "payload", i.getPayload(), false);
        field(sb, "actionTaken", i.getActionTaken(), false);
        field(sb, "status", i.getStatus(), false);
        field(sb, "createdAt", createdAt, false);
        return sb.append("}").toString();
    }

    private static void field(StringBuilder sb, String key, String val, boolean first) {
        if (!first) sb.append(",");
        sb.append('"').append(key).append("\":");
        sb.append(val == null ? "null" : jsonStr(val));
    }

    private static String jsonStr(String s) {
        StringBuilder b = new StringBuilder("\"");
        for (int idx = 0; idx < s.length(); idx++) {
            char c = s.charAt(idx);
            switch (c) {
                case '"'  -> b.append("\\\"");
                case '\\' -> b.append("\\\\");
                case '\n' -> b.append("\\n");
                case '\r' -> b.append("\\r");
                case '\t' -> b.append("\\t");
                default   -> {
                    if (c < 0x20) b.append(String.format("\\u%04x", (int) c));
                    else b.append(c);
                }
            }
        }
        return b.append('"').toString();
    }
}
