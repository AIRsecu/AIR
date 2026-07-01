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

/**
 * Discord 웹훅 알림 — 인시던트 발생 시 비동기 푸시(응답/빌드 비차단).
 *  웹훅 URL 은 환경변수 AIR_DISCORD_WEBHOOK 로 주입. 미설정이면 no-op(로그만).
 */
@Slf4j
@Component
public class DiscordNotifier {

    private final String webhook = System.getenv("AIR_DISCORD_WEBHOOK");
    private final HttpClient http = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(5)).build();

    public boolean enabled() {
        return webhook != null && !webhook.isBlank();
    }

    @Async("auditExecutor")
    public void notifyIncident(SecurityIncident inc, String severity, int score) {
        if (!enabled()) return;
        String emoji = switch (severity) {
            case "CRITICAL" -> "🔴";
            case "HIGH"     -> "🟠";
            case "MEDIUM"   -> "🟡";
            default          -> "⚪";
        };
        String content = emoji + " **[AIR] " + severity + " (risk " + score + ")** 공격 탐지·자동대응\n"
                + "• 유형: `" + nz(inc.getType()) + "`\n"
                + "• 엔드포인트: `" + nz(inc.getEndpoint()) + "`\n"
                + "• 출처 IP: " + nz(inc.getClientIp()) + "\n"
                + "• 조치: " + nz(inc.getActionTaken()) + "\n"
                + "• 상태: " + nz(inc.getStatus());
        String body = "{\"content\":" + jsonStr(content) + "}";
        try {
            HttpRequest req = HttpRequest.newBuilder(URI.create(webhook))
                    .timeout(Duration.ofSeconds(8))
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(body, StandardCharsets.UTF_8))
                    .build();
            HttpResponse<String> res = http.send(req, HttpResponse.BodyHandlers.ofString());
            if (res.statusCode() >= 300)
                log.warn("[AIR] Discord 알림 실패: {} {}", res.statusCode(), res.body());
            else
                log.info("[AIR] Discord 알림 전송: {} (risk {})", inc.getType(), score);
        } catch (Exception e) {
            log.warn("[AIR] Discord 알림 예외: {}", e.getMessage());
        }
    }

    private static String nz(String s) { return s == null ? "-" : s; }

    private static String jsonStr(String s) {
        return "\"" + s.replace("\\", "\\\\").replace("\"", "\\\"")
                .replace("\n", "\\n").replace("\r", "") + "\"";
    }
}
