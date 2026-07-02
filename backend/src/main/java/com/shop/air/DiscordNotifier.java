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
                + "• 유형: `" + codeSafe(inc.getType()) + "`\n"
                + "• 엔드포인트: `" + codeSafe(inc.getEndpoint()) + "`\n"
                + "• 출처 IP: `" + codeSafe(inc.getClientIp()) + "`\n"
                + "• 조치: " + nz(inc.getActionTaken()) + "\n"
                + "• 상태: " + nz(inc.getStatus());
        // [AIR] #5 allowed_mentions parse:[] → 공격자가 필드에 주입한 @everyone/@here/멘션을 무력화.
        String body = "{\"content\":" + jsonStr(content)
                + ",\"allowed_mentions\":{\"parse\":[]}}";
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

    /**
     * [AIR] #5 백틱 코드스팬 안에 넣을 공격자 영향 값 정리:
     *  백틱 제거(코드스팬 탈출→마크다운/멘션 인젝션 방지) + 개행/제어문자 제거 + 길이 제한.
     *  (코드스팬 내부에서는 *,_,~ 등 마크다운이 렌더되지 않으므로 백틱만 무력화하면 충분)
     */
    private static String codeSafe(String s) {
        if (s == null || s.isBlank()) return "-";
        String t = s.replace("`", "'").replaceAll("[\\r\\n\\t]", " ");
        return t.length() > 300 ? t.substring(0, 300) + "…" : t;
    }

    private static String jsonStr(String s) {
        return "\"" + s.replace("\\", "\\\\").replace("\"", "\\\"")
                .replace("\n", "\\n").replace("\r", "") + "\"";
    }
}
