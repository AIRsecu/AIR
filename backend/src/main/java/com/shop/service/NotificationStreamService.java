package com.shop.service;

import com.shop.domain.User;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

import java.io.IOException;
import java.util.Collection;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * SSE(Server-Sent Events) 연결 레지스트리.
 *  - userId 별로 열린 SseEmitter 들을 관리(한 사용자가 여러 탭 접속 가능)
 *  - 도메인 변경 시 NotificationService 가 send(...) 로 해당 사용자에게 푸시
 *  - 끊긴 연결은 onCompletion/onTimeout/onError 또는 전송 실패 시 정리
 *  ※ 폴링(20초) 대체: 변경 발생 시점에만 이벤트를 흘려보내 실시간성 확보.
 */
@Slf4j
@Service
public class NotificationStreamService {

    /** SSE 연결 타임아웃(밀리초). 만료되면 브라우저 EventSource 가 자동 재연결. */
    private static final long SSE_TIMEOUT_MS = 30 * 60 * 1000L;   // 30분

    /** userId → 열린 emitter 집합 */
    private final Map<String, Set<SseEmitter>> emitters = new ConcurrentHashMap<>();
    /** userId → 구독 시점 principal(역할/관리 테넌트 필터링용) */
    private final Map<String, User> principals = new ConcurrentHashMap<>();

    /** 구독 등록 후 emitter 반환. 컨트롤러는 이 값을 그대로 응답으로 돌려준다. */
    public SseEmitter subscribe(User user) {
        SseEmitter emitter = new SseEmitter(SSE_TIMEOUT_MS);
        emitters.computeIfAbsent(user.getId(), k -> ConcurrentHashMap.newKeySet()).add(emitter);
        principals.put(user.getId(), user);

        emitter.onCompletion(() -> remove(user.getId(), emitter));
        emitter.onTimeout(()    -> { emitter.complete(); remove(user.getId(), emitter); });
        emitter.onError(e       -> remove(user.getId(), emitter));

        // 연결 확인용 첫 코멘트(프록시 버퍼 플러시 + 즉시 onopen)
        try {
            emitter.send(SseEmitter.event().comment("connected"));
        } catch (IOException e) {
            remove(user.getId(), emitter);
        }
        return emitter;
    }

    /** 특정 사용자의 모든 열린 연결로 이벤트 전송(실패한 연결은 제거). */
    public void send(String userId, String event, Object data) {
        Set<SseEmitter> set = emitters.get(userId);
        if (set == null || set.isEmpty()) return;
        for (SseEmitter emitter : set) {
            try {
                emitter.send(SseEmitter.event().name(event).data(data));
            } catch (Exception e) {
                remove(userId, emitter);
            }
        }
    }

    /** 현재 접속 중인(emitter 가 살아있는) 사용자 principal 목록. */
    public Collection<User> connectedPrincipals() {
        return principals.values();
    }

    private void remove(String userId, SseEmitter emitter) {
        Set<SseEmitter> set = emitters.get(userId);
        if (set == null) return;
        set.remove(emitter);
        if (set.isEmpty()) {
            emitters.remove(userId);
            principals.remove(userId);
        }
    }
}
