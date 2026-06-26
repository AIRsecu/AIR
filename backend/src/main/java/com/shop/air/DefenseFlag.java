package com.shop.air;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

/** AIR 방어 토글 플래그. enabled=true 면 해당 방어 가드가 활성(차단). */
@Getter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class DefenseFlag {
    private String flagKey;
    private boolean enabled;
    private LocalDateTime updatedAt;
}
