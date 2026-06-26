package com.shop.util;

import java.security.SecureRandom;
import java.time.Instant;

/**
 * 단순 ULID 생성 유틸 (외부 라이브러리 미사용).
 * 형식: 타임스탬프(10) + 랜덤(16) = 26자 Base32
 */
public final class UlidUtil {

    private static final char[] CHARS =
            "0123456789ABCDEFGHJKMNPQRSTVWXYZ".toCharArray();
    private static final SecureRandom RNG = new SecureRandom();

    private UlidUtil() {}

    public static String generate() {
        long ts = Instant.now().toEpochMilli();
        char[] ulid = new char[26];

        // 타임스탬프 파트 (10자)
        for (int i = 9; i >= 0; i--) {
            ulid[i] = CHARS[(int)(ts & 0x1F)];
            ts >>= 5;
        }

        // 랜덤 파트 (16자)
        for (int i = 10; i < 26; i++) {
            ulid[i] = CHARS[RNG.nextInt(32)];
        }

        return new String(ulid);
    }
}
