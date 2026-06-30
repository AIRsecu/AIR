package com.shop.exception;

import lombok.Getter;
import org.springframework.http.HttpStatus;

@Getter
public class AppException extends RuntimeException {
    private final HttpStatus status;
    private final String     code;

    public AppException(HttpStatus status, String code, String message) {
        super(message);
        this.status = status;
        this.code   = code;
    }

    // 자주 쓰는 팩토리
    public static AppException notFound(String msg)    { return new AppException(HttpStatus.NOT_FOUND,   "NOT_FOUND",   msg); }
    public static AppException conflict(String msg)    { return new AppException(HttpStatus.CONFLICT,    "CONFLICT",    msg); }
    public static AppException forbidden(String msg)   { return new AppException(HttpStatus.FORBIDDEN,   "FORBIDDEN",   msg); }
    public static AppException badRequest(String msg)  { return new AppException(HttpStatus.BAD_REQUEST, "BAD_REQUEST", msg); }
    public static AppException unauthorized(String msg){ return new AppException(HttpStatus.UNAUTHORIZED,"UNAUTHORIZED",msg); }
}
