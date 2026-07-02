package com.shop.air;

import jakarta.servlet.ReadListener;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;

import java.io.*;
import java.nio.charset.StandardCharsets;

/** 요청 본문을 1회 읽어 캐시해, 탐지 필터와 컨트롤러가 모두 읽을 수 있게 한다. */
public class CachedBodyHttpServletRequest extends HttpServletRequestWrapper {

    private final byte[] body;

    public CachedBodyHttpServletRequest(HttpServletRequest request) throws IOException {
        super(request);
        try (InputStream is = request.getInputStream()) {
            this.body = is.readAllBytes();
        }
    }

    public String getBodyAsString() { return new String(body, StandardCharsets.UTF_8); }

    @Override
    public ServletInputStream getInputStream() {
        ByteArrayInputStream bais = new ByteArrayInputStream(body);
        return new ServletInputStream() {
            @Override public boolean isFinished() { return bais.available() == 0; }
            @Override public boolean isReady()    { return true; }
            @Override public void setReadListener(ReadListener l) { }
            @Override public int read()           { return bais.read(); }
        };
    }

    @Override
    public BufferedReader getReader() {
        return new BufferedReader(new InputStreamReader(new ByteArrayInputStream(body), StandardCharsets.UTF_8));
    }
}
