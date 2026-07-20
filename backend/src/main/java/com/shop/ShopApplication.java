package com.shop;

import org.mybatis.spring.annotation.MapperScan;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;

@SpringBootApplication
@EnableScheduling   // [A1] 인시던트 보존정책 스케줄러 활성
@MapperScan({"com.shop.mapper", "com.shop.air"})   // air 패키지 매퍼(DefenseFlag/SecurityIncident) 포함
public class ShopApplication {
    public static void main(String[] args) {
        SpringApplication.run(ShopApplication.class, args);
    }
}
