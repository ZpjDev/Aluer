package com.aluer;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableAsync;

@SpringBootApplication
@EnableAsync
public class ServerGuardApplication {
    public static void main(String[] args) {
        SpringApplication.run(ServerGuardApplication.class, args);
    }
}
