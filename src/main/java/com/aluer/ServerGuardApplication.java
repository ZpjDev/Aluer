package com.aluer;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.scheduling.annotation.EnableAsync;

/**
 * Aluer ServerGuard 主应用入口（外部引擎）
 *
 * 独立运行，等待 Paper 插件 Agent 通过 WebSocket 连接并推送实时数据。
 * 同时保留传统 external 监控模式的进程保活和日志分析能力。
 */
@SpringBootApplication
@EnableAsync
public class ServerGuardApplication {
    private static final Logger logger = LoggerFactory.getLogger(ServerGuardApplication.class);
    private static volatile ConfigurableApplicationContext context;

    public static void main(String[] args) {
        context = SpringApplication.run(ServerGuardApplication.class, args);

        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            logger.info("JVM shutdown hook triggered — closing application context");
            if (context != null) {
                context.close();
            }
        }, "serverguard-shutdown-hook"));

        logger.info("Aluer ServerGuard v5.0.0 is ready");
        logger.info("Agent WebSocket endpoint: ws://0.0.0.0:{}/agent", context.getEnvironment().getProperty("server.port", "8080"));
    }

    public static ConfigurableApplicationContext getContext() {
        return context;
    }
}
