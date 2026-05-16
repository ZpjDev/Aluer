package com.aluer;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.scheduling.annotation.EnableAsync;

/**
 * Aluer ServerGuard 主应用入口
 *
 * 支持两种运行模式：
 * 1. standalone — java -jar serverguard.jar（传统外部监控模式）
 * 2. plugin — 由 PaperMC 插件 AluerPlugin 调用 bootstrap() 启动嵌入式上下文
 *
 * 模式由系统属性 serverguard.mode 决定，AluerPlugin 启动时自动设置为 "plugin"
 */
@SpringBootApplication
@EnableAsync
public class ServerGuardApplication {
    private static final Logger logger = LoggerFactory.getLogger(ServerGuardApplication.class);
    private static volatile ConfigurableApplicationContext context;

    public static void main(String[] args) {
        // standalone 模式：直接启动
        System.setProperty("serverguard.mode", "external");
        context = SpringApplication.run(ServerGuardApplication.class, args);

        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            logger.info("JVM shutdown hook triggered — closing application context");
            if (context != null) {
                context.close();
            }
        }, "serverguard-shutdown-hook"));

        logger.info("Aluer ServerGuard standalone mode is ready");
    }

    /**
     * 插件模式启动入口 — 由 AluerPlugin.onEnable() 调用
     *
     * Paper 插件在 onEnable 时异步调用此方法，
     * 返回的 ConfigurableApplicationContext 由插件持有并在 onDisable 时关闭。
     *
     * @return Spring 应用上下文
     */
    public static ConfigurableApplicationContext bootstrap() {
        if (context != null) {
            logger.warn("Spring Boot context already running, reusing existing context");
            return context;
        }
        context = SpringApplication.run(ServerGuardApplication.class);
        logger.info("Aluer ServerGuard plugin mode bootstrapped — Spring context ready");
        return context;
    }

    public static ConfigurableApplicationContext getContext() {
        return context;
    }
}
