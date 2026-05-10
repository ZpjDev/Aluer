package com.aluer;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.scheduling.annotation.EnableAsync;

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

        logger.info("Aluer ServerGuard is ready");
    }

    public static ConfigurableApplicationContext getContext() {
        return context;
    }
}
