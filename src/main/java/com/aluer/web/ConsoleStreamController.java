package com.aluer.web;

import com.aluer.config.ServerGuardConfig;
import com.aluer.console.AluerOperationsCenterService;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

import java.io.IOException;
import java.util.Map;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

@RestController
@RequestMapping("/api/console/stream")
public class ConsoleStreamController {
    private final ServerGuardConfig config;
    private final AluerOperationsCenterService aluerOperationsCenterService;
    private final ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(2, runnable -> {
        Thread thread = new Thread(runnable, "aluer-console-stream");
        thread.setDaemon(true);
        return thread;
    });

    public ConsoleStreamController(ServerGuardConfig config,
                                   AluerOperationsCenterService aluerOperationsCenterService) {
        this.config = config;
        this.aluerOperationsCenterService = aluerOperationsCenterService;
    }

    @GetMapping(value = "/overview", produces = MediaType.TEXT_EVENT_STREAM_VALUE)
    public SseEmitter overviewStream() {
        SseEmitter emitter = new SseEmitter(0L);
        int intervalSeconds = Math.max(2, config.getDashboard().getRefreshIntervalSeconds());

        ScheduledFuture<?> future = scheduler.scheduleAtFixedRate(() -> sendOverview(emitter),
            0, intervalSeconds, TimeUnit.SECONDS);

        emitter.onCompletion(() -> future.cancel(true));
        emitter.onTimeout(() -> {
            future.cancel(true);
            emitter.complete();
        });
        emitter.onError(error -> future.cancel(true));
        return emitter;
    }

    private void sendOverview(SseEmitter emitter) {
        try {
            Map<String, Object> overview = aluerOperationsCenterService.buildOverview();
            emitter.send(SseEmitter.event()
                .name("overview")
                .data(overview));
        } catch (IOException e) {
            emitter.completeWithError(e);
        }
    }
}
