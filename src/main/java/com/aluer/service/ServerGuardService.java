package com.aluer.service;

import com.aluer.ai.*;
import com.aluer.alert.EmailAlertService;
import com.aluer.config.ServerGuardConfig;
import com.aluer.model.AlertEvent;
import com.aluer.model.AlertType;
import com.aluer.model.MetricsData;
import com.aluer.monitor.ProcessMonitor;
import com.aluer.monitor.ResourceMonitor;
import com.aluer.server.AgentWebSocketServer;
import com.google.gson.JsonObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * ServerGuard 核心调度服务
 *
 * 负责：
 * 1. 外部监控模式：进程保活 + 资源监控 + 日志分析（传统 external mode）
 * 2. Agent 模式：接收 Paper 插件 Agent 通过 WebSocket 推送的实时事件/指标/告警
 * 3. 告警处理管道（AI 分析 + 自动执行 + 邮件通知），两种模式共用
 */
@Service
public class ServerGuardService implements CommandLineRunner {
    private static final Logger logger = LoggerFactory.getLogger(ServerGuardService.class);

    private final ServerGuardConfig config;
    private final ProcessMonitor processMonitor;
    private final ResourceMonitor resourceMonitor;
    private final AdaptiveThreshold adaptiveThreshold;
    private final AnomalyDetector anomalyDetector;
    private final TimeSeriesPredictor timeSeriesPredictor;
    private final AttackDetector attackDetector;
    private final EmailAlertService emailAlertService;
    private final DeepSeekClient deepSeekClient;
    private final AutoExecutor autoExecutor;

    /** Agent WebSocket 服务器（接收 Paper 插件 Agent 的实时数据推送） */
    @Autowired(required = false)
    private AgentWebSocketServer agentServer;

    /** Agent 命令调度器（通过 WebSocket 向 Agent 下发防御指令） */
    @Autowired(required = false)
    private AgentCommandDispatcher agentCommandDispatcher;

    @Value("${server.port:8080}")
    private int serverPort;

    private final ScheduledExecutorService scheduler;
    private final AtomicBoolean running = new AtomicBoolean(true);

    /** Agent 推送的事件/告警计数 */
    private final AtomicBoolean agentHandlersRegistered = new AtomicBoolean(false);

    public ServerGuardService(
            ServerGuardConfig config,
            ProcessMonitor processMonitor,
            ResourceMonitor resourceMonitor,
            AdaptiveThreshold adaptiveThreshold,
            AnomalyDetector anomalyDetector,
            TimeSeriesPredictor timeSeriesPredictor,
            AttackDetector attackDetector,
            EmailAlertService emailAlertService,
            DeepSeekClient deepSeekClient,
            AutoExecutor autoExecutor) {
        this.config = config;
        this.processMonitor = processMonitor;
        this.resourceMonitor = resourceMonitor;
        this.adaptiveThreshold = adaptiveThreshold;
        this.anomalyDetector = anomalyDetector;
        this.timeSeriesPredictor = timeSeriesPredictor;
        this.attackDetector = attackDetector;
        this.emailAlertService = emailAlertService;
        this.deepSeekClient = deepSeekClient;
        this.autoExecutor = autoExecutor;

        this.scheduler = Executors.newScheduledThreadPool(4, r -> {
            Thread t = new Thread(r, "serverguard-scheduler");
            t.setDaemon(false);
            return t;
        });
    }

    @Override
    public void run(String... args) {
        printBanner();
        validateConfiguration();

        // 注册 Agent WebSocket 事件处理器
        if (agentServer != null) {
            registerAgentHandlers();
            agentHandlersRegistered.set(true);
            logger.info("Agent WebSocket handlers registered — ready to receive agent data");
        }

        // 启动监控（external 模式使用传统监控，agent 模式使用 agent 推送 + 传统指标补充）
        startMonitoring();

        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            logger.info("Shutdown signal received, gracefully stopping...");
            running.set(false);
            scheduler.shutdown();
            try {
                if (!scheduler.awaitTermination(8, TimeUnit.SECONDS)) scheduler.shutdownNow();
            } catch (InterruptedException e) {
                scheduler.shutdownNow();
                Thread.currentThread().interrupt();
            }
            emailAlertService.shutdown();
            logger.info("Aluer ServerGuard stopped");
        }, "serverguard-shutdown"));
    }

    // ─── Agent 事件处理器注册 ──────────────────────────

    private void registerAgentHandlers() {
        // 事件处理器：将 Agent 推送的原始事件转换为指标数据
        agentServer.setEventHandler((agentId, data) -> {
            try {
                String eventType = data.get("eventType") != null ? data.get("eventType").getAsString() : "";
                JsonObject eventData = data.getAsJsonObject("data");

                // 将事件数据注入 AI 分析引擎的指标流
                MetricsData metrics = buildMetricsFromAgentEvent(eventType, eventData);
                if (metrics != null) {
                    deepSeekClient.addMetrics(metrics);
                    adaptiveThreshold.addMetric(metrics);
                    anomalyDetector.addMetric(metrics);
                }
            } catch (Exception e) {
                logger.debug("Failed to process agent event: {}", e.getMessage());
            }
        });

        // 指标处理器：Agent 定期推送的 TPS/包速率等指标
        agentServer.setMetricsHandler((agentId, data) -> {
            try {
                MetricsData metrics = new MetricsData();
                metrics.setTps(data.get("tps") != null ? data.get("tps").getAsDouble() : 20.0);
                metrics.setOnlinePlayers(data.get("onlinePlayers") != null ? data.get("onlinePlayers").getAsInt() : 0);
                metrics.setConnections(metrics.getOnlinePlayers());

                deepSeekClient.addMetrics(metrics);
                adaptiveThreshold.addMetric(metrics);
                anomalyDetector.addMetric(metrics);
                timeSeriesPredictor.addMetric(metrics);
            } catch (Exception e) {
                logger.debug("Failed to process agent metrics: {}", e.getMessage());
            }
        });

        // 告警处理器：Agent 即时检测到的安全告警
        agentServer.setAlertHandler((agentId, data) -> {
            try {
                AlertEvent alert = new AlertEvent();
                String alertType = data.get("alertType") != null ? data.get("alertType").getAsString() : "SECURITY_OTHER";

                // 映射告警类型字符串到 AlertType 枚举
                try {
                    alert.setType(AlertType.valueOf(alertType));
                } catch (IllegalArgumentException e) {
                    alert.setType(AlertType.SECURITY_OTHER);
                }

                alert.setMessage(data.get("message") != null ? data.get("message").getAsString() : "");
                alert.setConfidence(data.get("confidence") != null ? data.get("confidence").getAsDouble() : 0.5);
                alert.setSource(data.get("source") != null ? data.get("source").getAsString() : agentId);
                alert.setTimestamp(Instant.now().toEpochMilli());

                handleAlert(alert);
            } catch (Exception e) {
                logger.debug("Failed to process agent alert: {}", e.getMessage());
            }
        });
    }

    /** 从 Agent 事件构建 MetricsData 快照 */
    private MetricsData buildMetricsFromAgentEvent(String eventType, JsonObject data) {
        // 跟踪玩家在线数变化
        if ("PLAYER_JOIN".equals(eventType) || "PLAYER_QUIT".equals(eventType)) {
            MetricsData m = new MetricsData();
            m.setTps(20.0); // 由定期 metrics 推送更新精确值
            m.setConnections(1); // 连接变化
            return m;
        }
        return null;
    }

    // ─── Banner ────────────────────────────────────────

    private void printBanner() {
        // Banner 已由 src/main/resources/banner.txt 提供（Spring Boot 启动时自动渲染）
        // 此处仅输出补充信息
        boolean hasAgent = agentServer != null;
        logger.info("Web Console: http://0.0.0.0:{}/", serverPort);
        if (hasAgent) {
            logger.info("Agent WS:   ws://0.0.0.0:{}/agent", serverPort);
        }
        logger.info("Type 'help' in the shell for full command reference.");
        logger.info("");
    }

    private void validateConfiguration() {
        int warnings = 0;
        if (!deepSeekClient.isEnabled()) {
            logger.warn("CONFIG: DeepSeek AI is disabled. Set DEEPSEEK_API_KEY to enable AI features.");
            warnings++;
        }
        if (warnings > 0) {
            logger.info("Configuration check complete: {} warning(s) found.", warnings);
        } else {
            logger.info("Configuration validated successfully.");
        }
    }

    // ─── 监控循环 ──────────────────────────────────────

    private void startMonitoring() {
        int interval = config.getMinecraft().getCheckIntervalSeconds();

        // 进程保活（external 模式使用）
        if (!config.isPluginMode()) {
            scheduler.scheduleAtFixedRate(this::checkProcess, 0, interval, TimeUnit.SECONDS);
        }

        scheduler.scheduleAtFixedRate(this::collectAndAnalyzeMetrics, 5, interval, TimeUnit.SECONDS);

        if (deepSeekClient.isEnabled() && config.getAi().getDeepseek().isAutoAnalyzeAlerts()) {
            int aiInterval = config.getAi().getDeepseek().getAnalysisIntervalSeconds();
            scheduler.scheduleAtFixedRate(this::runDeepSeekAnalysis, aiInterval, aiInterval, TimeUnit.SECONDS);
        }

        logger.info("Monitoring started with {}s interval", interval);
    }

    private void checkProcess() {
        try {
            AlertEvent event = processMonitor.checkAndRestart();
            if (event != null) handleAlert(event);
        } catch (Exception e) {
            logger.error("Process check failed: {}", e.getMessage());
        }
    }

    private void collectAndAnalyzeMetrics() {
        try {
            MetricsData data = resourceMonitor.collectMetrics();
            deepSeekClient.addMetrics(data);
            adaptiveThreshold.addMetric(data);
            anomalyDetector.addMetric(data);
            timeSeriesPredictor.addMetric(data);

            List<AlertEvent> resourceAlerts = resourceMonitor.checkThresholds(data);
            for (AlertEvent alert : resourceAlerts) handleAlert(alert);

            if (config.getAi().isEnabled() && config.getAi().isUseIsolationForest()) {
                AlertEvent aiAlert = anomalyDetector.detectAnomaly(data);
                if (aiAlert != null) handleAlert(aiAlert);
            }

            if (config.getAi().isEnabled() && config.getAi().isUsePrediction()) {
                TimeSeriesPredictor.PredictionResult prediction = timeSeriesPredictor.predict();
                if (prediction != null && prediction.isWillBreachThreshold() && prediction.getConfidence() > 0.6) {
                    logger.warn("TPS Prediction: {} (confidence: {:.0f}%) — {}",
                        prediction.getPredictedValue(), prediction.getConfidence() * 100, prediction.getRecommendation());
                }
            }

            List<AlertEvent> attackAlerts = attackDetector.analyzeThreats();
            for (AlertEvent alert : attackAlerts) handleAlert(alert);

        } catch (Exception e) {
            logger.error("Metrics collection failed: {}", e.getMessage());
        }
    }

    private void runDeepSeekAnalysis() {
        if (!deepSeekClient.isEnabled()) return;
        try {
            deepSeekClient.getServerHealthReportAsync().thenAccept(healthReport -> {
                if (healthReport == null) return;
                logger.info("=== DeepSeek AI Health Report ===");
                logger.info("Status: {}", healthReport.getSeverity());
                logger.info("Summary: {}", healthReport.getDescription());
                if ("critical".equals(healthReport.getSeverity()) || "warning".equals(healthReport.getSeverity())) {
                    for (String action : healthReport.getRecommendedActions()) {
                        logger.warn("Recommendation: {}", action);
                    }
                }
            });
        } catch (Exception e) {
            logger.error("DeepSeek analysis failed: {}", e.getMessage());
        }
    }

    // ─── 告警处理管道 ──────────────────────────────────

    private void handleAlert(AlertEvent alert) {
        deepSeekClient.addAlert(alert);
        logger.warn("Alert [{}]: {} (confidence: {:.0f}%)", alert.getType(), alert.getMessage(), alert.getConfidence() * 100);

        if (deepSeekClient.isEnabled() && config.getAi().getDeepseek().isAutoAnalyzeAlerts()) {
            deepSeekClient.analyzeAlertAsync(alert).thenAccept(analysis -> {
                if (analysis != null) {
                    logger.info("  [DeepSeek AI Analysis] severity={}, rootCause={}", analysis.getSeverity(), analysis.getRootCause());
                    alert.setRootCause(analysis.getRootCause());
                    alert.setSuggestedAction(String.join("; ", analysis.getRecommendedActions()));

                    // Agent 模式下通过 WebSocket 下发命令，external 模式下通过 RCON
                    if (agentCommandDispatcher != null && agentServer != null && agentServer.getConnectedAgentCount() > 0) {
                        agentCommandDispatcher.dispatchAutoAction(analysis, alert, agentServer);
                    } else {
                        autoExecutor.executeAutoAction(analysis, alert);
                    }
                }
            });
        }

        emailAlertService.sendAlert(alert);
    }

    public boolean isRunning() { return running.get(); }
    public void stop() { running.set(false); }
}
