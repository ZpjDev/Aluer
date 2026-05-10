package com.aluer.service;

import com.aluer.ai.*;
import com.aluer.alert.EmailAlertService;
import com.aluer.config.ServerGuardConfig;
import com.aluer.monitor.*;
import com.aluer.model.AlertEvent;
import com.aluer.model.MetricsData;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

@Service
public class ServerGuardService implements CommandLineRunner {
    private static final Logger logger = LoggerFactory.getLogger(ServerGuardService.class);

    private final ServerGuardConfig config;
    private final ProcessMonitor processMonitor;
    private final ResourceMonitor resourceMonitor;
    private final ConnectionMonitor connectionMonitor;
    private final LogMonitor logMonitor;
    private final AdaptiveThreshold adaptiveThreshold;
    private final AnomalyDetector anomalyDetector;
    private final TimeSeriesPredictor timeSeriesPredictor;
    private final AttackDetector attackDetector;
    private final EmailAlertService emailAlertService;
    private final DeepSeekClient deepSeekClient;
    private final AutoExecutor autoExecutor;
    private final RconClient rconClient;

    @Value("${server.port:8080}")
    private int serverPort;

    private final ScheduledExecutorService scheduler;
    private final AtomicBoolean running = new AtomicBoolean(true);

    public ServerGuardService(
            ServerGuardConfig config,
            ProcessMonitor processMonitor,
            ResourceMonitor resourceMonitor,
            ConnectionMonitor connectionMonitor,
            LogMonitor logMonitor,
            AdaptiveThreshold adaptiveThreshold,
            AnomalyDetector anomalyDetector,
            TimeSeriesPredictor timeSeriesPredictor,
            AttackDetector attackDetector,
            EmailAlertService emailAlertService,
            DeepSeekClient deepSeekClient,
            AutoExecutor autoExecutor,
            RconClient rconClient) {
        this.config = config;
        this.processMonitor = processMonitor;
        this.resourceMonitor = resourceMonitor;
        this.connectionMonitor = connectionMonitor;
        this.logMonitor = logMonitor;
        this.adaptiveThreshold = adaptiveThreshold;
        this.anomalyDetector = anomalyDetector;
        this.timeSeriesPredictor = timeSeriesPredictor;
        this.attackDetector = attackDetector;
        this.emailAlertService = emailAlertService;
        this.deepSeekClient = deepSeekClient;
        this.autoExecutor = autoExecutor;
        this.rconClient = rconClient;

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

        startMonitoring();

        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            logger.info("Shutdown signal received, gracefully stopping...");
            running.set(false);
            scheduler.shutdown();
            try {
                if (!scheduler.awaitTermination(8, TimeUnit.SECONDS)) {
                    scheduler.shutdownNow();
                }
            } catch (InterruptedException e) {
                scheduler.shutdownNow();
                Thread.currentThread().interrupt();
            }
            emailAlertService.shutdown();
            if (rconClient.isConnected()) {
                rconClient.close();
            }
            logger.info("Aluer ServerGuard stopped");
        }, "serverguard-shutdown"));
    }

    private void printBanner() {
        logger.info("");
        logger.info("╔══════════════════════════════════════════════════════════════╗");
        logger.info("║          Aluer ServerGuard v1.0.0                           ║");
        logger.info("║          AI-Powered Minecraft Server Protection              ║");
        logger.info("╠══════════════════════════════════════════════════════════════╣");
        logger.info("║  Java:        {} ║", String.format("%-36s", System.getProperty("java.version")));
        logger.info("║  Available CPUs: {}{} ║",
            String.format("%-32s", Runtime.getRuntime().availableProcessors()),
            "");
        logger.info("║  Max Memory:  {}{} ║",
            String.format("%-32s", (Runtime.getRuntime().maxMemory() / (1024 * 1024)) + " MB"),
            "");
        logger.info("╠══════════════════════════════════════════════════════════════╣");
        logger.info("║  RCON:        {}:{} {}{} ║",
            config.getMinecraft().getRcon().getHost(),
            config.getMinecraft().getRcon().getPort(),
            config.getMinecraft().getRcon().isEnabled() ? "enabled" : "disabled",
            "                         ");
        logger.info("║  DeepSeek AI: {}{} ║",
            deepSeekClient.isEnabled() ? "enabled (" + config.getAi().getDeepseek().getModel() + ")" : "disabled",
            deepSeekClient.isEnabled() ? "" : "                          ");
        logger.info("║  Web Console: http://0.0.0.0:{}{} ║",
            serverPort,
            "                        ");
        logger.info("╠══════════════════════════════════════════════════════════════╣");
        logger.info("║  Monitor:     {}s interval{}{} ║",
            config.getMinecraft().getCheckIntervalSeconds(),
            "                                 ",
            "");
        logger.info("║  Auto-Execute: {}{} ║",
            config.getAi().getDeepseek().getAutoExecute().isEnabled() ? "enabled" : "disabled",
            "                                ");
        logger.info("║  Auto-Heal:   {}{} ║",
            config.getSecurity().getSelfHealing().isEnabled() ? "enabled" : "disabled",
            "                                ");
        logger.info("╚══════════════════════════════════════════════════════════════╝");
        logger.info("");
        logger.info("Type 'help' in the shell for available commands.");
        logger.info("Access the web console at http://localhost:{}/", serverPort);
        logger.info("");
    }

    private void validateConfiguration() {
        int warnings = 0;

        if (!deepSeekClient.isEnabled()) {
            logger.warn("CONFIG: DeepSeek AI is disabled. Set DEEPSEEK_API_KEY to enable AI features.");
            warnings++;
        }

        String rconPassword = config.getMinecraft().getRcon().getPassword();
        if (rconPassword == null || rconPassword.isEmpty()) {
            logger.warn("CONFIG: RCON password is not set. Set RCON_PASSWORD env var.");
            warnings++;
        }

        if (!config.getAlert().getEmail().getUsername().isEmpty()) {
            if (config.getAlert().getEmail().getTo() == null || config.getAlert().getEmail().getTo().isEmpty()) {
                logger.warn("CONFIG: Email alert enabled but no recipients configured.");
                warnings++;
            }
        }

        if (config.getSecurity().getHostEnforcement().isDryRun()) {
            logger.info("CONFIG: Host enforcement is in dry-run mode (safe for first deployment).");
        }
        if (config.getSecurity().getSelfHealing().isDryRun()) {
            logger.info("CONFIG: Self-healing is in dry-run mode (safe for first deployment).");
        }

        if (warnings > 0) {
            logger.info("Configuration check complete: {} warning(s) found.", warnings);
        } else {
            logger.info("Configuration validated successfully.");
        }
    }

    private void startMonitoring() {
        int intervalSeconds = config.getMinecraft().getCheckIntervalSeconds();

        scheduler.scheduleAtFixedRate(this::checkProcess, 0, intervalSeconds, TimeUnit.SECONDS);
        scheduler.scheduleAtFixedRate(this::collectAndAnalyzeMetrics, 5, intervalSeconds, TimeUnit.SECONDS);

        if (deepSeekClient.isEnabled() && config.getAi().getDeepseek().isAutoAnalyzeAlerts()) {
            int analysisInterval = config.getAi().getDeepseek().getAnalysisIntervalSeconds();
            scheduler.scheduleAtFixedRate(this::runDeepSeekAnalysis, analysisInterval, analysisInterval, TimeUnit.SECONDS);
        }

        logger.info("Monitoring started with {}s interval", intervalSeconds);
    }

    private void checkProcess() {
        try {
            AlertEvent event = processMonitor.checkAndRestart();
            if (event != null) {
                logger.warn("Process alert: {}", event.getMessage());
                handleAlert(event);
            }
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
            for (AlertEvent alert : resourceAlerts) {
                handleAlert(alert);
            }

            AlertEvent connectionAlert = connectionMonitor.checkConnectionFlood();
            if (connectionAlert != null) {
                handleAlert(connectionAlert);
            }

            List<AlertEvent> logAlerts = logMonitor.analyzeLogs();
            for (AlertEvent alert : logAlerts) {
                handleAlert(alert);
            }

            if (config.getAi().isEnabled() && config.getAi().isUseIsolationForest()) {
                AlertEvent aiAlert = anomalyDetector.detectAnomaly(data);
                if (aiAlert != null) {
                    handleAlert(aiAlert);
                }
            }

            if (config.getAi().isEnabled() && config.getAi().isUsePrediction()) {
                TimeSeriesPredictor.PredictionResult prediction = timeSeriesPredictor.predict();
                if (prediction != null && prediction.isWillBreachThreshold() && prediction.getConfidence() > 0.6) {
                    logger.warn("TPS Prediction: {} (confidence: {:.0f}%) - {}",
                        prediction.getPredictedValue(),
                        prediction.getConfidence() * 100,
                        prediction.getRecommendation());
                }
            }

            List<AlertEvent> attackAlerts = attackDetector.analyzeThreats();
            for (AlertEvent alert : attackAlerts) {
                handleAlert(alert);
            }

        } catch (Exception e) {
            logger.error("Metrics collection failed: {}", e.getMessage());
        }
    }

    private void runDeepSeekAnalysis() {
        if (!deepSeekClient.isEnabled()) {
            return;
        }

        try {
            deepSeekClient.getServerHealthReportAsync().thenAccept(healthReport -> {
                if (healthReport == null) {
                    return;
                }
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

    private void handleAlert(AlertEvent alert) {
        deepSeekClient.addAlert(alert);

        logger.warn("Alert [{}]: {} (confidence: {:.0f}%)",
            alert.getType(), alert.getMessage(), alert.getConfidence() * 100);

        if (deepSeekClient.isEnabled() && config.getAi().getDeepseek().isAutoAnalyzeAlerts()) {
            deepSeekClient.analyzeAlertAsync(alert).thenAccept(analysis -> {
                if (analysis != null) {
                    logger.info("  [DeepSeek AI Analysis]");
                    logger.info("    Severity: {}", analysis.getSeverity());
                    logger.info("    Root Cause: {}", analysis.getRootCause());

                    if (!analysis.getRecommendedActions().isEmpty()) {
                        logger.info("    Recommended Actions:");
                        for (String action : analysis.getRecommendedActions()) {
                            logger.info("      - {}", action);
                        }
                    }

                    alert.setRootCause(analysis.getRootCause());
                    alert.setSuggestedAction(String.join("; ", analysis.getRecommendedActions()));

                    autoExecutor.executeAutoAction(analysis, alert);
                }
            });
        } else {
            if (alert.getRootCause() != null) {
                logger.info("  Root Cause: {}", alert.getRootCause());
            }
            if (alert.getSuggestedAction() != null) {
                logger.info("  Suggested Action: {}", alert.getSuggestedAction());
            }
        }

        emailAlertService.sendAlert(alert);

        if (alert.getType().name().contains("CONNECTION_FLOOD") ||
            alert.getType().name().contains("LOG_ATTACK")) {
            if (alert.getConfidence() > 0.8) {
                logger.info("High confidence attack alert — triggering auto defense");
            }
        }
    }

    public boolean isRunning() {
        return running.get();
    }

    public void stop() {
        running.set(false);
    }
}
