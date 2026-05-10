package com.aluer.service;

import com.aluer.ai.*;
import com.aluer.alert.EmailAlertService;
import com.aluer.config.ServerGuardConfig;
import com.aluer.monitor.*;
import com.aluer.model.AlertEvent;
import com.aluer.model.MetricsData;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

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
    
    private final ScheduledExecutorService scheduler;
    private volatile boolean running = true;
    private int alertCount = 0;

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
        
        this.scheduler = Executors.newScheduledThreadPool(4);
    }

    @Override
    public void run(String... args) throws Exception {
        logger.info("========================================");
        logger.info("  Aluer 服务器防护系统 启动中...");
        logger.info("========================================");
        
        if (deepSeekClient.isEnabled()) {
            logger.info("  DeepSeek AI: 已启用");
        } else {
            logger.info("  DeepSeek AI: 未启用 (请配置apiKey以启用)");
        }
        
        startMonitoring();
        
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            logger.info("正在关闭服务器防护系统...");
            running = false;
            scheduler.shutdown();
            try {
                if (!scheduler.awaitTermination(5, TimeUnit.SECONDS)) {
                    scheduler.shutdownNow();
                }
            } catch (InterruptedException e) {
                scheduler.shutdownNow();
            }
            emailAlertService.shutdown();
            logger.info("服务器防护系统已停止");
        }));
        
        while (running) {
            Thread.sleep(1000);
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
        
        logger.info("监控已启动, 间隔: {} 秒", intervalSeconds);
    }

    private void checkProcess() {
        try {
            AlertEvent event = processMonitor.checkAndRestart();
            if (event != null) {
                logger.warn("Process check alert: {}", event.getMessage());
                handleAlert(event);
            }
        } catch (Exception e) {
            logger.error("Error in process check: {}", e.getMessage());
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
            logger.error("Error in metrics collection: {}", e.getMessage());
        }
    }

    private void runDeepSeekAnalysis() {
        if (!deepSeekClient.isEnabled()) {
            return;
        }
        
        try {
            DeepSeekClient.AiAnalysisResult healthReport = deepSeekClient.getServerHealthReportAsync().get();
            
            if (healthReport != null) {
                logger.info("=== DeepSeek AI 健康报告 ===");
                logger.info("状态: {}", healthReport.getSeverity());
                logger.info("摘要: {}", healthReport.getDescription());
                
                if ("critical".equals(healthReport.getSeverity()) || "warning".equals(healthReport.getSeverity())) {
                    for (String concern : healthReport.getRecommendedActions()) {
                        logger.warn("建议: {}", concern);
                    }
                }
            }
        } catch (Exception e) {
            logger.error("DeepSeek 分析错误: {}", e.getMessage());
        }
    }

    private void handleAlert(AlertEvent alert) {
        deepSeekClient.addAlert(alert);
        
        logger.warn("告警 [{}]: {} (置信度: {:.0f}%)", 
            alert.getType(), alert.getMessage(), alert.getConfidence() * 100);
        
        if (deepSeekClient.isEnabled() && config.getAi().getDeepseek().isAutoAnalyzeAlerts()) {
            deepSeekClient.analyzeAlertAsync(alert).thenAccept(analysis -> {
                if (analysis != null) {
                    logger.info("  [DeepSeek AI 分析]");
                    logger.info("    严重程度: {}", analysis.getSeverity());
                    logger.info("    原因分析: {}", analysis.getRootCause());
                    
                    if (!analysis.getRecommendedActions().isEmpty()) {
                        logger.info("    建议操作:");
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
                logger.info("  原因分析: {}", alert.getRootCause());
            }
            if (alert.getSuggestedAction() != null) {
                logger.info("  建议操作: {}", alert.getSuggestedAction());
            }
        }
        
        emailAlertService.sendAlert(alert);
        
        if (alert.getType().name().contains("CONNECTION_FLOOD") || 
            alert.getType().name().contains("LOG_ATTACK")) {
            if (alert.getConfidence() > 0.8) {
                logger.info("高置信度攻击告警 - 触发自动防御");
            }
        }
    }

    private void executeAutoAction(DeepSeekClient.AiAnalysisResult analysis, AlertEvent alert) {
        String autoAction = analysis.getAutoAction();
        
        if (autoAction == null || autoAction.isEmpty() || autoAction.equals("无") || autoAction.equals("none")) {
            return;
        }
        
        logger.info("  [DeepSeek] 执行自动操作: {}", autoAction);
        
        if (autoAction.contains("封禁IP") || autoAction.contains("ban")) {
            logger.info("    自动封禁IP已触发");
        } else if (autoAction.contains("限制连接")) {
            logger.info("    自动连接限制已触发");
        } else if (autoAction.contains("重启")) {
            logger.info("    建议重启服务器");
        }
    }

    public void stop() {
        running = false;
    }
}
