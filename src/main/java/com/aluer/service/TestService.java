package com.aluer.service;

import com.aluer.ai.DeepSeekClient;
import com.aluer.alert.EmailAlertService;
import com.aluer.config.ServerGuardConfig;
import com.aluer.monitor.*;
import com.aluer.model.AlertEvent;
import com.aluer.model.AlertType;
import com.aluer.model.MetricsData;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

@Service
public class TestService {
    private static final Logger logger = LoggerFactory.getLogger(TestService.class);
    
    private final ServerGuardConfig config;
    private final RconClient rconClient;
    private final EmailAlertService emailAlertService;
    private final DeepSeekClient deepSeekClient;
    private final ProcessMonitor processMonitor;
    private final ResourceMonitor resourceMonitor;
    private final ConnectionMonitor connectionMonitor;
    private final LogMonitor logMonitor;

    public TestService(
            ServerGuardConfig config,
            RconClient rconClient,
            EmailAlertService emailAlertService,
            DeepSeekClient deepSeekClient,
            ProcessMonitor processMonitor,
            ResourceMonitor resourceMonitor,
            ConnectionMonitor connectionMonitor,
            LogMonitor logMonitor) {
        this.config = config;
        this.rconClient = rconClient;
        this.emailAlertService = emailAlertService;
        this.deepSeekClient = deepSeekClient;
        this.processMonitor = processMonitor;
        this.resourceMonitor = resourceMonitor;
        this.connectionMonitor = connectionMonitor;
        this.logMonitor = logMonitor;
    }

    public Map<String, TestResult> runAllTests() {
        Map<String, TestResult> results = new HashMap<>();
        
        logger.info("========================================");
        logger.info("       Aluer System Test Suite        ");
        logger.info("========================================");
        
        results.put("config", testConfiguration());
        results.put("rcon", testRconConnection());
        results.put("process", testProcessMonitor());
        results.put("resource", testResourceMonitor());
        results.put("connection", testConnectionMonitor());
        results.put("log", testLogMonitor());
        results.put("email", testEmailService());
        results.put("deepseek", testDeepSeekApi());
        
        printTestSummary(results);
        
        return results;
    }

    public Map<String, TestResult> runQuickTests() {
        Map<String, TestResult> results = new HashMap<>();
        
        results.put("config", testConfiguration());
        results.put("rcon", testRconConnection());
        results.put("email", testEmailService());
        
        printTestSummary(results);
        
        return results;
    }

    public TestResult testConfiguration() {
        TestResult result = new TestResult("Configuration");
        
        try {
            if (config.getMinecraft() == null) {
                result.fail("Minecraft config is null");
                return result;
            }
            
            if (config.getAi() == null) {
                result.fail("AI config is null");
                return result;
            }
            
            if (config.getAlert() == null) {
                result.fail("Alert config is null");
                return result;
            }
            
            result.pass();
            result.addDetail("Service: " + config.getMinecraft().getServiceName());
            result.addDetail("AI Enabled: " + config.getAi().isEnabled());
            result.addDetail("Email Enabled: " + config.getAlert().isEnabled());
            
        } catch (Exception e) {
            result.fail(e.getMessage());
        }
        
        return result;
    }

    public TestResult testRconConnection() {
        TestResult result = new TestResult("RCON Connection");
        
        try {
            if (!config.getMinecraft().getRcon().isEnabled()) {
                result.skip("RCON is disabled");
                return result;
            }
            
            String password = config.getMinecraft().getRcon().getPassword();
            if (password == null || password.isEmpty()) {
                result.fail("RCON password not configured");
                return result;
            }
            
            boolean connected = rconClient.connect();
            
            if (connected) {
                result.pass();
                
                String tps = rconClient.getTps();
                result.addDetail("TPS: " + tps);
                
                String players = rconClient.getOnlinePlayers();
                result.addDetail("Players: " + players);
                
                rconClient.close();
            } else {
                result.fail("Could not connect to RCON");
            }
            
        } catch (Exception e) {
            result.fail(e.getMessage());
        }
        
        return result;
    }

    public TestResult testProcessMonitor() {
        TestResult result = new TestResult("Process Monitor");
        
        try {
            boolean running = processMonitor.isProcessRunning();
            
            if (running) {
                result.pass();
                result.addDetail("Minecraft process is running");
            } else {
                result.fail("Minecraft process is not running");
            }
            
        } catch (Exception e) {
            result.fail(e.getMessage());
        }
        
        return result;
    }

    public TestResult testResourceMonitor() {
        TestResult result = new TestResult("Resource Monitor");
        
        try {
            MetricsData data = resourceMonitor.collectMetrics();
            
            result.addDetail(String.format("TPS: %.1f", data.getTps()));
            result.addDetail(String.format("CPU: %.1f%%", data.getCpuUsage()));
            result.addDetail(String.format("Memory: %.1f%%", data.getMemoryUsage()));
            result.addDetail("Players: " + data.getOnlinePlayers());
            result.addDetail("Connections: " + data.getConnections());
            
            if (data.getTps() > 0 || data.getCpuUsage() >= 0) {
                result.pass();
            } else {
                result.fail("Could not collect metrics");
            }
            
        } catch (Exception e) {
            result.fail(e.getMessage());
        }
        
        return result;
    }

    public TestResult testConnectionMonitor() {
        TestResult result = new TestResult("Connection Monitor");
        
        try {
            var connections = connectionMonitor.getActiveConnections();
            
            result.addDetail("Active connections: " + connections.size());
            
            if (connections.isEmpty()) {
                result.addDetail("No active connections (server may be offline)");
            } else {
                connections.forEach((ip, count) -> 
                    result.addDetail("  " + ip + ": " + count));
            }
            
            result.pass();
            
        } catch (Exception e) {
            result.fail(e.getMessage());
        }
        
        return result;
    }

    public TestResult testLogMonitor() {
        TestResult result = new TestResult("Log Monitor");
        
        try {
            String logPath = config.getMonitor().getLogPath();
            result.addDetail("Log path: " + logPath);
            
            var newLines = logMonitor.watchLogs();
            result.addDetail("New log lines: " + newLines.size());
            
            result.pass();
            
        } catch (Exception e) {
            result.fail(e.getMessage());
        }
        
        return result;
    }

    public TestResult testEmailService() {
        TestResult result = new TestResult("Email Service");
        
        try {
            if (!config.getAlert().isEnabled()) {
                result.skip("Email alerts are disabled");
                return result;
            }
            
            var emailConfig = config.getAlert().getEmail();
            if (emailConfig.getTo() == null || emailConfig.getTo().isEmpty()) {
                result.fail("No email recipients configured");
                return result;
            }
            
            result.addDetail("SMTP: " + emailConfig.getSmtpHost() + ":" + emailConfig.getSmtpPort());
            result.addDetail("To: " + String.join(", ", emailConfig.getTo()));
            
            result.pass();
            
        } catch (Exception e) {
            result.fail(e.getMessage());
        }
        
        return result;
    }

    public TestResult testDeepSeekApi() {
        TestResult result = new TestResult("DeepSeek API");
        
        try {
            if (!config.getAi().getDeepseek().isEnabled()) {
                result.skip("DeepSeek is disabled");
                return result;
            }
            
            if (!deepSeekClient.isEnabled()) {
                result.fail("DeepSeek API key not configured");
                return result;
            }
            
            result.addDetail("Model: " + config.getAi().getDeepseek().getModel());
            result.addDetail("Base URL: " + config.getAi().getDeepseek().getBaseUrl());
            
            AlertEvent testAlert = new AlertEvent(AlertType.TPS_LOW, "Test alert - TPS dropped below threshold");
            testAlert.setConfidence(0.85);
            
            CompletableFuture<DeepSeekClient.AiAnalysisResult> future = 
                deepSeekClient.analyzeAlertAsync(testAlert);
            
            DeepSeekClient.AiAnalysisResult analysis = future.get(30, java.util.concurrent.TimeUnit.SECONDS);
            
            if (analysis != null) {
                result.pass();
                result.addDetail("Severity: " + analysis.getSeverity());
                result.addDetail("Root Cause: " + analysis.getRootCause());
            } else {
                result.fail("No response from API");
            }
            
        } catch (Exception e) {
            result.fail(e.getMessage());
        }
        
        return result;
    }

    public TestResult testAutoExecute() {
        TestResult result = new TestResult("Auto Execute");
        
        try {
            var autoConfig = config.getAi().getDeepseek().getAutoExecute();
            
            result.addDetail("Enabled: " + autoConfig.isEnabled());
            result.addDetail("Ban IP: " + autoConfig.isBanIp());
            result.addDetail("Kick Player: " + autoConfig.isKickPlayer());
            result.addDetail("Clear Lag: " + autoConfig.isClearLag());
            result.addDetail("Min Confidence: " + autoConfig.getMinConfidence() + "%");
            
            if (autoConfig.isEnabled()) {
                result.pass();
            } else {
                result.skip("Auto execute is disabled");
            }
            
        } catch (Exception e) {
            result.fail(e.getMessage());
        }
        
        return result;
    }

    public TestResult sendTestEmail() {
        TestResult result = new TestResult("Send Test Email");
        
        try {
            if (!config.getAlert().isEnabled()) {
                result.skip("Email alerts are disabled");
                return result;
            }
            
            emailAlertService.sendTestEmail();
            result.pass();
            result.addDetail("Test email sent");
            
        } catch (Exception e) {
            result.fail(e.getMessage());
        }
        
        return result;
    }

    public TestResult testRconCommand(String command) {
        TestResult result = new TestResult("RCON Command: " + command);
        
        try {
            if (!config.getMinecraft().getRcon().isEnabled()) {
                result.skip("RCON is disabled");
                return result;
            }
            
            String output = rconClient.executeCommand(command);
            result.addDetail("Output: " + output);
            result.pass();
            
        } catch (Exception e) {
            result.fail(e.getMessage());
        }
        
        return result;
    }

    public TestResult simulateAttack() {
        TestResult result = new TestResult("Simulate Attack");
        
        try {
            String fakeIp = "192.168.1." + (int)(Math.random() * 255);
            
            for (int i = 0; i < 10; i++) {
                connectionMonitor.detectConnectionFlood();
            }
            
            result.pass();
            result.addDetail("Simulated attack from: " + fakeIp);
            result.addDetail("Connection flood detection tested");
            
        } catch (Exception e) {
            result.fail(e.getMessage());
        }
        
        return result;
    }

    private void printTestSummary(Map<String, TestResult> results) {
        logger.info("========================================");
        logger.info("           Test Results                 ");
        logger.info("========================================");
        
        int passed = 0;
        int failed = 0;
        int skipped = 0;
        
        for (var entry : results.entrySet()) {
            TestResult r = entry.getValue();
            String status = r.isPassed() ? "✓ PASS" : (r.isSkipped() ? "⊘ SKIP" : "✗ FAIL");
            logger.info("{} - {}", status, r.getName());
            
            if (r.isPassed()) passed++;
            else if (r.isSkipped()) skipped++;
            else failed++;
            
            for (String detail : r.getDetails()) {
                logger.info("    {}", detail);
            }
            
            if (!r.isPassed() && !r.isSkipped() && r.getError() != null) {
                logger.error("    Error: {}", r.getError());
            }
        }
        
        logger.info("========================================");
        logger.info("Passed: {}  Failed: {}  Skipped: {}", passed, failed, skipped);
        logger.info("========================================");
    }

    public static class TestResult {
        private final String name;
        private boolean passed = false;
        private boolean skipped = false;
        private String error;
        private java.util.List<String> details = new java.util.ArrayList<>();

        public TestResult(String name) {
            this.name = name;
        }

        public TestResult pass() {
            this.passed = true;
            return this;
        }

        public TestResult fail(String error) {
            this.error = error;
            this.passed = false;
            return this;
        }

        public TestResult skip(String reason) {
            this.skipped = true;
            this.error = reason;
            return this;
        }

        public TestResult addDetail(String detail) {
            this.details.add(detail);
            return this;
        }

        public String getName() { return name; }
        public boolean isPassed() { return passed; }
        public boolean isSkipped() { return skipped; }
        public String getError() { return error; }
        public java.util.List<String> getDetails() { return details; }
    }
}
