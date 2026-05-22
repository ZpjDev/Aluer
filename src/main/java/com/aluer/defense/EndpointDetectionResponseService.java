package com.aluer.defense;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.atomic.AtomicLong;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

@Component
public class EndpointDetectionResponseService {
    private static final Logger logger = LoggerFactory.getLogger(EndpointDetectionResponseService.class);

    private final Map<String, EndpointProfile> endpoints = new ConcurrentHashMap<>();
    private final Map<String, EDRRule> rules = new ConcurrentHashMap<>();
    private final Queue<EDRAlert> alertQueue = new ConcurrentLinkedQueue<>();
    private final Map<String, List<ThreatIndicator>> threatIndicators = new ConcurrentHashMap<>();
    private final AtomicLong totalEndpointsMonitored = new AtomicLong(0);
    private final AtomicLong threatsDetected = new AtomicLong(0);
    private final AtomicLong responsesExecuted = new AtomicLong(0);

    private volatile boolean enabled = false;
    private static final int MAX_ALERTS = 10000;
    private static final DateTimeFormatter DATE_FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    public EndpointDetectionResponseService() {
        initializeDefaultRules();
        logger.info("Endpoint Detection and Response Service initialized");
    }

    private void initializeDefaultRules() {
        addRule("SUSPICIOUS_PROCESS", "PROCESS", "cmd.exe|powershell.exe|/bin/sh", 90, "CRITICAL");
        addRule("UNAUTHORIZED_ACCESS", "ACCESS", "sudo|su |admin", 85, "HIGH");
        addRule("MALICIOUS_FILE", "FILE", "\\.exe$|\\.dll$|\\.bat$", 80, "HIGH");
        addRule("NETWORK_ANOMALY", "NETWORK", "unusual.*port|excessive.*connection", 75, "MEDIUM");
        addRule("REGISTRY_CHANGE", "REGISTRY", "HKLM|HKCU", 70, "MEDIUM");
        addRule("SERVICE_INSTALL", "SERVICE", "sc\\.exe|systemctl", 80, "HIGH");
        addRule("SCHEDULE_TASK", "TASK", "at\\.exe|schtasks", 75, "MEDIUM");
        addRule("WMI_EXECUTION", "WMI", "wmic|winmgmt", 85, "HIGH");
        addRule("PASSWORD_DUMP", "CREDENTIAL", "mimikatz|procdump|pwdump", 100, "CRITICAL");
        addRule("LATERAL_MOVEMENT", "MOVEMENT", "psexec|wmic|smb", 90, "HIGH");

        logger.info("Initialized {} EDR rules", rules.size());
    }

    public void addRule(String name, String category, String pattern, int severity, String priority) {
        EDRRule rule = new EDRRule(name, category, pattern, severity, priority);
        rules.put(name, rule);
    }

    public void registerEndpoint(String endpointId, String hostname, String os, String ip) {
        EndpointProfile endpoint = new EndpointProfile(endpointId, hostname, os, ip);
        endpoints.put(endpointId, endpoint);
        totalEndpointsMonitored.incrementAndGet();
        logger.info("Registered endpoint: {} ({})", hostname, os);
    }

    public void analyzeEndpoint(String endpointId, Map<String, Object> telemetry) {
        EndpointProfile endpoint = endpoints.get(endpointId);
        if (endpoint == null) return;

        for (EDRRule rule : rules.values()) {
            if (matchesRule(telemetry, rule)) {
                handleDetection(endpoint, rule, telemetry);
            }
        }

        endpoint.updateLastSeen();
    }

    private boolean matchesRule(Map<String, Object> telemetry, EDRRule rule) {
        for (Map.Entry<String, Object> entry : telemetry.entrySet()) {
            if (entry.getValue() instanceof String) {
                String value = (String) entry.getValue();
                if (value.matches(rule.getPattern())) {
                    return true;
                }
            }
        }
        return false;
    }

    private void handleDetection(EndpointProfile endpoint, EDRRule rule, Map<String, Object> telemetry) {
        threatsDetected.incrementAndGet();

        EDRAlert alert = new EDRAlert(
            endpoint.getEndpointId(),
            rule.getName(),
            rule.getCategory(),
            rule.getSeverity(),
            telemetry,
            LocalDateTime.now()
        );

        alertQueue.offer(alert);
        if (alertQueue.size() > MAX_ALERTS) {
            alertQueue.poll();
        }

        executeResponse(endpoint, rule);

        logger.warn("EDR Alert: {} detected on endpoint {} ({})", 
            rule.getName(), endpoint.getHostname(), endpoint.getEndpointId());
    }

    private void executeResponse(EndpointProfile endpoint, EDRRule rule) {
        responsesExecuted.incrementAndGet();

        switch (rule.getPriority()) {
            case "CRITICAL":
                isolateEndpoint(endpoint.getEndpointId());
                break;
            case "HIGH":
                killSuspiciousProcess(endpoint, rule);
                break;
            case "MEDIUM":
                quarantineFile(endpoint, rule);
                break;
            default:
                logSuspiciousActivity(endpoint, rule);
        }
    }

    private void isolateEndpoint(String endpointId) {
        EndpointProfile endpoint = endpoints.get(endpointId);
        if (endpoint != null) {
            endpoint.setStatus("ISOLATED");
            logger.warn("Endpoint {} has been isolated", endpointId);
        }
    }

    private void killSuspiciousProcess(EndpointProfile endpoint, EDRRule rule) {
        logger.info("Killing suspicious process on endpoint: {}", endpoint.getHostname());
    }

    private void quarantineFile(EndpointProfile endpoint, EDRRule rule) {
        logger.info("Quarantining suspicious file on endpoint: {}", endpoint.getHostname());
    }

    private void logSuspiciousActivity(EndpointProfile endpoint, EDRRule rule) {
        logger.info("Logging suspicious activity on endpoint: {}", endpoint.getHostname());
    }

    public void addThreatIndicator(String indicator, String type, String severity) {
        List<ThreatIndicator> indicators = threatIndicators.computeIfAbsent(type, k -> new ArrayList<>());
        indicators.add(new ThreatIndicator(indicator, type, severity, LocalDateTime.now()));
    }

    public Map<String, Object> getStats() {
        Map<String, Object> stats = new HashMap<>();
        stats.put("enabled", enabled);
        stats.put("totalEndpointsMonitored", totalEndpointsMonitored.get());
        stats.put("threatsDetected", threatsDetected.get());
        stats.put("responsesExecuted", responsesExecuted.get());
        stats.put("activeEndpoints", endpoints.size());
        stats.put("rulesConfigured", rules.size());
        stats.put("alertQueueSize", alertQueue.size());

        long critical = alertQueue.stream().filter(a -> a.getSeverity() >= 90).count();
        stats.put("criticalAlerts", critical);

        return stats;
    }

    public Map<String, EndpointProfile> getEndpoints() {
        return new HashMap<>(endpoints);
    }

    public List<EDRAlert> getRecentAlerts(int limit) {
        List<EDRAlert> alerts = new ArrayList<>();
        int count = 0;
        for (EDRAlert alert : alertQueue) {
            if (count++ >= limit) break;
            alerts.add(alert);
        }
        return alerts;
    }

    public void enable() {
        enabled = true;
        logger.info("EDR service enabled");
    }

    public void disable() {
        enabled = false;
        logger.info("EDR service disabled");
    }

    public static class EndpointProfile {
        private final String endpointId;
        private final String hostname;
        private final String os;
        private final String ip;
        private volatile String status;
        private volatile long lastSeen;

        public EndpointProfile(String endpointId, String hostname, String os, String ip) {
            this.endpointId = endpointId;
            this.hostname = hostname;
            this.os = os;
            this.ip = ip;
            this.status = "ACTIVE";
            this.lastSeen = System.currentTimeMillis();
        }

        public void updateLastSeen() { this.lastSeen = System.currentTimeMillis(); }

        public String getEndpointId() { return endpointId; }
        public String getHostname() { return hostname; }
        public String getOs() { return os; }
        public String getIp() { return ip; }
        public String getStatus() { return status; }
        public void setStatus(String status) { this.status = status; }
        public long getLastSeen() { return lastSeen; }
    }

    public static class EDRRule {
        private final String name;
        private final String category;
        private final String pattern;
        private final int severity;
        private final String priority;

        public EDRRule(String name, String category, String pattern, int severity, String priority) {
            this.name = name;
            this.category = category;
            this.pattern = pattern;
            this.severity = severity;
            this.priority = priority;
        }

        public String getName() { return name; }
        public String getCategory() { return category; }
        public String getPattern() { return pattern; }
        public int getSeverity() { return severity; }
        public String getPriority() { return priority; }
    }

    public static class EDRAlert {
        private final String endpointId;
        private final String ruleName;
        private final String category;
        private final int severity;
        private final Map<String, Object> telemetry;
        private final LocalDateTime timestamp;

        public EDRAlert(String endpointId, String ruleName, String category, int severity, Map<String, Object> telemetry, LocalDateTime timestamp) {
            this.endpointId = endpointId;
            this.ruleName = ruleName;
            this.category = category;
            this.severity = severity;
            this.telemetry = telemetry;
            this.timestamp = timestamp;
        }

        public String getEndpointId() { return endpointId; }
        public String getRuleName() { return ruleName; }
        public String getCategory() { return category; }
        public int getSeverity() { return severity; }
        public Map<String, Object> getTelemetry() { return telemetry; }
        public LocalDateTime getTimestamp() { return timestamp; }
    }

    public static class ThreatIndicator {
        private final String indicator;
        private final String type;
        private final String severity;
        private final LocalDateTime timestamp;

        public ThreatIndicator(String indicator, String type, String severity, LocalDateTime timestamp) {
            this.indicator = indicator;
            this.type = type;
            this.severity = severity;
            this.timestamp = timestamp;
        }

        public String getIndicator() { return indicator; }
        public String getType() { return type; }
        public String getSeverity() { return severity; }
        public LocalDateTime getTimestamp() { return timestamp; }
    }
}
