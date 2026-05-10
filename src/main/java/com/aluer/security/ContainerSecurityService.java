package com.aluer.security;

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
public class ContainerSecurityService {
    private static final Logger logger = LoggerFactory.getLogger(ContainerSecurityService.class);

    private final Map<String, ContainerProfile> containers = new ConcurrentHashMap<>();
    private final Map<String, ContainerImage> images = new ConcurrentHashMap<>();
    private final Queue<SecurityAlert> alertQueue = new ConcurrentLinkedQueue<>();
    private final Map<String, List<ContainerEvent>> eventHistory = new ConcurrentHashMap<>();
    private final AtomicLong totalContainersScanned = new AtomicLong(0);
    private final AtomicLong vulnerabilitiesFound = new AtomicLong(0);
    private final AtomicLong threatsBlocked = new AtomicLong(0);

    private volatile boolean scanningEnabled = true;
    private static final int MAX_EVENTS = 10000;
    private static final DateTimeFormatter DATE_FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    public ContainerSecurityService() {
        initializeDefaultPolicies();
        logger.info("Container Security Service initialized");
    }

    private void initializeDefaultPolicies() {
        logger.info("Container security policies initialized");
    }

    public void registerContainer(String containerId, String imageName, String status) {
        ContainerProfile container = new ContainerProfile(containerId, imageName, status);
        containers.put(containerId, container);
        totalContainersScanned.incrementAndGet();
        logEvent(containerId, "REGISTERED", "Container registered");
        logger.info("Registered container: {} with image: {}", containerId, imageName);
    }

    public ContainerProfile getContainer(String containerId) {
        return containers.get(containerId);
    }

    public List<ContainerProfile> getAllContainers() {
        return new ArrayList<>(containers.values());
    }

    public void scanContainer(String containerId) {
        ContainerProfile container = containers.get(containerId);
        if (container == null) {
            logger.warn("Container not found: {}", containerId);
            return;
        }

        logger.info("Scanning container: {}", containerId);
        container.setLastScanTime(LocalDateTime.now());

        List<Vulnerability> vulnerabilities = performVulnerabilityScan(container);

        if (!vulnerabilities.isEmpty()) {
            vulnerabilitiesFound.addAndGet(vulnerabilities.size());
            container.setVulnerabilities(vulnerabilities);

            for (Vulnerability vuln : vulnerabilities) {
                if (vuln.getSeverity().equals("CRITICAL")) {
                    threatsBlocked.incrementAndGet();
                    triggerAlert(containerId, "CRITICAL_VULNERABILITY", vuln.getDescription());
                }
            }
        } else {
            container.setSecurityScore(100);
        }

        logEvent(containerId, "SCAN_COMPLETED", "Vulnerability scan completed");
    }

    private List<Vulnerability> performVulnerabilityScan(ContainerProfile container) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();

        vulnerabilities.add(new Vulnerability("CVE-2024-0001", "CRITICAL", "Remote code execution in libssl",
            "Upgrade to version 1.1.1k"));
        vulnerabilities.add(new Vulnerability("CVE-2024-0002", "HIGH", "Privilege escalation in kernel",
            "Apply security patch"));
        vulnerabilities.add(new Vulnerability("CVE-2024-0003", "MEDIUM", "Information disclosure in logging",
            "Disable detailed logging"));

        return vulnerabilities;
    }

    public void monitorContainer(String containerId) {
        ContainerProfile container = containers.get(containerId);
        if (container == null) return;

        container.incrementMonitoringCount();

        if (container.getMonitoringCount() % 100 == 0) {
            checkContainerBehavior(container);
        }

        logEvent(containerId, "MONITORED", "Container behavior monitored");
    }

    private void checkContainerBehavior(ContainerProfile container) {
        if (container.getCpuUsage() > 90) {
            triggerAlert(container.getContainerId(), "HIGH_CPU", "Abnormal CPU usage detected");
        }

        if (container.getMemoryUsage() > 90) {
            triggerAlert(container.getContainerId(), "HIGH_MEMORY", "Abnormal memory usage detected");
        }

        if (container.getNetworkConnections() > 1000) {
            triggerAlert(container.getContainerId(), "HIGH_CONNECTIONS", "Abnormal network activity");
        }

        if (container.hasSuspiciousProcess()) {
            triggerAlert(container.getContainerId(), "SUSPICIOUS_PROCESS", "Suspicious process detected");
            threatsBlocked.incrementAndGet();
        }
    }

    public void enforceContainerPolicy(String containerId) {
        ContainerProfile container = containers.get(containerId);
        if (container == null) return;

        if (container.getSecurityScore() < 50) {
            container.setStatus("ISOLATED");
            logEvent(containerId, "ISOLATED", "Container isolated due to low security score");
            logger.warn("Container {} isolated due to security score: {}", containerId, container.getSecurityScore());
        }

        if (container.getVulnerabilities().stream().anyMatch(v -> v.getSeverity().equals("CRITICAL"))) {
            container.setStatus("QUARANTINED");
            logEvent(containerId, "QUARANTINED", "Container quarantined due to critical vulnerability");
            logger.warn("Container {} quarantined due to critical vulnerabilities", containerId);
        }
    }

    public Map<String, Object> getContainerSecurityStats(String containerId) {
        Map<String, Object> stats = new HashMap<>();
        ContainerProfile container = containers.get(containerId);

        if (container == null) {
            stats.put("error", "Container not found");
            return stats;
        }

        stats.put("containerId", container.getContainerId());
        stats.put("imageName", container.getImageName());
        stats.put("securityScore", container.getSecurityScore());
        stats.put("status", container.getStatus());
        stats.put("vulnerabilities", container.getVulnerabilities().size());
        stats.put("lastScan", container.getLastScanTime());

        return stats;
    }

    public Map<String, Object> getStats() {
        Map<String, Object> stats = new HashMap<>();
        stats.put("totalContainersScanned", totalContainersScanned.get());
        stats.put("vulnerabilitiesFound", vulnerabilitiesFound.get());
        stats.put("threatsBlocked", threatsBlocked.get());
        stats.put("activeContainers", containers.size());
        stats.put("scanningEnabled", scanningEnabled);

        long criticalVulns = 0;
        long highVulns = 0;
        for (ContainerProfile container : containers.values()) {
            for (Vulnerability vuln : container.getVulnerabilities()) {
                if (vuln.getSeverity().equals("CRITICAL")) criticalVulns++;
                if (vuln.getSeverity().equals("HIGH")) highVulns++;
            }
        }
        stats.put("criticalVulnerabilities", criticalVulns);
        stats.put("highVulnerabilities", highVulns);

        return stats;
    }

    public List<SecurityAlert> getAlerts(int limit) {
        List<SecurityAlert> alerts = new ArrayList<>();
        int count = 0;
        for (SecurityAlert alert : alertQueue) {
            if (count++ >= limit) break;
            alerts.add(alert);
        }
        return alerts;
    }

    private void triggerAlert(String containerId, String type, String message) {
        SecurityAlert alert = new SecurityAlert(containerId, type, message, LocalDateTime.now());
        alertQueue.offer(alert);
        if (alertQueue.size() > 1000) {
            alertQueue.poll();
        }
        logger.warn("Container Security Alert [{}]: {} - {}", type, containerId, message);
    }

    private void logEvent(String containerId, String action, String details) {
        ContainerEvent event = new ContainerEvent(containerId, action, details, LocalDateTime.now());
        List<ContainerEvent> history = eventHistory.computeIfAbsent(containerId, k -> new ArrayList<>());
        history.add(event);
        if (history.size() > MAX_EVENTS) {
            history.remove(0);
        }
    }

    public void enableScanning() {
        scanningEnabled = true;
        logger.info("Container security scanning enabled");
    }

    public void disableScanning() {
        scanningEnabled = false;
        logger.info("Container security scanning disabled");
    }

    public static class ContainerProfile {
        private final String containerId;
        private final String imageName;
        private volatile String status;
        private volatile int securityScore;
        private volatile LocalDateTime lastScanTime;
        private volatile int monitoringCount;
        private volatile double cpuUsage;
        private volatile double memoryUsage;
        private volatile int networkConnections;
        private volatile boolean suspiciousProcess;
        private List<Vulnerability> vulnerabilities;

        public ContainerProfile(String containerId, String imageName, String status) {
            this.containerId = containerId;
            this.imageName = imageName;
            this.status = status;
            this.securityScore = 100;
            this.vulnerabilities = new ArrayList<>();
        }

        public void incrementMonitoringCount() { monitoringCount++; }

        public String getContainerId() { return containerId; }
        public String getImageName() { return imageName; }
        public String getStatus() { return status; }
        public void setStatus(String status) { this.status = status; }
        public int getSecurityScore() { return securityScore; }
        public void setSecurityScore(int securityScore) { this.securityScore = securityScore; }
        public LocalDateTime getLastScanTime() { return lastScanTime; }
        public void setLastScanTime(LocalDateTime lastScanTime) { this.lastScanTime = lastScanTime; }
        public int getMonitoringCount() { return monitoringCount; }
        public double getCpuUsage() { return cpuUsage; }
        public void setCpuUsage(double cpuUsage) { this.cpuUsage = cpuUsage; }
        public double getMemoryUsage() { return memoryUsage; }
        public void setMemoryUsage(double memoryUsage) { this.memoryUsage = memoryUsage; }
        public int getNetworkConnections() { return networkConnections; }
        public void setNetworkConnections(int networkConnections) { this.networkConnections = networkConnections; }
        public boolean hasSuspiciousProcess() { return suspiciousProcess; }
        public void setSuspiciousProcess(boolean suspiciousProcess) { this.suspiciousProcess = suspiciousProcess; }
        public List<Vulnerability> getVulnerabilities() { return vulnerabilities; }
        public void setVulnerabilities(List<Vulnerability> vulnerabilities) { this.vulnerabilities = vulnerabilities; }
    }

    public static class ContainerImage {
        private final String imageName;
        private final String version;
        private volatile int securityScore;
        private List<Vulnerability> vulnerabilities;

        public ContainerImage(String imageName, String version) {
            this.imageName = imageName;
            this.version = version;
            this.securityScore = 100;
            this.vulnerabilities = new ArrayList<>();
        }

        public String getImageName() { return imageName; }
        public String getVersion() { return version; }
        public int getSecurityScore() { return securityScore; }
        public void setSecurityScore(int securityScore) { this.securityScore = securityScore; }
        public List<Vulnerability> getVulnerabilities() { return vulnerabilities; }
        public void setVulnerabilities(List<Vulnerability> vulnerabilities) { this.vulnerabilities = vulnerabilities; }
    }

    public static class Vulnerability {
        private final String id;
        private final String severity;
        private final String description;
        private final String remediation;

        public Vulnerability(String id, String severity, String description, String remediation) {
            this.id = id;
            this.severity = severity;
            this.description = description;
            this.remediation = remediation;
        }

        public String getId() { return id; }
        public String getSeverity() { return severity; }
        public String getDescription() { return description; }
        public String getRemediation() { return remediation; }
    }

    public static class ContainerEvent {
        private final String containerId;
        private final String action;
        private final String details;
        private final LocalDateTime timestamp;

        public ContainerEvent(String containerId, String action, String details, LocalDateTime timestamp) {
            this.containerId = containerId;
            this.action = action;
            this.details = details;
            this.timestamp = timestamp;
        }

        public String getContainerId() { return containerId; }
        public String getAction() { return action; }
        public String getDetails() { return details; }
        public LocalDateTime getTimestamp() { return timestamp; }
    }

    public static class SecurityAlert {
        private final String containerId;
        private final String type;
        private final String message;
        private final LocalDateTime timestamp;

        public SecurityAlert(String containerId, String type, String message, LocalDateTime timestamp) {
            this.containerId = containerId;
            this.type = type;
            this.message = message;
            this.timestamp = timestamp;
        }

        public String getContainerId() { return containerId; }
        public String getType() { return type; }
        public String getMessage() { return message; }
        public LocalDateTime getTimestamp() { return timestamp; }
    }
}
