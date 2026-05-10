package com.aluer.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.atomic.AtomicLong;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.regex.Pattern;
import java.util.regex.Matcher;
import java.security.MessageDigest;

@Component
public class IntrusionPreventionSystem {
    private static final Logger logger = LoggerFactory.getLogger(IntrusionPreventionSystem.class);

    private final HostEnforcementService hostEnforcementService;
    private final CloudflareIntegrationService cloudflareIntegrationService;
    private final Map<String, IPSRule> rules = new ConcurrentHashMap<>();
    private final Map<String, BlockedEntry> blockedIPs = new ConcurrentHashMap<>();
    private final Queue<IPSAlert> alertQueue = new ConcurrentLinkedQueue<>();
    private final Map<String, ConnectionTracker> connectionTrackers = new ConcurrentHashMap<>();
    private final AtomicLong totalPacketsProcessed = new AtomicLong(0);
    private final AtomicLong totalPacketsBlocked = new AtomicLong(0);
    private final AtomicLong totalAttacksPrevented = new AtomicLong(0);

    private static final int BLOCK_DURATION_MINUTES = 60;
    private static final int MAX_CONNECTIONS_PER_MINUTE = 100;
    private static final int PACKET_RATE_LIMIT = 1000;
    private static final DateTimeFormatter DATE_FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    public IntrusionPreventionSystem() {
        this(new HostEnforcementService(), new CloudflareIntegrationService());
    }

    @Autowired
    public IntrusionPreventionSystem(HostEnforcementService hostEnforcementService,
                                     CloudflareIntegrationService cloudflareIntegrationService) {
        this.hostEnforcementService = hostEnforcementService;
        this.cloudflareIntegrationService = cloudflareIntegrationService;
        initializeDefaultRules();
        logger.info("Intrusion Prevention System initialized");
    }

    private void initializeDefaultRules() {
        addRule("BLOCK_SSH_BRUTE_FORCE", "HIGH", "TCP", 22,
            "(\\w+:){1,100}Failed password", "SSH brute force attack");

        addRule("BLOCK_TELNET_BRUTE_FORCE", "HIGH", "TCP", 23,
            "(failed|invalid).*login", "Telnet brute force attack");

        addRule("BLOCK_FTP_BRUTE_FORCE", "HIGH", "TCP", 21,
            "530 Login authentication failed", "FTP brute force attack");

        addRule("BLOCK_MYSQL_BRUTE_FORCE", "HIGH", "TCP", 3306,
            "Access denied for user", "MySQL brute force attack");

        addRule("BLOCK_PORT_SCAN", "MEDIUM", "TCP", 0,
            "port.*scan", "Port scan detected");

        addRule("BLOCK_SYN_FLOOD", "HIGH", "TCP", 0,
            "SYN.*SYN.*SYN", "SYN flood attack");

        addRule("BLOCK_UDP_FLOOD", "HIGH", "UDP", 0,
            "udp.*flood", "UDP flood attack");

        addRule("BLOCK_ICMP_FLOOD", "MEDIUM", "ICMP", 0,
            "icmp.*flood", "ICMP flood attack");

        addRule("BLOCK_DNS_AMPLIFICATION", "HIGH", "UDP", 53,
            "dns.*amplification", "DNS amplification attack");

        addRule("BLOCK_SQL_INJECTION", "HIGH", "TCP", 0,
            "(union|select|insert|update|delete).*(from|where)", "SQL injection attempt");

        addRule("BLOCK_XSS_ATTACK", "HIGH", "TCP", 0,
            "<script|javascript:|onerror=", "Cross-site scripting attempt");

        addRule("BLOCK_DIRECTORY_TRAVERSAL", "MEDIUM", "TCP", 0,
            "(\\.\\./|\\.\\.\\\\)", "Directory traversal attempt");

        logger.info("Initialized {} IPS rules", rules.size());
    }

    public void addRule(String name, String severity, String protocol, int port, String pattern, String description) {
        IPSRule rule = new IPSRule(name, severity, protocol, port, pattern, description);
        rules.put(name, rule);
        logger.info("Added IPS rule: {}", name);
    }

    public IPSResult processPacket(String sourceIP, String destIP, int sourcePort, int destPort,
                                 String protocol, byte[] payload) {
        IPSResult result = new IPSResult();
        result.setSourceIP(sourceIP);
        result.setDestIP(destIP);
        result.setSourcePort(sourcePort);
        result.setDestPort(destPort);
        result.setProtocol(protocol);
        result.setTimestamp(LocalDateTime.now());

        totalPacketsProcessed.incrementAndGet();

        if (isBlocked(sourceIP)) {
            result.setBlocked(true);
            result.setReason("IP is already blocked");
            totalPacketsBlocked.incrementAndGet();
            return result;
        }

        if (checkRateLimit(sourceIP)) {
            blockIP(sourceIP, "Rate limit exceeded", 30);
            result.setBlocked(true);
            result.setReason("Rate limit exceeded");
            totalPacketsBlocked.incrementAndGet();
            totalAttacksPrevented.incrementAndGet();
            return result;
        }

        updateConnectionTracker(sourceIP, destIP, destPort, protocol);

        for (IPSRule rule : rules.values()) {
            if (!rule.isEnabled()) continue;

            if (!rule.matchesProtocol(protocol)) continue;
            if (rule.getPort() != 0 && rule.getPort() != destPort) continue;

            if (payload != null && rule.matchesPayload(new String(payload))) {
                result.addMatchedRule(rule.getName());
                result.setThreatDetected(true);

                if ("HIGH".equals(rule.getSeverity())) {
                    blockIP(sourceIP, rule.getDescription(), BLOCK_DURATION_MINUTES);
                    result.setBlocked(true);
                    result.setReason("Blocked: " + rule.getDescription());
                    totalPacketsBlocked.incrementAndGet();
                    totalAttacksPrevented.incrementAndGet();
                    triggerAlert(sourceIP, destIP, rule);
                } else if ("MEDIUM".equals(rule.getSeverity())) {
                    result.setWarning("Medium severity threat detected: " + rule.getDescription());
                    triggerAlert(sourceIP, destIP, rule);
                }
            }
        }

        return result;
    }

    private boolean isBlocked(String ip) {
        BlockedEntry entry = blockedIPs.get(ip);
        if (entry == null) return false;

        if (entry.isExpired()) {
            blockedIPs.remove(ip);
            return false;
        }

        return true;
    }

    private void blockIP(String ip, String reason, int durationMinutes) {
        BlockedEntry entry = new BlockedEntry(ip, reason, durationMinutes);
        blockedIPs.put(ip, entry);
        hostEnforcementService.blockIp(ip, reason, durationMinutes);
        logger.warn("Blocked IP: {} for {} minutes - Reason: {}", ip, durationMinutes, reason);
    }

    public void unblockIP(String ip) {
        blockedIPs.remove(ip);
        hostEnforcementService.releaseIp(ip, "IPS unblock");
        logger.info("Unblocked IP: {}", ip);
    }

    public HostEnforcementService.EnforcementActionResult enforceDecision(String ip, int severity, String reason, boolean challengeEdge) {
        if (severity >= 90) {
            HostEnforcementService.EnforcementActionResult local = hostEnforcementService.blockIp(ip, reason, BLOCK_DURATION_MINUTES);
            if (challengeEdge) {
                cloudflareIntegrationService.applyChallenge(ip, reason);
            } else {
                cloudflareIntegrationService.applyBlock(ip, reason);
            }
            return local;
        }
        return hostEnforcementService.rateLimitIp(ip,
            hostEnforcementService.getStats().get("managedRules") instanceof Number ? 60 : 60,
            reason);
    }

    private boolean checkRateLimit(String ip) {
        ConnectionTracker tracker = connectionTrackers.get(ip);
        if (tracker == null) return false;

        return tracker.getPacketsPerMinute() > PACKET_RATE_LIMIT;
    }

    private void updateConnectionTracker(String sourceIP, String destIP, int destPort, String protocol) {
        ConnectionTracker tracker = connectionTrackers.computeIfAbsent(sourceIP, k -> new ConnectionTracker(sourceIP));
        tracker.recordConnection(destIP, destPort, protocol);
    }

    private void triggerAlert(String sourceIP, String destIP, IPSRule rule) {
        IPSAlert alert = new IPSAlert(
            sourceIP,
            destIP,
            rule.getName(),
            rule.getSeverity(),
            rule.getDescription(),
            LocalDateTime.now()
        );
        alertQueue.offer(alert);

        if (alertQueue.size() > 1000) {
            alertQueue.poll();
        }
    }

    public void enableRule(String ruleName) {
        IPSRule rule = rules.get(ruleName);
        if (rule != null) {
            rule.setEnabled(true);
            logger.info("Enabled IPS rule: {}", ruleName);
        }
    }

    public void disableRule(String ruleName) {
        IPSRule rule = rules.get(ruleName);
        if (rule != null) {
            rule.setEnabled(false);
            logger.info("Disabled IPS rule: {}", ruleName);
        }
    }

    public void addBlockedIP(String ip, String reason, int durationMinutes) {
        blockIP(ip, reason, durationMinutes);
    }

    public Map<String, Object> getStats() {
        Map<String, Object> stats = new HashMap<>();
        stats.put("totalPacketsProcessed", totalPacketsProcessed.get());
        stats.put("totalPacketsBlocked", totalPacketsBlocked.get());
        stats.put("totalAttacksPrevented", totalAttacksPrevented.get());
        stats.put("activeBlocks", blockedIPs.size());
        stats.put("rulesLoaded", rules.size());
        stats.put("activeTrackers", connectionTrackers.size());

        long highSeverity = rules.values().stream()
            .filter(r -> "HIGH".equals(r.getSeverity()) && r.isEnabled())
            .count();
        stats.put("highSeverityRules", highSeverity);

        return stats;
    }

    public List<BlockedEntry> getBlockedIPs() {
        return new ArrayList<>(blockedIPs.values());
    }

    public List<IPSAlert> getRecentAlerts(int limit) {
        List<IPSAlert> alerts = new ArrayList<>();
        int count = 0;
        for (IPSAlert alert : alertQueue) {
            if (count++ >= limit) break;
            alerts.add(alert);
        }
        return alerts;
    }

    public Map<String, ConnectionTracker> getConnectionTrackers() {
        return new HashMap<>(connectionTrackers);
    }

    public void cleanupExpiredBlocks() {
        List<String> expired = new ArrayList<>();
        for (Map.Entry<String, BlockedEntry> entry : blockedIPs.entrySet()) {
            if (entry.getValue().isExpired()) {
                expired.add(entry.getKey());
            }
        }
        for (String ip : expired) {
            blockedIPs.remove(ip);
        }

        if (!expired.isEmpty()) {
            logger.info("Cleaned up {} expired blocks", expired.size());
        }
    }

    public static class IPSRule {
        private final String name;
        private final String severity;
        private final String protocol;
        private final int port;
        private final Pattern pattern;
        private final String description;
        private volatile boolean enabled = true;

        public IPSRule(String name, String severity, String protocol, int port, String pattern, String description) {
            this.name = name;
            this.severity = severity;
            this.protocol = protocol;
            this.port = port;
            this.pattern = Pattern.compile(pattern, Pattern.CASE_INSENSITIVE);
            this.description = description;
        }

        public boolean matchesProtocol(String protocol) {
            return this.protocol.equalsIgnoreCase(protocol) || this.protocol.equalsIgnoreCase("ALL");
        }

        public boolean matchesPayload(String payload) {
            if (payload == null || payload.isEmpty()) return false;
            return pattern.matcher(payload).find();
        }

        public String getName() { return name; }
        public String getSeverity() { return severity; }
        public String getProtocol() { return protocol; }
        public int getPort() { return port; }
        public Pattern getPattern() { return pattern; }
        public String getDescription() { return description; }
        public boolean isEnabled() { return enabled; }
        public void setEnabled(boolean enabled) { this.enabled = enabled; }
    }

    public static class BlockedEntry {
        private final String ip;
        private final String reason;
        private final long blockedAt;
        private final long expiresAt;

        public BlockedEntry(String ip, String reason, int durationMinutes) {
            this.ip = ip;
            this.reason = reason;
            this.blockedAt = System.currentTimeMillis();
            this.expiresAt = blockedAt + (durationMinutes * 60 * 1000L);
        }

        public boolean isExpired() {
            return System.currentTimeMillis() > expiresAt;
        }

        public String getIp() { return ip; }
        public String getReason() { return reason; }
        public long getBlockedAt() { return blockedAt; }
        public long getExpiresAt() { return expiresAt; }
    }

    public static class ConnectionTracker {
        private final String ip;
        private final Map<String, Integer> destConnections;
        private final AtomicLong totalPackets;
        private volatile long windowStart;
        private volatile long packetsInWindow;

        public ConnectionTracker(String ip) {
            this.ip = ip;
            this.destConnections = new ConcurrentHashMap<>();
            this.totalPackets = new AtomicLong(0);
            this.windowStart = System.currentTimeMillis();
            this.packetsInWindow = 0;
        }

        public synchronized void recordConnection(String destIP, int port, String protocol) {
            totalPackets.incrementAndGet();
            packetsInWindow++;

            String key = destIP + ":" + port;
            destConnections.merge(key, 1, Integer::sum);

            long now = System.currentTimeMillis();
            if (now - windowStart > 60000) {
                packetsInWindow = 0;
                windowStart = now;
            }
        }

        public long getPacketsPerMinute() {
            return packetsInWindow;
        }

        public String getIp() { return ip; }
        public long getTotalPackets() { return totalPackets.get(); }
        public Map<String, Integer> getDestConnections() { return destConnections; }
    }

    public static class IPSResult {
        private String sourceIP;
        private String destIP;
        private int sourcePort;
        private int destPort;
        private String protocol;
        private boolean blocked;
        private boolean threatDetected;
        private String reason;
        private String warning;
        private List<String> matchedRules;
        private LocalDateTime timestamp;

        public IPSResult() {
            this.matchedRules = new ArrayList<>();
        }

        public String getSourceIP() { return sourceIP; }
        public void setSourceIP(String sourceIP) { this.sourceIP = sourceIP; }
        public String getDestIP() { return destIP; }
        public void setDestIP(String destIP) { this.destIP = destIP; }
        public int getSourcePort() { return sourcePort; }
        public void setSourcePort(int sourcePort) { this.sourcePort = sourcePort; }
        public int getDestPort() { return destPort; }
        public void setDestPort(int destPort) { this.destPort = destPort; }
        public String getProtocol() { return protocol; }
        public void setProtocol(String protocol) { this.protocol = protocol; }
        public boolean isBlocked() { return blocked; }
        public void setBlocked(boolean blocked) { this.blocked = blocked; }
        public boolean isThreatDetected() { return threatDetected; }
        public void setThreatDetected(boolean threatDetected) { this.threatDetected = threatDetected; }
        public String getReason() { return reason; }
        public void setReason(String reason) { this.reason = reason; }
        public String getWarning() { return warning; }
        public void setWarning(String warning) { this.warning = warning; }
        public List<String> getMatchedRules() { return matchedRules; }
        public void addMatchedRule(String rule) { this.matchedRules.add(rule); }
        public LocalDateTime getTimestamp() { return timestamp; }
        public void setTimestamp(LocalDateTime timestamp) { this.timestamp = timestamp; }
    }

    public static class IPSAlert {
        private final String sourceIP;
        private final String destIP;
        private final String ruleName;
        private final String severity;
        private final String description;
        private final LocalDateTime timestamp;

        public IPSAlert(String sourceIP, String destIP, String ruleName, String severity, String description, LocalDateTime timestamp) {
            this.sourceIP = sourceIP;
            this.destIP = destIP;
            this.ruleName = ruleName;
            this.severity = severity;
            this.description = description;
            this.timestamp = timestamp;
        }

        public String getSourceIP() { return sourceIP; }
        public String getDestIP() { return destIP; }
        public String getRuleName() { return ruleName; }
        public String getSeverity() { return severity; }
        public String getDescription() { return description; }
        public LocalDateTime getTimestamp() { return timestamp; }
    }
}
