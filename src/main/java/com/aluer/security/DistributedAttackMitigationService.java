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
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

@Component
public class DistributedAttackMitigationService {
    private static final Logger logger = LoggerFactory.getLogger(DistributedAttackMitigationService.class);

    private final Map<String, AttackSignature> attackSignatures = new ConcurrentHashMap<>();
    private final Map<String, MitigationRule> mitigationRules = new ConcurrentHashMap<>();
    private final Map<String, AttackIncident> activeIncidents = new ConcurrentHashMap<>();
    private final Queue<MitigationEvent> eventLog = new ConcurrentLinkedQueue<>();
    private final Map<String, List<AttackVector>> attackVectors = new ConcurrentHashMap<>();
    private final AtomicLong totalAttacksDetected = new AtomicLong(0);
    private final AtomicLong totalAttacksMitigated = new AtomicLong(0);
    private final AtomicLong totalAttacksBlocked = new AtomicLong(0);

    private volatile boolean mitigationEnabled = true;
    private String currentDefenseLevel = "MEDIUM";
    private final ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(2);

    private static final int MAX_INCIDENTS = 1000;
    private static final int DEFENSE_LEVEL_HIGH_THRESHOLD = 100;
    private static final DateTimeFormatter DATE_FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    public DistributedAttackMitigationService() {
        initializeDefaultSignatures();
        initializeDefaultRules();
        startAutoMitigation();
        logger.info("Distributed Attack Mitigation Service initialized");
    }

    private void initializeDefaultSignatures() {
        addSignature("SYN_FLOOD", "DDoS", "SYN.*SYN.*SYN", 80, "SYN flood attack");
        addSignature("UDP_FLOOD", "DDoS", "UDP.*flood", 90, "UDP flood attack");
        addSignature("ICMP_FLOOD", "DDoS", "ICMP.*flood", 70, "ICMP flood attack");
        addSignature("HTTP_FLOOD", "DDoS", "GET.*repeated|POST.*repeated", 85, "HTTP flood attack");
        addSignature("DNS_AMPLIFICATION", "DDoS", "DNS.*amplification", 95, "DNS amplification attack");
        addSignature("NTP_AMPLIFICATION", "DDoS", "NTP.*amplification", 95, "NTP amplification attack");
        addSignature("SSDP_AMPLIFICATION", "DDoS", "SSDP.*amplification", 90, "SSDP amplification attack");
        addSignature("SLOWLORIS", "DDoS", "slow.*loris|partial.*request", 75, "Slowloris attack");
        addSignature("HTTP_PIPELINING", "DDoS", "pipelining.*abuse", 70, "HTTP pipelining attack");
        addSignature("BOTNET_ACTIVITY", "DDoS", "botnet.*detected", 90, "Botnet activity detected");
        addSignature("BRUTE_FORCE_SSH", "BruteForce", "SSH.*failed.*repeated", 85, "SSH brute force attack");
        addSignature("BRUTE_FORCE_FTP", "BruteForce", "FTP.*failed.*repeated", 85, "FTP brute force attack");
        addSignature("BRUTE_FORCE_RCON", "BruteForce", "RCON.*failed.*repeated", 90, "RCON brute force attack");
        addSignature("SQL_INJECTION", "Injection", "union.*select|insert.*into", 95, "SQL injection attack");
        addSignature("XSS_ATTACK", "Injection", "<script|javascript:", 90, "Cross-site scripting attack");
        addSignature("CSRF_ATTACK", "Injection", "CSRF.*token", 80, "CSRF attack");
        addSignature("COMMAND_INJECTION", "Injection", "cmd\\.exe|/bin/bash", 95, "Command injection attack");
        addSignature("PATH_TRAVERSAL", "Injection", "\\.\\./|\\.\\.\\\\", 85, "Path traversal attack");
        addSignature("DISTRIBUTED_SCAN", "Reconnaissance", "port.*scan.*distributed", 75, "Distributed port scan");
        addSignature("CRAWLER_ABUSE", "Reconnaissance", "crawler.*abuse|scraping", 60, "Web crawler abuse");

        logger.info("Initialized {} attack signatures", attackSignatures.size());
    }

    private void initializeDefaultRules() {
        addMitigationRule("BLOCK_SYN_FLOOD", "SYN_FLOOD", "BLOCK", 50, 60);
        addMitigationRule("RATE_LIMIT_UDP", "UDP_FLOOD", "RATE_LIMIT", 100, 30);
        addMitigationRule("BLOCK_ICMP", "ICMP_FLOOD", "BLOCK", 100, 60);
        addMitigationRule("RATE_LIMIT_HTTP", "HTTP_FLOOD", "RATE_LIMIT", 50, 10);
        addMitigationRule("DROP_DNS_AMP", "DNS_AMPLIFICATION", "BLOCK", 100, 300);
        addMitigationRule("BLOCK_NTP_AMP", "NTP_AMPLIFICATION", "BLOCK", 100, 300);
        addMitigationRule("THROTTLE_SLOWLORIS", "SLOWLORIS", "THROTTLE", 30, 60);
        addMitigationRule("BLOCK_BOTNET", "BOTNET_ACTIVITY", "BLOCK", 100, 600);
        addMitigationRule("BLOCK_SSH_BRUTE", "BRUTE_FORCE_SSH", "BLOCK", 10, 3600);
        addMitigationRule("BLOCK_FTP_BRUTE", "BRUTE_FORCE_FTP", "BLOCK", 10, 3600);
        addMitigationRule("BLOCK_RCON_BRUTE", "BRUTE_FORCE_RCON", "BLOCK", 5, 3600);
        addMitigationRule("SANITIZE_SQL", "SQL_INJECTION", "SANITIZE", 100, 0);
        addMitigationRule("SANITIZE_XSS", "XSS_ATTACK", "SANITIZE", 100, 0);
        addMitigationRule("BLOCK_CMD_INJECTION", "COMMAND_INJECTION", "BLOCK", 100, 0);
        addMitigationRule("BLOCK_TRAVERSAL", "PATH_TRAVERSAL", "BLOCK", 100, 0);

        logger.info("Initialized {} mitigation rules", mitigationRules.size());
    }

    private void addSignature(String id, String type, String pattern, int severity, String description) {
        AttackSignature sig = new AttackSignature(id, type, pattern, severity, description);
        attackSignatures.put(id, sig);
    }

    private void addMitigationRule(String name, String signatureId, String action, int threshold, int duration) {
        MitigationRule rule = new MitigationRule(name, signatureId, action, threshold, duration);
        mitigationRules.put(name, rule);
    }

    public void analyzeTraffic(String sourceIP, Map<String, Object> trafficData) {
        if (!mitigationEnabled) return;

        for (AttackSignature signature : attackSignatures.values()) {
            if (matchesSignature(trafficData, signature)) {
                handleAttackDetection(sourceIP, signature, trafficData);
            }
        }

        updateDefenseLevel();
    }

    private boolean matchesSignature(Map<String, Object> trafficData, AttackSignature signature) {
        String pattern = signature.getPattern();
        
        if (trafficData.containsKey("packetPattern")) {
            String packetPattern = (String) trafficData.get("packetPattern");
            if (packetPattern != null && packetPattern.matches(pattern)) {
                return true;
            }
        }

        if (trafficData.containsKey("requestPattern")) {
            String requestPattern = (String) trafficData.get("requestPattern");
            if (requestPattern != null && requestPattern.matches(pattern)) {
                return true;
            }
        }

        if (trafficData.containsKey("flags")) {
            String flags = (String) trafficData.get("flags");
            if (flags != null && flags.matches(pattern)) {
                return true;
            }
        }

        return false;
    }

    private void handleAttackDetection(String sourceIP, AttackSignature signature, Map<String, Object> trafficData) {
        totalAttacksDetected.incrementAndGet();

        String incidentId = UUID.randomUUID().toString();
        AttackIncident incident = new AttackIncident(
            incidentId,
            sourceIP,
            signature.getId(),
            signature.getType(),
            signature.getSeverity(),
            trafficData,
            LocalDateTime.now()
        );

        activeIncidents.put(incidentId, incident);

        List<AttackVector> vectors = attackVectors.computeIfAbsent(sourceIP, k -> new ArrayList<>());
        vectors.add(new AttackVector(signature.getId(), System.currentTimeMillis()));

        applyMitigation(sourceIP, signature);

        if (activeIncidents.size() > MAX_INCIDENTS) {
            String firstKey = activeIncidents.keySet().iterator().next();
            activeIncidents.remove(firstKey);
        }

        logger.warn("Attack detected from {}: {} [{}]", sourceIP, signature.getDescription(), signature.getType());
    }

    private void applyMitigation(String sourceIP, AttackSignature signature) {
        for (MitigationRule rule : mitigationRules.values()) {
            if (rule.getSignatureId().equals(signature.getId())) {
                switch (rule.getAction()) {
                    case "BLOCK":
                        applyBlock(sourceIP, rule.getDuration());
                        totalAttacksBlocked.incrementAndGet();
                        logEvent(sourceIP, signature.getId(), "BLOCKED", "Blocked by rule: " + rule.getName());
                        break;

                    case "RATE_LIMIT":
                        applyRateLimit(sourceIP, rule.getThreshold());
                        logEvent(sourceIP, signature.getId(), "RATE_LIMITED", "Rate limited by rule: " + rule.getName());
                        break;

                    case "SANITIZE":
                        applySanitization(sourceIP);
                        logEvent(sourceIP, signature.getId(), "SANITIZED", "Request sanitized");
                        break;

                    case "THROTTLE":
                        applyThrottling(sourceIP, rule.getThreshold());
                        logEvent(sourceIP, signature.getId(), "THROTTLED", "Connection throttled");
                        break;
                }

                totalAttacksMitigated.incrementAndGet();
                logger.info("Applied mitigation for {}: {}", sourceIP, rule.getAction());
                break;
            }
        }
    }

    private void applyBlock(String sourceIP, int duration) {
        logger.info("Blocking IP: {} for {} seconds", sourceIP, duration);
    }

    private void applyRateLimit(String sourceIP, int threshold) {
        logger.info("Applying rate limit to IP: {} (threshold: {})", sourceIP, threshold);
    }

    private void applySanitization(String sourceIP) {
        logger.info("Applying request sanitization for IP: {}", sourceIP);
    }

    private void applyThrottling(String sourceIP, int threshold) {
        logger.info("Throttling connection for IP: {} (threshold: {})", sourceIP, threshold);
    }

    private void updateDefenseLevel() {
        int activeAttackCount = activeIncidents.size();

        if (activeAttackCount > DEFENSE_LEVEL_HIGH_THRESHOLD * 2) {
            if (!"HIGH".equals(currentDefenseLevel)) {
                currentDefenseLevel = "HIGH";
                logger.warn("Defense level raised to HIGH - {} active attacks", activeAttackCount);
            }
        } else if (activeAttackCount > DEFENSE_LEVEL_HIGH_THRESHOLD) {
            if (!"MEDIUM".equals(currentDefenseLevel)) {
                currentDefenseLevel = "MEDIUM";
                logger.info("Defense level raised to MEDIUM - {} active attacks", activeAttackCount);
            }
        } else if (activeAttackCount < DEFENSE_LEVEL_HIGH_THRESHOLD / 2) {
            if (!"LOW".equals(currentDefenseLevel)) {
                currentDefenseLevel = "LOW";
                logger.info("Defense level lowered to LOW - {} active attacks", activeAttackCount);
            }
        }
    }

    private void startAutoMitigation() {
        scheduler.scheduleAtFixedRate(() -> {
            cleanupOldIncidents();
            analyzeAttackPatterns();
            generateDefenseRecommendations();
        }, 10, 10, TimeUnit.SECONDS);
    }

    private void cleanupOldIncidents() {
        long cutoffTime = System.currentTimeMillis() - (3600000);
        List<String> toRemove = new ArrayList<>();

        for (Map.Entry<String, AttackIncident> entry : activeIncidents.entrySet()) {
            if (entry.getValue().getDetectedAt().isBefore(LocalDateTime.now().minusHours(1))) {
                toRemove.add(entry.getKey());
            }
        }

        for (String id : toRemove) {
            activeIncidents.remove(id);
        }

        for (Map.Entry<String, List<AttackVector>> entry : attackVectors.entrySet()) {
            long recentCutoff = System.currentTimeMillis() - (300000);
            entry.getValue().removeIf(v -> v.getTimestamp() < recentCutoff);
        }
    }

    private void analyzeAttackPatterns() {
        for (Map.Entry<String, List<AttackVector>> entry : attackVectors.entrySet()) {
            List<AttackVector> vectors = entry.getValue();
            if (vectors.size() > 10) {
                Map<String, Long> typeCounts = new HashMap<>();
                for (AttackVector v : vectors) {
                    typeCounts.merge(v.getSignatureId(), 1L, Long::sum);
                }

                for (Map.Entry<String, Long> typeEntry : typeCounts.entrySet()) {
                    if (typeEntry.getValue() > 5) {
                        logger.warn("Attack pattern detected from {}: {} attacks of type {} in 5 minutes",
                            entry.getKey(), typeEntry.getValue(), typeEntry.getKey());
                    }
                }
            }
        }
    }

    private void generateDefenseRecommendations() {
        if (activeIncidents.size() > 50) {
            logger.warn("HIGH ATTACK VOLUME RECOMMENDATION: Consider enabling emergency defense mode");
        }

        Map<String, Long> typeCounts = new HashMap<>();
        for (AttackIncident incident : activeIncidents.values()) {
            typeCounts.merge(incident.getAttackType(), 1L, Long::sum);
        }

        for (Map.Entry<String, Long> entry : typeCounts.entrySet()) {
            if (entry.getValue() > 20) {
                logger.warn("DEFENSE RECOMMENDATION: High volume of {} attacks detected ({}), consider additional mitigation",
                    entry.getKey(), entry.getValue());
            }
        }
    }

    public Map<String, Object> getStats() {
        Map<String, Object> stats = new HashMap<>();
        stats.put("mitigationEnabled", mitigationEnabled);
        stats.put("defenseLevel", currentDefenseLevel);
        stats.put("totalAttacksDetected", totalAttacksDetected.get());
        stats.put("totalAttacksMitigated", totalAttacksMitigated.get());
        stats.put("totalAttacksBlocked", totalAttacksBlocked.get());
        stats.put("activeIncidents", activeIncidents.size());
        stats.put("attackSignatures", attackSignatures.size());
        stats.put("mitigationRules", mitigationRules.size());

        double mitigationRate = totalAttacksDetected.get() > 0 ?
            totalAttacksMitigated.get() * 100.0 / totalAttacksDetected.get() : 0;
        stats.put("mitigationRate", String.format("%.2f%%", mitigationRate));

        return stats;
    }

    public List<AttackIncident> getActiveIncidents(int limit) {
        List<AttackIncident> incidents = new ArrayList<>();
        int count = 0;
        for (AttackIncident incident : activeIncidents.values()) {
            if (count++ >= limit) break;
            incidents.add(incident);
        }
        return incidents;
    }

    public Map<String, Long> getAttackTypeDistribution() {
        Map<String, Long> distribution = new HashMap<>();
        for (AttackIncident incident : activeIncidents.values()) {
            distribution.merge(incident.getAttackType(), 1L, Long::sum);
        }
        return distribution;
    }

    public void enableMitigation() {
        mitigationEnabled = true;
        logger.info("Attack mitigation enabled");
    }

    public void disableMitigation() {
        mitigationEnabled = false;
        logger.info("Attack mitigation disabled");
    }

    public void setDefenseLevel(String level) {
        this.currentDefenseLevel = level;
        logger.info("Defense level set to: {}", level);
    }

    private void logEvent(String sourceIP, String signatureId, String action, String details) {
        MitigationEvent event = new MitigationEvent(sourceIP, signatureId, action, details, LocalDateTime.now());
        eventLog.offer(event);
        if (eventLog.size() > 5000) {
            eventLog.poll();
        }
    }

    public List<MitigationEvent> getRecentEvents(int limit) {
        List<MitigationEvent> events = new ArrayList<>();
        int count = 0;
        for (MitigationEvent event : eventLog) {
            if (count++ >= limit) break;
            events.add(event);
        }
        return events;
    }

    public static class AttackSignature {
        private final String id;
        private final String type;
        private final String pattern;
        private final int severity;
        private final String description;

        public AttackSignature(String id, String type, String pattern, int severity, String description) {
            this.id = id;
            this.type = type;
            this.pattern = pattern;
            this.severity = severity;
            this.description = description;
        }

        public String getId() { return id; }
        public String getType() { return type; }
        public String getPattern() { return pattern; }
        public int getSeverity() { return severity; }
        public String getDescription() { return description; }
    }

    public static class MitigationRule {
        private final String name;
        private final String signatureId;
        private final String action;
        private final int threshold;
        private final int duration;

        public MitigationRule(String name, String signatureId, String action, int threshold, int duration) {
            this.name = name;
            this.signatureId = signatureId;
            this.action = action;
            this.threshold = threshold;
            this.duration = duration;
        }

        public String getName() { return name; }
        public String getSignatureId() { return signatureId; }
        public String getAction() { return action; }
        public int getThreshold() { return threshold; }
        public int getDuration() { return duration; }
    }

    public static class AttackIncident {
        private final String incidentId;
        private final String sourceIP;
        private final String signatureId;
        private final String attackType;
        private final int severity;
        private final Map<String, Object> evidence;
        private final LocalDateTime detectedAt;

        public AttackIncident(String incidentId, String sourceIP, String signatureId, String attackType,
                           int severity, Map<String, Object> evidence, LocalDateTime detectedAt) {
            this.incidentId = incidentId;
            this.sourceIP = sourceIP;
            this.signatureId = signatureId;
            this.attackType = attackType;
            this.severity = severity;
            this.evidence = evidence;
            this.detectedAt = detectedAt;
        }

        public String getIncidentId() { return incidentId; }
        public String getSourceIP() { return sourceIP; }
        public String getSignatureId() { return signatureId; }
        public String getAttackType() { return attackType; }
        public int getSeverity() { return severity; }
        public Map<String, Object> getEvidence() { return evidence; }
        public LocalDateTime getDetectedAt() { return detectedAt; }
    }

    public static class AttackVector {
        private final String signatureId;
        private final long timestamp;

        public AttackVector(String signatureId, long timestamp) {
            this.signatureId = signatureId;
            this.timestamp = timestamp;
        }

        public String getSignatureId() { return signatureId; }
        public long getTimestamp() { return timestamp; }
    }

    public static class MitigationEvent {
        private final String sourceIP;
        private final String signatureId;
        private final String action;
        private final String details;
        private final LocalDateTime timestamp;

        public MitigationEvent(String sourceIP, String signatureId, String action, String details, LocalDateTime timestamp) {
            this.sourceIP = sourceIP;
            this.signatureId = signatureId;
            this.action = action;
            this.details = details;
            this.timestamp = timestamp;
        }

        public String getSourceIP() { return sourceIP; }
        public String getSignatureId() { return signatureId; }
        public String getAction() { return action; }
        public String getDetails() { return details; }
        public LocalDateTime getTimestamp() { return timestamp; }
    }
}
