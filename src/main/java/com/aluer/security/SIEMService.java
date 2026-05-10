package com.aluer.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.atomic.AtomicLong;
import java.time.LocalDateTime;
import java.time.Duration;
import java.time.format.DateTimeFormatter;
import java.util.stream.Collectors;

@Component
public class SIEMService {
    private static final Logger logger = LoggerFactory.getLogger(SIEMService.class);

    private final Map<String, SecurityEvent> eventDatabase = new ConcurrentHashMap<>();
    private final Queue<Alert> alertQueue = new ConcurrentLinkedQueue<>();
    private final Map<String, CorrelationRule> correlationRules = new ConcurrentHashMap<>();
    private final Map<String, List<SecurityEvent>> eventTimeline = new ConcurrentHashMap<>();
    private final AtomicLong totalEvents = new AtomicLong(0);
    private final AtomicLong totalAlerts = new AtomicLong(0);
    private final Map<String, AtomicLong> eventTypeCounts = new ConcurrentHashMap<>();

    private static final int MAX_EVENTS = 100000;
    private static final int ALERT_THRESHOLD = 10;
    private static final DateTimeFormatter DATE_FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    public SIEMService() {
        initializeCorrelationRules();
        logger.info("SIEM Service initialized");
    }

    private void initializeCorrelationRules() {
        addCorrelationRule("BRUTE_FORCE_ATTACK",
            Arrays.asList("LOGIN_FAILED", "LOGIN_FAILED", "LOGIN_FAILED"),
            "在短时间内多次登录失败",
            3, 300);

        addCorrelationRule("DDOS_DETECTED",
            Arrays.asList("HIGH_CONNECTION", "HIGH_CONNECTION", "HIGH_CONNECTION", "HIGH_CONNECTION"),
            "检测到DDoS攻击特征",
            4, 60);

        addCorrelationRule("DATA_EXFILTRATION",
            Arrays.asList("LARGE_UPLOAD", "UNUSUAL_ACCESS", "LARGE_UPLOAD"),
            "可能的数据外泄",
            3, 600);

        addCorrelationRule("PRIVILEGE_ESCALATION",
            Arrays.asList("ADMIN_LOGIN", "USER_CREATED", "PERMISSION_CHANGED"),
            "权限提升攻击",
            3, 300);

        addCorrelationRule("PERSISTENT_THREAT",
            Arrays.asList("SUSPICIOUS_PROCESS", "SCHEDULED_TASK", "STARTUP_ITEM"),
            "可能存在持久性威胁",
            3, 3600);

        addCorrelationRule("LATERAL_MOVEMENT",
            Arrays.asList("NEW_SERVICE", "PORT_OPEN", "REMOTE_ACCESS"),
            "横向移动检测",
            3, 600);

        logger.info("Initialized {} correlation rules", correlationRules.size());
    }

    public void addCorrelationRule(String name, List<String> sequence, String description, int minMatches, int timeWindowSeconds) {
        CorrelationRule rule = new CorrelationRule(name, sequence, description, minMatches, timeWindowSeconds);
        correlationRules.put(name, rule);
        logger.info("Added correlation rule: {}", name);
    }

    public void logEvent(String source, String eventType, String severity, String description, Map<String, Object> metadata) {
        String eventId = UUID.randomUUID().toString();
        SecurityEvent event = new SecurityEvent(eventId, source, eventType, severity, description, metadata, LocalDateTime.now());

        eventDatabase.put(eventId, event);
        totalEvents.incrementAndGet();

        eventTypeCounts.computeIfAbsent(eventType, k -> new AtomicLong(0)).incrementAndGet();

        eventTimeline.computeIfAbsent(source, k -> new ArrayList<>()).add(event);

        cleanupOldEvents();

        checkCorrelationRules(event);

        logger.debug("Logged security event: {} [{}]", eventType, severity);
    }

    public void logSimpleEvent(String source, String eventType, String severity, String description) {
        logEvent(source, eventType, severity, description, new HashMap<>());
    }

    private void checkCorrelationRules(SecurityEvent event) {
        for (CorrelationRule rule : correlationRules.values()) {
            if (!rule.isEnabled()) continue;

            List<SecurityEvent> recentEvents = eventTimeline.get(event.getSource());
            if (recentEvents == null || recentEvents.size() < rule.getMinMatches()) continue;

            List<String> recentTypes = recentEvents.stream()
                .map(SecurityEvent::getEventType)
                .collect(Collectors.toList());

            if (rule.matchesSequence(recentTypes)) {
                triggerAlert(rule.getName(), rule.getDescription(), "HIGH", event);
            }
        }
    }

    public void triggerAlert(String ruleName, String description, String severity, SecurityEvent relatedEvent) {
        String alertId = UUID.randomUUID().toString();
        Alert alert = new Alert(alertId, ruleName, description, severity, relatedEvent, LocalDateTime.now());

        alertQueue.offer(alert);
        totalAlerts.incrementAndGet();

        logger.warn("ALERT: {} - {}", ruleName, description);
    }

    public List<SecurityEvent> queryEvents(EventQuery query) {
        return eventDatabase.values().stream()
            .filter(e -> query.getEventType() == null || e.getEventType().equals(query.getEventType()))
            .filter(e -> query.getSeverity() == null || e.getSeverity().equals(query.getSeverity()))
            .filter(e -> query.getSource() == null || e.getSource().contains(query.getSource()))
            .filter(e -> query.getStartTime() == null || e.getTimestamp().isAfter(query.getStartTime()))
            .filter(e -> query.getEndTime() == null || e.getTimestamp().isBefore(query.getEndTime()))
            .sorted((a, b) -> b.getTimestamp().compareTo(a.getTimestamp()))
            .limit(query.getLimit())
            .collect(Collectors.toList());
    }

    public Map<String, Object> getDashboardData() {
        Map<String, Object> data = new HashMap<>();

        data.put("totalEvents", totalEvents.get());
        data.put("totalAlerts", totalAlerts.get());

        Map<String, Long> typeCounts = new HashMap<>();
        for (Map.Entry<String, AtomicLong> entry : eventTypeCounts.entrySet()) {
            typeCounts.put(entry.getKey(), entry.getValue().get());
        }
        data.put("eventTypeCounts", typeCounts);

        Map<String, Long> severityCounts = new HashMap<>();
        severityCounts.put("CRITICAL", eventDatabase.values().stream().filter(e -> "CRITICAL".equals(e.getSeverity())).count());
        severityCounts.put("HIGH", eventDatabase.values().stream().filter(e -> "HIGH".equals(e.getSeverity())).count());
        severityCounts.put("MEDIUM", eventDatabase.values().stream().filter(e -> "MEDIUM".equals(e.getSeverity())).count());
        severityCounts.put("LOW", eventDatabase.values().stream().filter(e -> "LOW".equals(e.getSeverity())).count());
        data.put("severityCounts", severityCounts);

        LocalDateTime oneHourAgo = LocalDateTime.now().minusHours(1);
        long recentEvents = eventDatabase.values().stream()
            .filter(e -> e.getTimestamp().isAfter(oneHourAgo))
            .count();
        data.put("eventsLastHour", recentEvents);

        List<Alert> recentAlerts = alertQueue.stream()
            .sorted((a, b) -> b.getTimestamp().compareTo(a.getTimestamp()))
            .limit(10)
            .collect(Collectors.toList());
        data.put("recentAlerts", recentAlerts);

        return data;
    }

    public List<Alert> getAlerts(String severity, int limit) {
        return alertQueue.stream()
            .filter(a -> severity == null || a.getSeverity().equals(severity))
            .sorted((a, b) -> b.getTimestamp().compareTo(a.getTimestamp()))
            .limit(limit)
            .collect(Collectors.toList());
    }

    public Map<String, Object> getThreatAnalysis() {
        Map<String, Object> analysis = new HashMap<>();

        Map<String, Long> sourceCounts = eventDatabase.values().stream()
            .collect(Collectors.groupingBy(SecurityEvent::getSource, Collectors.counting()));

        List<Map.Entry<String, Long>> topSources = sourceCounts.entrySet().stream()
            .sorted(Map.Entry.<String, Long>comparingByValue().reversed())
            .limit(10)
            .collect(Collectors.toList());
        analysis.put("topEventSources", topSources);

        Map<String, Long> eventTypeAnalysis = eventDatabase.values().stream()
            .collect(Collectors.groupingBy(SecurityEvent::getEventType, Collectors.counting()));

        List<Map.Entry<String, Long>> topEventTypes = eventTypeAnalysis.entrySet().stream()
            .sorted(Map.Entry.<String, Long>comparingByValue().reversed())
            .limit(10)
            .collect(Collectors.toList());
        analysis.put("topEventTypes", topEventTypes);

        Map<String, Long> attackPatterns = new HashMap<>();
        long bruteForce = eventTypeCounts.getOrDefault("LOGIN_FAILED", new AtomicLong(0)).get();
        attackPatterns.put("bruteForce", bruteForce);

        long ddos = eventTypeCounts.getOrDefault("HIGH_CONNECTION", new AtomicLong(0)).get();
        attackPatterns.put("ddos", ddos);

        long sqlInjection = eventTypeCounts.getOrDefault("SQL_INJECTION", new AtomicLong(0)).get();
        attackPatterns.put("sqlInjection", sqlInjection);

        analysis.put("attackPatterns", attackPatterns);

        return analysis;
    }

    private void cleanupOldEvents() {
        if (eventDatabase.size() > MAX_EVENTS) {
            List<SecurityEvent> sortedEvents = eventDatabase.values().stream()
                .sorted((a, b) -> a.getTimestamp().compareTo(b.getTimestamp()))
                .collect(Collectors.toList());

            int toRemove = eventDatabase.size() - (MAX_EVENTS / 2);
            for (int i = 0; i < toRemove && i < sortedEvents.size(); i++) {
                eventDatabase.remove(sortedEvents.get(i).getEventId());
            }

            logger.info("Cleaned up old events, remaining: {}", eventDatabase.size());
        }
    }

    public void enableRule(String ruleName) {
        CorrelationRule rule = correlationRules.get(ruleName);
        if (rule != null) {
            rule.setEnabled(true);
            logger.info("Enabled correlation rule: {}", ruleName);
        }
    }

    public void disableRule(String ruleName) {
        CorrelationRule rule = correlationRules.get(ruleName);
        if (rule != null) {
            rule.setEnabled(false);
            logger.info("Disabled correlation rule: {}", ruleName);
        }
    }

    public Map<String, Object> getStats() {
        Map<String, Object> stats = new HashMap<>();
        stats.put("totalEvents", totalEvents.get());
        stats.put("totalAlerts", totalAlerts.get());
        stats.put("activeEvents", eventDatabase.size());
        stats.put("correlationRules", correlationRules.size());
        return stats;
    }

    public static class SecurityEvent {
        private final String eventId;
        private final String source;
        private final String eventType;
        private final String severity;
        private final String description;
        private final Map<String, Object> metadata;
        private final LocalDateTime timestamp;

        public SecurityEvent(String eventId, String source, String eventType, String severity,
                          String description, Map<String, Object> metadata, LocalDateTime timestamp) {
            this.eventId = eventId;
            this.source = source;
            this.eventType = eventType;
            this.severity = severity;
            this.description = description;
            this.metadata = metadata;
            this.timestamp = timestamp;
        }

        public String getEventId() { return eventId; }
        public String getSource() { return source; }
        public String getEventType() { return eventType; }
        public String getSeverity() { return severity; }
        public String getDescription() { return description; }
        public Map<String, Object> getMetadata() { return metadata; }
        public LocalDateTime getTimestamp() { return timestamp; }
    }

    public static class Alert {
        private final String alertId;
        private final String ruleName;
        private final String description;
        private final String severity;
        private final SecurityEvent relatedEvent;
        private final LocalDateTime timestamp;

        public Alert(String alertId, String ruleName, String description, String severity,
                   SecurityEvent relatedEvent, LocalDateTime timestamp) {
            this.alertId = alertId;
            this.ruleName = ruleName;
            this.description = description;
            this.severity = severity;
            this.relatedEvent = relatedEvent;
            this.timestamp = timestamp;
        }

        public String getAlertId() { return alertId; }
        public String getRuleName() { return ruleName; }
        public String getDescription() { return description; }
        public String getSeverity() { return severity; }
        public SecurityEvent getRelatedEvent() { return relatedEvent; }
        public LocalDateTime getTimestamp() { return timestamp; }
    }

    public static class CorrelationRule {
        private final String name;
        private final List<String> sequence;
        private final String description;
        private final int minMatches;
        private final int timeWindowSeconds;
        private volatile boolean enabled = true;

        public CorrelationRule(String name, List<String> sequence, String description, int minMatches, int timeWindowSeconds) {
            this.name = name;
            this.sequence = sequence;
            this.description = description;
            this.minMatches = minMatches;
            this.timeWindowSeconds = timeWindowSeconds;
        }

        public boolean matchesSequence(List<String> eventTypes) {
            if (eventTypes.size() < minMatches) return false;

            int matches = 0;
            for (int i = 0; i <= eventTypes.size() - sequence.size(); i++) {
                boolean match = true;
                for (int j = 0; j < sequence.size(); j++) {
                    if (!eventTypes.get(i + j).equals(sequence.get(j))) {
                        match = false;
                        break;
                    }
                }
                if (match) return true;
            }
            return false;
        }

        public String getName() { return name; }
        public List<String> getSequence() { return sequence; }
        public String getDescription() { return description; }
        public int getMinMatches() { return minMatches; }
        public int getTimeWindowSeconds() { return timeWindowSeconds; }
        public boolean isEnabled() { return enabled; }
        public void setEnabled(boolean enabled) { this.enabled = enabled; }
    }

    public static class EventQuery {
        private String eventType;
        private String severity;
        private String source;
        private LocalDateTime startTime;
        private LocalDateTime endTime;
        private int limit = 100;

        public String getEventType() { return eventType; }
        public void setEventType(String eventType) { this.eventType = eventType; }
        public String getSeverity() { return severity; }
        public void setSeverity(String severity) { this.severity = severity; }
        public String getSource() { return source; }
        public void setSource(String source) { this.source = source; }
        public LocalDateTime getStartTime() { return startTime; }
        public void setStartTime(LocalDateTime startTime) { this.startTime = startTime; }
        public LocalDateTime getEndTime() { return endTime; }
        public void setEndTime(LocalDateTime endTime) { this.endTime = endTime; }
        public int getLimit() { return limit; }
        public void setLimit(int limit) { this.limit = limit; }
    }
}
