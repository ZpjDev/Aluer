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
public class LogCorrelationService {
    private static final Logger logger = LoggerFactory.getLogger(LogCorrelationService.class);

    private final Map<String, LogSource> logSources = new ConcurrentHashMap<>();
    private final Map<String, LogEntry> logBuffer = new ConcurrentHashMap<>();
    private final Queue<CorrelatedEvent> correlatedEvents = new ConcurrentLinkedQueue<>();
    private final Map<String, CorrelationPattern> patterns = new ConcurrentHashMap<>();
    private final Map<String, List<LogEntry>> logTimeline = new ConcurrentHashMap<>();
    private final AtomicLong totalLogsProcessed = new AtomicLong(0);
    private final AtomicLong correlatedEventsFound = new AtomicLong(0);

    private static final int MAX_BUFFER_SIZE = 50000;
    private static final DateTimeFormatter DATE_FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    public LogCorrelationService() {
        initializeDefaultPatterns();
        logger.info("Log Correlation Service initialized");
    }

    private void initializeDefaultPatterns() {
        addPattern("SQL_INJECTION", "SQL.*(union|select|insert|update|delete).*", Arrays.asList("SQL_INJECTION_START", "SQL_INJECTION_END"), 300);
        addPattern("BRUTE_FORCE", "AUTH.*(failed|invalid)", Arrays.asList("LOGIN_FAILED", "LOGIN_FAILED", "LOGIN_FAILED"), 60);
        addPattern("XSS_ATTACK", "HTTP.*(<script|javascript:)", Arrays.asList("XSS_START", "XSS_PAYLOAD"), 120);
        addPattern("DATA_EXFILTRATION", "(upload|download).*large", Arrays.asList("LARGE_UPLOAD", "DATA_TRANSFER"), 600);
        addPattern("PRIVILEGE_ESCALATION", "(sudo|admin|root).*(success|granted)", Arrays.asList("ELEVATED_ACCESS", "PERMISSION_CHANGE"), 300);
        addPattern("CREDENTIALS_COMPROMISED", "AUTH.*success.*(unusual|unknown)", Arrays.asList("ANOMALY_LOGIN", "CREDENTIAL_CHANGE"), 180);
        addPattern("DDoS_ATTACK", "NET.*(flood|storm|amplification)", Arrays.asList("HIGH_TRAFFIC", "CONNECTION_LIMIT"), 60);
        addPattern("MALWARE_INFECTION", "PROC.*(suspicious|malicious|infected)", Arrays.asList("SUSPICIOUS_PROCESS", "MALWARE_DETECTED"), 600);

        logger.info("Initialized {} correlation patterns", patterns.size());
    }

    public void addPattern(String name, String matchRegex, List<String> sequence, int timeWindow) {
        CorrelationPattern pattern = new CorrelationPattern(name, matchRegex, sequence, timeWindow);
        patterns.put(name, pattern);
    }

    public void addLogSource(String sourceId, String sourceType, String host, int port) {
        LogSource source = new LogSource(sourceId, sourceType, host, port);
        logSources.put(sourceId, source);
        logger.info("Added log source: {} ({})", sourceId, sourceType);
    }

    public void processLogEntry(String sourceId, String level, String category, String message, Map<String, Object> metadata) {
        String entryId = UUID.randomUUID().toString();
        LogEntry entry = new LogEntry(entryId, sourceId, level, category, message, metadata, LocalDateTime.now());

        logBuffer.put(entryId, entry);
        if (logBuffer.size() > MAX_BUFFER_SIZE) {
            String firstKey = logBuffer.keySet().iterator().next();
            logBuffer.remove(firstKey);
        }

        totalLogsProcessed.incrementAndGet();

        List<LogEntry> timeline = logTimeline.computeIfAbsent(sourceId, k -> new ArrayList<>());
        timeline.add(entry);
        if (timeline.size() > 1000) {
            timeline.remove(0);
        }

        checkCorrelationPatterns(entry);

        logger.debug("Processed log entry: {} [{}]", category, level);
    }

    private void checkCorrelationPatterns(LogEntry entry) {
        for (CorrelationPattern pattern : patterns.values()) {
            if (matchesPattern(entry, pattern)) {
                List<LogEntry> sourceTimeline = logTimeline.get(entry.getSourceId());
                if (sourceTimeline == null) continue;

                List<LogEntry> recentEntries = new ArrayList<>();
                long cutoffTime = System.currentTimeMillis() - (pattern.getTimeWindow() * 1000);

                for (LogEntry e : sourceTimeline) {
                    if (e.getTimestamp().isAfter(LocalDateTime.now().minusSeconds(pattern.getTimeWindow()))) {
                        recentEntries.add(e);
                    }
                }

                if (checkSequenceMatch(recentEntries, pattern)) {
                    CorrelatedEvent event = new CorrelatedEvent(
                        pattern.getName(),
                        entry.getSourceId(),
                        recentEntries,
                        "CORRELATION_DETECTED",
                        LocalDateTime.now()
                    );
                    correlatedEvents.offer(event);
                    correlatedEventsFound.incrementAndGet();

                    if (correlatedEvents.size() > 1000) {
                        correlatedEvents.poll();
                    }

                    logger.warn("Correlation detected: {} from source: {}", pattern.getName(), entry.getSourceId());
                }
            }
        }
    }

    private boolean matchesPattern(LogEntry entry, CorrelationPattern pattern) {
        try {
            return entry.getMessage().matches(pattern.getMatchRegex()) ||
                   entry.getCategory().matches(pattern.getMatchRegex());
        } catch (Exception e) {
            return false;
        }
    }

    private boolean checkSequenceMatch(List<LogEntry> entries, CorrelationPattern pattern) {
        List<String> sequence = pattern.getSequence();
        if (entries.size() < sequence.size()) return false;

        int matchCount = 0;
        for (int i = 0; i <= entries.size() - sequence.size(); i++) {
            boolean allMatch = true;
            for (int j = 0; j < sequence.size(); j++) {
                String entryCategory = entries.get(i + j).getCategory();
                if (!entryCategory.matches(sequence.get(j)) && !entryCategory.contains(sequence.get(j))) {
                    allMatch = false;
                    break;
                }
            }
            if (allMatch) return true;
        }
        return false;
    }

    public List<CorrelatedEvent> queryCorrelatedEvents(String patternName, int limit) {
        List<CorrelatedEvent> results = new ArrayList<>();
        for (CorrelatedEvent event : correlatedEvents) {
            if (patternName == null || event.getPatternName().equals(patternName)) {
                results.add(event);
            }
            if (results.size() >= limit) break;
        }
        return results;
    }

    public List<LogEntry> queryLogs(String sourceId, String level, String category, int limit) {
        List<LogEntry> results = new ArrayList<>();

        for (LogEntry entry : logBuffer.values()) {
            boolean matches = true;

            if (sourceId != null && !entry.getSourceId().equals(sourceId)) matches = false;
            if (level != null && !entry.getLevel().equals(level)) matches = false;
            if (category != null && !entry.getCategory().equals(category)) matches = false;

            if (matches) {
                results.add(entry);
            }

            if (results.size() >= limit) break;
        }

        results.sort((a, b) -> b.getTimestamp().compareTo(a.getTimestamp()));
        return results;
    }

    public Map<String, Object> getStats() {
        Map<String, Object> stats = new HashMap<>();
        stats.put("totalLogsProcessed", totalLogsProcessed.get());
        stats.put("correlatedEventsFound", correlatedEventsFound.get());
        stats.put("logSources", logSources.size());
        stats.put("correlationPatterns", patterns.size());
        stats.put("bufferSize", logBuffer.size());

        Map<String, Long> categoryCounts = new HashMap<>();
        for (LogEntry entry : logBuffer.values()) {
            categoryCounts.merge(entry.getCategory(), 1L, Long::sum);
        }
        stats.put("categoryCounts", categoryCounts);

        Map<String, Long> levelCounts = new HashMap<>();
        for (LogEntry entry : logBuffer.values()) {
            levelCounts.merge(entry.getLevel(), 1L, Long::sum);
        }
        stats.put("levelCounts", levelCounts);

        return stats;
    }

    public Map<String, LogSource> getLogSources() {
        return new HashMap<>(logSources);
    }

    public Map<String, CorrelationPattern> getPatterns() {
        return new HashMap<>(patterns);
    }

    public void enablePattern(String patternName) {
        CorrelationPattern pattern = patterns.get(patternName);
        if (pattern != null) {
            pattern.setEnabled(true);
            logger.info("Enabled correlation pattern: {}", patternName);
        }
    }

    public void disablePattern(String patternName) {
        CorrelationPattern pattern = patterns.get(patternName);
        if (pattern != null) {
            pattern.setEnabled(false);
            logger.info("Disabled correlation pattern: {}", patternName);
        }
    }

    public void clearBuffer() {
        logBuffer.clear();
        logger.info("Log buffer cleared");
    }

    public static class LogSource {
        private final String sourceId;
        private final String sourceType;
        private final String host;
        private final int port;
        private volatile boolean active = true;
        private volatile long lastLogTime;

        public LogSource(String sourceId, String sourceType, String host, int port) {
            this.sourceId = sourceId;
            this.sourceType = sourceType;
            this.host = host;
            this.port = port;
        }

        public String getSourceId() { return sourceId; }
        public String getSourceType() { return sourceType; }
        public String getHost() { return host; }
        public int getPort() { return port; }
        public boolean isActive() { return active; }
        public void setActive(boolean active) { this.active = active; }
        public long getLastLogTime() { return lastLogTime; }
        public void setLastLogTime(long lastLogTime) { this.lastLogTime = lastLogTime; }
    }

    public static class LogEntry {
        private final String entryId;
        private final String sourceId;
        private final String level;
        private final String category;
        private final String message;
        private final Map<String, Object> metadata;
        private final LocalDateTime timestamp;

        public LogEntry(String entryId, String sourceId, String level, String category,
                      String message, Map<String, Object> metadata, LocalDateTime timestamp) {
            this.entryId = entryId;
            this.sourceId = sourceId;
            this.level = level;
            this.category = category;
            this.message = message;
            this.metadata = metadata;
            this.timestamp = timestamp;
        }

        public String getEntryId() { return entryId; }
        public String getSourceId() { return sourceId; }
        public String getLevel() { return level; }
        public String getCategory() { return category; }
        public String getMessage() { return message; }
        public Map<String, Object> getMetadata() { return metadata; }
        public LocalDateTime getTimestamp() { return timestamp; }
    }

    public static class CorrelationPattern {
        private final String name;
        private final String matchRegex;
        private final List<String> sequence;
        private final int timeWindow;
        private volatile boolean enabled = true;

        public CorrelationPattern(String name, String matchRegex, List<String> sequence, int timeWindow) {
            this.name = name;
            this.matchRegex = matchRegex;
            this.sequence = sequence;
            this.timeWindow = timeWindow;
        }

        public String getName() { return name; }
        public String getMatchRegex() { return matchRegex; }
        public List<String> getSequence() { return sequence; }
        public int getTimeWindow() { return timeWindow; }
        public boolean isEnabled() { return enabled; }
        public void setEnabled(boolean enabled) { this.enabled = enabled; }
    }

    public static class CorrelatedEvent {
        private final String patternName;
        private final String sourceId;
        private final List<LogEntry> relatedEntries;
        private final String status;
        private final LocalDateTime timestamp;

        public CorrelatedEvent(String patternName, String sourceId, List<LogEntry> relatedEntries,
                            String status, LocalDateTime timestamp) {
            this.patternName = patternName;
            this.sourceId = sourceId;
            this.relatedEntries = relatedEntries;
            this.status = status;
            this.timestamp = timestamp;
        }

        public String getPatternName() { return patternName; }
        public String getSourceId() { return sourceId; }
        public List<LogEntry> getRelatedEntries() { return relatedEntries; }
        public String getStatus() { return status; }
        public LocalDateTime getTimestamp() { return timestamp; }
    }
}
