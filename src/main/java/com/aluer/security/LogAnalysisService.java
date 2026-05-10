package com.aluer.security;

import org.springframework.stereotype.Service;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;
import java.security.MessageDigest;

@Service
public class LogAnalysisService {

    private final Map<String, List<LogEntry>> logBuffer = new ConcurrentHashMap<>();
    private final Map<String, PatternRule> patternRules = new ConcurrentHashMap<>();
    private final Queue<SecurityEvent> securityEvents = new ConcurrentLinkedQueue<>();
    private final Map<String, AtomicInteger> threatCounts = new ConcurrentHashMap<>();
    private final ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(2);

    private static final int MAX_BUFFER_SIZE = 10000;
    private static final long ANALYSIS_INTERVAL = 30000;

    private final AtomicLong totalLogsAnalyzed = new AtomicLong(0);
    private final AtomicLong threatsDetected = new AtomicLong(0);

    public LogAnalysisService() {
        initializePatternRules();
        startAnalysisTask();
    }

    private void initializePatternRules() {
        addPatternRule("SQL_INJECTION", ".*(union|select|insert|update|delete|drop).*", 80, true);
        addPatternRule("XSS_ATTACK", ".*(<script|javascript:|onerror=|onload=).*", 80, true);
        addPatternRule("PATH_TRAVERSAL", ".*(\\.\\./|\\.\\.\\\\).*", 70, true);
        addPatternRule("COMMAND_INJECTION", ".*(;|\\||\\$\\(|`).*", 75, true);
        addPatternRule("BRUTE_FORCE", ".*(failed login|authentication failure|invalid password).*", 60, true);
        addPatternRule("FILE_ACCESS", ".*(\\.\\./etc/passwd|\\.\\./etc/shadow).*", 90, true);
        addPatternRule("PORT_SCAN", ".*(port scan|connection attempt).*", 50, true);
        addPatternRule("DDOS_PATTERN", ".*(flood| amplification|botnet).*", 70, true);
    }

    public void addPatternRule(String name, String pattern, int severity, boolean enabled) {
        try {
            PatternRule rule = new PatternRule(name, pattern, severity, enabled);
            patternRules.put(name, rule);
        } catch (Exception e) {
        }
    }

    public void analyzeLog(String source, String logMessage) {
        totalLogsAnalyzed.incrementAndGet();

        LogEntry entry = new LogEntry(source, logMessage, System.currentTimeMillis());

        List<LogEntry> buffer = logBuffer.computeIfAbsent(source, k -> new CopyOnWriteArrayList<>());
        buffer.add(entry);

        while (buffer.size() > MAX_BUFFER_SIZE) {
            buffer.remove(0);
        }

        for (PatternRule rule : patternRules.values()) {
            if (!rule.enabled) continue;

            if (rule.matches(logMessage)) {
                handleThreatDetected(source, rule.name, rule.severity, logMessage);
            }
        }
    }

    private void handleThreatDetected(String source, String threatType, int severity, String details) {
        threatsDetected.incrementAndGet();

        AtomicInteger count = threatCounts.computeIfAbsent(threatType, k -> new AtomicInteger(0));
        count.incrementAndGet();

        SecurityEvent event = new SecurityEvent(threatType, source, severity, details, System.currentTimeMillis());
        securityEvents.offer(event);

        while (securityEvents.size() > 5000) {
            securityEvents.poll();
        }
    }

    public void addCustomLog(String source, String message, Map<String, Object> metadata) {
        LogEntry entry = new LogEntry(source, message, System.currentTimeMillis());
        entry.metadata = metadata;

        List<LogEntry> buffer = logBuffer.computeIfAbsent(source, k -> new CopyOnWriteArrayList<>());
        buffer.add(entry);
    }

    public List<LogEntry> getLogs(String source, int limit) {
        List<LogEntry> buffer = logBuffer.get(source);
        if (buffer == null) {
            return new ArrayList<>();
        }

        List<LogEntry> result = new ArrayList<>();
        int count = 0;
        for (LogEntry entry : buffer) {
            if (count++ >= limit) break;
            result.add(entry);
        }
        return result;
    }

    public List<LogEntry> getRecentLogs(int limit) {
        List<LogEntry> allLogs = new ArrayList<>();
        for (List<LogEntry> buffer : logBuffer.values()) {
            allLogs.addAll(buffer);
        }

        allLogs.sort((a, b) -> Long.compare(b.timestamp, a.timestamp));

        return allLogs.stream().limit(limit).toList();
    }

    public List<SecurityEvent> getSecurityEvents(int limit) {
        List<SecurityEvent> result = new ArrayList<>();
        int count = 0;
        for (SecurityEvent event : securityEvents) {
            if (count++ >= limit) break;
            result.add(event);
        }
        return result;
    }

    public Map<String, Integer> getThreatCounts() {
        Map<String, Integer> result = new HashMap<>();
        threatCounts.forEach((k, v) -> result.put(k, v.get()));
        return result;
    }

    public Map<String, Object> getStatistics() {
        Map<String, Object> stats = new HashMap<>();
        stats.put("totalLogsAnalyzed", totalLogsAnalyzed.get());
        stats.put("threatsDetected", threatsDetected.get());
        stats.put("bufferedSources", logBuffer.size());
        stats.put("activeRules", patternRules.size());
        return stats;
    }

    public boolean enableRule(String ruleName) {
        PatternRule rule = patternRules.get(ruleName);
        if (rule == null) return false;
        rule.enabled = true;
        return true;
    }

    public boolean disableRule(String ruleName) {
        PatternRule rule = patternRules.get(ruleName);
        if (rule == null) return false;
        rule.enabled = false;
        return true;
    }

    public PatternRule getRule(String ruleName) {
        return patternRules.get(ruleName);
    }

    public Collection<PatternRule> getAllRules() {
        return patternRules.values();
    }

    private void startAnalysisTask() {
        scheduler.scheduleAtFixedRate(() -> {
            long now = System.currentTimeMillis();

            for (Map.Entry<String, List<LogEntry>> entry : logBuffer.entrySet()) {
                List<LogEntry> buffer = entry.getValue();
                buffer.removeIf(e -> now - e.timestamp > 3600000);
                if (buffer.isEmpty()) {
                    logBuffer.remove(entry.getKey());
                }
            }

            threatCounts.entrySet().removeIf(e -> e.getValue().get() == 0);

        }, ANALYSIS_INTERVAL, ANALYSIS_INTERVAL, TimeUnit.MILLISECONDS);
    }

    public static class PatternRule {
        public final String name;
        public final String pattern;
        public final int severity;
        public volatile boolean enabled;

        private final java.util.regex.Pattern compiledPattern;

        public PatternRule(String name, String pattern, int severity, boolean enabled) {
            this.name = name;
            this.pattern = pattern;
            this.severity = severity;
            this.enabled = enabled;
            this.compiledPattern = java.util.regex.Pattern.compile(pattern, java.util.regex.Pattern.CASE_INSENSITIVE);
        }

        public boolean matches(String input) {
            return compiledPattern.matcher(input).find();
        }
    }

    public static class LogEntry {
        public final String source;
        public final String message;
        public final long timestamp;
        public Map<String, Object> metadata;

        public LogEntry(String source, String message, long timestamp) {
            this.source = source;
            this.message = message;
            this.timestamp = timestamp;
        }
    }

    public static class SecurityEvent {
        public final String threatType;
        public final String source;
        public final int severity;
        public final String details;
        public final long timestamp;

        public SecurityEvent(String threatType, String source, int severity, String details, long timestamp) {
            this.threatType = threatType;
            this.source = source;
            this.severity = severity;
            this.details = details;
            this.timestamp = timestamp;
        }
    }
}
