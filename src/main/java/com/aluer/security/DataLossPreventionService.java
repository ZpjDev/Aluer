package com.aluer.security;

import com.aluer.config.ServerGuardConfig;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;
import java.util.regex.Pattern;

@Service
public class DataLossPreventionService {

    private final ServerGuardConfig config;
    private final Map<String, List<DLPEvent>> detections = new ConcurrentHashMap<>();
    private final AtomicLong totalDetections = new AtomicLong(0);

    public DataLossPreventionService() {
        this(new ServerGuardConfig());
    }

    public DataLossPreventionService(ServerGuardConfig config) {
        this.config = config;
    }

    private static final List<DLPRule> RULES = new ArrayList<>();

    static {
        RULES.add(new DLPRule("EMAIL_LEAK", DLPLevel.HIGH,
                Pattern.compile("[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}"),
                "Email address detected"));

        RULES.add(new DLPRule("IP_LEAK", DLPLevel.MEDIUM,
                Pattern.compile("\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b"),
                "IP address detected"));

        RULES.add(new DLPRule("API_KEY", DLPLevel.CRITICAL,
                Pattern.compile("(?:api[_-]?key|apikey|secret[_-]?key|access[_-]?token|auth[_-]?token)[=:]\\s*['\"]?[a-zA-Z0-9_\\-]{20,}['\"]?", Pattern.CASE_INSENSITIVE),
                "API key or secret detected"));

        RULES.add(new DLPRule("PASSWORD_LEAK", DLPLevel.CRITICAL,
                Pattern.compile("(?:password|passwd|pwd|secret)[=:]\\s*['\"]?\\S{6,}['\"]?", Pattern.CASE_INSENSITIVE),
                "Password or credential detected"));

        RULES.add(new DLPRule("CONNECTION_STRING", DLPLevel.CRITICAL,
                Pattern.compile("(?:jdbc|mongodb|redis|mysql|postgresql|sqlserver):[^\\s]{20,}", Pattern.CASE_INSENSITIVE),
                "Database connection string detected"));

        RULES.add(new DLPRule("SSH_KEY", DLPLevel.CRITICAL,
                Pattern.compile("-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----"),
                "SSH private key detected"));

        RULES.add(new DLPRule("JWT_TOKEN", DLPLevel.HIGH,
                Pattern.compile("eyJ[a-zA-Z0-9_-]{20,}\\.[a-zA-Z0-9_-]{20,}\\.[a-zA-Z0-9_-]{10,}"),
                "JWT token detected"));

        RULES.add(new DLPRule("PHONE_NUMBER", DLPLevel.MEDIUM,
                Pattern.compile("(?:\\+?86)?1[3-9]\\d{9}"),
                "Phone number detected"));

        RULES.add(new DLPRule("ID_CARD", DLPLevel.HIGH,
                Pattern.compile("\\b\\d{17}[\\dXx]\\b"),
                "ID card number detected"));

        RULES.add(new DLPRule("CREDIT_CARD", DLPLevel.CRITICAL,
                Pattern.compile("\\b(?:\\d[ -]?){13,19}\\b"),
                "Potential credit card number"));

        RULES.add(new DLPRule("RCON_PASSWORD", DLPLevel.CRITICAL,
                Pattern.compile("(?:rcon\\.password|enable-rcon)\\s*=\\s*\\S+", Pattern.CASE_INSENSITIVE),
                "RCON password in configuration"));

        RULES.add(new DLPRule("MINECRAFT_TOKEN", DLPLevel.HIGH,
                Pattern.compile("(?:accessToken|clientToken|XboxLive|minecraft:token)[=:]\\s*['\"]?[a-zA-Z0-9_\\-]{20,}['\"]?", Pattern.CASE_INSENSITIVE),
                "Minecraft authentication token detected"));
    }

    public DLPCheckResult scan(String content, String source, String channel) {
        if (!config.getSecurity().getSuperEvolution().isDlp()) return DLPCheckResult.clean();
        if (content == null || content.trim().isEmpty()) return DLPCheckResult.clean();

        Map<DLPLevel, List<String>> findings = new LinkedHashMap<>();
        for (DLPRule rule : RULES) {
            if (rule.pattern.matcher(content).find()) {
                findings.computeIfAbsent(rule.level, k -> new ArrayList<>()).add(rule.name + ": " + rule.description);
            }
        }

        if (!findings.isEmpty()) {
            List<String> allFindings = new ArrayList<>();
            findings.values().forEach(allFindings::addAll);
            DLPEvent event = new DLPEvent(Instant.now(), source, channel, allFindings,
                    content.length() > 200 ? content.substring(0, 200) : content);
            detections.computeIfAbsent(source, k -> new ArrayList<>()).add(event);
            totalDetections.incrementAndGet();
            return DLPCheckResult.detected(findings);
        }

        return DLPCheckResult.clean();
    }

    public String redactSensitiveData(String content) {
        if (content == null) return null;
        String result = content;
        for (DLPRule rule : RULES) {
            result = rule.pattern.matcher(result).replaceAll("[REDACTED-" + rule.name + "]");
        }
        return result;
    }

    public Map<String, Object> getStatus() {
        Map<String, Object> status = new LinkedHashMap<>();
        status.put("totalDetections", totalDetections.get());
        status.put("rulesCount", RULES.size());
        status.put("trackedSources", detections.size());

        Map<String, Long> byType = new LinkedHashMap<>();
        for (List<DLPEvent> events : detections.values()) {
            for (DLPEvent e : events) {
                for (String finding : e.findings) {
                    String type = finding.split(":")[0].trim();
                    byType.merge(type, 1L, Long::sum);
                }
            }
        }
        status.put("detectionsByType", byType);

        List<Map<String, Object>> recent = new ArrayList<>();
        for (Map.Entry<String, List<DLPEvent>> e : detections.entrySet()) {
            for (DLPEvent event : e.getValue()) {
                Map<String, Object> m = new LinkedHashMap<>();
                m.put("source", e.getKey());
                m.put("channel", event.channel);
                m.put("findings", event.findings);
                m.put("snippet", event.snippet);
                m.put("time", event.timestamp.toString());
                recent.add(m);
            }
        }
        recent.sort((a, b) -> b.get("time").toString().compareTo(a.get("time").toString()));
        status.put("recentDetections", recent.subList(0, Math.min(recent.size(), 20)));
        return status;
    }

    public long getTotalDetections() { return totalDetections.get(); }

    public enum DLPLevel { LOW, MEDIUM, HIGH, CRITICAL }

    private static class DLPRule {
        final String name;
        final DLPLevel level;
        final Pattern pattern;
        final String description;

        DLPRule(String name, DLPLevel level, Pattern pattern, String description) {
            this.name = name;
            this.level = level;
            this.pattern = pattern;
            this.description = description;
        }
    }

    private static class DLPEvent {
        final Instant timestamp;
        final String source;
        final String channel;
        final List<String> findings;
        final String snippet;

        DLPEvent(Instant timestamp, String source, String channel, List<String> findings, String snippet) {
            this.timestamp = timestamp;
            this.source = source;
            this.channel = channel;
            this.findings = findings;
            this.snippet = snippet;
        }
    }

    public static class DLPCheckResult {
        private final boolean detected;
        private final Map<DLPLevel, List<String>> findings;

        private DLPCheckResult(boolean detected, Map<DLPLevel, List<String>> findings) {
            this.detected = detected;
            this.findings = findings;
        }

        public static DLPCheckResult clean() { return new DLPCheckResult(false, Map.of()); }
        public static DLPCheckResult detected(Map<DLPLevel, List<String>> findings) { return new DLPCheckResult(true, findings); }

        public boolean isDetected() { return detected; }
        public Map<DLPLevel, List<String>> getFindings() { return findings; }
    }
}
