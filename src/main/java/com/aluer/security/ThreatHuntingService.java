package com.aluer.security;

import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

@Service
public class ThreatHuntingService {

    private final Map<String, List<HuntResult>> huntResults = new ConcurrentHashMap<>();
    private final Map<String, HuntDefinition> huntDefinitions = new ConcurrentHashMap<>();
    private final AtomicLong totalHunts = new AtomicLong(0);
    private final AtomicLong totalFindings = new AtomicLong(0);
    private final ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor();

    public ThreatHuntingService() {
        registerDefaultHunts();
        scheduler.scheduleAtFixedRate(this::runAllHunts, 300, 1800, TimeUnit.SECONDS);
    }

    private void registerDefaultHunts() {
        // Minecraft-specific threat hunting
        huntDefinitions.put("UNUSUAL_LOGIN_TIMES", new HuntDefinition(
                "Detect logins at unusual hours (2-5 AM server time)",
                "MINECRAFT", HuntSeverity.MEDIUM));

        huntDefinitions.put("RAPID_WORLD_CHANGES", new HuntDefinition(
                "Detect rapid dimension hopping (potential X-ray or cheat)",
                "MINECRAFT", HuntSeverity.HIGH));

        huntDefinitions.put("SUSPICIOUS_COMMANDS", new HuntDefinition(
                "Detect suspicious command execution patterns",
                "COMMAND", HuntSeverity.HIGH));

        huntDefinitions.put("PERSISTENCE_MECHANISMS", new HuntDefinition(
                "Detect persistence mechanisms (cron, systemd, autostart)",
                "HOST", HuntSeverity.CRITICAL));

        huntDefinitions.put("LATERAL_MOVEMENT", new HuntDefinition(
                "Detect lateral movement indicators (SSH, RDP, SMB connections)",
                "NETWORK", HuntSeverity.CRITICAL));

        huntDefinitions.put("PRIVILEGE_ESCALATION", new HuntDefinition(
                "Detect privilege escalation attempts (sudo, su, setuid)",
                "HOST", HuntSeverity.CRITICAL));

        huntDefinitions.put("DATA_EXFILTRATION", new HuntDefinition(
                "Detect large outbound data transfers to external IPs",
                "NETWORK", HuntSeverity.CRITICAL));

        huntDefinitions.put("CRYPTOMINING", new HuntDefinition(
                "Detect cryptomining indicators (high CPU, mining pools, stratum)",
                "HOST", HuntSeverity.HIGH));

        huntDefinitions.put("WEBSHELL", new HuntDefinition(
                "Detect webshell deployment (PHP/JSP shells in web directories)",
                "WEB", HuntSeverity.CRITICAL));

        huntDefinitions.put("BACKDOOR_ACCOUNT", new HuntDefinition(
                "Detect newly created privileged user accounts",
                "HOST", HuntSeverity.CRITICAL));
    }

    public HuntResult runHunt(String huntId, List<String> dataSources) {
        HuntDefinition def = huntDefinitions.get(huntId);
        if (def == null) return null;

        List<String> findings = new ArrayList<>();
        for (String data : dataSources) {
            List<String> result = huntForPatterns(def, data);
            findings.addAll(result);
        }

        HuntResult result = new HuntResult(huntId, def.name, def.category, def.severity,
                Instant.now(), findings, dataSources.size());
        huntResults.computeIfAbsent(huntId, k -> new ArrayList<>()).add(result);
        totalHunts.incrementAndGet();
        if (!findings.isEmpty()) totalFindings.addAndGet(findings.size());

        return result;
    }

    public void runAllHunts() {
        // Placeholder: in a real environment, this would query SIEM, logs, and monitors
        for (String huntId : huntDefinitions.keySet()) {
            List<String> data = List.of("dummy-data");
            runHunt(huntId, data);
        }
    }

    private List<String> huntForPatterns(HuntDefinition def, String data) {
        List<String> findings = new ArrayList<>();
        String lower = data.toLowerCase();

        switch (def.category) {
            case "MINECRAFT":
                if (lower.contains("joined the game") && lower.contains("02:") || lower.contains("03:") || lower.contains("04:")) {
                    findings.add("Unusual login time detected");
                }
                break;
            case "COMMAND":
                if (lower.contains("/op ") || lower.contains("/deop ") || lower.contains("/stop")) {
                    findings.add("Suspicious command execution");
                }
                break;
            case "HOST":
                if (lower.contains("crontab") || lower.contains("systemctl enable")
                        || lower.contains("update-rc.d") || lower.contains("chkconfig")) {
                    findings.add("Persistence mechanism detected");
                }
                if (lower.contains("sudo su") || lower.contains("chmod u+s") || lower.contains("setuid")) {
                    findings.add("Privilege escalation attempt");
                }
                break;
            case "NETWORK":
                if (lower.contains("ssh ") && lower.contains("root@")) {
                    findings.add("SSH lateral movement");
                }
                break;
            case "WEB":
                if (lower.contains(".jsp") || (lower.contains("<?php") && lower.contains("exec("))) {
                    findings.add("Potential webshell deployment");
                }
                break;
        }
        return findings;
    }

    public Map<String, Object> getStatus() {
        Map<String, Object> status = new LinkedHashMap<>();
        status.put("huntDefinitions", huntDefinitions.size());
        status.put("totalHunts", totalHunts.get());
        status.put("totalFindings", totalFindings.get());

        Map<String, Long> byCategory = new LinkedHashMap<>();
        Map<String, Long> bySeverity = new LinkedHashMap<>();
        for (HuntDefinition def : huntDefinitions.values()) {
            byCategory.merge(def.category, 1L, Long::sum);
            bySeverity.merge(def.severity.name(), 1L, Long::sum);
        }
        status.put("huntsByCategory", byCategory);
        status.put("huntsBySeverity", bySeverity);

        List<Map<String, Object>> recent = new ArrayList<>();
        for (Map.Entry<String, List<HuntResult>> e : huntResults.entrySet()) {
            for (HuntResult r : e.getValue()) {
                Map<String, Object> m = new LinkedHashMap<>();
                m.put("huntId", r.huntId);
                m.put("name", r.huntName);
                m.put("category", r.category);
                m.put("severity", r.severity.name());
                m.put("findings", r.findings.size());
                m.put("time", r.timestamp.toString());
                recent.add(m);
            }
        }
        recent.sort((a, b) -> b.get("time").toString().compareTo(a.get("time").toString()));
        status.put("recentHunts", recent.subList(0, Math.min(recent.size(), 20)));
        return status;
    }

    public long getTotalHunts() { return totalHunts.get(); }
    public long getTotalFindings() { return totalFindings.get(); }

    public enum HuntSeverity { LOW, MEDIUM, HIGH, CRITICAL }

    public static class HuntDefinition {
        final String name;
        final String category;
        final HuntSeverity severity;

        HuntDefinition(String name, String category, HuntSeverity severity) {
            this.name = name;
            this.category = category;
            this.severity = severity;
        }
    }

    public static class HuntResult {
        public final String huntId;
        public final String huntName;
        public final String category;
        public final HuntSeverity severity;
        public final Instant timestamp;
        public final List<String> findings;
        public final int dataSourcesProcessed;

        HuntResult(String huntId, String huntName, String category, HuntSeverity severity,
                   Instant timestamp, List<String> findings, int dataSourcesProcessed) {
            this.huntId = huntId;
            this.huntName = huntName;
            this.category = category;
            this.severity = severity;
            this.timestamp = timestamp;
            this.findings = findings;
            this.dataSourcesProcessed = dataSourcesProcessed;
        }
    }
}
