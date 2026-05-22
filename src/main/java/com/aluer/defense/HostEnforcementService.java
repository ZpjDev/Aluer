package com.aluer.defense;

import com.aluer.config.ServerGuardConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.regex.Pattern;

@Service
public class HostEnforcementService {
    private static final Logger logger = LoggerFactory.getLogger(HostEnforcementService.class);

    private static final Pattern IP_PATTERN = Pattern.compile("^[0-9a-fA-F:.]+$");

    private final ServerGuardConfig config;
    private final Map<String, ManagedRule> desiredRules = new ConcurrentHashMap<>();
    private final ConcurrentLinkedQueue<EnforcementActionResult> actionLog = new ConcurrentLinkedQueue<>();

    public HostEnforcementService() {
        this(new ServerGuardConfig());
    }

    @Autowired
    public HostEnforcementService(ServerGuardConfig config) {
        this.config = config;
    }

    public EnforcementActionResult blockIp(String ip, String reason, int durationMinutes) {
        return applyRule("BLOCK", ip, Math.max(1, durationMinutes), 0, reason);
    }

    public EnforcementActionResult releaseIp(String ip, String reason) {
        String normalizedIp = normalizeIp(ip);
        if (normalizedIp == null) {
            return record(new EnforcementActionResult(false, "RELEASE", "none", true,
                "invalid-ip", List.of(), reason, ip, 0, 0));
        }

        HostFirewallAdapter adapter = resolveAdapter();
        ManagedRule existing = findRule(normalizedIp, null);
        List<String> preview = adapter.previewReleaseCommands(normalizedIp, existing != null ? existing.mode : "BLOCK");
        boolean success = true;
        String status = "released";

        if (!isDryRunEnabled()) {
            success = executeCommands(adapter.buildReleaseCommands(normalizedIp, existing != null ? existing.mode : "BLOCK"));
            status = success ? "released" : "release-failed";
        }

        desiredRules.entrySet().removeIf(entry -> normalizedIp.equals(entry.getValue().ip));
        return record(new EnforcementActionResult(success, "RELEASE", adapter.getName(), isDryRunEnabled(),
            status, preview, reason, normalizedIp, 0, 0));
    }

    public EnforcementActionResult rateLimitIp(String ip, int limitPerMinute, String reason) {
        return applyRule("RATE_LIMIT", ip, config.getSecurity().getHostEnforcement().getDefaultBlockMinutes(),
            Math.max(1, limitPerMinute), reason);
    }

    public List<ManagedRule> listActiveRules() {
        List<ManagedRule> rules = new ArrayList<>(desiredRules.values());
        rules.sort(Comparator.comparingLong((ManagedRule rule) -> rule.createdAt).reversed());
        return rules;
    }

    public Map<String, Object> syncDesiredState() {
        long now = System.currentTimeMillis();
        int expired = 0;

        for (ManagedRule rule : new ArrayList<>(desiredRules.values())) {
            if (rule.expiresAt > 0 && rule.expiresAt < now) {
                releaseIp(rule.ip, "TTL expired");
                expired++;
            }
        }

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("expiredRulesReleased", expired);
        result.put("remainingRules", desiredRules.size());
        result.put("backend", resolveAdapter().getName());
        result.put("dryRun", isDryRunEnabled());
        return result;
    }

    public Map<String, Object> dryRunPreview(String action, String ip, String reason) {
        HostFirewallAdapter adapter = resolveAdapter();
        String normalizedAction = action == null ? "BLOCK" : action.toUpperCase(Locale.ROOT);
        String normalizedIp = normalizeIp(ip);

        List<String> preview;
        if (normalizedIp == null) {
            preview = List.of();
        } else if ("RELEASE".equals(normalizedAction)) {
            preview = adapter.previewReleaseCommands(normalizedIp, "BLOCK");
        } else if ("RATE_LIMIT".equals(normalizedAction)) {
            preview = adapter.previewRateLimitCommands(normalizedIp, config.getSecurity().getHostEnforcement().getDefaultRateLimitPerMinute());
        } else {
            preview = adapter.previewBlockCommands(normalizedIp);
        }

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("action", normalizedAction);
        result.put("ip", normalizedIp);
        result.put("backend", adapter.getName());
        result.put("reason", reason);
        result.put("dryRun", true);
        result.put("commands", preview);
        return result;
    }

    public Map<String, Object> getStats() {
        long blockRules = desiredRules.values().stream().filter(rule -> "BLOCK".equals(rule.mode)).count();
        long rateRules = desiredRules.values().stream().filter(rule -> "RATE_LIMIT".equals(rule.mode)).count();

        Map<String, Object> stats = new HashMap<>();
        stats.put("enabled", isEnabled());
        stats.put("dryRun", isDryRunEnabled());
        stats.put("backend", resolveAdapter().getName());
        stats.put("managedRules", desiredRules.size());
        stats.put("blockRules", blockRules);
        stats.put("rateLimitRules", rateRules);
        stats.put("loggedActions", actionLog.size());
        return stats;
    }

    public List<EnforcementActionResult> getRecentActions(int limit) {
        List<EnforcementActionResult> actions = new ArrayList<>();
        int count = 0;
        for (EnforcementActionResult action : actionLog) {
            if (count++ >= limit) {
                break;
            }
            actions.add(action);
        }
        return actions;
    }

    private EnforcementActionResult applyRule(String mode, String ip, int durationMinutes, int limitPerMinute, String reason) {
        String normalizedIp = normalizeIp(ip);
        if (normalizedIp == null) {
            return record(new EnforcementActionResult(false, mode, "none", true,
                "invalid-ip", List.of(), reason, ip, durationMinutes, limitPerMinute));
        }

        HostFirewallAdapter adapter = resolveAdapter();
        List<String> preview = "RATE_LIMIT".equals(mode)
            ? adapter.previewRateLimitCommands(normalizedIp, limitPerMinute)
            : adapter.previewBlockCommands(normalizedIp);

        boolean success = true;
        String status = isDryRunEnabled() ? "dry-run" : "applied";
        if (!isDryRunEnabled()) {
            List<List<String>> commands = "RATE_LIMIT".equals(mode)
                ? adapter.buildRateLimitCommands(normalizedIp, limitPerMinute)
                : adapter.buildBlockCommands(normalizedIp);
            success = executeCommands(commands);
            status = success ? "applied" : "execution-failed";
        }

        long expiresAt = durationMinutes > 0
            ? System.currentTimeMillis() + durationMinutes * 60_000L
            : 0;
        ManagedRule rule = new ManagedRule(normalizedIp, mode, reason, durationMinutes, limitPerMinute, expiresAt, adapter.getName());
        desiredRules.put(rule.getKey(), rule);

        return record(new EnforcementActionResult(success, mode, adapter.getName(), isDryRunEnabled(),
            status, preview, reason, normalizedIp, durationMinutes, limitPerMinute));
    }

    private ManagedRule findRule(String ip, String mode) {
        return desiredRules.values().stream()
            .filter(rule -> Objects.equals(rule.ip, ip))
            .filter(rule -> mode == null || Objects.equals(rule.mode, mode))
            .findFirst()
            .orElse(null);
    }

    private EnforcementActionResult record(EnforcementActionResult result) {
        actionLog.offer(result);
        while (actionLog.size() > 1000) {
            actionLog.poll();
        }
        logger.info("Host enforcement {} {} via {} [{}]", result.action, result.ip, result.backend, result.status);
        return result;
    }

    private boolean executeCommands(List<List<String>> commands) {
        boolean success = true;
        for (List<String> command : commands) {
            ProcessBuilder builder = new ProcessBuilder(command);
            builder.redirectErrorStream(true);
            try {
                Process process = builder.start();
                int exitCode = process.waitFor();
                if (exitCode != 0) {
                    success = false;
                    logger.warn("Host enforcement command failed: {}", String.join(" ", command));
                }
            } catch (IOException | InterruptedException e) {
                success = false;
                logger.warn("Host enforcement execution error: {}", e.getMessage());
                Thread.currentThread().interrupt();
            }
        }
        return success;
    }

    private HostFirewallAdapter resolveAdapter() {
        String preferred = config.getSecurity().getHostEnforcement().getPreferredBackend();
        if ("ufw".equalsIgnoreCase(preferred)) {
            return commandAvailable("ufw") ? new UfwAdapter() : new NoopAdapter();
        }
        if ("iptables".equalsIgnoreCase(preferred)) {
            return commandAvailable("iptables") ? new IptablesAdapter() : new NoopAdapter();
        }
        if (commandAvailable("ufw")) {
            return new UfwAdapter();
        }
        if (commandAvailable("iptables")) {
            return new IptablesAdapter();
        }
        return new NoopAdapter();
    }

    private boolean commandAvailable(String binary) {
        try {
            Process process = new ProcessBuilder("sh", "-lc", "command -v " + binary).start();
            return process.waitFor() == 0;
        } catch (IOException | InterruptedException e) {
            Thread.currentThread().interrupt();
            return false;
        }
    }

    private boolean isEnabled() {
        return config.getSecurity().getHostEnforcement().isEnabled();
    }

    private boolean isDryRunEnabled() {
        return !isEnabled() || config.getSecurity().getHostEnforcement().isDryRun();
    }

    private String normalizeIp(String ip) {
        if (ip == null) {
            return null;
        }
        String normalized = ip.trim();
        if (normalized.isEmpty() || !IP_PATTERN.matcher(normalized).matches()) {
            return null;
        }
        return normalized;
    }

    private interface HostFirewallAdapter {
        String getName();
        List<List<String>> buildBlockCommands(String ip);
        List<List<String>> buildReleaseCommands(String ip, String mode);
        List<List<String>> buildRateLimitCommands(String ip, int limitPerMinute);
        List<String> previewBlockCommands(String ip);
        List<String> previewReleaseCommands(String ip, String mode);
        List<String> previewRateLimitCommands(String ip, int limitPerMinute);
    }

    private static final class UfwAdapter implements HostFirewallAdapter {
        @Override
        public String getName() {
            return "ufw";
        }

        @Override
        public List<List<String>> buildBlockCommands(String ip) {
            return List.of(List.of("sudo", "ufw", "deny", "from", ip));
        }

        @Override
        public List<List<String>> buildReleaseCommands(String ip, String mode) {
            return List.of(List.of("sudo", "ufw", "delete", "deny", "from", ip));
        }

        @Override
        public List<List<String>> buildRateLimitCommands(String ip, int limitPerMinute) {
            return List.of(List.of("sudo", "ufw", "limit", "from", ip));
        }

        @Override
        public List<String> previewBlockCommands(String ip) {
            return List.of("sudo ufw deny from " + ip);
        }

        @Override
        public List<String> previewReleaseCommands(String ip, String mode) {
            return List.of("sudo ufw delete deny from " + ip);
        }

        @Override
        public List<String> previewRateLimitCommands(String ip, int limitPerMinute) {
            return List.of("sudo ufw limit from " + ip + " # ~" + limitPerMinute + "/min");
        }
    }

    private static final class IptablesAdapter implements HostFirewallAdapter {
        @Override
        public String getName() {
            return "iptables";
        }

        @Override
        public List<List<String>> buildBlockCommands(String ip) {
            return List.of(List.of("sudo", "iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"));
        }

        @Override
        public List<List<String>> buildReleaseCommands(String ip, String mode) {
            if ("RATE_LIMIT".equalsIgnoreCase(mode)) {
                return List.of(List.of("sudo", "iptables", "-D", "INPUT", "-s", ip, "-m", "limit", "--limit", "1/second", "-j", "ACCEPT"));
            }
            return List.of(List.of("sudo", "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"));
        }

        @Override
        public List<List<String>> buildRateLimitCommands(String ip, int limitPerMinute) {
            String rate = Math.max(1, limitPerMinute) + "/minute";
            return List.of(
                List.of("sudo", "iptables", "-I", "INPUT", "-s", ip, "-m", "limit", "--limit", rate, "-j", "ACCEPT"),
                List.of("sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP")
            );
        }

        @Override
        public List<String> previewBlockCommands(String ip) {
            return List.of("sudo iptables -I INPUT -s " + ip + " -j DROP");
        }

        @Override
        public List<String> previewReleaseCommands(String ip, String mode) {
            if ("RATE_LIMIT".equalsIgnoreCase(mode)) {
                return List.of("sudo iptables -D INPUT -s " + ip + " -m limit --limit 1/second -j ACCEPT");
            }
            return List.of("sudo iptables -D INPUT -s " + ip + " -j DROP");
        }

        @Override
        public List<String> previewRateLimitCommands(String ip, int limitPerMinute) {
            String rate = Math.max(1, limitPerMinute) + "/minute";
            return List.of(
                "sudo iptables -I INPUT -s " + ip + " -m limit --limit " + rate + " -j ACCEPT",
                "sudo iptables -A INPUT -s " + ip + " -j DROP"
            );
        }
    }

    private static final class NoopAdapter implements HostFirewallAdapter {
        @Override
        public String getName() {
            return "noop";
        }

        @Override
        public List<List<String>> buildBlockCommands(String ip) {
            return Collections.emptyList();
        }

        @Override
        public List<List<String>> buildReleaseCommands(String ip, String mode) {
            return Collections.emptyList();
        }

        @Override
        public List<List<String>> buildRateLimitCommands(String ip, int limitPerMinute) {
            return Collections.emptyList();
        }

        @Override
        public List<String> previewBlockCommands(String ip) {
            return List.of("noop block " + ip);
        }

        @Override
        public List<String> previewReleaseCommands(String ip, String mode) {
            return List.of("noop release " + ip);
        }

        @Override
        public List<String> previewRateLimitCommands(String ip, int limitPerMinute) {
            return List.of("noop rate-limit " + ip + " " + limitPerMinute + "/minute");
        }
    }

    public static class ManagedRule {
        private final String ip;
        private final String mode;
        private final String reason;
        private final int durationMinutes;
        private final int limitPerMinute;
        private final long createdAt;
        private final long expiresAt;
        private final String backend;

        public ManagedRule(String ip, String mode, String reason, int durationMinutes, int limitPerMinute, long expiresAt, String backend) {
            this.ip = ip;
            this.mode = mode;
            this.reason = reason;
            this.durationMinutes = durationMinutes;
            this.limitPerMinute = limitPerMinute;
            this.createdAt = System.currentTimeMillis();
            this.expiresAt = expiresAt;
            this.backend = backend;
        }

        public String getKey() {
            return ip + ":" + mode;
        }

        public String getIp() { return ip; }
        public String getMode() { return mode; }
        public String getReason() { return reason; }
        public int getDurationMinutes() { return durationMinutes; }
        public int getLimitPerMinute() { return limitPerMinute; }
        public long getCreatedAt() { return createdAt; }
        public long getExpiresAt() { return expiresAt; }
        public String getBackend() { return backend; }
    }

    public static class EnforcementActionResult {
        private final boolean success;
        private final String action;
        private final String backend;
        private final boolean dryRun;
        private final String status;
        private final List<String> commands;
        private final String reason;
        private final String ip;
        private final int durationMinutes;
        private final int limitPerMinute;
        private final long timestamp;

        public EnforcementActionResult(boolean success, String action, String backend, boolean dryRun, String status,
                                       List<String> commands, String reason, String ip, int durationMinutes, int limitPerMinute) {
            this.success = success;
            this.action = action;
            this.backend = backend;
            this.dryRun = dryRun;
            this.status = status;
            this.commands = commands;
            this.reason = reason;
            this.ip = ip;
            this.durationMinutes = durationMinutes;
            this.limitPerMinute = limitPerMinute;
            this.timestamp = Instant.now().toEpochMilli();
        }

        public boolean isSuccess() { return success; }
        public String getAction() { return action; }
        public String getBackend() { return backend; }
        public boolean isDryRun() { return dryRun; }
        public String getStatus() { return status; }
        public List<String> getCommands() { return commands; }
        public String getReason() { return reason; }
        public String getIp() { return ip; }
        public int getDurationMinutes() { return durationMinutes; }
        public int getLimitPerMinute() { return limitPerMinute; }
        public long getTimestamp() { return timestamp; }
    }
}
