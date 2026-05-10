package com.aluer.security;

import com.aluer.config.ServerGuardConfig;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;

@Service
public class PluginVerificationService {

    private final ServerGuardConfig config;

    private final Map<String, PluginBaseline> pluginBaselines = new ConcurrentHashMap<>();
    private final Map<String, Long> pluginFileSizes = new ConcurrentHashMap<>();
    private final Map<String, String> pluginLastHashes = new ConcurrentHashMap<>();
    private final Map<String, List<Long>> pluginSizeHistory = new ConcurrentHashMap<>();
    private final ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor();

    private final AtomicLong totalVerifications = new AtomicLong(0);
    private final AtomicLong totalPassed = new AtomicLong(0);
    private final AtomicLong totalFailed = new AtomicLong(0);

    private static final int SIZE_ANOMALY_FACTOR = 3;
    private static final long CACHE_CLEANUP_INTERVAL_MS = 3600000;

    private static final Set<String> KNOWN_MALICIOUS_PLUGINS = Set.of(
            "Wurst", "Impact", "Meteor", "Aristois", "LiquidBounce",
            "Future", "Rusherhack", "Phobos", "Konas", "Pyro",
            "XRay", "ChestESP", "PlayerESP", "Tracers", "AutoFish",
            "KillAura", "FlyHack", "SpeedHack", "NoFall", "AutoTool",
            "AutoArmor", "ChestSteal", "ScaffoldWalk", "CriticalHack", "BunnyHop"
    );

    public PluginVerificationService() {
        this(new ServerGuardConfig());
    }

    @Autowired
    public PluginVerificationService(ServerGuardConfig config) {
        this.config = config;
        scheduler.scheduleAtFixedRate(this::cleanupOldData, 120, 300, TimeUnit.SECONDS);
    }

    public void registerPlugin(String name, String filePath, String expectedHash) {
        if (name == null || filePath == null || expectedHash == null) {
            return;
        }
        PluginBaseline baseline = new PluginBaseline(name, filePath, expectedHash);
        pluginBaselines.put(name, baseline);
        pluginLastHashes.put(name, expectedHash);
    }

    public VerificationResult verifyPlugin(String name) {
        totalVerifications.incrementAndGet();

        if (!config.getSecurity().getSuperEvolution().isPluginVerification()) {
            return VerificationResult.passed();
        }

        PluginBaseline baseline = pluginBaselines.get(name);
        if (baseline == null) {
            return VerificationResult.unknown();
        }

        // Compute current hash of the plugin file
        String currentHash = computeFileHash(baseline.filePath);
        if (currentHash == null) {
            totalFailed.incrementAndGet();
            return VerificationResult.failed(List.of("Cannot read plugin file: " + baseline.filePath));
        }

        pluginLastHashes.put(name, currentHash);

        // Compare with baseline
        if (!currentHash.equalsIgnoreCase(baseline.expectedHash)) {
            totalFailed.incrementAndGet();
            return VerificationResult.failed(List.of(
                    "Hash mismatch for " + name + ": expected " + baseline.expectedHash + " but got " + currentHash));
        }

        totalPassed.incrementAndGet();
        return VerificationResult.passed();
    }

    public Map<String, VerificationResult> verifyAllPlugins() {
        Map<String, VerificationResult> results = new LinkedHashMap<>();

        if (!config.getSecurity().getSuperEvolution().isPluginVerification()) {
            return results;
        }

        for (String name : pluginBaselines.keySet()) {
            results.put(name, verifyPlugin(name));
        }
        return results;
    }

    public VerificationResult scanPluginName(String name) {
        if (name == null) {
            return VerificationResult.unknown();
        }

        List<String> reasons = new ArrayList<>();

        // Check against known malicious plugin names
        for (String malicious : KNOWN_MALICIOUS_PLUGINS) {
            if (name.toLowerCase().contains(malicious.toLowerCase())) {
                reasons.add("KNOWN_MALICIOUS_PLUGIN: " + name + " matches known cheat/hacked client: " + malicious);
            }
        }

        // Check for suspicious naming patterns
        String lower = name.toLowerCase();
        if (lower.contains("hack") || lower.contains("cheat") || lower.contains("exploit")
                || lower.contains("inject") || lower.contains("bypass") || lower.contains("crack")) {
            reasons.add("SUSPICIOUS_PLUGIN_NAME: " + name + " contains suspicious keywords");
        }

        if (!reasons.isEmpty()) {
            return VerificationResult.failed(reasons);
        }

        return VerificationResult.passed();
    }

    public boolean checkFileSizeAnomaly(String name, long currentSize) {
        Long previousSize = pluginFileSizes.get(name);
        if (previousSize == null) {
            pluginFileSizes.put(name, currentSize);
            return false;
        }

        // Record in history
        pluginSizeHistory.computeIfAbsent(name, k -> new ArrayList<>()).add(currentSize);
        List<Long> history = pluginSizeHistory.get(name);
        if (history.size() > 20) {
            history.remove(0);
        }

        // Calculate average size
        double avg = history.stream().mapToLong(Long::longValue).average().orElse(currentSize);

        // Check if size deviates significantly
        boolean anomaly = currentSize > avg * SIZE_ANOMALY_FACTOR || currentSize < avg / SIZE_ANOMALY_FACTOR;
        pluginFileSizes.put(name, currentSize);
        return anomaly;
    }

    public boolean checkJarStructure(String filePath) {
        if (filePath == null) return false;
        String lower = filePath.toLowerCase();
        return lower.endsWith(".jar");
    }

    public void updateBaseline(String name, String newHash) {
        PluginBaseline baseline = pluginBaselines.get(name);
        if (baseline != null) {
            baseline.expectedHash = newHash;
            pluginLastHashes.put(name, newHash);
        }
    }

    public void removePlugin(String name) {
        pluginBaselines.remove(name);
        pluginFileSizes.remove(name);
        pluginLastHashes.remove(name);
        pluginSizeHistory.remove(name);
    }

    public PluginBaseline getPluginBaseline(String name) {
        return pluginBaselines.get(name);
    }

    public Map<String, Object> getStatus() {
        Map<String, Object> status = new LinkedHashMap<>();
        status.put("enabled", config.getSecurity().getSuperEvolution().isPluginVerification());
        status.put("registeredPlugins", pluginBaselines.size());
        status.put("totalVerifications", totalVerifications.get());
        status.put("totalPassed", totalPassed.get());
        status.put("totalFailed", totalFailed.get());
        status.put("knownMaliciousCount", KNOWN_MALICIOUS_PLUGINS.size());

        List<Map<String, Object>> plugins = new ArrayList<>();
        for (Map.Entry<String, PluginBaseline> e : pluginBaselines.entrySet()) {
            Map<String, Object> p = new LinkedHashMap<>();
            p.put("name", e.getKey());
            p.put("filePath", e.getValue().filePath);
            p.put("expectedHash", e.getValue().expectedHash);
            p.put("lastHash", pluginLastHashes.get(e.getKey()));
            p.put("lastFileSize", pluginFileSizes.get(e.getKey()));
            plugins.add(p);
        }
        status.put("registeredPluginList", plugins);
        return status;
    }

    public long getTotalVerifications() { return totalVerifications.get(); }
    public long getTotalPassed() { return totalPassed.get(); }
    public long getTotalFailed() { return totalFailed.get(); }

    public static Set<String> getKnownMaliciousPlugins() {
        return new HashSet<>(KNOWN_MALICIOUS_PLUGINS);
    }

    private String computeFileHash(String filePath) {
        // Simulated hash computation - in production this would read the actual file
        // Returns a deterministic hash based on file path for demonstration purposes
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(filePath.getBytes());
            StringBuilder sb = new StringBuilder();
            for (byte b : digest) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            return null;
        }
    }

    private void cleanupOldData() {
        long cutoff = System.currentTimeMillis() - CACHE_CLEANUP_INTERVAL_MS;

        // Prune size history for plugins no longer registered
        pluginSizeHistory.keySet().retainAll(pluginBaselines.keySet());

        // Limit size history entries per plugin
        for (List<Long> history : pluginSizeHistory.values()) {
            while (history.size() > 20) {
                history.remove(0);
            }
        }
    }

    public static class PluginBaseline {
        public final String name;
        public final String filePath;
        public volatile String expectedHash;

        public PluginBaseline(String name, String filePath, String expectedHash) {
            this.name = name;
            this.filePath = filePath;
            this.expectedHash = expectedHash;
        }
    }

    public static class VerificationResult {
        private final boolean passed;
        private final boolean failed;
        private final boolean unknown;
        private final List<String> reasons;

        private VerificationResult(boolean passed, boolean failed, boolean unknown, List<String> reasons) {
            this.passed = passed;
            this.failed = failed;
            this.unknown = unknown;
            this.reasons = reasons;
        }

        public static VerificationResult passed() {
            return new VerificationResult(true, false, false, List.of());
        }

        public static VerificationResult failed(List<String> reasons) {
            return new VerificationResult(false, true, false, reasons);
        }

        public static VerificationResult unknown() {
            return new VerificationResult(false, false, true, List.of());
        }

        public boolean isPassed() { return passed; }
        public boolean isFailed() { return failed; }
        public boolean isUnknown() { return unknown; }
        public List<String> getReasons() { return reasons; }
    }
}
