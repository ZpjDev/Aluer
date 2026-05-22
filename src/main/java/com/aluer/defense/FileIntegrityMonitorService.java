package com.aluer.defense;

import com.aluer.config.ServerGuardConfig;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.PathMatcher;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;

@Service
public class FileIntegrityMonitorService {
    private final ServerGuardConfig config;
    private final Map<String, String> baselineHashes = new ConcurrentHashMap<>();
    private final ConcurrentLinkedQueue<IntegrityAlert> alerts = new ConcurrentLinkedQueue<>();
    private volatile long lastScanTime = 0L;

    public FileIntegrityMonitorService() {
        this(new ServerGuardConfig());
    }

    @Autowired
    public FileIntegrityMonitorService(ServerGuardConfig config) {
        this.config = config;
    }

    public synchronized Map<String, Object> scanNow() {
        if (!config.getSecurity().getAntiIntrusion().getFileIntegrity().isEnabled()) {
            return Map.of("enabled", false, "trackedFiles", baselineHashes.size(), "alerts", 0);
        }

        Map<String, String> currentHashes = collectCurrentHashes();
        int newAlerts = 0;

        if (baselineHashes.isEmpty()) {
            baselineHashes.putAll(currentHashes);
        } else {
            for (Map.Entry<String, String> entry : currentHashes.entrySet()) {
                String oldHash = baselineHashes.get(entry.getKey());
                if (oldHash == null) {
                    alerts.offer(new IntegrityAlert("CREATED", entry.getKey(), "New monitored file discovered", Instant.now().toEpochMilli()));
                    newAlerts++;
                } else if (!oldHash.equals(entry.getValue())) {
                    alerts.offer(new IntegrityAlert("MODIFIED", entry.getKey(), "File hash changed", Instant.now().toEpochMilli()));
                    newAlerts++;
                }
            }

            for (String tracked : new ArrayList<>(baselineHashes.keySet())) {
                if (!currentHashes.containsKey(tracked)) {
                    alerts.offer(new IntegrityAlert("DELETED", tracked, "Monitored file disappeared", Instant.now().toEpochMilli()));
                    newAlerts++;
                }
            }

            baselineHashes.clear();
            baselineHashes.putAll(currentHashes);
        }

        trimAlerts();
        lastScanTime = System.currentTimeMillis();

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("enabled", true);
        result.put("trackedFiles", baselineHashes.size());
        result.put("newAlerts", newAlerts);
        result.put("lastScanTime", lastScanTime);
        return result;
    }

    public synchronized Map<String, Object> rebuildBaseline() {
        baselineHashes.clear();
        Map<String, String> hashes = collectCurrentHashes();
        baselineHashes.putAll(hashes);
        lastScanTime = System.currentTimeMillis();

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("baselineFiles", baselineHashes.size());
        result.put("lastScanTime", lastScanTime);
        return result;
    }

    public Map<String, Object> getBaselineStatus() {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("enabled", config.getSecurity().getAntiIntrusion().getFileIntegrity().isEnabled());
        result.put("trackedFiles", baselineHashes.size());
        result.put("alerts", alerts.size());
        result.put("lastScanTime", lastScanTime);
        result.put("paths", config.getSecurity().getAntiIntrusion().getFileIntegrity().getMonitoredPaths());
        return result;
    }

    public List<IntegrityAlert> getRecentAlerts(int limit) {
        List<IntegrityAlert> result = new ArrayList<>();
        int count = 0;
        for (IntegrityAlert alert : alerts) {
            if (count++ >= limit) {
                break;
            }
            result.add(alert);
        }
        result.sort(Comparator.comparingLong(IntegrityAlert::getTimestamp).reversed());
        return result;
    }

    private Map<String, String> collectCurrentHashes() {
        Map<String, String> hashes = new HashMap<>();
        for (String configuredPath : config.getSecurity().getAntiIntrusion().getFileIntegrity().getMonitoredPaths()) {
            hashes.putAll(resolvePathHashes(configuredPath));
        }
        return hashes;
    }

    private Map<String, String> resolvePathHashes(String configuredPath) {
        Map<String, String> hashes = new HashMap<>();
        Path path = Paths.get(configuredPath);

        try {
            if (configuredPath.contains("*")) {
                Path parent = path.getParent();
                if (parent != null && Files.isDirectory(parent)) {
                    PathMatcher matcher = FileSystems.getDefault().getPathMatcher("glob:" + configuredPath);
                    try (var stream = Files.walk(parent, 1)) {
                        stream.filter(Files::isRegularFile)
                            .filter(matcher::matches)
                            .forEach(file -> hashes.put(file.toString(), sha256(file)));
                    }
                }
                return hashes;
            }

            if (Files.isDirectory(path)) {
                int maxDepth = config.getSecurity().getAntiIntrusion().getFileIntegrity().getMaxDepth();
                try (var stream = Files.walk(path, maxDepth)) {
                    stream.filter(Files::isRegularFile)
                        .forEach(file -> hashes.put(file.toString(), sha256(file)));
                }
            } else if (Files.isRegularFile(path)) {
                hashes.put(path.toString(), sha256(path));
            }
        } catch (IOException ignored) {
        }

        return hashes;
    }

    private String sha256(Path file) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] bytes = Files.readAllBytes(file);
            byte[] hash = digest.digest(bytes);
            StringBuilder hex = new StringBuilder();
            for (byte b : hash) {
                hex.append(String.format("%02x", b));
            }
            return hex.toString();
        } catch (IOException | NoSuchAlgorithmException e) {
            return "unavailable";
        }
    }

    private void trimAlerts() {
        while (alerts.size() > 1000) {
            alerts.poll();
        }
    }

    public static class IntegrityAlert {
        private final String type;
        private final String path;
        private final String details;
        private final long timestamp;

        public IntegrityAlert(String type, String path, String details, long timestamp) {
            this.type = type;
            this.path = path;
            this.details = details;
            this.timestamp = timestamp;
        }

        public String getType() { return type; }
        public String getPath() { return path; }
        public String getDetails() { return details; }
        public long getTimestamp() { return timestamp; }
    }
}
