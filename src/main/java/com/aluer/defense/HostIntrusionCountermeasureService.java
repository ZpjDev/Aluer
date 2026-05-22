package com.aluer.defense;

import com.aluer.config.ServerGuardConfig;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentLinkedQueue;

@Service
public class HostIntrusionCountermeasureService {
    private final ServerGuardConfig config;
    private final EndpointDetectionResponseService endpointDetectionResponseService;
    private final AdvancedMalwareDetectionService advancedMalwareDetectionService;
    private final IntrusionDetectionService intrusionDetectionService;
    private final FileIntegrityMonitorService fileIntegrityMonitorService;
    private final CommandExecutionGuardService commandExecutionGuardService;
    private final ConcurrentLinkedQueue<HostIntrusionIncident> incidents = new ConcurrentLinkedQueue<>();

    public HostIntrusionCountermeasureService() {
        this(new ServerGuardConfig(), new EndpointDetectionResponseService(), new AdvancedMalwareDetectionService(),
            new IntrusionDetectionService(), new FileIntegrityMonitorService(), new CommandExecutionGuardService());
    }

    @Autowired
    public HostIntrusionCountermeasureService(ServerGuardConfig config,
                                              EndpointDetectionResponseService endpointDetectionResponseService,
                                              AdvancedMalwareDetectionService advancedMalwareDetectionService,
                                              IntrusionDetectionService intrusionDetectionService,
                                              FileIntegrityMonitorService fileIntegrityMonitorService,
                                              CommandExecutionGuardService commandExecutionGuardService) {
        this.config = config;
        this.endpointDetectionResponseService = endpointDetectionResponseService;
        this.advancedMalwareDetectionService = advancedMalwareDetectionService;
        this.intrusionDetectionService = intrusionDetectionService;
        this.fileIntegrityMonitorService = fileIntegrityMonitorService;
        this.commandExecutionGuardService = commandExecutionGuardService;
    }

    public HostIntrusionIncident analyzeCommand(String actor, String command, String source) {
        CommandExecutionGuardService.AntiIntrusionIncident incident = commandExecutionGuardService.analyzeCommand(actor, command, source);
        if (incident == null) {
            return null;
        }
        HostIntrusionIncident hostIncident = new HostIntrusionIncident(
            incident.getType(),
            "COMMAND",
            incident.getSeverity(),
            actor,
            source,
            incident.getEvidence(),
            incident.getTimestamp()
        );
        record(hostIncident);
        return hostIncident;
    }

    public HostIntrusionIncident analyzeProcess(String processName, String source) {
        if (!config.getSecurity().getAntiIntrusion().isMonitorProcesses()) {
            return null;
        }

        String normalized = processName == null ? "" : processName.toLowerCase(Locale.ROOT);
        intrusionDetectionService.checkProcessActivity("system", processName, true);

        if (!(normalized.contains("curl")
            || normalized.contains("wget")
            || normalized.contains("nc ")
            || normalized.contains("socat")
            || normalized.contains("xmrig")
            || normalized.contains("python -c")
            || normalized.contains("bash -c"))) {
            return null;
        }

        HostIntrusionIncident incident = new HostIntrusionIncident(
            "SUSPICIOUS_PROCESS",
            "PROCESS",
            88,
            "system",
            source,
            processName,
            Instant.now().toEpochMilli()
        );
        record(incident);
        return incident;
    }

    public HostIntrusionIncident analyzeFile(String path) {
        if (!config.getSecurity().getAntiIntrusion().isMonitorFiles()) {
            return null;
        }

        Path target = Paths.get(path);
        if (!Files.exists(target) || !Files.isRegularFile(target)) {
            return null;
        }

        try {
            byte[] content = Files.readAllBytes(target);
            String hash = sha256(content);
            AdvancedMalwareDetectionService.ScanResult scanResult = advancedMalwareDetectionService.scanFile(target.getFileName().toString(), content, hash);
            if (scanResult.isThreatDetected()) {
                HostIntrusionIncident incident = new HostIntrusionIncident(
                    "MALWARE_OR_BACKDOOR",
                    "FILE",
                    severityToScore(scanResult.getThreatSeverity()),
                    "system",
                    path,
                    scanResult.getThreatName() + ": " + scanResult.getThreatDescription(),
                    Instant.now().toEpochMilli()
                );
                intrusionDetectionService.checkFileAccess("system", path, "scan");
                record(incident);
                return incident;
            }
        } catch (IOException e) {
            return new HostIntrusionIncident("FILE_SCAN_ERROR", "FILE", 50, "system", path, e.getMessage(), Instant.now().toEpochMilli());
        }

        return null;
    }

    public Map<String, Object> runFullScan() {
        Map<String, Object> integrity = fileIntegrityMonitorService.scanNow();
        List<HostIntrusionIncident> detected = new ArrayList<>();

        if (config.getSecurity().getAntiIntrusion().isMonitorPlugins()) {
            for (String file : discoverPluginFiles()) {
                HostIntrusionIncident incident = analyzeFile(file);
                if (incident != null) {
                    detected.add(incident);
                }
            }
        }

        for (FileIntegrityMonitorService.IntegrityAlert alert : fileIntegrityMonitorService.getRecentAlerts(20)) {
            record(new HostIntrusionIncident(
                "FILE_INTEGRITY_" + alert.getType(),
                "INTEGRITY",
                82,
                "integrity-monitor",
                alert.getPath(),
                alert.getDetails(),
                alert.getTimestamp()
            ));
        }

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("integrity", integrity);
        result.put("detectedIncidents", detected.size());
        result.put("recentIncidents", getRecentIncidents(10));
        return result;
    }

    public Map<String, Object> getPosture() {
        Map<String, Object> posture = new LinkedHashMap<>();
        posture.put("enabled", config.getSecurity().getAntiIntrusion().isEnabled());
        posture.put("recentIncidents", incidents.size());
        posture.put("criticalIncidents", incidents.stream().filter(incident -> incident.severity >= 90).count());
        posture.put("fileIntegrity", fileIntegrityMonitorService.getBaselineStatus());
        posture.put("commandGuard", commandExecutionGuardService.getStats());
        posture.put("edr", endpointDetectionResponseService.getStats());
        return posture;
    }

    public List<HostIntrusionIncident> getRecentIncidents(int limit) {
        List<HostIntrusionIncident> result = new ArrayList<>();
        int count = 0;
        for (HostIntrusionIncident incident : incidents) {
            if (count++ >= limit) {
                break;
            }
            result.add(incident);
        }
        result.sort(Comparator.comparingLong(HostIntrusionIncident::getTimestamp).reversed());
        return result;
    }

    public List<FileIntegrityMonitorService.IntegrityAlert> getIntegrityAlerts(int limit) {
        return fileIntegrityMonitorService.getRecentAlerts(limit);
    }

    private List<String> discoverPluginFiles() {
        List<String> files = new ArrayList<>();
        for (String configuredPath : config.getSecurity().getAntiIntrusion().getFileIntegrity().getMonitoredPaths()) {
            Path path = Paths.get(configuredPath);
            try {
                if (Files.isDirectory(path) && configuredPath.toLowerCase(Locale.ROOT).contains("plugins")) {
                    try (var stream = Files.walk(path, 2)) {
                        stream.filter(Files::isRegularFile).forEach(file -> files.add(file.toString()));
                    }
                } else if (Files.isRegularFile(path) && path.getFileName().toString().endsWith(".jar")) {
                    files.add(path.toString());
                }
            } catch (IOException ignored) {
            }
        }
        return files;
    }

    private void record(HostIntrusionIncident incident) {
        incidents.offer(incident);
        while (incidents.size() > 1000) {
            incidents.poll();
        }
    }

    private int severityToScore(String severity) {
        if (severity == null) {
            return 50;
        }
        return switch (severity.toUpperCase(Locale.ROOT)) {
            case "CRITICAL" -> 95;
            case "HIGH" -> 85;
            case "MEDIUM" -> 70;
            default -> 55;
        };
    }

    private String sha256(byte[] content) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(content);
            StringBuilder builder = new StringBuilder();
            for (byte b : hash) {
                builder.append(String.format("%02x", b));
            }
            return builder.toString();
        } catch (NoSuchAlgorithmException e) {
            return Integer.toHexString(content.length);
        }
    }

    public static class HostIntrusionIncident {
        private final String type;
        private final String category;
        private final int severity;
        private final String actor;
        private final String source;
        private final String details;
        private final long timestamp;

        public HostIntrusionIncident(String type, String category, int severity, String actor, String source, String details, long timestamp) {
            this.type = type;
            this.category = category;
            this.severity = severity;
            this.actor = actor;
            this.source = source;
            this.details = details;
            this.timestamp = timestamp;
        }

        public String getType() { return type; }
        public String getCategory() { return category; }
        public int getSeverity() { return severity; }
        public String getActor() { return actor; }
        public String getSource() { return source; }
        public String getDetails() { return details; }
        public long getTimestamp() { return timestamp; }
    }
}
