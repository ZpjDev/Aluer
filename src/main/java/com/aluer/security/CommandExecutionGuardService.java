package com.aluer.security;

import com.aluer.config.ServerGuardConfig;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentLinkedQueue;

@Service
public class CommandExecutionGuardService {
    private final ServerGuardConfig config;
    private final IntrusionDetectionService intrusionDetectionService;
    private final ConcurrentLinkedQueue<AntiIntrusionIncident> incidents = new ConcurrentLinkedQueue<>();

    public CommandExecutionGuardService() {
        this(new ServerGuardConfig(), new IntrusionDetectionService());
    }

    @Autowired
    public CommandExecutionGuardService(ServerGuardConfig config,
                                        IntrusionDetectionService intrusionDetectionService) {
        this.config = config;
        this.intrusionDetectionService = intrusionDetectionService;
    }

    public AntiIntrusionIncident analyzeCommand(String actor, String command, String source) {
        if (!config.getSecurity().getAntiIntrusion().isMonitorCommands()) {
            return null;
        }

        String normalized = command == null ? "" : command.toLowerCase(Locale.ROOT);
        String type = null;
        int severity = 0;

        if (normalized.contains("curl ") && normalized.contains("| sh")) {
            type = "REMOTE_SCRIPT_EXECUTION";
            severity = 95;
        } else if (normalized.contains("wget ") && normalized.contains("| bash")) {
            type = "DOWNLOADER_ABUSE";
            severity = 95;
        } else if (normalized.contains("systemctl ") || normalized.contains("service ")) {
            type = "SERVICE_ABUSE";
            severity = 85;
        } else if (normalized.contains("sudo ") || normalized.contains(" su ")) {
            type = "PRIVILEGE_ESCALATION";
            severity = 88;
        } else if (normalized.contains("../") || normalized.contains("..\\")) {
            type = "PATH_TRAVERSAL";
            severity = 80;
        } else if (normalized.contains("&&") || normalized.contains("||") || normalized.contains(";$")) {
            type = "CHAINED_COMMAND";
            severity = 70;
        } else if (normalized.contains("rcon-cli") && normalized.contains("op ")) {
            type = "RCON_PRIVILEGED_ACTION";
            severity = 92;
        } else if (normalized.contains("rm -rf") || normalized.contains("mkfs") || normalized.contains("dd if=")) {
            type = "DESTRUCTIVE_COMMAND";
            severity = 100;
        }

        if (type == null) {
            intrusionDetectionService.checkCommandExecution(actor == null ? "system" : actor, command);
            return null;
        }

        intrusionDetectionService.checkCommandExecution(actor == null ? "system" : actor, command);
        AntiIntrusionIncident incident = new AntiIntrusionIncident(type, severity, actor, source, command, Instant.now().toEpochMilli());
        incidents.offer(incident);
        trimIncidents();
        return incident;
    }

    public AntiIntrusionIncident analyzeRconCommand(String actor, String command, String sourceIp) {
        AntiIntrusionIncident incident = analyzeCommand(actor == null ? "rcon" : actor, command, sourceIp);
        if (incident != null) {
            incidents.offer(new AntiIntrusionIncident(
                "RCON_COMMAND_ABUSE",
                Math.max(incident.severity, 85),
                actor,
                sourceIp,
                command,
                Instant.now().toEpochMilli()
            ));
            trimIncidents();
        }
        return incident;
    }

    public List<AntiIntrusionIncident> getRecentIncidents(int limit) {
        List<AntiIntrusionIncident> result = new ArrayList<>();
        int count = 0;
        for (AntiIntrusionIncident incident : incidents) {
            if (count++ >= limit) {
                break;
            }
            result.add(incident);
        }
        result.sort(Comparator.comparingLong(AntiIntrusionIncident::getTimestamp).reversed());
        return result;
    }

    public Map<String, Object> getStats() {
        Map<String, Object> stats = new LinkedHashMap<>();
        stats.put("monitoringEnabled", config.getSecurity().getAntiIntrusion().isMonitorCommands());
        stats.put("recentIncidents", incidents.size());
        stats.put("criticalIncidents", incidents.stream().filter(incident -> incident.severity >= 90).count());
        return stats;
    }

    private void trimIncidents() {
        while (incidents.size() > 1000) {
            incidents.poll();
        }
    }

    public static class AntiIntrusionIncident {
        private final String type;
        private final int severity;
        private final String actor;
        private final String source;
        private final String evidence;
        private final long timestamp;

        public AntiIntrusionIncident(String type, int severity, String actor, String source, String evidence, long timestamp) {
            this.type = type;
            this.severity = severity;
            this.actor = actor;
            this.source = source;
            this.evidence = evidence;
            this.timestamp = timestamp;
        }

        public String getType() { return type; }
        public int getSeverity() { return severity; }
        public String getActor() { return actor; }
        public String getSource() { return source; }
        public String getEvidence() { return evidence; }
        public long getTimestamp() { return timestamp; }
    }
}
