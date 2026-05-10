package com.aluer.security;

import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

@Service
public class IncidentResponseService {

    private final Map<String, Incident> activeIncidents = new ConcurrentHashMap<>();
    private final Map<String, List<ResponseAction>> actionLog = new ConcurrentHashMap<>();
    private final AtomicLong totalIncidents = new AtomicLong(0);
    private final AtomicLong totalActions = new AtomicLong(0);

    private static final Map<String, ResponsePlaybook> PLAYBOOKS = new LinkedHashMap<>();

    static {
        PLAYBOOKS.put("DDOS_ATTACK", new ResponsePlaybook("DDoS Attack Response", List.of(
                new PlayAction("ENABLE_RATE_LIMITING", "Activate aggressive rate limiting on all endpoints", 0),
                new PlayAction("BLOCK_TOP_OFFENDERS", "Block top 10 attacking IPs via firewall", 30),
                new PlayAction("ENABLE_CDN_CHALLENGE", "Switch Cloudflare to 'Under Attack' mode", 60),
                new PlayAction("SCALE_RESOURCES", "Increase connection pool and thread limits", 120),
                new PlayAction("NOTIFY_ADMIN", "Send critical alert to administrators", 0)
        ), IncidentSeverity.CRITICAL));

        PLAYBOOKS.put("BRUTE_FORCE", new ResponsePlaybook("Brute Force Response", List.of(
                new PlayAction("LOCK_ACCOUNT", "Temporarily lock targeted account", 0),
                new PlayAction("BLOCK_SOURCE_IP", "Block attacking IP for 30 minutes", 10),
                new PlayAction("ENABLE_CAPTCHA", "Enable CAPTCHA for login endpoints", 60),
                new PlayAction("INCREASE_DELAY", "Increase progressive delay to maximum", 0),
                new PlayAction("LOG_FORENSICS", "Collect forensics data for investigation", 120)
        ), IncidentSeverity.HIGH));

        PLAYBOOKS.put("INTRUSION_DETECTED", new ResponsePlaybook("Intrusion Response", List.of(
                new PlayAction("ISOLATE_AFFECTED", "Isolate affected components immediately", 0),
                new PlayAction("COLLECT_EVIDENCE", "Start forensics evidence collection", 10),
                new PlayAction("BLOCK_INDICATORS", "Block all identified IOCs", 30),
                new PlayAction("RESTORE_BACKUP", "Restore from last known good backup", 300),
                new PlayAction("PATCH_VULNERABILITY", "Apply security patches if applicable", 600),
                new PlayAction("FULL_AUDIT", "Perform complete security audit", 1800)
        ), IncidentSeverity.CRITICAL));

        PLAYBOOKS.put("MINECRAFT_EXPLOIT", new ResponsePlaybook("Minecraft Exploit Response", List.of(
                new PlayAction("KICK_EXPLOITER", "Kick player identified as exploit source", 0),
                new PlayAction("BAN_IP", "Ban exploit source IP in firewall", 5),
                new PlayAction("ENABLE_WHITELIST", "Temporarily enable server whitelist", 15),
                new PlayAction("CHECK_PLUGINS", "Verify plugin integrity", 60),
                new PlayAction("SCAN_LOGS", "Full log analysis for exploit patterns", 120)
        ), IncidentSeverity.HIGH));

        PLAYBOOKS.put("DATA_BREACH", new ResponsePlaybook("Data Breach Response", List.of(
                new PlayAction("REVOKE_TOKENS", "Revoke all active API tokens and sessions", 0),
                new PlayAction("ROTATE_KEYS", "Rotate all API keys and passwords", 60),
                new PlayAction("NOTIFY_USERS", "Send breach notification to affected users", 300),
                new PlayAction("AUDIT_ACCESS", "Audit all recent access logs", 120),
                new PlayAction("ENGAGE_LEGAL", "Engage legal/compliance team", 3600)
        ), IncidentSeverity.CRITICAL));
    }

    public Incident declareIncident(String type, String description, String source, IncidentSeverity severity) {
        String incidentId = "INC-" + Instant.now().getEpochSecond() + "-" + randomHex(4);
        ResponsePlaybook playbook = PLAYBOOKS.getOrDefault(type, null);
        Incident incident = new Incident(incidentId, type, description, source, severity, playbook, Instant.now());
        activeIncidents.put(incidentId, incident);
        totalIncidents.incrementAndGet();

        if (playbook != null) {
            for (PlayAction action : playbook.actions) {
                executeAction(incidentId, action);
            }
        }
        return incident;
    }

    public ResponseAction executeAction(String incidentId, PlayAction action) {
        ResponseAction executed = new ResponseAction(action, Instant.now());
        actionLog.computeIfAbsent(incidentId, k -> new ArrayList<>()).add(executed);
        totalActions.incrementAndGet();
        return executed;
    }

    public Incident resolveIncident(String incidentId, String resolution) {
        Incident incident = activeIncidents.remove(incidentId);
        if (incident != null) {
            incident.resolve(resolution);
        }
        return incident;
    }

    public Map<String, Object> getStatus() {
        Map<String, Object> status = new LinkedHashMap<>();
        status.put("activeIncidents", activeIncidents.size());
        status.put("totalIncidents", totalIncidents.get());
        status.put("totalActions", totalActions.get());
        status.put("playbooksAvailable", PLAYBOOKS.keySet());

        List<Map<String, Object>> incidents = new ArrayList<>();
        for (Incident inc : activeIncidents.values()) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("id", inc.incidentId);
            m.put("type", inc.type);
            m.put("severity", inc.severity.name());
            m.put("description", inc.description);
            m.put("source", inc.source);
            m.put("declaredTime", inc.declaredTime.toString());
            m.put("actionsTaken", actionLog.getOrDefault(inc.incidentId, List.of()).size());
            incidents.add(m);
        }
        status.put("incidents", incidents);

        List<String> playbookNames = new ArrayList<>();
        for (Map.Entry<String, ResponsePlaybook> e : PLAYBOOKS.entrySet()) {
            playbookNames.add(e.getKey() + ": " + e.getValue().name + " (" + e.getValue().actions.size() + " actions)");
        }
        status.put("playbooks", playbookNames);
        return status;
    }

    public long getTotalIncidents() { return totalIncidents.get(); }
    public long getTotalActions() { return totalActions.get(); }

    private String randomHex(int len) {
        byte[] bytes = new byte[len];
        new Random().nextBytes(bytes);
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) sb.append(String.format("%02x", b));
        return sb.toString();
    }

    public enum IncidentSeverity { LOW, MEDIUM, HIGH, CRITICAL }

    public static class ResponsePlaybook {
        public final String name;
        public final List<PlayAction> actions;
        public final IncidentSeverity defaultSeverity;

        ResponsePlaybook(String name, List<PlayAction> actions, IncidentSeverity defaultSeverity) {
            this.name = name;
            this.actions = actions;
            this.defaultSeverity = defaultSeverity;
        }
    }

    public static class PlayAction {
        public final String name;
        public final String description;
        public final int delaySeconds;

        public PlayAction(String name, String description, int delaySeconds) {
            this.name = name;
            this.description = description;
            this.delaySeconds = delaySeconds;
        }
    }

    public static class Incident {
        public final String incidentId;
        public final String type;
        public final String description;
        public final String source;
        public final IncidentSeverity severity;
        public final ResponsePlaybook playbook;
        public final Instant declaredTime;
        public Instant resolvedTime;
        public String resolution;
        public boolean resolved;

        Incident(String incidentId, String type, String description, String source,
                 IncidentSeverity severity, ResponsePlaybook playbook, Instant declaredTime) {
            this.incidentId = incidentId;
            this.type = type;
            this.description = description;
            this.source = source;
            this.severity = severity;
            this.playbook = playbook;
            this.declaredTime = declaredTime;
        }

        void resolve(String resolution) {
            this.resolution = resolution;
            this.resolvedTime = Instant.now();
            this.resolved = true;
        }
    }

    public static class ResponseAction {
        public final PlayAction action;
        public final Instant executedTime;

        ResponseAction(PlayAction action, Instant executedTime) {
            this.action = action;
            this.executedTime = executedTime;
        }
    }
}
