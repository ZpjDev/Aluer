package com.aluer.security;

import com.aluer.config.ServerGuardConfig;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;

@Service
public class DDoSDefenseCoordinator {
    private static final long WINDOW_MS = 60_000L;

    private final ServerGuardConfig config;
    private final DDoSProtectionService ddosProtectionService;
    private final DistributedAttackMitigationService distributedAttackMitigationService;
    private final MinecraftProtocolSecurityService minecraftProtocolSecurityService;
    private final HostEnforcementService hostEnforcementService;

    private final Map<String, SlowConnectionTracker> slowConnections = new ConcurrentHashMap<>();
    private final ConcurrentLinkedQueue<DDoSIncidentSummary> incidents = new ConcurrentLinkedQueue<>();

    public DDoSDefenseCoordinator() {
        this(new ServerGuardConfig(), new DDoSProtectionService(), new DistributedAttackMitigationService(),
            new MinecraftProtocolSecurityService(), new HostEnforcementService());
    }

    @Autowired
    public DDoSDefenseCoordinator(ServerGuardConfig config,
                                  DDoSProtectionService ddosProtectionService,
                                  DistributedAttackMitigationService distributedAttackMitigationService,
                                  MinecraftProtocolSecurityService minecraftProtocolSecurityService,
                                  HostEnforcementService hostEnforcementService) {
        this.config = config;
        this.ddosProtectionService = ddosProtectionService;
        this.distributedAttackMitigationService = distributedAttackMitigationService;
        this.minecraftProtocolSecurityService = minecraftProtocolSecurityService;
        this.hostEnforcementService = hostEnforcementService;
    }

    public List<DDoSIncidentSummary> analyzeTraffic(String sourceIP, String destIP, int sourcePort, int destPort,
                                                    String protocol, byte[] payload) {
        if (!config.getSecurity().getDdosDefense().isEnabled()) {
            return List.of();
        }

        List<DDoSIncidentSummary> result = new ArrayList<>();
        int payloadSize = payload == null ? 0 : payload.length;
        String normalizedProtocol = protocol == null ? "TCP" : protocol.toUpperCase(Locale.ROOT);
        String payloadText = payload == null ? "" : new String(payload, StandardCharsets.UTF_8).toLowerCase(Locale.ROOT);

        boolean allowed = ddosProtectionService.checkConnection(sourceIP);
        if (!allowed) {
            result.add(recordIncident(sourceIP, "L4", "CONNECTION_FLOOD", 90, "Connection flood threshold exceeded"));
        }

        ddosProtectionService.checkPacketSize(sourceIP, payloadSize);
        ddosProtectionService.checkBandwidth(sourceIP, payloadSize);

        if ("TCP".equals(normalizedProtocol)) {
            ddosProtectionService.checkSynFlood(sourceIP);
        } else if ("UDP".equals(normalizedProtocol)) {
            ddosProtectionService.checkUDPAmplification(sourceIP, payloadSize);
        } else if ("ICMP".equals(normalizedProtocol)) {
            ddosProtectionService.checkICMPFlood(sourceIP);
        }

        if (containsHttpTraffic(payloadText)) {
            boolean httpAllowed = ddosProtectionService.checkHTTPFlood(sourceIP, detectUserAgent(payloadText), detectPath(payloadText));
            if (!httpAllowed) {
                result.add(recordIncident(sourceIP, "L7", "HTTP_FLOOD", 88, "HTTP flood threshold exceeded"));
            }
        }

        SlowConnectionTracker tracker = slowConnections.computeIfAbsent(sourceIP, SlowConnectionTracker::new);
        tracker.record(payloadSize);
        if (tracker.isSlowConnection(config.getSecurity().getDdosDefense().getSlowConnectionThreshold())) {
            result.add(recordIncident(sourceIP, "L7", "SLOW_CONNECTION", 70, "Slow connection pattern detected"));
        }

        for (MinecraftProtocolSecurityService.MinecraftThreatSignal signal : minecraftProtocolSecurityService.analyzePacket(
            sourceIP, destIP, sourcePort, destPort, payload)) {
            String category = signal.getType().contains("RCON") ? "MINECRAFT-RCON" : "MINECRAFT";
            result.add(recordIncident(sourceIP, category, signal.getType(), signal.getConfidence(), signal.getDetails()));
        }

        Map<String, Object> trafficData = new HashMap<>();
        trafficData.put("packetPattern", buildPacketPattern(normalizedProtocol, payloadText));
        trafficData.put("requestPattern", payloadText);
        trafficData.put("flags", normalizedProtocol);
        distributedAttackMitigationService.analyzeTraffic(sourceIP, trafficData);

        if (ddosProtectionService.isBlocked(sourceIP)) {
            hostEnforcementService.blockIp(sourceIP, "DDoS coordinator escalation", config.getSecurity().getHostEnforcement().getDefaultBlockMinutes());
        }

        trimIncidentLog();
        return result;
    }

    public Map<String, Object> getPosture() {
        Map<String, Object> ddosStats = ddosProtectionService.getStats();
        Map<String, Object> mitigationStats = distributedAttackMitigationService.getStats();
        Map<String, Object> minecraftPosture = minecraftProtocolSecurityService.getPosture();

        Map<String, Object> posture = new LinkedHashMap<>();
        posture.put("blockedIPs", ddosStats.getOrDefault("blockedIPs", 0));
        posture.put("totalDetected", ddosStats.getOrDefault("totalDetected", 0));
        posture.put("totalBlocked", ddosStats.getOrDefault("totalBlocked", 0));
        posture.put("activeIncidents", incidents.size());
        posture.put("mitigatedIncidents", mitigationStats.getOrDefault("totalAttacksMitigated", 0));
        posture.put("defenseLevel", mitigationStats.getOrDefault("currentDefenseLevel", "LOW"));
        posture.put("minecraftThreats", minecraftPosture.getOrDefault("recentSignals", 0));
        posture.put("botSwarmSources", minecraftPosture.getOrDefault("botSwarmSources", 0));
        posture.put("recentIncidents", getRecentIncidents(5));
        return posture;
    }

    public List<DDoSIncidentSummary> getRecentIncidents(int limit) {
        List<DDoSIncidentSummary> result = new ArrayList<>();
        int count = 0;
        for (DDoSIncidentSummary incident : incidents) {
            if (count++ >= limit) {
                break;
            }
            result.add(incident);
        }
        result.sort(Comparator.comparingLong(DDoSIncidentSummary::getTimestamp).reversed());
        return result;
    }

    public List<DDoSIncidentSummary> getIncidentsForIp(String ip, int limit) {
        List<DDoSIncidentSummary> result = new ArrayList<>();
        for (DDoSIncidentSummary incident : getRecentIncidents(200)) {
            if (ip.equals(incident.getSourceIP())) {
                result.add(incident);
                if (result.size() >= limit) {
                    break;
                }
            }
        }
        return result;
    }

    private DDoSIncidentSummary recordIncident(String sourceIP, String layer, String type, int severity, String details) {
        DDoSIncidentSummary incident = new DDoSIncidentSummary(sourceIP, layer, type, severity, details, Instant.now().toEpochMilli());
        incidents.offer(incident);
        return incident;
    }

    private void trimIncidentLog() {
        while (incidents.size() > 1000) {
            incidents.poll();
        }
    }

    private boolean containsHttpTraffic(String payload) {
        return payload.startsWith("get ") || payload.startsWith("post ") || payload.contains(" http/1.");
    }

    private String detectUserAgent(String payload) {
        int index = payload.indexOf("user-agent:");
        if (index < 0) {
            return "unknown";
        }
        int end = payload.indexOf('\n', index);
        return end > index ? payload.substring(index, end).trim() : payload.substring(index).trim();
    }

    private String detectPath(String payload) {
        if (payload.startsWith("get ") || payload.startsWith("post ")) {
            String[] parts = payload.split(" ");
            if (parts.length > 1) {
                return parts[1];
            }
        }
        return "/";
    }

    private String buildPacketPattern(String protocol, String payloadText) {
        if (payloadText.contains("rcon")) {
            return "RCON failed repeated";
        }
        if (payloadText.contains("status") || payloadText.contains("ping")) {
            return "MINECRAFT status flood";
        }
        if (payloadText.contains("login")) {
            return "MINECRAFT login flood";
        }
        if ("UDP".equals(protocol) && payloadText.length() > 1024) {
            return "UDP flood";
        }
        return protocol + " traffic";
    }

    private static final class SlowConnectionTracker {
        private final String sourceIP;
        private final List<Entry> entries = new ArrayList<>();

        private SlowConnectionTracker(String sourceIP) {
            this.sourceIP = sourceIP;
        }

        private void record(int size) {
            long now = System.currentTimeMillis();
            entries.removeIf(entry -> entry.timestamp < now - WINDOW_MS);
            entries.add(new Entry(now, size));
        }

        private boolean isSlowConnection(int threshold) {
            if (entries.size() < threshold) {
                return false;
            }
            long smallPackets = entries.stream().filter(entry -> entry.size < 64).count();
            return smallPackets > entries.size() * 0.7;
        }

        private record Entry(long timestamp, int size) {
        }
    }

    public static class DDoSIncidentSummary {
        private final String sourceIP;
        private final String layer;
        private final String type;
        private final int severity;
        private final String details;
        private final long timestamp;

        public DDoSIncidentSummary(String sourceIP, String layer, String type, int severity, String details, long timestamp) {
            this.sourceIP = sourceIP;
            this.layer = layer;
            this.type = type;
            this.severity = severity;
            this.details = details;
            this.timestamp = timestamp;
        }

        public String getSourceIP() { return sourceIP; }
        public String getLayer() { return layer; }
        public String getType() { return type; }
        public int getSeverity() { return severity; }
        public String getDetails() { return details; }
        public long getTimestamp() { return timestamp; }
    }
}
