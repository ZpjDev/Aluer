package com.aluer.network;

import com.aluer.config.ServerGuardConfig;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;

@Service
public class MinecraftProtocolSecurityService {
    private static final long WINDOW_MS = 60_000L;

    private final ServerGuardConfig config;
    private final Map<String, MinecraftSessionProfile> profiles = new ConcurrentHashMap<>();
    private final ConcurrentLinkedQueue<MinecraftThreatSignal> signals = new ConcurrentLinkedQueue<>();

    public MinecraftProtocolSecurityService() {
        this(new ServerGuardConfig());
    }

    @Autowired
    public MinecraftProtocolSecurityService(ServerGuardConfig config) {
        this.config = config;
    }

    public List<MinecraftThreatSignal> analyzePacket(String sourceIP, String destIP, int sourcePort, int destPort, byte[] payload) {
        if (!config.getSecurity().getMinecraftDefense().isEnabled()) {
            return Collections.emptyList();
        }

        if (!isMinecraftRelevantPort(destPort)) {
            return Collections.emptyList();
        }

        MinecraftSessionProfile profile = profiles.computeIfAbsent(sourceIP, MinecraftSessionProfile::new);
        profile.destinations.add(destIP);
        profile.totalPackets++;
        profile.lastSeen = System.currentTimeMillis();

        String stage = classifyStage(destPort, payload);
        recordStage(profile, stage);

        List<MinecraftThreatSignal> result = new ArrayList<>();

        if ("STATUS".equals(stage) && profile.statusRequests.size() >= config.getSecurity().getMinecraftDefense().getStatusPingThreshold()) {
            result.add(createSignal(sourceIP, "STATUS_PING_FLOOD", 88, "Frequent status probes on Minecraft port"));
        }
        if ("LOGIN".equals(stage) && profile.loginAttempts.size() >= config.getSecurity().getMinecraftDefense().getLoginBurstThreshold()) {
            result.add(createSignal(sourceIP, "LOGIN_BURST", 84, "Burst of login attempts detected"));
        }
        if ("QUERY".equals(stage) && profile.queryRequests.size() >= config.getSecurity().getMinecraftDefense().getQueryFloodThreshold()) {
            result.add(createSignal(sourceIP, "QUERY_ABUSE", 80, "Frequent query traffic detected"));
        }
        if ("RCON".equals(stage) && profile.rconAttempts.size() >= config.getSecurity().getMinecraftDefense().getRconBruteForceThreshold()) {
            result.add(createSignal(sourceIP, "RCON_BRUTE_FORCE", 92, "Repeated RCON authentication attempts"));
        }
        if (detectInvalidVarint(payload)) {
            result.add(createSignal(sourceIP, "INVALID_VARINT", 90, "Malformed VarInt header detected"));
        }
        if (detectMalformedHandshake(destPort, payload)) {
            result.add(createSignal(sourceIP, "MALFORMED_HANDSHAKE", 82, "Unexpected or truncated handshake"));
        }
        if (detectCompressionAbuse(payload)) {
            result.add(createSignal(sourceIP, "COMPRESSION_ABUSE", 72, "Large or repetitive payload suggests compression abuse"));
        }
        if (detectProtocolStateBypass(profile, stage)) {
            result.add(createSignal(sourceIP, "PROTOCOL_STATE_BYPASS", 86, "Unexpected protocol stage transition"));
        }

        if (stage.equals("LOGIN") || stage.equals("STATUS")) {
            int uniqueSources = countUniqueSourcesForStage(stage);
            if (uniqueSources >= config.getSecurity().getMinecraftDefense().getBotSwarmThreshold()) {
                result.add(createSignal(sourceIP, "BOT_SWARM", 78, "Multiple IPs are synchronously probing Minecraft"));
            }
        }

        for (MinecraftThreatSignal signal : result) {
            profile.signalsTriggered.merge(signal.type, 1, Integer::sum);
            signals.offer(signal);
        }

        while (signals.size() > 1000) {
            signals.poll();
        }

        return result;
    }

    public List<MinecraftThreatSignal> getRecentSignals(int limit) {
        List<MinecraftThreatSignal> result = new ArrayList<>();
        int count = 0;
        for (MinecraftThreatSignal signal : signals) {
            if (count++ >= limit) {
                break;
            }
            result.add(signal);
        }
        result.sort(Comparator.comparingLong(MinecraftThreatSignal::getTimestamp).reversed());
        return result;
    }

    public List<MinecraftThreatSignal> getSignalsForIp(String ip, int limit) {
        List<MinecraftThreatSignal> result = new ArrayList<>();
        for (MinecraftThreatSignal signal : getRecentSignals(200)) {
            if (ip.equals(signal.sourceIP)) {
                result.add(signal);
                if (result.size() >= limit) {
                    break;
                }
            }
        }
        return result;
    }

    public Map<String, Object> getPosture() {
        Map<String, Object> posture = new LinkedHashMap<>();
        posture.put("activeSessions", profiles.size());
        posture.put("recentSignals", signals.size());
        posture.put("botSwarmSources", countSignals("BOT_SWARM"));
        posture.put("rconRisk", countSignals("RCON_BRUTE_FORCE"));
        posture.put("malformedPackets", countSignals("INVALID_VARINT") + countSignals("MALFORMED_HANDSHAKE"));
        posture.put("topSources", getTopProfiles(5));
        return posture;
    }

    public List<Map<String, Object>> getSessionProfiles(int limit) {
        return getTopProfiles(limit);
    }

    private List<Map<String, Object>> getTopProfiles(int limit) {
        List<MinecraftSessionProfile> sessionProfiles = new ArrayList<>(profiles.values());
        sessionProfiles.sort(Comparator.comparingLong((MinecraftSessionProfile profile) -> profile.totalPackets).reversed());

        List<Map<String, Object>> result = new ArrayList<>();
        for (MinecraftSessionProfile profile : sessionProfiles) {
            if (result.size() >= limit) {
                break;
            }
            result.add(profile.toMap());
        }
        return result;
    }

    private int countSignals(String type) {
        int count = 0;
        for (MinecraftThreatSignal signal : signals) {
            if (type.equals(signal.type)) {
                count++;
            }
        }
        return count;
    }

    private int countUniqueSourcesForStage(String stage) {
        Set<String> sources = new HashSet<>();
        long cutoff = System.currentTimeMillis() - WINDOW_MS;
        for (MinecraftSessionProfile profile : profiles.values()) {
            List<Long> timestamps = switch (stage) {
                case "STATUS" -> profile.statusRequests;
                case "LOGIN" -> profile.loginAttempts;
                default -> List.of();
            };
            timestamps.removeIf(timestamp -> timestamp < cutoff);
            if (!timestamps.isEmpty()) {
                sources.add(profile.sourceIP);
            }
        }
        return sources.size();
    }

    private boolean detectInvalidVarint(byte[] payload) {
        if (payload == null || payload.length == 0) {
            return false;
        }
        int continuation = 0;
        for (int i = 0; i < Math.min(6, payload.length); i++) {
            if ((payload[i] & 0x80) != 0) {
                continuation++;
            } else {
                break;
            }
        }
        return continuation > 4;
    }

    private boolean detectMalformedHandshake(int destPort, byte[] payload) {
        if (payload == null) {
            return true;
        }
        if (destPort == config.getSecurity().getMinecraftDefense().getGameTcpPort() && payload.length < 2) {
            return true;
        }
        String content = payload.length == 0 ? "" : new String(payload, StandardCharsets.UTF_8).toLowerCase(Locale.ROOT);
        return content.contains("handshake") && payload.length < 8;
    }

    private boolean detectCompressionAbuse(byte[] payload) {
        if (payload == null || payload.length < config.getSecurity().getMinecraftDefense().getCompressionPayloadThreshold()) {
            return false;
        }
        int repeated = 0;
        for (int i = 1; i < payload.length; i++) {
            if (payload[i] == payload[i - 1]) {
                repeated++;
            }
        }
        return repeated > payload.length / 3;
    }

    private boolean detectProtocolStateBypass(MinecraftSessionProfile profile, String stage) {
        if (profile.lastStage == null || stage.equals(profile.lastStage)) {
            return false;
        }
        if ("LOGIN".equals(stage) && !"HANDSHAKE".equals(profile.lastStage)) {
            return true;
        }
        if ("QUERY".equals(stage) && "RCON".equals(profile.lastStage)) {
            return true;
        }
        return "RCON".equals(stage) && "STATUS".equals(profile.lastStage);
    }

    private String classifyStage(int destPort, byte[] payload) {
        if (destPort == config.getSecurity().getMinecraftDefense().getRconTcpPort()) {
            return "RCON";
        }
        if (destPort == config.getSecurity().getMinecraftDefense().getQueryUdpPort() && payload != null && payload.length > 0 && payload[0] == (byte) 0xFE) {
            return "QUERY";
        }

        String content = payload == null ? "" : new String(payload, StandardCharsets.UTF_8).toLowerCase(Locale.ROOT);
        if (content.contains("status") || content.contains("ping")) {
            return "STATUS";
        }
        if (content.contains("login") || content.contains("join")) {
            return "LOGIN";
        }
        if (content.contains("handshake")) {
            return "HANDSHAKE";
        }
        if (content.contains("query")) {
            return "QUERY";
        }
        return destPort == config.getSecurity().getMinecraftDefense().getGameTcpPort() ? "HANDSHAKE" : "UNKNOWN";
    }

    private void recordStage(MinecraftSessionProfile profile, String stage) {
        long now = System.currentTimeMillis();
        profile.lastStage = stage;
        switch (stage) {
            case "STATUS" -> pruneAndAdd(profile.statusRequests, now);
            case "LOGIN" -> pruneAndAdd(profile.loginAttempts, now);
            case "QUERY" -> pruneAndAdd(profile.queryRequests, now);
            case "RCON" -> pruneAndAdd(profile.rconAttempts, now);
            default -> pruneAndAdd(profile.handshakes, now);
        }
    }

    private void pruneAndAdd(List<Long> timestamps, long timestamp) {
        timestamps.removeIf(existing -> existing < timestamp - WINDOW_MS);
        timestamps.add(timestamp);
    }

    private MinecraftThreatSignal createSignal(String sourceIP, String type, int confidence, String details) {
        return new MinecraftThreatSignal(sourceIP, type, confidence, details, Instant.now().toEpochMilli());
    }

    private boolean isMinecraftRelevantPort(int port) {
        ServerGuardConfig.MinecraftDefenseConfig defense = config.getSecurity().getMinecraftDefense();
        return port == defense.getGameTcpPort()
            || port == defense.getQueryUdpPort()
            || port == defense.getRconTcpPort();
    }

    public static class MinecraftThreatSignal {
        private final String sourceIP;
        private final String type;
        private final int confidence;
        private final String details;
        private final long timestamp;

        public MinecraftThreatSignal(String sourceIP, String type, int confidence, String details, long timestamp) {
            this.sourceIP = sourceIP;
            this.type = type;
            this.confidence = confidence;
            this.details = details;
            this.timestamp = timestamp;
        }

        public String getSourceIP() { return sourceIP; }
        public String getType() { return type; }
        public int getConfidence() { return confidence; }
        public String getDetails() { return details; }
        public long getTimestamp() { return timestamp; }
    }

    public static class MinecraftSessionProfile {
        private final String sourceIP;
        private final Set<String> destinations = ConcurrentHashMap.newKeySet();
        private final List<Long> statusRequests = Collections.synchronizedList(new ArrayList<>());
        private final List<Long> loginAttempts = Collections.synchronizedList(new ArrayList<>());
        private final List<Long> queryRequests = Collections.synchronizedList(new ArrayList<>());
        private final List<Long> rconAttempts = Collections.synchronizedList(new ArrayList<>());
        private final List<Long> handshakes = Collections.synchronizedList(new ArrayList<>());
        private final Map<String, Integer> signalsTriggered = new ConcurrentHashMap<>();
        private volatile long totalPackets = 0;
        private volatile long lastSeen = System.currentTimeMillis();
        private volatile String lastStage = null;

        public MinecraftSessionProfile(String sourceIP) {
            this.sourceIP = sourceIP;
        }

        public Map<String, Object> toMap() {
            Map<String, Object> data = new HashMap<>();
            data.put("sourceIP", sourceIP);
            data.put("totalPackets", totalPackets);
            data.put("destinations", destinations.size());
            data.put("statusRequests", statusRequests.size());
            data.put("loginAttempts", loginAttempts.size());
            data.put("queryRequests", queryRequests.size());
            data.put("rconAttempts", rconAttempts.size());
            data.put("signalsTriggered", signalsTriggered);
            data.put("lastStage", lastStage);
            data.put("lastSeen", lastSeen);
            return data;
        }
    }
}
