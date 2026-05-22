package com.aluer.network;

import com.aluer.defense.DDoSDefenseCoordinator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.atomic.AtomicLong;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.nio.ByteBuffer;

@Component
public class ProtocolAnalysisService {
    private static final Logger logger = LoggerFactory.getLogger(ProtocolAnalysisService.class);

    private final MinecraftProtocolSecurityService minecraftProtocolSecurityService;
    private final DDoSDefenseCoordinator ddosDefenseCoordinator;
    private final Map<String, ProtocolStatistics> protocolStats = new ConcurrentHashMap<>();
    private final Map<String, ConnectionState> connectionStates = new ConcurrentHashMap<>();
    private final Queue<ProtocolEvent> eventLog = new ConcurrentLinkedQueue<>();
    private final Map<String, List<PacketFragment>> fragmentBuffers = new ConcurrentHashMap<>();
    private final AtomicLong totalPacketsAnalyzed = new AtomicLong(0);
    private final AtomicLong totalMalformedPackets = new AtomicLong(0);
    private final AtomicLong totalSuspiciousPackets = new AtomicLong(0);

    private static final int MAX_PACKET_SIZE = 1024 * 1024;
    private static final int FRAGMENT_TIMEOUT_MS = 5000;
    private static final DateTimeFormatter DATE_FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    public ProtocolAnalysisService() {
        this(new MinecraftProtocolSecurityService(), new DDoSDefenseCoordinator());
    }

    @Autowired
    public ProtocolAnalysisService(MinecraftProtocolSecurityService minecraftProtocolSecurityService,
                                   DDoSDefenseCoordinator ddosDefenseCoordinator) {
        this.minecraftProtocolSecurityService = minecraftProtocolSecurityService;
        this.ddosDefenseCoordinator = ddosDefenseCoordinator;
        initializeProtocols();
    }

    private void initializeProtocols() {
        protocolStats.put("TCP", new ProtocolStatistics("TCP"));
        protocolStats.put("UDP", new ProtocolStatistics("UDP"));
        protocolStats.put("ICMP", new ProtocolStatistics("ICMP"));
        protocolStats.put("HTTP", new ProtocolStatistics("HTTP"));
        protocolStats.put("HTTPS", new ProtocolStatistics("HTTPS"));
        protocolStats.put("RCON", new ProtocolStatistics("RCON"));
    }

    public AnalysisResult analyzePacket(byte[] packetData, String sourceIP, String destIP, int sourcePort, int destPort) {
        AnalysisResult result = new AnalysisResult();
        result.setSourceIP(sourceIP);
        result.setDestIP(destIP);
        result.setSourcePort(sourcePort);
        result.setDestPort(destPort);
        result.setTimestamp(LocalDateTime.now());

        if (packetData == null || packetData.length == 0) {
            result.setValid(false);
            result.setReason("Empty packet");
            totalMalformedPackets.incrementAndGet();
            return result;
        }

        if (packetData.length > MAX_PACKET_SIZE) {
            result.setValid(false);
            result.setReason("Packet too large");
            totalMalformedPackets.incrementAndGet();
            return result;
        }

        totalPacketsAnalyzed.incrementAndGet();

        String protocol = detectProtocol(packetData, destPort);
        result.setProtocol(protocol);

        ProtocolStatistics stats = protocolStats.get(protocol);
        if (stats != null) {
            stats.incrementPacketCount();
            stats.addBytes(packetData.length);
        }

        if (isMalformedPacket(packetData, protocol)) {
            result.setValid(false);
            result.setReason("Malformed packet structure");
            result.setThreatLevel("HIGH");
            totalMalformedPackets.incrementAndGet();

            if (stats != null) {
                stats.incrementMalformedCount();
            }

            logEvent(sourceIP, destIP, protocol, "MALFORMED", "Malformed packet detected");
            return result;
        }

        if (isSuspiciousPacket(packetData, protocol)) {
            result.setThreatLevel("MEDIUM");
            result.addWarning("Suspicious packet pattern detected");
            totalSuspiciousPackets.incrementAndGet();

            if (stats != null) {
                stats.incrementSuspiciousCount();
            }

            logEvent(sourceIP, destIP, protocol, "SUSPICIOUS", "Suspicious packet pattern");
        }

        List<MinecraftProtocolSecurityService.MinecraftThreatSignal> minecraftSignals =
            minecraftProtocolSecurityService.analyzePacket(sourceIP, destIP, sourcePort, destPort, packetData);
        for (MinecraftProtocolSecurityService.MinecraftThreatSignal signal : minecraftSignals) {
            result.addWarning(signal.getType() + ": " + signal.getDetails());
            result.setThreatLevel("HIGH");
            logEvent(sourceIP, destIP, "MINECRAFT", signal.getType(), signal.getDetails());
        }

        for (DDoSDefenseCoordinator.DDoSIncidentSummary incident : ddosDefenseCoordinator.analyzeTraffic(
            sourceIP, destIP, sourcePort, destPort, protocol, packetData)) {
            result.addWarning(incident.getType() + ": " + incident.getDetails());
            if (!"HIGH".equals(result.getThreatLevel())) {
                result.setThreatLevel(incident.getSeverity() >= 85 ? "HIGH" : "MEDIUM");
            }
        }

        if (isFragmentedPacket(packetData)) {
            result.setFragmented(true);
            handleFragment(sourceIP, packetData, result);
        }

        updateConnectionState(sourceIP, destIP, protocol, result);

        result.setValid(true);
        return result;
    }

    private String detectProtocol(byte[] packetData, int destPort) {
        if (destPort == 25565) return "MINECRAFT";
        if (destPort == 25575) return "RCON";
        if (destPort == 80) return "HTTP";
        if (destPort == 443) return "HTTPS";

        if (packetData.length >= 20) {
            int protocol = packetData[9] & 0xFF;
            switch (protocol) {
                case 6: return "TCP";
                case 17: return "UDP";
                case 1: return "ICMP";
            }
        }

        return "UNKNOWN";
    }

    private boolean isMalformedPacket(byte[] packetData, String protocol) {
        if ("TCP".equals(protocol) || "MINECRAFT".equals(protocol) || "RCON".equals(protocol)) {
            if (packetData.length < 20) return true;

            int headerLength = (packetData[0] & 0x0F) * 4;
            if (headerLength < 20) return true;

            int dataOffset = headerLength;
            if (packetData.length > dataOffset) {
                byte flags = packetData[dataOffset];
                if ((flags & 0x3F) == 0) return false;

                int payloadLength = packetData.length - dataOffset;
                if (payloadLength < 0) return true;
            }
        }

        if ("UDP".equals(protocol)) {
            if (packetData.length < 8) return true;
        }

        return false;
    }

    private boolean isSuspiciousPacket(byte[] packetData, String protocol) {
        if (packetData.length > 65535) return true;

        if (packetData.length > 1400 && "UDP".equals(protocol)) {
            return true;
        }

        for (int i = 0; i < Math.min(packetData.length, 100); i++) {
            if (packetData[i] == 0x00 && i % 10 == 0) {
                int zeroCount = 0;
                for (int j = i; j < Math.min(i + 10, packetData.length); j++) {
                    if (packetData[j] == 0x00) zeroCount++;
                }
                if (zeroCount > 8) return true;
            }
        }

        return false;
    }

    private boolean isFragmentedPacket(byte[] packetData) {
        if (packetData.length < 20) return false;

        short flags = (short) ((packetData[6] << 8) | (packetData[7] & 0xFF));
        boolean moreFragments = (flags & 0x2000) != 0;
        boolean fragmentOffset = (flags & 0x1FFF) != 0;

        return moreFragments || fragmentOffset;
    }

    private void handleFragment(String sourceIP, byte[] packetData, AnalysisResult result) {
        String key = sourceIP + "-" + result.getDestIP();
        List<PacketFragment> fragments = fragmentBuffers.computeIfAbsent(key, k -> new ArrayList<>());

        short identification = (short) ((packetData[4] << 8) | (packetData[5] & 0xFF));
        short flags = (short) ((packetData[6] << 8) | (packetData[7] & 0xFF));
        short offset = (short) (flags & 0x1FFF);

        PacketFragment fragment = new PacketFragment(identification, offset, packetData, System.currentTimeMillis());
        fragments.add(fragment);

        cleanupOldFragments(fragments);

        int totalLength = fragments.stream().mapToInt(f -> f.getData().length).sum();
        if (totalLength > MAX_PACKET_SIZE) {
            result.addWarning("Fragment buffer overflow prevented");
            fragments.clear();
        }
    }

    private void cleanupOldFragments(List<PacketFragment> fragments) {
        long now = System.currentTimeMillis();
        fragments.removeIf(f -> now - f.getTimestamp() > FRAGMENT_TIMEOUT_MS);
    }

    private void updateConnectionState(String sourceIP, String destIP, String protocol, AnalysisResult result) {
        String key = sourceIP + "-" + destIP;
        ConnectionState state = connectionStates.computeIfAbsent(key, k -> new ConnectionState(sourceIP, destIP, protocol));

        state.update(result);

        if (state.getPacketCount() > 10000) {
            result.addWarning("High packet count on connection");
            logEvent(sourceIP, destIP, protocol, "HIGH_VOLUME", "Connection high volume warning");
        }

        long connectionAge = System.currentTimeMillis() - state.getStartTime();
        if (connectionAge > 3600000 && state.getPacketCount() < 10) {
            result.addWarning("Stale connection detected");
        }
    }

    public Map<String, Object> getStats() {
        Map<String, Object> stats = new HashMap<>();
        stats.put("totalPacketsAnalyzed", totalPacketsAnalyzed.get());
        stats.put("totalMalformedPackets", totalMalformedPackets.get());
        stats.put("totalSuspiciousPackets", totalSuspiciousPackets.get());
        stats.put("activeConnections", connectionStates.size());

        Map<String, ProtocolStatistics> protoStats = new HashMap<>();
        for (Map.Entry<String, ProtocolStatistics> entry : protocolStats.entrySet()) {
            protoStats.put(entry.getKey(), entry.getValue());
        }
        stats.put("protocolStats", protoStats);

        return stats;
    }

    public Map<String, ConnectionState> getConnectionStates() {
        return new HashMap<>(connectionStates);
    }

    public List<ProtocolEvent> getRecentEvents(int limit) {
        List<ProtocolEvent> events = new ArrayList<>();
        int count = 0;
        for (ProtocolEvent event : eventLog) {
            if (count++ >= limit) break;
            events.add(event);
        }
        return events;
    }

    private void logEvent(String sourceIP, String destIP, String protocol, String eventType, String details) {
        ProtocolEvent event = new ProtocolEvent(
            sourceIP, destIP, protocol, eventType, details, LocalDateTime.now()
        );
        eventLog.offer(event);

        if (eventLog.size() > 10000) {
            eventLog.poll();
        }
    }

    public static class AnalysisResult {
        private String sourceIP;
        private String destIP;
        private int sourcePort;
        private int destPort;
        private String protocol;
        private boolean valid;
        private String reason;
        private String threatLevel;
        private boolean fragmented;
        private List<String> warnings = new ArrayList<>();
        private LocalDateTime timestamp;

        public String getSourceIP() { return sourceIP; }
        public void setSourceIP(String sourceIP) { this.sourceIP = sourceIP; }
        public String getDestIP() { return destIP; }
        public void setDestIP(String destIP) { this.destIP = destIP; }
        public int getSourcePort() { return sourcePort; }
        public void setSourcePort(int sourcePort) { this.sourcePort = sourcePort; }
        public int getDestPort() { return destPort; }
        public void setDestPort(int destPort) { this.destPort = destPort; }
        public String getProtocol() { return protocol; }
        public void setProtocol(String protocol) { this.protocol = protocol; }
        public boolean isValid() { return valid; }
        public void setValid(boolean valid) { this.valid = valid; }
        public String getReason() { return reason; }
        public void setReason(String reason) { this.reason = reason; }
        public String getThreatLevel() { return threatLevel; }
        public void setThreatLevel(String threatLevel) { this.threatLevel = threatLevel; }
        public boolean isFragmented() { return fragmented; }
        public void setFragmented(boolean fragmented) { this.fragmented = fragmented; }
        public List<String> getWarnings() { return warnings; }
        public void addWarning(String warning) { this.warnings.add(warning); }
        public LocalDateTime getTimestamp() { return timestamp; }
        public void setTimestamp(LocalDateTime timestamp) { this.timestamp = timestamp; }
    }

    public static class ProtocolStatistics {
        private final String protocolName;
        private final AtomicLong packetCount = new AtomicLong(0);
        private final AtomicLong byteCount = new AtomicLong(0);
        private final AtomicLong malformedCount = new AtomicLong(0);
        private final AtomicLong suspiciousCount = new AtomicLong(0);

        public ProtocolStatistics(String protocolName) {
            this.protocolName = protocolName;
        }

        public void incrementPacketCount() { packetCount.incrementAndGet(); }
        public void addBytes(int bytes) { byteCount.addAndGet(bytes); }
        public void incrementMalformedCount() { malformedCount.incrementAndGet(); }
        public void incrementSuspiciousCount() { suspiciousCount.incrementAndGet(); }

        public String getProtocolName() { return protocolName; }
        public long getPacketCount() { return packetCount.get(); }
        public long getByteCount() { return byteCount.get(); }
        public long getMalformedCount() { return malformedCount.get(); }
        public long getSuspiciousCount() { return suspiciousCount.get(); }
    }

    public static class ConnectionState {
        private final String sourceIP;
        private final String destIP;
        private final String protocol;
        private final long startTime;
        private volatile long lastPacketTime;
        private volatile long packetCount;
        private volatile long totalBytes;
        private volatile String currentState;

        public ConnectionState(String sourceIP, String destIP, String protocol) {
            this.sourceIP = sourceIP;
            this.destIP = destIP;
            this.protocol = protocol;
            this.startTime = System.currentTimeMillis();
            this.lastPacketTime = startTime;
            this.packetCount = 0;
            this.totalBytes = 0;
            this.currentState = "ESTABLISHED";
        }

        public synchronized void update(AnalysisResult result) {
            lastPacketTime = System.currentTimeMillis();
            packetCount++;
            if (!result.isValid()) {
                currentState = "ERROR";
            } else if ("HIGH".equals(result.getThreatLevel())) {
                currentState = "THREAT";
            }
        }

        public String getSourceIP() { return sourceIP; }
        public String getDestIP() { return destIP; }
        public String getProtocol() { return protocol; }
        public long getStartTime() { return startTime; }
        public long getLastPacketTime() { return lastPacketTime; }
        public long getPacketCount() { return packetCount; }
        public long getTotalBytes() { return totalBytes; }
        public String getCurrentState() { return currentState; }
    }

    public static class PacketFragment {
        private final short identification;
        private final short offset;
        private final byte[] data;
        private final long timestamp;

        public PacketFragment(short identification, short offset, byte[] data, long timestamp) {
            this.identification = identification;
            this.offset = offset;
            this.data = data;
            this.timestamp = timestamp;
        }

        public short getIdentification() { return identification; }
        public short getOffset() { return offset; }
        public byte[] getData() { return data; }
        public long getTimestamp() { return timestamp; }
    }

    public static class ProtocolEvent {
        private final String sourceIP;
        private final String destIP;
        private final String protocol;
        private final String eventType;
        private final String details;
        private final LocalDateTime timestamp;

        public ProtocolEvent(String sourceIP, String destIP, String protocol,
                           String eventType, String details, LocalDateTime timestamp) {
            this.sourceIP = sourceIP;
            this.destIP = destIP;
            this.protocol = protocol;
            this.eventType = eventType;
            this.details = details;
            this.timestamp = timestamp;
        }

        public String getSourceIP() { return sourceIP; }
        public String getDestIP() { return destIP; }
        public String getProtocol() { return protocol; }
        public String getEventType() { return eventType; }
        public String getDetails() { return details; }
        public LocalDateTime getTimestamp() { return timestamp; }
    }
}
