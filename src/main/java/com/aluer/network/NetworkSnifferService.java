package com.aluer.network;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.atomic.AtomicLong;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.Map.Entry;

@Component
public class NetworkSnifferService {
    private static final Logger logger = LoggerFactory.getLogger(NetworkSnifferService.class);

    private final Map<String, CapturedPacket> packetBuffer = new LinkedHashMap<>();
    private final Queue<SnifferAlert> alertQueue = new ConcurrentLinkedQueue<>();
    private final Map<String, PacketStatistics> protocolStats = new ConcurrentHashMap<>();
    private final Map<String, java.util.List<CapturedPacket>> packetHistory = new java.util.concurrent.ConcurrentHashMap<>();
    private final Map<String, SessionInfo> sessions = new ConcurrentHashMap<>();
    private final AtomicLong totalPacketsCaptured = new AtomicLong(0);
    private final AtomicLong totalBytesCaptured = new AtomicLong(0);
    private final AtomicLong suspiciousPackets = new AtomicLong(0);

    private volatile boolean capturing = false;
    private final ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(1);

    private static final int MAX_BUFFER_SIZE = 10000;
    private static final int PACKET_HISTORY_SIZE = 1000;
    private static final DateTimeFormatter DATE_FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    public NetworkSnifferService() {
        initializeProtocolStats();
        logger.info("Network Sniffer Service initialized");
    }

    private void initializeProtocolStats() {
        protocolStats.put("TCP", new PacketStatistics("TCP"));
        protocolStats.put("UDP", new PacketStatistics("UDP"));
        protocolStats.put("ICMP", new PacketStatistics("ICMP"));
        protocolStats.put("HTTP", new PacketStatistics("HTTP"));
        protocolStats.put("HTTPS", new PacketStatistics("HTTPS"));
        protocolStats.put("DNS", new PacketStatistics("DNS"));
        protocolStats.put("SSH", new PacketStatistics("SSH"));
        protocolStats.put("FTP", new PacketStatistics("FTP"));
        protocolStats.put("OTHER", new PacketStatistics("OTHER"));
    }

    public void startCapture() {
        capturing = true;
        logger.info("Packet capture started");

        scheduler.scheduleAtFixedRate(() -> {
            analyzeCapturedTraffic();
            detectAnomalies();
            cleanupOldData();
        }, 5, 5, TimeUnit.SECONDS);
    }

    public void stopCapture() {
        capturing = false;
        logger.info("Packet capture stopped");
    }

    public void capturePacket(String sourceIP, String destIP, int sourcePort, int destPort,
                            String protocol, byte[] payload, int length) {
        if (!capturing) return;

        totalPacketsCaptured.incrementAndGet();
        totalBytesCaptured.addAndGet(length);

        String packetId = UUID.randomUUID().toString();
        CapturedPacket packet = new CapturedPacket(
            packetId, sourceIP, destIP, sourcePort, destPort,
            protocol, payload, length, LocalDateTime.now()
        );

        packetBuffer.put(packetId, packet);
        if (packetBuffer.size() > MAX_BUFFER_SIZE) {
            String firstKey = packetBuffer.keySet().iterator().next();
            packetBuffer.remove(firstKey);
        }

        String sessionKey = sourceIP + "-" + destIP + "-" + destPort;
        SessionInfo session = sessions.computeIfAbsent(sessionKey, k -> new SessionInfo(sourceIP, destIP, destPort));
        session.addPacket(packet);

        updateProtocolStats(protocol, length);
        updatePacketHistory(sourceIP, packet);

        if (isSuspiciousPacket(packet)) {
            suspiciousPackets.incrementAndGet();
            triggerAlert(packet, "Suspicious packet detected");
        }

        analyzePacketContent(packet);
    }

    private void updateProtocolStats(String protocol, int length) {
        PacketStatistics stats = protocolStats.computeIfAbsent(protocol, k -> new PacketStatistics(protocol));
        stats.incrementPacketCount();
        stats.addBytes(length);
    }

    private void updatePacketHistory(String ip, CapturedPacket packet) {
        List<CapturedPacket> history = packetHistory.computeIfAbsent(ip, k -> new ArrayList<>());
        history.add(packet);
        if (history.size() > PACKET_HISTORY_SIZE) {
            history.remove(0);
        }
    }

    private boolean isSuspiciousPacket(CapturedPacket packet) {
        if (packet.getPayload() != null && packet.getPayload().length > 10000) {
            return true;
        }

        if (packet.getPayload() != null) {
            String payloadStr = new String(packet.getPayload());
            if (payloadStr.contains("NULL") || payloadStr.contains("\\x00")) {
                return true;
            }
        }

        return false;
    }

    private void analyzePacketContent(CapturedPacket packet) {
        if (packet.getPayload() == null || packet.getPayload().length == 0) return;

        String payloadStr = new String(packet.getPayload());

        if (payloadStr.matches(".*(?i)(union|select|insert|update|delete).*")) {
            triggerAlert(packet, "SQL Injection attempt detected");
        }

        if (payloadStr.matches(".*(?i)(<script|javascript:|onerror=).*")) {
            triggerAlert(packet, "XSS attempt detected");
        }

        if (payloadStr.matches(".*(?i)(\\.\\./|\\.\\.\\\\).*")) {
            triggerAlert(packet, "Directory traversal attempt detected");
        }

        if (payloadStr.matches(".*(?i)(cmd\\.exe|powershell|/bin/bash).*")) {
            triggerAlert(packet, "Command injection attempt detected");
        }
    }

    private void analyzeCapturedTraffic() {
        if (packetBuffer.isEmpty()) return;

        Map<String, Integer> ipCounts = new HashMap<>();
        for (CapturedPacket packet : packetBuffer.values()) {
            ipCounts.merge(packet.getSourceIP(), 1, Integer::sum);
        }

        for (Map.Entry<String, Integer> entry : ipCounts.entrySet()) {
            if (entry.getValue() > 1000) {
                logger.warn("High packet count from IP: {} - {} packets", entry.getKey(), entry.getValue());
            }
        }
    }

    private void detectAnomalies() {
        for (SessionInfo session : sessions.values()) {
            if (session.getPacketCount() > 5000 && session.getTotalBytes() < session.getPacketCount() * 10) {
                logger.warn("Potential slowloris attack from {} to {}", session.getSourceIP(), session.getDestIP());
            }

            if (session.getPacketCount() > 10000) {
                triggerAlert(session.getLatestPacket(), "Potential DoS attack detected");
            }
        }
    }

    private void cleanupOldData() {
        long now = System.currentTimeMillis();
        List<String> expiredSessions = new ArrayList<>();

        for (Map.Entry<String, SessionInfo> entry : sessions.entrySet()) {
            if (now - entry.getValue().getLastPacketTime() > 300000) {
                expiredSessions.add(entry.getKey());
            }
        }

        for (String key : expiredSessions) {
            sessions.remove(key);
        }
    }

    private void triggerAlert(CapturedPacket packet, String reason) {
        SnifferAlert alert = new SnifferAlert(
            packet.getSourceIP(),
            packet.getDestIP(),
            packet.getProtocol(),
            reason,
            LocalDateTime.now()
        );
        alertQueue.offer(alert);

        if (alertQueue.size() > 500) {
            alertQueue.poll();
        }

        logger.warn("Sniffer Alert: {} -> {} : {}", packet.getSourceIP(), packet.getDestIP(), reason);
    }

    public Map<String, Object> getStats() {
        Map<String, Object> stats = new HashMap<>();
        stats.put("capturing", capturing);
        stats.put("totalPacketsCaptured", totalPacketsCaptured.get());
        stats.put("totalBytesCaptured", totalBytesCaptured.get());
        stats.put("suspiciousPackets", suspiciousPackets.get());
        stats.put("bufferSize", packetBuffer.size());
        stats.put("activeSessions", sessions.size());
        stats.put("alertQueueSize", alertQueue.size());

        Map<String, PacketStatistics> protoStats = new HashMap<>();
        for (Map.Entry<String, PacketStatistics> entry : protocolStats.entrySet()) {
            protoStats.put(entry.getKey(), entry.getValue());
        }
        stats.put("protocolStats", protoStats);

        return stats;
    }

    public List<CapturedPacket> getRecentPackets(int limit) {
        List<CapturedPacket> packets = new ArrayList<>();
        int count = 0;
        for (CapturedPacket packet : packetBuffer.values()) {
            if (count++ >= limit) break;
            packets.add(packet);
        }
        return packets;
    }

    public List<CapturedPacket> getPacketsByIP(String ip, int limit) {
        List<CapturedPacket> packets = new ArrayList<>();
        List<CapturedPacket> history = packetHistory.get(ip);
        if (history != null) {
            int count = 0;
            for (CapturedPacket packet : history) {
                if (count++ >= limit) break;
                packets.add(packet);
            }
        }
        return packets;
    }

    public List<SnifferAlert> getRecentAlerts(int limit) {
        List<SnifferAlert> alerts = new ArrayList<>();
        int count = 0;
        for (SnifferAlert alert : alertQueue) {
            if (count++ >= limit) break;
            alerts.add(alert);
        }
        return alerts;
    }

    public Map<String, SessionInfo> getActiveSessions() {
        return new HashMap<>(sessions);
    }

    public void clearBuffer() {
        packetBuffer.clear();
        logger.info("Packet buffer cleared");
    }

    public void exportPackets(String format) {
        logger.info("Exporting packets in {} format", format);
    }

    public static class CapturedPacket {
        private final String packetId;
        private final String sourceIP;
        private final String destIP;
        private final int sourcePort;
        private final int destPort;
        private final String protocol;
        private final byte[] payload;
        private final int length;
        private final LocalDateTime timestamp;

        public CapturedPacket(String packetId, String sourceIP, String destIP, int sourcePort,
                           int destPort, String protocol, byte[] payload, int length, LocalDateTime timestamp) {
            this.packetId = packetId;
            this.sourceIP = sourceIP;
            this.destIP = destIP;
            this.sourcePort = sourcePort;
            this.destPort = destPort;
            this.protocol = protocol;
            this.payload = payload;
            this.length = length;
            this.timestamp = timestamp;
        }

        public String getPacketId() { return packetId; }
        public String getSourceIP() { return sourceIP; }
        public String getDestIP() { return destIP; }
        public int getSourcePort() { return sourcePort; }
        public int getDestPort() { return destPort; }
        public String getProtocol() { return protocol; }
        public byte[] getPayload() { return payload; }
        public int getLength() { return length; }
        public LocalDateTime getTimestamp() { return timestamp; }
    }

    public static class PacketStatistics {
        private final String protocolName;
        private final AtomicLong packetCount = new AtomicLong(0);
        private final AtomicLong byteCount = new AtomicLong(0);

        public PacketStatistics(String protocolName) {
            this.protocolName = protocolName;
        }

        public void incrementPacketCount() { packetCount.incrementAndGet(); }
        public void addBytes(int bytes) { byteCount.addAndGet(bytes); }

        public String getProtocolName() { return protocolName; }
        public long getPacketCount() { return packetCount.get(); }
        public long getByteCount() { return byteCount.get(); }
    }

    public static class SessionInfo {
        private final String sourceIP;
        private final String destIP;
        private final int destPort;
        private volatile long packetCount;
        private volatile long totalBytes;
        private volatile long startTime;
        private volatile long lastPacketTime;
        private volatile CapturedPacket latestPacket;

        public SessionInfo(String sourceIP, String destIP, int destPort) {
            this.sourceIP = sourceIP;
            this.destIP = destIP;
            this.destPort = destPort;
            this.startTime = System.currentTimeMillis();
            this.lastPacketTime = startTime;
        }

        public void addPacket(CapturedPacket packet) {
            packetCount++;
            totalBytes += packet.getLength();
            lastPacketTime = System.currentTimeMillis();
            latestPacket = packet;
        }

        public String getSourceIP() { return sourceIP; }
        public String getDestIP() { return destIP; }
        public int getDestPort() { return destPort; }
        public long getPacketCount() { return packetCount; }
        public long getTotalBytes() { return totalBytes; }
        public long getStartTime() { return startTime; }
        public long getLastPacketTime() { return lastPacketTime; }
        public CapturedPacket getLatestPacket() { return latestPacket; }
    }

    public static class SnifferAlert {
        private final String sourceIP;
        private final String destIP;
        private final String protocol;
        private final String reason;
        private final LocalDateTime timestamp;

        public SnifferAlert(String sourceIP, String destIP, String protocol, String reason, LocalDateTime timestamp) {
            this.sourceIP = sourceIP;
            this.destIP = destIP;
            this.protocol = protocol;
            this.reason = reason;
            this.timestamp = timestamp;
        }

        public String getSourceIP() { return sourceIP; }
        public String getDestIP() { return destIP; }
        public String getProtocol() { return protocol; }
        public String getReason() { return reason; }
        public LocalDateTime getTimestamp() { return timestamp; }
    }
}
