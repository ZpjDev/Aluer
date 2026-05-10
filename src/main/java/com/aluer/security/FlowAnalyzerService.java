package com.aluer.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.atomic.AtomicLong;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

@Component
public class FlowAnalyzerService {
    private static final Logger logger = LoggerFactory.getLogger(FlowAnalyzerService.class);

    private final Map<String, FlowRecord> activeFlows = new ConcurrentHashMap<>();
    private final Map<String, FlowStatistics> flowStatistics = new ConcurrentHashMap<>();
    private final Queue<FlowAlert> alertQueue = new ConcurrentLinkedQueue<>();
    private final Map<String, List<HistoryEntry>> flowHistory = new ConcurrentHashMap<>();
    private final AtomicLong totalFlowsAnalyzed = new AtomicLong(0);
    private final AtomicLong totalBytesTransferred = new AtomicLong(0);

    private static final int FLOW_TIMEOUT_SECONDS = 300;
    private static final int MAX_ACTIVE_FLOWS = 10000;
    private static final long BYTES_THRESHOLD = 100 * 1024 * 1024;
    private static final DateTimeFormatter DATE_FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    public FlowAnalyzerService() {
        logger.info("Flow Analyzer Service initialized");
    }

    public void recordPacket(String sourceIP, String destIP, int sourcePort, int destPort,
                           int packetSize, String protocol) {
        String flowKey = generateFlowKey(sourceIP, destIP, sourcePort, destPort, protocol);

        FlowRecord flow = activeFlows.computeIfAbsent(flowKey, k -> {
            FlowRecord newFlow = new FlowRecord(sourceIP, destIP, sourcePort, destPort, protocol);
            totalFlowsAnalyzed.incrementAndGet();
            return newFlow;
        });

        flow.addPacket(packetSize);
        totalBytesTransferred.addAndGet(packetSize);

        if (flow.getTotalBytes() > BYTES_THRESHOLD) {
            triggerAlert(flow, "HIGH_VOLUME", "异常高流量传输: " + formatBytes(flow.getTotalBytes()));
        }

        if (flow.getPacketCount() > 10000) {
            triggerAlert(flow, "HIGH_PACKET_COUNT", "高数据包数量: " + flow.getPacketCount());
        }

        long flowAge = System.currentTimeMillis() - flow.getStartTime();
        if (flowAge > FLOW_TIMEOUT_SECONDS * 1000) {
            expireFlow(flowKey);
        }
    }

    public void recordBidirectionalFlow(String clientIP, String serverIP, int clientPort, int serverPort,
                                       int clientToServerBytes, int serverToClientBytes, String protocol) {
        String forwardKey = generateFlowKey(clientIP, serverIP, clientPort, serverPort, protocol);
        String reverseKey = generateFlowKey(serverIP, clientIP, serverPort, clientPort, protocol);

        FlowRecord forwardFlow = activeFlows.computeIfAbsent(forwardKey, k -> {
            FlowRecord f = new FlowRecord(clientIP, serverIP, clientPort, serverPort, protocol);
            totalFlowsAnalyzed.incrementAndGet();
            return f;
        });
        forwardFlow.addPacket(clientToServerBytes);

        FlowRecord reverseFlow = activeFlows.computeIfAbsent(reverseKey, k -> {
            FlowRecord f = new FlowRecord(serverIP, clientIP, serverPort, clientPort, protocol);
            totalFlowsAnalyzed.incrementAndGet();
            return f;
        });
        reverseFlow.addPacket(serverToClientBytes);

        totalBytesTransferred.addAndGet(clientToServerBytes + serverToClientBytes);

        analyzeFlowRatio(forwardFlow, reverseFlow);
    }

    private void analyzeFlowRatio(FlowRecord forward, FlowRecord reverse) {
        long forwardBytes = forward.getTotalBytes();
        long reverseBytes = reverse.getTotalBytes();

        if (forwardBytes > 0 && reverseBytes > 0) {
            double ratio = (double) forwardBytes / reverseBytes;

            if (ratio > 100 || ratio < 0.01) {
                triggerAlert(forward, "ASYMMETRIC_FLOW", "不对称流量比率: " + String.format("%.2f", ratio));
            }
        }

        long forwardPackets = forward.getPacketCount();
        long reversePackets = reverse.getPacketCount();
        if (forwardPackets > 0 && reversePackets > 0) {
            double packetRatio = (double) forwardPackets / reversePackets;
            if (packetRatio > 50 || packetRatio < 0.02) {
                triggerAlert(forward, "PACKET_RATIO_ANOMALY", "数据包比率异常: " + String.format("%.2f", packetRatio));
            }
        }
    }

    public Map<String, Object> analyzeFlowPatterns(String ip) {
        Map<String, Object> analysis = new HashMap<>();

        List<FlowRecord> relatedFlows = new ArrayList<>();
        for (FlowRecord flow : activeFlows.values()) {
            if (flow.getSourceIP().equals(ip) || flow.getDestIP().equals(ip)) {
                relatedFlows.add(flow);
            }
        }

        if (relatedFlows.isEmpty()) {
            analysis.put("status", "no_flows");
            return analysis;
        }

        long totalBytes = relatedFlows.stream().mapToLong(FlowRecord::getTotalBytes).sum();
        long totalPackets = relatedFlows.stream().mapToLong(FlowRecord::getPacketCount).sum();

        analysis.put("totalFlows", relatedFlows.size());
        analysis.put("totalBytes", totalBytes);
        analysis.put("totalPackets", totalPackets);

        Map<String, Long> destPorts = new HashMap<>();
        Map<String, Long> protocols = new HashMap<>();

        for (FlowRecord flow : relatedFlows) {
            destPorts.merge(String.valueOf(flow.getDestPort()), 1L, Long::sum);
            protocols.merge(flow.getProtocol(), 1L, Long::sum);
        }

        analysis.put("destinationPorts", destPorts);
        analysis.put("protocols", protocols);

        double avgBytesPerFlow = (double) totalBytes / relatedFlows.size();
        analysis.put("avgBytesPerFlow", avgBytesPerFlow);

        if (avgBytesPerFlow > 10 * 1024 * 1024) {
            analysis.put("warning", "异常高流量");
        }

        return analysis;
    }

    public List<FlowRecord> getTopFlows(int limit, String sortBy) {
        List<FlowRecord> flows = new ArrayList<>(activeFlows.values());

        if ("bytes".equals(sortBy)) {
            flows.sort((a, b) -> Long.compare(b.getTotalBytes(), a.getTotalBytes()));
        } else if ("packets".equals(sortBy)) {
            flows.sort((a, b) -> Long.compare(b.getPacketCount(), a.getPacketCount()));
        } else if ("duration".equals(sortBy)) {
            flows.sort((a, b) -> Long.compare(b.getDuration(), a.getDuration()));
        } else {
            flows.sort((a, b) -> Long.compare(b.getTotalBytes(), a.getTotalBytes()));
        }

        return flows.subList(0, Math.min(limit, flows.size()));
    }

    public Map<String, FlowStatistics> getProtocolStatistics() {
        Map<String, FlowStatistics> stats = new HashMap<>();

        for (FlowRecord flow : activeFlows.values()) {
            FlowStatistics protocolStats = stats.computeIfAbsent(flow.getProtocol(), k -> new FlowStatistics(flow.getProtocol()));
            protocolStats.addFlow(flow);
        }

        return stats;
    }

    public Map<String, Object> getTrafficMatrix() {
        Map<String, Object> matrix = new HashMap<>();

        Map<String, Long> sourceIPTraffic = new HashMap<>();
        Map<String, Long> destIPTraffic = new HashMap<>();
        Map<String, Long> protocolTraffic = new HashMap<>();
        Map<String, Long> portTraffic = new HashMap<>();

        for (FlowRecord flow : activeFlows.values()) {
            sourceIPTraffic.merge(flow.getSourceIP(), flow.getTotalBytes(), Long::sum);
            destIPTraffic.merge(flow.getDestIP(), flow.getTotalBytes(), Long::sum);
            protocolTraffic.merge(flow.getProtocol(), flow.getTotalBytes(), Long::sum);
            portTraffic.merge(String.valueOf(flow.getDestPort()), flow.getTotalBytes(), Long::sum);
        }

        matrix.put("bySourceIP", sortByValue(sourceIPTraffic, 10));
        matrix.put("byDestIP", sortByValue(destIPTraffic, 10));
        matrix.put("byProtocol", sortByValue(protocolTraffic, 10));
        matrix.put("byPort", sortByValue(portTraffic, 10));

        return matrix;
    }

    private Map<String, Long> sortByValue(Map<String, Long> map, int limit) {
        return map.entrySet().stream()
            .sorted(Map.Entry.<String, Long>comparingByValue().reversed())
            .limit(limit)
            .collect(LinkedHashMap::new,
                (m, e) -> m.put(e.getKey(), e.getValue()),
                LinkedHashMap::putAll);
    }

    public void detectAnomalies() {
        if (activeFlows.size() > MAX_ACTIVE_FLOWS) {
            logger.warn("High number of active flows: {}", activeFlows.size());
        }

        for (FlowRecord flow : activeFlows.values()) {
            if (flow.getPacketCount() > 0) {
                double avgPacketSize = (double) flow.getTotalBytes() / flow.getPacketCount();
                if (avgPacketSize > 10000) {
                    triggerAlert(flow, "LARGE_AVG_PACKET", "平均数据包过大: " + String.format("%.0f", avgPacketSize) + " bytes");
                }
                if (avgPacketSize < 10) {
                    triggerAlert(flow, "SMALL_AVG_PACKET", "平均数据包过小: " + String.format("%.0f", avgPacketSize) + " bytes");
                }
            }
        }
    }

    public void expireFlow(String flowKey) {
        FlowRecord flow = activeFlows.remove(flowKey);
        if (flow != null) {
            List<HistoryEntry> history = flowHistory.computeIfAbsent(flow.getSourceIP(), k -> new ArrayList<>());
            history.add(new HistoryEntry(flow.getDestIP(), flow.getTotalBytes(), flow.getPacketCount(), LocalDateTime.now()));

            if (history.size() > 1000) {
                history.subList(0, 500).clear();
            }

            FlowStatistics stats = flowStatistics.get(flow.getProtocol());
            if (stats != null) {
                stats.recordCompletedFlow(flow);
            }
        }
    }

    public Map<String, Object> getStats() {
        Map<String, Object> stats = new HashMap<>();
        stats.put("totalFlowsAnalyzed", totalFlowsAnalyzed.get());
        stats.put("totalBytesTransferred", totalBytesTransferred.get());
        stats.put("activeFlows", activeFlows.size());
        stats.put("alertQueueSize", alertQueue.size());

        long totalFlowBytes = activeFlows.values().stream().mapToLong(FlowRecord::getTotalBytes).sum();
        stats.put("activeFlowBytes", totalFlowBytes);

        return stats;
    }

    public List<FlowAlert> getRecentAlerts(int limit) {
        List<FlowAlert> alerts = new ArrayList<>();
        int count = 0;
        for (FlowAlert alert : alertQueue) {
            if (count++ >= limit) break;
            alerts.add(alert);
        }
        return alerts;
    }

    private void triggerAlert(FlowRecord flow, String alertType, String details) {
        FlowAlert alert = new FlowAlert(
            flow.getSourceIP(),
            flow.getDestIP(),
            alertType,
            details,
            flow.getTotalBytes(),
            LocalDateTime.now()
        );
        alertQueue.offer(alert);

        if (alertQueue.size() > 1000) {
            alertQueue.poll();
        }

        logger.warn("Flow Alert: {} - {} -> {}: {}", alertType, flow.getSourceIP(), flow.getDestIP(), details);
    }

    private String generateFlowKey(String sourceIP, String destIP, int sourcePort, int destPort, String protocol) {
        return sourceIP + "-" + destIP + "-" + sourcePort + "-" + destPort + "-" + protocol;
    }

    private String formatBytes(long bytes) {
        if (bytes < 1024) return bytes + " B";
        if (bytes < 1024 * 1024) return String.format("%.2f KB", bytes / 1024.0);
        if (bytes < 1024 * 1024 * 1024) return String.format("%.2f MB", bytes / (1024.0 * 1024));
        return String.format("%.2f GB", bytes / (1024.0 * 1024 * 1024));
    }

    public static class FlowRecord {
        private final String sourceIP;
        private final String destIP;
        private final int sourcePort;
        private final int destPort;
        private final String protocol;
        private final long startTime;
        private volatile long lastPacketTime;
        private volatile long packetCount;
        private volatile long totalBytes;

        public FlowRecord(String sourceIP, String destIP, int sourcePort, int destPort, String protocol) {
            this.sourceIP = sourceIP;
            this.destIP = destIP;
            this.sourcePort = sourcePort;
            this.destPort = destPort;
            this.protocol = protocol;
            this.startTime = System.currentTimeMillis();
            this.lastPacketTime = startTime;
            this.packetCount = 0;
            this.totalBytes = 0;
        }

        public synchronized void addPacket(int size) {
            packetCount++;
            totalBytes += size;
            lastPacketTime = System.currentTimeMillis();
        }

        public long getDuration() {
            return lastPacketTime - startTime;
        }

        public String getSourceIP() { return sourceIP; }
        public String getDestIP() { return destIP; }
        public int getSourcePort() { return sourcePort; }
        public int getDestPort() { return destPort; }
        public String getProtocol() { return protocol; }
        public long getStartTime() { return startTime; }
        public long getLastPacketTime() { return lastPacketTime; }
        public long getPacketCount() { return packetCount; }
        public long getTotalBytes() { return totalBytes; }
    }

    public static class FlowStatistics {
        private final String protocol;
        private final AtomicLong totalFlows = new AtomicLong(0);
        private final AtomicLong completedFlows = new AtomicLong(0);
        private final AtomicLong totalBytes = new AtomicLong(0);
        private final AtomicLong totalPackets = new AtomicLong(0);

        public FlowStatistics(String protocol) {
            this.protocol = protocol;
        }

        public void addFlow(FlowRecord flow) {
            totalFlows.incrementAndGet();
            totalBytes.addAndGet(flow.getTotalBytes());
            totalPackets.addAndGet(flow.getPacketCount());
        }

        public void recordCompletedFlow(FlowRecord flow) {
            completedFlows.incrementAndGet();
        }

        public String getProtocol() { return protocol; }
        public long getTotalFlows() { return totalFlows.get(); }
        public long getCompletedFlows() { return completedFlows.get(); }
        public long getTotalBytes() { return totalBytes.get(); }
        public long getTotalPackets() { return totalPackets.get(); }
    }

    public static class FlowAlert {
        private final String sourceIP;
        private final String destIP;
        private final String alertType;
        private final String details;
        private final long bytes;
        private final LocalDateTime timestamp;

        public FlowAlert(String sourceIP, String destIP, String alertType, String details, long bytes, LocalDateTime timestamp) {
            this.sourceIP = sourceIP;
            this.destIP = destIP;
            this.alertType = alertType;
            this.details = details;
            this.bytes = bytes;
            this.timestamp = timestamp;
        }

        public String getSourceIP() { return sourceIP; }
        public String getDestIP() { return destIP; }
        public String getAlertType() { return alertType; }
        public String getDetails() { return details; }
        public long getBytes() { return bytes; }
        public LocalDateTime getTimestamp() { return timestamp; }
    }

    public static class HistoryEntry {
        private final String destIP;
        private final long bytes;
        private final long packets;
        private final LocalDateTime timestamp;

        public HistoryEntry(String destIP, long bytes, long packets, LocalDateTime timestamp) {
            this.destIP = destIP;
            this.bytes = bytes;
            this.packets = packets;
            this.timestamp = timestamp;
        }

        public String getDestIP() { return destIP; }
        public long getBytes() { return bytes; }
        public long getPackets() { return packets; }
        public LocalDateTime getTimestamp() { return timestamp; }
    }
}
