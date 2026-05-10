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
public class TrafficShapingService {
    private static final Logger logger = LoggerFactory.getLogger(TrafficShapingService.class);

    private final Map<String, TrafficClass> trafficClasses = new ConcurrentHashMap<>();
    private final Map<String, Queue<PacketRecord>> packetQueues = new ConcurrentHashMap<>();
    private final Map<String, TokenBucket> tokenBuckets = new ConcurrentHashMap<>();
    private final Map<String, TrafficStats> trafficStats = new ConcurrentHashMap<>();
    private final Queue<TrafficEvent> eventLog = new ConcurrentLinkedQueue<>();
    private final AtomicLong totalPacketsShaped = new AtomicLong(0);
    private final AtomicLong totalPacketsDropped = new AtomicLong(0);
    private final AtomicLong totalPacketsDelayed = new AtomicLong(0);

    private static final DateTimeFormatter DATE_FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    public TrafficShapingService() {
        initializeDefaultClasses();
    }

    private void initializeDefaultClasses() {
        addTrafficClass("high-priority", 1000, 100, 50);
        addTrafficClass("medium-priority", 500, 200, 100);
        addTrafficClass("low-priority", 100, 500, 200);
        addTrafficClass("bulk", 50, 1000, 500);

        for (String className : trafficClasses.keySet()) {
            packetQueues.put(className, new ConcurrentLinkedQueue<>());
            tokenBuckets.put(className, new TokenBucket(
                trafficClasses.get(className).getBucketSize(),
                trafficClasses.get(className).getRefillRate()
            ));
            trafficStats.put(className, new TrafficStats(className));
        }
    }

    public void addTrafficClass(String name, int bucketSize, int refillRate, int maxDelay) {
        TrafficClass tc = new TrafficClass(name, bucketSize, refillRate, maxDelay);
        trafficClasses.put(name, tc);
        logger.info("Added traffic class: {}", name);
    }

    public boolean processPacket(String sourceIP, String destIP, int port, int packetSize, String protocol) {
        String trafficClass = classifyPacket(sourceIP, destIP, port, protocol);
        TokenBucket bucket = tokenBuckets.get(trafficClass);
        TrafficStats stats = trafficStats.get(trafficClass);

        if (bucket == null || stats == null) {
            return false;
        }

        if (!bucket.consume(packetSize)) {
            totalPacketsDropped.incrementAndGet();
            stats.recordDropped(packetSize);
            logEvent(sourceIP, destIP, packetSize, "DROPPED", trafficClass);
            return false;
        }

        Queue<PacketRecord> queue = packetQueues.get(trafficClass);
        if (queue != null && queue.size() > 100) {
            totalPacketsDropped.incrementAndGet();
            stats.recordDropped(packetSize);
            logEvent(sourceIP, destIP, packetSize, "QUEUE_FULL", trafficClass);
            return false;
        }

        PacketRecord record = new PacketRecord(sourceIP, destIP, packetSize, LocalDateTime.now());
        if (queue != null) {
            queue.offer(record);
        }

        totalPacketsShaped.incrementAndGet();
        stats.recordProcessed(packetSize);
        logEvent(sourceIP, destIP, packetSize, "SHAPED", trafficClass);

        return true;
    }

    private String classifyPacket(String sourceIP, String destIP, int port, String protocol) {
        if (isPriorityIP(sourceIP)) {
            return "high-priority";
        }
        if (port == 25565 || port == 25575) {
            return "high-priority";
        }
        if ("UDP".equalsIgnoreCase(protocol)) {
            return "medium-priority";
        }
        if (isKnownServer(port)) {
            return "medium-priority";
        }
        return "low-priority";
    }

    private boolean isPriorityIP(String ip) {
        return ip.startsWith("127.") || ip.startsWith("192.168.") || ip.startsWith("10.");
    }

    private boolean isKnownServer(int port) {
        return port > 0 && port < 1024;
    }

    public Map<String, Object> getStats() {
        Map<String, Object> stats = new HashMap<>();
        stats.put("totalPacketsShaped", totalPacketsShaped.get());
        stats.put("totalPacketsDropped", totalPacketsDropped.get());
        stats.put("totalPacketsDelayed", totalPacketsDelayed.get());

        Map<String, TrafficStats> classStats = new HashMap<>();
        for (Map.Entry<String, TrafficStats> entry : trafficStats.entrySet()) {
            classStats.put(entry.getKey(), entry.getValue());
        }
        stats.put("classStats", classStats);

        return stats;
    }

    public void adjustClassRate(String className, int newRefillRate) {
        TrafficClass tc = trafficClasses.get(className);
        if (tc != null) {
            tc.setRefillRate(newRefillRate);
            TokenBucket bucket = tokenBuckets.get(className);
            if (bucket != null) {
                bucket.setRate(newRefillRate);
            }
            logger.info("Adjusted rate for class {} to {}", className, newRefillRate);
        }
    }

    public void clearQueue(String className) {
        Queue<PacketRecord> queue = packetQueues.get(className);
        if (queue != null) {
            queue.clear();
            logger.info("Cleared queue for class: {}", className);
        }
    }

    private void logEvent(String sourceIP, String destIP, int size, String action, String trafficClass) {
        TrafficEvent event = new TrafficEvent(
            sourceIP, destIP, size, action, trafficClass, LocalDateTime.now()
        );
        eventLog.offer(event);

        if (eventLog.size() > 10000) {
            eventLog.poll();
        }
    }

    public List<TrafficEvent> getRecentEvents(int limit) {
        List<TrafficEvent> events = new ArrayList<>();
        int count = 0;
        for (TrafficEvent event : eventLog) {
            if (count++ >= limit) break;
            events.add(event);
        }
        return events;
    }

    public Map<String, Object> getDetailedStats(String className) {
        Map<String, Object> stats = new HashMap<>();
        TrafficClass tc = trafficClasses.get(className);
        TrafficStats ts = trafficStats.get(className);
        TokenBucket tb = tokenBuckets.get(className);

        if (tc != null) {
            stats.put("bucketSize", tc.getBucketSize());
            stats.put("refillRate", tc.getRefillRate());
            stats.put("maxDelay", tc.getMaxDelay());
        }
        if (ts != null) {
            stats.put("packetsProcessed", ts.getPacketsProcessed());
            stats.put("packetsDropped", ts.getPacketsDropped());
            stats.put("bytesProcessed", ts.getBytesProcessed());
        }
        if (tb != null) {
            stats.put("availableTokens", tb.getAvailableTokens());
        }

        return stats;
    }

    public static class TrafficClass {
        private final String name;
        private final int bucketSize;
        private int refillRate;
        private final int maxDelay;

        public TrafficClass(String name, int bucketSize, int refillRate, int maxDelay) {
            this.name = name;
            this.bucketSize = bucketSize;
            this.refillRate = refillRate;
            this.maxDelay = maxDelay;
        }

        public String getName() { return name; }
        public int getBucketSize() { return bucketSize; }
        public int getRefillRate() { return refillRate; }
        public int getMaxDelay() { return maxDelay; }
        public void setRefillRate(int refillRate) { this.refillRate = refillRate; }
    }

    public static class TokenBucket {
        private final int maxTokens;
        private volatile int availableTokens;
        private volatile int refillRate;
        private long lastRefillTime;

        public TokenBucket(int maxTokens, int refillRate) {
            this.maxTokens = maxTokens;
            this.availableTokens = maxTokens;
            this.refillRate = refillRate;
            this.lastRefillTime = System.currentTimeMillis();
        }

        public synchronized boolean consume(int tokens) {
            refill();
            if (availableTokens >= tokens) {
                availableTokens -= tokens;
                return true;
            }
            return false;
        }

        private void refill() {
            long now = System.currentTimeMillis();
            long elapsed = now - lastRefillTime;
            if (elapsed > 100) {
                int tokensToAdd = (int) (elapsed * refillRate / 1000);
                availableTokens = Math.min(maxTokens, availableTokens + tokensToAdd);
                lastRefillTime = now;
            }
        }

        public int getAvailableTokens() { return availableTokens; }
        public void setRate(int refillRate) { this.refillRate = refillRate; }
    }

    public static class PacketRecord {
        private final String sourceIP;
        private final String destIP;
        private final int size;
        private final LocalDateTime timestamp;

        public PacketRecord(String sourceIP, String destIP, int size, LocalDateTime timestamp) {
            this.sourceIP = sourceIP;
            this.destIP = destIP;
            this.size = size;
            this.timestamp = timestamp;
        }

        public String getSourceIP() { return sourceIP; }
        public String getDestIP() { return destIP; }
        public int getSize() { return size; }
        public LocalDateTime getTimestamp() { return timestamp; }
    }

    public static class TrafficStats {
        private final String className;
        private final AtomicLong packetsProcessed = new AtomicLong(0);
        private final AtomicLong packetsDropped = new AtomicLong(0);
        private final AtomicLong bytesProcessed = new AtomicLong(0);

        public TrafficStats(String className) {
            this.className = className;
        }

        public void recordProcessed(int size) {
            packetsProcessed.incrementAndGet();
            bytesProcessed.addAndGet(size);
        }

        public void recordDropped(int size) {
            packetsDropped.incrementAndGet();
        }

        public String getClassName() { return className; }
        public long getPacketsProcessed() { return packetsProcessed.get(); }
        public long getPacketsDropped() { return packetsDropped.get(); }
        public long getBytesProcessed() { return bytesProcessed.get(); }
    }

    public static class TrafficEvent {
        private final String sourceIP;
        private final String destIP;
        private final int size;
        private final String action;
        private final String trafficClass;
        private final LocalDateTime timestamp;

        public TrafficEvent(String sourceIP, String destIP, int size, String action,
                          String trafficClass, LocalDateTime timestamp) {
            this.sourceIP = sourceIP;
            this.destIP = destIP;
            this.size = size;
            this.action = action;
            this.trafficClass = trafficClass;
            this.timestamp = timestamp;
        }

        public String getSourceIP() { return sourceIP; }
        public String getDestIP() { return destIP; }
        public int getSize() { return size; }
        public String getAction() { return action; }
        public String getTrafficClass() { return trafficClass; }
        public LocalDateTime getTimestamp() { return timestamp; }
    }
}
