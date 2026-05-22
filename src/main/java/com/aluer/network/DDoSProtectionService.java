package com.aluer.network;

import org.springframework.stereotype.Service;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;
import java.net.*;
import java.nio.*;

@Service
public class DDoSProtectionService {

    private final Map<String, TrafficRecord> trafficMap = new ConcurrentHashMap<>();
    private final Map<String, BlockedIP> blockedIPs = new ConcurrentHashMap<>();
    private final Map<String, List<Long>> requestTimestamps = new ConcurrentHashMap<>();
    private final Map<String, AtomicInteger> connectionCounts = new ConcurrentHashMap<>();
    private final Queue<AttackEvent> attackLog = new ConcurrentLinkedQueue<>();
    private final ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(2);

    private static final int MAX_REQUESTS_PER_SECOND = 100;
    private static final int MAX_CONNECTIONS_PER_IP = 50;
    private static final long BLOCK_DURATION = 300000;
    private static final long TRAFFIC_WINDOW = 1000;
    private static final int MAX_PACKET_SIZE = 65535;
    private static final double MAX_BYTES_PER_SECOND = 100_000_000;

    private final AtomicLong totalBlocked = new AtomicLong(0);
    private final AtomicLong totalDetected = new AtomicLong(0);

    public DDoSProtectionService() {
        startCleanupTask();
    }

    public boolean checkConnection(String ip) {
        if (isBlocked(ip)) {
            logAttack(ip, "BLOCKED_CONNECTION", "Connection from blocked IP");
            return false;
        }

        AtomicInteger count = connectionCounts.computeIfAbsent(ip, k -> new AtomicInteger(0));
        int current = count.incrementAndGet();

        if (current > MAX_CONNECTIONS_PER_IP) {
            blockIP(ip, "CONNECTION_FLOOD", "Too many connections: " + current);
            return false;
        }

        return true;
    }

    public boolean checkRequest(String ip, String endpoint) {
        if (isBlocked(ip)) {
            return false;
        }

        List<Long> timestamps = requestTimestamps.computeIfAbsent(ip + ":" + endpoint, k -> new CopyOnWriteArrayList<>());
        long now = System.currentTimeMillis();

        timestamps.removeIf(t -> now - t > TRAFFIC_WINDOW);
        timestamps.add(now);

        if (timestamps.size() > MAX_REQUESTS_PER_SECOND) {
            blockIP(ip, "REQUEST_FLOOD", "Too many requests: " + timestamps.size());
            return false;
        }

        return true;
    }

    public boolean checkPacketSize(String ip, int size) {
        if (isBlocked(ip)) {
            return false;
        }

        if (size > MAX_PACKET_SIZE) {
            blockIP(ip, "OVERSIZED_PACKET", "Packet size: " + size);
            return false;
        }

        return true;
    }

    public boolean checkBandwidth(String ip, long bytes) {
        if (isBlocked(ip)) {
            return false;
        }

        TrafficRecord record = trafficMap.computeIfAbsent(ip, k -> new TrafficRecord(ip));
        record.addBytes(bytes);

        if (record.getBytesPerSecond() > MAX_BYTES_PER_SECOND) {
            blockIP(ip, "BANDWIDTH_EXCEED", "Bandwidth: " + record.getBytesPerSecond());
            return false;
        }

        return true;
    }

    public boolean checkPort(String ip, int port) {
        if (isBlocked(ip)) {
            return false;
        }

        Set<Integer> scannedPorts = recordPortScan(ip, port);

        if (scannedPorts.size() > 20) {
            blockIP(ip, "PORT_SCAN", "Scanned " + scannedPorts.size() + " ports");
            return false;
        }

        return true;
    }

    private Set<Integer> recordPortScan(String ip, int port) {
        Map<Integer, Long> portScans = portScanMap.computeIfAbsent(ip, k -> new ConcurrentHashMap<>());
        long now = System.currentTimeMillis();

        portScans.entrySet().removeIf(e -> now - e.getValue() > 60000);
        portScans.put(port, now);

        return portScans.keySet();
    }

    private final Map<String, Map<Integer, Long>> portScanMap = new ConcurrentHashMap<>();

    public boolean checkSynFlood(String ip) {
        if (isBlocked(ip)) {
            return false;
        }

        AtomicInteger synCount = synCountMap.computeIfAbsent(ip, k -> new AtomicInteger(0));
        int count = synCount.incrementAndGet();

        if (count > 100) {
            blockIP(ip, "SYN_FLOOD", "SYN packets: " + count);
            return false;
        }

        return true;
    }

    private final Map<String, AtomicInteger> synCountMap = new ConcurrentHashMap<>();

    public boolean checkFragmentation(String ip, short identification, int offset) {
        if (isBlocked(ip)) {
            return false;
        }

        FragmentRecord frag = fragmentationMap.computeIfAbsent(ip, k -> new FragmentRecord());
        if (frag.addFragment(identification, offset)) {
            blockIP(ip, "FRAGMENTATION_ATTACK", "Too many fragments");
            return false;
        }

        return true;
    }

    private final Map<String, FragmentRecord> fragmentationMap = new ConcurrentHashMap<>();

    public boolean checkUDPAmplification(String ip, int payloadSize) {
        if (isBlocked(ip)) {
            return false;
        }

        AtomicInteger udpCount = udpAmplificationMap.computeIfAbsent(ip, k -> new AtomicInteger(0));
        int count = udpCount.incrementAndGet();

        if (count > 50 && payloadSize > 1000) {
            blockIP(ip, "UDP_AMPLIFICATION", "Large UDP packets: " + count);
            return false;
        }

        return true;
    }

    private final Map<String, AtomicInteger> udpAmplificationMap = new ConcurrentHashMap<>();

    public boolean checkICMPFlood(String ip) {
        if (isBlocked(ip)) {
            return false;
        }

        AtomicInteger icmpCount = icmpFloodMap.computeIfAbsent(ip, k -> new AtomicInteger(0));
        int count = icmpCount.incrementAndGet();

        if (count > 50) {
            blockIP(ip, "ICMP_FLOOD", "ICMP packets: " + count);
            return false;
        }

        return true;
    }

    private final Map<String, AtomicInteger> icmpFloodMap = new ConcurrentHashMap<>();

    public boolean checkHTTPFlood(String ip, String userAgent, String path) {
        if (isBlocked(ip)) {
            return false;
        }

        List<String> paths = httpFloodMap.computeIfAbsent(ip, k -> new CopyOnWriteArrayList<>());
        long now = System.currentTimeMillis();

        paths.add(now + ":" + path);
        paths.removeIf(p -> Long.parseLong(p.split(":")[0]) < now - 10000);

        Map<String, Integer> pathCounts = new HashMap<>();
        for (String p : paths) {
            String pathOnly = p.split(":")[1];
            pathCounts.merge(pathOnly, 1, Integer::sum);
        }

        String problematicPath = null;
        for (Map.Entry<String, Integer> entry : pathCounts.entrySet()) {
            if (entry.getValue() > 30) {
                problematicPath = entry.getKey();
                blockIP(ip, "HTTP_FLOOD", "Path " + problematicPath + " hit " + entry.getValue() + " times");
                return false;
            }
        }

        if (isKnownBot(userAgent)) {
            return true;
        }

        if (paths.size() > 200) {
            blockIP(ip, "HTTP_FLOOD", "Too many requests");
            return false;
        }

        return true;
    }

    private final Map<String, List<String>> httpFloodMap = new ConcurrentHashMap<>();

    private boolean isKnownBot(String userAgent) {
        if (userAgent == null) return false;
        String lower = userAgent.toLowerCase();
        return lower.contains("googlebot") || lower.contains("bingbot") || 
               lower.contains("slurp") || lower.contains("duckduckbot");
    }

    public boolean checkSSLHandshake(String ip) {
        if (isBlocked(ip)) {
            return false;
        }

        AtomicInteger handshakeCount = sslHandshakeMap.computeIfAbsent(ip, k -> new AtomicInteger(0));
        int count = handshakeCount.incrementAndGet();

        if (count > 30) {
            blockIP(ip, "SSL_FLOOD", "SSL handshakes: " + count);
            return false;
        }

        return true;
    }

    private final Map<String, AtomicInteger> sslHandshakeMap = new ConcurrentHashMap<>();

    public void blockIP(String ip, String reason, String details) {
        if (blockedIPs.containsKey(ip)) {
            BlockedIP existing = blockedIPs.get(ip);
            existing.count.incrementAndGet();
            existing.lastBlockTime = System.currentTimeMillis();
        } else {
            BlockedIP blocked = new BlockedIP(ip, reason, details);
            blockedIPs.put(ip, blocked);
            totalBlocked.incrementAndGet();
        }

        logAttack(ip, reason, details);
    }

    public void unblockIP(String ip) {
        blockedIPs.remove(ip);
        trafficMap.remove(ip);
        requestTimestamps.entrySet().removeIf(e -> e.getKey().startsWith(ip));
        connectionCounts.remove(ip);
    }

    public boolean isBlocked(String ip) {
        BlockedIP blocked = blockedIPs.get(ip);
        if (blocked == null) {
            return false;
        }

        if (System.currentTimeMillis() - blocked.lastBlockTime > BLOCK_DURATION) {
            unblockIP(ip);
            return false;
        }

        return true;
    }

    public BlockedIP getBlockInfo(String ip) {
        return blockedIPs.get(ip);
    }

    public Collection<BlockedIP> getAllBlockedIPs() {
        return blockedIPs.values();
    }

    public void logAttack(String ip, String type, String details) {
        AttackEvent event = new AttackEvent(ip, type, details, System.currentTimeMillis());
        attackLog.offer(event);
        totalDetected.incrementAndGet();

        while (attackLog.size() > 10000) {
            attackLog.poll();
        }
    }

    public List<AttackEvent> getAttackLog(int limit) {
        List<AttackEvent> result = new ArrayList<>();
        int count = 0;
        for (AttackEvent event : attackLog) {
            if (count++ >= limit) break;
            result.add(event);
        }
        return result;
    }

    private void startCleanupTask() {
        scheduler.scheduleAtFixedRate(() -> {
            long now = System.currentTimeMillis();

            for (Map.Entry<String, BlockedIP> entry : blockedIPs.entrySet()) {
                if (now - entry.getValue().lastBlockTime > BLOCK_DURATION) {
                    unblockIP(entry.getKey());
                }
            }

            trafficMap.entrySet().removeIf(e -> e.getValue().isStale());
            requestTimestamps.entrySet().removeIf(e -> {
                List<Long> list = e.getValue();
                list.removeIf(t -> now - t > TRAFFIC_WINDOW);
                return list.isEmpty();
            });

            connectionCounts.entrySet().removeIf(e -> e.getValue().get() == 0);

            synCountMap.entrySet().removeIf(e -> e.getValue().get() == 0);
            icmpFloodMap.entrySet().removeIf(e -> e.getValue().get() == 0);
            udpAmplificationMap.entrySet().removeIf(e -> e.getValue().get() == 0);

        }, 30, 30, TimeUnit.SECONDS);
    }

    public Map<String, Object> getStats() {
        Map<String, Object> stats = new HashMap<>();
        stats.put("blockedIPs", blockedIPs.size());
        stats.put("totalBlocked", totalBlocked.get());
        stats.put("totalDetected", totalDetected.get());
        stats.put("activeTrafficRecords", trafficMap.size());
        return stats;
    }

    public static class TrafficRecord {
        private final String ip;
        private final AtomicLong totalBytes = new AtomicLong(0);
        private final AtomicLong windowBytes = new AtomicLong(0);
        private volatile long lastUpdate = System.currentTimeMillis();

        public TrafficRecord(String ip) {
            this.ip = ip;
        }

        public void addBytes(long bytes) {
            long now = System.currentTimeMillis();
            if (now - lastUpdate > 1000) {
                windowBytes.set(bytes);
                lastUpdate = now;
            } else {
                windowBytes.addAndGet(bytes);
            }
            totalBytes.addAndGet(bytes);
        }

        public long getBytesPerSecond() {
            return windowBytes.get();
        }

        public long getTotalBytes() {
            return totalBytes.get();
        }

        public boolean isStale() {
            return System.currentTimeMillis() - lastUpdate > 60000;
        }
    }

    public static class BlockedIP {
        public final String ip;
        public final String reason;
        public final String details;
        public final long firstBlockTime;
        public volatile long lastBlockTime;
        public final AtomicInteger count = new AtomicInteger(1);

        public BlockedIP(String ip, String reason, String details) {
            this.ip = ip;
            this.reason = reason;
            this.details = details;
            this.firstBlockTime = System.currentTimeMillis();
            this.lastBlockTime = System.currentTimeMillis();
        }
    }

    public static class AttackEvent {
        public final String ip;
        public final String type;
        public final String details;
        public final long timestamp;

        public AttackEvent(String ip, String type, String details, long timestamp) {
            this.ip = ip;
            this.type = type;
            this.details = details;
            this.timestamp = timestamp;
        }
    }

    public static class FragmentRecord {
        private final Map<Short, Set<Integer>> fragments = new ConcurrentHashMap<>();

        public synchronized boolean addFragment(short identification, int offset) {
            Set<Integer> offsets = fragments.computeIfAbsent(identification, k -> ConcurrentHashMap.newKeySet());
            offsets.add(offset);

            if (offsets.size() > 100) {
                fragments.remove(identification);
                return true;
            }
            return false;
        }
    }
}
