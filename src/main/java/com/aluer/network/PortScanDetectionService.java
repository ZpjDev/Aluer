package com.aluer.network;

import org.springframework.stereotype.Service;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;
import java.nio.file.*;
import java.io.*;

@Service
public class PortScanDetectionService {

    private final Map<String, ScanRecord> scanRecords = new ConcurrentHashMap<>();
    private final Map<String, BlockedScanner> blockedScanners = new ConcurrentHashMap<>();
    private final Queue<ScanEvent> scanLog = new ConcurrentLinkedQueue<>();
    private final ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(2);

    private static final int MAX_PORTS_SCANNED = 20;
    private static final long SCAN_WINDOW = 60000;
    private static final long BLOCK_DURATION = 3600000;
    private static final int MAX_SCAN_EVENTS = 100;

    private final AtomicLong totalScansDetected = new AtomicLong(0);

    public PortScanDetectionService() {
        startMonitoring();
    }

    public boolean checkPortAccess(String sourceIP, int port) {
        if (isBlocked(sourceIP)) {
            return false;
        }

        ScanRecord record = scanRecords.computeIfAbsent(sourceIP, k -> new ScanRecord(sourceIP));
        boolean isScanning = record.recordPortAccess(port);

        if (isScanning) {
            blockScanner(sourceIP, "PORT_SCAN", "Scanned " + record.getScannedPortCount() + " ports");
            totalScansDetected.incrementAndGet();
            return false;
        }

        return true;
    }

    public boolean checkMultipleConnections(String sourceIP, Set<Integer> ports) {
        if (isBlocked(sourceIP)) {
            return false;
        }

        ScanRecord record = scanRecords.computeIfAbsent(sourceIP, k -> new ScanRecord(sourceIP));
        boolean isScanning = record.recordMultipleConnections(ports);

        if (isScanning) {
            blockScanner(sourceIP, "MULTI_PORT_CONNECTION", "Connected to " + ports.size() + " ports");
            totalScansDetected.incrementAndGet();
            return false;
        }

        return true;
    }

    public boolean checkConnectionRate(String sourceIP) {
        if (isBlocked(sourceIP)) {
            return false;
        }

        ScanRecord record = scanRecords.computeIfAbsent(sourceIP, k -> new ScanRecord(sourceIP));
        boolean isRateExcessive = record.checkConnectionRate();

        if (isRateExcessive) {
            blockScanner(sourceIP, "HIGH_CONNECTION_RATE", "Connection rate exceeded");
            return false;
        }

        return true;
    }

    public void recordConnection(String sourceIP, int port) {
        ScanRecord record = scanRecords.get(sourceIP);
        if (record != null) {
            record.recordConnection(port);
        }
    }

    public boolean isBlocked(String ip) {
        BlockedScanner blocked = blockedScanners.get(ip);
        if (blocked == null) {
            return false;
        }

        if (System.currentTimeMillis() - blocked.blockedAt > BLOCK_DURATION) {
            blockedScanners.remove(ip);
            return false;
        }

        return true;
    }

    public void blockScanner(String ip, String reason, String details) {
        BlockedScanner blocked = blockedScanners.computeIfAbsent(ip, k -> new BlockedScanner(ip));
        blocked.reason = reason;
        blocked.details = details;
        blocked.blockedAt = System.currentTimeMillis();
        blocked.count.incrementAndGet();

        logScan(ip, reason, details);
    }

    public void unblockScanner(String ip) {
        blockedScanners.remove(ip);
    }

    public BlockedScanner getBlockInfo(String ip) {
        return blockedScanners.get(ip);
    }

    public Collection<BlockedScanner> getBlockedScanners() {
        return blockedScanners.values();
    }

    public ScanRecord getScanRecord(String ip) {
        return scanRecords.get(ip);
    }

    public Collection<ScanRecord> getAllScanRecords() {
        return scanRecords.values();
    }

    private void logScan(String ip, String reason, String details) {
        ScanEvent event = new ScanEvent(ip, reason, details, System.currentTimeMillis());
        scanLog.offer(event);

        while (scanLog.size() > 1000) {
            scanLog.poll();
        }
    }

    public List<ScanEvent> getScanLog(int limit) {
        List<ScanEvent> result = new ArrayList<>();
        int count = 0;
        for (ScanEvent event : scanLog) {
            if (count++ >= limit) break;
            result.add(event);
        }
        return result;
    }

    private void startMonitoring() {
        scheduler.scheduleAtFixedRate(() -> {
            long now = System.currentTimeMillis();

            scanRecords.entrySet().removeIf(entry -> 
                now - entry.getValue().lastActivity > 300000);

            blockedScanners.entrySet().removeIf(entry ->
                now - entry.getValue().blockedAt > BLOCK_DURATION);

        }, 30, 30, TimeUnit.SECONDS);
    }

    public Map<String, Object> getStats() {
        Map<String, Object> stats = new HashMap<>();
        stats.put("activeScanners", scanRecords.size());
        stats.put("blockedScanners", blockedScanners.size());
        stats.put("totalDetected", totalScansDetected.get());
        return stats;
    }

    public static class ScanRecord {
        private final String ip;
        private final Set<Integer> scannedPorts = ConcurrentHashMap.newKeySet();
        private final List<Long> connectionTimestamps = new ArrayList<>();
        private volatile long lastActivity;

        public ScanRecord(String ip) {
            this.ip = ip;
            this.lastActivity = System.currentTimeMillis();
        }

        public boolean recordPortAccess(int port) {
            scannedPorts.add(port);
            lastActivity = System.currentTimeMillis();

            cleanupOldRecords();

            return scannedPorts.size() > MAX_PORTS_SCANNED;
        }

        public boolean recordMultipleConnections(Set<Integer> ports) {
            for (int port : ports) {
                scannedPorts.add(port);
            }
            lastActivity = System.currentTimeMillis();

            cleanupOldRecords();

            return scannedPorts.size() > MAX_PORTS_SCANNED;
        }

        public void recordConnection(int port) {
            scannedPorts.add(port);
            connectionTimestamps.add(System.currentTimeMillis());
            lastActivity = System.currentTimeMillis();

            cleanupOldRecords();
        }

        public boolean checkConnectionRate() {
            cleanupOldRecords();

            long now = System.currentTimeMillis();
            connectionTimestamps.removeIf(t -> now - t > 10000);

            return connectionTimestamps.size() > MAX_SCAN_EVENTS;
        }

        private void cleanupOldRecords() {
            long cutoff = System.currentTimeMillis() - SCAN_WINDOW;
            scannedPorts.removeIf(p -> false);
            connectionTimestamps.removeIf(t -> t < cutoff);
        }

        public int getScannedPortCount() {
            return scannedPorts.size();
        }

        public Set<Integer> getScannedPorts() {
            return new HashSet<>(scannedPorts);
        }
    }

    public static class BlockedScanner {
        public final String ip;
        public String reason;
        public String details;
        public volatile long blockedAt;
        public final AtomicInteger count = new AtomicInteger(1);

        public BlockedScanner(String ip) {
            this.ip = ip;
            this.blockedAt = System.currentTimeMillis();
        }
    }

    public static class ScanEvent {
        public final String ip;
        public final String reason;
        public final String details;
        public final long timestamp;

        public ScanEvent(String ip, String reason, String details, long timestamp) {
            this.ip = ip;
            this.reason = reason;
            this.details = details;
            this.timestamp = timestamp;
        }
    }
}
