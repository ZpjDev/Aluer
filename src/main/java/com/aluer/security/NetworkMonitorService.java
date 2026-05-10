package com.aluer.security;

import org.springframework.stereotype.Service;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;

@Service
public class NetworkMonitorService {

    private final Map<String, NetworkSession> sessions = new ConcurrentHashMap<>();
    private final Map<String, BandwidthTracker> bandwidthTrackers = new ConcurrentHashMap<>();
    private final Queue<NetworkAlert> alerts = new ConcurrentLinkedQueue<>();
    private final ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(2);

    private static final long SESSION_TIMEOUT = 300000;
    private static final long BANDWIDTH_UPDATE_INTERVAL = 1000;

    private final AtomicLong totalBytesIn = new AtomicLong(0);
    private final AtomicLong totalBytesOut = new AtomicLong(0);
    private final AtomicLong totalPacketsIn = new AtomicLong(0);
    private final AtomicLong totalPacketsOut = new AtomicLong(0);

    public NetworkMonitorService() {
        startMonitoringTask();
    }

    public void recordInboundTraffic(String ip, long bytes, int packets) {
        totalBytesIn.addAndGet(bytes);
        totalPacketsIn.addAndGet(packets);

        BandwidthTracker tracker = bandwidthTrackers.computeIfAbsent(ip, k -> new BandwidthTracker(ip));
        tracker.recordInbound(bytes, packets);

        NetworkSession session = sessions.computeIfAbsent(ip, k -> new NetworkSession(ip));
        session.recordInbound(bytes, packets);
    }

    public void recordOutboundTraffic(String ip, long bytes, int packets) {
        totalBytesOut.addAndGet(bytes);
        totalPacketsOut.addAndGet(packets);

        BandwidthTracker tracker = bandwidthTrackers.computeIfAbsent(ip, k -> new BandwidthTracker(ip));
        tracker.recordOutbound(bytes, packets);

        NetworkSession session = sessions.computeIfAbsent(ip, k -> new NetworkSession(ip));
        session.recordOutbound(bytes, packets);
    }

    public void recordConnection(String ip, int port, String protocol) {
        NetworkSession session = sessions.computeIfAbsent(ip, k -> new NetworkSession(ip));
        session.addConnection(port, protocol);
    }

    public void closeConnection(String ip, int port) {
        NetworkSession session = sessions.get(ip);
        if (session != null) {
            session.removeConnection(port);
        }
    }

    public boolean isHighBandwidth(String ip) {
        BandwidthTracker tracker = bandwidthTrackers.get(ip);
        if (tracker == null) {
            return false;
        }
        return tracker.isHighBandwidth();
    }

    public boolean isExcessiveConnections(String ip) {
        NetworkSession session = sessions.get(ip);
        if (session == null) {
            return false;
        }
        return session.getConnectionCount() > 100;
    }

    public NetworkSession getSession(String ip) {
        return sessions.get(ip);
    }

    public Collection<NetworkSession> getAllSessions() {
        return sessions.values();
    }

    public BandwidthTracker getBandwidthTracker(String ip) {
        return bandwidthTrackers.get(ip);
    }

    public void addAlert(String ip, String type, String details) {
        NetworkAlert alert = new NetworkAlert(ip, type, details, System.currentTimeMillis());
        alerts.offer(alert);

        while (alerts.size() > 500) {
            alerts.poll();
        }
    }

    public List<NetworkAlert> getAlerts(int limit) {
        List<NetworkAlert> result = new ArrayList<>();
        int count = 0;
        for (NetworkAlert alert : alerts) {
            if (count++ >= limit) break;
            result.add(alert);
        }
        return result;
    }

    public Map<String, Object> getGlobalStats() {
        Map<String, Object> stats = new HashMap<>();
        stats.put("activeSessions", sessions.size());
        stats.put("totalBytesIn", totalBytesIn.get());
        stats.put("totalBytesOut", totalBytesOut.get());
        stats.put("totalPacketsIn", totalPacketsIn.get());
        stats.put("totalPacketsOut", totalPacketsOut.get());
        return stats;
    }

    private void startMonitoringTask() {
        scheduler.scheduleAtFixedRate(() -> {
            long now = System.currentTimeMillis();

            sessions.entrySet().removeIf(entry ->
                now - entry.getValue().lastActivity > SESSION_TIMEOUT);

            for (BandwidthTracker tracker : bandwidthTrackers.values()) {
                tracker.resetIfNeeded();
            }

        }, 30, 30, TimeUnit.SECONDS);
    }

    public static class NetworkSession {
        private final String ip;
        private final Set<Integer> connections = ConcurrentHashMap.newKeySet();
        private volatile long totalBytesIn = 0;
        private volatile long totalBytesOut = 0;
        private volatile long totalPacketsIn = 0;
        private volatile long totalPacketsOut = 0;
        private volatile long lastActivity;

        public NetworkSession(String ip) {
            this.ip = ip;
            this.lastActivity = System.currentTimeMillis();
        }

        public void recordInbound(long bytes, int packets) {
            totalBytesIn += bytes;
            totalPacketsIn += packets;
            lastActivity = System.currentTimeMillis();
        }

        public void recordOutbound(long bytes, int packets) {
            totalBytesOut += bytes;
            totalPacketsOut += packets;
            lastActivity = System.currentTimeMillis();
        }

        public void addConnection(int port, String protocol) {
            connections.add(port);
            lastActivity = System.currentTimeMillis();
        }

        public void removeConnection(int port) {
            connections.remove(port);
        }

        public int getConnectionCount() {
            return connections.size();
        }

        public String getIp() { return ip; }
        public long getTotalBytesIn() { return totalBytesIn; }
        public long getTotalBytesOut() { return totalBytesOut; }
    }

    public static class BandwidthTracker {
        private final String ip;
        private volatile long windowBytesIn = 0;
        private volatile long windowBytesOut = 0;
        private volatile long windowPacketsIn = 0;
        private volatile long windowPacketsOut = 0;
        private volatile long lastUpdate;

        public BandwidthTracker(String ip) {
            this.ip = ip;
            this.lastUpdate = System.currentTimeMillis();
        }

        public void recordInbound(long bytes, int packets) {
            windowBytesIn += bytes;
            windowPacketsIn += packets;
        }

        public void recordOutbound(long bytes, int packets) {
            windowBytesOut += bytes;
            windowPacketsOut += packets;
        }

        public void resetIfNeeded() {
            long now = System.currentTimeMillis();
            if (now - lastUpdate > BANDWIDTH_UPDATE_INTERVAL) {
                windowBytesIn = 0;
                windowBytesOut = 0;
                windowPacketsIn = 0;
                windowPacketsOut = 0;
                lastUpdate = now;
            }
        }

        public boolean isHighBandwidth() {
            return windowBytesIn > 10_000_000 || windowBytesOut > 10_000_000;
        }

        public String getIp() { return ip; }
        public long getWindowBytesIn() { return windowBytesIn; }
        public long getWindowBytesOut() { return windowBytesOut; }
    }

    public static class NetworkAlert {
        private final String ip;
        private final String type;
        private final String details;
        private final long timestamp;

        public NetworkAlert(String ip, String type, String details, long timestamp) {
            this.ip = ip;
            this.type = type;
            this.details = details;
            this.timestamp = timestamp;
        }

        public String getIp() { return ip; }
        public String getType() { return type; }
        public String getDetails() { return details; }
        public long getTimestamp() { return timestamp; }
    }
}
