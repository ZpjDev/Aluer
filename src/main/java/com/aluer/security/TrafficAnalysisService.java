package com.aluer.security;

import org.springframework.stereotype.Service;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;
import java.util.regex.*;

@Service
public class TrafficAnalysisService {

    private final Map<String, TrafficSession> sessions = new ConcurrentHashMap<>();
    private final Map<String, List<TrafficSample>> trafficHistory = new ConcurrentHashMap<>();
    private final Map<String, AnomalyScore> anomalyScores = new ConcurrentHashMap<>();
    private final Queue<TrafficAlert> alerts = new ConcurrentLinkedQueue<>();
    private final ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(2);

    private static final int MAX_SESSIONS = 10000;
    private static final long SESSION_TIMEOUT = 300000;
    private static final int HISTORY_SIZE = 1000;
    private static final double ANOMALY_THRESHOLD = 0.75;

    private final AtomicLong totalPacketsAnalyzed = new AtomicLong(0);
    private final AtomicLong totalAnomaliesDetected = new AtomicLong(0);

    public TrafficAnalysisService() {
        startAnalysisTask();
    }

    public boolean analyzePacket(String sourceIP, String destIP, int port, int packetSize, String protocol) {
        totalPacketsAnalyzed.incrementAndGet();

        TrafficSession session = sessions.computeIfAbsent(sourceIP, k -> new TrafficSession(sourceIP));
        session.recordPacket(destIP, port, packetSize, protocol);

        boolean isAnomaly = checkForAnomalies(session);

        if (isAnomaly) {
            AnomalyScore score = anomalyScores.computeIfAbsent(sourceIP, k -> new AnomalyScore(sourceIP));
            score.increment();

            if (score.getScore() > ANOMALY_THRESHOLD) {
                triggerAlert(sourceIP, "TRAFFIC_ANOMALY", "Anomaly score: " + score.getScore());
                totalAnomaliesDetected.incrementAndGet();
                return false;
            }
        }

        recordTrafficSample(sourceIP, packetSize, protocol);

        return true;
    }

    private boolean checkForAnomalies(TrafficSession session) {
        if (session.packetCount > 1000) {
            return true;
        }

        if (session.totalBytes > 100_000_000) {
            return true;
        }

        if (session.uniquePorts.size() > 100) {
            return true;
        }

        if (session.uniqueDestinations.size() > 50) {
            return true;
        }

        return false;
    }

    private void recordTrafficSample(String ip, int packetSize, String protocol) {
        List<TrafficSample> history = trafficHistory.computeIfAbsent(ip, k -> new CopyOnWriteArrayList<>());
        
        TrafficSample sample = new TrafficSample(packetSize, protocol, System.currentTimeMillis());
        history.add(sample);

        while (history.size() > HISTORY_SIZE) {
            history.remove(0);
        }
    }

    public void triggerAlert(String sourceIP, String type, String details) {
        TrafficAlert alert = new TrafficAlert(sourceIP, type, details, System.currentTimeMillis());
        alerts.offer(alert);

        while (alerts.size() > 500) {
            alerts.poll();
        }
    }

    public TrafficSession getSession(String ip) {
        return sessions.get(ip);
    }

    public Collection<TrafficSession> getAllSessions() {
        return sessions.values();
    }

    public AnomalyScore getAnomalyScore(String ip) {
        return anomalyScores.get(ip);
    }

    public Map<String, AnomalyScore> getAllAnomalyScores() {
        return new HashMap<>(anomalyScores);
    }

    public List<TrafficAlert> getAlerts(int limit) {
        List<TrafficAlert> result = new ArrayList<>();
        int count = 0;
        for (TrafficAlert alert : alerts) {
            if (count++ >= limit) break;
            result.add(alert);
        }
        return result;
    }

    public Map<String, Object> getTrafficStats(String ip) {
        TrafficSession session = sessions.get(ip);
        if (session == null) {
            return Collections.emptyMap();
        }

        Map<String, Object> stats = new HashMap<>();
        stats.put("packetCount", session.packetCount);
        stats.put("totalBytes", session.totalBytes);
        stats.put("uniquePorts", session.uniquePorts.size());
        stats.put("uniqueDestinations", session.uniqueDestinations.size());
        stats.put("protocols", new HashSet<>(session.protocols));

        return stats;
    }

    public Map<String, Object> getGlobalStats() {
        Map<String, Object> stats = new HashMap<>();
        stats.put("activeSessions", sessions.size());
        stats.put("totalPacketsAnalyzed", totalPacketsAnalyzed.get());
        stats.put("totalAnomaliesDetected", totalAnomaliesDetected.get());
        stats.put("uniqueIPsTracked", trafficHistory.size());

        long totalBytes = sessions.values().stream()
            .mapToLong(s -> s.totalBytes)
            .sum();
        stats.put("totalBytesProcessed", totalBytes);

        return stats;
    }

    private void startAnalysisTask() {
        scheduler.scheduleAtFixedRate(() -> {
            long now = System.currentTimeMillis();

            sessions.entrySet().removeIf(entry ->
                now - entry.getValue().lastActivity > SESSION_TIMEOUT);

            anomalyScores.entrySet().removeIf(entry ->
                entry.getValue().getScore() < 0.1);

            for (TrafficSession session : sessions.values()) {
                session.resetCountersIfNeeded();
            }

        }, 60, 60, TimeUnit.SECONDS);
    }

    public static class TrafficSession {
        private final String ip;
        private final Map<String, Integer> destinationPorts = new ConcurrentHashMap<>();
        private final Set<Integer> uniquePorts = ConcurrentHashMap.newKeySet();
        private final Set<String> uniqueDestinations = ConcurrentHashMap.newKeySet();
        private final Set<String> protocols = ConcurrentHashMap.newKeySet();
        
        private volatile long packetCount = 0;
        private volatile long totalBytes = 0;
        private volatile long lastActivity;
        private volatile long windowStart = System.currentTimeMillis();

        public TrafficSession(String ip) {
            this.ip = ip;
            this.lastActivity = System.currentTimeMillis();
        }

        public void recordPacket(String destIP, int port, int packetSize, String protocol) {
            packetCount++;
            totalBytes += packetSize;
            lastActivity = System.currentTimeMillis();

            uniquePorts.add(port);
            uniqueDestinations.add(destIP);
            protocols.add(protocol);

            String key = destIP + ":" + port;
            destinationPorts.merge(key, 1, Integer::sum);
        }

        public void resetCountersIfNeeded() {
            long now = System.currentTimeMillis();
            if (now - windowStart > 60000) {
                packetCount = 0;
                totalBytes = 0;
                windowStart = now;
            }
        }

        public String getIp() {
            return ip;
        }
    }

    public static class TrafficSample {
        private final int size;
        private final String protocol;
        private final long timestamp;

        public TrafficSample(int size, String protocol, long timestamp) {
            this.size = size;
            this.protocol = protocol;
            this.timestamp = timestamp;
        }

        public int getSize() {
            return size;
        }

        public String getProtocol() {
            return protocol;
        }

        public long getTimestamp() {
            return timestamp;
        }
    }

    public static class AnomalyScore {
        private final String ip;
        private final AtomicInteger score = new AtomicInteger(0);
        private volatile long lastUpdate;

        public AnomalyScore(String ip) {
            this.ip = ip;
            this.lastUpdate = System.currentTimeMillis();
        }

        public void increment() {
            score.updateAndGet(s -> Math.min(100, s + 10));
            lastUpdate = System.currentTimeMillis();
        }

        public void decrement() {
            score.updateAndGet(s -> Math.max(0, s - 5));
            lastUpdate = System.currentTimeMillis();
        }

        public double getScore() {
            if (System.currentTimeMillis() - lastUpdate > 300000) {
                score.set(0);
            }
            return score.get() / 100.0;
        }
    }

    public static class TrafficAlert {
        private final String sourceIP;
        private final String type;
        private final String details;
        private final long timestamp;

        public TrafficAlert(String sourceIP, String type, String details, long timestamp) {
            this.sourceIP = sourceIP;
            this.type = type;
            this.details = details;
            this.timestamp = timestamp;
        }

        public String getSourceIP() {
            return sourceIP;
        }

        public String getType() {
            return type;
        }

        public String getDetails() {
            return details;
        }

        public long getTimestamp() {
            return timestamp;
        }
    }
}
