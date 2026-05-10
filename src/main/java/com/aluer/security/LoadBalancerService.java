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
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

@Component
public class LoadBalancerService {
    private static final Logger logger = LoggerFactory.getLogger(LoadBalancerService.class);

    private final Map<String, BackendServer> backendServers = new ConcurrentHashMap<>();
    private final Map<String, LoadBalancerRule> rules = new ConcurrentHashMap<>();
    private final Map<String, Queue<Request>> requestQueue = new ConcurrentHashMap<>();
    private final Map<String, LoadBalancerStats> stats = new ConcurrentHashMap<>();
    private final Queue<LoadBalancerEvent> eventLog = new ConcurrentLinkedQueue<>();
    private final AtomicLong totalRequests = new AtomicLong(0);
    private final AtomicLong totalFailedRequests = new AtomicLong(0);
    private final AtomicLong totalRedirects = new AtomicLong(0);

    private String currentAlgorithm = "ROUND_ROBIN";
    private volatile boolean enabled = true;
    private final ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(1);

    private static final int MAX_QUEUE_SIZE = 1000;
    private static final int HEALTH_CHECK_INTERVAL = 30;
    private static final DateTimeFormatter DATE_FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    public LoadBalancerService() {
        initializeDefaultRules();
        startHealthCheck();
        logger.info("Load Balancer Service initialized");
    }

    private void initializeDefaultRules() {
        addRule("round-robin", "ROUND_ROBIN", "Simple round robin distribution");
        addRule("least-connections", "LEAST_CONNECTIONS", "Route to server with fewest connections");
        addRule("weighted", "WEIGHTED", "Weighted distribution based on server capacity");
        addRule("ip-hash", "IP_HASH", "Sticky sessions based on client IP");
        addRule("response-time", "RESPONSE_TIME", "Route to fastest responding server");
    }

    private void addRule(String name, String algorithm, String description) {
        LoadBalancerRule rule = new LoadBalancerRule(name, algorithm, description);
        rules.put(name, rule);
    }

    public void addBackendServer(String serverId, String host, int port, int weight) {
        BackendServer server = new BackendServer(serverId, host, port, weight);
        backendServers.put(serverId, server);
        stats.put(serverId, new LoadBalancerStats(serverId));
        logger.info("Added backend server: {} -> {}:{}", serverId, host, port);
    }

    public void removeBackendServer(String serverId) {
        backendServers.remove(serverId);
        stats.remove(serverId);
        logger.info("Removed backend server: {}", serverId);
    }

    public BackendServer selectBackendServer(String clientIP) {
        if (!enabled) return null;

        List<BackendServer> healthyServers = getHealthyServers();
        if (healthyServers.isEmpty()) {
            logger.warn("No healthy backend servers available");
            return null;
        }

        totalRequests.incrementAndGet();

        BackendServer selected;
        switch (currentAlgorithm) {
            case "LEAST_CONNECTIONS":
                selected = selectLeastConnections(healthyServers);
                break;
            case "WEIGHTED":
                selected = selectWeighted(healthyServers);
                break;
            case "IP_HASH":
                selected = selectByIPHash(clientIP, healthyServers);
                break;
            case "RESPONSE_TIME":
                selected = selectByResponseTime(healthyServers);
                break;
            default:
                selected = selectRoundRobin(healthyServers);
        }

        if (selected != null) {
            LoadBalancerStats serverStats = stats.get(selected.getServerId());
            if (serverStats != null) {
                serverStats.incrementRequestCount();
            }
            logEvent("ROUTED", clientIP, selected.getHost() + ":" + selected.getPort());
        }

        return selected;
    }

    private List<BackendServer> getHealthyServers() {
        List<BackendServer> healthy = new ArrayList<>();
        for (BackendServer server : backendServers.values()) {
            if (server.isHealthy()) {
                healthy.add(server);
            }
        }
        return healthy;
    }

    private BackendServer selectRoundRobin(List<BackendServer> servers) {
        int index = (int) (totalRequests.get() % servers.size());
        return servers.get(index);
    }

    private BackendServer selectLeastConnections(List<BackendServer> servers) {
        BackendServer selected = null;
        long minConnections = Long.MAX_VALUE;

        for (BackendServer server : servers) {
            LoadBalancerStats serverStats = stats.get(server.getServerId());
            long connections = serverStats != null ? serverStats.getActiveConnections() : 0;

            if (connections < minConnections) {
                minConnections = connections;
                selected = server;
            }
        }

        return selected;
    }

    private BackendServer selectWeighted(List<BackendServer> servers) {
        int totalWeight = servers.stream().mapToInt(BackendServer::getWeight).sum();
        int random = new Random().nextInt(totalWeight);

        int cumulative = 0;
        for (BackendServer server : servers) {
            cumulative += server.getWeight();
            if (random < cumulative) {
                return server;
            }
        }

        return servers.get(0);
    }

    private BackendServer selectByIPHash(String clientIP, List<BackendServer> servers) {
        int hash = clientIP.hashCode();
        int index = Math.abs(hash) % servers.size();
        return servers.get(index);
    }

    private BackendServer selectByResponseTime(List<BackendServer> servers) {
        BackendServer selected = null;
        long fastestResponse = Long.MAX_VALUE;

        for (BackendServer server : servers) {
            LoadBalancerStats serverStats = stats.get(server.getServerId());
            long avgResponse = serverStats != null ? serverStats.getAverageResponseTime() : 0;

            if (avgResponse < fastestResponse) {
                fastestResponse = avgResponse;
                selected = server;
            }
        }

        return selected;
    }

    public void recordRequestSuccess(String serverId, long responseTime) {
        LoadBalancerStats serverStats = stats.get(serverId);
        if (serverStats != null) {
            serverStats.recordSuccess(responseTime);
        }
    }

    public void recordRequestFailure(String serverId) {
        LoadBalancerStats serverStats = stats.get(serverId);
        if (serverStats != null) {
            serverStats.recordFailure();
        }
        totalFailedRequests.incrementAndGet();

        BackendServer server = backendServers.get(serverId);
        if (server != null) {
            server.incrementFailureCount();
            if (server.getFailureCount() >= 5) {
                server.setHealthy(false);
                logger.warn("Backend server {} marked as unhealthy after {} failures", serverId, server.getFailureCount());
                logEvent("SERVER_UNHEALTHY", serverId, "Marked as unhealthy");
            }
        }
    }

    public void setAlgorithm(String algorithm) {
        this.currentAlgorithm = algorithm;
        logger.info("Load balancer algorithm changed to: {}", algorithm);
    }

    public void enable() {
        this.enabled = true;
        logger.info("Load balancer enabled");
    }

    public void disable() {
        this.enabled = false;
        logger.info("Load balancer disabled");
    }

    private void startHealthCheck() {
        scheduler.scheduleAtFixedRate(() -> {
            checkBackendHealth();
        }, HEALTH_CHECK_INTERVAL, HEALTH_CHECK_INTERVAL, TimeUnit.SECONDS);
    }

    private void checkBackendHealth() {
        for (BackendServer server : backendServers.values()) {
            boolean healthy = performHealthCheck(server);

            if (healthy && !server.isHealthy()) {
                server.setHealthy(true);
                server.resetFailureCount();
                logger.info("Backend server {} is healthy again", server.getServerId());
                logEvent("SERVER_HEALTHY", server.getServerId(), "Health check passed");
            } else if (!healthy && server.isHealthy()) {
                server.setHealthy(false);
                logger.warn("Backend server {} failed health check", server.getServerId());
                logEvent("SERVER_UNHEALTHY", server.getServerId(), "Health check failed");
            }
        }
    }

    private boolean performHealthCheck(BackendServer server) {
        return true;
    }

    public Map<String, Object> getStats() {
        Map<String, Object> statsMap = new HashMap<>();
        statsMap.put("enabled", enabled);
        statsMap.put("algorithm", currentAlgorithm);
        statsMap.put("totalRequests", totalRequests.get());
        statsMap.put("totalFailedRequests", totalFailedRequests.get());
        statsMap.put("totalRedirects", totalRedirects.get());
        statsMap.put("backendServers", backendServers.size());

        long healthyServers = backendServers.values().stream().filter(BackendServer::isHealthy).count();
        statsMap.put("healthyServers", healthyServers);

        double successRate = totalRequests.get() > 0 ?
            (totalRequests.get() - totalFailedRequests.get()) * 100.0 / totalRequests.get() : 0;
        statsMap.put("successRate", String.format("%.2f%%", successRate));

        return statsMap;
    }

    public Map<String, BackendServer> getBackendServers() {
        return new HashMap<>(backendServers);
    }

    public Map<String, LoadBalancerStats> getServerStats() {
        return new HashMap<>(stats);
    }

    public List<LoadBalancerEvent> getRecentEvents(int limit) {
        List<LoadBalancerEvent> events = new ArrayList<>();
        int count = 0;
        for (LoadBalancerEvent event : eventLog) {
            if (count++ >= limit) break;
            events.add(event);
        }
        return events;
    }

    private void logEvent(String type, String source, String details) {
        LoadBalancerEvent event = new LoadBalancerEvent(type, source, details, LocalDateTime.now());
        eventLog.offer(event);
        if (eventLog.size() > 1000) {
            eventLog.poll();
        }
    }

    public static class BackendServer {
        private final String serverId;
        private final String host;
        private final int port;
        private final int weight;
        private volatile boolean healthy = true;
        private volatile int failureCount = 0;

        public BackendServer(String serverId, String host, int port, int weight) {
            this.serverId = serverId;
            this.host = host;
            this.port = port;
            this.weight = weight;
        }

        public void incrementFailureCount() { failureCount++; }
        public void resetFailureCount() { failureCount = 0; }

        public String getServerId() { return serverId; }
        public String getHost() { return host; }
        public int getPort() { return port; }
        public int getWeight() { return weight; }
        public boolean isHealthy() { return healthy; }
        public void setHealthy(boolean healthy) { this.healthy = healthy; }
        public int getFailureCount() { return failureCount; }
    }

    public static class LoadBalancerRule {
        private final String name;
        private final String algorithm;
        private final String description;

        public LoadBalancerRule(String name, String algorithm, String description) {
            this.name = name;
            this.algorithm = algorithm;
            this.description = description;
        }

        public String getName() { return name; }
        public String getAlgorithm() { return algorithm; }
        public String getDescription() { return description; }
    }

    public static class LoadBalancerStats {
        private final String serverId;
        private final AtomicLong requestCount = new AtomicLong(0);
        private final AtomicLong failureCount = new AtomicLong(0);
        private final AtomicLong totalResponseTime = new AtomicLong(0);
        private volatile long activeConnections = 0;

        public LoadBalancerStats(String serverId) {
            this.serverId = serverId;
        }

        public void incrementRequestCount() { requestCount.incrementAndGet(); activeConnections++; }
        public void recordSuccess(long responseTime) {
            totalResponseTime.addAndGet(responseTime);
            activeConnections = Math.max(0, activeConnections - 1);
        }
        public void recordFailure() {
            failureCount.incrementAndGet();
            activeConnections = Math.max(0, activeConnections - 1);
        }

        public long getAverageResponseTime() {
            long count = requestCount.get();
            return count > 0 ? totalResponseTime.get() / count : 0;
        }

        public String getServerId() { return serverId; }
        public long getRequestCount() { return requestCount.get(); }
        public long getFailureCount() { return failureCount.get(); }
        public long getActiveConnections() { return activeConnections; }
    }

    public static class Request {
        private final String requestId;
        private final String clientIP;
        private final String path;
        private final long timestamp;

        public Request(String requestId, String clientIP, String path) {
            this.requestId = requestId;
            this.clientIP = clientIP;
            this.path = path;
            this.timestamp = System.currentTimeMillis();
        }

        public String getRequestId() { return requestId; }
        public String getClientIP() { return clientIP; }
        public String getPath() { return path; }
        public long getTimestamp() { return timestamp; }
    }

    public static class LoadBalancerEvent {
        private final String type;
        private final String source;
        private final String details;
        private final LocalDateTime timestamp;

        public LoadBalancerEvent(String type, String source, String details, LocalDateTime timestamp) {
            this.type = type;
            this.source = source;
            this.details = details;
            this.timestamp = timestamp;
        }

        public String getType() { return type; }
        public String getSource() { return source; }
        public String getDetails() { return details; }
        public LocalDateTime getTimestamp() { return timestamp; }
    }
}
