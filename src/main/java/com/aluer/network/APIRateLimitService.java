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

@Component
public class APIRateLimitService {
    private static final Logger logger = LoggerFactory.getLogger(APIRateLimitService.class);

    private final Map<String, RateLimitRule> rules = new ConcurrentHashMap<>();
    private final Map<String, ClientRateLimit> clientLimits = new ConcurrentHashMap<>();
    private final Queue<RateLimitEvent> eventLog = new ConcurrentLinkedQueue<>();
    private final AtomicLong totalRequests = new AtomicLong(0);
    private final AtomicLong limitedRequests = new AtomicLong(0);
    private final AtomicLong blockedRequests = new AtomicLong(0);

    private static final int DEFAULT_LIMIT_PER_MINUTE = 60;
    private static final int DEFAULT_LIMIT_PER_HOUR = 1000;
    private static final int DEFAULT_LIMIT_PER_DAY = 10000;
    private static final DateTimeFormatter DATE_FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    public APIRateLimitService() {
        initializeDefaultRules();
        logger.info("API Rate Limit Service initialized");
    }

    private void initializeDefaultRules() {
        addRule("default", DEFAULT_LIMIT_PER_MINUTE, DEFAULT_LIMIT_PER_HOUR, DEFAULT_LIMIT_PER_DAY);
        addRule("login", 10, 50, 100);
        addRule("register", 5, 20, 50);
        addRule("message", 30, 200, 500);
        addRule("file-upload", 10, 50, 100);
        addRule("api-critical", 100, 500, 2000);

        logger.info("Initialized {} rate limit rules", rules.size());
    }

    public void addRule(String name, int limitPerMinute, int limitPerHour, int limitPerDay) {
        RateLimitRule rule = new RateLimitRule(name, limitPerMinute, limitPerHour, limitPerDay);
        rules.put(name, rule);
    }

    public RateLimitResult checkRateLimit(String clientId, String endpoint) {
        RateLimitResult result = new RateLimitResult();
        result.setClientId(clientId);
        result.setEndpoint(endpoint);
        result.setTimestamp(LocalDateTime.now());

        totalRequests.incrementAndGet();

        ClientRateLimit clientLimit = clientLimits.computeIfAbsent(clientId, k -> new ClientRateLimit(clientId));

        RateLimitRule rule = rules.getOrDefault(endpoint, rules.get("default"));

        if (clientLimit.isPermanentlyBlocked()) {
            result.setAllowed(false);
            result.setReason("Client is permanently blocked");
            result.setBlocked(true);
            blockedRequests.incrementAndGet();
            logEvent(clientId, endpoint, "BLOCKED", "Permanently blocked");
            return result;
        }

        if (!clientLimit.checkLimit(rule)) {
            result.setAllowed(false);
            result.setReason("Rate limit exceeded");
            result.setLimited(true);
            limitedRequests.incrementAndGet();
            clientLimit.incrementViolationCount();

            if (clientLimit.getViolationCount() >= 10) {
                clientLimit.setPermanentlyBlocked(true);
                blockedRequests.incrementAndGet();
                logEvent(clientId, endpoint, "PERMANENT_BLOCK", "Too many violations");
            } else {
                logEvent(clientId, endpoint, "LIMITED", "Rate limit exceeded");
            }

            return result;
        }

        clientLimit.recordRequest();
        result.setAllowed(true);
        result.setRemainingMinute(clientLimit.getRemainingRequests("minute"));
        result.setRemainingHour(clientLimit.getRemainingRequests("hour"));
        result.setRemainingDay(clientLimit.getRemainingRequests("day"));

        logEvent(clientId, endpoint, "ALLOWED", "Request allowed");

        return result;
    }

    public void unblockClient(String clientId) {
        ClientRateLimit clientLimit = clientLimits.get(clientId);
        if (clientLimit != null) {
            clientLimit.reset();
            logger.info("Client {} has been unblocked", clientId);
        }
    }

    public void setClientLimit(String clientId, int minuteLimit, int hourLimit, int dayLimit) {
        ClientRateLimit clientLimit = clientLimits.computeIfAbsent(clientId, k -> new ClientRateLimit(clientId));
        clientLimit.setCustomLimits(minuteLimit, hourLimit, dayLimit);
    }

    public Map<String, Object> getStats() {
        Map<String, Object> stats = new HashMap<>();
        stats.put("totalRequests", totalRequests.get());
        stats.put("limitedRequests", limitedRequests.get());
        stats.put("blockedRequests", blockedRequests.get());
        stats.put("activeClients", clientLimits.size());
        stats.put("rulesConfigured", rules.size());

        return stats;
    }

    public Map<String, ClientRateLimit> getClients() {
        return new HashMap<>(clientLimits);
    }

    public List<RateLimitEvent> getRecentEvents(int limit) {
        List<RateLimitEvent> events = new ArrayList<>();
        int count = 0;
        for (RateLimitEvent event : eventLog) {
            if (count++ >= limit) break;
            events.add(event);
        }
        return events;
    }

    private void logEvent(String clientId, String endpoint, String action, String details) {
        RateLimitEvent event = new RateLimitEvent(clientId, endpoint, action, details, LocalDateTime.now());
        eventLog.offer(event);
        if (eventLog.size() > 5000) {
            eventLog.poll();
        }
    }

    public static class RateLimitRule {
        private final String name;
        private final int limitPerMinute;
        private final int limitPerHour;
        private final int limitPerDay;

        public RateLimitRule(String name, int limitPerMinute, int limitPerHour, int limitPerDay) {
            this.name = name;
            this.limitPerMinute = limitPerMinute;
            this.limitPerHour = limitPerHour;
            this.limitPerDay = limitPerDay;
        }

        public String getName() { return name; }
        public int getLimitPerMinute() { return limitPerMinute; }
        public int getLimitPerHour() { return limitPerHour; }
        public int getLimitPerDay() { return limitPerDay; }
    }

    public static class ClientRateLimit {
        private final String clientId;
        private volatile int requestsThisMinute = 0;
        private volatile int requestsThisHour = 0;
        private volatile int requestsThisDay = 0;
        private volatile long minuteStartTime;
        private volatile long hourStartTime;
        private volatile long dayStartTime;
        private volatile int violationCount = 0;
        private volatile boolean permanentlyBlocked = false;
        private Integer customMinuteLimit;
        private Integer customHourLimit;
        private Integer customDayLimit;

        public ClientRateLimit(String clientId) {
            this.clientId = clientId;
            this.minuteStartTime = System.currentTimeMillis();
            this.hourStartTime = System.currentTimeMillis();
            this.dayStartTime = System.currentTimeMillis();
        }

        public synchronized boolean checkLimit(RateLimitRule rule) {
            resetIfNeeded();

            int minuteLimit = customMinuteLimit != null ? customMinuteLimit : rule.getLimitPerMinute();
            int hourLimit = customHourLimit != null ? customHourLimit : rule.getLimitPerHour();
            int dayLimit = customDayLimit != null ? customDayLimit : rule.getLimitPerDay();

            return requestsThisMinute < minuteLimit &&
                   requestsThisHour < hourLimit &&
                   requestsThisDay < dayLimit;
        }

        public synchronized void recordRequest() {
            resetIfNeeded();
            requestsThisMinute++;
            requestsThisHour++;
            requestsThisDay++;
        }

        private void resetIfNeeded() {
            long now = System.currentTimeMillis();

            if (now - minuteStartTime > 60000) {
                requestsThisMinute = 0;
                minuteStartTime = now;
            }

            if (now - hourStartTime > 3600000) {
                requestsThisHour = 0;
                hourStartTime = now;
            }

            if (now - dayStartTime > 86400000) {
                requestsThisDay = 0;
                dayStartTime = now;
            }
        }

        public int getRemainingRequests(String timeframe) {
            resetIfNeeded();
            RateLimitRule rule = new RateLimitRule("default", 60, 1000, 10000);
            int minuteLimit = customMinuteLimit != null ? customMinuteLimit : rule.getLimitPerMinute();
            int hourLimit = customHourLimit != null ? customHourLimit : rule.getLimitPerHour();
            int dayLimit = customDayLimit != null ? customDayLimit : rule.getLimitPerDay();

            switch (timeframe) {
                case "minute": return Math.max(0, minuteLimit - requestsThisMinute);
                case "hour": return Math.max(0, hourLimit - requestsThisHour);
                case "day": return Math.max(0, dayLimit - requestsThisDay);
                default: return 0;
            }
        }

        public void incrementViolationCount() { violationCount++; }
        public void reset() {
            violationCount = 0;
            permanentlyBlocked = false;
            requestsThisMinute = 0;
            requestsThisHour = 0;
            requestsThisDay = 0;
        }

        public void setCustomLimits(int minute, int hour, int day) {
            this.customMinuteLimit = minute;
            this.customHourLimit = hour;
            this.customDayLimit = day;
        }

        public String getClientId() { return clientId; }
        public int getViolationCount() { return violationCount; }
        public boolean isPermanentlyBlocked() { return permanentlyBlocked; }
        public void setPermanentlyBlocked(boolean blocked) { this.permanentlyBlocked = blocked; }
    }

    public static class RateLimitResult {
        private String clientId;
        private String endpoint;
        private boolean allowed;
        private boolean limited;
        private boolean blocked;
        private String reason;
        private int remainingMinute;
        private int remainingHour;
        private int remainingDay;
        private LocalDateTime timestamp;

        public String getClientId() { return clientId; }
        public void setClientId(String clientId) { this.clientId = clientId; }
        public String getEndpoint() { return endpoint; }
        public void setEndpoint(String endpoint) { this.endpoint = endpoint; }
        public boolean isAllowed() { return allowed; }
        public void setAllowed(boolean allowed) { this.allowed = allowed; }
        public boolean isLimited() { return limited; }
        public void setLimited(boolean limited) { this.limited = limited; }
        public boolean isBlocked() { return blocked; }
        public void setBlocked(boolean blocked) { this.blocked = blocked; }
        public String getReason() { return reason; }
        public void setReason(String reason) { this.reason = reason; }
        public int getRemainingMinute() { return remainingMinute; }
        public void setRemainingMinute(int remaining) { this.remainingMinute = remaining; }
        public int getRemainingHour() { return remainingHour; }
        public void setRemainingHour(int remaining) { this.remainingHour = remaining; }
        public int getRemainingDay() { return remainingDay; }
        public void setRemainingDay(int remaining) { this.remainingDay = remaining; }
        public LocalDateTime getTimestamp() { return timestamp; }
        public void setTimestamp(LocalDateTime timestamp) { this.timestamp = timestamp; }
    }

    public static class RateLimitEvent {
        private final String clientId;
        private final String endpoint;
        private final String action;
        private final String details;
        private final LocalDateTime timestamp;

        public RateLimitEvent(String clientId, String endpoint, String action, String details, LocalDateTime timestamp) {
            this.clientId = clientId;
            this.endpoint = endpoint;
            this.action = action;
            this.details = details;
            this.timestamp = timestamp;
        }

        public String getClientId() { return clientId; }
        public String getEndpoint() { return endpoint; }
        public String getAction() { return action; }
        public String getDetails() { return details; }
        public LocalDateTime getTimestamp() { return timestamp; }
    }
}
