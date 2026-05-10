package com.aluer.security;

import org.springframework.stereotype.Service;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;
import java.security.MessageDigest;

@Service
public class RateLimitService {

    private final Map<String, RateLimitRule> rules = new ConcurrentHashMap<>();
    private final Map<String, List<Long>> requestTimestamps = new ConcurrentHashMap<>();
    private final Map<String, AtomicInteger> requestCounts = new ConcurrentHashMap<>();
    private final Map<String, RateLimitStats> stats = new ConcurrentHashMap<>();
    private final Queue<RateLimitEvent> events = new ConcurrentLinkedQueue<>();
    private final ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(2);

    private static final int DEFAULT_MAX_REQUESTS = 100;
    private static final long DEFAULT_WINDOW_MS = 60000;
    private static final long BAN_DURATION = 300000;

    public RateLimitService() {
        initializeDefaultRules();
        startCleanupTask();
    }

    private void initializeDefaultRules() {
        addRule("api", DEFAULT_MAX_REQUESTS, DEFAULT_WINDOW_MS, "API requests");
        addRule("login", 5, 60000, "Login attempts");
        addRule("chat", 10, 5000, "Chat messages");
        addRule("command", 30, 60000, "Commands");
        addRule("file_upload", 5, 60000, "File uploads");
    }

    public void addRule(String name, int maxRequests, long windowMs, String description) {
        RateLimitRule rule = new RateLimitRule(name, maxRequests, windowMs, description);
        rules.put(name, rule);
    }

    public boolean checkRateLimit(String identifier, String ruleName) {
        RateLimitRule rule = rules.get(ruleName);
        if (rule == null) {
            rule = rules.get("api");
        }

        if (rule == null) {
            return true;
        }

        final RateLimitRule finalRule = rule;
        String key = identifier + ":" + ruleName;
        List<Long> timestamps = requestTimestamps.computeIfAbsent(key, k -> new CopyOnWriteArrayList<>());
        long now = System.currentTimeMillis();

        timestamps.removeIf(t -> now - t > finalRule.windowMs);

        if (timestamps.size() >= finalRule.maxRequests) {
            recordRejection(identifier, ruleName, "Rate limit exceeded");
            return false;
        }

        timestamps.add(now);

        recordRequest(identifier, ruleName);

        return true;
    }

    public void recordRejection(String identifier, String ruleName, String reason) {
        RateLimitStats stat = stats.computeIfAbsent(identifier, k -> new RateLimitStats(identifier));
        stat.rejections.incrementAndGet();

        RateLimitEvent event = new RateLimitEvent(identifier, ruleName, reason, false, System.currentTimeMillis());
        events.offer(event);

        while (events.size() > 1000) {
            events.poll();
        }
    }

    public void recordRequest(String identifier, String ruleName) {
        RateLimitStats stat = stats.computeIfAbsent(identifier, k -> new RateLimitStats(identifier));
        stat.requests.incrementAndGet();

        AtomicInteger count = requestCounts.computeIfAbsent(identifier, k -> new AtomicInteger(0));
        count.incrementAndGet();
    }

    public void resetLimits(String identifier) {
        String prefix = identifier + ":";
        requestTimestamps.keySet().removeIf(k -> k.startsWith(prefix));
        stats.remove(identifier);
        requestCounts.remove(identifier);
    }

    public RateLimitStats getStats(String identifier) {
        return stats.get(identifier);
    }

    public Map<String, RateLimitStats> getAllStats() {
        return new HashMap<>(stats);
    }

    public List<RateLimitEvent> getEvents(int limit) {
        List<RateLimitEvent> result = new ArrayList<>();
        int count = 0;
        for (RateLimitEvent event : events) {
            if (count++ >= limit) break;
            result.add(event);
        }
        return result;
    }

    public Collection<RateLimitRule> getRules() {
        return rules.values();
    }

    private void startCleanupTask() {
        scheduler.scheduleAtFixedRate(() -> {
            long now = System.currentTimeMillis();

            for (Map.Entry<String, List<Long>> entry : requestTimestamps.entrySet()) {
                List<Long> list = entry.getValue();
                String ruleName = entry.getKey().split(":")[1];
                RateLimitRule rule = rules.get(ruleName);
                if (rule != null) {
                    list.removeIf(t -> now - t > rule.windowMs);
                    if (list.isEmpty()) {
                        requestTimestamps.remove(entry.getKey());
                    }
                }
            }

            stats.entrySet().removeIf(entry -> 
                entry.getValue().requests.get() == 0 && 
                entry.getValue().rejections.get() == 0);

        }, 60, 60, TimeUnit.SECONDS);
    }

    public Map<String, Object> getStats() {
        Map<String, Object> result = new HashMap<>();
        result.put("rulesCount", rules.size());
        result.put("trackedIdentifiers", stats.size());
        result.put("totalRequests", stats.values().stream()
            .mapToLong(s -> s.requests.get())
            .sum());
        result.put("totalRejections", stats.values().stream()
            .mapToLong(s -> s.rejections.get())
            .sum());
        return result;
    }

    public static class RateLimitRule {
        public final String name;
        public final int maxRequests;
        public final long windowMs;
        public final String description;

        public RateLimitRule(String name, int maxRequests, long windowMs, String description) {
            this.name = name;
            this.maxRequests = maxRequests;
            this.windowMs = windowMs;
            this.description = description;
        }
    }

    public static class RateLimitStats {
        public final String identifier;
        public final AtomicLong requests = new AtomicLong(0);
        public final AtomicLong rejections = new AtomicLong(0);

        public RateLimitStats(String identifier) {
            this.identifier = identifier;
        }
    }

    public static class RateLimitEvent {
        public final String identifier;
        public final String ruleName;
        public final String reason;
        public final boolean allowed;
        public final long timestamp;

        public RateLimitEvent(String identifier, String ruleName, String reason, boolean allowed, long timestamp) {
            this.identifier = identifier;
            this.ruleName = ruleName;
            this.reason = reason;
            this.allowed = allowed;
            this.timestamp = timestamp;
        }
    }
}
