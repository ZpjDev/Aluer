package com.aluer.security;

import org.springframework.stereotype.Service;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;

@Service
public class IPReputationService {

    private final Map<String, IPProfile> ipProfiles = new ConcurrentHashMap<>();
    private final Map<String, List<ReputationEvent>> reputationHistory = new ConcurrentHashMap<>();
    private final Set<String> blacklistedIPs = ConcurrentHashMap.newKeySet();
    private final Set<String> whitelistedIPs = ConcurrentHashMap.newKeySet();
    private final Queue<ReputationAlert> alerts = new ConcurrentLinkedQueue<>();
    private final ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(2);

    private static final double DEFAULT_REPUTATION_SCORE = 50.0;
    private static final double MAX_SCORE = 100.0;
    private static final double MIN_SCORE = 0.0;
    private static final long SCORE_DECAY_TIME = 86400000;

    private final AtomicLong totalEvaluations = new AtomicLong(0);

    public IPReputationService() {
        startReputationTask();
    }

    public double evaluateIP(String ip) {
        totalEvaluations.incrementAndGet();

        if (whitelistedIPs.contains(ip)) {
            return MAX_SCORE;
        }

        if (blacklistedIPs.contains(ip)) {
            return MIN_SCORE;
        }

        IPProfile profile = ipProfiles.computeIfAbsent(ip, k -> new IPProfile(ip));
        double score = profile.calculateScore();

        if (score < 20) {
            addAlert(ip, "LOW_REPUTATION", "IP reputation score below threshold: " + score);
        }

        return score;
    }

    public void recordSuccessfulConnection(String ip) {
        IPProfile profile = ipProfiles.computeIfAbsent(ip, k -> new IPProfile(ip));
        profile.recordSuccess();

        ReputationEvent event = new ReputationEvent(ip, "SUCCESS", "Connection successful", System.currentTimeMillis());
        addToHistory(ip, event);
    }

    public void recordFailedConnection(String ip, String reason) {
        IPProfile profile = ipProfiles.computeIfAbsent(ip, k -> new IPProfile(ip));
        profile.recordFailure();

        ReputationEvent event = new ReputationEvent(ip, "FAILURE", reason, System.currentTimeMillis());
        addToHistory(ip, event);

        if (profile.failures.get() > 10) {
            addAlert(ip, "REPEAT_FAILURES", "Multiple failed connections: " + profile.failures.get());
        }
    }

    public void recordSuspiciousActivity(String ip, String activityType) {
        IPProfile profile = ipProfiles.computeIfAbsent(ip, k -> new IPProfile(ip));
        profile.recordSuspicious(activityType);

        ReputationEvent event = new ReputationEvent(ip, "SUSPICIOUS", activityType, System.currentTimeMillis());
        addToHistory(ip, event);

        if (profile.suspiciousCount.get() > 5) {
            addAlert(ip, "SUSPICIOUS_ACTIVITY", "Multiple suspicious activities: " + activityType);
        }
    }

    public void recordAttack(String ip, String attackType) {
        IPProfile profile = ipProfiles.computeIfAbsent(ip, k -> new IPProfile(ip));
        profile.recordAttack(attackType);

        ReputationEvent event = new ReputationEvent(ip, "ATTACK", attackType, System.currentTimeMillis());
        addToHistory(ip, event);

        addAlert(ip, "ATTACK_DETECTED", "Attack detected: " + attackType);
    }

    public void addToBlacklist(String ip) {
        blacklistedIPs.add(ip);
        whitelistedIPs.remove(ip);

        IPProfile profile = ipProfiles.get(ip);
        if (profile != null) {
            profile.blacklisted = true;
        }

        ReputationEvent event = new ReputationEvent(ip, "BLACKLIST", "Added to blacklist", System.currentTimeMillis());
        addToHistory(ip, event);
    }

    public void removeFromBlacklist(String ip) {
        blacklistedIPs.remove(ip);

        IPProfile profile = ipProfiles.get(ip);
        if (profile != null) {
            profile.blacklisted = false;
        }

        ReputationEvent event = new ReputationEvent(ip, "UNBLACKLIST", "Removed from blacklist", System.currentTimeMillis());
        addToHistory(ip, event);
    }

    public void addToWhitelist(String ip) {
        whitelistedIPs.add(ip);
        blacklistedIPs.remove(ip);

        IPProfile profile = ipProfiles.computeIfAbsent(ip, k -> new IPProfile(ip));
        profile.whitelisted = true;
        profile.score = MAX_SCORE;

        ReputationEvent event = new ReputationEvent(ip, "WHITELIST", "Added to whitelist", System.currentTimeMillis());
        addToHistory(ip, event);
    }

    public void removeFromWhitelist(String ip) {
        whitelistedIPs.remove(ip);

        IPProfile profile = ipProfiles.get(ip);
        if (profile != null) {
            profile.whitelisted = false;
        }
    }

    public boolean isBlacklisted(String ip) {
        return blacklistedIPs.contains(ip);
    }

    public boolean isWhitelisted(String ip) {
        return whitelistedIPs.contains(ip);
    }

    public IPProfile getProfile(String ip) {
        return ipProfiles.get(ip);
    }

    public Collection<IPProfile> getAllProfiles() {
        return ipProfiles.values();
    }

    public List<ReputationEvent> getHistory(String ip, int limit) {
        List<ReputationEvent> history = reputationHistory.get(ip);
        if (history == null) {
            return new ArrayList<>();
        }

        return history.stream().limit(limit).toList();
    }

    private void addToHistory(String ip, ReputationEvent event) {
        List<ReputationEvent> history = reputationHistory.computeIfAbsent(ip, k -> new CopyOnWriteArrayList<>());
        history.add(event);

        while (history.size() > 100) {
            history.remove(0);
        }
    }

    private void addAlert(String ip, String type, String details) {
        ReputationAlert alert = new ReputationAlert(ip, type, details, System.currentTimeMillis());
        alerts.offer(alert);

        while (alerts.size() > 500) {
            alerts.poll();
        }
    }

    public List<ReputationAlert> getAlerts(int limit) {
        List<ReputationAlert> result = new ArrayList<>();
        int count = 0;
        for (ReputationAlert alert : alerts) {
            if (count++ >= limit) break;
            result.add(alert);
        }
        return result;
    }

    private void startReputationTask() {
        scheduler.scheduleAtFixedRate(() -> {
            for (IPProfile profile : ipProfiles.values()) {
                if (profile.whitelisted || profile.blacklisted) {
                    continue;
                }

                if (System.currentTimeMillis() - profile.lastUpdate > SCORE_DECAY_TIME) {
                    profile.applyDecay();
                }
            }

            reputationHistory.entrySet().removeIf(entry -> {
                List<ReputationEvent> history = entry.getValue();
                history.removeIf(e -> System.currentTimeMillis() - e.timestamp > SCORE_DECAY_TIME);
                return history.isEmpty();
            });

        }, 3600, 3600, TimeUnit.SECONDS);
    }

    public Map<String, Object> getStats() {
        Map<String, Object> stats = new HashMap<>();
        stats.put("totalProfiles", ipProfiles.size());
        stats.put("blacklisted", blacklistedIPs.size());
        stats.put("whitelisted", whitelistedIPs.size());
        stats.put("totalEvaluations", totalEvaluations.get());
        return stats;
    }

    public static class IPProfile {
        public final String ip;
        public final AtomicLong successes = new AtomicLong(0);
        public final AtomicLong failures = new AtomicLong(0);
        public final AtomicInteger suspiciousCount = new AtomicInteger(0);
        public final Map<String, AtomicInteger> attackCounts = new ConcurrentHashMap<>();
        public volatile double score = DEFAULT_REPUTATION_SCORE;
        public volatile boolean whitelisted = false;
        public volatile boolean blacklisted = false;
        public volatile long lastUpdate;

        public IPProfile(String ip) {
            this.ip = ip;
            this.lastUpdate = System.currentTimeMillis();
            this.score = DEFAULT_REPUTATION_SCORE;
        }

        public void recordSuccess() {
            successes.incrementAndGet();
            score = Math.min(MAX_SCORE, score + 2);
            lastUpdate = System.currentTimeMillis();
        }

        public void recordFailure() {
            failures.incrementAndGet();
            score = Math.max(MIN_SCORE, score - 5);
            lastUpdate = System.currentTimeMillis();
        }

        public void recordSuspicious(String activityType) {
            suspiciousCount.incrementAndGet();
            score = Math.max(MIN_SCORE, score - 10);
            lastUpdate = System.currentTimeMillis();
        }

        public void recordAttack(String attackType) {
            attackCounts.computeIfAbsent(attackType, k -> new AtomicInteger(0)).incrementAndGet();
            score = Math.max(MIN_SCORE, score - 20);
            lastUpdate = System.currentTimeMillis();
        }

        public void applyDecay() {
            score = Math.max(MIN_SCORE, score - 1);
            lastUpdate = System.currentTimeMillis();
        }

        public double calculateScore() {
            if (whitelisted) return MAX_SCORE;
            if (blacklisted) return MIN_SCORE;

            double baseScore = 50.0;

            long totalAttempts = successes.get() + failures.get();
            if (totalAttempts > 0) {
                double successRate = (double) successes.get() / totalAttempts;
                baseScore += successRate * 30;
            }

            baseScore -= failures.get() * 2;
            baseScore -= suspiciousCount.get() * 5;

            for (AtomicInteger count : attackCounts.values()) {
                baseScore -= count.get() * 10;
            }

            return Math.max(MIN_SCORE, Math.min(MAX_SCORE, baseScore));
        }
    }

    public static class ReputationEvent {
        public final String ip;
        public final String type;
        public final String details;
        public final long timestamp;

        public ReputationEvent(String ip, String type, String details, long timestamp) {
            this.ip = ip;
            this.type = type;
            this.details = details;
            this.timestamp = timestamp;
        }
    }

    public static class ReputationAlert {
        public final String ip;
        public final String type;
        public final String details;
        public final long timestamp;

        public ReputationAlert(String ip, String type, String details, long timestamp) {
            this.ip = ip;
            this.type = type;
            this.details = details;
            this.timestamp = timestamp;
        }
    }
}
