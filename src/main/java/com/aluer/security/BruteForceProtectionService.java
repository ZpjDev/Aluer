package com.aluer.security;

import com.aluer.config.ServerGuardConfig;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

@Service
public class BruteForceProtectionService {

    private final ServerGuardConfig config;
    private final Map<String, FailureRecord> failureTracker = new ConcurrentHashMap<>();
    private final Map<String, Instant> blockedAccounts = new ConcurrentHashMap<>();
    private final Map<String, List<Instant>> ipAttemptTimeline = new ConcurrentHashMap<>();
    private final ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor();

    private static final int MAX_ATTEMPTS_WINDOW_1 = 5;
    private static final int MAX_ATTEMPTS_WINDOW_2 = 15;
    private static final int MAX_ATTEMPTS_WINDOW_3 = 50;
    private static final long WINDOW_1_SECONDS = 60;
    private static final long WINDOW_2_SECONDS = 600;
    private static final long WINDOW_3_SECONDS = 3600;

    private static final long BASE_BLOCK_SECONDS = 300;
    private static final long ESCALATED_BLOCK_SECONDS = 1800;
    private static final long MAX_BLOCK_SECONDS = 7200;

    private static final long PROGRESSIVE_DELAY_BASE_MS = 1000;
    private static final long PROGRESSIVE_DELAY_PER_FAILURE_MS = 500;
    private static final long MAX_PROGRESSIVE_DELAY_MS = 15000;

    private static final int IP_GLOBAL_MAX_ATTEMPTS = 100;
    private static final long IP_WINDOW_SECONDS = 600;

    private final AtomicLong totalBlocks = new AtomicLong(0);
    private final AtomicLong totalBruteForceDetections = new AtomicLong(0);

    public BruteForceProtectionService() {
        this(new ServerGuardConfig());
    }

    @Autowired
    public BruteForceProtectionService(ServerGuardConfig config) {
        this.config = config;
        scheduler.scheduleAtFixedRate(this::cleanupExpired, 60, 120, TimeUnit.SECONDS);
    }

    public AuthResult checkLoginAttempt(String username, String ip, String source) {
        if (!config.getSecurity().getSuperEvolution().isBruteForce()) {
            return AuthResult.allowed(0);
        }

        if (isBlocked(username)) {
            return AuthResult.blocked("Account " + username + " is temporarily locked due to excessive failed attempts");
        }

        if (isIPGloballyBlocked(ip)) {
            return AuthResult.blocked("IP " + ip + " is temporarily blocked due to global brute force activity");
        }

        FailureRecord record = failureTracker.computeIfAbsent(username, k -> new FailureRecord());
        long now = Instant.now().getEpochSecond();

        record.attemptsInWindow1.removeIf(t -> now - t > WINDOW_1_SECONDS);
        record.attemptsInWindow2.removeIf(t -> now - t > WINDOW_2_SECONDS);
        record.attemptsInWindow3.removeIf(t -> now - t > WINDOW_3_SECONDS);

        int w1 = record.attemptsInWindow1.size();
        int w2 = record.attemptsInWindow2.size();
        int w3 = record.attemptsInWindow3.size();

        if (w1 >= MAX_ATTEMPTS_WINDOW_1) {
            return handleBruteForce(username, ip, "Window1: " + w1 + " attempts in " + WINDOW_1_SECONDS + "s", BASE_BLOCK_SECONDS);
        }
        if (w2 >= MAX_ATTEMPTS_WINDOW_2) {
            return handleBruteForce(username, ip, "Window2: " + w2 + " attempts in " + WINDOW_2_SECONDS + "s", ESCALATED_BLOCK_SECONDS);
        }
        if (w3 >= MAX_ATTEMPTS_WINDOW_3) {
            return handleBruteForce(username, ip, "Window3: " + w3 + " attempts in " + WINDOW_3_SECONDS + "s", MAX_BLOCK_SECONDS);
        }

        long delay = Math.min(PROGRESSIVE_DELAY_BASE_MS + (record.failureCount * PROGRESSIVE_DELAY_PER_FAILURE_MS), MAX_PROGRESSIVE_DELAY_MS);
        record.lastDelayMs = delay;

        return AuthResult.allowed(delay);
    }

    public void recordFailedAttempt(String username, String ip) {
        FailureRecord record = failureTracker.computeIfAbsent(username, k -> new FailureRecord());
        long now = Instant.now().getEpochSecond();
        record.attemptsInWindow1.add(now);
        record.attemptsInWindow2.add(now);
        record.attemptsInWindow3.add(now);
        record.failureCount++;
        record.lastFailure = Instant.now();

        ipAttemptTimeline.computeIfAbsent(ip, k -> new ArrayList<>()).add(Instant.now());
    }

    public void recordSuccessfulAttempt(String username, String ip) {
        failureTracker.remove(username);
        ipAttemptTimeline.remove(ip);
    }

    public void unblock(String username) {
        blockedAccounts.remove(username);
        failureTracker.remove(username);
    }

    public boolean isBlocked(String username) {
        Instant blockedUntil = blockedAccounts.get(username);
        if (blockedUntil == null) return false;
        if (Instant.now().isAfter(blockedUntil)) {
            blockedAccounts.remove(username);
            return false;
        }
        return true;
    }

    public Map<String, Object> getStatus() {
        Map<String, Object> status = new LinkedHashMap<>();
        status.put("trackedAccounts", failureTracker.size());
        status.put("blockedAccounts", blockedAccounts.size());
        status.put("totalBlocks", totalBlocks.get());
        status.put("totalBruteForceDetections", totalBruteForceDetections.get());
        List<Map<String, Object>> blocked = new ArrayList<>();
        for (Map.Entry<String, Instant> e : blockedAccounts.entrySet()) {
            Map<String, Object> entry = new LinkedHashMap<>();
            entry.put("account", e.getKey());
            entry.put("until", e.getValue().toString());
            entry.put("remainingSeconds", Math.max(0, e.getValue().getEpochSecond() - Instant.now().getEpochSecond()));
            blocked.add(entry);
        }
        status.put("blockedList", blocked);
        return status;
    }

    public int getTrackedAccountCount() { return failureTracker.size(); }
    public int getBlockedAccountCount() { return blockedAccounts.size(); }
    public long getTotalBlocks() { return totalBlocks.get(); }
    public long getTotalBruteForceDetections() { return totalBruteForceDetections.get(); }

    private AuthResult handleBruteForce(String username, String ip, String reason, long blockSeconds) {
        blockedAccounts.put(username, Instant.now().plusSeconds(blockSeconds));
        totalBlocks.incrementAndGet();
        totalBruteForceDetections.incrementAndGet();
        return AuthResult.blockedWithDetection("Brute force detected for " + username + ": " + reason + ". Blocked for " + blockSeconds + "s");
    }

    private boolean isIPGloballyBlocked(String ip) {
        List<Instant> attempts = ipAttemptTimeline.get(ip);
        if (attempts == null) return false;
        Instant cutoff = Instant.now().minusSeconds(IP_WINDOW_SECONDS);
        attempts.removeIf(t -> t.isBefore(cutoff));
        if (attempts.isEmpty()) {
            ipAttemptTimeline.remove(ip);
            return false;
        }
        return attempts.size() > IP_GLOBAL_MAX_ATTEMPTS;
    }

    private void cleanupExpired() {
        Instant now = Instant.now();
        failureTracker.entrySet().removeIf(e -> {
            FailureRecord r = e.getValue();
            r.attemptsInWindow1.removeIf(t -> now.getEpochSecond() - t > WINDOW_1_SECONDS);
            r.attemptsInWindow2.removeIf(t -> now.getEpochSecond() - t > WINDOW_2_SECONDS);
            r.attemptsInWindow3.removeIf(t -> now.getEpochSecond() - t > WINDOW_3_SECONDS);
            return r.attemptsInWindow1.isEmpty() && r.attemptsInWindow2.isEmpty()
                    && r.attemptsInWindow3.isEmpty() && r.lastFailure != null
                    && r.lastFailure.plusSeconds(WINDOW_3_SECONDS * 2).isBefore(now);
        });
        blockedAccounts.entrySet().removeIf(e -> e.getValue().isBefore(now));
        ipAttemptTimeline.entrySet().removeIf(e -> {
            e.getValue().removeIf(t -> t.isBefore(now.minusSeconds(IP_WINDOW_SECONDS)));
            return e.getValue().isEmpty();
        });
    }

    private static class FailureRecord {
        final List<Long> attemptsInWindow1 = new ArrayList<>();
        final List<Long> attemptsInWindow2 = new ArrayList<>();
        final List<Long> attemptsInWindow3 = new ArrayList<>();
        int failureCount;
        Instant lastFailure;
        long lastDelayMs;
    }

    public static class AuthResult {
        private final boolean allowed;
        private final boolean bruteForceDetected;
        private final String message;
        private final long progressiveDelayMs;

        private AuthResult(boolean allowed, boolean bruteForceDetected, String message, long delayMs) {
            this.allowed = allowed;
            this.bruteForceDetected = bruteForceDetected;
            this.message = message;
            this.progressiveDelayMs = delayMs;
        }

        public static AuthResult allowed(long delayMs) {
            return new AuthResult(true, false, null, delayMs);
        }

        public static AuthResult blocked(String message) {
            return new AuthResult(false, false, message, 0);
        }

        public static AuthResult blockedWithDetection(String message) {
            return new AuthResult(false, true, message, 0);
        }

        public boolean isAllowed() { return allowed; }
        public boolean isBruteForceDetected() { return bruteForceDetected; }
        public String getMessage() { return message; }
        public long getProgressiveDelayMs() { return progressiveDelayMs; }
    }
}
