package com.aluer.security;

import com.aluer.config.ServerGuardConfig;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;

@Service
public class ConnectionThrottleService {

    private final ServerGuardConfig config;

    private final Map<String, List<Long>> connectionTimestamps = new ConcurrentHashMap<>();
    private final Map<String, Integer> excessCounters = new ConcurrentHashMap<>();
    private final Map<String, Long> lastActivity = new ConcurrentHashMap<>();
    private final Map<String, Long> delayedUntil = new ConcurrentHashMap<>();

    private final AtomicLong totalConnections = new AtomicLong(0);
    private final AtomicLong blockedCount = new AtomicLong(0);
    private final AtomicLong delayedCount = new AtomicLong(0);

    private final ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor();

    private static final long WINDOW_5S = 5000L;
    private static final long WINDOW_60S = 60000L;
    private static final long WINDOW_300S = 300000L;
    private static final long BURST_WINDOW_MS = 1000L;
    private static final int BURST_THRESHOLD = 3;
    private static final int MAX_CONNECTIONS_PER_IP = 5;
    private static final long STALE_THRESHOLD_MS = 600000L;

    private static final long DELAY_1ST_MS = 2000L;
    private static final long DELAY_2ND_MS = 5000L;
    private static final long DELAY_3RD_MS = 15000L;
    private static final long DELAY_4TH_MS = 30000L;

    public ConnectionThrottleService() {
        this(new ServerGuardConfig());
    }

    @Autowired
    public ConnectionThrottleService(ServerGuardConfig config) {
        this.config = config;
        scheduler.scheduleAtFixedRate(this::cleanupStale, 60, 60, TimeUnit.SECONDS);
    }

    public ThrottleResult tryAcquire(String ip) {
        if (!config.getSecurity().getSuperEvolution().isConnectionThrottle()) {
            return ThrottleResult.allowed();
        }

        totalConnections.incrementAndGet();
        long now = System.currentTimeMillis();

        ThrottleResult delayed = checkExistingDelay(ip, now);
        if (delayed != null) {
            return delayed;
        }

        List<Long> timestamps = connectionTimestamps.computeIfAbsent(ip, k -> new CopyOnWriteArrayList<>());
        timestamps.add(now);
        lastActivity.put(ip, now);

        ThrottleResult rejection = checkWindows(ip, timestamps, now);
        if (rejection != null) {
            blockedCount.incrementAndGet();
            return rejection;
        }

        return ThrottleResult.allowed();
    }

    private ThrottleResult checkExistingDelay(String ip, long now) {
        Long delayUntil = delayedUntil.get(ip);
        if (delayUntil != null && delayUntil > now) {
            long remainingMs = delayUntil - now;
            return ThrottleResult.delayed(remainingMs);
        }
        if (delayUntil != null && delayUntil <= now) {
            delayedUntil.remove(ip);
        }
        return null;
    }

    private ThrottleResult checkWindows(String ip, List<Long> timestamps, long now) {
        // Burst detection: 3+ connections in 1 second
        long burstCutoff = now - BURST_WINDOW_MS;
        long burstCount = timestamps.stream().filter(t -> t > burstCutoff).count();
        if (burstCount >= BURST_THRESHOLD) {
            String reason = "Connection burst: " + burstCount + " connections in " + BURST_WINDOW_MS + "ms";
            return ThrottleResult.rejected(reason);
        }

        // Max connections per IP
        long maxCutoff = now - WINDOW_300S;
        long totalForIp = timestamps.stream().filter(t -> t > maxCutoff).count();
        if (totalForIp > MAX_CONNECTIONS_PER_IP) {
            String reason = "Max connections per IP exceeded: " + totalForIp + " > " + MAX_CONNECTIONS_PER_IP;
            return ThrottleResult.rejected(reason);
        }

        // Window-based throttling
        long window5sCutoff = now - WINDOW_5S;
        long count5s = timestamps.stream().filter(t -> t > window5sCutoff).count();
        long window60sCutoff = now - WINDOW_60S;
        long count60s = timestamps.stream().filter(t -> t > window60sCutoff).count();
        long window300sCutoff = now - WINDOW_300S;
        long count300s = timestamps.stream().filter(t -> t > window300sCutoff).count();

        int excessLevel = excessCounters.getOrDefault(ip, 0);

        boolean thresholdExceeded = false;
        if (count5s > 2) thresholdExceeded = true;
        if (count60s > 8) thresholdExceeded = true;
        if (count300s > 20) thresholdExceeded = true;

        if (thresholdExceeded) {
            excessCounters.put(ip, excessLevel + 1);
            long delayMs;
            switch (excessLevel) {
                case 0: delayMs = DELAY_1ST_MS; break;
                case 1: delayMs = DELAY_2ND_MS; break;
                case 2: delayMs = DELAY_3RD_MS; break;
                default: delayMs = DELAY_4TH_MS; break;
            }
            delayedUntil.put(ip, now + delayMs);
            delayedCount.incrementAndGet();
            String reason = "Progressive delay: excess level " + (excessLevel + 1) + ", delay " + delayMs + "ms";
            return ThrottleResult.rejected(reason);
        }

        return null;
    }

    private void cleanupStale() {
        long now = System.currentTimeMillis();
        List<String> staleIPs = new ArrayList<>();
        for (Map.Entry<String, Long> entry : lastActivity.entrySet()) {
            if (now - entry.getValue() > STALE_THRESHOLD_MS) {
                staleIPs.add(entry.getKey());
            }
        }
        for (String ip : staleIPs) {
            connectionTimestamps.remove(ip);
            excessCounters.remove(ip);
            lastActivity.remove(ip);
            delayedUntil.remove(ip);
        }
    }

    public Map<String, Object> getStatus() {
        Map<String, Object> status = new LinkedHashMap<>();
        status.put("totalConnections", totalConnections.get());
        status.put("blockedCount", blockedCount.get());
        status.put("delayedCount", delayedCount.get());
        status.put("activeIPs", connectionTimestamps.size());
        status.put("delayedIPs", delayedUntil.size());
        status.put("configEnabled", config.getSecurity().getSuperEvolution().isConnectionThrottle());
        return status;
    }

    // -- DelayedResult used internally (exposed for caller clarity) --
    private static class DelayedResult extends ThrottleResult {
        DelayedResult(long delayMs) {
            super(false, true, false, delayMs, null);
        }
    }

    // -- RejectionResult used internally --
    private static class RejectionResult extends ThrottleResult {
        RejectionResult(String reason) {
            super(false, false, true, 0, reason);
        }
    }

    // -- ThrottleResult --
    public static class ThrottleResult {
        private final boolean allowed;
        private final boolean delayed;
        private final boolean rejected;
        private final long delayMs;
        private final String reason;

        private ThrottleResult(boolean allowed, boolean delayed, boolean rejected, long delayMs, String reason) {
            this.allowed = allowed;
            this.delayed = delayed;
            this.rejected = rejected;
            this.delayMs = delayMs;
            this.reason = reason;
        }

        public static ThrottleResult allowed() {
            return new ThrottleResult(true, false, false, 0, null);
        }

        public static ThrottleResult delayed(long delayMs) {
            return new ThrottleResult(false, true, false, delayMs, "Delayed for " + delayMs + "ms");
        }

        public static ThrottleResult rejected(String reason) {
            return new ThrottleResult(false, false, true, 0, reason);
        }

        public boolean isAllowed() { return allowed; }
        public boolean isDelayed() { return delayed; }
        public boolean isRejected() { return rejected; }
        public long getDelayMs() { return delayMs; }
        public String getReason() { return reason; }
    }
}
