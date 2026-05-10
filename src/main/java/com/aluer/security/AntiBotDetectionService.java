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
public class AntiBotDetectionService {

    private final ServerGuardConfig config;
    private final Map<String, PlayerJoinRecord> joinHistory = new ConcurrentHashMap<>();
    private final Map<String, List<Instant>> ipJoinTimeline = new ConcurrentHashMap<>();
    private final Map<String, Instant> blockedBots = new ConcurrentHashMap<>();
    private final Map<String, Integer> botScoreByIP = new ConcurrentHashMap<>();
    private final ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor();

    // Minecraft bot behavior thresholds
    private static final long JOIN_VELOCITY_WINDOW_MS = 3000;
    private static final int MAX_JOINS_IN_VELOCITY_WINDOW = 5;
    private static final int MAX_ACCOUNTS_PER_IP = 4;
    private static final long IP_JOIN_WINDOW_SECONDS = 300;
    private static final int MAX_JOINS_PER_IP_IN_WINDOW = 20;
    private static final long BOT_BLOCK_SECONDS = 3600;
    private static final int BOT_SCORE_THRESHOLD = 75;

    // Known bot username patterns
    private static final List<String> BOT_NAME_PATTERNS = List.of(
            "^[A-Za-z]{2,4}\\d{4,8}$",
            "^Bot_\\w+$",
            "^\\w+Bot$",
            "^[a-z]{3,6}[0-9]{3,6}$",
            "^MC-\\w+$",
            "^[A-Z]{2,4}_[a-z]{3,6}$"
    );

    private static final Set<String> KNOWN_BOT_PREFIXES = Set.of(
            "Bot", "MCBot", "Headless", "Auto", "Cracked",
            "Spambot", "Joinbot", "Pingbot", "Nullbot"
    );

    private final AtomicLong totalBotsDetected = new AtomicLong(0);
    private final AtomicLong totalBotsBlocked = new AtomicLong(0);

    public AntiBotDetectionService() {
        this(new ServerGuardConfig());
    }

    @Autowired
    public AntiBotDetectionService(ServerGuardConfig config) {
        this.config = config;
        scheduler.scheduleAtFixedRate(this::cleanupExpired, 120, 300, TimeUnit.SECONDS);
    }

    public BotCheckResult checkPlayerJoin(String playerName, String ip, String clientBrand) {
        if (!config.getSecurity().getSuperEvolution().isAntiBot()) {
            return BotCheckResult.clean();
        }

        if (blockedBots.containsKey(ip)) {
            Instant until = blockedBots.get(ip);
            if (Instant.now().isAfter(until)) {
                blockedBots.remove(ip);
            } else {
                return BotCheckResult.blocked("IP is bot-blocked until " + until);
            }
        }

        int score = 0;
        List<String> reasons = new ArrayList<>();

        // Rule 1: Suspicious username patterns
        if (matchesBotNamePattern(playerName) || hasBotPrefix(playerName)) {
            score += 25;
            reasons.add("BOT_NAME_PATTERN: " + playerName);
        }

        // Rule 2: Join velocity (too many joins in short time from same IP)
        List<Instant> joins = ipJoinTimeline.computeIfAbsent(ip, k -> new ArrayList<>());
        joins.add(Instant.now());
        long velocityCutoff = System.currentTimeMillis() - JOIN_VELOCITY_WINDOW_MS;
        long recentJoins = joins.stream().filter(t -> t.toEpochMilli() > velocityCutoff).count();
        if (recentJoins > MAX_JOINS_IN_VELOCITY_WINDOW) {
            score += 35;
            reasons.add("JOIN_VELOCITY: " + recentJoins + " joins in " + JOIN_VELOCITY_WINDOW_MS + "ms");
        }

        // Rule 3: Too many accounts from same IP
        PlayerJoinRecord record = joinHistory.computeIfAbsent(ip, k -> new PlayerJoinRecord());
        record.playerNames.add(playerName);
        if (record.playerNames.size() > MAX_ACCOUNTS_PER_IP) {
            score += 30;
            reasons.add("MULTI_ACCOUNT: " + record.playerNames.size() + " accounts from IP " + ip);
        }

        // Rule 4: Total joins from IP in time window
        Instant windowCutoff = Instant.now().minusSeconds(IP_JOIN_WINDOW_SECONDS);
        joins.removeIf(t -> t.isBefore(windowCutoff));
        if (joins.size() > MAX_JOINS_PER_IP_IN_WINDOW) {
            score += 20;
            reasons.add("IP_JOIN_FLOOD: " + joins.size() + " joins in " + IP_JOIN_WINDOW_SECONDS + "s");
        }

        // Rule 5: Suspicious client brand
        if (clientBrand != null && isSuspiciousClient(clientBrand)) {
            score += 15;
            reasons.add("SUSPICIOUS_CLIENT: " + clientBrand);
        }

        // Rule 6: Cumulative bot score
        int existingScore = botScoreByIP.getOrDefault(ip, 0);
        botScoreByIP.put(ip, existingScore + score);

        boolean isBot = score >= BOT_SCORE_THRESHOLD || (existingScore + score) >= BOT_SCORE_THRESHOLD;
        if (isBot) {
            blockedBots.put(ip, Instant.now().plusSeconds(BOT_BLOCK_SECONDS));
            totalBotsDetected.incrementAndGet();
            totalBotsBlocked.incrementAndGet();
            return BotCheckResult.detected(score, reasons, BOT_BLOCK_SECONDS);
        }

        record.lastJoin = Instant.now();
        return score > 0 ? BotCheckResult.suspicious(score, reasons) : BotCheckResult.clean();
    }

    public void unblockIP(String ip) {
        blockedBots.remove(ip);
        botScoreByIP.remove(ip);
        joinHistory.remove(ip);
    }

    public Map<String, Object> getStatus() {
        Map<String, Object> status = new LinkedHashMap<>();
        status.put("trackedIPs", joinHistory.size());
        status.put("blockedBots", blockedBots.size());
        status.put("totalBotsDetected", totalBotsDetected.get());
        status.put("totalBotsBlocked", totalBotsBlocked.get());
        List<Map<String, Object>> blocked = new ArrayList<>();
        for (Map.Entry<String, Instant> e : blockedBots.entrySet()) {
            Map<String, Object> entry = new LinkedHashMap<>();
            entry.put("ip", e.getKey());
            entry.put("until", e.getValue().toString());
            PlayerJoinRecord rec = joinHistory.get(e.getKey());
            if (rec != null) entry.put("accounts", new ArrayList<>(rec.playerNames));
            entry.put("botScore", botScoreByIP.getOrDefault(e.getKey(), 0));
            blocked.add(entry);
        }
        status.put("blockedList", blocked);
        return status;
    }

    public long getTotalBotsDetected() { return totalBotsDetected.get(); }
    public long getTotalBotsBlocked() { return totalBotsBlocked.get(); }

    private boolean matchesBotNamePattern(String name) {
        if (name == null) return false;
        for (String pattern : BOT_NAME_PATTERNS) {
            if (name.matches(pattern)) return true;
        }
        return false;
    }

    private boolean hasBotPrefix(String name) {
        if (name == null) return false;
        for (String prefix : KNOWN_BOT_PREFIXES) {
            if (name.toLowerCase().startsWith(prefix.toLowerCase())) return true;
        }
        return false;
    }

    private boolean isSuspiciousClient(String brand) {
        if (brand == null) return true; // null brand = suspicious
        String lower = brand.toLowerCase();
        return lower.contains("bot") || lower.contains("headless")
                || lower.contains("cracked") || lower.contains("hack")
                || lower.contains("inject") || lower.contains("cheat");
    }

    private void cleanupExpired() {
        Instant now = Instant.now();
        blockedBots.entrySet().removeIf(e -> e.getValue().isBefore(now));
        ipJoinTimeline.entrySet().removeIf(e -> {
            e.getValue().removeIf(t -> t.isBefore(now.minusSeconds(IP_JOIN_WINDOW_SECONDS * 2)));
            return e.getValue().isEmpty();
        });
    }

    private static class PlayerJoinRecord {
        final Set<String> playerNames = new HashSet<>();
        Instant lastJoin = Instant.now();
    }

    public static class BotCheckResult {
        private final boolean blocked;
        private final boolean detected;
        private final boolean suspicious;
        private final int score;
        private final List<String> reasons;
        private final String message;
        private final long blockSeconds;

        private BotCheckResult(boolean blocked, boolean detected, boolean suspicious, int score,
                               List<String> reasons, String message, long blockSeconds) {
            this.blocked = blocked;
            this.detected = detected;
            this.suspicious = suspicious;
            this.score = score;
            this.reasons = reasons;
            this.message = message;
            this.blockSeconds = blockSeconds;
        }

        public static BotCheckResult clean() {
            return new BotCheckResult(false, false, false, 0, List.of(), null, 0);
        }

        public static BotCheckResult suspicious(int score, List<String> reasons) {
            return new BotCheckResult(false, false, true, score, reasons, "Suspicious bot activity: " + String.join("; ", reasons), 0);
        }

        public static BotCheckResult detected(int score, List<String> reasons, long blockSeconds) {
            return new BotCheckResult(true, true, true, score, reasons,
                    "Bot detected: " + String.join("; ", reasons), blockSeconds);
        }

        public static BotCheckResult blocked(String message) {
            return new BotCheckResult(true, false, false, 0, List.of(), message, 0);
        }

        public boolean isBlocked() { return blocked; }
        public boolean isDetected() { return detected; }
        public boolean isSuspicious() { return suspicious; }
        public int getScore() { return score; }
        public List<String> getReasons() { return reasons; }
        public String getMessage() { return message; }
        public long getBlockSeconds() { return blockSeconds; }
    }
}
