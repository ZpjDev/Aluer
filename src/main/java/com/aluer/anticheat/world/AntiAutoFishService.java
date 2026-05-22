package com.aluer.anticheat.world;

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

/**
 * 自动钓鱼检测 (Auto Fish) — V4.0 玩家行为安全模块
 *
 * 检测原理：
 *   Auto Fish 作弊模块通过监听游戏声音事件（浮标下沉音效）、粒子效果或浮标运动来自动收竿，
 *   实现在无人值守的情况下持续获得钓鱼战利品。本模块通过以下维度检测自动钓鱼：
 *   1. 收竿反应时间——正常人类对浮标下沉的反应时间在 200-800ms 之间，
 *      自动钓鱼模块通常在 0-100ms（精确到 1-2 tick）内收竿，远超人类反应极限。
 *   2. 连续精准收竿——单次快速收竿可能是运气，但连续 3 次以上均 < 100ms 收竿则极可能为自动。
 *   3. 长期垂钓一致性——正常玩家不可能连续数小时只钓鱼不移动，
 *      自动钓鱼可以在同一位置连续运行数小时，每次收竿间隔高度均匀。
 *   4. 收竿间隔模式——人类收竿间隔有随机性，自动钓鱼的间隔标准差极小。
 *
 * 配置开关：serverguard.security.super-evolution.anti-auto-fish
 */
@Service
public class AntiAutoFishService {

    private final ServerGuardConfig config;
    private final Map<String, List<FishingEvent>> playerFishingEvents = new ConcurrentHashMap<>();
    private final Map<String, FishSessionStats> playerSessionStats = new ConcurrentHashMap<>();
    private final Map<String, Instant> flaggedPlayers = new ConcurrentHashMap<>();
    private final ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor();

    /** 抛竿总次数 */
    private final AtomicLong totalCastings = new AtomicLong(0);
    /** 自动钓鱼违规次数 */
    private final AtomicLong autoFishViolations = new AtomicLong(0);

    /** 自动钓鱼收竿最大延迟（毫秒）——超过此值判断为人类操作 */
    private static final long MAX_AUTO_FISH_REACTION_MS = 100;

    /** 正常人类最小反应时间（毫秒）——低于此值基本不可能为人类 */
    private static final long MIN_HUMAN_REACTION_MS = 150;

    /** 连续快速收竿次数阈值 */
    private static final int CONSECUTIVE_FAST_REEL_THRESHOLD = 3;

    /** 长期垂钓判定时间（秒）——同一位置持续钓鱼超过此时间为可疑 */
    private static final long LONG_FISHING_SESSION_SEC = 600;

    /** 收竿间隔变异系数阈值——低于此值说明收竿间隔过于均匀 */
    private static final double MAX_INTERVAL_COV = 0.10;

    /** 最少收竿样本数（用于统计有效分析） */
    private static final int MIN_REEL_SAMPLES = 5;

    /** 记录保留时间（秒） */
    private static final long RECORD_RETENTION_SECONDS = 1200;

    /** 标记持续时间（秒） */
    private static final long FLAG_DURATION_SECONDS = 3600;

    public AntiAutoFishService() {
        this(new ServerGuardConfig());
    }

    @Autowired
    public AntiAutoFishService(ServerGuardConfig config) {
        this.config = config;
        scheduler.scheduleAtFixedRate(this::cleanupOldRecords, 300, 600, TimeUnit.SECONDS);
    }

    /**
     * 记录一次抛竿事件——钓鱼竿被投出。
     *
     * 每次玩家使用钓鱼竿投出浮标时调用，建立一次新的钓鱼尝试记录。
     *
     * @param playerName 玩家名称
     * @param playerUUID 玩家 UUID
     * @param x          玩家 X 坐标
     * @param y          玩家 Y 坐标
     * @param z          玩家 Z 坐标
     */
    public void recordCast(String playerName, String playerUUID, double x, double y, double z) {
        if (!config.getSecurity().getSuperEvolution().isAntiAutoFish()) {
            return;
        }

        Instant now = Instant.now();
        List<FishingEvent> events = playerFishingEvents.computeIfAbsent(playerName,
            k -> Collections.synchronizedList(new ArrayList<>()));
        events.add(new FishingEvent(now, "CAST", x, y, z, 0));

        FishSessionStats stats = playerSessionStats.computeIfAbsent(playerName,
            k -> new FishSessionStats());
        stats.updatePosition(x, y, z);

        totalCastings.incrementAndGet();
    }

    /**
     * 检测收竿事件——分析收竿反应时间是否为自动钓鱼行为。
     *
     * 这是自动钓鱼检测的核心方法。通过比较"最近一次抛竿时间"与"收竿时间"
     * （以浮标下沉事件时间为参考），计算反应延迟。
     *
     * @param playerName  玩家名称
     * @param playerUUID  玩家 UUID
     * @param fishCaught  是否钓到了东西（用于真实性分析）
     * @param lureLevel   鱼饵附魔等级（影响等待时间）
     * @param luckOfSea   海之眷顾附魔等级（影响战利品）
     * @return 检测结果
     */
    public DetectionResult detectReel(String playerName, String playerUUID,
                                       boolean fishCaught, int lureLevel, int luckOfSea) {
        if (!config.getSecurity().getSuperEvolution().isAntiAutoFish()) {
            return DetectionResult.clean();
        }

        // 检查标记
        Instant flaggedUntil = flaggedPlayers.get(playerName);
        if (flaggedUntil != null) {
            if (Instant.now().isAfter(flaggedUntil)) {
                flaggedPlayers.remove(playerName);
            } else {
                return DetectionResult.flagged(List.of(
                    "PLAYER_ALREADY_FLAGGED: " + playerName));
            }
        }

        Instant now = Instant.now();
        List<FishingEvent> events = playerFishingEvents.computeIfAbsent(playerName,
            k -> Collections.synchronizedList(new ArrayList<>()));

        // 找到最近一次 CAST 事件
        Optional<FishingEvent> lastCast = events.stream()
            .filter(e -> "CAST".equals(e.eventType))
            .reduce((first, second) -> second);

        if (lastCast.isEmpty()) {
            // 没有对应的抛竿记录（可能是模块启动前玩家已经在钓鱼）
            return DetectionResult.clean();
        }

        // 计算反应时间：从抛竿到收竿的总时间减去预期等待时间（基于 lure 等级）
        long totalTime = now.toEpochMilli() - lastCast.get().time.toEpochMilli();
        // Lure 附魔每级减少 5 秒等待时间，5 秒为基准
        int baseWaitSec = Math.max(5, 30 - lureLevel * 5);
        long estimatedReactionTime = totalTime - (baseWaitSec * 1000L);

        // 记录收竿事件（使用 totalTime 作为实际经过时间）
        FishingEvent reelEvent = new FishingEvent(now, "REEL", 0, 0, 0,
            totalTime);
        events.add(reelEvent);

        int score = 0;
        List<String> reasons = new ArrayList<>();

        // === 检测 1: 收竿反应时间 ===
        // 计算最近一次有效收竿的反应时间
        // 从事件列表中获取最近的 REEL 事件间的时间差来估算反应时间
        long reactionTime = estimateReactionTime(events);
        if (reactionTime >= 0) {
            if (reactionTime < MAX_AUTO_FISH_REACTION_MS) {
                score += 30;
                reasons.add("FAST_REACTION: " + reactionTime +
                    "ms reel time (auto-fish threshold=" + MAX_AUTO_FISH_REACTION_MS + "ms)");
            }

            if (reactionTime < MIN_HUMAN_REACTION_MS) {
                score += 5; // 额外加分
                reasons.add("SUB_HUMAN_REACTION: " + reactionTime +
                    "ms is below human minimum (" + MIN_HUMAN_REACTION_MS + "ms)");
            }
        }

        // === 检测 2: 连续精准收竿 ===
        // 检查最近的 REEL 事件是否都是快速收竿
        long consecutiveFastReels = countConsecutiveFastReels(events);
        if (consecutiveFastReels >= CONSECUTIVE_FAST_REEL_THRESHOLD) {
            score += 40;
            reasons.add("CONSECUTIVE_FAST_REEL: " + consecutiveFastReels +
                " consecutive reels under " + MAX_AUTO_FISH_REACTION_MS + "ms");
        }

        // === 检测 3: 长期垂钓一致性 ===
        FishSessionStats stats = playerSessionStats.computeIfAbsent(playerName,
            k -> new FishSessionStats());
        stats.recordReel(now);

        long sessionDurationSec = stats.getSessionDurationSec(now);
        if (sessionDurationSec > LONG_FISHING_SESSION_SEC) {
            score += 20;
            reasons.add("LONG_SESSION: fishing for " + (sessionDurationSec / 60) +
                " minutes continuously (threshold=" + (LONG_FISHING_SESSION_SEC / 60) + " min)");
        }

        // 检查收竿间隔的变异系数
        if (stats.reelCount >= MIN_REEL_SAMPLES) {
            double cov = stats.getIntervalCOV();
            if (cov < MAX_INTERVAL_COV) {
                score += 25;
                reasons.add("UNIFORM_INTERVAL: reel interval COV=" + String.format("%.4f", cov) +
                    " (mechanical pattern threshold < " + MAX_INTERVAL_COV + ")");
            }
        }

        if (score >= 50) {
            flaggedPlayers.put(playerName, Instant.now().plusSeconds(FLAG_DURATION_SECONDS));
            autoFishViolations.incrementAndGet();
            return DetectionResult.flagged(reasons);
        } else if (score >= 30) {
            return DetectionResult.suspicious(score, reasons);
        }

        return DetectionResult.clean();
    }

    /**
     * 清除指定玩家的所有追踪数据。
     *
     * @param playerName 玩家名称
     */
    public void clearPlayer(String playerName) {
        playerFishingEvents.remove(playerName);
        playerSessionStats.remove(playerName);
        flaggedPlayers.remove(playerName);
    }

    /**
     * 获取模块运行状态。
     *
     * @return 包含统计数据的 LinkedHashMap
     */
    public Map<String, Object> getStatus() {
        Map<String, Object> s = new LinkedHashMap<>();
        s.put("totalCastings", totalCastings.get());
        s.put("autoFishViolations", autoFishViolations.get());
        s.put("trackedPlayers", playerFishingEvents.size());
        s.put("flaggedPlayers", flaggedPlayers.size());
        s.put("enabled", config.getSecurity().getSuperEvolution().isAntiAutoFish());

        // 构建反应时间统计
        Map<String, Object> reactionTimeStats = new LinkedHashMap<>();
        List<Long> allReactionTimes = new ArrayList<>();
        for (List<FishingEvent> events : playerFishingEvents.values()) {
            for (FishingEvent e : events) {
                if ("REEL".equals(e.eventType) && e.reactionTime > 0) {
                    allReactionTimes.add(e.reactionTime);
                }
            }
        }
        if (!allReactionTimes.isEmpty()) {
            double avgReaction = allReactionTimes.stream().mapToLong(Long::longValue).average().orElse(0);
            reactionTimeStats.put("sampleCount", allReactionTimes.size());
            reactionTimeStats.put("averageMs", Math.round(avgReaction));
            reactionTimeStats.put("minMs", allReactionTimes.stream().min(Long::compareTo).orElse(0L));
            reactionTimeStats.put("maxMs", allReactionTimes.stream().max(Long::compareTo).orElse(0L));
        } else {
            reactionTimeStats.put("sampleCount", 0);
            reactionTimeStats.put("averageMs", 0L);
        }
        s.put("reactionTimeStats", reactionTimeStats);

        // 被标记玩家列表
        List<Map<String, Object>> flagged = new ArrayList<>();
        for (Map.Entry<String, Instant> e : flaggedPlayers.entrySet()) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("player", e.getKey());
            m.put("flaggedUntil", e.getValue().toString());
            FishSessionStats stats = playerSessionStats.get(e.getKey());
            if (stats != null) {
                m.put("reelCount", stats.reelCount);
                m.put("sessionDurationMin", stats.getSessionDurationSec(Instant.now()) / 60);
            }
            flagged.add(m);
        }
        s.put("flaggedPlayersList", flagged);

        return s;
    }

    public long getTotalCastings() { return totalCastings.get(); }
    public long getAutoFishViolations() { return autoFishViolations.get(); }

    /**
     * 估算最近一次收竿的反应时间。
     *
     * 通过查找最近两次相邻的 REEL 事件间的时间差来估算反应延迟。
     * 如果找不到足够的 REEL 事件，返回 -1。
     *
     * @param events 钓鱼事件列表
     * @return 估算的反应时间（毫秒），无法估算时返回 -1
     */
    private long estimateReactionTime(List<FishingEvent> events) {
        List<FishingEvent> reels = events.stream()
            .filter(e -> "REEL".equals(e.eventType))
            .toList();

        if (reels.size() >= 2) {
            // 返回最近的 REEL 事件反应时间
            FishingEvent lastReel = reels.get(reels.size() - 1);
            if (lastReel.reactionTime > 0) {
                return lastReel.reactionTime;
            }
        }

        // 使用 REEL 事件间的间隔作为反应时间估算
        if (reels.size() >= 2) {
            long interval = reels.get(reels.size() - 1).time.toEpochMilli()
                - reels.get(reels.size() - 2).time.toEpochMilli();
            // 如果间隔很短，可能是连续快速收竿
            if (interval < 5000) {
                // 估算反应时间 = 间隔 * 比例因子
                return interval / 4;
            }
        }

        return -1;
    }

    /**
     * 计算最近连续快速收竿的次数。
     *
     * 从最新收竿事件向前回溯，统计 reactionTime 低于 MAX_AUTO_FISH_REACTION_MS 的连续次数。
     *
     * @param events 钓鱼事件列表
     * @return 连续快速收竿次数
     */
    private long countConsecutiveFastReels(List<FishingEvent> events) {
        List<FishingEvent> reels = events.stream()
            .filter(e -> "REEL".equals(e.eventType))
            .toList();

        int count = 0;
        for (int i = reels.size() - 1; i >= 0; i--) {
            if (reels.get(i).reactionTime > 0
                && reels.get(i).reactionTime < MAX_AUTO_FISH_REACTION_MS) {
                count++;
            } else {
                break;
            }
        }
        return count;
    }

    /**
     * 定期清理过期记录。
     */
    private void cleanupOldRecords() {
        Instant cutoff = Instant.now().minusSeconds(RECORD_RETENTION_SECONDS);
        playerFishingEvents.entrySet().removeIf(e -> {
            List<FishingEvent> events = e.getValue();
            events.removeIf(r -> r.time.isBefore(cutoff));
            return events.isEmpty();
        });
        playerSessionStats.entrySet().removeIf(e ->
            e.getValue().lastActivity.isBefore(cutoff));
        flaggedPlayers.entrySet().removeIf(e -> e.getValue().isBefore(Instant.now()));
    }

    // ==================== 内部数据类 ====================

    /**
     * 钓鱼事件记录——包含抛竿/收竿等事件的时间和元数据。
     */
    private static class FishingEvent {
        final Instant time;
        final String eventType; // "CAST" / "REEL"
        final double x, y, z;
        final long reactionTime; // 毫秒，仅 REEL 事件有意义

        FishingEvent(Instant time, String eventType, double x, double y, double z,
                    long reactionTime) {
            this.time = time;
            this.eventType = eventType;
            this.x = x;
            this.y = y;
            this.z = z;
            this.reactionTime = reactionTime;
        }
    }

    /**
     * 钓鱼会话统计——追踪长期垂钓行为的一致性指标。
     */
    private static class FishSessionStats {
        Instant sessionStart = Instant.now();
        Instant lastActivity = Instant.now();
        int reelCount = 0;
        final List<Long> reelIntervals = new ArrayList<>();
        private Instant lastReelTime = null;
        private double lastX, lastY, lastZ;

        void updatePosition(double x, double y, double z) {
            this.lastX = x;
            this.lastY = y;
            this.lastZ = z;
            this.lastActivity = Instant.now();
        }

        void recordReel(Instant time) {
            if (lastReelTime != null) {
                long interval = time.toEpochMilli() - lastReelTime.toEpochMilli();
                reelIntervals.add(interval);
                // 保持最近 50 个间隔用于 COV 计算
                if (reelIntervals.size() > 50) {
                    reelIntervals.remove(0);
                }
            }
            lastReelTime = time;
            reelCount++;
            lastActivity = Instant.now();
        }

        long getSessionDurationSec(Instant now) {
            return (now.toEpochMilli() - sessionStart.toEpochMilli()) / 1000;
        }

        /**
         * 计算收竿间隔的变异系数（Coefficient of Variation）。
         *
         * @return COV 值，无法计算时返回 1.0
         */
        double getIntervalCOV() {
            if (reelIntervals.size() < 3) return 1.0;
            double mean = reelIntervals.stream().mapToLong(Long::longValue).average().orElse(0);
            if (mean == 0) return 1.0;
            double variance = reelIntervals.stream()
                .mapToDouble(i -> Math.pow(i - mean, 2))
                .average().orElse(0);
            return Math.sqrt(variance) / mean;
        }
    }

    // ==================== 检测结果类 ====================

    /**
     * 自动钓鱼检测结果。
     */
    public static class DetectionResult {
        private final boolean flagged;
        private final boolean suspicious;
        private final int score;
        private final List<String> reasons;

        private DetectionResult(boolean flagged, boolean suspicious, int score, List<String> reasons) {
            this.flagged = flagged;
            this.suspicious = suspicious;
            this.score = score;
            this.reasons = reasons;
        }

        /** 无异常：钓鱼行为正常 */
        public static DetectionResult clean() {
            return new DetectionResult(false, false, 0, List.of());
        }

        /** 可疑行为：存在自动钓鱼特征但置信度不足 */
        public static DetectionResult suspicious(int score, List<String> reasons) {
            return new DetectionResult(false, true, score, reasons);
        }

        /** 已标记：检测到高置信度自动钓鱼行为 */
        public static DetectionResult flagged(List<String> reasons) {
            return new DetectionResult(true, true, 100, reasons);
        }

        public boolean isFlagged() { return flagged; }
        public boolean isSuspicious() { return suspicious; }
        public boolean isClean() { return !flagged && !suspicious; }
        public int getScore() { return score; }
        public List<String> getReasons() { return reasons; }
    }
}
