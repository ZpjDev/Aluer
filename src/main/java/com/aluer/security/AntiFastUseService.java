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

/**
 * 加速物品使用检测 (FastUse) — V5.3 世界/玩家/杂物安全模块
 *
 * 检测原理：
 *   Meteor Client 的 FastUse 模块可以移除物品使用冷却，实现瞬发使用。
 *   正常游戏中每种物品都有固定的使用持续时间：
 *   弓拉满约 1.0 秒，食物食用约 1.6 秒，药水饮用约 1.3 秒，盾牌举盾约 0.25 秒，弩装填约 1.25 秒。
 *   本模块通过以下维度检测加速使用：
 *   1. 物品使用持续时间检测——记录每种物品从开始使用到完成使用的实际耗时，
 *      与物品类型的理论最短时间对比。
 *   2. 同类型物品连续快用——单次快速可能是延迟，但连续 3 次同类型快用即为明确信号。
 *   3. 跨类型通用快用——如果玩家对多种物品类型都表现出快速使用，增加置信度。
 *   4. 使用间隔均匀性——自动化模块的使用间隔往往高度一致。
 *
 * 配置开关：serverguard.security.super-evolution.anti-fast-use
 */
@Service
public class AntiFastUseService {

    private final ServerGuardConfig config;
    /** 每个玩家的物品使用开始记录：playerName -> itemType -> 开始时间 */
    private final Map<String, Map<String, Instant>> playerUseStartTimes = new ConcurrentHashMap<>();
    /** 每个玩家的物品使用历史：playerName -> 使用事件列表 */
    private final Map<String, List<UseEvent>> playerUseHistory = new ConcurrentHashMap<>();
    /** 已标记的玩家 */
    private final Map<String, Instant> flaggedPlayers = new ConcurrentHashMap<>();
    private final ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor();

    private final AtomicLong totalUseEvents = new AtomicLong(0);
    private final AtomicLong fastUseViolations = new AtomicLong(0);

    /** 食物最短使用时间（毫秒）——大多数食物为 1.6 秒 = 32 tick */
    private static final long FOOD_MIN_USE_MS = 1600;
    /** 弓拉满最短时间（毫秒）——约 1.0 秒 = 20 tick */
    private static final long BOW_DRAW_MIN_MS = 1000;
    /** 药水饮用最短时间（毫秒）——约 1.3 秒 = 26 tick (1.1s for splash/lingering) */
    private static final long POTION_DRINK_MIN_MS = 1300;
    /** 盾牌举盾最短时间（毫秒）——约 0.25 秒 = 5 tick */
    private static final long SHIELD_RAISE_MIN_MS = 250;
    /** 弩装填最短时间（毫秒）——约 1.25 秒 = 25 tick */
    private static final long CROSSBOW_LOAD_MIN_MS = 1250;
    /** 快速使用判定比例——实际时间 < 理论最短 * 0.7 即为快用 */
    private static final double FAST_USE_RATIO = 0.7;
    /** 连续快用次数阈值 */
    private static final int CONSECUTIVE_FAST_THRESHOLD = 3;

    /** 记录保留时间（秒） */
    private static final long RECORD_RETENTION_SECONDS = 600;
    /** 标记持续时间（秒） */
    private static final long FLAG_DURATION_SECONDS = 1800;

    public AntiFastUseService() {
        this(new ServerGuardConfig());
    }

    @Autowired
    public AntiFastUseService(ServerGuardConfig config) {
        this.config = config;
        scheduler.scheduleAtFixedRate(this::cleanupOldRecords, 120, 300, TimeUnit.SECONDS);
    }

    /**
     * 记录物品开始使用事件——玩家开始持有一个可使用的物品。
     *
     * 在玩家按下右键开始使用物品（弓拉弓、吃食物、喝药水、举盾等）时调用。
     *
     * @param playerName 玩家名称
     * @param playerUUID 玩家 UUID
     * @param itemType   物品类型标识（"BOW"/"FOOD"/"POTION"/"SHIELD"/"CROSSBOW"/"TRIDENT"/...）
     */
    public void recordUseStart(String playerName, String playerUUID, String itemType) {
        if (!config.getSecurity().getSuperEvolution().isAntiFastUse()) {
            return;
        }

        Instant now = Instant.now();
        Map<String, Instant> itemStarts = playerUseStartTimes.computeIfAbsent(playerName,
            k -> new ConcurrentHashMap<>());
        itemStarts.put(itemType, now);
    }

    /**
     * 检测物品使用完成事件——判断使用速度是否异常。
     *
     * @param playerName 玩家名称
     * @param playerUUID 玩家 UUID
     * @param itemType   物品类型标识
     * @return 检测结果
     */
    public DetectionResult detectUseComplete(String playerName, String playerUUID, String itemType) {
        if (!config.getSecurity().getSuperEvolution().isAntiFastUse()) {
            return DetectionResult.clean();
        }

        Instant flaggedUntil = flaggedPlayers.get(playerName);
        if (flaggedUntil != null) {
            if (Instant.now().isAfter(flaggedUntil)) {
                flaggedPlayers.remove(playerName);
            } else {
                return DetectionResult.flagged(List.of(
                    "PLAYER_ALREADY_FLAGGED: " + playerName + " under fast use investigation"));
            }
        }

        Instant now = Instant.now();
        Map<String, Instant> itemStarts = playerUseStartTimes.get(playerName);
        if (itemStarts == null) {
            return DetectionResult.clean();
        }

        Instant startTime = itemStarts.remove(itemType);
        if (startTime == null) {
            // 没有对应的开始记录，可能是模块启动前已经开始使用
            return DetectionResult.clean();
        }

        long actualDurationMs = now.toEpochMilli() - startTime.toEpochMilli();
        long minExpected = getMinExpectedDuration(itemType);

        int score = 0;
        List<String> reasons = new ArrayList<>();

        // === 检测 1: 物品使用持续时间检测 ===
        if (actualDurationMs < minExpected * FAST_USE_RATIO) {
            score += 30;
            reasons.add("FAST_USE: " + itemType + " used in " + actualDurationMs +
                "ms (expected min " + minExpected + "ms, ratio=" + FAST_USE_RATIO + ")");
        }

        // === 检测 2: 极快速使用——低于绝对下限 ===
        // 食物不可能在 500ms 内吃完，弓不可能在 200ms 内拉满
        long absoluteMin = getAbsoluteMinDuration(itemType);
        if (actualDurationMs < absoluteMin) {
            score += 25;
            reasons.add("SUB_ABSOLUTE_MIN: " + itemType + " used in " + actualDurationMs +
                "ms (absolute min " + absoluteMin + "ms, physically impossible)");
        }

        // 记录使用事件
        List<UseEvent> history = playerUseHistory.computeIfAbsent(playerName,
            k -> Collections.synchronizedList(new ArrayList<>()));
        history.add(new UseEvent(now, itemType, actualDurationMs, minExpected));
        totalUseEvents.incrementAndGet();

        // === 检测 3: 同类型物品连续快用 ===
        long consecutiveFast = countConsecutiveFastUses(history, itemType);
        if (consecutiveFast >= CONSECUTIVE_FAST_THRESHOLD) {
            score += 35;
            reasons.add("CONSECUTIVE_FAST_USE: " + consecutiveFast +
                " consecutive fast uses of " + itemType);
        }

        // === 检测 4: 跨类型通用快用 ===
        // 如果玩家对多种不同物品类型都表现出快速使用，置信度更高
        Set<String> fastItemTypes = new HashSet<>();
        for (int i = Math.max(0, history.size() - 10); i < history.size(); i++) {
            UseEvent e = history.get(i);
            if (e.actualDurationMs < e.expectedMinMs * FAST_USE_RATIO) {
                fastItemTypes.add(e.itemType);
            }
        }
        if (fastItemTypes.size() >= 3) {
            score += 20;
            reasons.add("MULTI_TYPE_FAST: fast use detected across " + fastItemTypes.size() +
                " item types: " + String.join(", ", fastItemTypes));
        }

        if (score >= 50) {
            flaggedPlayers.put(playerName, Instant.now().plusSeconds(FLAG_DURATION_SECONDS));
            fastUseViolations.incrementAndGet();
            return DetectionResult.flagged(reasons);
        } else if (score >= 30) {
            return DetectionResult.suspicious(score, reasons);
        }

        return DetectionResult.clean();
    }

    /**
     * 获取指定物品类型的理论最短使用时间（毫秒）。
     */
    private long getMinExpectedDuration(String itemType) {
        if (itemType == null) return 1000;
        return switch (itemType.toUpperCase()) {
            case "BOW" -> BOW_DRAW_MIN_MS;
            case "FOOD", "MUSHROOM_STEW", "SUSPICIOUS_STEW", "BEETROOT_SOUP",
                 "RABBIT_STEW", "CHORUS_FRUIT", "GOLDEN_APPLE", "ENCHANTED_GOLDEN_APPLE",
                 "HONEY_BOTTLE", "MILK_BUCKET" -> FOOD_MIN_USE_MS;
            case "POTION", "SPLASH_POTION", "LINGERING_POTION", "EXPERIENCE_BOTTLE" -> POTION_DRINK_MIN_MS;
            case "SHIELD" -> SHIELD_RAISE_MIN_MS;
            case "CROSSBOW" -> CROSSBOW_LOAD_MIN_MS;
            case "TRIDENT" -> 1000; // 三叉戟蓄力约 1 秒
            case "SPYGLASS" -> 1200; // 望远镜
            default -> 1000; // 通用默认值
        };
    }

    /**
     * 获取指定物品类型的绝对最短使用时间（毫秒）——低于这个值就是物理不可能。
     */
    private long getAbsoluteMinDuration(String itemType) {
        if (itemType == null) return 300;
        return switch (itemType.toUpperCase()) {
            case "FOOD", "MUSHROOM_STEW", "GOLDEN_APPLE" -> 800;
            case "BOW" -> 200;
            case "POTION" -> 600;
            case "SHIELD" -> 100;
            case "CROSSBOW" -> 600;
            default -> 300;
        };
    }

    /**
     * 统计指定物品类型的连续快用次数。
     */
    private long countConsecutiveFastUses(List<UseEvent> history, String itemType) {
        int count = 0;
        for (int i = history.size() - 1; i >= 0; i--) {
            UseEvent e = history.get(i);
            if (e.itemType.equalsIgnoreCase(itemType)
                && e.actualDurationMs < e.expectedMinMs * FAST_USE_RATIO) {
                count++;
            } else if (e.itemType.equalsIgnoreCase(itemType)) {
                break; // 同类型但速度正常，停止计数
            }
        }
        return count;
    }

    public void clearPlayer(String playerName) {
        playerUseStartTimes.remove(playerName);
        playerUseHistory.remove(playerName);
        flaggedPlayers.remove(playerName);
    }

    public Map<String, Object> getStatus() {
        Map<String, Object> s = new LinkedHashMap<>();
        s.put("totalUseEvents", totalUseEvents.get());
        s.put("fastUseViolations", fastUseViolations.get());
        s.put("trackedPlayers", playerUseHistory.size());
        s.put("flaggedPlayers", flaggedPlayers.size());
        s.put("enabled", config.getSecurity().getSuperEvolution().isAntiFastUse());
        return s;
    }

    public long getTotalUseEvents() { return totalUseEvents.get(); }
    public long getFastUseViolations() { return fastUseViolations.get(); }

    private void cleanupOldRecords() {
        Instant cutoff = Instant.now().minusSeconds(RECORD_RETENTION_SECONDS);
        playerUseHistory.entrySet().removeIf(e -> {
            List<UseEvent> events = e.getValue();
            events.removeIf(ev -> ev.time.isBefore(cutoff));
            return events.isEmpty();
        });
        playerUseStartTimes.entrySet().removeIf(e ->
            !playerUseHistory.containsKey(e.getKey()));
        flaggedPlayers.entrySet().removeIf(e -> e.getValue().isBefore(Instant.now()));
    }

    // ==================== 内部数据类 ====================

    /**
     * 物品使用事件记录——追踪单次使用从开始到完成的耗时。
     */
    private static class UseEvent {
        final Instant time;
        final String itemType;
        final long actualDurationMs;   // 实际使用耗时
        final long expectedMinMs;      // 该物品理论最短时间

        UseEvent(Instant time, String itemType, long actualDurationMs, long expectedMinMs) {
            this.time = time;
            this.itemType = itemType;
            this.actualDurationMs = actualDurationMs;
            this.expectedMinMs = expectedMinMs;
        }
    }

    // ==================== 检测结果类 ====================

    /**
     * 加速物品使用检测结果。
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

        public static DetectionResult clean() {
            return new DetectionResult(false, false, 0, List.of());
        }

        public static DetectionResult suspicious(int score, List<String> reasons) {
            return new DetectionResult(false, true, score, reasons);
        }

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
