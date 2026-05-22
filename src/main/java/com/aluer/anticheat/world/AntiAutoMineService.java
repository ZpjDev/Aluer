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
 * 自动挖矿检测 (AutoMine) — V5.3 世界/玩家/杂物安全模块
 *
 * 检测原理：
 *   Meteor Client 的 AutoMine 模块能自动挖掘玩家视野中或预设类型的方块，无需人工瞄准。
 *   正常人类挖矿具有明显的非均匀特征：反应延迟可变、方块间切换有停顿、瞄准有微调。
 *   而 AutoMine 表现出的行为模式是高度一致的机器人特征。本模块通过以下维度检测：
 *   1. 挖掘间隔一致性——人类挖掘间隔有自然随机波动（变异系数通常 > 0.25），
 *      机器人挖掘间隔高度一致（变异系数 < 0.12）。
 *   2. 零遗漏检测——人类会偶尔打空或错过目标方块，AutoMine 每次都精准命中。
 *      如果一个玩家挖了 20+ 方块却没有一次空挥，即为可疑。
 *   3. 视线微调检测——人类在切换挖掘目标时会有小幅度的视角调整，
 *      机器人直接跳转到目标方块，没有中间过渡。
 *   4. 长时间连续挖掘——正常玩家每隔数分钟会移动、拾取物品或暂停，
 *      AutoMine 可以连续挖矿数十分钟不中断。
 *
 * 配置开关：serverguard.security.super-evolution.anti-auto-mine
 */
@Service
public class AntiAutoMineService {

    private final ServerGuardConfig config;
    /** 每个玩家的挖掘记录 */
    private final Map<String, List<MineRecord>> playerMineRecords = new ConcurrentHashMap<>();
    /** 每个玩家的空挥计数（swing without breaking） */
    private final Map<String, AtomicLong> playerMissedSwings = new ConcurrentHashMap<>();
    /** 已标记的玩家 */
    private final Map<String, Instant> flaggedPlayers = new ConcurrentHashMap<>();
    private final ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor();

    private final AtomicLong totalMineEvents = new AtomicLong(0);
    private final AtomicLong autoMineViolations = new AtomicLong(0);

    /** 挖掘间隔变异系数阈值——低于此值为机器人特征 */
    private static final double INTERVAL_COV_THRESHOLD = 0.12;
    /** 最少样本数用于变异系数分析 */
    private static final int MIN_SAMPLES_FOR_COV = 10;
    /** 零遗漏判定——超过此数量连续命中无空挥即为可疑 */
    private static final int PERFECT_STREAK_THRESHOLD = 20;
    /** 视线切换角度阈值（度）——人类在切换方块间会有微调 */
    private static final double LOOK_MICRO_ADJUST_THRESHOLD = 1.5;
    /** 长时间连续挖掘阈值（分钟） */
    private static final long LONG_MINING_MINUTES = 15;

    /** 记录保留时间（秒） */
    private static final long RECORD_RETENTION_SECONDS = 900;
    /** 标记持续时间（秒） */
    private static final long FLAG_DURATION_SECONDS = 1800;

    public AntiAutoMineService() {
        this(new ServerGuardConfig());
    }

    @Autowired
    public AntiAutoMineService(ServerGuardConfig config) {
        this.config = config;
        scheduler.scheduleAtFixedRate(this::cleanupOldRecords, 120, 300, TimeUnit.SECONDS);
    }

    /**
     * 记录一次挥动事件（无论是否命中方块）。
     *
     * @param playerName 玩家名称
     * @param playerUUID 玩家 UUID
     * @param lookYaw    玩家当前水平视角
     * @param lookPitch  玩家当前垂直视角
     */
    public void recordSwing(String playerName, String playerUUID, float lookYaw, float lookPitch) {
        if (!config.getSecurity().getSuperEvolution().isAntiAutoMine()) {
            return;
        }
        AtomicLong missed = playerMissedSwings.computeIfAbsent(playerName,
            k -> new AtomicLong(0));
        missed.incrementAndGet();
    }

    /**
     * 检测一次方块破坏完成事件——与上一次破坏进行对比分析。
     *
     * @param playerName 玩家名称
     * @param playerUUID 玩家 UUID
     * @param blockType  被破坏的方块类型
     * @param x          方块 X 坐标
     * @param y          方块 Y 坐标
     * @param z          方块 Z 坐标
     * @param lookYaw    完成破坏时的水平视角
     * @param lookPitch  完成破坏时的垂直视角
     * @return 检测结果
     */
    public DetectionResult detectBlockBreak(String playerName, String playerUUID,
                                              String blockType, int x, int y, int z,
                                              float lookYaw, float lookPitch) {
        if (!config.getSecurity().getSuperEvolution().isAntiAutoMine()) {
            return DetectionResult.clean();
        }

        Instant flaggedUntil = flaggedPlayers.get(playerName);
        if (flaggedUntil != null) {
            if (Instant.now().isAfter(flaggedUntil)) {
                flaggedPlayers.remove(playerName);
            } else {
                return DetectionResult.flagged(List.of(
                    "PLAYER_ALREADY_FLAGGED: " + playerName + " under auto-mine investigation"));
            }
        }

        Instant now = Instant.now();
        List<MineRecord> records = playerMineRecords.computeIfAbsent(playerName,
            k -> Collections.synchronizedList(new ArrayList<>()));
        // 获取本次破坏前一次挥动的空挥状态
        AtomicLong missed = playerMissedSwings.computeIfAbsent(playerName,
            k -> new AtomicLong(0));
        boolean hadMissBefore = missed.get() > 0;
        long missedCount = missed.getAndSet(0); // 重置空挥计数器

        MineRecord record = new MineRecord(now, blockType, x, y, z, lookYaw, lookPitch,
            missedCount == 0);
        records.add(record);
        totalMineEvents.incrementAndGet();

        int score = 0;
        List<String> reasons = new ArrayList<>();

        // === 检测 1: 挖掘间隔一致性 ===
        if (records.size() >= MIN_SAMPLES_FOR_COV) {
            double cov = calculateIntervalCOV(records);
            if (cov < INTERVAL_COV_THRESHOLD) {
                score += 30;
                reasons.add("UNIFORM_INTERVAL: break interval COV=" + String.format("%.4f", cov) +
                    " (bot-like consistency, threshold < " + INTERVAL_COV_THRESHOLD + ")");
            }
        }

        // === 检测 2: 零遗漏检测（完美连续命中） ===
        // 计算连续完美命中（无空挥）的次数
        long perfectStreak = countPerfectStreak(records);
        if (perfectStreak >= PERFECT_STREAK_THRESHOLD) {
            score += 35;
            reasons.add("PERFECT_STREAK: " + perfectStreak +
                " consecutive blocks broken without a single missed swing (bot-like precision)");
        }

        // === 检测 3: 视线微调缺失检测 ===
        // 检查最近两次破坏间的视角变化
        if (records.size() >= 2) {
            MineRecord prev = records.get(records.size() - 2);
            double yawDiff = Math.abs(record.lookYaw - prev.lookYaw);
            double pitchDiff = Math.abs(record.lookPitch - prev.lookPitch);
            // 如果切换了方块但视角几乎没变，说明不是手动瞄准
            boolean sameBlock = (prev.x == x && prev.y == y && prev.z == z);
            if (!sameBlock && yawDiff < LOOK_MICRO_ADJUST_THRESHOLD && pitchDiff < LOOK_MICRO_ADJUST_THRESHOLD) {
                // 切换方块但视角无微调，可疑（累积检测）
            }
            // 检测大量无微调的方块切换
            if (records.size() >= 10) {
                long noAdjustSwitches = countNoAdjustSwitches(records);
                if (noAdjustSwitches >= 8) {
                    score += 20;
                    reasons.add("NO_LOOK_ADJUST: " + noAdjustSwitches +
                        " block switches with no visible micro-adjustment (auto-targeting)");
                }
            }
        }

        // === 检测 4: 长时间连续挖掘 ===
        if (records.size() >= 2) {
            long sessionMs = now.toEpochMilli() - records.get(0).time.toEpochMilli();
            long sessionMinutes = sessionMs / 60000;
            if (sessionMinutes > LONG_MINING_MINUTES) {
                score += 20;
                reasons.add("LONG_SESSION: continuously mining for " + sessionMinutes +
                    " minutes without break (threshold=" + LONG_MINING_MINUTES + " min)");
            }
        }

        if (score >= 50) {
            flaggedPlayers.put(playerName, Instant.now().plusSeconds(FLAG_DURATION_SECONDS));
            autoMineViolations.incrementAndGet();
            return DetectionResult.flagged(reasons);
        } else if (score >= 30) {
            return DetectionResult.suspicious(score, reasons);
        }

        return DetectionResult.clean();
    }

    /**
     * 计算挖掘间隔的变异系数（COV）。
     */
    private double calculateIntervalCOV(List<MineRecord> records) {
        List<Long> intervals = new ArrayList<>();
        int start = Math.max(0, records.size() - 20);
        for (int i = start + 1; i < records.size(); i++) {
            intervals.add(records.get(i).time.toEpochMilli() - records.get(i - 1).time.toEpochMilli());
        }
        if (intervals.size() < 5) return 1.0;
        double mean = intervals.stream().mapToLong(Long::longValue).average().orElse(0);
        if (mean == 0) return 1.0;
        double variance = intervals.stream()
            .mapToDouble(i -> Math.pow(i - mean, 2))
            .average().orElse(0);
        return Math.sqrt(variance) / mean;
    }

    /**
     * 统计连续完美命中（无空挥）的次数。
     */
    private long countPerfectStreak(List<MineRecord> records) {
        int streak = 0;
        for (int i = records.size() - 1; i >= 0; i--) {
            if (records.get(i).wasPerfectHit) {
                streak++;
            } else {
                break;
            }
        }
        return streak;
    }

    /**
     * 统计最近方块切换中无视差微调的次数。
     */
    private long countNoAdjustSwitches(List<MineRecord> records) {
        int count = 0;
        int start = Math.max(0, records.size() - 10);
        for (int i = start + 1; i < records.size(); i++) {
            MineRecord prev = records.get(i - 1);
            MineRecord curr = records.get(i);
            boolean sameBlock = (prev.x == curr.x && prev.y == curr.y && prev.z == curr.z);
            if (!sameBlock) {
                double yawDiff = Math.abs(curr.lookYaw - prev.lookYaw);
                double pitchDiff = Math.abs(curr.lookPitch - prev.lookPitch);
                if (yawDiff < LOOK_MICRO_ADJUST_THRESHOLD && pitchDiff < LOOK_MICRO_ADJUST_THRESHOLD) {
                    count++;
                }
            }
        }
        return count;
    }

    public void clearPlayer(String playerName) {
        playerMineRecords.remove(playerName);
        playerMissedSwings.remove(playerName);
        flaggedPlayers.remove(playerName);
    }

    public Map<String, Object> getStatus() {
        Map<String, Object> s = new LinkedHashMap<>();
        s.put("totalMineEvents", totalMineEvents.get());
        s.put("autoMineViolations", autoMineViolations.get());
        s.put("trackedPlayers", playerMineRecords.size());
        s.put("flaggedPlayers", flaggedPlayers.size());
        s.put("enabled", config.getSecurity().getSuperEvolution().isAntiAutoMine());
        return s;
    }

    public long getTotalMineEvents() { return totalMineEvents.get(); }
    public long getAutoMineViolations() { return autoMineViolations.get(); }

    private void cleanupOldRecords() {
        Instant cutoff = Instant.now().minusSeconds(RECORD_RETENTION_SECONDS);
        playerMineRecords.entrySet().removeIf(e -> {
            List<MineRecord> records = e.getValue();
            records.removeIf(r -> r.time.isBefore(cutoff));
            return records.isEmpty();
        });
        playerMissedSwings.entrySet().removeIf(e ->
            !playerMineRecords.containsKey(e.getKey()));
        flaggedPlayers.entrySet().removeIf(e -> e.getValue().isBefore(Instant.now()));
    }

    // ==================== 内部数据类 ====================

    /**
     * 挖掘记录——追踪单次方块破坏的时间、位置和视角信息。
     */
    private static class MineRecord {
        final Instant time;
        final String blockType;
        final int x, y, z;
        final float lookYaw, lookPitch;
        final boolean wasPerfectHit; // 本次破坏前是否没有空挥（完美命中）

        MineRecord(Instant time, String blockType, int x, int y, int z,
                  float lookYaw, float lookPitch, boolean wasPerfectHit) {
            this.time = time;
            this.blockType = blockType;
            this.x = x;
            this.y = y;
            this.z = z;
            this.lookYaw = lookYaw;
            this.lookPitch = lookPitch;
            this.wasPerfectHit = wasPerfectHit;
        }
    }

    // ==================== 检测结果类 ====================

    /**
     * 自动挖矿检测结果。
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
