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
 * 快速破坏检测 (Nuker) — V4.0 玩家行为安全模块
 *
 * 检测原理：
 *   Nuker 是 Minecraft 作弊客户端中最具破坏力的功能之一，它能以极快速度瞬间破坏大范围方块。
 *   本模块通过多维数据分析来识别 Nuker 行为模式：
 *   1. 速度检测——正常生存模式挖掘受工具等级和效率附魔限制，木质工具约0.4秒/块，
 *      钻石镐约0.3秒/块，效率V约0.15秒/块；Nuker 通常能在 50ms 内完成一次破坏。
 *   2. 多目标同时破坏——在同一 tick 内破坏多个方块，这是普通玩家物理上不可能做到的行为，
 *      只有通过发包劫持实现的 Nuker 才能达成。
 *   3. 破坏模式分析——Nuker 通常破坏大范围方块（半径超过3格），正常挖掘通常集中在1-2格半径内。
 *   4. 挖掘时间间隔分布——通过分析连续破坏的时间间隔，检测是否有自动化特征。
 *
 * 配置开关：serverguard.security.super-evolution.anti-nuker
 */
@Service
public class AntiNukerService {

    private final ServerGuardConfig config;
    private final Map<String, List<BreakRecord>> playerBreakRecords = new ConcurrentHashMap<>();
    private final Map<String, List<PositionRecord>> playerPositionRecords = new ConcurrentHashMap<>();
    private final Map<String, Instant> flaggedPlayers = new ConcurrentHashMap<>();
    private final ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor();

    /** 单个玩家的总破坏次数计数器 */
    private final AtomicLong totalBreaks = new AtomicLong(0);
    /** Nuker 违规检测次数 */
    private final AtomicLong nukerViolations = new AtomicLong(0);

    /**
     * 单次检测窗口内允许的最大方块破坏数量（正常玩家采矿时约2-4块/秒）
     */
    private static final int MAX_BREAKS_PER_WINDOW = 3;

    /**
     * 检测时间窗口（毫秒）——在此窗口内破坏超过阙值即为异常
     */
    private static final long DETECTION_WINDOW_MS = 500;

    /**
     * 同 tick 最大允许破坏数量——在同一 50ms tick 内破坏超过此数为多目标同时破坏
     */
    private static final int MAX_SAME_TICK_BREAKS = 1;

    /**
     * 破坏间距离超过此值（块）视为分散破坏模式
     */
    private static final int MAX_BREAK_DISTANCE = 3;

    /**
     * 单个玩家记录保留时间（秒）——过期清理
     */
    private static final long RECORD_RETENTION_SECONDS = 300;

    /**
     * 标记玩家持续时间（秒）
     */
    private static final long FLAG_DURATION_SECONDS = 1800;

    public AntiNukerService() {
        this(new ServerGuardConfig());
    }

    @Autowired
    public AntiNukerService(ServerGuardConfig config) {
        this.config = config;
        // 定期清理过期记录，防止内存泄漏
        scheduler.scheduleAtFixedRate(this::cleanupOldRecords, 60, 120, TimeUnit.SECONDS);
    }

    /**
     * 检测一次方块破坏事件是否为 Nuker 行为。
     *
     * @param playerName 玩家名称
     * @param playerUUID 玩家 UUID
     * @param blockType  被破坏的方块类型
     * @param x          方块 X 坐标
     * @param y          方块 Y 坐标
     * @param z          方块 Z 坐标
     * @param world      所在世界名称
     * @return 检测结果（clean / flagged / suspicious）
     */
    public DetectionResult detect(String playerName, String playerUUID, String blockType,
                                   int x, int y, int z, String world) {
        // 如果配置中禁用了反 Nuker 模块，直接返回 clean
        if (!config.getSecurity().getSuperEvolution().isAntiNuker()) {
            return DetectionResult.clean();
        }

        // 检查玩家是否已被标记
        Instant flaggedUntil = flaggedPlayers.get(playerName);
        if (flaggedUntil != null) {
            if (Instant.now().isAfter(flaggedUntil)) {
                // 标记已过期，移除标记
                flaggedPlayers.remove(playerName);
            } else {
                // 仍在标记期内，直接返回 flagged
                return DetectionResult.flagged(List.of(
                    "PLAYER_ALREADY_FLAGGED: " + playerName + " is under active nuker investigation"));
            }
        }

        // 记录本次破坏事件
        Instant now = Instant.now();
        BreakRecord record = new BreakRecord(now, blockType, x, y, z, world);
        List<BreakRecord> records = playerBreakRecords.computeIfAbsent(playerName,
            k -> Collections.synchronizedList(new ArrayList<>()));
        records.add(record);
        totalBreaks.incrementAndGet();

        // 记录坐标用于分散模式分析
        PositionRecord posRecord = new PositionRecord(now, x, y, z, world);
        List<PositionRecord> posRecords = playerPositionRecords.computeIfAbsent(playerName,
            k -> Collections.synchronizedList(new ArrayList<>()));
        posRecords.add(posRecord);

        int score = 0;
        List<String> reasons = new ArrayList<>();

        // === 检测 1: 速度检测 ===
        // 计算在检测窗口内破坏的方块数量
        long windowStart = now.toEpochMilli() - DETECTION_WINDOW_MS;
        long breaksInWindow = records.stream()
            .filter(r -> r.time.toEpochMilli() > windowStart)
            .count();

        if (breaksInWindow > MAX_BREAKS_PER_WINDOW) {
            score += 35;
            reasons.add("SPEED_VIOLATION: " + breaksInWindow + " blocks broken in " +
                DETECTION_WINDOW_MS + "ms (threshold=" + MAX_BREAKS_PER_WINDOW + ")");
        }

        // === 检测 2: 多目标同时破坏检测 ===
        // 在同一 tick (50ms) 内破坏多个方块，只有 Nuker 能做到
        long tickStart = now.toEpochMilli() - 50;
        long sameTickBreaks = records.stream()
            .filter(r -> r.time.toEpochMilli() > tickStart)
            .count();

        if (sameTickBreaks > MAX_SAME_TICK_BREAKS) {
            score += 50; // 这是最高置信度的检测
            reasons.add("MULTI_TARGET_BREAK: " + sameTickBreaks +
                " blocks broken in same tick (impossible for legit player)");
        }

        // === 检测 3: 分散破坏模式检测 ===
        // Nuker 在大范围内同时破坏，正常玩家挖矿范围小
        if (posRecords.size() >= 5) {
            // 计算最近几个破坏点的空间分散度
            int recentCount = Math.min(posRecords.size(), 5);
            List<PositionRecord> recentPositions = posRecords.subList(
                posRecords.size() - recentCount, posRecords.size());

            // 计算平均距离（使用当前点与之前点的距离）
            double totalDistance = 0;
            int distanceCount = 0;
            for (int i = 1; i < recentPositions.size(); i++) {
                PositionRecord prev = recentPositions.get(i - 1);
                PositionRecord curr = recentPositions.get(i);
                double dist = Math.sqrt(
                    Math.pow(curr.x - prev.x, 2) +
                    Math.pow(curr.y - prev.y, 2) +
                    Math.pow(curr.z - prev.z, 2));
                totalDistance += dist;
                distanceCount++;
            }

            double avgDistance = distanceCount > 0 ? totalDistance / distanceCount : 0;
            if (avgDistance > MAX_BREAK_DISTANCE) {
                score += 20;
                reasons.add("SCATTER_PATTERN: avg break distance=" +
                    String.format("%.1f", avgDistance) + " blocks (threshold=" + MAX_BREAK_DISTANCE + ")");
            }
        }

        // === 检测 4: 破坏间隔分析 ===
        // 分析连续破坏之间的时间间隔是否有自动化特征
        if (records.size() >= 5) {
            List<Long> intervals = new ArrayList<>();
            for (int i = records.size() - 5; i < records.size() - 1; i++) {
                long interval = records.get(i + 1).time.toEpochMilli() - records.get(i).time.toEpochMilli();
                intervals.add(interval);
            }

            // 如果所有间隔都在 100ms 以内，说明是持续的快速破坏
            long fastIntervals = intervals.stream().filter(i -> i < 100).count();
            if (fastIntervals >= 4) {
                score += 15;
                reasons.add("CONSISTENT_FAST_BREAK: " + fastIntervals +
                    "/4 breaks under 100ms interval");
            }
        }

        // === 判定结果 ===
        if (score >= 50) {
            // 高置信度：标记玩家
            flaggedPlayers.put(playerName, Instant.now().plusSeconds(FLAG_DURATION_SECONDS));
            nukerViolations.incrementAndGet();
            return DetectionResult.flagged(reasons);
        } else if (score >= 30) {
            // 中等置信度：报告可疑
            return DetectionResult.suspicious(score, reasons);
        }

        return DetectionResult.clean();
    }

    /**
     * 清除指定玩家的所有追踪数据（玩家退出时调用）。
     *
     * @param playerName 玩家名称
     */
    public void clearPlayer(String playerName) {
        playerBreakRecords.remove(playerName);
        playerPositionRecords.remove(playerName);
        flaggedPlayers.remove(playerName);
    }

    /**
     * 获取当前模块运行状态。
     *
     * @return 包含各类统计数据的 LinkedHashMap
     */
    public Map<String, Object> getStatus() {
        Map<String, Object> s = new LinkedHashMap<>();
        s.put("totalBreaks", totalBreaks.get());
        s.put("nukerViolations", nukerViolations.get());
        s.put("trackedPlayers", playerBreakRecords.size());
        s.put("flaggedPlayers", flaggedPlayers.size());
        s.put("enabled", config.getSecurity().getSuperEvolution().isAntiNuker());

        // 最近被标记的玩家列表
        List<Map<String, Object>> flagged = new ArrayList<>();
        for (Map.Entry<String, Instant> e : flaggedPlayers.entrySet()) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("player", e.getKey());
            m.put("flaggedUntil", e.getValue().toString());
            List<BreakRecord> records = playerBreakRecords.get(e.getKey());
            if (records != null) {
                m.put("totalRecordedBreaks", records.size());
            }
            flagged.add(m);
        }
        s.put("flaggedPlayersList", flagged);

        return s;
    }

    public long getTotalBreaks() { return totalBreaks.get(); }
    public long getNukerViolations() { return nukerViolations.get(); }
    public int getTrackedPlayers() { return playerBreakRecords.size(); }

    /**
     * 定期清理过期记录，防止内存无限增长。
     */
    private void cleanupOldRecords() {
        Instant cutoff = Instant.now().minusSeconds(RECORD_RETENTION_SECONDS);
        playerBreakRecords.entrySet().removeIf(e -> {
            List<BreakRecord> records = e.getValue();
            records.removeIf(r -> r.time.isBefore(cutoff));
            return records.isEmpty();
        });
        playerPositionRecords.entrySet().removeIf(e -> {
            List<PositionRecord> records = e.getValue();
            records.removeIf(r -> r.time.isBefore(cutoff));
            return records.isEmpty();
        });
        flaggedPlayers.entrySet().removeIf(e -> e.getValue().isBefore(Instant.now()));
    }

    // ==================== 内部数据类 ====================

    /**
     * 方块破坏记录——记录单次破坏事件的关键数据。
     */
    private static class BreakRecord {
        final Instant time;
        final String blockType;
        final int x, y, z;
        final String world;

        BreakRecord(Instant time, String blockType, int x, int y, int z, String world) {
            this.time = time;
            this.blockType = blockType;
            this.x = x;
            this.y = y;
            this.z = z;
            this.world = world;
        }
    }

    /**
     * 位置记录——用于分析破坏的空间分布模式。
     */
    private static class PositionRecord {
        final Instant time;
        final int x, y, z;
        final String world;

        PositionRecord(Instant time, int x, int y, int z, String world) {
            this.time = time;
            this.x = x;
            this.y = y;
            this.z = z;
            this.world = world;
        }
    }

    // ==================== 检测结果类 ====================

    /**
     * Nuker 检测结果——包含标记状态、可疑分数和原因列表。
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

        /** 无异常：方块破坏行为正常 */
        public static DetectionResult clean() {
            return new DetectionResult(false, false, 0, List.of());
        }

        /** 可疑行为：存在异常模式但置信度未达到直接标记的阈值 */
        public static DetectionResult suspicious(int score, List<String> reasons) {
            return new DetectionResult(false, true, score, reasons);
        }

        /** 已标记：检测到高置信度 Nuker 行为 */
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
