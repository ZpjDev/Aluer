package com.aluer.anticheat.combat;

import com.aluer.config.ServerGuardConfig;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * 自动包围（Surround）检测服务 — V5.1 反作弊战斗模块
 *
 * 检测原理：
 * 1. 方块放置速度检测 — Meteor Client的Surround模块在极短时间内（<0.5秒）
 *    在玩家脚部周围精确放置4-8个方块。正常玩家放置方块速度为1-2块/秒。
 *    如果玩家在500ms内放置4个以上方块且全部在自身周围1格半径内，则标记。
 * 2. 放置位置模式检测 — Surround hack的方块位置高度模式化：
 *    精确在玩家位置的东/南/西/北四个方向（±1, 0, 0）和（0, 0, ±1）处放置。
 *    如果方块放置位置恰好匹配这四个精确坐标偏移且同步发生，确定是自动化操作。
 * 3. 防御方块类型检测 — Surround hack偏好使用黑曜石、末影箱、重生锚等
 *    爆炸抗性方块。如果玩家在自身周围迅速放置大量这些特定方块，高度可疑。
 * 4. 放置模式协调性检测 — 检测四面同步放置（4个基本方位同时被覆盖）vs 正常玩家
 *    的手动逐一放置模式。自动化包围的放置顺序可能是完美的旋转序列。
 *
 * 配置开关：serverguard.security.super-evolution.anti-surround
 */
@Service
public class AntiSurroundService {

    private final ServerGuardConfig config;

    /**
     * 追踪每个玩家最近放置的方块记录（playerName -> 方块放置记录列表）
     */
    private final Map<String, List<BlockPlaceRecord>> playerPlacementHistory = new ConcurrentHashMap<>();

    /**
     * 追踪每个玩家的连续包围事件计数（playerName -> 包围检测次数统计）
     */
    private final Map<String, SurroundStats> playerSurroundStats = new ConcurrentHashMap<>();

    /**
     * 追踪疑似Surround的事件（playerName -> 可疑事件列表）
     */
    private final Map<String, List<Map<String, Object>>> surroundEvents = new ConcurrentHashMap<>();

    private final AtomicLong totalPlacements = new AtomicLong(0);
    private final AtomicLong flaggedCount = new AtomicLong(0);

    /**
     * 包围方块放置速度检测窗口（毫秒）— 500ms内放置4+块即标记
     */
    private static final long SURROUND_SPEED_WINDOW_MS = 500;

    /**
     * 窗口内最小包围方块数 — 低于此数量不算包围行为
     */
    private static final int MIN_SURROUND_BLOCKS = 4;

    /**
     * 精确方位位置容差（方块坐标）— 放置位置与理论精确方位的偏差容差
     */
    private static final double POSITION_TOLERANCE = 0.01;

    /**
     * 包围半径（方块）— 包围方块相对于玩家的最大距离
     */
    private static final double SURROUND_RADIUS = 1.5;

    /**
     * 密集方块放置窗口（毫秒）— 在此窗口内放置大量方块则标记
     */
    private static final long MASS_PLACEMENT_WINDOW_MS = 2_000;

    /**
     * 密集放置窗口内的异常方块数阈值
     */
    private static final int MASS_PLACEMENT_THRESHOLD = 6;

    /**
     * 每个玩家保留的最大放置记录数
     */
    private static final int MAX_RECORDS = 40;

    /**
     * 最常见的包围用爆炸抗性方块列表
     */
    private static final Set<String> SURROUND_BLOCK_TYPES = Set.of(
            "OBSIDIAN", "CRYING_OBSIDIAN", "ENDER_CHEST",
            "RESPAWN_ANCHOR", "ANCIENT_DEBRIS", "NETHERITE_BLOCK",
            "BEDROCK", "ENCHANTING_TABLE", "ANVIL", "CHIPPED_ANVIL", "DAMAGED_ANVIL"
    );

    /**
     * 无参构造函数 — 测试/默认配置使用
     */
    public AntiSurroundService() {
        this(new ServerGuardConfig());
    }

    /**
     * Spring 注入构造函数
     * @param config 全局配置，提供模块开关控制
     */
    public AntiSurroundService(ServerGuardConfig config) {
        this.config = config;
    }

    /**
     * 检测玩家方块放置行为是否为自动包围
     *
     * @param playerName 玩家名称
     * @param playerUUID 玩家UUID
     * @param blockType 放置的方块类型
     * @param blockX 放置方块X坐标（方块坐标，整数）
     * @param blockY 放置方块Y坐标（方块坐标，整数）
     * @param blockZ 放置方块Z坐标（方块坐标，整数）
     * @param playerX 玩家当前X坐标
     * @param playerZ 玩家当前Z坐标
     * @param playerFeetY 玩家脚部Y坐标
     * @param timestamp 时间戳
     * @return 检测结果
     */
    public SurroundCheckResult detect(String playerName, String playerUUID,
                                       String blockType, int blockX, int blockY, int blockZ,
                                       double playerX, double playerZ, double playerFeetY,
                                       Instant timestamp) {
        // 模块开关检查
        if (!config.getSecurity().getSuperEvolution().isAntiSurround()) {
            return SurroundCheckResult.clean();
        }

        totalPlacements.incrementAndGet();
        List<String> reasons = new ArrayList<>();

        List<BlockPlaceRecord> history = playerPlacementHistory.computeIfAbsent(
                playerName, k -> new ArrayList<>());
        SurroundStats stats = playerSurroundStats.computeIfAbsent(
                playerName, k -> new SurroundStats());

        BlockPlaceRecord record = new BlockPlaceRecord(timestamp, blockType,
                blockX, blockY, blockZ, playerX, playerZ, playerFeetY);
        history.add(record);
        while (history.size() > MAX_RECORDS) {
            history.remove(0);
        }

        // 1. 检测放置的方块是否在玩家自身周围的包围范围内
        double distToPlayer = Math.sqrt(
                Math.pow(blockX + 0.5 - playerX, 2) +
                Math.pow(blockZ + 0.5 - playerZ, 2));

        boolean isNearPlayer = distToPlayer <= SURROUND_RADIUS;
        boolean isFootLevel = Math.abs(blockY - (int) playerFeetY) <= 1;
        boolean isDefensiveBlock = SURROUND_BLOCK_TYPES.contains(blockType.toUpperCase());

        // 仅对玩家周围的防御性方块进行包围检测
        if (!isNearPlayer || !isFootLevel) {
            return SurroundCheckResult.clean();
        }

        if (isDefensiveBlock) {
            stats.defensiveBlockCount++;
        }

        // 2. 放置速度检测 — 在短时间内是否放置了大量方块
        Instant windowStart = timestamp.minusMillis(SURROUND_SPEED_WINDOW_MS);
        long recentNearbyBlocks = history.stream()
                .filter(r -> !r.timestamp.isBefore(windowStart))
                .filter(r -> r.isNearPlayer)
                .count();

        if (recentNearbyBlocks >= MIN_SURROUND_BLOCKS) {
            // 检查放置位置是否形成包围模式（四个基本方位）
            int cardinalDirections = countCardinalDirections(history, windowStart,
                    (int) Math.round(playerX), (int) Math.round(playerFeetY), (int) Math.round(playerZ));

            if (cardinalDirections >= 3) {
                reasons.add("FAST_SURROUND: " + recentNearbyBlocks + " blocks in "
                        + SURROUND_SPEED_WINDOW_MS + "ms covering " + cardinalDirections
                        + " cardinal directions");
            }
        }

        // 3. 精确方位位置检测 — 方块是否在精确的(±1,0,0)和(0,0,±1)位置
        int relX = blockX - (int) Math.round(playerX);
        int relZ = blockZ - (int) Math.round(playerZ);

        boolean isCardinalPlacement = false;
        // 检测四个基本方位：(1,0), (-1,0), (0,1), (0,-1)
        if ((Math.abs(relX) == 1 && relZ == 0) || (relX == 0 && Math.abs(relZ) == 1)) {
            isCardinalPlacement = true;
            stats.cardinalPlacements++;
        }

        // 检测是否为四个角位：(1,1), (1,-1), (-1,1), (-1,-1)
        boolean isCornerPlacement = (Math.abs(relX) == 1 && Math.abs(relZ) == 1);

        if ((isCardinalPlacement || isCornerPlacement) && isDefensiveBlock) {
            stats.surroundPatternCount++;
        }

        // 4. 协调放置模式检测 — 短时间窗口内四面同步覆盖
        if (history.size() >= 4) {
            Instant massWindowStart = timestamp.minusMillis(MASS_PLACEMENT_WINDOW_MS);
            long recentDefensive = history.stream()
                    .filter(r -> !r.timestamp.isBefore(massWindowStart))
                    .filter(r -> r.isDefensive)
                    .count();

            if (recentDefensive >= MASS_PLACEMENT_THRESHOLD && isDefensiveBlock) {
                reasons.add("MASS_DEFENSIVE_PLACEMENT: " + recentDefensive
                        + " defensive blocks in " + (MASS_PLACEMENT_WINDOW_MS / 1000) + "s");
            }
        }

        // 5. 异常包围模式检查 — 如果玩家统计了大量包围模式但缺乏自然变化
        if (stats.cardinalPlacements >= 8 && stats.surroundPatternCount >= 6) {
            double patternRatio = (double) stats.surroundPatternCount / Math.max(1, stats.cardinalPlacements);
            if (patternRatio > 0.7) {
                reasons.add("SURROUND_PATTERN_RATIO: " + String.format("%.0f", patternRatio * 100)
                        + "% of placements match surround pattern ("
                        + stats.surroundPatternCount + "/" + stats.cardinalPlacements + ")");
            }
        }

        // 记录可疑事件
        if (!reasons.isEmpty()) {
            List<Map<String, Object>> events = surroundEvents.computeIfAbsent(
                    playerName, k -> new ArrayList<>());
            Map<String, Object> event = new LinkedHashMap<>();
            event.put("time", timestamp.toString());
            event.put("blockType", blockType);
            event.put("relX", relX);
            event.put("relZ", relZ);
            event.put("reasons", reasons);
            events.add(event);
            while (events.size() > 20) {
                events.remove(0);
            }
        }

        if (reasons.size() >= 2) {
            flaggedCount.incrementAndGet();
            return SurroundCheckResult.flagged(reasons);
        } else if (reasons.size() == 1) {
            return SurroundCheckResult.suspicious(reasons);
        }

        return SurroundCheckResult.clean();
    }

    /**
     * 统计时间窗口内覆盖的基本方位数量（东/南/西/北）
     */
    private int countCardinalDirections(List<BlockPlaceRecord> history,
                                         Instant windowStart, int playerIntX, int playerIntY, int playerIntZ) {
        Set<String> coveredDirections = new HashSet<>();
        for (BlockPlaceRecord r : history) {
            if (r.timestamp.isBefore(windowStart)) continue;
            if (r.blockY != playerIntY) continue;

            int dx = r.blockX - playerIntX;
            int dz = r.blockZ - playerIntZ;

            if (dx == 1 && dz == 0) coveredDirections.add("EAST");
            else if (dx == -1 && dz == 0) coveredDirections.add("WEST");
            else if (dx == 0 && dz == 1) coveredDirections.add("SOUTH");
            else if (dx == 0 && dz == -1) coveredDirections.add("NORTH");
        }
        return coveredDirections.size();
    }

    /**
     * 玩家离线时清理追踪数据
     * @param playerName 离线玩家名称
     */
    public void clearPlayer(String playerName) {
        playerPlacementHistory.remove(playerName);
        playerSurroundStats.remove(playerName);
        surroundEvents.remove(playerName);
    }

    /**
     * 获取模块运行状态
     * @return 包含计数器和活跃追踪玩家数的Map
     */
    public Map<String, Object> getStatus() {
        Map<String, Object> status = new LinkedHashMap<>();
        status.put("totalPlacements", totalPlacements.get());
        status.put("flaggedCount", flaggedCount.get());
        status.put("activeTrackedPlayers", playerPlacementHistory.size());

        // 列出高包围模式玩家
        List<Map<String, Object>> patternPlayers = new ArrayList<>();
        for (Map.Entry<String, SurroundStats> entry : playerSurroundStats.entrySet()) {
            SurroundStats stats = entry.getValue();
            if (stats.surroundPatternCount >= 4) {
                Map<String, Object> info = new LinkedHashMap<>();
                info.put("player", entry.getKey());
                info.put("patternPlacements", stats.surroundPatternCount);
                info.put("cardinalPlacements", stats.cardinalPlacements);
                info.put("defensiveBlocks", stats.defensiveBlockCount);
                patternPlayers.add(info);
            }
        }
        patternPlayers.sort((a, b) ->
                Integer.compare((Integer) b.get("patternPlacements"), (Integer) a.get("patternPlacements")));
        status.put("patternPlayers", patternPlayers);

        return status;
    }

    /**
     * 内部方块放置记录 — 记录单次方块放置的空间和时间信息
     */
    private static class BlockPlaceRecord {
        final Instant timestamp;
        final String blockType;
        final int blockX, blockY, blockZ;
        final double playerX, playerZ, playerFeetY;
        final boolean isNearPlayer;
        final boolean isDefensive;

        BlockPlaceRecord(Instant timestamp, String blockType, int blockX, int blockY, int blockZ,
                        double playerX, double playerZ, double playerFeetY) {
            this.timestamp = timestamp;
            this.blockType = blockType;
            this.blockX = blockX;
            this.blockY = blockY;
            this.blockZ = blockZ;
            this.playerX = playerX;
            this.playerZ = playerZ;
            this.playerFeetY = playerFeetY;
            // 预计算距离和防御类型标志
            double dist = Math.sqrt(Math.pow(blockX + 0.5 - playerX, 2)
                    + Math.pow(blockZ + 0.5 - playerZ, 2));
            this.isNearPlayer = dist <= SURROUND_RADIUS;
            this.isDefensive = SURROUND_BLOCK_TYPES.contains(blockType.toUpperCase());
        }
    }

    /**
     * 内部包围统计数据
     */
    private static class SurroundStats {
        int cardinalPlacements = 0;     // 四个基本方位的放置数量
        int surroundPatternCount = 0;   // 匹配包围模式的放置数量
        int defensiveBlockCount = 0;    // 防御方块的放置总数
    }

    /**
     * Surround检测结果 — 不可变结果类
     */
    public static class SurroundCheckResult {
        private final boolean flagged;
        private final boolean suspicious;
        private final List<String> reasons;

        private SurroundCheckResult(boolean flagged, boolean suspicious, List<String> reasons) {
            this.flagged = flagged;
            this.suspicious = suspicious;
            this.reasons = reasons;
        }

        /** 无异常 — 正常的方块放置行为 */
        public static SurroundCheckResult clean() {
            return new SurroundCheckResult(false, false, List.of());
        }

        /** 可疑 — 单次快速放置或方位匹配但不足以确定 */
        public static SurroundCheckResult suspicious(List<String> reasons) {
            return new SurroundCheckResult(false, true, reasons);
        }

        /** 已标记 — 确定使用了Surround auto-build hack */
        public static SurroundCheckResult flagged(List<String> reasons) {
            return new SurroundCheckResult(true, false, reasons);
        }

        public boolean isFlagged() { return flagged; }
        public boolean isSuspicious() { return suspicious; }
        public boolean isClean() { return !flagged && !suspicious; }
        public List<String> getReasons() { return reasons; }
    }
}
