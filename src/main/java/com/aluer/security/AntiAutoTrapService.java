package com.aluer.security;

import com.aluer.config.ServerGuardConfig;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * 自动困笼（AutoTrap）检测服务 — V5.1 反作弊战斗模块
 *
 * 检测原理：
 * 1. 困笼结构检测 — Meteor Client的AutoTrap模块在目标玩家周围自动构建笼状结构，
 *    使用活塞推动方块或直接放置方块封住目标头部和身体周围。
 *    检测多个方块在极短时间内精确围绕另一玩家的身体/头部位置排列。
 * 2. 相对位置模式检测 — 困笼方块在目标玩家的特定相对坐标位置出现：
 *    头部位置(0,+2,0)及周围形成天花板，身体位置(0,+1,0)及周围的±1偏移形成墙壁。
 *    如果方块放置位置匹配这些困笼专用的偏移模式，高度可疑。
 * 3. 多目标同时困笼检测 — AutoTrap一次操作涉及放置多个方块（通常4-6块）。
 *    如果检测到在1-2秒内围绕同一目标玩家放置了4+块方块，形成封闭结构，则标记。
 * 4. 合法建造与困笼区分 — 正常建造行为通常有停顿、位置不精确、顺序不模式化。
 *    困笼行为的特点：极高的速度（<2秒完成）、精确的相对位置、一次性多块。
 *
 * 配置开关：serverguard.security.super-evolution.anti-auto-trap
 */
@Service
public class AntiAutoTrapService {

    private final ServerGuardConfig config;

    /**
     * 追踪每个玩家对他人进行的方块放置记录（playerName -> 放置记录列表）
     * 每个记录包含放置者和目标玩家的关系
     */
    private final Map<String, List<TrapPlacementRecord>> playerTrapHistory = new ConcurrentHashMap<>();

    /**
     * 追踪每个潜在目标被围困的记录（targetName -> 被围困记录列表）
     */
    private final Map<String, List<TargetTrapRecord>> targetTrapHistory = new ConcurrentHashMap<>();

    /**
     * 追踪每个玩家的围困模式统计
     */
    private final Map<String, TrapStats> playerTrapStats = new ConcurrentHashMap<>();

    /**
     * 追踪疑似AutoTrap的事件（playerName -> 可疑事件列表）
     */
    private final Map<String, List<Map<String, Object>>> autoTrapEvents = new ConcurrentHashMap<>();

    private final AtomicLong totalTrapPlacements = new AtomicLong(0);
    private final AtomicLong flaggedCount = new AtomicLong(0);

    /**
     * 困笼速度检测窗口（毫秒）— 2秒内完成困笼结构即标记
     */
    private static final long TRAP_SPEED_WINDOW_MS = 2_000;

    /**
     * 窗口内构成困笼的最小方块数
     */
    private static final int MIN_TRAP_BLOCKS = 4;

    /**
     * 困笼方块相对目标的最大距离（方块坐标）— 用于判定方块是否围绕在目标周围
     */
    private static final double MAX_TRAP_DISTANCE = 2.5;

    /**
     * 困笼结构覆盖的关键位置数量阈值 — 超过此值的特定位置被覆盖则标记
     */
    private static final int MIN_COVERED_POSITIONS = 3;

    /**
     * 连续困笼事件检测窗口（毫秒）— 在此窗口内连续进行困笼操作
     */
    private static final long CONSECUTIVE_TRAP_WINDOW_MS = 30_000;

    /**
     * 连续困笼事件最大允许次数
     */
    private static final int MAX_CONSECUTIVE_TRAPS = 2;

    /**
     * 每个玩家保留的最大记录数
     */
    private static final int MAX_RECORDS = 50;

    /**
     * 无参构造函数 — 测试/默认配置使用
     */
    public AntiAutoTrapService() {
        this(new ServerGuardConfig());
    }

    /**
     * Spring 注入构造函数
     * @param config 全局配置，提供模块开关控制
     */
    public AntiAutoTrapService(ServerGuardConfig config) {
        this.config = config;
    }

    /**
     * 检测方块放置是否构成自动困笼行为
     *
     * @param playerName 方块放置者名称
     * @param playerUUID 放置者UUID
     * @param targetPlayerName 方块放置的目标/附近玩家名称（可为null表示无目标）
     * @param blockType 放置的方块类型
     * @param blockX 放置方块X坐标（方块坐标，整数）
     * @param blockY 放置方块Y坐标（方块坐标，整数）
     * @param blockZ 放置方块Z坐标（方块坐标，整数）
     * @param targetX 目标玩家X坐标
     * @param targetY 目标玩家脚部Y坐标
     * @param targetZ 目标玩家Z坐标
     * @param timestamp 时间戳
     * @return 检测结果
     */
    public AutoTrapCheckResult detect(String playerName, String playerUUID,
                                       String targetPlayerName, String blockType,
                                       int blockX, int blockY, int blockZ,
                                       double targetX, double targetY, double targetZ,
                                       Instant timestamp) {
        // 模块开关检查
        if (!config.getSecurity().getSuperEvolution().isAntiAutoTrap()) {
            return AutoTrapCheckResult.clean();
        }

        // 如果没有明确的目标玩家，不做困笼检测（困笼必须有目标）
        if (targetPlayerName == null || targetPlayerName.isEmpty()) {
            return AutoTrapCheckResult.clean();
        }

        totalTrapPlacements.incrementAndGet();
        List<String> reasons = new ArrayList<>();

        List<TrapPlacementRecord> history = playerTrapHistory.computeIfAbsent(
                playerName, k -> new ArrayList<>());
        TrapStats stats = playerTrapStats.computeIfAbsent(
                playerName, k -> new TrapStats());

        // 计算方块相对于目标玩家的位置
        int relX = blockX - (int) Math.round(targetX);
        int relY = blockY - (int) Math.round(targetY);
        int relZ = blockZ - (int) Math.round(targetZ);

        // 计算方块到目标玩家的距离
        double distToTarget = Math.sqrt(
                Math.pow(blockX + 0.5 - targetX, 2) +
                Math.pow(blockY + 0.5 - targetY, 2) +
                Math.pow(blockZ + 0.5 - targetZ, 2));

        boolean isCloseToTarget = distToTarget <= MAX_TRAP_DISTANCE;

        // 仅对靠近目标玩家的方块进行困笼检测
        if (!isCloseToTarget) {
            return AutoTrapCheckResult.clean();
        }

        TrapPlacementRecord record = new TrapPlacementRecord(timestamp, targetPlayerName,
                blockType, blockX, blockY, blockZ, relX, relY, relZ, distToTarget);
        history.add(record);
        while (history.size() > MAX_RECORDS) {
            history.remove(0);
        }

        // 同时记录到目标被围困历史中
        List<TargetTrapRecord> targetHistory = targetTrapHistory.computeIfAbsent(
                targetPlayerName, k -> new ArrayList<>());
        TargetTrapRecord targetRecord = new TargetTrapRecord(timestamp, playerName,
                relX, relY, relZ, blockType);
        targetHistory.add(targetRecord);
        while (targetHistory.size() > MAX_RECORDS) {
            targetHistory.remove(0);
        }

        // 1. 困笼结构检测 — 在短时间窗口内围绕同一目标放置多个方块
        Instant windowStart = timestamp.minusMillis(TRAP_SPEED_WINDOW_MS);
        long recentTargetBlocks = history.stream()
                .filter(r -> !r.timestamp.isBefore(windowStart))
                .filter(r -> r.targetPlayerName.equals(targetPlayerName))
                .count();

        if (recentTargetBlocks >= MIN_TRAP_BLOCKS) {
            // 检查这些方块是否覆盖了多个关键位置（头部+身体周围）
            int coveredPositions = countCoveredPositions(history, windowStart,
                    targetPlayerName, (int) Math.round(targetY));

            if (coveredPositions >= MIN_COVERED_POSITIONS) {
                reasons.add("CAGE_STRUCTURE: " + recentTargetBlocks
                        + " blocks covering " + coveredPositions + " key positions around "
                        + targetPlayerName + " in " + (TRAP_SPEED_WINDOW_MS / 1000) + "s");
                stats.trapEvents++;
            }
        }

        // 2. 头部/身体关键位置检测
        // 困笼通常在目标头部(+2Y)和身体(+1Y)周围放置方块
        boolean isHeadLevel = relY == 2;   // 头部高度
        boolean isBodyLevel = relY == 1;    // 身体高度
        boolean isTopBlock = relY >= 2;     // 天花板方块

        if (isHeadLevel || isBodyLevel) {
            // 检查是否在水平方向包围（身体周围±1各方格位置）
            int horzOffset = Math.abs(relX) + Math.abs(relZ);
            if (horzOffset == 1) {
                // 在目标的紧邻卡片方向放置方块 — 困笼墙壁特征
                stats.bodyWallPlacements++;
            }
        }

        if (isTopBlock && Math.abs(relX) <= 1 && Math.abs(relZ) <= 1) {
            // 在目标头顶放置方块 — 困笼天花板特征
            stats.headBlockPlacements++;
        }

        // 3. 连续困笼模式检测
        if (history.size() >= 3) {
            Instant consecutiveWindow = timestamp.minusMillis(CONSECUTIVE_TRAP_WINDOW_MS);
            long recentTrapEvents = history.stream()
                    .filter(r -> !r.timestamp.isBefore(consecutiveWindow))
                    .filter(r -> r.relY >= 1 && Math.abs(r.relX) <= 1 && Math.abs(r.relZ) <= 1)
                    .count();

            if (recentTrapEvents >= MIN_TRAP_BLOCKS * MAX_CONSECUTIVE_TRAPS) {
                reasons.add("REPEATED_TRAPPING: " + recentTrapEvents
                        + " trap-like placements in " + (CONSECUTIVE_TRAP_WINDOW_MS / 1000) + "s");
            }
        }

        // 4. 困笼模式统计检测
        if (stats.bodyWallPlacements >= 8 && stats.headBlockPlacements >= 3) {
            reasons.add("TRAP_PATTERN_SUSTAINED: " + stats.bodyWallPlacements
                    + " body walls + " + stats.headBlockPlacements
                    + " head blocks placed (trap pattern)");
        }

        // 记录可疑事件
        if (!reasons.isEmpty()) {
            List<Map<String, Object>> events = autoTrapEvents.computeIfAbsent(
                    playerName, k -> new ArrayList<>());
            Map<String, Object> event = new LinkedHashMap<>();
            event.put("time", timestamp.toString());
            event.put("target", targetPlayerName);
            event.put("blockType", blockType);
            event.put("relPos", "(" + relX + "," + relY + "," + relZ + ")");
            event.put("reasons", reasons);
            events.add(event);
            while (events.size() > 20) {
                events.remove(0);
            }
        }

        if (reasons.size() >= 2) {
            flaggedCount.incrementAndGet();
            return AutoTrapCheckResult.flagged(reasons);
        } else if (reasons.size() == 1) {
            return AutoTrapCheckResult.suspicious(reasons);
        }

        return AutoTrapCheckResult.clean();
    }

    /**
     * 统计在时间窗口内围绕同一目标覆盖的困笼关键位置数量
     */
    private int countCoveredPositions(List<TrapPlacementRecord> history,
                                       Instant windowStart, String targetName, int targetIntY) {
        Set<String> positions = new HashSet<>();
        for (TrapPlacementRecord r : history) {
            if (r.timestamp.isBefore(windowStart)) continue;
            if (!r.targetPlayerName.equals(targetName)) continue;
            // 记录相对位置（仅记录头部和身体周围的方块位置）
            if ((r.relY == 1 || r.relY == 2) && Math.abs(r.relX) <= 1 && Math.abs(r.relZ) <= 1) {
                positions.add(r.relX + "," + r.relY + "," + r.relZ);
            }
        }
        return positions.size();
    }

    /**
     * 玩家离线时清理追踪数据
     * @param playerName 离线玩家名称
     */
    public void clearPlayer(String playerName) {
        playerTrapHistory.remove(playerName);
        playerTrapStats.remove(playerName);
        autoTrapEvents.remove(playerName);
    }

    /**
     * 获取模块运行状态
     * @return 包含计数器和活跃追踪玩家数的Map
     */
    public Map<String, Object> getStatus() {
        Map<String, Object> status = new LinkedHashMap<>();
        status.put("totalTrapPlacements", totalTrapPlacements.get());
        status.put("flaggedCount", flaggedCount.get());
        status.put("activeTrackedPlayers", playerTrapHistory.size());
        status.put("targetsWithTraps", targetTrapHistory.size());

        // 列出被困最多的目标
        List<Map<String, Object>> topTargets = new ArrayList<>();
        for (Map.Entry<String, List<TargetTrapRecord>> entry : targetTrapHistory.entrySet()) {
            if (entry.getValue().size() >= 3) {
                Map<String, Object> info = new LinkedHashMap<>();
                info.put("target", entry.getKey());
                info.put("trapBlocks", entry.getValue().size());

                // 找出最活跃的放置者
                Map<String, Integer> placerCount = new HashMap<>();
                for (TargetTrapRecord r : entry.getValue()) {
                    placerCount.merge(r.placerName, 1, Integer::sum);
                }
                String topPlacer = placerCount.entrySet().stream()
                        .max(Map.Entry.comparingByValue())
                        .map(Map.Entry::getKey)
                        .orElse("unknown");
                info.put("topPlacer", topPlacer);
                topTargets.add(info);
            }
        }
        topTargets.sort((a, b) ->
                Integer.compare((Integer) b.get("trapBlocks"), (Integer) a.get("trapBlocks")));
        status.put("topTargets", topTargets.subList(0, Math.min(topTargets.size(), 10)));

        return status;
    }

    /**
     * 内部困笼放置记录 — 记录困笼相关的方块放置信息
     */
    private static class TrapPlacementRecord {
        final Instant timestamp;
        final String targetPlayerName;
        final String blockType;
        final int blockX, blockY, blockZ;
        final int relX, relY, relZ;      // 相对于目标的位置
        final double distToTarget;

        TrapPlacementRecord(Instant timestamp, String targetPlayerName, String blockType,
                           int blockX, int blockY, int blockZ,
                           int relX, int relY, int relZ, double distToTarget) {
            this.timestamp = timestamp;
            this.targetPlayerName = targetPlayerName;
            this.blockType = blockType;
            this.blockX = blockX;
            this.blockY = blockY;
            this.blockZ = blockZ;
            this.relX = relX;
            this.relY = relY;
            this.relZ = relZ;
            this.distToTarget = distToTarget;
        }
    }

    /**
     * 内部目标被围困记录 — 记录目标玩家被围困的事件
     */
    private static class TargetTrapRecord {
        final Instant timestamp;
        final String placerName;
        final int relX, relY, relZ;
        final String blockType;

        TargetTrapRecord(Instant timestamp, String placerName, int relX, int relY, int relZ, String blockType) {
            this.timestamp = timestamp;
            this.placerName = placerName;
            this.relX = relX;
            this.relY = relY;
            this.relZ = relZ;
            this.blockType = blockType;
        }
    }

    /**
     * 内部困笼统计数据
     */
    private static class TrapStats {
        int trapEvents = 0;              // 困笼事件计数
        int bodyWallPlacements = 0;       // 身体墙壁放置数
        int headBlockPlacements = 0;      // 头部天花板放置数
    }

    /**
     * AutoTrap检测结果 — 不可变结果类
     */
    public static class AutoTrapCheckResult {
        private final boolean flagged;
        private final boolean suspicious;
        private final List<String> reasons;

        private AutoTrapCheckResult(boolean flagged, boolean suspicious, List<String> reasons) {
            this.flagged = flagged;
            this.suspicious = suspicious;
            this.reasons = reasons;
        }

        /** 无异常 — 正常的方块放置行为（非困笼） */
        public static AutoTrapCheckResult clean() {
            return new AutoTrapCheckResult(false, false, List.of());
        }

        /** 可疑 — 存在部分困笼特征但证据不完整 */
        public static AutoTrapCheckResult suspicious(List<String> reasons) {
            return new AutoTrapCheckResult(false, true, reasons);
        }

        /** 已标记 — 确定使用了AutoTrap hack */
        public static AutoTrapCheckResult flagged(List<String> reasons) {
            return new AutoTrapCheckResult(true, false, reasons);
        }

        public boolean isFlagged() { return flagged; }
        public boolean isSuspicious() { return suspicious; }
        public boolean isClean() { return !flagged && !suspicious; }
        public List<String> getReasons() { return reasons; }
    }
}
