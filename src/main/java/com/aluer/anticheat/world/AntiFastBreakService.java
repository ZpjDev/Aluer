package com.aluer.anticheat.world;

import com.aluer.config.ServerGuardConfig;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * 加速破坏（FastBreak）检测服务 — V5.0 反作弊扩展模块
 *
 * 检测原理：
 * 1. 破坏速度检测 — 每种方块在Minecraft中都有标准的破坏时间。
 *    例如泥土约0.75秒（空手），黑曜石约250秒（空手），石头约7.5秒（空手）。
 *    使用合适工具和附魔可大幅缩短时间。本模块追踪每个方块的破坏用时，
 *    如果显著低于理论最短时间，标记为异常。
 * 2. 连续快速破坏检测 — 单次快速破坏可能是延迟补偿导致，
 *    但连续多次快速破坏则是明显的FastBreak hack。
 *    需要检测方块破坏序列中的持续加速模式。
 * 3. 方块硬度分组 — 不同硬度的方块有不同的破坏时间下限。
 *    将方块分为软（泥土/沙子）、中（石头/木头）、硬（黑曜石/末地石）三个等级，
 *    使用不同的阈值进行检测。
 * 4. 工具与附魔考虑 — 考虑急迫效果、效率附魔、适用工具等因素。
 *    一个有效率V的下界合金镐挖掘石头的理论速度远快于空手，
 *    需要在实际计算中考虑这些加速因素。
 *
 * 配置开关：serverguard.security.super-evolution.anti-fast-break
 */
@Service
public class AntiFastBreakService {

    private final ServerGuardConfig config;

    /**
     * 追踪每个玩家的方块破坏记录（playerName -> 破坏记录列表）
     * 用于分析连续破坏速度模式
     */
    private final Map<String, List<BreakRecord>> playerBreakHistory = new ConcurrentHashMap<>();

    /**
     * 追踪每个玩家当前正在破坏的方块（playerName -> 开始破坏的信息）
     * 用于计算单次破坏用时
     */
    private final Map<String, BreakStartInfo> playerCurrentBreak = new ConcurrentHashMap<>();

    /**
     * 追踪每个玩家连续快速破坏的计数（playerName -> 连续快速破坏次数）
     */
    private final Map<String, Integer> playerConsecutiveFastBreaks = new ConcurrentHashMap<>();

    private final AtomicLong totalChecks = new AtomicLong(0);
    private final AtomicLong flaggedCount = new AtomicLong(0);

    // ==================== 方块硬度分组与阈值 ====================

    /**
     * 软方块最小破坏时间（毫秒）— 泥土、沙子、沙砾等
     * 空手约750ms，效率V+下界合金铲约50ms，设置30ms为检测下限
     */
    private static final long SOFT_BLOCK_MIN_MS = 30;

    /**
     * 中等硬度方块最小破坏时间（毫秒）— 石头、原木、木板等
     * 空手约7500ms，效率V+下界合金镐约150ms，设置100ms为检测下限
     */
    private static final long MEDIUM_BLOCK_MIN_MS = 100;

    /**
     * 硬方块最小破坏时间（毫秒）— 黑曜石、末地石、远古残骸等
     * 黑曜石空手约250000ms，效率V+下界合金镐约9500ms，设置5000ms为检测下限
     */
    private static final long HARD_BLOCK_MIN_MS = 5000;

    /**
     * 触发标记所需的连续快速破坏次数
     */
    private static final int MIN_CONSECUTIVE_FAST_BREAKS = 3;

    /**
     * 破坏速度检测窗口大小 — 分析最近N次破坏
     */
    private static final int ANALYSIS_WINDOW_SIZE = 10;

    /**
     * 每个玩家保留的最大破坏记录数
     */
    private static final int MAX_BREAK_RECORDS = 50;

    /**
     * 无参构造函数 — 测试/默认配置使用
     */
    public AntiFastBreakService() {
        this(new ServerGuardConfig());
    }

    /**
     * Spring 注入构造函数
     * @param config 全局配置，提供模块开关控制
     */
    public AntiFastBreakService(ServerGuardConfig config) {
        this.config = config;
    }

    /**
     * 记录玩家开始破坏一个方块（用于计时）
     *
     * @param playerName 玩家名称
     * @param blockType 方块类型名称（如 DIRT, STONE, OBSIDIAN）
     * @param toolType 使用的工具类型（如 DIAMOND_PICKAXE, NETHERITE_PICKAXE）
     * @param hasEfficiency 是否有效率附魔
     * @param efficiencyLevel 效率附魔等级（0表示无）
     * @param hasHaste 是否有急迫效果
     * @param hasteLevel 急迫效果等级（0表示无）
     * @param timestamp 开始破坏的时间戳
     */
    public void onStartBreak(String playerName, String blockType, String toolType,
                              boolean hasEfficiency, int efficiencyLevel,
                              boolean hasHaste, int hasteLevel, Instant timestamp) {
        if (!config.getSecurity().getSuperEvolution().isAntiFastBreak()) {
            return;
        }
        playerCurrentBreak.put(playerName, new BreakStartInfo(
                blockType, toolType, hasEfficiency, efficiencyLevel,
                hasHaste, hasteLevel, timestamp));
    }

    /**
     * 检测玩家完成方块破坏是否超速
     *
     * @param playerName 玩家名称
     * @param playerUUID 玩家UUID
     * @param blockType 破坏的方块类型名称
     * @param toolType 使用的工具类型
     * @param hasEfficiency 是否有效率附魔
     * @param efficiencyLevel 效率附魔等级
     * @param hasHaste 是否有急迫效果
     * @param hasteLevel 急迫效果等级
     * @param timestamp 完成破坏的时间戳
     * @return 检测结果
     */
    public FastBreakCheckResult onBreakComplete(String playerName, String playerUUID,
                                                  String blockType, String toolType,
                                                  boolean hasEfficiency, int efficiencyLevel,
                                                  boolean hasHaste, int hasteLevel,
                                                  Instant timestamp) {
        // 模块开关检查
        if (!config.getSecurity().getSuperEvolution().isAntiFastBreak()) {
            return FastBreakCheckResult.clean();
        }

        totalChecks.incrementAndGet();
        List<String> reasons = new ArrayList<>();

        // 获取破坏开始信息以计算用时
        BreakStartInfo startInfo = playerCurrentBreak.remove(playerName);

        if (startInfo != null) {
            long breakTimeMs = timestamp.toEpochMilli() - startInfo.timestamp.toEpochMilli();

            // 确定方块的硬度等级和最小破坏时间阈值
            BlockHardness hardness = classifyBlockHardness(blockType);
            long minBreakTime = getMinBreakTime(hardness, toolType, hasEfficiency,
                    efficiencyLevel, hasHaste, hasteLevel);

            // 1. 破坏速度检测 — 实际用时是否低于理论最小值
            if (breakTimeMs < minBreakTime && breakTimeMs >= 0) {
                int consecutive = playerConsecutiveFastBreaks.merge(playerName, 1, Integer::sum);

                if (consecutive >= MIN_CONSECUTIVE_FAST_BREAKS) {
                    // 连续多次快速破坏 — 确认为FastBreak hack
                    flaggedCount.incrementAndGet();
                    reasons.add("SUSTAINED_FAST_BREAK: " + consecutive + " consecutive fast breaks ("
                            + breakTimeMs + "ms for " + blockType + ", min: " + minBreakTime
                            + "ms, hardness: " + hardness + ")");
                } else {
                    reasons.add("FAST_BREAK: " + blockType + " broken in " + breakTimeMs
                            + "ms (min expected: " + minBreakTime + "ms, consecutive: "
                            + consecutive + "/" + MIN_CONSECUTIVE_FAST_BREAKS + ")");
                }
            } else {
                // 破坏速度正常，重置快速破坏计数
                playerConsecutiveFastBreaks.put(playerName, 0);
            }

            // 记录破坏事件
            List<BreakRecord> history = playerBreakHistory.computeIfAbsent(
                    playerName, k -> new ArrayList<>());
            history.add(new BreakRecord(timestamp, blockType, hardness, breakTimeMs,
                    toolType, efficiencyLevel, hasteLevel));
            while (history.size() > MAX_BREAK_RECORDS) {
                history.remove(0);
            }
        }

        // 2. 连续硬方块快速破坏模式分析
        List<BreakRecord> history = playerBreakHistory.get(playerName);
        if (history != null && history.size() >= ANALYSIS_WINDOW_SIZE) {
            List<BreakRecord> recent = history.subList(
                    history.size() - ANALYSIS_WINDOW_SIZE, history.size());

            int hardFastBreaks = 0;
            for (BreakRecord r : recent) {
                BlockHardness h = r.hardness;
                long min = getMinBreakTime(h, r.toolType, false, 0, false, 0);
                if (r.breakTimeMs < min && (h == BlockHardness.HARD || h == BlockHardness.MEDIUM)) {
                    hardFastBreaks++;
                }
            }

            if (hardFastBreaks >= MIN_CONSECUTIVE_FAST_BREAKS + 2) {
                reasons.add("HARD_BLOCK_SPEED_PATTERN: " + hardFastBreaks + "/"
                        + ANALYSIS_WINDOW_SIZE + " recent hard/medium blocks broken too fast");
            }
        }

        // 汇总结果
        if (reasons.size() >= 2) {
            flaggedCount.incrementAndGet();
            return FastBreakCheckResult.flagged(reasons);
        } else if (reasons.size() == 1) {
            return FastBreakCheckResult.suspicious(reasons);
        }

        return FastBreakCheckResult.clean();
    }

    /**
     * 根据方块类型名称分类硬度等级
     * 使用字符串匹配简化分类（Agent端负责传入标准化的方块类型名称）
     */
    private BlockHardness classifyBlockHardness(String blockType) {
        if (blockType == null) return BlockHardness.MEDIUM;

        String upper = blockType.toUpperCase();

        // 硬方块：黑曜石、远古残骸、末地石、哭泣的黑曜石、下界合金块等
        if (upper.contains("OBSIDIAN") || upper.contains("ANCIENT_DEBRIS")
                || upper.contains("END_STONE") || upper.contains("NETHERITE")
                || upper.contains("CRYING_OBSIDIAN") || upper.contains("RESPAWN_ANCHOR")
                || upper.contains("BEDROCK")) {
            return BlockHardness.HARD;
        }

        // 软方块：泥土、沙子、沙砾、灵魂沙、雪等
        if (upper.contains("DIRT") || upper.contains("SAND") || upper.contains("GRAVEL")
                || upper.contains("SOUL_SAND") || upper.contains("SNOW")
                || upper.contains("WOOL") || upper.contains("LEAVES")
                || upper.contains("GRASS") || upper.contains("MYCELIUM")
                || upper.contains("PODZOL") || upper.contains("CLAY")
                || upper.contains("FARMLAND") || upper.contains("MUD")) {
            return BlockHardness.SOFT;
        }

        // 默认为中等硬度（石头、原木、木板、矿石等）
        return BlockHardness.MEDIUM;
    }

    /**
     * 计算在给定工具和效果下破坏某硬度方块的理论最短时间
     *
     * @param hardness 方块硬度等级
     * @param toolType 工具类型
     * @param hasEfficiency 是否有效率附魔
     * @param efficiencyLevel 效率附魔等级
     * @param hasHaste 是否有急迫效果
     * @param hasteLevel 急迫效果等级
     * @return 理论最短破坏时间（毫秒）
     */
    private long getMinBreakTime(BlockHardness hardness, String toolType,
                                  boolean hasEfficiency, int efficiencyLevel,
                                  boolean hasHaste, int hasteLevel) {
        long baseMin = switch (hardness) {
            case SOFT -> SOFT_BLOCK_MIN_MS;
            case MEDIUM -> MEDIUM_BLOCK_MIN_MS;
            case HARD -> HARD_BLOCK_MIN_MS;
        };

        // 效率附魔加速（每级约30%额外加速，但检测下限不能因此降为零）
        if (hasEfficiency && efficiencyLevel > 0) {
            // 效率V可缩短约(1 + level^2 + 1)的倍数，但作弊检测不能完全按此公式降阈值
            // 效率V的加速因子约为26倍，阈值降至原来的约1/26但保留下限
            double efficiencyFactor = 1.0 + (efficiencyLevel * efficiencyLevel) + 1;
            baseMin = (long) (baseMin / efficiencyFactor);
        }

        // 急迫效果加速（每级20%）
        if (hasHaste && hasteLevel > 0) {
            double hasteMultiplier = 1.0 + (hasteLevel * 0.2);
            baseMin = (long) (baseMin / hasteMultiplier);
        }

        // 确保不为负数
        return Math.max(1, baseMin);
    }

    /**
     * 玩家离线时清理其追踪数据，释放内存
     * @param playerName 离线玩家名称
     */
    public void clearPlayer(String playerName) {
        playerBreakHistory.remove(playerName);
        playerCurrentBreak.remove(playerName);
        playerConsecutiveFastBreaks.remove(playerName);
    }

    /**
     * 获取模块运行状态
     * @return 包含计数器和活跃追踪玩家数的Map
     */
    public Map<String, Object> getStatus() {
        Map<String, Object> status = new LinkedHashMap<>();
        status.put("totalChecks", totalChecks.get());
        status.put("flaggedCount", flaggedCount.get());
        status.put("activeTrackedPlayers", playerBreakHistory.size());
        return status;
    }

    /**
     * 方块硬度等级枚举
     */
    private enum BlockHardness {
        SOFT,    // 软方块（泥土、沙子等）
        MEDIUM,  // 中等硬度（石头、原木等）
        HARD     // 硬方块（黑曜石、远古残骸等）
    }

    /**
     * 内部破坏开始信息 — 记录玩家开始破坏方块时的状态
     */
    private static class BreakStartInfo {
        final String blockType;
        final String toolType;
        final boolean hasEfficiency;
        final int efficiencyLevel;
        final boolean hasHaste;
        final int hasteLevel;
        final Instant timestamp;

        BreakStartInfo(String blockType, String toolType, boolean hasEfficiency,
                       int efficiencyLevel, boolean hasHaste, int hasteLevel,
                       Instant timestamp) {
            this.blockType = blockType;
            this.toolType = toolType;
            this.hasEfficiency = hasEfficiency;
            this.efficiencyLevel = efficiencyLevel;
            this.hasHaste = hasHaste;
            this.hasteLevel = hasteLevel;
            this.timestamp = timestamp;
        }
    }

    /**
     * 内部破坏记录 — 记录一次完成破坏的详细信息
     */
    private static class BreakRecord {
        final Instant timestamp;
        final String blockType;
        final BlockHardness hardness;
        final long breakTimeMs;
        final String toolType;
        final int efficiencyLevel;
        final int hasteLevel;

        BreakRecord(Instant timestamp, String blockType, BlockHardness hardness,
                    long breakTimeMs, String toolType, int efficiencyLevel, int hasteLevel) {
            this.timestamp = timestamp;
            this.blockType = blockType;
            this.hardness = hardness;
            this.breakTimeMs = breakTimeMs;
            this.toolType = toolType;
            this.efficiencyLevel = efficiencyLevel;
            this.hasteLevel = hasteLevel;
        }
    }

    /**
     * 快速破坏检测结果 — 不可变结果类
     */
    public static class FastBreakCheckResult {
        private final boolean flagged;
        private final boolean suspicious;
        private final List<String> reasons;

        private FastBreakCheckResult(boolean flagged, boolean suspicious, List<String> reasons) {
            this.flagged = flagged;
            this.suspicious = suspicious;
            this.reasons = reasons;
        }

        /** 无异常 — 正常破坏速度 */
        public static FastBreakCheckResult clean() {
            return new FastBreakCheckResult(false, false, List.of());
        }

        /** 可疑 — 破坏速度略快但可能为工具/附魔/延迟因素 */
        public static FastBreakCheckResult suspicious(List<String> reasons) {
            return new FastBreakCheckResult(false, true, reasons);
        }

        /** 已标记 — 多项规则命中，确认为加速破坏 */
        public static FastBreakCheckResult flagged(List<String> reasons) {
            return new FastBreakCheckResult(true, false, reasons);
        }

        public boolean isFlagged() { return flagged; }
        public boolean isSuspicious() { return suspicious; }
        public boolean isClean() { return !flagged && !suspicious; }
        public List<String> getReasons() { return reasons; }
    }
}
