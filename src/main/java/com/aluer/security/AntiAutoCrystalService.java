package com.aluer.security;

import com.aluer.config.ServerGuardConfig;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * 自动末影水晶（AutoCrystal）检测服务 — V5.1 反作弊战斗模块
 *
 * 检测原理：
 * 1. 水晶放置速度检测 — Meteor Client的CrystalAura/AutoCrystal模块可以在同一tick内
 *    完成黑曜石放置、末影水晶放置、水晶引爆的完整序列。正常玩家在这些操作之间
 *    需要明显的时间间隔（放置黑曜石~200ms，放置水晶~200ms，引爆水晶~200ms）。
 *    如果黑曜石放置到水晶放置之间的时间间隔<50ms（同一tick），标记为作弊。
 * 2. 水晶引爆速度检测 — 从水晶放置到水晶引爆的时间间隔。
 *    合法PvP玩家：放置水晶后需要时间切换到手/物品来攻击水晶引爆（通常300-1000ms）。
 *    CrystalAura hack：水晶放置后1-2 tick内即被引爆（0-100ms），自动化操作无延迟。
 *    特别关注同一玩家放置水晶后立即引爆自己水晶的模式。
 * 3. 最优水晶位置计算检测 — 末影水晶PvP中，水晶对敌人造成最大伤害的数学最优位置
 *    是目标玩家周围第1层方块（脚高）和第2层方块（头高）上的特定坐标位置。
 *    正常玩家需要手动推算这些位置，会有位置误差。如果玩家持续在数学最优位置精确放置
 *    水晶且无误差，表明使用了计算脚本。
 * 4. 水晶伤害一致性检测 — 如果玩家每次水晶爆炸都精准对敌人造成最大伤害（~6点/3心），
 *    且敌人始终在水晶爆炸半径（约6方块）的边缘，说明水晶放置位置是算法驱动而非手动。
 *
 * 配置开关：serverguard.security.super-evolution.anti-auto-crystal
 */
@Service
public class AntiAutoCrystalService {

    private final ServerGuardConfig config;

    /**
     * 追踪每个玩家的水晶放置时间（playerName -> 水晶放置记录列表）
     * 用于计算放置速度和与引爆的间隔
     */
    private final Map<String, List<CrystalPlacement>> playerCrystalPlacements = new ConcurrentHashMap<>();

    /**
     * 追踪每个玩家的水晶引爆时间（playerName -> 引爆记录列表）
     */
    private final Map<String, List<CrystalBreak>> playerCrystalBreaks = new ConcurrentHashMap<>();

    /**
     * 追踪每个玩家的黑曜石放置时间（playerName -> 黑曜石放置时间列表）
     */
    private final Map<String, List<Instant>> playerObsidianPlacements = new ConcurrentHashMap<>();

    /**
     * 追踪水晶位置的最优性统计（playerName -> 最优位置统计）
     */
    private final Map<String, CrystalStats> playerCrystalStats = new ConcurrentHashMap<>();

    /**
     * 追踪疑似AutoCrystal的事件（playerName -> 可疑事件列表）
     */
    private final Map<String, List<Map<String, Object>>> autoCrystalEvents = new ConcurrentHashMap<>();

    private final AtomicLong totalCrystalsPlaced = new AtomicLong(0);
    private final AtomicLong totalCrystalsBroken = new AtomicLong(0);
    private final AtomicLong flaggedCount = new AtomicLong(0);

    /**
     * 水晶在放置后爆炸的最短合法时间间隔（毫秒）— 低于此值视为自动化
     * 人类需要至少300ms来切换物品和攻击
     */
    private static final long MIN_LEGIT_PLACE_BREAK_MS = 300;

    /**
     * Hack级别的放置引爆间隔（毫秒）— 50ms内几乎确定是自动水晶
     */
    private static final long HACK_PLACE_BREAK_MS = 50;

    /**
     * 黑曜石放置到水晶放置的最短合法间隔（毫秒）
     * 人类需要切换物品和放置水晶的时间
     */
    private static final long MIN_OBSIDIAN_TO_CRYSTAL_MS = 100;

    /**
     * 最优水晶位置容差（方块）— 判定为"精确最优位置"的距离偏差
     */
    private static final double OPTIMAL_POSITION_TOLERANCE = 0.2;

    /**
     * 水晶爆炸最大伤害距离（方块）— 末影水晶爆炸对目标造成最大伤害的距离
     * 取值为爆炸半径6.0方块的边缘（实际有效伤害范围约4.5方块）
     */
    private static final double MAX_CRYSTAL_DAMAGE_DISTANCE = 6.0;

    /**
     * 高伤害一致性阈值 — 如果玩家的水晶爆炸伤害与最大伤害的偏差小于此值次数过多
     */
    private static final double MAX_DAMAGE_CONSISTENCY = 0.5;

    /**
     * 连续快速水晶操作次数阈值
     */
    private static final int MAX_FAST_CRYSTAL_OPS = 3;

    /**
     * 短时间窗口（毫秒）— 用于检测连续快速水晶操作
     */
    private static final long RAPID_CRYSTAL_WINDOW_MS = 5_000;

    /**
     * 每个玩家保留的最大记录数
     */
    private static final int MAX_RECORDS = 50;

    /**
     * 无参构造函数 — 测试/默认配置使用
     */
    public AntiAutoCrystalService() {
        this(new ServerGuardConfig());
    }

    /**
     * Spring 注入构造函数
     * @param config 全局配置，提供模块开关控制
     */
    public AntiAutoCrystalService(ServerGuardConfig config) {
        this.config = config;
    }

    /**
     * 记录一次黑曜石放置事件（作为水晶放置的前置步骤）
     * 应在检测到黑曜石被放置时调用
     *
     * @param playerName 玩家名称
     * @param playerUUID 玩家UUID
     * @param obsidianX 黑曜石放置X坐标
     * @param obsidianY 黑曜石放置Y坐标
     * @param obsidianZ 黑曜石放置Z坐标
     * @param timestamp 时间戳
     */
    public void recordObsidianPlacement(String playerName, String playerUUID,
                                         int obsidianX, int obsidianY, int obsidianZ,
                                         Instant timestamp) {
        if (!config.getSecurity().getSuperEvolution().isAntiAutoCrystal()) {
            return;
        }

        List<Instant> obsidianTimes = playerObsidianPlacements.computeIfAbsent(
                playerName, k -> new ArrayList<>());
        obsidianTimes.add(timestamp);
        while (obsidianTimes.size() > MAX_RECORDS) {
            obsidianTimes.remove(0);
        }
    }

    /**
     * 记录一次水晶放置事件
     *
     * @param playerName 玩家名称
     * @param playerUUID 玩家UUID
     * @param crystalX 水晶X坐标
     * @param crystalY 水晶Y坐标
     * @param crystalZ 水晶Z坐标
     * @param targetName 攻击目标名称（可为null）
     * @param targetX 目标X坐标
     * @param targetY 目标Y坐标
     * @param targetZ 目标Z坐标
     * @param isOptimalPosition 位置是否为理论最优位置（调用方可预计算）
     * @param timestamp 时间戳
     */
    public void recordCrystalPlacement(String playerName, String playerUUID,
                                        int crystalX, int crystalY, int crystalZ,
                                        String targetName, double targetX, double targetY, double targetZ,
                                        boolean isOptimalPosition, Instant timestamp) {
        if (!config.getSecurity().getSuperEvolution().isAntiAutoCrystal()) {
            return;
        }

        totalCrystalsPlaced.incrementAndGet();

        CrystalPlacement placement = new CrystalPlacement(timestamp, crystalX, crystalY, crystalZ,
                targetName, targetX, targetY, targetZ, isOptimalPosition);

        List<CrystalPlacement> placements = playerCrystalPlacements.computeIfAbsent(
                playerName, k -> new ArrayList<>());
        placements.add(placement);
        while (placements.size() > MAX_RECORDS) {
            placements.remove(0);
        }

        CrystalStats stats = playerCrystalStats.computeIfAbsent(
                playerName, k -> new CrystalStats());
        if (isOptimalPosition) {
            stats.optimalPlacements++;
        }
        stats.totalPlacements++;
    }

    /**
     * 检测一次水晶引爆事件
     *
     * @param playerName 引发水晶爆炸的玩家名称
     * @param playerUUID 玩家UUID
     * @param crystalX 被引爆水晶X坐标
     * @param crystalY 被引爆水晶Y坐标
     * @param crystalZ 被引爆水晶Z坐标
     * @param damageDealt 对目标造成的伤害
     * @param targetDistance 目标到水晶的距离
     * @param timestamp 时间戳
     * @return 检测结果
     */
    public AutoCrystalCheckResult detectCrystalBreak(String playerName, String playerUUID,
                                                       int crystalX, int crystalY, int crystalZ,
                                                       double damageDealt, double targetDistance,
                                                       Instant timestamp) {
        // 模块开关检查
        if (!config.getSecurity().getSuperEvolution().isAntiAutoCrystal()) {
            return AutoCrystalCheckResult.clean();
        }

        totalCrystalsBroken.incrementAndGet();
        List<String> reasons = new ArrayList<>();

        // 记录引爆时间
        List<CrystalBreak> breaks = playerCrystalBreaks.computeIfAbsent(
                playerName, k -> new ArrayList<>());
        CrystalBreak crystalBreak = new CrystalBreak(timestamp, crystalX, crystalY, crystalZ,
                damageDealt, targetDistance);
        breaks.add(crystalBreak);
        while (breaks.size() > MAX_RECORDS) {
            breaks.remove(0);
        }

        // 1. 水晶放置到引爆时间间隔检测
        List<CrystalPlacement> placements = playerCrystalPlacements.get(playerName);
        if (placements != null && !placements.isEmpty()) {
            // 寻找最近的水晶放置事件（匹配坐标或最近时间）
            CrystalPlacement lastPlacement = null;
            for (int i = placements.size() - 1; i >= 0; i--) {
                CrystalPlacement p = placements.get(i);
                if (p.crystalX == crystalX && p.crystalY == crystalY && p.crystalZ == crystalZ) {
                    lastPlacement = p;
                    break;
                }
            }
            // 如果没有精确匹配，使用最近一次放置
            if (lastPlacement == null) {
                lastPlacement = placements.get(placements.size() - 1);
            }

            long placeBreakInterval = timestamp.toEpochMilli() - lastPlacement.timestamp.toEpochMilli();

            // 确保时间间隔为正数（引爆在放置之后）
            if (placeBreakInterval >= 0 && placeBreakInterval < MIN_LEGIT_PLACE_BREAK_MS) {
                if (placeBreakInterval < HACK_PLACE_BREAK_MS) {
                    reasons.add("INSTANT_CRYSTAL_BREAK: " + placeBreakInterval
                            + "ms place-to-break (hack threshold: " + HACK_PLACE_BREAK_MS + "ms)");
                } else {
                    reasons.add("FAST_CRYSTAL_BREAK: " + placeBreakInterval
                            + "ms place-to-break (human minimum: " + MIN_LEGIT_PLACE_BREAK_MS + "ms)");
                }
            }
        }

        // 2. 最优位置模式检测 — 通过统计检测
        CrystalStats stats = playerCrystalStats.get(playerName);
        if (stats != null && stats.totalPlacements >= 10) {
            double optimalRatio = (double) stats.optimalPlacements / stats.totalPlacements;
            if (optimalRatio >= 0.80) {
                reasons.add("OPTIMAL_POSITIONING_PATTERN: " + String.format("%.0f", optimalRatio * 100)
                        + "% of crystals at optimal positions (" + stats.optimalPlacements
                        + "/" + stats.totalPlacements + ")");
            }
        }

        // 3. 水晶伤害一致性检测
        if (damageDealt > 0 && targetDistance > 0 && targetDistance <= MAX_CRYSTAL_DAMAGE_DISTANCE) {
            // 计算理论最大伤害与所受伤害的比例
            // 末影水晶爆炸在中心造成约97点伤害，在目标距离处按衰减计算
            double expectedDamage = 97.0 * (1.0 - targetDistance / MAX_CRYSTAL_DAMAGE_DISTANCE);
            double damageAccuracy = Math.abs(damageDealt - expectedDamage) / Math.max(1.0, expectedDamage);

            if (damageAccuracy < MAX_DAMAGE_CONSISTENCY) {
                stats.perfectDamageCount++;
            }
            stats.totalDamageEvents++;

            if (stats.totalDamageEvents >= 5) {
                double perfectRatio = (double) stats.perfectDamageCount / stats.totalDamageEvents;
                if (perfectRatio >= 0.80) {
                    reasons.add("DAMAGE_CONSISTENCY: " + String.format("%.0f", perfectRatio * 100)
                            + "% near-max-damage explosions (" + stats.perfectDamageCount
                            + "/" + stats.totalDamageEvents + ")");
                }
            }
        }

        // 4. 连续快速水晶操作检测
        if (breaks.size() >= MAX_FAST_CRYSTAL_OPS) {
            Instant windowStart = timestamp.minusMillis(RAPID_CRYSTAL_WINDOW_MS);
            long recentBreaks = breaks.stream()
                    .filter(b -> !b.timestamp.isBefore(windowStart))
                    .count();

            if (recentBreaks >= MAX_FAST_CRYSTAL_OPS * 2) {
                reasons.add("RAPID_CRYSTAL_CHAIN: " + recentBreaks
                        + " crystal explosions in " + (RAPID_CRYSTAL_WINDOW_MS / 1000) + "s");
            }
        }

        // 记录可疑事件
        if (!reasons.isEmpty()) {
            List<Map<String, Object>> events = autoCrystalEvents.computeIfAbsent(
                    playerName, k -> new ArrayList<>());
            Map<String, Object> event = new LinkedHashMap<>();
            event.put("time", timestamp.toString());
            event.put("crystalPos", "(" + crystalX + "," + crystalY + "," + crystalZ + ")");
            event.put("damageDealt", String.format("%.1f", damageDealt));
            event.put("targetDistance", String.format("%.2f", targetDistance));
            event.put("reasons", reasons);
            events.add(event);
            while (events.size() > 20) {
                events.remove(0);
            }
        }

        if (reasons.size() >= 2) {
            flaggedCount.incrementAndGet();
            return AutoCrystalCheckResult.flagged(reasons);
        } else if (reasons.size() == 1) {
            return AutoCrystalCheckResult.suspicious(reasons);
        }

        return AutoCrystalCheckResult.clean();
    }

    /**
     * 获取指定玩家周围的最优水晶放置位置列表
     * 供外部调用者预计算位置最优性
     *
     * @param targetX 目标X坐标
     * @param targetZ 目标Z坐标
     * @return 最优水晶位置坐标集合（相对目标的偏移）
     */
    public static Set<String> getOptimalCrystalPositions(double targetX, double targetZ) {
        Set<String> positions = new HashSet<>();
        int[] offsets = {-1, 0, 1};
        for (int ox : offsets) {
            for (int oz : offsets) {
                if (ox == 0 && oz == 0) continue; // 不在目标正中心放置
                // 添加脚部高度和头部高度的最优位置
                positions.add((int) Math.round(targetX + ox) + ",0," + (int) Math.round(targetZ + oz));
                positions.add((int) Math.round(targetX + ox) + ",1," + (int) Math.round(targetZ + oz));
            }
        }
        return positions;
    }

    /**
     * 玩家离线时清理追踪数据
     * @param playerName 离线玩家名称
     */
    public void clearPlayer(String playerName) {
        playerCrystalPlacements.remove(playerName);
        playerCrystalBreaks.remove(playerName);
        playerObsidianPlacements.remove(playerName);
        playerCrystalStats.remove(playerName);
        autoCrystalEvents.remove(playerName);
    }

    /**
     * 获取模块运行状态
     * @return 包含计数器和活跃追踪玩家数的Map
     */
    public Map<String, Object> getStatus() {
        Map<String, Object> status = new LinkedHashMap<>();
        status.put("totalCrystalsPlaced", totalCrystalsPlaced.get());
        status.put("totalCrystalsBroken", totalCrystalsBroken.get());
        status.put("flaggedCount", flaggedCount.get());
        status.put("activeTrackedPlayers", playerCrystalPlacements.size());

        // 列出高频水晶使用者
        List<Map<String, Object>> heavyUsers = new ArrayList<>();
        for (Map.Entry<String, CrystalStats> entry : playerCrystalStats.entrySet()) {
            CrystalStats stats = entry.getValue();
            if (stats.totalPlacements >= 5 || stats.totalDamageEvents >= 3) {
                Map<String, Object> info = new LinkedHashMap<>();
                info.put("player", entry.getKey());
                info.put("crystalsPlaced", stats.totalPlacements);
                info.put("optimalPlacements", stats.optimalPlacements);
                info.put("damageEvents", stats.totalDamageEvents);
                info.put("perfectDamage", stats.perfectDamageCount);
                heavyUsers.add(info);
            }
        }
        heavyUsers.sort((a, b) ->
                Integer.compare((Integer) b.get("crystalsPlaced"), (Integer) a.get("crystalsPlaced")));
        status.put("heavyCrystalUsers", heavyUsers);

        return status;
    }

    /**
     * 内部水晶放置记录
     */
    private static class CrystalPlacement {
        final Instant timestamp;
        final int crystalX, crystalY, crystalZ;
        final String targetName;
        final double targetX, targetY, targetZ;
        final boolean isOptimalPosition;

        CrystalPlacement(Instant timestamp, int crystalX, int crystalY, int crystalZ,
                        String targetName, double targetX, double targetY, double targetZ,
                        boolean isOptimalPosition) {
            this.timestamp = timestamp;
            this.crystalX = crystalX;
            this.crystalY = crystalY;
            this.crystalZ = crystalZ;
            this.targetName = targetName;
            this.targetX = targetX;
            this.targetY = targetY;
            this.targetZ = targetZ;
            this.isOptimalPosition = isOptimalPosition;
        }
    }

    /**
     * 内部水晶引爆记录
     */
    private static class CrystalBreak {
        final Instant timestamp;
        final int crystalX, crystalY, crystalZ;
        final double damageDealt;
        final double targetDistance;

        CrystalBreak(Instant timestamp, int crystalX, int crystalY, int crystalZ,
                    double damageDealt, double targetDistance) {
            this.timestamp = timestamp;
            this.crystalX = crystalX;
            this.crystalY = crystalY;
            this.crystalZ = crystalZ;
            this.damageDealt = damageDealt;
            this.targetDistance = targetDistance;
        }
    }

    /**
     * 内部水晶统计数据
     */
    private static class CrystalStats {
        int totalPlacements = 0;
        int optimalPlacements = 0;
        int totalDamageEvents = 0;
        int perfectDamageCount = 0;
    }

    /**
     * AutoCrystal检测结果 — 不可变结果类
     */
    public static class AutoCrystalCheckResult {
        private final boolean flagged;
        private final boolean suspicious;
        private final List<String> reasons;

        private AutoCrystalCheckResult(boolean flagged, boolean suspicious, List<String> reasons) {
            this.flagged = flagged;
            this.suspicious = suspicious;
            this.reasons = reasons;
        }

        /** 无异常 — 正常的水晶放置和引爆操作 */
        public static AutoCrystalCheckResult clean() {
            return new AutoCrystalCheckResult(false, false, List.of());
        }

        /** 可疑 — 存在快速操作但可能为高水平玩家正常操作 */
        public static AutoCrystalCheckResult suspicious(List<String> reasons) {
            return new AutoCrystalCheckResult(false, true, reasons);
        }

        /** 已标记 — 确定使用了AutoCrystal/CrystalAura hack */
        public static AutoCrystalCheckResult flagged(List<String> reasons) {
            return new AutoCrystalCheckResult(true, false, reasons);
        }

        public boolean isFlagged() { return flagged; }
        public boolean isSuspicious() { return suspicious; }
        public boolean isClean() { return !flagged && !suspicious; }
        public List<String> getReasons() { return reasons; }
    }
}
