package com.aluer.anticheat.movement;

import com.aluer.config.ServerGuardConfig;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * 无减速（NoSlow）检测服务 — V5.2 反作弊移动模块
 *
 * 检测原理：
 * 1. 物品使用时移速检测 — Minecraft中玩家在使用物品（吃食物、拉弓、举盾、喝药水）时
 *    会强制减速至潜行速度（约1.31 m/s）。NoSlow hack通过取消物品使用减速封包，
 *    使玩家在使用物品时仍能全速移动。
 * 2. 按物品类型设定速度阈值 — 不同类型的物品使用有不同的预期速度上限：
 *    吃食物（1.5 m/s）、拉弓（1.2 m/s）、举盾（0.8 m/s）、喝药水（1.5 m/s）、
 *    吃东西（1.5 m/s）。超过对应阈值即标记。
 * 3. 连续tick检测 — 区分偶发的网络延迟导致的瞬间速度尖峰和持续性的作弊行为，
 *    要求连续多tick同时"使用物品+高速移动"才判定为作弊。
 * 4. 使用状态交叉验证 — 结合玩家"正在使用物品"状态与Agent上报的移动速度数据，
 *    精准判断玩家是否在使用物品的同时快速移动。
 *
 * 配置开关：serverguard.security.super-evolution.anti-no-slow
 */
@Service
public class AntiNoSlowService {

    private final ServerGuardConfig config;

    /**
     * 追踪每个玩家的物品使用历史记录（playerName -> 使用记录列表）
     */
    private final Map<String, List<ItemUseRecord>> playerUseHistory = new ConcurrentHashMap<>();

    /**
     * 追踪每个玩家连续违规tick计数（playerName -> 连续违规次数）
     * 用于区分瞬时延迟与持续作弊
     */
    private final Map<String, Integer> playerViolationTicks = new ConcurrentHashMap<>();

    /**
     * 追踪每个玩家当前正在使用的物品类型（playerName -> 物品类型描述）
     */
    private final Map<String, String> playerActiveItem = new ConcurrentHashMap<>();

    private final AtomicLong totalChecks = new AtomicLong(0);
    private final AtomicLong noSlowViolations = new AtomicLong(0);

    /**
     * 各物品类型在使用时的最大合法水平速度（m/s）
     * 正常使用物品时玩家被强制减速至潜行速度约1.31 m/s
     */
    private static final double MAX_EATING_SPEED = 1.5;
    private static final double MAX_BOW_DRAW_SPEED = 1.2;
    private static final double MAX_SHIELD_BLOCK_SPEED = 0.8;
    private static final double MAX_POTION_DRINK_SPEED = 1.5;
    private static final double MAX_FOOD_EAT_SPEED = 1.5;
    private static final double MAX_DEFAULT_ITEM_USE_SPEED = 1.3;

    /**
     * 正常步行速度的60%阈值 — 用于快速判断
     * Minecraft步行速度约4.317 m/s，60%约2.59 m/s
     */
    private static final double WALK_SPEED_60_PERCENT = 2.59;

    /**
     * 连续违规tick阈值 — 需要连续超过此tick数才判定为作弊
     * 低于此值可能是网络延迟导致的数据包积压释放
     */
    private static final int MIN_CONSECUTIVE_VIOLATION_TICKS = 5;

    /**
     * 每个玩家保留的最大记录数
     */
    private static final int MAX_RECORDS_PER_PLAYER = 40;

    /**
     * 无参构造函数 — 测试/默认配置使用
     */
    public AntiNoSlowService() {
        this(new ServerGuardConfig());
    }

    /**
     * Spring 注入构造函数
     * @param config 全局配置，提供模块开关控制
     */
    public AntiNoSlowService(ServerGuardConfig config) {
        this.config = config;
    }

    /**
     * 检测玩家是否在使用物品时维持异常高速（NoSlow hack）
     *
     * @param playerName   玩家名称
     * @param playerUUID   玩家UUID
     * @param isUsingItem  玩家是否正在使用物品（右键按住）
     * @param itemType     正在使用的物品类型（EATING, BOW, SHIELD, POTION, FOOD, OTHER）
     * @param fromX        移动起始X坐标
     * @param fromZ        移动起始Z坐标
     * @param toX          移动结束X坐标
     * @param toZ          移动结束Z坐标
     * @param deltaSeconds 本次移动时间间隔（秒）
     * @param timestamp    时间戳
     * @return 检测结果
     */
    public NoSlowCheckResult detect(String playerName, String playerUUID,
                                     boolean isUsingItem, String itemType,
                                     double fromX, double fromZ,
                                     double toX, double toZ,
                                     double deltaSeconds, Instant timestamp) {
        // 模块开关检查 — 关闭时跳过所有检测
        if (!config.getSecurity().getSuperEvolution().isAntiNoSlow()) {
            return NoSlowCheckResult.clean();
        }

        totalChecks.incrementAndGet();

        // 玩家当前未使用物品，无需检测，重置违规计数
        if (!isUsingItem) {
            playerViolationTicks.remove(playerName);
            playerActiveItem.remove(playerName);
            return NoSlowCheckResult.clean();
        }

        // 更新当前使用的物品类型
        playerActiveItem.put(playerName, itemType != null ? itemType : "OTHER");

        List<ItemUseRecord> history = playerUseHistory.computeIfAbsent(
                playerName, k -> new ArrayList<>());

        // 避免除零 — 默认50ms（1 tick）
        if (deltaSeconds <= 0) {
            deltaSeconds = 0.05;
        }

        // 计算XZ平面水平速度
        double dx = toX - fromX;
        double dz = toZ - fromZ;
        double horizontalDistance = Math.sqrt(dx * dx + dz * dz);
        double horizontalSpeed = horizontalDistance / deltaSeconds;

        // 根据物品类型确定速度阈值
        double speedThreshold = getItemSpeedThreshold(itemType);

        ItemUseRecord record = new ItemUseRecord(timestamp, itemType,
                horizontalSpeed, horizontalDistance, deltaSeconds);
        history.add(record);
        while (history.size() > MAX_RECORDS_PER_PLAYER) {
            history.remove(0);
        }

        List<String> reasons = new ArrayList<>();

        // 1. 核心检测：使用物品时水平速度超过对应物品类型阈值
        if (horizontalSpeed > speedThreshold) {
            // 累加违规tick计数
            int violationTicks = playerViolationTicks.getOrDefault(playerName, 0) + 1;
            playerViolationTicks.put(playerName, violationTicks);

            // 超过连续阈值才判定为作弊
            if (violationTicks >= MIN_CONSECUTIVE_VIOLATION_TICKS) {
                noSlowViolations.incrementAndGet();
                reasons.add("SUSTAINED_NOSLOW: " + String.format("%.2f", horizontalSpeed)
                        + " m/s while using " + itemType.toLowerCase()
                        + " for " + violationTicks + " consecutive ticks"
                        + " (threshold: " + String.format("%.2f", speedThreshold) + " m/s)");
            }
        } else {
            // 速度正常，重置违规计数
            playerViolationTicks.remove(playerName);
        }

        // 2. 快速筛查：使用物品时速度超过步行速度60%
        if (horizontalSpeed > WALK_SPEED_60_PERCENT) {
            int violationTicks = playerViolationTicks.getOrDefault(playerName, 0);
            if (violationTicks >= MIN_CONSECUTIVE_VIOLATION_TICKS) {
                reasons.add("HIGH_SPEED_ITEM_USE: " + String.format("%.2f", horizontalSpeed)
                        + " m/s (" + String.format("%.0f", (horizontalSpeed / 4.317) * 100)
                        + "% of walk speed) while using " + itemType.toLowerCase());
            }
        }

        // 3. 使用模式分析 — 检测高频使用+高速移动的组合模式
        if (history.size() >= 10) {
            long highSpeedWhileUsing = history.stream()
                    .filter(r -> r.horizontalSpeed > speedThreshold)
                    .count();
            double highSpeedRatio = (double) highSpeedWhileUsing / history.size();

            // 如果超过70%的使用物品时间都处于高速移动，高度可疑
            if (highSpeedRatio > 0.7 && history.size() >= 10) {
                reasons.add("PATTERN_HIGH_SPEED_USE: "
                        + String.format("%.0f", highSpeedRatio * 100)
                        + "% of item use ticks at high speed ("
                        + highSpeedWhileUsing + "/" + history.size() + " ticks)");
            }
        }

        if (reasons.size() >= 2) {
            return NoSlowCheckResult.flagged(reasons);
        } else if (reasons.size() == 1) {
            return NoSlowCheckResult.suspicious(reasons);
        }

        return NoSlowCheckResult.clean();
    }

    /**
     * 根据物品类型返回对应的速度阈值
     *
     * @param itemType 物品类型字符串
     * @return 该物品类型允许的最大水平速度（m/s）
     */
    private double getItemSpeedThreshold(String itemType) {
        if (itemType == null) return MAX_DEFAULT_ITEM_USE_SPEED;
        return switch (itemType.toUpperCase()) {
            case "EATING" -> MAX_EATING_SPEED;
            case "BOW" -> MAX_BOW_DRAW_SPEED;
            case "SHIELD" -> MAX_SHIELD_BLOCK_SPEED;
            case "POTION" -> MAX_POTION_DRINK_SPEED;
            case "FOOD" -> MAX_FOOD_EAT_SPEED;
            default -> MAX_DEFAULT_ITEM_USE_SPEED;
        };
    }

    /**
     * 玩家离线时清理追踪数据
     * @param playerName 离线玩家名称
     */
    public void clearPlayer(String playerName) {
        playerUseHistory.remove(playerName);
        playerViolationTicks.remove(playerName);
        playerActiveItem.remove(playerName);
    }

    /**
     * 获取模块运行状态
     * @return 包含计数器和违规数量的Map
     */
    public Map<String, Object> getStatus() {
        Map<String, Object> status = new LinkedHashMap<>();
        status.put("totalChecks", totalChecks.get());
        status.put("noSlowViolations", noSlowViolations.get());
        status.put("activeTrackedPlayers", playerUseHistory.size());
        status.put("playersInViolation", playerViolationTicks.size());

        // 列出当前正在使用物品的玩家
        List<Map<String, String>> usingPlayers = new ArrayList<>();
        for (Map.Entry<String, String> entry : playerActiveItem.entrySet()) {
            Map<String, String> info = new LinkedHashMap<>();
            info.put("player", entry.getKey());
            info.put("item", entry.getValue());
            info.put("violationTicks", String.valueOf(
                    playerViolationTicks.getOrDefault(entry.getKey(), 0)));
            usingPlayers.add(info);
        }
        status.put("activeItemUsers", usingPlayers);
        return status;
    }

    /**
     * 内部物品使用记录 — 记录玩家使用物品时的移动信息
     */
    private static class ItemUseRecord {
        final Instant timestamp;
        final String itemType;
        final double horizontalSpeed;
        final double horizontalDistance;
        final double deltaSeconds;

        ItemUseRecord(Instant timestamp, String itemType,
                      double horizontalSpeed, double horizontalDistance,
                      double deltaSeconds) {
            this.timestamp = timestamp;
            this.itemType = itemType;
            this.horizontalSpeed = horizontalSpeed;
            this.horizontalDistance = horizontalDistance;
            this.deltaSeconds = deltaSeconds;
        }
    }

    /**
     * NoSlow检测结果 — 不可变结果类
     */
    public static class NoSlowCheckResult {
        private final boolean flagged;
        private final boolean suspicious;
        private final List<String> reasons;

        private NoSlowCheckResult(boolean flagged, boolean suspicious, List<String> reasons) {
            this.flagged = flagged;
            this.suspicious = suspicious;
            this.reasons = reasons;
        }

        /** 无异常 — 正常使用物品并减速 */
        public static NoSlowCheckResult clean() {
            return new NoSlowCheckResult(false, false, List.of());
        }

        /** 可疑 — 短暂超速但不足够确认为NoSlow hack */
        public static NoSlowCheckResult suspicious(List<String> reasons) {
            return new NoSlowCheckResult(false, true, reasons);
        }

        /** 已标记 — 确认NoSlow hack，持续在使用物品时高速移动 */
        public static NoSlowCheckResult flagged(List<String> reasons) {
            return new NoSlowCheckResult(true, false, reasons);
        }

        public boolean isFlagged() { return flagged; }
        public boolean isSuspicious() { return suspicious; }
        public boolean isClean() { return !flagged && !suspicious; }
        public List<String> getReasons() { return reasons; }
    }
}
