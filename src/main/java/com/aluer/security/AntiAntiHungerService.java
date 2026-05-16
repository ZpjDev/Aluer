package com.aluer.security;

import com.aluer.config.ServerGuardConfig;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * 反饥饿消耗（AntiHunger）检测服务 — V5.2 反作弊移动模块
 *
 * 检测原理：
 * 1. 饥饿消耗与活动量不匹配检测 — 正常饥饿值约每40秒消耗1单位（步行），
 *    冲刺时约每10秒消耗1单位，跳跃额外消耗0.05-0.2单位/次。
 *    AntiHunger hack通过伪造onGround=true欺骗服务端跳过饥饿消耗tick。
 * 2. 长时间零消耗检测 — 如果玩家持续高活动量（大量移动、跳跃、冲刺）但
 *    饥饿值在5+分钟内保持不变，标记为AntiHunger。
 * 3. 单位距离饥饿消耗检测 — 正常玩家每移动1000方块消耗约15-25单位饥饿值；
 *    AntiHunger玩家的消耗为0-3单位/1000方块。
 * 4. 跳跃时onGround一致性检测 — hack在跳跃时发送onGround=true来跳过饥饿检查；
 *    服务端可根据Y速度变化自行推断onGround状态，与客户端声称的onGround对比。
 * 5. 冲刺状态与饥饿消耗一致性检测 — 冲刺时饥饿消耗速率是步行的约4倍，
 *    如果长时间冲刺而饥饿值不变，高度可疑。
 *
 * 配置开关：serverguard.security.super-evolution.anti-anti-hunger
 */
@Service
public class AntiAntiHungerService {

    private final ServerGuardConfig config;

    /**
     * 追踪每个玩家的活动/饥饿历史（playerName -> 时间窗口记录列表）
     */
    private final Map<String, List<HungerRecord>> playerHungerHistory = new ConcurrentHashMap<>();

    /**
     * 追踪每个玩家自上次饥饿变化以来的累积活动量
     */
    private final Map<String, PlayerActivity> playerActivitySinceLastHungerChange = new ConcurrentHashMap<>();

    /**
     * 追踪每个玩家当前的食物等级（playerName -> 当前饥饿值）
     */
    private final Map<String, Integer> playerCurrentFoodLevel = new ConcurrentHashMap<>();

    /**
     * 追踪每个玩家最近一次饥饿值变化的时间戳
     */
    private final Map<String, Instant> playerLastHungerChange = new ConcurrentHashMap<>();

    /**
     * 追踪连续onGround=true但Y速度显示应处于空中的tick数
     */
    private final Map<String, Integer> playerGroundSpoofTicks = new ConcurrentHashMap<>();

    private final AtomicLong totalChecks = new AtomicLong(0);
    private final AtomicLong antiHungerViolations = new AtomicLong(0);

    /**
     * 高活动量定义为每分钟移动超过50方块 — 低于此视为低活动量
     */
    private static final double HIGH_ACTIVITY_DISTANCE_PER_MINUTE = 50.0;

    /**
     * 空闲定义 — 每分钟移动少于10方块
     */
    private static final double IDLE_DISTANCE_PER_MINUTE = 10.0;

    /**
     * 零饥饿消耗最大容忍时间（分钟）— 高活动量下超过此时间标记
     */
    private static final int MAX_ZERO_CONSUMPTION_MINUTES = 5;

    /**
     * 正常每1000方块的饥饿消耗范围（单位）
     * 步行：约1000/4.317 ≈ 231秒 ≈ 5.8单位
     * 冲刺：约1000/5.612 ≈ 178秒 ≈ 17.8单位
     * 混合活动：约15-25单位
     */
    private static final double MIN_HUNGER_PER_1000_BLOCKS = 10.0;
    private static final double MAX_HUNGER_PER_1000_BLOCKS = 30.0;
    private static final double SUSPICIOUS_HUNGER_PER_1000_BLOCKS = 5.0;

    /**
     * 每个玩家保留的最大记录数
     */
    private static final int MAX_RECORDS_PER_PLAYER = 120;

    /**
     * 无参构造函数 — 测试/默认配置使用
     */
    public AntiAntiHungerService() {
        this(new ServerGuardConfig());
    }

    /**
     * Spring 注入构造函数
     * @param config 全局配置，提供模块开关控制
     */
    public AntiAntiHungerService(ServerGuardConfig config) {
        this.config = config;
    }

    /**
     * 检测玩家是否使用AntiHunger hack绕过饥饿消耗
     *
     * @param playerName       玩家名称
     * @param playerUUID       玩家UUID
     * @param foodLevel        玩家当前食物等级（0-20）
     * @param isSprinting      玩家是否在冲刺
     * @param isJumping        玩家是否在跳跃（当前tick Y速度为正）
     * @param clientOnGround   客户端声称的onGround状态
     * @param serverCalcOnGround 服务端计算的onGround状态（基于Y坐标/碰撞检测）
     * @param fromX            移动起始X
     * @param fromY            移动起始Y
     * @param fromZ            移动起始Z
     * @param toX              移动结束X
     * @param toY              移动结束Y
     * @param toZ              移动结束Z
     * @param deltaSeconds     本tick时间间隔（秒）
     * @param timestamp        时间戳
     * @return 检测结果
     */
    public AntiHungerCheckResult detect(String playerName, String playerUUID,
                                         int foodLevel, boolean isSprinting, boolean isJumping,
                                         boolean clientOnGround, boolean serverCalcOnGround,
                                         double fromX, double fromY, double fromZ,
                                         double toX, double toY, double toZ,
                                         double deltaSeconds, Instant timestamp) {
        // 模块开关检查 — 关闭时跳过所有检测
        if (!config.getSecurity().getSuperEvolution().isAntiAntiHunger()) {
            return AntiHungerCheckResult.clean();
        }

        totalChecks.incrementAndGet();

        // 计算水平移动距离
        double dx = toX - fromX;
        double dz = toZ - fromZ;
        double horizontalDist = Math.sqrt(dx * dx + dz * dz);

        List<HungerRecord> history = playerHungerHistory.computeIfAbsent(
                playerName, k -> new ArrayList<>());

        HungerRecord record = new HungerRecord(timestamp, foodLevel, isSprinting,
                isJumping, clientOnGround, serverCalcOnGround, horizontalDist, deltaSeconds);
        history.add(record);
        while (history.size() > MAX_RECORDS_PER_PLAYER) {
            history.remove(0);
        }

        List<String> reasons = new ArrayList<>();

        // ─── 检测1：饥饿值变化追踪 — 检测长时间零消耗 ───
        Integer previousFood = playerCurrentFoodLevel.get(playerName);
        if (previousFood != null && previousFood != foodLevel) {
            // 饥饿值发生了变化 — 重置活动量追踪
            playerActivitySinceLastHungerChange.remove(playerName);
            playerLastHungerChange.put(playerName, timestamp);
        }
        playerCurrentFoodLevel.put(playerName, foodLevel);

        // 初始化或更新活动量追踪
        PlayerActivity activity = playerActivitySinceLastHungerChange.computeIfAbsent(
                playerName, k -> new PlayerActivity(timestamp));
        activity.addDistance(horizontalDist);
        if (isJumping) activity.incrementJumps();
        if (isSprinting) activity.addSprintTime(deltaSeconds);
        activity.lastUpdate = timestamp;

        // 检查自上次饥饿变化以来的时间
        Instant lastChange = playerLastHungerChange.get(playerName);
        if (lastChange == null) {
            lastChange = timestamp;
            playerLastHungerChange.put(playerName, timestamp);
        }

        long secondsSinceChange = (timestamp.toEpochMilli() - lastChange.toEpochMilli()) / 1000;
        double minutesSinceChange = secondsSinceChange / 60.0;

        if (minutesSinceChange >= MAX_ZERO_CONSUMPTION_MINUTES
                && activity.totalDistance > (HIGH_ACTIVITY_DISTANCE_PER_MINUTE * minutesSinceChange)) {
            // 高活动量 + 长时间零饥饿消耗 → AntiHunger
            reasons.add("ZERO_CONSUMPTION_HIGH_ACTIVITY: food level unchanged ("
                    + foodLevel + ") for " + String.format("%.1f", minutesSinceChange)
                    + " minutes despite " + String.format("%.0f", activity.totalDistance)
                    + " blocks moved, " + activity.totalJumps
                    + " jumps, " + String.format("%.1f", activity.totalSprintSeconds)
                    + "s sprinting");
            antiHungerViolations.incrementAndGet();
        } else if (minutesSinceChange >= MAX_ZERO_CONSUMPTION_MINUTES
                && activity.totalDistance > (IDLE_DISTANCE_PER_MINUTE * minutesSinceChange)) {
            // 中等活动量 + 长时间无消耗 — 可疑
            reasons.add("ZERO_CONSUMPTION_MODERATE_ACTIVITY: food level unchanged for "
                    + String.format("%.1f", minutesSinceChange) + " min, "
                    + String.format("%.0f", activity.totalDistance) + " blocks moved");
        }

        // ─── 检测2：每千方块饥饿消耗率 ───
        if (history.size() >= 30) {
            // 取最近30条记录分析
            int recentCount = Math.min(30, history.size());
            double recentTotalDist = 0;
            int firstFood = -1;
            int lastFood = -1;

            for (int i = history.size() - recentCount; i < history.size(); i++) {
                HungerRecord hr = history.get(i);
                recentTotalDist += hr.horizontalDist;
                if (firstFood < 0) firstFood = hr.foodLevel;
                lastFood = hr.foodLevel;
            }

            if (recentTotalDist > 100 && firstFood > 0 && lastFood > 0) {
                int hungerConsumed = Math.max(0, firstFood - lastFood);
                double hungerPer1000 = (hungerConsumed / recentTotalDist) * 1000.0;

                if (hungerPer1000 < SUSPICIOUS_HUNGER_PER_1000_BLOCKS && hungerConsumed <= 2
                        && recentTotalDist > 500) {
                    reasons.add("LOW_HUNGER_PER_DISTANCE: " + String.format("%.1f", hungerPer1000)
                            + " hunger consumed per 1000 blocks (normal: "
                            + String.format("%.0f", MIN_HUNGER_PER_1000_BLOCKS) + "-"
                            + String.format("%.0f", MAX_HUNGER_PER_1000_BLOCKS)
                            + ", suspicious threshold: <"
                            + String.format("%.1f", SUSPICIOUS_HUNGER_PER_1000_BLOCKS) + ")");
                }
            }
        }

        // ─── 检测3：onGround伪造检测 — 客户端声称在地面但服务端计算显示应在空中 ───
        if (clientOnGround && !serverCalcOnGround && isJumping) {
            int spoofTicks = playerGroundSpoofTicks.getOrDefault(playerName, 0) + 1;
            playerGroundSpoofTicks.put(playerName, spoofTicks);

            if (spoofTicks >= 5) {
                reasons.add("GROUND_SPOOF_HUNGER: client claims onGround=true while "
                        + "server indicates airborne for " + spoofTicks
                        + " consecutive ticks (used to skip hunger ticks)");
            }
        } else if (!clientOnGround || !isJumping) {
            // 不在跳跃或客户端正确报告了空中状态，重置计数
            Integer spoofTicks = playerGroundSpoofTicks.remove(playerName);
            // 保留最近有ground spoof的记录作为证据
            if (spoofTicks != null && spoofTicks >= 3) {
                reasons.add("GROUND_SPOOF_PATTERN: " + spoofTicks
                        + " tick ground spoof burst ended");
            }
        }

        // ─── 检测4：冲刺时间与饥饿消耗比率 ───
        if (activity.totalSprintSeconds > 120 && minutesSinceChange >= 3
                && activity.totalDistance > 500) {
            // 冲刺超过2分钟，距离超过500方块，饥饿值未变化
            double sprintMinutes = activity.totalSprintSeconds / 60.0;
            // 纯冲刺下预期消耗约6单位/分钟
            double expectedConsumption = sprintMinutes * 6.0;
            if (expectedConsumption >= 10.0) {
                reasons.add("SPRINT_NO_HUNGER_DRAIN: "
                        + String.format("%.1f", sprintMinutes)
                        + " minutes of sprinting with zero food level change"
                        + " (expected ~" + String.format("%.0f", expectedConsumption)
                        + " units consumed)");
                antiHungerViolations.incrementAndGet();
            }
        }

        if (reasons.size() >= 2) {
            return AntiHungerCheckResult.flagged(reasons);
        } else if (reasons.size() == 1) {
            return AntiHungerCheckResult.suspicious(reasons);
        }

        return AntiHungerCheckResult.clean();
    }

    /**
     * 玩家离线时清理追踪数据
     * @param playerName 离线玩家名称
     */
    public void clearPlayer(String playerName) {
        playerHungerHistory.remove(playerName);
        playerActivitySinceLastHungerChange.remove(playerName);
        playerCurrentFoodLevel.remove(playerName);
        playerLastHungerChange.remove(playerName);
        playerGroundSpoofTicks.remove(playerName);
    }

    /**
     * 获取模块运行状态
     * @return 包含计数器和违规数量的Map
     */
    public Map<String, Object> getStatus() {
        Map<String, Object> status = new LinkedHashMap<>();
        status.put("totalChecks", totalChecks.get());
        status.put("antiHungerViolations", antiHungerViolations.get());
        status.put("activeTrackedPlayers", playerHungerHistory.size());

        // 列出长时间零消耗的玩家
        List<Map<String, Object>> zeroConsumptionPlayers = new ArrayList<>();
        for (Map.Entry<String, PlayerActivity> entry : playerActivitySinceLastHungerChange.entrySet()) {
            PlayerActivity act = entry.getValue();
            if (act.totalDistance > 200) {
                Map<String, Object> info = new LinkedHashMap<>();
                info.put("player", entry.getKey());
                info.put("distanceSinceChange", String.format("%.0f", act.totalDistance));
                info.put("jumpsSinceChange", act.totalJumps);
                info.put("sprintSeconds", String.format("%.1f", act.totalSprintSeconds));
                zeroConsumptionPlayers.add(info);
            }
        }
        status.put("zeroConsumptionSuspects", zeroConsumptionPlayers);
        return status;
    }

    /**
     * 内部饥饿记录 — 记录玩家单tick的活动和饥饿状态
     */
    private static class HungerRecord {
        final Instant timestamp;
        final int foodLevel;
        final boolean isSprinting;
        final boolean isJumping;
        final boolean clientOnGround;
        final boolean serverCalcOnGround;
        final double horizontalDist;
        final double deltaSeconds;

        HungerRecord(Instant timestamp, int foodLevel, boolean isSprinting,
                     boolean isJumping, boolean clientOnGround, boolean serverCalcOnGround,
                     double horizontalDist, double deltaSeconds) {
            this.timestamp = timestamp;
            this.foodLevel = foodLevel;
            this.isSprinting = isSprinting;
            this.isJumping = isJumping;
            this.clientOnGround = clientOnGround;
            this.serverCalcOnGround = serverCalcOnGround;
            this.horizontalDist = horizontalDist;
            this.deltaSeconds = deltaSeconds;
        }
    }

    /**
     * 内部玩家活动追踪 — 累积自上次饥饿值变化以来的活动量
     */
    private static class PlayerActivity {
        double totalDistance = 0;
        int totalJumps = 0;
        double totalSprintSeconds = 0;
        Instant startTime;
        Instant lastUpdate;

        PlayerActivity(Instant startTime) {
            this.startTime = startTime;
            this.lastUpdate = startTime;
        }

        void addDistance(double dist) { this.totalDistance += dist; }
        void incrementJumps() { this.totalJumps++; }
        void addSprintTime(double seconds) { this.totalSprintSeconds += seconds; }
    }

    /**
     * AntiHunger检测结果 — 不可变结果类
     */
    public static class AntiHungerCheckResult {
        private final boolean flagged;
        private final boolean suspicious;
        private final List<String> reasons;

        private AntiHungerCheckResult(boolean flagged, boolean suspicious, List<String> reasons) {
            this.flagged = flagged;
            this.suspicious = suspicious;
            this.reasons = reasons;
        }

        /** 无异常 — 正常的饥饿消耗速率 */
        public static AntiHungerCheckResult clean() {
            return new AntiHungerCheckResult(false, false, List.of());
        }

        /** 可疑 — 饥饿消耗略低但活动量不足以完全确认 */
        public static AntiHungerCheckResult suspicious(List<String> reasons) {
            return new AntiHungerCheckResult(false, true, reasons);
        }

        /** 已标记 — 确认AntiHunger hack，高活动量零饥饿消耗 */
        public static AntiHungerCheckResult flagged(List<String> reasons) {
            return new AntiHungerCheckResult(true, false, reasons);
        }

        public boolean isFlagged() { return flagged; }
        public boolean isSuspicious() { return suspicious; }
        public boolean isClean() { return !flagged && !suspicious; }
        public List<String> getReasons() { return reasons; }
    }
}
