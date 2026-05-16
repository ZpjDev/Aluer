package com.aluer.security;

import com.aluer.config.ServerGuardConfig;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * 自动暴击（Criticals）检测服务 — V5.1 反作弊战斗模块
 *
 * 检测原理：
 * 1. 暴击条件验证 — Minecraft中合法暴击需要满足：玩家处于下落状态（Y速度<0）、
 *    不在水/岩浆中、不在梯子上、未被致盲、攻击冷却>=84.8%。
 *    攻击事件时检查这些条件，任何一项不满足的暴击都是作弊。
 * 2. 零速度暴击检测 — 如果玩家Y速度为零（静止在地面）且声称暴击，这是不可能发生的。
 *    合法暴击必须在跳跃下落过程中触发，静止状态下无法产生暴击。
 *    这是最可靠的检测指标：地面+Y速度为零+暴击 = 确定作弊。
 * 3. 暴击率追踪 — 追踪每个玩家的暴击攻击占比。
 *    正常玩家：5-20%的攻击为暴击（需要跳跃操作）。黑客：80-100%的攻击为暴击。
 *    如果玩家暴击率超过60%且从未检测到跳跃行为，则标记。
 * 4. 无跳跃暴击模式 — 追踪玩家在攻击前的Y坐标变化。如果玩家从未经历Y上升>0.3，
 *    但持续产生暴击，说明客户端伪造了暴击状态。将跳跃检测与暴击事件进行关联分析。
 *
 * 配置开关：serverguard.security.super-evolution.anti-criticals
 */
@Service
public class AntiCriticalsService {

    private final ServerGuardConfig config;

    /**
     * 追踪每个玩家的暴击统计（playerName -> 暴击/攻击统计数据）
     */
    private final Map<String, CriticalStats> playerCriticalStats = new ConcurrentHashMap<>();

    /**
     * 追踪每个玩家攻击前的Y坐标历史（playerName -> Y坐标记录列表）
     * 用于判断玩家在攻击前是否进行了跳跃操作
     */
    private final Map<String, List<Double>> playerYHistory = new ConcurrentHashMap<>();

    /**
     * 追踪每个玩家最近是否检测到跳跃行为（playerName -> 最后跳跃时间）
     */
    private final Map<String, Instant> playerLastJump = new ConcurrentHashMap<>();

    /**
     * 追踪疑似暴击作弊的事件（playerName -> 可疑事件列表）
     */
    private final Map<String, List<Map<String, Object>>> criticalEvents = new ConcurrentHashMap<>();

    private final AtomicLong totalAttacks = new AtomicLong(0);
    private final AtomicLong totalCriticals = new AtomicLong(0);
    private final AtomicLong flaggedCount = new AtomicLong(0);

    /**
     * 合法暴击所需的最小攻击冷却百分比
     * Minecraft中满蓄力攻击（100%冷却）方可触发暴击，服务器最低容忍84.8%
     */
    private static final double MIN_COOLDOWN_FOR_CRITICAL = 84.8;

    /**
     * 判定为"零速度暴击"的Y速度阈值（m/s）
     * 如果Y速度绝对值小于此值，认为玩家在垂直方向静止
     */
    private static final double ZERO_VELOCITY_THRESHOLD = 0.02;

    /**
     * 跳跃检测的Y上升阈值（方块）— 如果Y坐标在短时间内上升超过此值，认为发生了跳跃
     */
    private static final double JUMP_Y_THRESHOLD = 0.3;

    /**
     * 异常暴击率阈值 — 超过此比例的攻击是暴击则标记
     * 正常玩家暴击率通常低于20%，作弊玩家可达80-100%
     */
    private static final double ABNORMAL_CRITICAL_RATIO = 0.60;

    /**
     * 暴击率检测所需最小攻击样本数
     */
    private static final int MIN_ATTACK_SAMPLE = 20;

    /**
     * 每个玩家保留的最大Y坐标记录数
     */
    private static final int MAX_Y_RECORDS = 30;

    /**
     * 跳跃窗口时间（毫秒）— 攻击前在此时间窗口内检测跳跃
     */
    private static final long JUMP_WINDOW_MS = 500;

    /**
     * 无参构造函数 — 测试/默认配置使用
     */
    public AntiCriticalsService() {
        this(new ServerGuardConfig());
    }

    /**
     * Spring 注入构造函数
     * @param config 全局配置，提供模块开关控制
     */
    public AntiCriticalsService(ServerGuardConfig config) {
        this.config = config;
    }

    /**
     * 检测玩家攻击是否为作弊暴击
     *
     * @param playerName 玩家名称
     * @param playerUUID 玩家UUID
     * @param isCriticalHit 客户端是否报告为暴击
     * @param attackCooldown 攻击冷却百分比（0-100）
     * @param playerYVelocity 玩家当前Y方向速度（负值表示下落）
     * @param isOnGround 玩家是否在地面
     * @param isInLiquid 玩家是否在水中或岩浆中
     * @param isOnLadder 玩家是否在梯子上
     * @param isBlinded 玩家是否有失明效果
     * @param currentY 玩家当前Y坐标
     * @param timestamp 时间戳
     * @return 检测结果
     */
    public CriticalsCheckResult detect(String playerName, String playerUUID,
                                        boolean isCriticalHit, double attackCooldown,
                                        double playerYVelocity, boolean isOnGround,
                                        boolean isInLiquid, boolean isOnLadder,
                                        boolean isBlinded, double currentY, Instant timestamp) {
        // 模块开关检查 — 关闭时跳过所有检测直接返回安全结果
        if (!config.getSecurity().getSuperEvolution().isAntiCriticals()) {
            return CriticalsCheckResult.clean();
        }

        totalAttacks.incrementAndGet();
        List<String> reasons = new ArrayList<>();

        // 更新玩家Y坐标历史（用于跳跃检测）
        List<Double> yHistory = playerYHistory.computeIfAbsent(
                playerName, k -> new ArrayList<>());
        yHistory.add(currentY);
        while (yHistory.size() > MAX_Y_RECORDS) {
            yHistory.remove(0);
        }

        // 更新暴击统计数据
        CriticalStats stats = playerCriticalStats.computeIfAbsent(
                playerName, k -> new CriticalStats());

        if (isCriticalHit) {
            totalCriticals.incrementAndGet();
            stats.totalCriticals++;
        }
        stats.totalAttacks++;

        // 仅对暴击事件进行深入检测
        if (!isCriticalHit) {
            return CriticalsCheckResult.clean();
        }

        // 1. 基本条件验证 — 检查Minecraft暴击的硬性条件
        // 攻击冷却不足 — 无法产生暴击
        if (attackCooldown < MIN_COOLDOWN_FOR_CRITICAL) {
            reasons.add("COOLDOWN_VIOLATION: critical with " + String.format("%.1f", attackCooldown)
                    + "% cooldown (minimum: " + String.format("%.1f", MIN_COOLDOWN_FOR_CRITICAL) + "%)");
        }

        // 在水或岩浆中 — 不可能产生暴击
        if (isInLiquid) {
            reasons.add("LIQUID_VIOLATION: critical in water/lava (impossible)");
        }

        // 在梯子上 — 不可能产生暴击
        if (isOnLadder) {
            reasons.add("LADDER_VIOLATION: critical on ladder (impossible)");
        }

        // 失明状态 — 不能产生暴击
        if (isBlinded) {
            reasons.add("BLIND_VIOLATION: critical while blinded (impossible)");
        }

        // 2. 零速度暴击检测 — 核心检测指标
        // 合法暴击必须在下落过程中触发，Y速度必须为负值（向下运动）
        // 如果玩家静止在地面上且Y速度为零，暴击是确定性的作弊行为
        boolean isZeroVelocity = Math.abs(playerYVelocity) < ZERO_VELOCITY_THRESHOLD;

        if (isZeroVelocity && isOnGround) {
            reasons.add("ZERO_VELOCITY_CRITICAL: critical with Y velocity="
                    + String.format("%.3f", playerYVelocity) + " (must be falling)");
        }

        // 上升中的暴击也是不可能的（Y速度为正）
        if (playerYVelocity > ZERO_VELOCITY_THRESHOLD) {
            reasons.add("RISING_CRITICAL: critical while moving upward (velocity="
                    + String.format("%.3f", playerYVelocity) + ", must be falling)");
        }

        // 3. 跳跃检测 — 检查玩家在攻击前是否跳跃过
        // 记录Y坐标上升超过阈值的事件为跳跃
        boolean recentlyJumped = false;
        if (yHistory.size() >= 3) {
            // 检查最近几次Y值变化，判断是否有向上跳跃
            for (int i = Math.max(0, yHistory.size() - 5); i < yHistory.size() - 1; i++) {
                double yChange = yHistory.get(i + 1) - yHistory.get(i);
                if (yChange > JUMP_Y_THRESHOLD) {
                    playerLastJump.put(playerName, timestamp);
                    recentlyJumped = true;
                    break;
                }
            }
        }

        // 检查是否在跳跃窗口内有跳跃记录
        if (!recentlyJumped) {
            Instant lastJumpTime = playerLastJump.get(playerName);
            if (lastJumpTime != null) {
                long timeSinceJump = timestamp.toEpochMilli() - lastJumpTime.toEpochMilli();
                recentlyJumped = timeSinceJump <= JUMP_WINDOW_MS;
            }
        }

        // 4. 暴击率追踪 — 检测异常高的暴击比例
        if (stats.totalAttacks >= MIN_ATTACK_SAMPLE) {
            double criticalRatio = (double) stats.totalCriticals / stats.totalAttacks;

            if (criticalRatio >= ABNORMAL_CRITICAL_RATIO) {
                // 高暴击率 + 无跳跃记录 = 几乎确定作弊
                if (!recentlyJumped && playerLastJump.get(playerName) == null) {
                    reasons.add("HIGH_CRITICAL_RATIO_NO_JUMPS: " + String.format("%.0f", criticalRatio * 100)
                            + "% critical rate with no detected jumps ("
                            + stats.totalCriticals + "/" + stats.totalAttacks + " attacks)");
                } else if (criticalRatio >= 0.80) {
                    // 极高暴击率即使有跳跃也异常（正常玩家做不到接近100%暴击）
                    reasons.add("EXTREME_CRITICAL_RATIO: " + String.format("%.0f", criticalRatio * 100)
                            + "% critical rate (" + stats.totalCriticals + "/" + stats.totalAttacks + " attacks)");
                }
            }
        }

        // 记录可疑暴击事件
        if (!reasons.isEmpty()) {
            List<Map<String, Object>> events = criticalEvents.computeIfAbsent(
                    playerName, k -> new ArrayList<>());
            Map<String, Object> event = new LinkedHashMap<>();
            event.put("time", timestamp.toString());
            event.put("yVelocity", String.format("%.3f", playerYVelocity));
            event.put("onGround", isOnGround);
            event.put("cooldown", String.format("%.1f", attackCooldown));
            event.put("reasons", reasons);
            events.add(event);
            while (events.size() > 20) {
                events.remove(0);
            }
        }

        // 汇总结果
        if (reasons.size() >= 2) {
            // 多种检测规则同时命中 — 高度可疑
            flaggedCount.incrementAndGet();
            return CriticalsCheckResult.flagged(reasons);
        } else if (reasons.size() == 1) {
            // 单一规则命中 — 仅标记为可疑
            return CriticalsCheckResult.suspicious(reasons);
        }

        return CriticalsCheckResult.clean();
    }

    /**
     * 玩家离线时清理追踪数据，释放内存
     * @param playerName 离线玩家名称
     */
    public void clearPlayer(String playerName) {
        playerCriticalStats.remove(playerName);
        playerYHistory.remove(playerName);
        playerLastJump.remove(playerName);
        criticalEvents.remove(playerName);
    }

    /**
     * 获取模块运行状态
     * @return 包含计数器和活跃追踪玩家数的Map
     */
    public Map<String, Object> getStatus() {
        Map<String, Object> status = new LinkedHashMap<>();
        status.put("totalAttacks", totalAttacks.get());
        status.put("totalCriticals", totalCriticals.get());
        status.put("flaggedCount", flaggedCount.get());
        status.put("activeTrackedPlayers", playerCriticalStats.size());

        // 计算全局暴击率
        long totalA = totalAttacks.get();
        long totalC = totalCriticals.get();
        if (totalA > 0) {
            status.put("globalCriticalRatio", String.format("%.1f%%",
                    100.0 * totalC / totalA));
        }

        // 列出高暴击率玩家
        List<Map<String, Object>> highRatioPlayers = new ArrayList<>();
        for (Map.Entry<String, CriticalStats> entry : playerCriticalStats.entrySet()) {
            CriticalStats stats = entry.getValue();
            if (stats.totalAttacks >= MIN_ATTACK_SAMPLE) {
                double ratio = (double) stats.totalCriticals / stats.totalAttacks;
                if (ratio >= ABNORMAL_CRITICAL_RATIO) {
                    Map<String, Object> info = new LinkedHashMap<>();
                    info.put("player", entry.getKey());
                    info.put("criticalRatio", String.format("%.1f%%", ratio * 100));
                    info.put("criticals", stats.totalCriticals);
                    info.put("attacks", stats.totalAttacks);
                    highRatioPlayers.add(info);
                }
            }
        }
        highRatioPlayers.sort((a, b) -> {
            String ra = (String) a.get("criticalRatio");
            String rb = (String) b.get("criticalRatio");
            return rb.compareTo(ra);
        });
        status.put("highCriticalRatioPlayers", highRatioPlayers);

        return status;
    }

    /**
     * 内部暴击统计数据 — 追踪单个玩家的攻击和暴击计数
     */
    private static class CriticalStats {
        long totalAttacks = 0;
        long totalCriticals = 0;
    }

    /**
     * 暴击检测结果 — 不可变结果类
     */
    public static class CriticalsCheckResult {
        private final boolean flagged;
        private final boolean suspicious;
        private final List<String> reasons;

        private CriticalsCheckResult(boolean flagged, boolean suspicious, List<String> reasons) {
            this.flagged = flagged;
            this.suspicious = suspicious;
            this.reasons = reasons;
        }

        /** 无异常 — 合法暴击或非暴击攻击 */
        public static CriticalsCheckResult clean() {
            return new CriticalsCheckResult(false, false, List.of());
        }

        /** 可疑 — 单一异常指标但不足以确定作弊 */
        public static CriticalsCheckResult suspicious(List<String> reasons) {
            return new CriticalsCheckResult(false, true, reasons);
        }

        /** 已标记 — 多项检测命中，极可能使用Criticals hack */
        public static CriticalsCheckResult flagged(List<String> reasons) {
            return new CriticalsCheckResult(true, false, reasons);
        }

        public boolean isFlagged() { return flagged; }
        public boolean isSuspicious() { return suspicious; }
        public boolean isClean() { return !flagged && !suspicious; }
        public List<String> getReasons() { return reasons; }
    }
}
