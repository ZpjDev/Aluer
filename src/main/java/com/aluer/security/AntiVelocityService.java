package com.aluer.security;

import com.aluer.config.ServerGuardConfig;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * 击退修改（AntiVelocity）检测服务 — V5.0 反作弊扩展模块
 *
 * 检测原理：
 * 1. 击退幅度检测 — Minecraft中玩家受到攻击后会产生可预测的击退效果。
 *    击退力度由攻击者和被攻击者的位置关系、武器附魔等因素决定。
 *    AntiVelocity/NoKnockback外挂会大幅减少或完全消除击退效果。
 *    本模块追踪受击后的速度变化，如果速度变化低于理论最小值则标记。
 * 2. 水平击退比例检测 — 正常击退在XZ水平面有显著的速度分量。
 *    如果水平速度分量异常小（<0.1 blocks），表明可能存在击退修改。
 * 3. 连续低击退检测 — 单次低击退可能是角度问题（正面硬接），
 *    但连续多次受击都几乎没有击退效果则是明显的作弊信号。
 * 4. 垂直击退检测 — 正常击退包含向上的Y轴分量（约0.4 blocks）。
 *    如果玩家受击后Y轴完全不变，也是击退修改的典型特征。
 *
 * 配置开关：serverguard.security.super-evolution.anti-velocity
 */
@Service
public class AntiVelocityService {

    private final ServerGuardConfig config;

    /**
     * 追踪每个玩家的受击和速度变化记录（playerName -> 记录列表）
     * 用于分析连续受击后的击退模式
     */
    private final Map<String, List<VelocityRecord>> playerVelocityHistory = new ConcurrentHashMap<>();

    /**
     * 追踪每个玩家连续低击退的累计次数（playerName -> 累计次数）
     * 用于检测持续性的击退修改行为
     */
    private final Map<String, Integer> playerLowKnockbackCount = new ConcurrentHashMap<>();

    private final AtomicLong totalChecks = new AtomicLong(0);
    private final AtomicLong flaggedCount = new AtomicLong(0);

    /**
     * 最小水平击退阈值（blocks）— XZ平面速度变化低于此值视为异常
     * 正常击退的水平分量至少为0.15 blocks（含最小击退效应）
     */
    private static final double MIN_HORIZONTAL_VELOCITY = 0.15;

    /**
     * 垂直击退阈值（blocks）— Y轴速度变化低于此值视为异常
     * 正常击退包含约0.4 blocks的Y轴分量
     */
    private static final double MIN_VERTICAL_VELOCITY = 0.05;

    /**
     * 触发标记所需的最小连续低击退次数
     * 需要至少3次连续低击退才能排除角度/地形因素
     */
    private static final int MIN_CONSECUTIVE_LOW_KNOCKBACK = 3;

    /**
     * 击退检测时间窗口（毫秒）— 受击后在此时间窗口内检测速度变化
     * 正常击退在受击后500ms内完成
     */
    private static final long KNOCKBACK_WINDOW_MS = 500;

    /**
     * 极低击退标记阈值 — 水平速度低于此值为几乎完全抵消击退
     */
    private static final double CRITICAL_LOW_VELOCITY = 0.05;

    /**
     * 每个玩家保留的最大记录数
     */
    private static final int MAX_RECORDS_PER_PLAYER = 30;

    /**
     * 无参构造函数 — 测试/默认配置使用
     */
    public AntiVelocityService() {
        this(new ServerGuardConfig());
    }

    /**
     * Spring 注入构造函数
     * @param config 全局配置，提供模块开关控制
     */
    public AntiVelocityService(ServerGuardConfig config) {
        this.config = config;
    }

    /**
     * 检测玩家在受击后是否存在击退修改行为
     *
     * @param playerName 被攻击玩家名称
     * @param playerUUID 被攻击玩家UUID
     * @param attackerName 攻击者名称
     * @param damageAmount 受到的伤害量
     * @param velocityX 受击后的X轴速度分量
     * @param velocityY 受击后的Y轴速度分量
     * @param velocityZ 受击后的Z轴速度分量
     * @param timestamp 受击时间戳
     * @return 检测结果
     */
    public VelocityCheckResult detect(String playerName, String playerUUID,
                                       String attackerName, double damageAmount,
                                       double velocityX, double velocityY, double velocityZ,
                                       Instant timestamp) {
        // 模块开关检查 — 关闭时跳过所有检测直接返回安全结果
        if (!config.getSecurity().getSuperEvolution().isAntiVelocity()) {
            return VelocityCheckResult.clean();
        }

        totalChecks.incrementAndGet();
        List<String> reasons = new ArrayList<>();

        // 计算水平速度（XZ平面）
        double horizontalVelocity = Math.sqrt(velocityX * velocityX + velocityZ * velocityZ);
        double verticalVelocity = Math.abs(velocityY);

        // 获取或创建玩家击退历史记录
        List<VelocityRecord> history = playerVelocityHistory.computeIfAbsent(
                playerName, k -> new ArrayList<>());

        VelocityRecord record = new VelocityRecord(timestamp, attackerName, damageAmount,
                horizontalVelocity, verticalVelocity, velocityX, velocityY, velocityZ);
        history.add(record);
        // 控制列表大小
        while (history.size() > MAX_RECORDS_PER_PLAYER) {
            history.remove(0);
        }

        // 1. 极低击退检测 — 水平/垂直速度均接近零
        if (horizontalVelocity < CRITICAL_LOW_VELOCITY && verticalVelocity < MIN_VERTICAL_VELOCITY
                && damageAmount > 0) {
            // 受到伤害但几乎完全无击退 — 这是强力的NoKnockback外挂
            flaggedCount.incrementAndGet();
            reasons.add("NO_KNOCKBACK: horizontal velocity " + String.format("%.4f", horizontalVelocity)
                    + ", vertical " + String.format("%.4f", verticalVelocity)
                    + " after " + String.format("%.1f", damageAmount) + " damage");
        }

        // 2. 水平击退比例检测
        if (horizontalVelocity < MIN_HORIZONTAL_VELOCITY && damageAmount > 0) {
            int count = playerLowKnockbackCount.merge(playerName, 1, Integer::sum);

            if (count >= MIN_CONSECUTIVE_LOW_KNOCKBACK) {
                // 连续多次低击退 — 确认为击退修改
                reasons.add("CONSISTENT_LOW_KNOCKBACK: " + count + " consecutive hits with horizontal velocity < "
                        + String.format("%.2f", MIN_HORIZONTAL_VELOCITY) + " (current: "
                        + String.format("%.3f", horizontalVelocity) + ")");
            } else if (count >= 2) {
                // 2次低击退 — 可疑
                reasons.add("LOW_KNOCKBACK_TREND: " + count + " of last hits had low knockback ("
                        + String.format("%.3f", horizontalVelocity) + " horizontal)");
            }
        } else if (horizontalVelocity >= MIN_HORIZONTAL_VELOCITY) {
            // 击退恢复正常，重置低击退计数
            playerLowKnockbackCount.put(playerName, 0);
        }

        // 3. 垂直击退缺失检测 — 受击后Y轴完全不变化
        if (verticalVelocity < MIN_VERTICAL_VELOCITY && damageAmount > 0.5) {
            reasons.add("VERTICAL_KNOCKBACK_MISSING: vertical velocity "
                    + String.format("%.4f", verticalVelocity) + " after "
                    + String.format("%.1f", damageAmount) + " damage (min expected: "
                    + String.format("%.2f", MIN_VERTICAL_VELOCITY) + ")");
        }

        // 4. 连续受击模式分析 — 检测多次受击中击退始终异常低
        if (history.size() >= MIN_CONSECUTIVE_LOW_KNOCKBACK) {
            List<VelocityRecord> recent = history.subList(
                    Math.max(0, history.size() - MIN_CONSECUTIVE_LOW_KNOCKBACK), history.size());
            long lowKnockbackHits = recent.stream()
                    .filter(r -> r.horizontalVelocity < MIN_HORIZONTAL_VELOCITY
                            && r.damageAmount > 0)
                    .count();

            if (lowKnockbackHits >= MIN_CONSECUTIVE_LOW_KNOCKBACK) {
                reasons.add("PATTERN_LOW_KNOCKBACK: " + lowKnockbackHits + "/"
                        + recent.size() + " recent hits had suppressed knockback");
            }
        }

        // 汇总结果
        if (reasons.size() >= 2) {
            flaggedCount.incrementAndGet();
            return VelocityCheckResult.flagged(reasons);
        } else if (reasons.size() == 1) {
            return VelocityCheckResult.suspicious(reasons);
        }

        return VelocityCheckResult.clean();
    }

    /**
     * 玩家离线时清理其追踪数据，释放内存
     * @param playerName 离线玩家名称
     */
    public void clearPlayer(String playerName) {
        playerVelocityHistory.remove(playerName);
        playerLowKnockbackCount.remove(playerName);
    }

    /**
     * 获取模块运行状态
     * @return 包含计数器和活跃追踪玩家数的Map
     */
    public Map<String, Object> getStatus() {
        Map<String, Object> status = new LinkedHashMap<>();
        status.put("totalChecks", totalChecks.get());
        status.put("flaggedCount", flaggedCount.get());
        status.put("activeTrackedPlayers", playerVelocityHistory.size());
        return status;
    }

    /**
     * 内部击退记录 — 记录单次受击后的速度变化信息
     */
    private static class VelocityRecord {
        final Instant timestamp;
        final String attackerName;
        final double damageAmount;
        final double horizontalVelocity;
        final double verticalVelocity;
        final double velocityX;
        final double velocityY;
        final double velocityZ;

        VelocityRecord(Instant timestamp, String attackerName, double damageAmount,
                       double horizontalVelocity, double verticalVelocity,
                       double velocityX, double velocityY, double velocityZ) {
            this.timestamp = timestamp;
            this.attackerName = attackerName;
            this.damageAmount = damageAmount;
            this.horizontalVelocity = horizontalVelocity;
            this.verticalVelocity = verticalVelocity;
            this.velocityX = velocityX;
            this.velocityY = velocityY;
            this.velocityZ = velocityZ;
        }
    }

    /**
     * 击退检测结果 — 不可变结果类
     */
    public static class VelocityCheckResult {
        private final boolean flagged;
        private final boolean suspicious;
        private final List<String> reasons;

        private VelocityCheckResult(boolean flagged, boolean suspicious, List<String> reasons) {
            this.flagged = flagged;
            this.suspicious = suspicious;
            this.reasons = reasons;
        }

        /** 无异常 — 正常击退效果 */
        public static VelocityCheckResult clean() {
            return new VelocityCheckResult(false, false, List.of());
        }

        /** 可疑 — 击退效果偏弱但证据不够充分 */
        public static VelocityCheckResult suspicious(List<String> reasons) {
            return new VelocityCheckResult(false, true, reasons);
        }

        /** 已标记 — 多项规则命中，高度可能使用击退修改 */
        public static VelocityCheckResult flagged(List<String> reasons) {
            return new VelocityCheckResult(true, false, reasons);
        }

        public boolean isFlagged() { return flagged; }
        public boolean isSuspicious() { return suspicious; }
        public boolean isClean() { return !flagged && !suspicious; }
        public List<String> getReasons() { return reasons; }
    }
}
