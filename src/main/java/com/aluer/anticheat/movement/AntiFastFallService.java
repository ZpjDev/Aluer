package com.aluer.anticheat.movement;

import com.aluer.config.ServerGuardConfig;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * 快速坠落（FastFall）检测服务 — V5.2 反作弊移动模块
 *
 * 检测原理：
 * 1. 超终端速度检测 — Minecraft中正常坠落的最大速度（终端速度）约为3.92方块/tick
 *    （78.4 m/s）。FastFall hack通过修改客户端，使下落速度持续超过5+方块/tick。
 * 2. 持续超速检测 — 区分偶然的网络延迟导致的瞬间速度尖峰和持续性的FastFall作弊。
 *    要求连续多tick的下落速度超过终端速度才判定为作弊。
 * 3. 瞬间坠落检测 — FastFall常与NoFall配合使用，实现"瞬间坠落到地面但不受伤"的效果。
 *    检测玩家在极短时间内Y坐标大幅下降但又出现到地面且无伤害的情况。
 * 4. 下落加速度异常检测 — 正常自由落体加速度为-0.08方块/tick²（重力加速度），
 *    FastFall的下落加速度远超此值。检测下落过程中的Y速度变化率。
 * 5. 下落模式与合法情况区分 — 排除鞘翅俯冲（合法快速下落）、
 *    水中下沉（不同物理规则）、使用末影珍珠等合法快速下落方式。
 *
 * 配置开关：serverguard.security.super-evolution.anti-fast-fall
 */
@Service
public class AntiFastFallService {

    private final ServerGuardConfig config;

    /**
     * 追踪每个玩家的Y速度历史（playerName -> Y速度历史列表）
     */
    private final Map<String, List<Double>> playerYVelocityHistory = new ConcurrentHashMap<>();

    /**
     * 追踪每个玩家的下落记录（playerName -> 下落事件列表）
     */
    private final Map<String, List<FallEvent>> playerFallEvents = new ConcurrentHashMap<>();

    /**
     * 追踪每个玩家的连续超速下落tick数（playerName -> 连续tick数）
     */
    private final Map<String, Integer> playerOverspeedTicks = new ConcurrentHashMap<>();

    /**
     * 追踪每个玩家当前下落过程的起始Y坐标（playerName -> 起始Y）
     */
    private final Map<String, Double> playerFallStartY = new ConcurrentHashMap<>();

    /**
     * 追踪每个玩家是否处于下落状态（playerName -> Boolean）
     */
    private final Map<String, Boolean> playerInFall = new ConcurrentHashMap<>();

    /**
     * 追踪每个玩家下落过程中经过的tick数（playerName -> tick计数）
     */
    private final Map<String, Integer> playerFallTickCount = new ConcurrentHashMap<>();

    private final AtomicLong totalChecks = new AtomicLong(0);
    private final AtomicLong fastFallViolations = new AtomicLong(0);

    /**
     * Minecraft正常终端速度（方块/tick）
     * 自由落体最大速度约3.92 blocks/tick = 78.4 m/s
     * 这个值是由重力加速度(0.08)和空气阻力(0.98)的平衡决定的
     */
    private static final double TERMINAL_VELOCITY = 3.92;

    /**
     * FastFall检测阈值 — 明显超出终端速度的速度（方块/tick）
     * 留出少量余量以容忍浮点误差和合法的短暂速度尖峰
     */
    private static final double FAST_FALL_THRESHOLD = 5.0;

    /**
     * 连续超速tick阈值 — 需要连续超过此tick数才判定为作弊
     * 低于此值可能是网络延迟/丢包导致的数据包积压后一次性处理
     */
    private static final int MIN_CONSECUTIVE_OVERSPEED_TICKS = 5;

    /**
     * 瞬间坠落检测阈值（方块）— 单tick内Y坐标下降超过此值
     */
    private static final double INSTANT_FALL_THRESHOLD = 10.0;

    /**
     * Y速度正值阈值 — 低于此值的波动忽略
     */
    private static final double ZERO_VELOCITY_THRESHOLD = 0.01;

    /**
     * 正常重力加速度（方块/tick²）
     */
    private static final double GRAVITY_ACCELERATION = 0.08;

    /**
     * FastFall加速度阈值 — 下落加速度超过重力的数倍即异常
     */
    private static final double ABNORMAL_ACCELERATION = GRAVITY_ACCELERATION * 3.0;

    /**
     * 每个玩家保留的最大记录数
     */
    private static final int MAX_RECORDS_PER_PLAYER = 60;

    /**
     * 无参构造函数 — 测试/默认配置使用
     */
    public AntiFastFallService() {
        this(new ServerGuardConfig());
    }

    /**
     * Spring 注入构造函数
     * @param config 全局配置，提供模块开关控制
     */
    public AntiFastFallService(ServerGuardConfig config) {
        this.config = config;
    }

    /**
     * 检测玩家是否使用了加速下落（FastFall hack）
     *
     * @param playerName     玩家名称
     * @param playerUUID     玩家UUID
     * @param fromY          移动起始Y坐标
     * @param toY            移动结束Y坐标
     * @param yVelocity      当前tick Y速度（方块/tick，负值表示下落）
     * @param prevYVelocity  上一tick Y速度
     * @param onGround       玩家是否在地面
     * @param isInWater      玩家是否在水中（排除合法水中下沉）
     * @param isInLava       玩家是否在岩浆中
     * @param isElytraFlying 玩家是否鞘翅飞行（排除合法俯冲）
     * @param isClimbing     玩家是否在攀爬（梯子/藤蔓）
     * @param timestamp      时间戳
     * @return 检测结果
     */
    public FastFallCheckResult detect(String playerName, String playerUUID,
                                       double fromY, double toY,
                                       double yVelocity, double prevYVelocity,
                                       boolean onGround, boolean isInWater,
                                       boolean isInLava, boolean isElytraFlying,
                                       boolean isClimbing, Instant timestamp) {
        // 模块开关检查 — 关闭时跳过所有检测
        if (!config.getSecurity().getSuperEvolution().isAntiFastFall()) {
            return FastFallCheckResult.clean();
        }

        totalChecks.incrementAndGet();

        // 合法的快速下落情况 — 不需要检测
        if (isInWater || isInLava || isElytraFlying || isClimbing) {
            playerOverspeedTicks.remove(playerName);
            playerInFall.remove(playerName);
            return FastFallCheckResult.clean();
        }

        double dy = toY - fromY;
        double absYVelocity = Math.abs(yVelocity);
        boolean isFalling = dy < 0 && Math.abs(yVelocity) > ZERO_VELOCITY_THRESHOLD;

        List<Double> yVelHistory = playerYVelocityHistory.computeIfAbsent(
                playerName, k -> new ArrayList<>());
        yVelHistory.add(yVelocity);
        while (yVelHistory.size() > MAX_RECORDS_PER_PLAYER) {
            yVelHistory.remove(0);
        }

        List<FallEvent> fallEvents = playerFallEvents.computeIfAbsent(
                playerName, k -> new ArrayList<>());

        List<String> reasons = new ArrayList<>();

        // ─── 检测1：持续超终端速度下落 ───
        if (isFalling && absYVelocity > TERMINAL_VELOCITY) {
            // 下落速度超过终端速度
            if (absYVelocity > FAST_FALL_THRESHOLD) {
                int overspeedTicks = playerOverspeedTicks.getOrDefault(playerName, 0) + 1;
                playerOverspeedTicks.put(playerName, overspeedTicks);

                // 记录下落事件
                FallEvent event = new FallEvent(timestamp, fromY, toY, absYVelocity,
                        overspeedTicks);
                fallEvents.add(event);
                while (fallEvents.size() > MAX_RECORDS_PER_PLAYER) {
                    fallEvents.remove(0);
                }

                if (overspeedTicks >= MIN_CONSECUTIVE_OVERSPEED_TICKS) {
                    reasons.add("SUSTAINED_OVERSPEED_FALL: " + String.format("%.2f", absYVelocity)
                            + " blocks/tick downward for " + overspeedTicks
                            + " consecutive ticks (terminal velocity: "
                            + String.format("%.2f", TERMINAL_VELOCITY + " blocks/tick)"));
                    fastFallViolations.incrementAndGet();
                }
            } else {
                // 超过终端速度但未达到FastFall阈值 — 轻微超速，重置计数
                // 但保留最近记录作为可疑模式
                if (absYVelocity > TERMINAL_VELOCITY * 1.1) {
                    reasons.add("SLIGHT_OVERSPEED: " + String.format("%.2f", absYVelocity)
                            + " blocks/tick, slightly above terminal "
                            + String.format("%.2f", TERMINAL_VELOCITY));
                }
                playerOverspeedTicks.remove(playerName);
            }
        } else if (isFalling) {
            // 正常下落速度 — 重置超速计数
            playerOverspeedTicks.remove(playerName);
        }

        // ─── 检测2：瞬间坠落（Instant Fall）— 配合NoFall使用 ───
        if (dy < -INSTANT_FALL_THRESHOLD && absYVelocity > FAST_FALL_THRESHOLD * 2) {
            reasons.add("INSTANT_FALL: dropped " + String.format("%.1f", Math.abs(dy))
                    + " blocks in one tick at " + String.format("%.2f", absYVelocity)
                    + " blocks/tick (possibly combined with NoFall)");
            fastFallViolations.incrementAndGet();
        }

        // ─── 检测3：下落加速度异常 — 加速度远超正常重力 ───
        if (isFalling && yVelHistory.size() >= 3) {
            int size = yVelHistory.size();
            // 计算最近两个tick之间的加速度（Y速度更负 = 加速下落）
            double vel1 = yVelHistory.get(size - 2);
            double vel2 = yVelHistory.get(size - 1);
            double acceleration = Math.abs(vel2 - vel1); // 每tick的速度变化

            // 正常下落加速度约0.08方块/tick²
            // FastFall的下落加速度可能远超此值
            if (acceleration > ABNORMAL_ACCELERATION && vel2 < 0 && vel1 < 0
                    && Math.abs(vel2) > Math.abs(vel1)) {
                reasons.add("ABNORMAL_FALL_ACCELERATION: velocity change of "
                        + String.format("%.3f", acceleration) + " blocks/tick²"
                        + " (normal gravity: " + String.format("%.2f", GRAVITY_ACCELERATION)
                        + ", yVel went from " + String.format("%.2f", vel1)
                        + " to " + String.format("%.2f", vel2) + ")");
            }
        }

        // ─── 检测4：下落模式分析 — 检查近期下落事件是否有规律性超速 ───
        if (fallEvents.size() >= 10) {
            long overspeedEvents = fallEvents.stream()
                    .filter(e -> e.absSpeed > FAST_FALL_THRESHOLD)
                    .count();
            if (overspeedEvents >= 5) {
                reasons.add("PATTERN_OVERSPEED_FALLS: " + overspeedEvents
                        + " of last " + fallEvents.size() + " falls exceeded "
                        + String.format("%.2f", FAST_FALL_THRESHOLD) + " blocks/tick");
            }
        }

        // ─── 检测5：下落速度一致性检查 — FastFall通常维持恒定超速 ───
        if (yVelHistory.size() >= 8 && !onGround) {
            // 取最近8个tick中有下落速度的tick
            List<Double> recentFalls = new ArrayList<>();
            for (int i = Math.max(0, yVelHistory.size() - 8); i < yVelHistory.size(); i++) {
                double v = yVelHistory.get(i);
                if (v < -ZERO_VELOCITY_THRESHOLD) {
                    recentFalls.add(Math.abs(v));
                }
            }
            if (recentFalls.size() >= 5) {
                double avgSpeed = recentFalls.stream().mapToDouble(Double::doubleValue).average().orElse(0);
                double minSpeed = recentFalls.stream().mapToDouble(Double::doubleValue).min().orElse(0);

                // 如果最小速度都超过终端速度，高度可疑
                if (minSpeed > TERMINAL_VELOCITY * 1.2 && recentFalls.size() >= 6) {
                    reasons.add("CONSISTENT_OVERSPEED: all " + recentFalls.size()
                            + " recent fall ticks exceeded terminal velocity"
                            + " (min=" + String.format("%.2f", minSpeed)
                            + ", avg=" + String.format("%.2f", avgSpeed) + " blocks/tick)");
                    fastFallViolations.incrementAndGet();
                }
            }
        }

        if (reasons.size() >= 2) {
            return FastFallCheckResult.flagged(reasons);
        } else if (reasons.size() == 1) {
            return FastFallCheckResult.suspicious(reasons);
        }

        return FastFallCheckResult.clean();
    }

    /**
     * 玩家离线时清理追踪数据
     * @param playerName 离线玩家名称
     */
    public void clearPlayer(String playerName) {
        playerYVelocityHistory.remove(playerName);
        playerFallEvents.remove(playerName);
        playerOverspeedTicks.remove(playerName);
        playerFallStartY.remove(playerName);
        playerInFall.remove(playerName);
        playerFallTickCount.remove(playerName);
    }

    /**
     * 获取模块运行状态
     * @return 包含计数器和违规数量的Map
     */
    public Map<String, Object> getStatus() {
        Map<String, Object> status = new LinkedHashMap<>();
        status.put("totalChecks", totalChecks.get());
        status.put("fastFallViolations", fastFallViolations.get());
        status.put("activeTrackedPlayers", playerYVelocityHistory.size());

        // 列出当前超速下落的玩家
        List<Map<String, Object>> overspeedPlayers = new ArrayList<>();
        for (Map.Entry<String, Integer> entry : playerOverspeedTicks.entrySet()) {
            if (entry.getValue() >= 1) {
                Map<String, Object> info = new LinkedHashMap<>();
                info.put("player", entry.getKey());
                info.put("overspeedTicks", entry.getValue());
                overspeedPlayers.add(info);
            }
        }
        status.put("overspeedPlayers", overspeedPlayers);
        return status;
    }

    /**
     * 内部下落事件记录 — 记录单次超速下落事件
     */
    private static class FallEvent {
        final Instant timestamp;
        final double fromY;
        final double toY;
        final double absSpeed;
        final int consecutiveTick;

        FallEvent(Instant timestamp, double fromY, double toY,
                  double absSpeed, int consecutiveTick) {
            this.timestamp = timestamp;
            this.fromY = fromY;
            this.toY = toY;
            this.absSpeed = absSpeed;
            this.consecutiveTick = consecutiveTick;
        }
    }

    /**
     * FastFall检测结果 — 不可变结果类
     */
    public static class FastFallCheckResult {
        private final boolean flagged;
        private final boolean suspicious;
        private final List<String> reasons;

        private FastFallCheckResult(boolean flagged, boolean suspicious, List<String> reasons) {
            this.flagged = flagged;
            this.suspicious = suspicious;
            this.reasons = reasons;
        }

        /** 无异常 — 正常的下落速度 */
        public static FastFallCheckResult clean() {
            return new FastFallCheckResult(false, false, List.of());
        }

        /** 可疑 — 暂时性超速但证据不充分 */
        public static FastFallCheckResult suspicious(List<String> reasons) {
            return new FastFallCheckResult(false, true, reasons);
        }

        /** 已标记 — 确认FastFall hack，持续超终端速度下落 */
        public static FastFallCheckResult flagged(List<String> reasons) {
            return new FastFallCheckResult(true, false, reasons);
        }

        public boolean isFlagged() { return flagged; }
        public boolean isSuspicious() { return suspicious; }
        public boolean isClean() { return !flagged && !suspicious; }
        public List<String> getReasons() { return reasons; }
    }
}
