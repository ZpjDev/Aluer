package com.aluer.anticheat.movement;

import com.aluer.config.ServerGuardConfig;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * 自动跨步（Step）检测服务 — V5.2 反作弊移动模块
 *
 * 检测原理：
 * 1. Y坐标突增检测 — Minecraft中玩家自动行走时可以跨越的最高方块是半砖（0.5方块），
 *    需要跳跃才能跨上完整方块（1.0方块）。Step hack自动将1.0方块高度的障碍物
 *    当作可跨过的半砖，无需跳跃即上升1完整方块。
 * 2. 跳跃冲量缺失检测 — 正常跳跃有抛物线速度曲线，Y速度从正到负渐变。
 *    Step hack通过直接修改Y坐标（瞬间传送），缺少跳跃的初始冲量和后续自由落体。
 *    检测单tick内Y上升超过0.9方块且无跳跃速度分量。
 * 3. 连续step模式检测 — Step hack在遇到连续台阶时会逐级上升，
 *    形成"楼梯式"的上升模式（每次精准上升1.0方块），与正常跳跃的抛物线模式截然不同。
 * 4. 水平移动同时上升 — 正常玩家在移动中遇到方块需要停止、跳跃、再继续移动。
 *    Step hack用户在水平移动的同时无缝上升，水平速度没有丝毫中断。
 *
 * 配置开关：serverguard.security.super-evolution.anti-step
 */
@Service
public class AntiStepService {

    private final ServerGuardConfig config;

    /**
     * 追踪每个玩家的移动历史（playerName -> 移动记录列表）
     */
    private final Map<String, List<StepMoveRecord>> playerMoveHistory = new ConcurrentHashMap<>();

    /**
     * 追踪每个玩家连续step上升的次数（playerName -> 连续step次数）
     */
    private final Map<String, Integer> playerStepCount = new ConcurrentHashMap<>();

    /**
     * 追踪每个玩家的Y坐标历史（playerName -> Y坐标列表）
     */
    private final Map<String, List<Double>> playerYHistory = new ConcurrentHashMap<>();

    private final AtomicLong totalChecks = new AtomicLong(0);
    private final AtomicLong stepViolations = new AtomicLong(0);

    /**
     * 单tick内最大正常Y上升（无跳跃）— 正常步行可以跨越0.5方块（半砖）
     * 超过0.9方块必定需要跳跃或存在异常
     */
    private static final double MAX_NORMAL_STEP_UP = 0.9;

    /**
     * 完整方块高度 — Step hack典型上升高度
     */
    private static final double FULL_BLOCK_HEIGHT = 1.0;

    /**
     * Step高度误差容差（方块）— Y变化在此范围内可视为step上升
     */
    private static final double STEP_HEIGHT_TOLERANCE = 0.15;

    /**
     * 正常跳跃的Y速度分量阈值 — 跳跃时Y速度至少为正
     * Step hack缺少Y速度分量（ΔY大但速度为零或负）
     */
    private static final double JUMP_VELOCITY_MIN = 0.1;

    /**
     * 连续step检测阈值 — 连续检测到超过此值的step-like上升判定为作弊
     */
    private static final int MAX_CONSECUTIVE_STEPS = 3;

    /**
     * 每个玩家保留的最大记录数
     */
    private static final int MAX_RECORDS_PER_PLAYER = 40;

    /**
     * 无参构造函数 — 测试/默认配置使用
     */
    public AntiStepService() {
        this(new ServerGuardConfig());
    }

    /**
     * Spring 注入构造函数
     * @param config 全局配置，提供模块开关控制
     */
    public AntiStepService(ServerGuardConfig config) {
        this.config = config;
    }

    /**
     * 检测玩家是否使用Step hack自动跨上完整方块
     *
     * @param playerName   玩家名称
     * @param playerUUID   玩家UUID
     * @param fromX        移动起始X坐标
     * @param fromY        移动起始Y坐标
     * @param fromZ        移动起始Z坐标
     * @param toX          移动结束X坐标
     * @param toY          移动结束Y坐标
     * @param toZ          移动结束Z坐标
     * @param yVelocity    玩家Y轴速度分量（正=向上，负=向下）
     * @param isJumping    玩家是否发送了跳跃数据包
     * @param onGround     玩家移动前是否在地面
     * @param timestamp    时间戳
     * @return 检测结果
     */
    public StepCheckResult detect(String playerName, String playerUUID,
                                   double fromX, double fromY, double fromZ,
                                   double toX, double toY, double toZ,
                                   double yVelocity, boolean isJumping,
                                   boolean onGround, Instant timestamp) {
        // 模块开关检查 — 关闭时跳过所有检测
        if (!config.getSecurity().getSuperEvolution().isAntiStep()) {
            return StepCheckResult.clean();
        }

        totalChecks.incrementAndGet();

        double dy = toY - fromY;
        double dx = toX - fromX;
        double dz = toZ - fromZ;
        double horizontalDist = Math.sqrt(dx * dx + dz * dz);

        List<StepMoveRecord> history = playerMoveHistory.computeIfAbsent(
                playerName, k -> new ArrayList<>());
        List<Double> yHistory = playerYHistory.computeIfAbsent(
                playerName, k -> new ArrayList<>());

        StepMoveRecord record = new StepMoveRecord(timestamp, fromX, fromY, fromZ,
                toX, toY, toZ, dy, yVelocity, isJumping, onGround, horizontalDist);
        history.add(record);
        yHistory.add(toY);

        while (history.size() > MAX_RECORDS_PER_PLAYER) {
            history.remove(0);
        }
        while (yHistory.size() > 30) {
            yHistory.remove(0);
        }

        List<String> reasons = new ArrayList<>();

        // 1. 核心检测：单tick上升超过0.9方块，且无跳跃冲量
        if (dy >= MAX_NORMAL_STEP_UP && !isJumping && Math.abs(yVelocity) < JUMP_VELOCITY_MIN) {
            int stepCount = playerStepCount.getOrDefault(playerName, 0) + 1;
            playerStepCount.put(playerName, stepCount);

            if (stepCount >= MAX_CONSECUTIVE_STEPS) {
                stepViolations.incrementAndGet();
                reasons.add("SUSTAINED_STEP: " + stepCount
                        + " consecutive step-ups (dy=" + String.format("%.2f", dy)
                        + ", no jump impulse, yVel=" + String.format("%.3f", yVelocity) + ")");
            } else {
                reasons.add("STEP_DETECT: dy=" + String.format("%.2f", dy)
                        + " without jump (yVel=" + String.format("%.3f", yVelocity)
                        + ", count=" + stepCount + "/" + MAX_CONSECUTIVE_STEPS + ")");
            }
        } else {
            // 不是step移动，重置计数
            playerStepCount.remove(playerName);
        }

        // 2. 精确step高度检测 — dy恰好在1.0方块附近（完整方块高度）
        if (Math.abs(dy - FULL_BLOCK_HEIGHT) <= STEP_HEIGHT_TOLERANCE && !isJumping) {
            // Step hack典型特征：精准跨上1.0方块，无跳跃
            if (yVelocity <= 0 || Math.abs(yVelocity) < JUMP_VELOCITY_MIN) {
                reasons.add("EXACT_BLOCK_STEP: dy=" + String.format("%.2f", dy)
                        + " (1.0 block) without jump impulse (yVel="
                        + String.format("%.3f", yVelocity) + ")");
            }
        }

        // 3. 水平移动+上升无缝检测 — 正常玩家跨越方块时水平速度会短暂降低
        if (dy >= MAX_NORMAL_STEP_UP && !isJumping && horizontalDist > 0.3) {
            // 检查玩家的水平速度是否在step时保持不变（正常玩家会减速）
            if (history.size() >= 3) {
                double prevAvgSpeed = 0;
                int count = 0;
                for (int i = Math.max(0, history.size() - 5); i < history.size() - 1; i++) {
                    StepMoveRecord r = history.get(i);
                    if (!r.isJumping && r.dy < 0.3) {
                        prevAvgSpeed += r.horizontalDist;
                        count++;
                    }
                }
                if (count > 0) {
                    prevAvgSpeed /= count;
                    // 如果step时的水平速度和平时无异，说明没有因障碍物减速
                    if (horizontalDist >= prevAvgSpeed * 0.8) {
                        reasons.add("NO_SPEED_LOSS_ON_STEP: maintained horizontal speed "
                                + String.format("%.2f", horizontalDist) + " while stepping "
                                + String.format("%.2f", dy) + " blocks (avg: "
                                + String.format("%.2f", prevAvgSpeed) + ")");
                    }
                }
            }
        }

        // 4. 楼梯式上升模式分析 — 一系列精确的1.0方块上升
        if (history.size() >= 8 && !isJumping) {
            long exactBlockSteps = history.stream()
                    .filter(r -> Math.abs(r.dy - FULL_BLOCK_HEIGHT) <= STEP_HEIGHT_TOLERANCE
                            && !r.isJumping)
                    .count();
            if (exactBlockSteps >= 4) {
                reasons.add("STAIRCASE_PATTERN: " + exactBlockSteps
                        + " exact 1.0-block steps in " + history.size()
                        + " ticks (step hack staircase pattern)");
            }
        }

        if (reasons.size() >= 2) {
            return StepCheckResult.flagged(reasons);
        } else if (reasons.size() == 1) {
            return StepCheckResult.suspicious(reasons);
        }

        return StepCheckResult.clean();
    }

    /**
     * 玩家离线时清理追踪数据
     * @param playerName 离线玩家名称
     */
    public void clearPlayer(String playerName) {
        playerMoveHistory.remove(playerName);
        playerStepCount.remove(playerName);
        playerYHistory.remove(playerName);
    }

    /**
     * 获取模块运行状态
     * @return 包含计数器和违规数量的Map
     */
    public Map<String, Object> getStatus() {
        Map<String, Object> status = new LinkedHashMap<>();
        status.put("totalChecks", totalChecks.get());
        status.put("stepViolations", stepViolations.get());
        status.put("activeTrackedPlayers", playerMoveHistory.size());

        // 列出当前疑似step的玩家
        List<Map<String, Object>> stepSuspects = new ArrayList<>();
        for (Map.Entry<String, Integer> entry : playerStepCount.entrySet()) {
            Map<String, Object> info = new LinkedHashMap<>();
            info.put("player", entry.getKey());
            info.put("consecutiveSteps", entry.getValue());
            stepSuspects.add(info);
        }
        status.put("stepSuspects", stepSuspects);
        return status;
    }

    /**
     * 内部step移动记录 — 记录玩家单次移动的详细数据
     */
    private static class StepMoveRecord {
        final Instant timestamp;
        final double fromX, fromY, fromZ;
        final double toX, toY, toZ;
        final double dy;
        final double yVelocity;
        final boolean isJumping;
        final boolean onGround;
        final double horizontalDist;

        StepMoveRecord(Instant timestamp, double fromX, double fromY, double fromZ,
                       double toX, double toY, double toZ, double dy,
                       double yVelocity, boolean isJumping, boolean onGround,
                       double horizontalDist) {
            this.timestamp = timestamp;
            this.fromX = fromX; this.fromY = fromY; this.fromZ = fromZ;
            this.toX = toX; this.toY = toY; this.toZ = toZ;
            this.dy = dy;
            this.yVelocity = yVelocity;
            this.isJumping = isJumping;
            this.onGround = onGround;
            this.horizontalDist = horizontalDist;
        }
    }

    /**
     * Step检测结果 — 不可变结果类
     */
    public static class StepCheckResult {
        private final boolean flagged;
        private final boolean suspicious;
        private final List<String> reasons;

        private StepCheckResult(boolean flagged, boolean suspicious, List<String> reasons) {
            this.flagged = flagged;
            this.suspicious = suspicious;
            this.reasons = reasons;
        }

        /** 无异常 — 正常行走或跳跃跨越方块 */
        public static StepCheckResult clean() {
            return new StepCheckResult(false, false, List.of());
        }

        /** 可疑 — 单次step但不足够确认为Step hack */
        public static StepCheckResult suspicious(List<String> reasons) {
            return new StepCheckResult(false, true, reasons);
        }

        /** 已标记 — 确认Step hack，连续无跳跃跨越完整方块 */
        public static StepCheckResult flagged(List<String> reasons) {
            return new StepCheckResult(true, false, reasons);
        }

        public boolean isFlagged() { return flagged; }
        public boolean isSuspicious() { return suspicious; }
        public boolean isClean() { return !flagged && !suspicious; }
        public List<String> getReasons() { return reasons; }
    }
}
