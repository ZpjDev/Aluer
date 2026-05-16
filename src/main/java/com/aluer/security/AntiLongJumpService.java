package com.aluer.security;

import com.aluer.config.ServerGuardConfig;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * 远跳（LongJump）检测服务 — V5.2 反作弊移动模块
 *
 * 检测原理：
 * 1. 极端水平跳跃距离检测 — Minecraft中正常最大跳跃距离约4方块（冲刺+跳跃），
 *    而LongJump hack可达到10-30+方块。通过计算单次跳跃的水平位移量来检测。
 * 2. 跳跃后水平速度衰减检测 — 正常跳跃后水平速度迅速衰减（每tick乘以0.91的空气阻力系数），
 *    LongJump在跳跃后维持高速不衰减。追踪起跳后连续tick的水平速度变化趋势。
 * 3. 连跳模式检测 — LongJump常配合"bunny hop"模式，通过跳跃链维持高速。
 *    检测玩家是否通过连续跳跃维持异常的水平速度。
 * 4. 绝对速度上限检测 — 检查玩家是否达到任何合法组合都无法达到的移动速度。
 *    合法组合的极限：速度II（+40%）+ 冲刺（+30%）+ 跳跃加成 ≈ 最大约7.8 m/s。
 *
 * 配置开关：serverguard.security.super-evolution.anti-long-jump
 */
@Service
public class AntiLongJumpService {

    private final ServerGuardConfig config;

    /**
     * 追踪每个玩家的移动历史（playerName -> 移动记录列表）
     */
    private final Map<String, List<LongJumpRecord>> playerMoveHistory = new ConcurrentHashMap<>();

    /**
     * 追踪每个玩家当前是否处于跳跃后的空中状态（playerName -> 跳跃后tick计数）
     * 用于追踪起跳后的水平速度衰减模式
     */
    private final Map<String, List<Double>> playerPostJumpSpeeds = new ConcurrentHashMap<>();

    /**
     * 追踪每个玩家的连续跳跃高速移动计数（playerName -> 连续次数）
     */
    private final Map<String, Integer> playerBunnyHopCount = new ConcurrentHashMap<>();

    /**
     * 追踪每个玩家的最近一次跳跃起始坐标（playerName -> 跳跃起跳点坐标数组 [x, z]）
     */
    private final Map<String, double[]> playerJumpStartPos = new ConcurrentHashMap<>();

    /**
     * 追踪每个玩家是否处于跳跃后的空中状态（playerName -> Boolean）
     */
    private final Map<String, Boolean> playerInPostJump = new ConcurrentHashMap<>();

    private final AtomicLong totalChecks = new AtomicLong(0);
    private final AtomicLong longJumpViolations = new AtomicLong(0);

    /**
     * 单次跳跃最大合法水平距离（方块）
     * 冲刺+跳跃在平地的极限约4方块，加上速度II效果略多一些
     */
    private static final double MAX_LEGIT_JUMP_DISTANCE = 4.5;

    /**
     * LongJump典型最小跳跃距离（方块）— 低于此值不予考虑
     */
    private static final double LONG_JUMP_MIN_DISTANCE = 8.0;

    /**
     * 正常空气阻力系数 — 每tick水平速度乘以0.91
     * 预期3 tick后速度衰减为原来的 0.91^3 ≈ 0.754
     */
    private static final double AIR_RESISTANCE_PER_TICK = 0.91;

    /**
     * 跳跃后坚持tick数后速度应衰减到的预期比例上限
     * 3 tick后正常玩家速度应降至初始的75%以下
     */
    private static final double EXPECTED_SPEED_DECAY_RATIO = 0.75;

    /**
     * 绝对最大合法水平速度（m/s）
     * 速度II（+40%）+ 冲刺（+30%）+ 跳跃初始速度 ≈ 4.317 * 1.4 * 1.3 ≈ 7.85 m/s
     * LongJump可达到10+ m/s
     */
    private static final double ABSOLUTE_MAX_SPEED = 7.85;

    /**
     * 连续高速跳跃阈值 — 连续超过此值的跳跃标记为连跳作弊
     */
    private static final int MAX_CONSECUTIVE_BUNNY_HOPS = 3;

    /**
     * 每个玩家保留的最大移动记录数
     */
    private static final int MAX_RECORDS_PER_PLAYER = 50;

    /**
     * 无参构造函数 — 测试/默认配置使用
     */
    public AntiLongJumpService() {
        this(new ServerGuardConfig());
    }

    /**
     * Spring 注入构造函数
     * @param config 全局配置，提供模块开关控制
     */
    public AntiLongJumpService(ServerGuardConfig config) {
        this.config = config;
    }

    /**
     * 检测玩家是否执行了异常的远跳（LongJump hack）
     *
     * @param playerName     玩家名称
     * @param playerUUID     玩家UUID
     * @param fromX          移动起始X坐标
     * @param fromY          移动起始Y坐标
     * @param fromZ          移动起始Z坐标
     * @param toX            移动结束X坐标
     * @param toY            移动结束Y坐标
     * @param toZ            移动结束Z坐标
     * @param horizontalSpeed 当前tick的水平速度（m/s）
     * @param onGround       玩家是否在地面
     * @param isJumping      玩家是否发送了跳跃数据包（Y速度突变为正）
     * @param prevOnGround   上一tick是否在地面（用于判断起跳）
     * @param timestamp      时间戳
     * @return 检测结果
     */
    public LongJumpCheckResult detect(String playerName, String playerUUID,
                                       double fromX, double fromY, double fromZ,
                                       double toX, double toY, double toZ,
                                       double horizontalSpeed,
                                       boolean onGround, boolean isJumping,
                                       boolean prevOnGround, Instant timestamp) {
        // 模块开关检查 — 关闭时跳过所有检测
        if (!config.getSecurity().getSuperEvolution().isAntiLongJump()) {
            return LongJumpCheckResult.clean();
        }

        totalChecks.incrementAndGet();

        // 计算本次移动的水平距离和Y变化
        double dx = toX - fromX;
        double dz = toZ - fromZ;
        double dy = toY - fromY;
        double horizontalDist = Math.sqrt(dx * dx + dz * dz);

        List<LongJumpRecord> history = playerMoveHistory.computeIfAbsent(
                playerName, k -> new ArrayList<>());

        LongJumpRecord record = new LongJumpRecord(timestamp, fromX, fromY, fromZ,
                toX, toY, toZ, horizontalSpeed, horizontalDist, dy,
                onGround, isJumping, prevOnGround);
        history.add(record);
        while (history.size() > MAX_RECORDS_PER_PLAYER) {
            history.remove(0);
        }

        List<String> reasons = new ArrayList<>();

        // ─── 检测1：起跳追踪 — 检测从地面起跳后的跳跃距离 ───
        // 当玩家上一tick在地面且当前tick Y速度为正（起跳信号），记录起跳位置
        if (prevOnGround && dy > 0) {
            playerJumpStartPos.put(playerName, new double[]{fromX, fromZ});
            playerInPostJump.put(playerName, true);
            // 初始化跳跃后速度追踪列表
            playerPostJumpSpeeds.computeIfAbsent(playerName, k -> new ArrayList<>()).clear();
        }

        // 如果玩家处于跳跃后的空中状态，累积速度数据
        if (Boolean.TRUE.equals(playerInPostJump.get(playerName))) {
            List<Double> postJumpSpeeds = playerPostJumpSpeeds.computeIfAbsent(
                    playerName, k -> new ArrayList<>());
            postJumpSpeeds.add(horizontalSpeed);

            // 跳跃后3 tick检测速度衰减
            if (postJumpSpeeds.size() >= 3) {
                double initialSpeed = postJumpSpeeds.get(0);
                double currentSpeed = postJumpSpeeds.get(postJumpSpeeds.size() - 1);

                // 正常衰减：3 tick后速度应 < 初始的75%
                // LongJump：维持高速，衰减比例远低于预期
                if (initialSpeed > 3.0 && currentSpeed > 3.0) {
                    double decayRatio = currentSpeed / Math.max(initialSpeed, 0.001);
                    if (decayRatio > EXPECTED_SPEED_DECAY_RATIO) {
                        reasons.add("SPEED_DECAY_FAILURE: post-jump speed "
                                + String.format("%.2f", currentSpeed) + " m/s after "
                                + postJumpSpeeds.size() + " ticks, decay ratio "
                                + String.format("%.2f", decayRatio)
                                + " exceeds expected " + String.format("%.2f", EXPECTED_SPEED_DECAY_RATIO));
                    }
                }
            }
        }

        // 玩家落地后清理跳跃后追踪状态
        if (onGround && Boolean.TRUE.equals(playerInPostJump.get(playerName))) {
            // 计算从起跳到落地的总水平距离
            double[] startPos = playerJumpStartPos.remove(playerName);
            List<Double> postJumpSpeeds = playerPostJumpSpeeds.remove(playerName);
            playerInPostJump.remove(playerName);

            if (startPos != null) {
                double totalJumpDist = Math.sqrt(
                        Math.pow(toX - startPos[0], 2) + Math.pow(toZ - startPos[1], 2));

                if (totalJumpDist >= LONG_JUMP_MIN_DISTANCE) {
                    // 极端跳跃距离 — 单次跳跃不可能达到此距离
                    reasons.add("EXTREME_JUMP_DISTANCE: " + String.format("%.1f", totalJumpDist)
                            + " blocks in a single jump"
                            + " (max legit: " + String.format("%.1f", MAX_LEGIT_JUMP_DISTANCE) + ")");
                    longJumpViolations.incrementAndGet();
                } else if (totalJumpDist >= MAX_LEGIT_JUMP_DISTANCE + 2.0) {
                    // 超出合法范围2方块以上 — 可疑
                    reasons.add("EXCESSIVE_JUMP_DISTANCE: " + String.format("%.1f", totalJumpDist)
                            + " blocks jump distance exceeds legit max");
                }

                // 连跳模式检测 — 检查是否通过连续跳跃维持高速
                if (totalJumpDist >= MAX_LEGIT_JUMP_DISTANCE && postJumpSpeeds != null
                        && !postJumpSpeeds.isEmpty()) {
                    double avgSpeed = postJumpSpeeds.stream()
                            .mapToDouble(Double::doubleValue).average().orElse(0);
                    if (avgSpeed > ABSOLUTE_MAX_SPEED) {
                        int bunnyCount = playerBunnyHopCount.getOrDefault(playerName, 0) + 1;
                        playerBunnyHopCount.put(playerName, bunnyCount);
                        reasons.add("BUNNY_HOP_PATTERN: avg post-jump speed "
                                + String.format("%.2f", avgSpeed) + " m/s exceeds absolute max "
                                + String.format("%.2f", ABSOLUTE_MAX_SPEED) + " m/s"
                                + " (#" + bunnyCount + " in chain)");

                        if (bunnyCount >= MAX_CONSECUTIVE_BUNNY_HOPS) {
                            reasons.add("SUSTAINED_BUNNY_HOP: " + bunnyCount
                                    + " consecutive extreme jumps detected");
                            longJumpViolations.incrementAndGet();
                        }
                    }
                }
            }
        }

        // 重置连跳计数（如果落地且速度正常）
        if (onGround && horizontalSpeed < MAX_LEGIT_JUMP_DISTANCE) {
            if (!reasons.toString().contains("BUNNY_HOP")) {
                playerBunnyHopCount.remove(playerName);
            }
        }

        // ─── 检测2：绝对速度上限检测 ───
        // 任何合法组合都无法达到的水平速度
        if (horizontalSpeed > ABSOLUTE_MAX_SPEED) {
            reasons.add("ABSOLUTE_SPEED_EXCEEDED: " + String.format("%.2f", horizontalSpeed)
                    + " m/s exceeds absolute legit max "
                    + String.format("%.2f", ABSOLUTE_MAX_SPEED) + " m/s"
                    + " (onGround=" + onGround + ")");

            if (!onGround) {
                longJumpViolations.incrementAndGet();
            }
        }

        // ─── 检测3：移动历史模式分析 — 检查是否频繁出现超大水平位移 ───
        if (history.size() >= 10) {
            long extremeMoves = history.stream()
                    .filter(r -> r.horizontalDist > LONG_JUMP_MIN_DISTANCE && !r.onGround)
                    .count();
            if (extremeMoves >= 5) {
                reasons.add("FREQUENT_EXTREME_HOPS: " + extremeMoves
                        + " extreme-distance airborne moves in last "
                        + history.size() + " ticks");
            }
        }

        if (reasons.size() >= 2) {
            return LongJumpCheckResult.flagged(reasons);
        } else if (reasons.size() == 1) {
            return LongJumpCheckResult.suspicious(reasons);
        }

        return LongJumpCheckResult.clean();
    }

    /**
     * 玩家离线时清理追踪数据
     * @param playerName 离线玩家名称
     */
    public void clearPlayer(String playerName) {
        playerMoveHistory.remove(playerName);
        playerPostJumpSpeeds.remove(playerName);
        playerBunnyHopCount.remove(playerName);
        playerJumpStartPos.remove(playerName);
        playerInPostJump.remove(playerName);
    }

    /**
     * 获取模块运行状态
     * @return 包含计数器和违规数量的Map
     */
    public Map<String, Object> getStatus() {
        Map<String, Object> status = new LinkedHashMap<>();
        status.put("totalChecks", totalChecks.get());
        status.put("longJumpViolations", longJumpViolations.get());
        status.put("activeTrackedPlayers", playerMoveHistory.size());
        status.put("playersInPostJump", playerInPostJump.size());

        // 列出连跳计数异常的玩家
        List<Map<String, Object>> bunnyHopSuspects = new ArrayList<>();
        for (Map.Entry<String, Integer> entry : playerBunnyHopCount.entrySet()) {
            if (entry.getValue() >= 1) {
                Map<String, Object> info = new LinkedHashMap<>();
                info.put("player", entry.getKey());
                info.put("bunnyHopCount", entry.getValue());
                bunnyHopSuspects.add(info);
            }
        }
        status.put("bunnyHopSuspects", bunnyHopSuspects);
        return status;
    }

    /**
     * 内部远跳移动记录 — 记录玩家单次移动的完整数据
     */
    private static class LongJumpRecord {
        final Instant timestamp;
        final double fromX, fromY, fromZ;
        final double toX, toY, toZ;
        final double horizontalSpeed;
        final double horizontalDist;
        final double dy;
        final boolean onGround;
        final boolean isJumping;
        final boolean prevOnGround;

        LongJumpRecord(Instant timestamp, double fromX, double fromY, double fromZ,
                       double toX, double toY, double toZ, double horizontalSpeed,
                       double horizontalDist, double dy, boolean onGround,
                       boolean isJumping, boolean prevOnGround) {
            this.timestamp = timestamp;
            this.fromX = fromX; this.fromY = fromY; this.fromZ = fromZ;
            this.toX = toX; this.toY = toY; this.toZ = toZ;
            this.horizontalSpeed = horizontalSpeed;
            this.horizontalDist = horizontalDist;
            this.dy = dy;
            this.onGround = onGround;
            this.isJumping = isJumping;
            this.prevOnGround = prevOnGround;
        }
    }

    /**
     * LongJump检测结果 — 不可变结果类
     */
    public static class LongJumpCheckResult {
        private final boolean flagged;
        private final boolean suspicious;
        private final List<String> reasons;

        private LongJumpCheckResult(boolean flagged, boolean suspicious, List<String> reasons) {
            this.flagged = flagged;
            this.suspicious = suspicious;
            this.reasons = reasons;
        }

        /** 无异常 — 正常跳跃距离和速度衰减 */
        public static LongJumpCheckResult clean() {
            return new LongJumpCheckResult(false, false, List.of());
        }

        /** 可疑 — 单次跳跃距离偏大但证据不充分 */
        public static LongJumpCheckResult suspicious(List<String> reasons) {
            return new LongJumpCheckResult(false, true, reasons);
        }

        /** 已标记 — 确认LongJump hack，极端跳跃距离或持续连跳模式 */
        public static LongJumpCheckResult flagged(List<String> reasons) {
            return new LongJumpCheckResult(true, false, reasons);
        }

        public boolean isFlagged() { return flagged; }
        public boolean isSuspicious() { return suspicious; }
        public boolean isClean() { return !flagged && !suspicious; }
        public List<String> getReasons() { return reasons; }
    }
}
