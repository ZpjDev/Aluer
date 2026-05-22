package com.aluer.anticheat.movement;

import com.aluer.config.ServerGuardConfig;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * 空中跳跃（AirJump）检测服务 — V5.2 反作弊移动模块
 *
 * 检测原理：
 * 1. 空中跳跃数据包检测 — Minecraft中跳跃只能在玩家双脚接触地面时执行。
 *    当玩家onGround=false时，跳跃数据包将被服务端忽略。
 *    AirJump hack通过修改客户端，在空中（onGround=false）时也能发送有效的跳跃数据包，
 *    使Y速度变为正值，实现在半空"再次跳跃"。
 * 2. 离地高度+正Y速度检测 — 正常跳跃时Y速度变为正值的瞬间玩家在地面（脚Y值与地面方块顶面相同）。
 *    AirJump时Y速度变为正值时玩家已经离地超过1方块。检测玩家离地高度与Y速度变化的关系。
 * 3. 连续空中跳跃检测 — 某些AirJump hack允许无限次空中跳跃（类似二段跳但无限制）。
 *    检测短时间内的多次Y速度由负转正的模式。
 * 4. 跳跃间隔与高度分析 — 正常跳跃有冷却时间（约0.4秒），AirJump可以在任意时刻触发。
 *    检测异常的Y速度变化间隔和跳跃高度。
 *
 * 配置开关：serverguard.security.super-evolution.anti-air-jump
 */
@Service
public class AntiAirJumpService {

    private final ServerGuardConfig config;

    /**
     * 追踪每个玩家的移动历史（playerName -> 移动记录列表）
     */
    private final Map<String, List<AirJumpRecord>> playerMoveHistory = new ConcurrentHashMap<>();

    /**
     * 追踪每个玩家的Y速度历史（playerName -> Y速度列表）
     */
    private final Map<String, List<Double>> playerYVelocityHistory = new ConcurrentHashMap<>();

    /**
     * 追踪每个玩家的连续空中跳跃次数（playerName -> 连续次数）
     */
    private final Map<String, Integer> playerAirJumpCount = new ConcurrentHashMap<>();

    /**
     * 追踪每个玩家最近一次跳跃的时间戳（playerName -> 时间戳）
     */
    private final Map<String, Instant> playerLastJump = new ConcurrentHashMap<>();

    /**
     * 追踪每个玩家的地面高度（playerName -> 最近地面Y坐标）
     */
    private final Map<String, Double> playerGroundY = new ConcurrentHashMap<>();

    private final AtomicLong totalChecks = new AtomicLong(0);
    private final AtomicLong airJumpViolations = new AtomicLong(0);

    /**
     * 离地高度阈值（方块）— 玩家Y坐标与最近地面Y坐标之差超过此值
     * 且Y速度又变为正值 → 空中跳跃
     */
    private static final double OFF_GROUND_THRESHOLD = 1.0;

    /**
     * Y速度正值阈值 — 低于此值的波动忽略（浮点误差/网络微调）
     */
    private static final double POSITIVE_VELOCITY_THRESHOLD = 0.01;

    /**
     * 连续空中跳跃阈值 — 连续超过此值判定为AirJump hack
     */
    private static final int MAX_CONSECUTIVE_AIR_JUMPS = 2;

    /**
     * 最小跳跃间隔（毫秒）— 正常跳跃之间至少有0.4秒间隔
     */
    private static final long MIN_JUMP_INTERVAL_MS = 400;

    /**
     * 每个玩家保留的最大记录数
     */
    private static final int MAX_RECORDS_PER_PLAYER = 40;

    /**
     * 无参构造函数 — 测试/默认配置使用
     */
    public AntiAirJumpService() {
        this(new ServerGuardConfig());
    }

    /**
     * Spring 注入构造函数
     * @param config 全局配置，提供模块开关控制
     */
    public AntiAirJumpService(ServerGuardConfig config) {
        this.config = config;
    }

    /**
     * 检测玩家是否在空中执行跳跃（AirJump hack）
     *
     * @param playerName   玩家名称
     * @param playerUUID   玩家UUID
     * @param fromX        移动起始X坐标
     * @param fromY        移动起始Y坐标
     * @param fromZ        移动起始Z坐标
     * @param toX          移动结束X坐标
     * @param toY          移动结束Y坐标
     * @param toZ          移动结束Z坐标
     * @param yVelocity    玩家Y轴速度分量
     * @param prevYVelocity 上一tick的Y轴速度分量
     * @param onGround     玩家是否在地面
     * @param isJumping    玩家是否发送了跳跃数据包
     * @param groundY      玩家最近站在的地面Y坐标（方块顶面）
     * @param timestamp    时间戳
     * @return 检测结果
     */
    public AirJumpCheckResult detect(String playerName, String playerUUID,
                                      double fromX, double fromY, double fromZ,
                                      double toX, double toY, double toZ,
                                      double yVelocity, double prevYVelocity,
                                      boolean onGround, boolean isJumping,
                                      double groundY, Instant timestamp) {
        // 模块开关检查 — 关闭时跳过所有检测
        if (!config.getSecurity().getSuperEvolution().isAntiAirJump()) {
            return AirJumpCheckResult.clean();
        }

        totalChecks.incrementAndGet();

        double dy = toY - fromY;
        double dx = toX - fromX;
        double dz = toZ - fromZ;
        double horizontalDist = Math.sqrt(dx * dx + dz * dz);

        // 更新地面Y坐标
        if (onGround) {
            playerGroundY.put(playerName, toY);
        }

        List<AirJumpRecord> history = playerMoveHistory.computeIfAbsent(
                playerName, k -> new ArrayList<>());
        List<Double> yVelHistory = playerYVelocityHistory.computeIfAbsent(
                playerName, k -> new ArrayList<>());

        AirJumpRecord record = new AirJumpRecord(timestamp, fromX, fromY, fromZ,
                toX, toY, toZ, dy, yVelocity, prevYVelocity, onGround, isJumping,
                horizontalDist);
        history.add(record);
        yVelHistory.add(yVelocity);

        while (history.size() > MAX_RECORDS_PER_PLAYER) {
            history.remove(0);
        }
        while (yVelHistory.size() > 30) {
            yVelHistory.remove(0);
        }

        List<String> reasons = new ArrayList<>();

        // 1. 核心检测：跳跃数据包+onGround=false+离地高度>1方块
        if (isJumping && !onGround && yVelocity > POSITIVE_VELOCITY_THRESHOLD) {
            double currentGroundY = playerGroundY.getOrDefault(playerName, fromY);
            double heightAboveGround = toY - currentGroundY;

            if (heightAboveGround >= OFF_GROUND_THRESHOLD) {
                int airJumpCount = playerAirJumpCount.getOrDefault(playerName, 0) + 1;
                playerAirJumpCount.put(playerName, airJumpCount);

                reasons.add("AIR_JUMP: jump packet while " + String.format("%.1f", heightAboveGround)
                        + " blocks above ground (yVel=" + String.format("%.3f", yVelocity)
                        + ", onGround=false)");

                if (airJumpCount >= MAX_CONSECUTIVE_AIR_JUMPS) {
                    airJumpViolations.incrementAndGet();
                    reasons.add("CONSECUTIVE_AIR_JUMPS: " + airJumpCount
                            + " consecutive mid-air jumps detected");
                }
            }
        } else if (onGround) {
            // 回到地面，重置空中跳跃计数
            playerAirJumpCount.remove(playerName);
        }

        // 2. Y速度由负转正+离地检测（即使没有显式的跳跃数据包）
        if (!onGround && yVelocity > POSITIVE_VELOCITY_THRESHOLD
                && prevYVelocity <= 0 && !isJumping) {
            double currentGroundY = playerGroundY.getOrDefault(playerName, fromY);
            double heightAboveGround = toY - currentGroundY;

            if (heightAboveGround >= OFF_GROUND_THRESHOLD) {
                reasons.add("VELOCITY_REVERSAL_IN_AIR: yVel went from "
                        + String.format("%.3f", prevYVelocity) + " to "
                        + String.format("%.3f", yVelocity) + " at "
                        + String.format("%.1f", heightAboveGround)
                        + " blocks above ground");
            }
        }

        // 3. 连续空中跳跃模式 — 多次Y速度归零后重新变正
        if (!onGround && yVelocity > POSITIVE_VELOCITY_THRESHOLD
                && yVelHistory.size() >= 8) {
            int positiveBursts = 0;
            boolean wasNegative = false;
            for (int i = Math.max(0, yVelHistory.size() - 8); i < yVelHistory.size(); i++) {
                double vel = yVelHistory.get(i);
                if (vel > POSITIVE_VELOCITY_THRESHOLD && wasNegative) {
                    positiveBursts++;
                    wasNegative = false;
                } else if (vel <= 0) {
                    wasNegative = true;
                }
            }
            if (positiveBursts >= 3) {
                reasons.add("MULTIPLE_AIR_BURSTS: " + positiveBursts
                        + " upward velocity bursts in recent history while airborne");
            }
        }

        // 4. 异常跳跃间隔检测 — 如果上次跳跃时间戳存在且间隔过短
        Instant lastJump = playerLastJump.get(playerName);
        if (isJumping) {
            if (lastJump != null) {
                long intervalMs = timestamp.toEpochMilli() - lastJump.toEpochMilli();
                if (intervalMs < MIN_JUMP_INTERVAL_MS && !onGround) {
                    reasons.add("RAPID_AIR_JUMP: jump interval "
                            + intervalMs + "ms (min normal: " + MIN_JUMP_INTERVAL_MS
                            + "ms) while airborne");
                }
            }
            playerLastJump.put(playerName, timestamp);
        }

        if (reasons.size() >= 2) {
            return AirJumpCheckResult.flagged(reasons);
        } else if (reasons.size() == 1) {
            return AirJumpCheckResult.suspicious(reasons);
        }

        return AirJumpCheckResult.clean();
    }

    /**
     * 玩家离线时清理追踪数据
     * @param playerName 离线玩家名称
     */
    public void clearPlayer(String playerName) {
        playerMoveHistory.remove(playerName);
        playerYVelocityHistory.remove(playerName);
        playerAirJumpCount.remove(playerName);
        playerLastJump.remove(playerName);
        playerGroundY.remove(playerName);
    }

    /**
     * 获取模块运行状态
     * @return 包含计数器和违规数量的Map
     */
    public Map<String, Object> getStatus() {
        Map<String, Object> status = new LinkedHashMap<>();
        status.put("totalChecks", totalChecks.get());
        status.put("airJumpViolations", airJumpViolations.get());
        status.put("activeTrackedPlayers", playerMoveHistory.size());

        // 列出疑似空中跳跃的玩家
        List<Map<String, Object>> airJumpSuspects = new ArrayList<>();
        for (Map.Entry<String, Integer> entry : playerAirJumpCount.entrySet()) {
            Map<String, Object> info = new LinkedHashMap<>();
            info.put("player", entry.getKey());
            info.put("airJumpCount", entry.getValue());
            airJumpSuspects.add(info);
        }
        status.put("airJumpSuspects", airJumpSuspects);
        return status;
    }

    /**
     * 内部空中跳跃移动记录 — 记录玩家单次移动的完整数据
     */
    private static class AirJumpRecord {
        final Instant timestamp;
        final double fromX, fromY, fromZ;
        final double toX, toY, toZ;
        final double dy;
        final double yVelocity;
        final double prevYVelocity;
        final boolean onGround;
        final boolean isJumping;
        final double horizontalDist;

        AirJumpRecord(Instant timestamp, double fromX, double fromY, double fromZ,
                      double toX, double toY, double toZ, double dy,
                      double yVelocity, double prevYVelocity, boolean onGround,
                      boolean isJumping, double horizontalDist) {
            this.timestamp = timestamp;
            this.fromX = fromX; this.fromY = fromY; this.fromZ = fromZ;
            this.toX = toX; this.toY = toY; this.toZ = toZ;
            this.dy = dy;
            this.yVelocity = yVelocity;
            this.prevYVelocity = prevYVelocity;
            this.onGround = onGround;
            this.isJumping = isJumping;
            this.horizontalDist = horizontalDist;
        }
    }

    /**
     * AirJump检测结果 — 不可变结果类
     */
    public static class AirJumpCheckResult {
        private final boolean flagged;
        private final boolean suspicious;
        private final List<String> reasons;

        private AirJumpCheckResult(boolean flagged, boolean suspicious, List<String> reasons) {
            this.flagged = flagged;
            this.suspicious = suspicious;
            this.reasons = reasons;
        }

        /** 无异常 — 正常的跳跃或落地行为 */
        public static AirJumpCheckResult clean() {
            return new AirJumpCheckResult(false, false, List.of());
        }

        /** 可疑 — 单次异常但不足够确认为AirJump hack */
        public static AirJumpCheckResult suspicious(List<String> reasons) {
            return new AirJumpCheckResult(false, true, reasons);
        }

        /** 已标记 — 确认AirJump hack，连续在空中跳跃 */
        public static AirJumpCheckResult flagged(List<String> reasons) {
            return new AirJumpCheckResult(true, false, reasons);
        }

        public boolean isFlagged() { return flagged; }
        public boolean isSuspicious() { return suspicious; }
        public boolean isClean() { return !flagged && !suspicious; }
        public List<String> getReasons() { return reasons; }
    }
}
