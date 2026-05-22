package com.aluer.anticheat.movement;

import com.aluer.config.ServerGuardConfig;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * 水平速度（Speed）检测服务 — V4.0 反作弊扩展模块
 *
 * 检测原理：
 * 1. XZ平面水平速度检测 — Minecraft生存模式默认步行速度约4.317 m/s，疾跑约5.612 m/s
 *    检测水平速度是否超过7.0 m/s，超过则标记为异常
 * 2. 持续超速检测 — 区分短时速度尖峰（网络延迟可能导致的速度跳跃）和持续超速（真实作弊行为）
 *    需要速度异常持续超过1秒才标记
 * 3. GroundSpoof检测 — 检测玩家是否伪造地面状态：玩家声称在地面但垂直速度异常
 *    （正常玩家在地面时Y轴变化极小，而Speed hack的BHop模式会有振荡）
 * 4. 速度模式分析 — 检测机械性的恒速运动（正常玩家速度会有自然波动）
 *
 * 注意：此模块专注于水平速度（XZ平面）检测，与AntiFly检测的垂直速度检测互补
 *
 * 配置开关：serverguard.security.super-evolution.anti-speed
 */
@Service
public class AntiSpeedService {

    private final ServerGuardConfig config;

    /**
     * 追踪每个玩家的移动轨迹（playerName -> 移动记录列表）
     * 用于计算时间窗口内的速度和加速度
     */
    private final Map<String, List<MovementRecord>> playerMovementHistory = new ConcurrentHashMap<>();

    /**
     * 追踪每个玩家的持续超速计时（playerName -> 超速开始的时间戳）
     * 非空表示该玩家当前处于超速状态
     */
    private final Map<String, Instant> playerSpeedingSince = new ConcurrentHashMap<>();

    /**
     * 追踪每个玩家的速度统计（playerName -> 速度统计）
     */
    private final Map<String, SpeedStats> playerSpeedStats = new ConcurrentHashMap<>();

    private final AtomicLong totalSamples = new AtomicLong(0);
    private final AtomicLong speedViolations = new AtomicLong(0);

    /**
     * 水平速度阈值（m/s）— Minecraft生存模式疾跑约5.612 m/s，设置7.0留出延迟余量
     */
    private static final double MAX_HORIZONTAL_SPEED = 7.0;

    /**
     * 持续超速最小时间（毫秒）— 需要超速状态至少持续1秒才判定为作弊
     * 短时速度尖峰可能是网络延迟造成的数据包积压释放
     */
    private static final long MIN_OVERSPEED_DURATION_MS = 1_000;

    /**
     * 地面垂直速度阈值 — 正常玩家在地面时Y轴变化极小（<0.1），
     * 超过此值的Y轴变化说明可能存在GroundSpoof（BHop等speed hack的辅助技术）
     */
    private static final double GROUND_VERTICAL_THRESHOLD = 0.15;

    /**
     * 每个玩家保留的最大移动记录数
     */
    private static final int MAX_MOVEMENT_RECORDS = 50;

    /**
     * 无参构造函数 — 测试/默认配置使用
     */
    public AntiSpeedService() {
        this(new ServerGuardConfig());
    }

    /**
     * Spring 注入构造函数
     * @param config 全局配置，提供模块开关控制
     */
    public AntiSpeedService(ServerGuardConfig config) {
        this.config = config;
    }

    /**
     * 检测玩家水平移动速度是否异常
     *
     * @param playerName 玩家名称
     * @param playerUUID 玩家UUID
     * @param fromX 移动起始X坐标
     * @param fromZ 移动起始Z坐标
     * @param fromY 移动起始Y坐标（用于GroundSpoof检测）
     * @param toX 移动结束X坐标
     * @param toZ 移动结束Z坐标
     * @param toY 移动结束Y坐标（用于GroundSpoof检测）
     * @param onGround 玩家是否声称在地面
     * @param deltaSeconds 本次移动的时间间隔（秒），用于计算速度
     * @param timestamp 时间戳
     * @return 检测结果
     */
    public SpeedCheckResult detect(String playerName, String playerUUID,
                                    double fromX, double fromY, double fromZ,
                                    double toX, double toY, double toZ,
                                    boolean onGround, double deltaSeconds, Instant timestamp) {
        // 模块开关检查 — 关闭时跳过所有检测
        if (!config.getSecurity().getSuperEvolution().isAntiSpeed()) {
            return SpeedCheckResult.clean();
        }

        totalSamples.incrementAndGet();

        List<MovementRecord> history = playerMovementHistory.computeIfAbsent(
                playerName, k -> new ArrayList<>());
        SpeedStats stats = playerSpeedStats.computeIfAbsent(
                playerName, k -> new SpeedStats());

        List<String> reasons = new ArrayList<>();

        // 避免除零
        if (deltaSeconds <= 0) {
            deltaSeconds = 0.05; // 默认50ms（1 tick）
        }

        // 计算XZ平面水平速度
        double dx = toX - fromX;
        double dz = toZ - fromZ;
        double horizontalDistance = Math.sqrt(dx * dx + dz * dz);
        double horizontalSpeed = horizontalDistance / deltaSeconds;

        // 更新速度统计
        stats.totalSpeed += horizontalSpeed;
        stats.totalSamples++;
        stats.maxSpeed = Math.max(stats.maxSpeed, horizontalSpeed);

        MovementRecord record = new MovementRecord(timestamp, fromX, fromY, fromZ, toX, toY, toZ,
                onGround, horizontalSpeed, deltaSeconds);
        history.add(record);
        while (history.size() > MAX_MOVEMENT_RECORDS) {
            history.remove(0);
        }

        // 1. 水平速度检测
        if (horizontalSpeed > MAX_HORIZONTAL_SPEED) {
            // 记录超速开始时间
            playerSpeedingSince.putIfAbsent(playerName, timestamp);

            // 检查超速持续时间是否超过阈值
            Instant speedStart = playerSpeedingSince.get(playerName);
            long overspeedDurationMs = timestamp.toEpochMilli() - speedStart.toEpochMilli();

            if (overspeedDurationMs >= MIN_OVERSPEED_DURATION_MS) {
                // 持续超速 — 这是作弊行为而非网络延迟
                speedViolations.incrementAndGet();
                reasons.add("SUSTAINED_OVERSPEED: " + String.format("%.2f", horizontalSpeed)
                        + " m/s for " + (overspeedDurationMs / 1000) + "s (threshold: "
                        + String.format("%.1f", MAX_HORIZONTAL_SPEED) + " m/s)");
            } else {
                // 速度尖峰 — 可能是延迟，仅记录可疑
                reasons.add("SPEED_SPIKE: " + String.format("%.2f", horizontalSpeed)
                        + " m/s (duration: " + overspeedDurationMs + "ms, threshold: " + MIN_OVERSPEED_DURATION_MS + "ms)");
            }
        } else {
            // 速度恢复正常，清除超速计时器
            playerSpeedingSince.remove(playerName);
        }

        // 2. GroundSpoof检测 — 玩家声称在地面但Y轴速度异常
        if (onGround) {
            double dy = toY - fromY;
            double verticalSpeed = Math.abs(dy) / deltaSeconds;

            if (verticalSpeed > GROUND_VERTICAL_THRESHOLD) {
                reasons.add("GROUND_SPOOF: claims on ground but vertical speed is "
                        + String.format("%.2f", verticalSpeed) + " m/s (max ground: "
                        + String.format("%.2f", GROUND_VERTICAL_THRESHOLD) + " m/s)");
            }
        }

        // 3. 速度模式分析 — 检测机械性恒速运动
        if (history.size() >= 10) {
            double speedSum = 0;
            double speedSumSq = 0;
            int count = Math.min(history.size(), 10);
            List<MovementRecord> recentRecords = history.subList(history.size() - count, history.size());

            for (MovementRecord r : recentRecords) {
                speedSum += r.horizontalSpeed;
                speedSumSq += r.horizontalSpeed * r.horizontalSpeed;
            }

            double meanSpeed = speedSum / count;
            double variance = (speedSumSq / count) - (meanSpeed * meanSpeed);
            double stdDev = Math.sqrt(Math.max(0, variance));

            // 速度非常恒定（标准差极小）且速度较高 — 典型的机械性Speed hack
            if (stdDev < 0.1 && meanSpeed > 5.0) {
                reasons.add("MECHANICAL_SPEED: constant speed " + String.format("%.2f", meanSpeed)
                        + " m/s with stdDev " + String.format("%.3f", stdDev));
            }
        }

        if (reasons.size() >= 2) {
            return SpeedCheckResult.flagged(reasons);
        } else if (reasons.size() == 1) {
            return SpeedCheckResult.suspicious(reasons);
        }

        return SpeedCheckResult.clean();
    }

    /**
     * 玩家离线时清理追踪数据
     * @param playerName 离线玩家名称
     */
    public void clearPlayer(String playerName) {
        playerMovementHistory.remove(playerName);
        playerSpeedingSince.remove(playerName);
        playerSpeedStats.remove(playerName);
    }

    /**
     * 获取模块运行状态
     * @return 包含计数器、平均速度、最高速度的Map
     */
    public Map<String, Object> getStatus() {
        Map<String, Object> status = new LinkedHashMap<>();
        status.put("totalSamples", totalSamples.get());
        status.put("speedViolations", speedViolations.get());
        status.put("activeTrackedPlayers", playerMovementHistory.size());

        // 计算全局平均速度和最高速度
        double globalAvgSpeed = 0;
        double globalMaxSpeed = 0;
        int totalSamples = 0;

        for (SpeedStats stats : playerSpeedStats.values()) {
            totalSamples += stats.totalSamples;
            globalMaxSpeed = Math.max(globalMaxSpeed, stats.maxSpeed);
        }
        if (totalSamples > 0) {
            double totalSpeedSum = 0;
            for (SpeedStats stats : playerSpeedStats.values()) {
                totalSpeedSum += stats.totalSpeed;
            }
            globalAvgSpeed = totalSpeedSum / totalSamples;
        }

        status.put("averageSpeed", String.format("%.2f", globalAvgSpeed));
        status.put("maxSpeed", String.format("%.2f", globalMaxSpeed));

        // 列出当前超速的玩家
        List<String> overspeedingPlayers = new ArrayList<>(playerSpeedingSince.keySet());
        status.put("overspeedingPlayers", overspeedingPlayers);

        return status;
    }

    /**
     * 内部移动记录 — 记录单次移动的空间和时间信息
     */
    private static class MovementRecord {
        final Instant timestamp;
        final double fromX, fromY, fromZ;
        final double toX, toY, toZ;
        final boolean onGround;
        final double horizontalSpeed;
        final double deltaSeconds;

        MovementRecord(Instant timestamp, double fromX, double fromY, double fromZ,
                       double toX, double toY, double toZ, boolean onGround,
                       double horizontalSpeed, double deltaSeconds) {
            this.timestamp = timestamp;
            this.fromX = fromX; this.fromY = fromY; this.fromZ = fromZ;
            this.toX = toX; this.toY = toY; this.toZ = toZ;
            this.onGround = onGround;
            this.horizontalSpeed = horizontalSpeed;
            this.deltaSeconds = deltaSeconds;
        }
    }

    /**
     * 速度统计内部类 — 追踪单个玩家的累加速度数据
     */
    private static class SpeedStats {
        double totalSpeed = 0;
        int totalSamples = 0;
        double maxSpeed = 0;
    }

    /**
     * 速度检测结果 — 不可变结果类
     */
    public static class SpeedCheckResult {
        private final boolean flagged;
        private final boolean suspicious;
        private final List<String> reasons;

        private SpeedCheckResult(boolean flagged, boolean suspicious, List<String> reasons) {
            this.flagged = flagged;
            this.suspicious = suspicious;
            this.reasons = reasons;
        }

        /** 无异常 — 正常移动速度 */
        public static SpeedCheckResult clean() {
            return new SpeedCheckResult(false, false, List.of());
        }

        /** 可疑 — 速度略超阈值但可能是延迟导致 */
        public static SpeedCheckResult suspicious(List<String> reasons) {
            return new SpeedCheckResult(false, true, reasons);
        }

        /** 已标记 — 确认超速移动（持续超速或GroundSpoof） */
        public static SpeedCheckResult flagged(List<String> reasons) {
            return new SpeedCheckResult(true, false, reasons);
        }

        public boolean isFlagged() { return flagged; }
        public boolean isSuspicious() { return suspicious; }
        public boolean isClean() { return !flagged && !suspicious; }
        public List<String> getReasons() { return reasons; }
    }
}
