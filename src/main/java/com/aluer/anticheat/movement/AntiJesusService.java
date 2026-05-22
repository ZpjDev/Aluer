package com.aluer.anticheat.movement;

import com.aluer.config.ServerGuardConfig;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * 水上/岩浆上行走（Jesus）检测服务 — V4.0 反作弊扩展模块
 *
 * 检测原理：
 * 1. 液体表面行走检测 — Minecraft中玩家无法在水面或岩浆面上稳定行走而不下沉。
 *    正常情况下，玩家在液体上会立即开始下沉。Jesus hack通过在客户端伪造液体为固体方块，
 *    使玩家可以在液体表面上行走。
 * 2. 持续水上行走时间检测 — 追踪玩家在液体上方的连续时间，超过1秒则标记。
 *    正常玩家在接触液体时会立即开始垂直移动（下沉或游泳），而Jesus hack用户Y坐标保持稳定。
 * 3. 耶稣模式抖动检测 — 典型的hack客户端会表现出"抖动"模式：
 *    玩家Y坐标在水面附近小幅振荡（尝试维持在水面），而不是自然下沉。
 * 4. 水面Y坐标估算 — 通过追踪液体表面的Y坐标（通常是整数Y值），
 *    判断玩家是否站在液体方块的上表面（精确站在水面上是Jesus hack的特征）。
 *
 * 配置开关：serverguard.security.super-evolution.anti-jesus
 */
@Service
public class AntiJesusService {

    private final ServerGuardConfig config;

    /**
     * 追踪每个玩家与液体相关的移动记录（playerName -> 记录列表）
     */
    private final Map<String, List<LiquidRecord>> playerLiquidHistory = new ConcurrentHashMap<>();

    /**
     * 追踪每个玩家在液体上方的连续时间（playerName -> 首次检测到水上行走的时间戳）
     */
    private final Map<String, Instant> playerJesusStart = new ConcurrentHashMap<>();

    /**
     * 追踪每个玩家最近的Y坐标（用于抖动检测）
     */
    private final Map<String, List<Double>> playerYHistory = new ConcurrentHashMap<>();

    private final AtomicLong totalChecks = new AtomicLong(0);
    private final AtomicLong jesusViolations = new AtomicLong(0);

    /**
     * 连续水上行走时间阈值（毫秒）— 超过1秒标记
     */
    private static final long MAX_JESUS_DURATION_MS = 1_000;

    /**
     * 水面Y坐标误差容差（方块）— 玩家Y坐标在此范围内被视为在水面高度
     * Minecraft中一个完整方块的高度为1.0，玩家脚部Y值与其所站方块顶面相同
     */
    private static final double LIQUID_SURFACE_TOLERANCE = 0.3;

    /**
     * 抖动检测 — Y坐标波动阈值，Jesus hack用户会在水面高度附近小幅振动
     * 正常玩家在水中会稳定下沉或游泳
     */
    private static final double JITTER_AMPLITUDE_MAX = 0.15;

    /**
     * 抖动检测 — 连续小幅度波动次数超过此值视为Jesus hack的抖动特征
     */
    private static final int MAX_JITTER_WAVES = 5;

    /**
     * 每个玩家保留的最大记录数
     */
    private static final int MAX_RECORDS_PER_PLAYER = 30;

    /**
     * 液体表面的典型Y偏移 — 液体方块的顶面Y值是整数+偏移，水在整数高度上方，
     * 玩家站在水面上的脚Y值约为液体方块Y值（整数）+1.0的位置附近
     */

    /**
     * 无参构造函数 — 测试/默认配置使用
     */
    public AntiJesusService() {
        this(new ServerGuardConfig());
    }

    /**
     * Spring 注入构造函数
     * @param config 全局配置，提供模块开关控制
     */
    public AntiJesusService(ServerGuardConfig config) {
        this.config = config;
    }

    /**
     * 检测玩家是否在水或岩浆上非法行走
     *
     * @param playerName 玩家名称
     * @param playerUUID 玩家UUID
     * @param playerY 玩家脚部Y坐标
     * @param liquidSurfaceY 液体表面Y坐标（整数，液体方块顶面的Y值）
     * @param liquidType 液体类型 ("WATER" 或 "LAVA")
     * @param onGround 玩家是否声称在地面
     * @param isMoving 玩家是否在移动中
     * @param timestamp 时间戳
     * @return 检测结果
     */
    public JesusCheckResult detect(String playerName, String playerUUID,
                                    double playerY, double liquidSurfaceY,
                                    String liquidType, boolean onGround,
                                    boolean isMoving, Instant timestamp) {
        // 模块开关检查 — 关闭时跳过所有检测
        if (!config.getSecurity().getSuperEvolution().isAntiJesus()) {
            return JesusCheckResult.clean();
        }

        totalChecks.incrementAndGet();

        List<LiquidRecord> history = playerLiquidHistory.computeIfAbsent(
                playerName, k -> new ArrayList<>());

        List<Double> yHistory = playerYHistory.computeIfAbsent(
                playerName, k -> new ArrayList<>());

        LiquidRecord record = new LiquidRecord(timestamp, playerY, liquidSurfaceY, liquidType, onGround, isMoving);
        history.add(record);
        yHistory.add(playerY);

        while (history.size() > MAX_RECORDS_PER_PLAYER) {
            history.remove(0);
        }
        while (yHistory.size() > 20) {
            yHistory.remove(0);
        }

        List<String> reasons = new ArrayList<>();

        // 1. 液体表面行走检测 — 玩家Y坐标在液体表面高度附近，且声称在地面
        double yDiff = playerY - liquidSurfaceY;

        // 玩家在液体表面时，如果实际站在液体上方，脚Y应该在液体方块表面Y值处
        // 正常的液体方块表面在Y = liquidSurfaceY（方块整数Y值的顶面）
        boolean isOnLiquidSurface = Math.abs(yDiff) <= LIQUID_SURFACE_TOLERANCE;

        if (isOnLiquidSurface && onGround) {
            // 玩家声称站在液体表面上 — Jesus hack特征
            playerJesusStart.putIfAbsent(playerName, timestamp);

            Instant jesusStart = playerJesusStart.get(playerName);
            long jesusDurationMs = timestamp.toEpochMilli() - jesusStart.toEpochMilli();

            if (jesusDurationMs >= MAX_JESUS_DURATION_MS) {
                // 持续在液体表面行走 — 确认Jesus hack
                jesusViolations.incrementAndGet();
                reasons.add("SUSTAINED_JESUS: " + (jesusDurationMs / 1000.0)
                        + "s walking on " + liquidType.toLowerCase()
                        + " surface (Y=" + String.format("%.2f", playerY)
                        + ", surface=" + String.format("%.1f", liquidSurfaceY) + ")");
            }
        } else {
            // 不再在液体表面，清除计时器
            playerJesusStart.remove(playerName);
        }

        // 2. 抖动检测 — 检测Y坐标在液体表面附近的小幅振荡
        if (isOnLiquidSurface && yHistory.size() >= 6) {
            int jitterCount = 0;
            double prevDiff = yHistory.get(0) - liquidSurfaceY;

            for (int i = 1; i < yHistory.size(); i++) {
                double currentDiff = yHistory.get(i) - liquidSurfaceY;
                // 检测相邻两次Y值是否都在阈值内但方向相反（抖动特征）
                if (Math.abs(prevDiff) <= JITTER_AMPLITUDE_MAX
                        && Math.abs(currentDiff) <= JITTER_AMPLITUDE_MAX
                        && prevDiff * currentDiff < 0) {
                    jitterCount++;
                }
                prevDiff = currentDiff;
            }

            // 如果抖动次数过多，这是Jesus hack的典型行为模式
            if (jitterCount >= MAX_JITTER_WAVES) {
                reasons.add("JITTER_PATTERN: " + jitterCount
                        + " oscillations near " + liquidType.toLowerCase()
                        + " surface (amplitude < " + String.format("%.2f", JITTER_AMPLITUDE_MAX) + ")");
            }
        }

        // 3. 异常稳定性检测 — 在液体表面完全静止站立（不自然的行为）
        if (isOnLiquidSurface && !isMoving && onGround) {
            // 收集足够的静止记录
            long stationaryCount = history.stream()
                    .filter(r -> r.onLiquidSurface && !r.isMoving && r.onGround)
                    .count();
            if (stationaryCount >= 8) {
                reasons.add("STATIONARY_ON_LIQUID: standing still on " + liquidType.toLowerCase()
                        + " surface (" + stationaryCount + " consecutive checks)");
            }
        }

        if (reasons.size() >= 2) {
            return JesusCheckResult.flagged(reasons);
        } else if (reasons.size() == 1) {
            return JesusCheckResult.suspicious(reasons);
        }

        return JesusCheckResult.clean();
    }

    /**
     * 玩家离线时清理追踪数据
     * @param playerName 离线玩家名称
     */
    public void clearPlayer(String playerName) {
        playerLiquidHistory.remove(playerName);
        playerJesusStart.remove(playerName);
        playerYHistory.remove(playerName);
    }

    /**
     * 获取模块运行状态
     * @return 包含计数器和违规数量的Map
     */
    public Map<String, Object> getStatus() {
        Map<String, Object> status = new LinkedHashMap<>();
        status.put("totalChecks", totalChecks.get());
        status.put("jesusViolations", jesusViolations.get());
        status.put("activeTrackedPlayers", playerLiquidHistory.size());

        // 列出当前疑似Jesus的玩家
        List<String> suspectedPlayers = new ArrayList<>(playerJesusStart.keySet());
        status.put("suspectedJesusPlayers", suspectedPlayers);
        return status;
    }

    /**
     * 内部液体接触记录 — 记录玩家与液体交互的时空信息
     */
    private static class LiquidRecord {
        final Instant timestamp;
        final double playerY;
        final double liquidSurfaceY;
        final String liquidType;
        final boolean onGround;
        final boolean onLiquidSurface;
        final boolean isMoving;

        LiquidRecord(Instant timestamp, double playerY, double liquidSurfaceY,
                     String liquidType, boolean onGround, boolean isMoving) {
            this.timestamp = timestamp;
            this.playerY = playerY;
            this.liquidSurfaceY = liquidSurfaceY;
            this.liquidType = liquidType;
            this.onGround = onGround;
            this.isMoving = isMoving;
            // 计算是否在液体表面上
            this.onLiquidSurface = Math.abs(playerY - liquidSurfaceY) <= LIQUID_SURFACE_TOLERANCE;
        }
    }

    /**
     * Jesus检测结果 — 不可变结果类
     */
    public static class JesusCheckResult {
        private final boolean flagged;
        private final boolean suspicious;
        private final List<String> reasons;

        private JesusCheckResult(boolean flagged, boolean suspicious, List<String> reasons) {
            this.flagged = flagged;
            this.suspicious = suspicious;
            this.reasons = reasons;
        }

        /** 无异常 — 玩家正常与液体交互（游泳/下沉） */
        public static JesusCheckResult clean() {
            return new JesusCheckResult(false, false, List.of());
        }

        /** 可疑 — 短暂在液体表面但不足够确认为Jesus hack */
        public static JesusCheckResult suspicious(List<String> reasons) {
            return new JesusCheckResult(false, true, reasons);
        }

        /** 已标记 — 确认在液体表面非法行走（Jesus hack） */
        public static JesusCheckResult flagged(List<String> reasons) {
            return new JesusCheckResult(true, false, reasons);
        }

        public boolean isFlagged() { return flagged; }
        public boolean isSuspicious() { return suspicious; }
        public boolean isClean() { return !flagged && !suspicious; }
        public List<String> getReasons() { return reasons; }
    }
}
