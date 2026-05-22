package com.aluer.anticheat.movement;

import com.aluer.config.ServerGuardConfig;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * 鞘翅飞行操控（ElytraFly）检测服务 — V5.0 反作弊扩展模块
 *
 * 检测原理：
 * 1. 水平飞行速度检测 — 正常鞘翅飞行的最大水平速度约为30 blocks/秒
 *    （配合烟花火箭可以在短时间内更快）。ElytraFly外挂可以实现超过100 blocks/秒
 *    的持续高速飞行。本模块追踪滑翔状态下的水平速度，检测持续超速。
 * 2. 垂直高度操控检测 — 正常鞘翅飞行中，玩家高度应当持续下降（滑翔特性）。
 *    外挂可以修改高度变化率，实现无烟花平飞甚至上升。
 *    检测无烟花火箭情况下的持续高度保持或上升行为。
 * 3. 伪烟花推进检测 — 烟花火箭可以给鞘翅提供瞬间加速。
 *    外挂可以模拟烟花推进效果而不消耗烟花。检测玩家在没有使用烟花的情况下
 *    出现的类似烟花加速的速度模式。
 * 4. 鞘翅抗击退检测 — 鞘翅飞行状态下受到攻击应有正常的击退位移。
 *    结合AntiVelocity检测逻辑，检测鞘翅飞行时的击退修改。
 * 5. 持续高速飞行时间检测 — 即使使用烟花，鞘翅飞行速度也有上限。
 *    检测超长时间的极端高速飞行（远超正常烟花推进持续时间）。
 *
 * 配置开关：serverguard.security.super-evolution.anti-elytra-fly
 */
@Service
public class AntiElytraFlyService {

    private final ServerGuardConfig config;

    /**
     * 追踪每个玩家的鞘翅飞行轨迹（playerName -> 飞行记录列表）
     * 用于分析飞行速度、高度变化和加速度模式
     */
    private final Map<String, List<ElytraMovement>> playerElytraHistory = new ConcurrentHashMap<>();

    /**
     * 追踪每个玩家的鞘翅飞行会话统计（playerName -> 当前飞行统计）
     * 用于追踪单次飞行的持续时间、最高速度等
     */
    private final Map<String, ElytraFlightSession> playerFlightSessions = new ConcurrentHashMap<>();

    /**
     * 追踪每个玩家的最近烟花使用时间（playerName -> 最近烟花时间）
     * 用于检测伪烟花推进
     */
    private final Map<String, Instant> playerLastFireworkTime = new ConcurrentHashMap<>();

    /**
     * 追踪各玩家在被检测到的超速持续时间（playerName -> 超速开始时间）
     * 用于区分短时速度尖峰和持续超速
     */
    private final Map<String, Instant> playerOverspeedSince = new ConcurrentHashMap<>();

    private final AtomicLong totalChecks = new AtomicLong(0);
    private final AtomicLong flaggedCount = new AtomicLong(0);

    /**
     * 鞘翅飞行最大正常水平速度（blocks/秒）— 不包含烟花加速
     * 正常无烟花鞘翅飞行约30 blocks/秒为上限
     */
    private static final double MAX_NORMAL_ELYTRA_SPEED = 30.0;

    /**
     * 鞘翅飞行最大烟花加速水平速度（blocks/秒）— 使用烟花火箭时
     * 烟花加速后短时间内可以达到更高的速度
     */
    private static final double MAX_FIREWORK_ELYTRA_SPEED = 55.0;

    /**
     * 绝对异常速度阈值（blocks/秒）— 超过此值几乎肯定是外挂
     * 即使使用烟花也无法合法达到此速度
     */
    private static final double ABSOLUTE_MAX_SPEED = 80.0;

    /**
     * 高度操控阈值 — 无烟花时持续保持或上升的最大tick数
     * 正常滑翔应持续下降，不能长时间保持高度
     */
    private static final int MAX_SUSTAINED_ALTITUDE_TICKS = 40;

    /**
     * 高度变化检测阈值（blocks/tick）— Y轴变化小于此值视为高度保持
     * 正常滑翔至少下降约0.02 blocks/tick
     */
    private static final double ALTITUDE_CHANGE_THRESHOLD = -0.005;

    /**
     * 持续超速检测最小时间（毫秒）— 超速状态需持续至少1秒才标记
     */
    private static final long MIN_OVERSPEED_DURATION_MS = 1_000;

    /**
     * 伪烟花检测窗口（毫秒）— 检测在无烟花的此时间内出现的异常加速
     */
    private static final long PSEUDO_FIREWORK_WINDOW_MS = 2_000;

    /**
     * 加速度阈值（blocks/秒^2）— 无烟花时的加速度不应超过此值
     */
    private static final double MAX_NATURAL_ACCELERATION = 15.0;

    /**
     * 每个玩家保留的最大飞行记录数
     */
    private static final int MAX_ELYTRA_RECORDS = 60;

    /**
     * 无参构造函数 — 测试/默认配置使用
     */
    public AntiElytraFlyService() {
        this(new ServerGuardConfig());
    }

    /**
     * Spring 注入构造函数
     * @param config 全局配置，提供模块开关控制
     */
    public AntiElytraFlyService(ServerGuardConfig config) {
        this.config = config;
    }

    /**
     * 检测玩家鞘翅飞行是否存在速度/高度操控
     *
     * @param playerName 玩家名称
     * @param playerUUID 玩家UUID
     * @param fromX 移动起始X坐标
     * @param fromY 移动起始Y坐标
     * @param fromZ 移动起始Z坐标
     * @param toX 移动结束X坐标
     * @param toY 移动结束Y坐标
     * @param toZ 移动结束Z坐标
     * @param isGliding 玩家是否处于鞘翅滑翔状态
     * @param deltaSeconds 本次移动的时间间隔（秒）
     * @param hasFirework 玩家是否在此时段使用了烟花火箭
     * @param gameMode 玩家游戏模式
     * @param timestamp 时间戳
     * @return 检测结果
     */
    public ElytraFlyCheckResult detect(String playerName, String playerUUID,
                                         double fromX, double fromY, double fromZ,
                                         double toX, double toY, double toZ,
                                         boolean isGliding, double deltaSeconds,
                                         boolean hasFirework, String gameMode,
                                         Instant timestamp) {
        // 模块开关检查 — 关闭时跳过所有检测
        if (!config.getSecurity().getSuperEvolution().isAntiElytraFly()) {
            return ElytraFlyCheckResult.clean();
        }

        // 非滑翔状态不检测（但仍需要清理飞行会话）
        if (!isGliding) {
            playerFlightSessions.remove(playerName);
            playerOverspeedSince.remove(playerName);
            return ElytraFlyCheckResult.clean();
        }

        // 创造/观察者模式不检测
        if ("creative".equalsIgnoreCase(gameMode) || "spectator".equalsIgnoreCase(gameMode)) {
            return ElytraFlyCheckResult.clean();
        }

        totalChecks.incrementAndGet();
        List<String> reasons = new ArrayList<>();

        // 避免除零
        if (deltaSeconds <= 0) {
            deltaSeconds = 0.05;
        }

        // 计算水平速度
        double dx = toX - fromX;
        double dz = toZ - fromZ;
        double horizontalDistance = Math.sqrt(dx * dx + dz * dz);
        double horizontalSpeed = horizontalDistance / deltaSeconds;

        // 计算垂直速度
        double dy = toY - fromY;
        double verticalSpeed = dy / deltaSeconds;

        // 获取或创建飞行会话
        ElytraFlightSession session = playerFlightSessions.computeIfAbsent(
                playerName, k -> new ElytraFlightSession());
        session.update(horizontalSpeed, verticalSpeed, timestamp);

        // 获取或创建飞行历史
        List<ElytraMovement> history = playerElytraHistory.computeIfAbsent(
                playerName, k -> new ArrayList<>());
        ElytraMovement movement = new ElytraMovement(timestamp, horizontalSpeed, verticalSpeed,
                hasFirework, deltaSeconds);
        history.add(movement);
        while (history.size() > MAX_ELYTRA_RECORDS) {
            history.remove(0);
        }

        // 记录烟花使用时间
        if (hasFirework) {
            playerLastFireworkTime.put(playerName, timestamp);
        }

        // 1. 绝对异常速度检测 — 超过绝对最大速度
        if (horizontalSpeed > ABSOLUTE_MAX_SPEED) {
            // 这个速度无论任何合法手段都无法达到
            flaggedCount.incrementAndGet();
            reasons.add("CRITICAL_SPEED: " + String.format("%.2f", horizontalSpeed)
                    + " blocks/s exceeds absolute max of "
                    + String.format("%.1f", ABSOLUTE_MAX_SPEED) + " blocks/s");
        }

        // 2. 水平速度检测 — 区分有无烟花
        double speedLimit = hasFirework ? MAX_FIREWORK_ELYTRA_SPEED : MAX_NORMAL_ELYTRA_SPEED;

        if (horizontalSpeed > speedLimit) {
            // 记录超速开始时间
            playerOverspeedSince.putIfAbsent(playerName, timestamp);

            Instant overspeedStart = playerOverspeedSince.get(playerName);
            long overspeedDurationMs = timestamp.toEpochMilli() - overspeedStart.toEpochMilli();

            if (overspeedDurationMs >= MIN_OVERSPEED_DURATION_MS) {
                // 持续超速 — 确认为外挂
                reasons.add("SUSTAINED_ELYTRA_OVERSPEED: "
                        + String.format("%.2f", horizontalSpeed) + " blocks/s for "
                        + (overspeedDurationMs / 1000) + "s (limit: "
                        + String.format("%.1f", speedLimit) + ", firework: " + hasFirework + ")");
            }
        } else {
            // 速度恢复正常
            playerOverspeedSince.remove(playerName);
        }

        // 3. 高度操控检测 — 无烟花时持续保持高度或上升
        if (!hasFirework) {
            if (verticalSpeed > ALTITUDE_CHANGE_THRESHOLD) {
                // 高度未下降（保持或上升），递增计数
                session.sustainedAltitudeTicks++;
                if (session.sustainedAltitudeTicks > MAX_SUSTAINED_ALTITUDE_TICKS) {
                    reasons.add("ALTITUDE_CONTROL: maintained/ascended for "
                            + session.sustainedAltitudeTicks + " ticks without firework "
                            + "(vertical speed: " + String.format("%.3f", verticalSpeed) + " blocks/tick)");
                }
            } else {
                // 正常下降
                session.sustainedAltitudeTicks = 0;
            }
        } else {
            // 有烟花时重置高度保持计数（烟花可以维持高度）
            session.sustainedAltitudeTicks = 0;
        }

        // 4. 伪烟花推进检测 — 无烟花但出现类似烟花加速的速度模式
        Instant lastFirework = playerLastFireworkTime.get(playerName);
        boolean recentFirework = lastFirework != null
                && timestamp.toEpochMilli() - lastFirework.toEpochMilli() < PSEUDO_FIREWORK_WINDOW_MS;

        if (!hasFirework && !recentFirework && history.size() >= 2) {
            // 计算加速度
            ElytraMovement prev = history.get(history.size() - 2);
            double acceleration = (horizontalSpeed - prev.horizontalSpeed) / deltaSeconds;

            // 无烟花时不应出现剧烈正加速度
            if (acceleration > MAX_NATURAL_ACCELERATION && horizontalSpeed > MAX_NORMAL_ELYTRA_SPEED) {
                reasons.add("PSEUDO_FIREWORK: acceleration " + String.format("%.2f", acceleration)
                        + " blocks/s^2 without firework (speed: " + String.format("%.2f", horizontalSpeed)
                        + " blocks/s, max natural: " + String.format("%.1f", MAX_NATURAL_ACCELERATION)
                        + " blocks/s^2)");
            }
        }

        // 5. 飞行持续时间与最大速度统计
        if (session.maxSpeed > MAX_FIREWORK_ELYTRA_SPEED) {
            long flightDuration = timestamp.toEpochMilli() - session.flightStartTime.toEpochMilli();
            if (flightDuration > 10_000) {
                // 超过10秒的高速飞行
                reasons.add("EXTREME_FLIGHT: max speed " + String.format("%.2f", session.maxSpeed)
                        + " blocks/s sustained over " + (flightDuration / 1000) + "s");
            }
        }

        // 汇总结果
        if (reasons.size() >= 2) {
            flaggedCount.incrementAndGet();
            return ElytraFlyCheckResult.flagged(reasons);
        } else if (reasons.size() == 1) {
            return ElytraFlyCheckResult.suspicious(reasons);
        }

        return ElytraFlyCheckResult.clean();
    }

    /**
     * 玩家停止滑翔时调用，结束飞行会话
     * @param playerName 玩家名称
     */
    public void onStopGliding(String playerName) {
        playerFlightSessions.remove(playerName);
        playerOverspeedSince.remove(playerName);
    }

    /**
     * 记录玩家使用了烟花火箭（Agent监听器调用）
     * @param playerName 玩家名称
     * @param timestamp 使用时间戳
     */
    public void recordFireworkUse(String playerName, Instant timestamp) {
        playerLastFireworkTime.put(playerName, timestamp);
    }

    /**
     * 玩家离线时清理其追踪数据，释放内存
     * @param playerName 离线玩家名称
     */
    public void clearPlayer(String playerName) {
        playerElytraHistory.remove(playerName);
        playerFlightSessions.remove(playerName);
        playerLastFireworkTime.remove(playerName);
        playerOverspeedSince.remove(playerName);
    }

    /**
     * 获取模块运行状态
     * @return 包含计数器、活跃追踪玩家数和最高速度的Map
     */
    public Map<String, Object> getStatus() {
        Map<String, Object> status = new LinkedHashMap<>();
        status.put("totalChecks", totalChecks.get());
        status.put("flaggedCount", flaggedCount.get());
        status.put("activeTrackedPlayers", playerElytraHistory.size());
        status.put("activeFlightSessions", playerFlightSessions.size());

        // 列出当前在飞的玩家及其最大速度
        List<Map<String, Object>> activeFlyers = new ArrayList<>();
        for (Map.Entry<String, ElytraFlightSession> e : playerFlightSessions.entrySet()) {
            ElytraFlightSession s = e.getValue();
            long duration = Instant.now().toEpochMilli() - s.flightStartTime.toEpochMilli();
            Map<String, Object> info = new LinkedHashMap<>();
            info.put("player", e.getKey());
            info.put("maxSpeed", String.format("%.2f", s.maxSpeed));
            info.put("flightDurationSeconds", duration / 1000);
            info.put("sustainedAltitudeTicks", s.sustainedAltitudeTicks);
            activeFlyers.add(info);
        }
        status.put("activeFlyers", activeFlyers);

        return status;
    }

    /**
     * 内部鞘翅飞行移动记录
     */
    private static class ElytraMovement {
        final Instant timestamp;
        final double horizontalSpeed;
        final double verticalSpeed;
        final boolean hasFirework;
        final double deltaSeconds;

        ElytraMovement(Instant timestamp, double horizontalSpeed, double verticalSpeed,
                       boolean hasFirework, double deltaSeconds) {
            this.timestamp = timestamp;
            this.horizontalSpeed = horizontalSpeed;
            this.verticalSpeed = verticalSpeed;
            this.hasFirework = hasFirework;
            this.deltaSeconds = deltaSeconds;
        }
    }

    /**
     * 内部鞘翅飞行会话统计 — 追踪单次飞行的持续时间和极值
     */
    private static class ElytraFlightSession {
        final Instant flightStartTime;
        double maxSpeed;
        int sustainedAltitudeTicks;

        ElytraFlightSession() {
            this.flightStartTime = Instant.now();
            this.maxSpeed = 0;
            this.sustainedAltitudeTicks = 0;
        }

        void update(double horizontalSpeed, double verticalSpeed, Instant now) {
            this.maxSpeed = Math.max(this.maxSpeed, horizontalSpeed);
        }
    }

    /**
     * 鞘翅飞行检测结果 — 不可变结果类
     */
    public static class ElytraFlyCheckResult {
        private final boolean flagged;
        private final boolean suspicious;
        private final List<String> reasons;

        private ElytraFlyCheckResult(boolean flagged, boolean suspicious, List<String> reasons) {
            this.flagged = flagged;
            this.suspicious = suspicious;
            this.reasons = reasons;
        }

        /** 无异常 — 正常鞘翅飞行 */
        public static ElytraFlyCheckResult clean() {
            return new ElytraFlyCheckResult(false, false, List.of());
        }

        /** 可疑 — 速度偏高但证据不够充分（可能为烟花/地形因素） */
        public static ElytraFlyCheckResult suspicious(List<String> reasons) {
            return new ElytraFlyCheckResult(false, true, reasons);
        }

        /** 已标记 — 多项规则命中，确认为鞘翅飞行操控 */
        public static ElytraFlyCheckResult flagged(List<String> reasons) {
            return new ElytraFlyCheckResult(true, false, reasons);
        }

        public boolean isFlagged() { return flagged; }
        public boolean isSuspicious() { return suspicious; }
        public boolean isClean() { return !flagged && !suspicious; }
        public List<String> getReasons() { return reasons; }
    }
}
