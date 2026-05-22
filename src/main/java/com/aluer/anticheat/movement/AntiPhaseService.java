package com.aluer.anticheat.movement;

import com.aluer.config.ServerGuardConfig;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * 穿墙/方块剪切（Phase）检测服务 — V5.0 反作弊扩展模块
 *
 * 检测原理：
 * 1. 固体方块穿越检测 — 玩家两次连续移动位置之间如果存在固体方块，
 *    则玩家穿过了方块，这是Phase hack的典型特征。通过步进采样两点间
 *    路径上的方块状态进行检测。
 * 2. 移动距离异常检测 — 正常玩家无法在单tick内移动超过一定距离。
 *    如果玩家单次移动穿越了多个固体方块，几乎可以确定为Phase hack。
 * 3. 地狱门Phase检测 — Phase hack的一个常见变种是利用地狱门传送瞬间
 *    将玩家位置修改到门的另一端（通常是固体方块内部）。
 *    检测玩家在地狱门附近出现的不可能位置。
 * 4. 方块内停留检测 — 正常游戏机制会阻止玩家停留在固体方块内部。
 *    如果检测到玩家在固体方块内部持续存在，说明存在Phase hack。
 *
 * 注意：此模块接收来自Agent监听器的方块状态数据，
 * 由于Paper API为provided scope，实际的isSolid/isOccluding检查
 * 由Agent在Minecraft进程内部完成并传递结果。
 *
 * 配置开关：serverguard.security.super-evolution.anti-phase
 */
@Service
public class AntiPhaseService {

    private final ServerGuardConfig config;

    /**
     * 追踪每个玩家的移动轨迹（playerName -> 最近的位置记录）
     * 用于检测两点间是否穿越了固体方块
     */
    private final Map<String, PlayerPosition> playerLastPosition = new ConcurrentHashMap<>();

    /**
     * 追踪每个玩家的可疑穿墙事件（playerName -> 事件列表）
     * 用于累积检测模式和判定作弊行为
     */
    private final Map<String, List<PhaseEvent>> playerPhaseEvents = new ConcurrentHashMap<>();

    /**
     * 追踪在地狱门附近的玩家及其进入时间（playerName -> 最近门户交互时间）
     * 用于检测地狱门Phase exploit
     */
    private final Map<String, Instant> playerPortalInteraction = new ConcurrentHashMap<>();

    private final AtomicLong totalChecks = new AtomicLong(0);
    private final AtomicLong flaggedCount = new AtomicLong(0);

    /**
     * 单次移动允许的最大距离（方块）— 生存模式正常移动不会超过此值
     * 超过此值表明可能穿过了固体方块
     */
    private static final double MAX_NORMAL_MOVE_DISTANCE = 10.0;

    /**
     * 路径采样步长（方块）— 在两点间进行路径采样时的步长
     * 较小值提供更精细的检测，较大值提高性能
     */
    private static final double PATH_SAMPLE_STEP = 0.5;

    /**
     * 触发标记所需的最小穿墙事件数
     */
    private static final int MIN_PHASE_EVENTS = 2;

    /**
     * 穿墙事件时间窗口（毫秒）— 在此窗口内的事件视为同一作弊会话
     */
    private static final long PHASE_WINDOW_MS = 30_000;

    /**
     * 地狱门Phase检测窗口（秒）— 门户交互后此时间内出现的不可能位置
     */
    private static final long PORTAL_PHASE_WINDOW_MS = 3_000;

    /**
     * 方块内部检测所需的连续检查次数
     */
    private static final int MIN_INSIDE_BLOCK_CHECKS = 3;

    /**
     * 每个玩家保留的最大穿墙事件记录数
     */
    private static final int MAX_PHASE_EVENTS = 20;

    /**
     * 无参构造函数 — 测试/默认配置使用
     */
    public AntiPhaseService() {
        this(new ServerGuardConfig());
    }

    /**
     * Spring 注入构造函数
     * @param config 全局配置，提供模块开关控制
     */
    public AntiPhaseService(ServerGuardConfig config) {
        this.config = config;
    }

    /**
     * 检测玩家移动是否穿越了固体方块（Phase hack）
     *
     * @param playerName 玩家名称
     * @param playerUUID 玩家UUID
     * @param fromX 移动起始X坐标
     * @param fromY 移动起始Y坐标
     * @param fromZ 移动起始Z坐标
     * @param toX 移动结束X坐标
     * @param toY 移动结束Y坐标
     * @param toZ 移动结束Z坐标
     * @param solidBlocksBetween 两点间固体方块数量（由Agent在Minecraft进程中统计）
     * @param isPlayerInsideBlock 移动后玩家是否在固体方块内部（由Agent检测）
     * @param isNearPortal 玩家是否在地狱门附近
     * @param gameMode 玩家游戏模式
     * @param timestamp 时间戳
     * @return 检测结果
     */
    public PhaseCheckResult detect(String playerName, String playerUUID,
                                    double fromX, double fromY, double fromZ,
                                    double toX, double toY, double toZ,
                                    int solidBlocksBetween, boolean isPlayerInsideBlock,
                                    boolean isNearPortal, String gameMode,
                                    Instant timestamp) {
        // 模块开关检查 — 关闭时跳过所有检测直接返回安全结果
        if (!config.getSecurity().getSuperEvolution().isAntiPhase()) {
            return PhaseCheckResult.clean();
        }

        // 创造和观察者模式不受方块限制，直接跳过
        if ("creative".equalsIgnoreCase(gameMode) || "spectator".equalsIgnoreCase(gameMode)) {
            return PhaseCheckResult.clean();
        }

        totalChecks.incrementAndGet();
        List<String> reasons = new ArrayList<>();

        // 获取或创建玩家事件历史
        List<PhaseEvent> events = playerPhaseEvents.computeIfAbsent(
                playerName, k -> new ArrayList<>());

        // 计算移动距离
        double dx = toX - fromX;
        double dy = toY - fromY;
        double dz = toZ - fromZ;
        double distance = Math.sqrt(dx * dx + dy * dy + dz * dz);

        // 1. 固体方块穿越检测 — 两点间存在固体方块
        if (solidBlocksBetween > 0) {
            PhaseEvent event = new PhaseEvent(timestamp, fromX, fromY, fromZ, toX, toY, toZ,
                    solidBlocksBetween, isPlayerInsideBlock, isNearPortal, distance);
            events.add(event);
            // 控制列表大小
            while (events.size() > MAX_PHASE_EVENTS) {
                events.remove(0);
            }

            // 检查是否为地狱门Phase exploit
            Instant portalTime = playerPortalInteraction.get(playerName);
            boolean isPortalPhase = portalTime != null
                    && timestamp.toEpochMilli() - portalTime.toEpochMilli() < PORTAL_PHASE_WINDOW_MS;

            if (isPortalPhase && isNearPortal) {
                reasons.add("PORTAL_PHASE: moved through " + solidBlocksBetween
                        + " solid block(s) within " + PORTAL_PHASE_WINDOW_MS / 1000
                        + "s of portal interaction (distance: " + String.format("%.2f", distance) + " blocks)");
            } else {
                reasons.add("SOLID_BLOCK_PHASE: moved through " + solidBlocksBetween
                        + " solid block(s) over " + String.format("%.2f", distance) + " blocks");
            }

            // 统计时间窗口内的穿墙事件数
            Instant windowStart = timestamp.minusMillis(PHASE_WINDOW_MS);
            long recentPhases = events.stream()
                    .filter(e -> e.timestamp.isAfter(windowStart) && e.solidBlocksCrossed > 0)
                    .count();

            if (recentPhases >= MIN_PHASE_EVENTS) {
                reasons.add("REPEATED_PHASE: " + recentPhases + " phase events in "
                        + PHASE_WINDOW_MS / 1000 + "s");
            }
        }

        // 2. 方块内部停留检测 — 玩家在固体方块内部持续存在
        if (isPlayerInsideBlock) {
            reasons.add("INSIDE_BLOCK: player detected inside solid block at ("
                    + String.format("%.1f", toX) + ", "
                    + String.format("%.1f", toY) + ", "
                    + String.format("%.1f", toZ) + ")");
        }

        // 3. 移动距离异常检测 — 单次移动距离过大
        if (distance > MAX_NORMAL_MOVE_DISTANCE && solidBlocksBetween > 0) {
            reasons.add("IMPOSSIBLE_DISTANCE: moved " + String.format("%.2f", distance)
                    + " blocks through " + solidBlocksBetween + " solid blocks (max normal: "
                    + String.format("%.1f", MAX_NORMAL_MOVE_DISTANCE) + ")");
        }

        // 更新玩家最后位置
        playerLastPosition.put(playerName, new PlayerPosition(toX, toY, toZ, timestamp));

        // 更新地狱门交互追踪
        if (isNearPortal) {
            playerPortalInteraction.put(playerName, timestamp);
        }

        // 汇总结果
        if (reasons.size() >= 2) {
            flaggedCount.incrementAndGet();
            return PhaseCheckResult.flagged(reasons);
        } else if (reasons.size() == 1) {
            return PhaseCheckResult.suspicious(reasons);
        }

        return PhaseCheckResult.clean();
    }

    /**
     * 记录玩家与地狱门的交互（Agent在检测到门户事件时调用）
     * @param playerName 玩家名称
     * @param timestamp 交互时间戳
     */
    public void recordPortalInteraction(String playerName, Instant timestamp) {
        playerPortalInteraction.put(playerName, timestamp);
    }

    /**
     * 玩家离线时清理其追踪数据，释放内存
     * @param playerName 离线玩家名称
     */
    public void clearPlayer(String playerName) {
        playerLastPosition.remove(playerName);
        playerPhaseEvents.remove(playerName);
        playerPortalInteraction.remove(playerName);
    }

    /**
     * 获取模块运行状态
     * @return 包含计数器和活跃追踪玩家数的Map
     */
    public Map<String, Object> getStatus() {
        Map<String, Object> status = new LinkedHashMap<>();
        status.put("totalChecks", totalChecks.get());
        status.put("flaggedCount", flaggedCount.get());
        status.put("activeTrackedPlayers", playerLastPosition.size());
        return status;
    }

    /**
     * 内部玩家位置记录
     */
    private static class PlayerPosition {
        final double x, y, z;
        final Instant timestamp;

        PlayerPosition(double x, double y, double z, Instant timestamp) {
            this.x = x; this.y = y; this.z = z;
            this.timestamp = timestamp;
        }
    }

    /**
     * 内部穿墙事件记录
     */
    private static class PhaseEvent {
        final Instant timestamp;
        final double fromX, fromY, fromZ;
        final double toX, toY, toZ;
        final int solidBlocksCrossed;
        final boolean insideBlock;
        final boolean nearPortal;
        final double distance;

        PhaseEvent(Instant timestamp, double fromX, double fromY, double fromZ,
                   double toX, double toY, double toZ, int solidBlocksCrossed,
                   boolean insideBlock, boolean nearPortal, double distance) {
            this.timestamp = timestamp;
            this.fromX = fromX; this.fromY = fromY; this.fromZ = fromZ;
            this.toX = toX; this.toY = toY; this.toZ = toZ;
            this.solidBlocksCrossed = solidBlocksCrossed;
            this.insideBlock = insideBlock;
            this.nearPortal = nearPortal;
            this.distance = distance;
        }
    }

    /**
     * Phase检测结果 — 不可变结果类
     */
    public static class PhaseCheckResult {
        private final boolean flagged;
        private final boolean suspicious;
        private final List<String> reasons;

        private PhaseCheckResult(boolean flagged, boolean suspicious, List<String> reasons) {
            this.flagged = flagged;
            this.suspicious = suspicious;
            this.reasons = reasons;
        }

        /** 无异常 — 正常移动路径 */
        public static PhaseCheckResult clean() {
            return new PhaseCheckResult(false, false, List.of());
        }

        /** 可疑 — 检测到穿墙但证据不够充分（可能为网络延迟/边界情况） */
        public static PhaseCheckResult suspicious(List<String> reasons) {
            return new PhaseCheckResult(false, true, reasons);
        }

        /** 已标记 — 多项规则命中，确认为穿墙作弊 */
        public static PhaseCheckResult flagged(List<String> reasons) {
            return new PhaseCheckResult(true, false, reasons);
        }

        public boolean isFlagged() { return flagged; }
        public boolean isSuspicious() { return suspicious; }
        public boolean isClean() { return !flagged && !suspicious; }
        public List<String> getReasons() { return reasons; }
    }
}
