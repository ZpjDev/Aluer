package com.aluer.security;

import com.aluer.config.ServerGuardConfig;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * 数据包飞行（PacketFly）检测服务 — V5.2 反作弊移动模块
 *
 * 检测原理：
 * 1. 无辅助持续上升检测 — PacketFly是最先进的飞行hack之一，通过操控移动数据包序列
 *    欺骗服务端，实现无鞘翅、无缓降、无创造模式的持续飞行。
 *    检测玩家在生存模式下没有任何飞行辅助物品（鞘翅/烟花/浮空效果）的持续垂直上升。
 * 2. 震荡模式检测 — PacketFly最典型的特征是"上下震荡"模式：
 *    快速的上下来回移动（约±0.5-2.0方块/tick的振荡），目的是重置服务端的摔落距离计算，
 *    从而避免被反飞行检测。正常玩家不会产生这种高频的垂直振荡模式。
 * 3. 永不落地检测 — PacketFly用户可以无限期保持在空中不接触地面，
 *    远超正常玩家通过跳跃、鞘翅滑翔等方式能维持的最大空中时间。
 * 4. 总垂直位移异常检测 — 在生存模式下，累计的总上升高度不应超过物理极限。
 *    PacketFly用户可以在几分钟内上升数百方块而没有任何合法的上升手段。
 *
 * 配置开关：serverguard.security.super-evolution.anti-packet-fly
 */
@Service
public class AntiPacketFlyService {

    private final ServerGuardConfig config;

    /**
     * 追踪每个玩家的移动历史（playerName -> 移动记录列表）
     */
    private final Map<String, List<PacketFlyRecord>> playerMoveHistory = new ConcurrentHashMap<>();

    /**
     * 追踪每个玩家的连续空中tick（playerName -> 连续不落地tick计数）
     */
    private final Map<String, Integer> playerAirTicks = new ConcurrentHashMap<>();

    /**
     * 追踪每个玩家的累计上升高度（playerName -> 累计上升方块数）
     */
    private final Map<String, Double> playerTotalRise = new ConcurrentHashMap<>();

    /**
     * 追踪每个玩家最近一次接触地面的时间（playerName -> 时间戳）
     */
    private final Map<String, Instant> playerLastGroundContact = new ConcurrentHashMap<>();

    /**
     * 追踪每个玩家的振荡检测数据（playerName -> Y方向变化列表）
     */
    private final Map<String, List<Double>> playerDyHistory = new ConcurrentHashMap<>();

    private final AtomicLong totalChecks = new AtomicLong(0);
    private final AtomicLong packetFlyViolations = new AtomicLong(0);

    /**
     * 单tick最大合法垂直上升（生存模式无飞行辅助）— 约为0.42 blocks/tick（跳跃峰值）
     */
    private static final double MAX_SURVIVAL_VERTICAL_RISE = 0.5;

    /**
     * 持续空中tick阈值 — 超过此值且持续上升则标记
     * 正常玩家从最高处跳下也最多在空中停留约12 ticks
     */
    private static final int MAX_AIR_TICKS_NORMAL = 20;

    /**
     * 振荡检测窗口大小 — 在此窗口内检测方向反转次数
     */
    private static final int OSCILLATION_WINDOW = 10;

    /**
     * 振荡检测：方向反转次数阈值 — 在窗口内反转超过此值即为振荡模式
     */
    private static final int MAX_DIRECTION_REVERSALS = 4;

    /**
     * 累计上升高度异常阈值 — 生存模式无辅助累计上升超过此值可疑
     */
    private static final double MAX_CUMULATIVE_RISE = 50.0;

    /**
     * 永不落地时间阈值（毫秒）— 超过30秒不落地即为异常
     */
    private static final long MAX_AIR_TIME_MS = 30_000;

    /**
     * 每个玩家保留的最大记录数
     */
    private static final int MAX_RECORDS_PER_PLAYER = 60;

    /**
     * 无参构造函数 — 测试/默认配置使用
     */
    public AntiPacketFlyService() {
        this(new ServerGuardConfig());
    }

    /**
     * Spring 注入构造函数
     * @param config 全局配置，提供模块开关控制
     */
    public AntiPacketFlyService(ServerGuardConfig config) {
        this.config = config;
    }

    /**
     * 检测玩家是否使用PacketFly数据包操控飞行
     *
     * @param playerName       玩家名称
     * @param playerUUID       玩家UUID
     * @param fromX            移动起始X坐标
     * @param fromY            移动起始Y坐标
     * @param fromZ            移动起始Z坐标
     * @param toX              移动结束X坐标
     * @param toY              移动结束Y坐标
     * @param toZ              移动结束Z坐标
     * @param onGround         玩家是否在地面
     * @param gameMode         游戏模式（survival/creative/spectator）
     * @param hasElytra        是否装备鞘翅
     * @param hasLevitation    是否有浮空效果
     * @param isUsingFirework  是否正在使用烟花（鞘翅助推）
     * @param timestamp        时间戳
     * @return 检测结果
     */
    public PacketFlyCheckResult detect(String playerName, String playerUUID,
                                        double fromX, double fromY, double fromZ,
                                        double toX, double toY, double toZ,
                                        boolean onGround, String gameMode,
                                        boolean hasElytra, boolean hasLevitation,
                                        boolean isUsingFirework, Instant timestamp) {
        // 模块开关检查 — 关闭时跳过所有检测
        if (!config.getSecurity().getSuperEvolution().isAntiPacketFly()) {
            return PacketFlyCheckResult.clean();
        }

        totalChecks.incrementAndGet();

        // 创造/旁观模式允许飞行，跳过
        if ("creative".equalsIgnoreCase(gameMode) || "spectator".equalsIgnoreCase(gameMode)) {
            return PacketFlyCheckResult.clean();
        }

        double dy = toY - fromY;
        double dx = toX - fromX;
        double dz = toZ - fromZ;
        double horizontalDist = Math.sqrt(dx * dx + dz * dz);

        List<PacketFlyRecord> history = playerMoveHistory.computeIfAbsent(
                playerName, k -> new ArrayList<>());
        List<Double> dyHistory = playerDyHistory.computeIfAbsent(
                playerName, k -> new ArrayList<>());

        PacketFlyRecord record = new PacketFlyRecord(timestamp, fromX, fromY, fromZ,
                toX, toY, toZ, dy, horizontalDist, onGround, hasElytra,
                hasLevitation, isUsingFirework);
        history.add(record);
        dyHistory.add(dy);

        while (history.size() > MAX_RECORDS_PER_PLAYER) {
            history.remove(0);
        }
        while (dyHistory.size() > 30) {
            dyHistory.remove(0);
        }

        // 更新空中tick计数
        if (!onGround) {
            int airTicks = playerAirTicks.getOrDefault(playerName, 0) + 1;
            playerAirTicks.put(playerName, airTicks);
        } else {
            playerAirTicks.remove(playerName);
            playerLastGroundContact.put(playerName, timestamp);
            // 落地时重置累计上升
            playerTotalRise.remove(playerName);
        }

        // 累计上升高度（只计正方向）
        if (dy > 0) {
            double totalRise = playerTotalRise.getOrDefault(playerName, 0.0) + dy;
            playerTotalRise.put(playerName, totalRise);
        }

        // 确定玩家是否有合法飞行手段
        boolean canFlyLegitimately = hasElytra || hasLevitation || isUsingFirework;

        List<String> reasons = new ArrayList<>();

        // 1. 核心检测：无合法手段的持续上升
        if (!onGround && dy > MAX_SURVIVAL_VERTICAL_RISE && !canFlyLegitimately) {
            reasons.add("IMPOSSIBLE_RISE: dy=" + String.format("%.3f", dy)
                    + " blocks/tick in survival with no flight items"
                    + " (max normal: " + String.format("%.2f", MAX_SURVIVAL_VERTICAL_RISE) + ")");
        }

        // 2. 振荡模式检测 — PacketFly的典型特征
        if (dyHistory.size() >= OSCILLATION_WINDOW) {
            int reversals = 0;
            double prevSign = Math.signum(dyHistory.get(dyHistory.size() - OSCILLATION_WINDOW));

            for (int i = dyHistory.size() - OSCILLATION_WINDOW + 1; i < dyHistory.size(); i++) {
                double currentSign = Math.signum(dyHistory.get(i));
                if (currentSign != 0 && prevSign != 0 && currentSign != prevSign) {
                    reversals++;
                }
                if (currentSign != 0) {
                    prevSign = currentSign;
                }
            }

            // 高频振荡且振幅明显 — PacketFly特征
            if (reversals >= MAX_DIRECTION_REVERSALS) {
                // 检查振荡幅度是否显著
                double maxDy = 0;
                int start = Math.max(0, dyHistory.size() - OSCILLATION_WINDOW);
                for (int i = start; i < dyHistory.size(); i++) {
                    maxDy = Math.max(maxDy, Math.abs(dyHistory.get(i)));
                }
                if (maxDy > 0.3) {
                    reasons.add("PACKET_FLY_OSCILLATION: " + reversals
                            + " direction reversals in " + OSCILLATION_WINDOW
                            + " ticks (amplitude: " + String.format("%.2f", maxDy)
                            + ", typical PacketFly bounce pattern)");
                }
            }
        }

        // 3. 永不落地检测
        int airTicks = playerAirTicks.getOrDefault(playerName, 0);
        if (airTicks >= MAX_AIR_TICKS_NORMAL && !canFlyLegitimately) {
            // 检查是否持续上升（而非下落）
            long risingTicks = history.stream()
                    .filter(r -> r.dy > 0.05)
                    .count();
            if (risingTicks >= MAX_AIR_TICKS_NORMAL / 2) {
                reasons.add("NEVER_LANDS: " + airTicks
                        + " ticks in air without touching ground"
                        + " (" + risingTicks + " ticks rising, no flight items)");
            }
        }

        // 4. 累计上升高度异常
        double totalRise = playerTotalRise.getOrDefault(playerName, 0.0);
        if (totalRise > MAX_CUMULATIVE_RISE && !canFlyLegitimately) {
            packetFlyViolations.incrementAndGet();
            reasons.add("EXCESSIVE_CUMULATIVE_RISE: " + String.format("%.1f", totalRise)
                    + " blocks total rise without flight items"
                    + " (threshold: " + String.format("%.0f", MAX_CUMULATIVE_RISE) + ")");
        }

        // 5. 空中持续时间过长（基于时间戳）
        Instant lastGround = playerLastGroundContact.get(playerName);
        if (lastGround != null && !canFlyLegitimately) {
            long airTimeMs = timestamp.toEpochMilli() - lastGround.toEpochMilli();
            if (airTimeMs > MAX_AIR_TIME_MS) {
                reasons.add("PROLONGED_AIR_TIME: " + (airTimeMs / 1000)
                        + " seconds without ground contact (no flight items)");
            }
        }

        if (reasons.size() >= 2) {
            return PacketFlyCheckResult.flagged(reasons);
        } else if (reasons.size() == 1) {
            return PacketFlyCheckResult.suspicious(reasons);
        }

        return PacketFlyCheckResult.clean();
    }

    /**
     * 玩家离线时清理追踪数据
     * @param playerName 离线玩家名称
     */
    public void clearPlayer(String playerName) {
        playerMoveHistory.remove(playerName);
        playerAirTicks.remove(playerName);
        playerTotalRise.remove(playerName);
        playerLastGroundContact.remove(playerName);
        playerDyHistory.remove(playerName);
    }

    /**
     * 获取模块运行状态
     * @return 包含计数器和违规数量的Map
     */
    public Map<String, Object> getStatus() {
        Map<String, Object> status = new LinkedHashMap<>();
        status.put("totalChecks", totalChecks.get());
        status.put("packetFlyViolations", packetFlyViolations.get());
        status.put("activeTrackedPlayers", playerMoveHistory.size());

        // 列出空中玩家
        List<Map<String, Object>> airbornePlayers = new ArrayList<>();
        for (Map.Entry<String, Integer> entry : playerAirTicks.entrySet()) {
            if (entry.getValue() > MAX_AIR_TICKS_NORMAL) {
                Map<String, Object> info = new LinkedHashMap<>();
                info.put("player", entry.getKey());
                info.put("airTicks", entry.getValue());
                info.put("totalRise", String.format("%.1f",
                        playerTotalRise.getOrDefault(entry.getKey(), 0.0)));
                airbornePlayers.add(info);
            }
        }
        status.put("extendedAirbornePlayers", airbornePlayers);
        return status;
    }

    /**
     * 内部PacketFly移动记录 — 记录玩家单次移动的状态数据
     */
    private static class PacketFlyRecord {
        final Instant timestamp;
        final double fromX, fromY, fromZ;
        final double toX, toY, toZ;
        final double dy;
        final double horizontalDist;
        final boolean onGround;
        final boolean hasElytra;
        final boolean hasLevitation;
        final boolean isUsingFirework;

        PacketFlyRecord(Instant timestamp, double fromX, double fromY, double fromZ,
                        double toX, double toY, double toZ, double dy,
                        double horizontalDist, boolean onGround,
                        boolean hasElytra, boolean hasLevitation,
                        boolean isUsingFirework) {
            this.timestamp = timestamp;
            this.fromX = fromX; this.fromY = fromY; this.fromZ = fromZ;
            this.toX = toX; this.toY = toY; this.toZ = toZ;
            this.dy = dy;
            this.horizontalDist = horizontalDist;
            this.onGround = onGround;
            this.hasElytra = hasElytra;
            this.hasLevitation = hasLevitation;
            this.isUsingFirework = isUsingFirework;
        }
    }

    /**
     * PacketFly检测结果 — 不可变结果类
     */
    public static class PacketFlyCheckResult {
        private final boolean flagged;
        private final boolean suspicious;
        private final List<String> reasons;

        private PacketFlyCheckResult(boolean flagged, boolean suspicious, List<String> reasons) {
            this.flagged = flagged;
            this.suspicious = suspicious;
            this.reasons = reasons;
        }

        /** 无异常 — 正常的地面/合法飞行移动 */
        public static PacketFlyCheckResult clean() {
            return new PacketFlyCheckResult(false, false, List.of());
        }

        /** 可疑 — 短暂的异常但不满足所有检测条件 */
        public static PacketFlyCheckResult suspicious(List<String> reasons) {
            return new PacketFlyCheckResult(false, true, reasons);
        }

        /** 已标记 — 确认PacketFly hack，持续无合法手段的飞行 */
        public static PacketFlyCheckResult flagged(List<String> reasons) {
            return new PacketFlyCheckResult(true, false, reasons);
        }

        public boolean isFlagged() { return flagged; }
        public boolean isSuspicious() { return suspicious; }
        public boolean isClean() { return !flagged && !suspicious; }
        public List<String> getReasons() { return reasons; }
    }
}
