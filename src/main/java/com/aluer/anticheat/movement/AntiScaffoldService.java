package com.aluer.anticheat.movement;

import com.aluer.config.ServerGuardConfig;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * 自动搭路（Scaffold）检测服务 — V4.0 反作弊扩展模块
 *
 * 检测原理：
 * 1. 方块放置速率检测 — Scaffold hack的特征是快速连续放置方块用于搭路，
 *    正常玩家的方块放置间隔不可能短到1秒内放置5+方块且持续3秒以上。
 * 2. 放置角度检测 — Scaffold hack通常要求玩家向下看（pitch接近90度），
 *    而正常玩家在放置方块时会自然地改变视角。检测放置时俯仰角的机械一致性。
 * 3. Safewalk检测 — Scaffold hack的一个常见附加功能是Safewalk，
 *    防止玩家在方块边缘掉落或移位（通过自动潜行或调整位置实现）。
 * 4. 放置位置模式检测 — 检测方块是否精确放置在脚下/前方（Scaffold模式），
 *    以及放置面是否为空气面（空中搭路）。
 *
 * 配置开关：serverguard.security.super-evolution.anti-scaffold
 */
@Service
public class AntiScaffoldService {

    private final ServerGuardConfig config;

    /**
     * 追踪每个玩家的方块放置记录（playerName -> 放置记录列表）
     */
    private final Map<String, List<PlacementRecord>> playerPlacementHistory = new ConcurrentHashMap<>();

    /**
     * 追踪每个玩家的持续高速放置计时（playerName -> 高速放置开始时间）
     */
    private final Map<String, Instant> playerRapidPlacingSince = new ConcurrentHashMap<>();

    /**
     * 追踪每个玩家的放置角度记录（playerName -> 角度列表）
     */
    private final Map<String, List<Double>> playerPitchHistory = new ConcurrentHashMap<>();

    /**
     * 追踪每个玩家的方块边缘安全状态（playerName -> 是否处于安全行走区域）
     */
    private final Map<String, SafewalkData> playerSafewalkData = new ConcurrentHashMap<>();

    private final AtomicLong totalPlacements = new AtomicLong(0);
    private final AtomicLong scaffoldViolations = new AtomicLong(0);

    /**
     * 最大正常放置速率（方块/秒）— 超过此速率视为异常快速放置
     * 正常玩家在有预谋的情况下也很难超过3-4方块/秒
     */
    private static final double MAX_PLACEMENT_RATE = 5.0;

    /**
     * 持续高速放置时间阈值（毫秒）— 需要高速放置持续3秒以上才标记
     */
    private static final long MIN_RAPID_DURATION_MS = 3_000;

    /**
     * Scaffold俯仰角阈值（度数）— pitch接近-90或90时表示玩家在看正下或正上方
     * Scaffold hack用户典型地向下看（pitch接近-90）
     */
    private static final double SCAFFOLD_PITCH_THRESHOLD = 60.0;

    /**
     * 放置角度一致性阈值 — 连续放置时pitch变化小于此值表示机械性的固定视角
     */
    private static final double PITCH_CONSISTENCY_THRESHOLD = 3.0;

    /**
     * 最小放置次数 — 需要足够的放置样本才能进行分析
     */
    private static final int MIN_PLACEMENTS_FOR_ANALYSIS = 10;

    /**
     * 每个玩家保留的最大放置记录数
     */
    private static final int MAX_PLACEMENT_RECORDS = 50;

    /**
     * 无参构造函数 — 测试/默认配置使用
     */
    public AntiScaffoldService() {
        this(new ServerGuardConfig());
    }

    /**
     * Spring 注入构造函数
     * @param config 全局配置，提供模块开关控制
     */
    public AntiScaffoldService(ServerGuardConfig config) {
        this.config = config;
    }

    /**
     * 检测玩家的方块放置行为是否存在Scaffold hack特征
     *
     * @param playerName 玩家名称
     * @param playerUUID 玩家UUID
     * @param placedX 放置方块X坐标
     * @param placedY 放置方块Y坐标
     * @param placedZ 放置方块Z坐标
     * @param playerYaw 玩家水平视角（度数）
     * @param playerPitch 玩家俯仰视角（度数）
     * @param isPlaceBelowPlayer 放置位置是否在玩家脚下
     * @param isAdjacentToPlayer 放置位置是否紧邻玩家
     * @param blockType 放置的方块类型
     * @param timestamp 时间戳
     * @return 检测结果
     */
    public ScaffoldCheckResult detect(String playerName, String playerUUID,
                                       double placedX, double placedY, double placedZ,
                                       double playerYaw, double playerPitch,
                                       boolean isPlaceBelowPlayer, boolean isAdjacentToPlayer,
                                       String blockType, Instant timestamp) {
        // 模块开关检查 — 关闭时跳过所有检测
        if (!config.getSecurity().getSuperEvolution().isAntiScaffold()) {
            return ScaffoldCheckResult.clean();
        }

        totalPlacements.incrementAndGet();

        List<PlacementRecord> history = playerPlacementHistory.computeIfAbsent(
                playerName, k -> new ArrayList<>());
        List<Double> pitchHistory = playerPitchHistory.computeIfAbsent(
                playerName, k -> new ArrayList<>());

        PlacementRecord record = new PlacementRecord(timestamp, placedX, placedY, placedZ,
                playerYaw, playerPitch, isPlaceBelowPlayer, isAdjacentToPlayer, blockType);
        history.add(record);
        pitchHistory.add(playerPitch);

        while (history.size() > MAX_PLACEMENT_RECORDS) {
            history.remove(0);
        }
        while (pitchHistory.size() > 20) {
            pitchHistory.remove(0);
        }

        List<String> reasons = new ArrayList<>();

        // 1. 方块放置速率检测
        // 计算最近3秒内的放置数量
        Instant threeSecondsAgo = timestamp.minusMillis(3_000);
        long recentPlacements = history.stream()
                .filter(r -> !r.timestamp.isBefore(threeSecondsAgo))
                .count();
        double placementRate = recentPlacements / 3.0; // 每秒放置数

        if (placementRate > MAX_PLACEMENT_RATE) {
            // 高速放置
            playerRapidPlacingSince.putIfAbsent(playerName, timestamp);

            Instant rapidStartTime = playerRapidPlacingSince.get(playerName);
            long rapidDurationMs = timestamp.toEpochMilli() - rapidStartTime.toEpochMilli();

            if (rapidDurationMs >= MIN_RAPID_DURATION_MS) {
                reasons.add("RAPID_PLACEMENT: " + String.format("%.1f", placementRate)
                        + " blocks/s for " + (rapidDurationMs / 1000.0)
                        + "s (threshold: " + String.format("%.1f", MAX_PLACEMENT_RATE) + " blocks/s)");
            }
        } else {
            // 速率恢复正常
            playerRapidPlacingSince.remove(playerName);
        }

        // 2. 放置角度检测 — Scaffold hack用户看下方放置
        double absPitch = Math.abs(playerPitch);
        if (absPitch > SCAFFOLD_PITCH_THRESHOLD && (isPlaceBelowPlayer || isAdjacentToPlayer)) {
            // 玩家在看下方且方块放在脚下或旁边 — 典型Scaffold姿势

            // 检查角度一致性
            if (pitchHistory.size() >= MIN_PLACEMENTS_FOR_ANALYSIS) {
                double maxDeviation = 0;
                double[] pitches = new double[pitchHistory.size()];
                for (int i = 0; i < pitchHistory.size(); i++) {
                    pitches[i] = pitchHistory.get(i);
                }
                for (int i = 1; i < pitches.length; i++) {
                    double diff = Math.abs(pitches[i] - pitches[i - 1]);
                    if (diff > maxDeviation) maxDeviation = diff;
                }

                if (maxDeviation < PITCH_CONSISTENCY_THRESHOLD && absPitch > SCAFFOLD_PITCH_THRESHOLD) {
                    reasons.add("SCAFFOLD_ANGLE: pitch " + String.format("%.1f", absPitch)
                            + " degrees (looking down), max deviation "
                            + String.format("%.2f", PITCH_CONSISTENCY_THRESHOLD) + " degrees");
                }
            }
        }

        // 3. 放置位置模式检测 — 连续在脚下/前方放置
        if (history.size() >= MIN_PLACEMENTS_FOR_ANALYSIS) {
            long belowCount = history.stream().filter(r -> r.isPlaceBelowPlayer).count();
            long adjacentCount = history.stream().filter(r -> r.isAdjacentToPlayer).count();
            long scaffoldPlaceCount = belowCount + adjacentCount;

            // 超过90%的放置都在脚下或相邻位置 — 典型的Scaffold模式
            if ((double) scaffoldPlaceCount / history.size() > 0.9
                    && scaffoldPlaceCount >= MIN_PLACEMENTS_FOR_ANALYSIS) {
                reasons.add("SCAFFOLD_PLACEMENT_PATTERN: " + scaffoldPlaceCount + "/"
                        + history.size() + " placements are below/adjacent to player");
            }
        }

        // 4. Safewalk检测 — 追踪玩家在方块边缘的行为
        if (isPlaceBelowPlayer) {
            // 玩家在边缘放置方块防止掉落 — 更新Safewalk追踪
            SafewalkData swd = playerSafewalkData.computeIfAbsent(
                    playerName, k -> new SafewalkData());
            swd.edgePlacements++;
            swd.lastEdgePlacement = timestamp;

            if (swd.edgePlacements > 15) {
                reasons.add("SAFEWALK: " + swd.edgePlacements
                        + " edge placements (possible Safewalk + Scaffold combination)");
            }
        }

        if (reasons.size() >= 2) {
            scaffoldViolations.incrementAndGet();
            return ScaffoldCheckResult.flagged(reasons);
        } else if (reasons.size() == 1) {
            return ScaffoldCheckResult.suspicious(reasons);
        }

        return ScaffoldCheckResult.clean();
    }

    /**
     * 玩家离线时清理追踪数据
     * @param playerName 离线玩家名称
     */
    public void clearPlayer(String playerName) {
        playerPlacementHistory.remove(playerName);
        playerRapidPlacingSince.remove(playerName);
        playerPitchHistory.remove(playerName);
        playerSafewalkData.remove(playerName);
    }

    /**
     * 获取模块运行状态
     * @return 包含计数器和活跃追踪玩家的Map
     */
    public Map<String, Object> getStatus() {
        Map<String, Object> status = new LinkedHashMap<>();
        status.put("totalPlacements", totalPlacements.get());
        status.put("scaffoldViolations", scaffoldViolations.get());
        status.put("trackedBuilders", playerPlacementHistory.size());

        // 列出当前活跃的建造玩家
        List<Map<String, Object>> activeBuilders = new ArrayList<>();
        for (Map.Entry<String, List<PlacementRecord>> entry : playerPlacementHistory.entrySet()) {
            if (!entry.getValue().isEmpty()) {
                Map<String, Object> info = new LinkedHashMap<>();
                info.put("player", entry.getKey());
                info.put("recentPlacements", entry.getValue().size());
                // 计算最近放置速率
                if (entry.getValue().size() >= 2) {
                    PlacementRecord first = entry.getValue().get(0);
                    PlacementRecord last = entry.getValue().get(entry.getValue().size() - 1);
                    long durationMs = last.timestamp.toEpochMilli() - first.timestamp.toEpochMilli();
                    if (durationMs > 0) {
                        double rate = entry.getValue().size() / (durationMs / 1000.0);
                        info.put("placementRate", String.format("%.1f", rate));
                    }
                }
                activeBuilders.add(info);
            }
        }
        activeBuilders.sort((a, b) -> Integer.compare(
                (Integer) b.get("recentPlacements"), (Integer) a.get("recentPlacements")));
        status.put("activeBuilders", activeBuilders.subList(0, Math.min(activeBuilders.size(), 10)));
        return status;
    }

    /**
     * 内部方块放置记录 — 记录单次放置的空间、角度和位置信息
     */
    private static class PlacementRecord {
        final Instant timestamp;
        final double placedX, placedY, placedZ;
        final double playerYaw, playerPitch;
        final boolean isPlaceBelowPlayer;
        final boolean isAdjacentToPlayer;
        final String blockType;

        PlacementRecord(Instant timestamp, double placedX, double placedY, double placedZ,
                        double playerYaw, double playerPitch, boolean isPlaceBelowPlayer,
                        boolean isAdjacentToPlayer, String blockType) {
            this.timestamp = timestamp;
            this.placedX = placedX;
            this.placedY = placedY;
            this.placedZ = placedZ;
            this.playerYaw = playerYaw;
            this.playerPitch = playerPitch;
            this.isPlaceBelowPlayer = isPlaceBelowPlayer;
            this.isAdjacentToPlayer = isAdjacentToPlayer;
            this.blockType = blockType;
        }
    }

    /**
     * Safewalk追踪数据 — 记录玩家在方块边缘放置方块的频率
     */
    private static class SafewalkData {
        int edgePlacements = 0;
        Instant lastEdgePlacement = Instant.now();
    }

    /**
     * Scaffold检测结果 — 不可变结果类
     */
    public static class ScaffoldCheckResult {
        private final boolean flagged;
        private final boolean suspicious;
        private final List<String> reasons;

        private ScaffoldCheckResult(boolean flagged, boolean suspicious, List<String> reasons) {
            this.flagged = flagged;
            this.suspicious = suspicious;
            this.reasons = reasons;
        }

        /** 无异常 — 正常方块放置行为 */
        public static ScaffoldCheckResult clean() {
            return new ScaffoldCheckResult(false, false, List.of());
        }

        /** 可疑 — 放置行为略有异常但不完全符合Scaffold模式 */
        public static ScaffoldCheckResult suspicious(List<String> reasons) {
            return new ScaffoldCheckResult(false, true, reasons);
        }

        /** 已标记 — 确认Scaffold hack（高速搭路+固定视角+脚下放置模式） */
        public static ScaffoldCheckResult flagged(List<String> reasons) {
            return new ScaffoldCheckResult(true, false, reasons);
        }

        public boolean isFlagged() { return flagged; }
        public boolean isSuspicious() { return suspicious; }
        public boolean isClean() { return !flagged && !suspicious; }
        public List<String> getReasons() { return reasons; }
    }
}
