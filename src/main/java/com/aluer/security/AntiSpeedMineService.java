package com.aluer.security;

import com.aluer.config.ServerGuardConfig;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

/**
 * 加速挖掘检测 (SpeedMine/InstaMine/PacketMine) — V5.3 世界/玩家/杂物安全模块
 *
 * 检测原理：
 *   Meteor Client 的 SpeedMine/InstaMine/PacketMine 模块通过操控挖掘数据包来加速或瞬间破坏方块。
 *   正常生存模式下，每种方块配合不同工具都有固定的最短破坏时间，这些时间由服务端权威控制。
 *   本模块通过以下维度检测加速挖掘作弊：
 *   1. 速度检测——记录从 startBreak 到 blockBreak 的实际耗时，与各材质方块的理论最短时间对比。
 *      黑曜石 + 钻石镐最短约 9.4 秒；若 < 1 秒即为明显的 InstaMine。
 *      石头 + 钻石镐最短约 0.3 秒；若 < 0.1 秒即为可疑。
 *   2. 连续快速破坏——单次快速破坏可能是延迟/网络抖动，但连续 5 次以上快速破坏必定为作弊。
 *   3. 视线检测 (PacketMine)——PacketMine 可以破坏玩家没有朝向的方块。
 *      通过计算玩家视线向量与破坏方块之间的夹角来判断是否看向目标方块。
 *      如果玩家持续破坏不在视线范围内的方块，则检测为 PacketMine。
 *   4. 破坏间隔均匀性——正常人类挖掘间隔有随机波动，自动化挖掘间隔高度一致。
 *
 * 配置开关：serverguard.security.super-evolution.anti-speed-mine
 */
@Service
public class AntiSpeedMineService {

    private final ServerGuardConfig config;
    /** 每个玩家的挖掘会话记录：playerName -> 挖掘开始事件列表 */
    private final Map<String, List<MiningSession>> playerMiningSessions = new ConcurrentHashMap<>();
    /** 每个玩家的快挖次数计数器 */
    private final Map<String, AtomicLong> playerFastBreakCount = new ConcurrentHashMap<>();
    /** 已标记的玩家及其过期时间 */
    private final Map<String, Instant> flaggedPlayers = new ConcurrentHashMap<>();
    private final ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor();

    /** 总挖掘事件计数 */
    private final AtomicLong totalMiningEvents = new AtomicLong(0);
    /** 加速挖掘违规次数 */
    private final AtomicLong speedMineViolations = new AtomicLong(0);

    /** 连续快挖判定阈值——连续快挖超过此数即标记 */
    private static final int CONSECUTIVE_FAST_BREAK_THRESHOLD = 5;

    /** 黑曜石 + 钻石镐理论最短时间（毫秒） */
    private static final long OBSIDIAN_MIN_TIME_MS = 9400;
    /** 石头 + 钻石镐理论最短时间（毫秒） */
    private static final long STONE_MIN_TIME_MS = 300;
    /** 通用快挖时间阈值（毫秒）——低于此值视为快速挖掘 */
    private static final long FAST_BREAK_THRESHOLD_MS = 150;

    /** 视线检测最大允许夹角（度）——玩家视线与方块中心夹角超过此值视为未朝向方块 */
    private static final double MAX_LOOK_ANGLE_DEGREES = 60.0;

    /** 记录保留时间（秒） */
    private static final long RECORD_RETENTION_SECONDS = 600;
    /** 标记持续时间（秒） */
    private static final long FLAG_DURATION_SECONDS = 1800;

    public AntiSpeedMineService() {
        this(new ServerGuardConfig());
    }

    @Autowired
    public AntiSpeedMineService(ServerGuardConfig config) {
        this.config = config;
        scheduler.scheduleAtFixedRate(this::cleanupOldRecords, 120, 300, TimeUnit.SECONDS);
    }

    /**
     * 记录一次开始挖掘事件——玩家开始破坏一个方块。
     * 在玩家点击鼠标左键开始挖掘时调用，记录起始时间和玩家视角方向。
     *
     * @param playerName   玩家名称
     * @param playerUUID   玩家 UUID
     * @param blockType    被挖掘的方块类型
     * @param x            方块 X 坐标
     * @param y            方块 Y 坐标
     * @param z            方块 Z 坐标
     * @param lookX        玩家视线方向 X 分量
     * @param lookY        玩家视线方向 Y 分量
     * @param lookZ        玩家视线方向 Z 分量
     * @param playerX      玩家眼睛 X 坐标
     * @param playerY      玩家眼睛 Y 坐标
     * @param playerZ      玩家眼睛 Z 坐标
     */
    public void recordStartBreak(String playerName, String playerUUID, String blockType,
                                  int x, int y, int z,
                                  float lookX, float lookY, float lookZ,
                                  double playerX, double playerY, double playerZ) {
        if (!config.getSecurity().getSuperEvolution().isAntiSpeedMine()) {
            return;
        }

        Instant now = Instant.now();
        List<MiningSession> sessions = playerMiningSessions.computeIfAbsent(playerName,
            k -> Collections.synchronizedList(new ArrayList<>()));
        // 记录本次挖掘开始，包含视线信息用于后续 PacketMine 检测
        sessions.add(new MiningSession(now, blockType, x, y, z, lookX, lookY, lookZ,
            playerX, playerY, playerZ, false));
        totalMiningEvents.incrementAndGet();
    }

    /**
     * 检测一次方块破坏完成事件——判断挖掘速度是否异常。
     *
     * 这是加速挖掘检测的核心方法。通过计算从 startBreak 到 blockBreak 的实际耗时，
     * 与各材质方块的理论最短时间对比。
     *
     * @param playerName 玩家名称
     * @param playerUUID 玩家 UUID
     * @param blockType  被破坏的方块类型
     * @param x          方块 X 坐标
     * @param y          方块 Y 坐标
     * @param z          方块 Z 坐标
     * @return 检测结果
     */
    public DetectionResult detectBlockBreak(String playerName, String playerUUID,
                                             String blockType, int x, int y, int z) {
        if (!config.getSecurity().getSuperEvolution().isAntiSpeedMine()) {
            return DetectionResult.clean();
        }

        // 检查玩家是否已被标记
        Instant flaggedUntil = flaggedPlayers.get(playerName);
        if (flaggedUntil != null) {
            if (Instant.now().isAfter(flaggedUntil)) {
                flaggedPlayers.remove(playerName);
            } else {
                return DetectionResult.flagged(List.of(
                    "PLAYER_ALREADY_FLAGGED: " + playerName + " under speed mine investigation"));
            }
        }

        Instant now = Instant.now();
        List<MiningSession> sessions = playerMiningSessions.get(playerName);
        if (sessions == null || sessions.isEmpty()) {
            return DetectionResult.clean();
        }

        // 找到最近一个匹配方块类型的未完成挖掘会话
        MiningSession matchedSession = null;
        int matchedIndex = -1;
        for (int i = sessions.size() - 1; i >= 0; i--) {
            MiningSession s = sessions.get(i);
            if (!s.completed && s.x == x && s.y == y && s.z == z) {
                matchedSession = s;
                matchedIndex = i;
                break;
            }
        }

        // 广度匹配：如果没有精确坐标匹配，按方块类型匹配最近一个
        if (matchedSession == null) {
            for (int i = sessions.size() - 1; i >= 0; i--) {
                MiningSession s = sessions.get(i);
                if (!s.completed) {
                    matchedSession = s;
                    matchedIndex = i;
                    break;
                }
            }
        }

        if (matchedSession == null) {
            return DetectionResult.clean();
        }

        // 标记该会话为已完成，计算实际挖掘时间
        matchedSession.completed = true;
        long actualTimeMs = now.toEpochMilli() - matchedSession.startTime.toEpochMilli();

        int score = 0;
        List<String> reasons = new ArrayList<>();

        // === 检测 1: 速度检测——按方块类型对比理论最短时间 ===
        long minExpectedTime = getMinExpectedTime(blockType);
        if (actualTimeMs < minExpectedTime * 0.5) {
            // 挖掘时间不足理论最短时间的 50%
            score += 30;
            reasons.add("SPEED_VIOLATION: " + blockType + " broken in " + actualTimeMs +
                "ms (expected min " + minExpectedTime + "ms)");
        }

        // === 检测 1b: 通用快挖检测——低于 150ms 的统一阈值 ===
        if (actualTimeMs < FAST_BREAK_THRESHOLD_MS) {
            score += 20;
            reasons.add("SUB_THRESHOLD_BREAK: " + blockType + " broken in " + actualTimeMs +
                "ms (below universal threshold " + FAST_BREAK_THRESHOLD_MS + "ms)");

            // 增加快挖计数
            AtomicLong fastBreakCount = playerFastBreakCount.computeIfAbsent(playerName,
                k -> new AtomicLong(0));
            fastBreakCount.incrementAndGet();
        }

        // === 检测 2: 连续快速破坏检测 ===
        // 统计最近几次挖掘中低于阈值的连续次数
        long consecutiveFast = countConsecutiveFastBreaks(sessions);
        if (consecutiveFast >= CONSECUTIVE_FAST_BREAK_THRESHOLD) {
            score += 40;
            reasons.add("CONSECUTIVE_FAST_BREAK: " + consecutiveFast +
                " consecutive breaks under " + FAST_BREAK_THRESHOLD_MS + "ms");
        }

        // === 检测 3: PacketMine 视线检测 ===
        // 计算玩家视线与方块中心之间的夹角
        double blockCenterX = x + 0.5;
        double blockCenterY = y + 0.5;
        double blockCenterZ = z + 0.5;
        double angleDeg = calculateLookAngle(
            matchedSession.playerX, matchedSession.playerY, matchedSession.playerZ,
            matchedSession.lookX, matchedSession.lookY, matchedSession.lookZ,
            blockCenterX, blockCenterY, blockCenterZ);

        if (angleDeg > MAX_LOOK_ANGLE_DEGREES) {
            score += 25;
            reasons.add("PACKET_MINE: look angle " + String.format("%.1f", angleDeg) +
                " deg exceeds max " + MAX_LOOK_ANGLE_DEGREES + " deg (not facing block)");
        }

        // === 检测 4: 挖掘间隔均匀性 ===
        if (sessions.size() >= 10) {
            double cov = calculateIntervalCOV(sessions);
            if (cov < 0.15) {
                score += 15;
                reasons.add("UNIFORM_INTERVAL: break interval COV=" + String.format("%.4f", cov) +
                    " (mechanical pattern)");
            }
        }

        // === 判定 ===
        if (score >= 50) {
            flaggedPlayers.put(playerName, Instant.now().plusSeconds(FLAG_DURATION_SECONDS));
            speedMineViolations.incrementAndGet();
            return DetectionResult.flagged(reasons);
        } else if (score >= 30) {
            return DetectionResult.suspicious(score, reasons);
        }

        return DetectionResult.clean();
    }

    /**
     * 获取指定方块类型的理论最短挖掘时间（毫秒）。
     *
     * 数据来源：Minecraft Wiki — Breaking / Speed 表格
     * 默认使用钻石镐效率 V 的计算值，未列出则使用通用估算。
     */
    private long getMinExpectedTime(String blockType) {
        if (blockType == null) return 500;
        return switch (blockType.toUpperCase()) {
            case "OBSIDIAN", "CRYING_OBSIDIAN" -> OBSIDIAN_MIN_TIME_MS;
            case "STONE", "COBBLESTONE", "DEEPSLATE" -> STONE_MIN_TIME_MS;
            case "ENDER_CHEST", "ANCIENT_DEBRIS" -> 6250;
            case "DIAMOND_ORE", "DEEPSLATE_DIAMOND_ORE", "EMERALD_ORE", "DEEPSLATE_EMERALD_ORE" -> 850;
            case "IRON_ORE", "DEEPSLATE_IRON_ORE", "GOLD_ORE", "DEEPSLATE_GOLD_ORE" -> 550;
            case "NETHERRACK", "DIRT", "SAND", "GRAVEL" -> 150;
            case "WOOD", "OAK_LOG", "BIRCH_LOG", "SPRUCE_LOG", "JUNGLE_LOG",
                 "ACACIA_LOG", "DARK_OAK_LOG", "CRIMSON_STEM", "WARPED_STEM" -> 300;
            default -> 400; // 通用默认值
        };
    }

    /**
     * 计算玩家视线方向与目标方块中心之间的夹角（度）。
     *
     * 使用向量点积公式：cos(theta) = (a.b) / (|a| * |b|)
     * 夹角越大说明玩家越没看向目标，PacketMine 的特征是夹角接近 90 度甚至超过。
     */
    private double calculateLookAngle(double playerX, double playerY, double playerZ,
                                       float lookX, float lookY, float lookZ,
                                       double targetX, double targetY, double targetZ) {
        // 从玩家位置到目标方块中心的向量
        double dx = targetX - playerX;
        double dy = targetY - playerY;
        double dz = targetZ - playerZ;

        double dist = Math.sqrt(dx * dx + dy * dy + dz * dz);
        if (dist < 0.001) return 0.0; // 几乎在同一位置

        // 视线向量长度
        double lookLen = Math.sqrt(lookX * lookX + lookY * lookY + lookZ * lookZ);
        if (lookLen < 0.001) return 90.0; // 无视线方向，默认为大角度

        // 点积
        double dot = (dx / dist) * (lookX / lookLen)
                   + (dy / dist) * (lookY / lookLen)
                   + (dz / dist) * (lookZ / lookLen);

        // 限制在 [-1, 1] 范围内防浮点溢出
        dot = Math.max(-1.0, Math.min(1.0, dot));
        return Math.toDegrees(Math.acos(dot));
    }

    /**
     * 统计最近连续低于快挖阈值的挖掘事件数量。
     */
    private long countConsecutiveFastBreaks(List<MiningSession> sessions) {
        int fastCount = 0;
        Instant now = Instant.now();
        long windowStart = now.toEpochMilli() - 10000; // 只看最近 10 秒
        for (int i = sessions.size() - 1; i >= 0; i--) {
            MiningSession s = sessions.get(i);
            if (!s.completed) continue;
            long breakTime = s.getBreakTimeMs();
            if (breakTime > 0 && breakTime < FAST_BREAK_THRESHOLD_MS
                && s.startTime.toEpochMilli() > windowStart) {
                fastCount++;
            } else if (breakTime >= FAST_BREAK_THRESHOLD_MS) {
                break; // 遇到正常速度的挖掘则停止计数
            }
        }
        return fastCount;
    }

    /**
     * 计算挖掘间隔的变异系数（COV），用于检测自动化挖掘的均匀节奏。
     */
    private double calculateIntervalCOV(List<MiningSession> sessions) {
        List<Long> intervals = new ArrayList<>();
        for (int i = Math.max(0, sessions.size() - 20); i < sessions.size() - 1; i++) {
            MiningSession a = sessions.get(i);
            MiningSession b = sessions.get(i + 1);
            if (a.completed && b.completed) {
                intervals.add(b.startTime.toEpochMilli() - a.startTime.toEpochMilli());
            }
        }
        if (intervals.size() < 5) return 1.0;
        double mean = intervals.stream().mapToLong(Long::longValue).average().orElse(0);
        if (mean == 0) return 1.0;
        double variance = intervals.stream()
            .mapToDouble(i -> Math.pow(i - mean, 2))
            .average().orElse(0);
        return Math.sqrt(variance) / mean;
    }

    public void clearPlayer(String playerName) {
        playerMiningSessions.remove(playerName);
        playerFastBreakCount.remove(playerName);
        flaggedPlayers.remove(playerName);
    }

    public Map<String, Object> getStatus() {
        Map<String, Object> s = new LinkedHashMap<>();
        s.put("totalMiningEvents", totalMiningEvents.get());
        s.put("speedMineViolations", speedMineViolations.get());
        s.put("trackedPlayers", playerMiningSessions.size());
        s.put("flaggedPlayers", flaggedPlayers.size());
        s.put("enabled", config.getSecurity().getSuperEvolution().isAntiSpeedMine());
        return s;
    }

    public long getTotalMiningEvents() { return totalMiningEvents.get(); }
    public long getSpeedMineViolations() { return speedMineViolations.get(); }

    private void cleanupOldRecords() {
        Instant cutoff = Instant.now().minusSeconds(RECORD_RETENTION_SECONDS);
        playerMiningSessions.entrySet().removeIf(e -> {
            List<MiningSession> sessions = e.getValue();
            sessions.removeIf(s -> s.startTime.isBefore(cutoff));
            return sessions.isEmpty();
        });
        playerFastBreakCount.entrySet().removeIf(e ->
            !playerMiningSessions.containsKey(e.getKey()));
        flaggedPlayers.entrySet().removeIf(e -> e.getValue().isBefore(Instant.now()));
    }

    // ==================== 内部数据类 ====================

    /**
     * 挖掘会话记录——追踪单次方块挖掘从开始到完成的完整信息。
     */
    private static class MiningSession {
        final Instant startTime;
        final String blockType;
        final int x, y, z;
        final float lookX, lookY, lookZ;   // 开始挖掘时玩家的视线方向
        final double playerX, playerY, playerZ; // 开始挖掘时玩家的眼睛坐标
        boolean completed;                  // 是否已完成（blockBreak 触发）
        Instant endTime;                    // 完成时间（completed 后才有效）

        MiningSession(Instant startTime, String blockType, int x, int y, int z,
                     float lookX, float lookY, float lookZ,
                     double playerX, double playerY, double playerZ, boolean completed) {
            this.startTime = startTime;
            this.blockType = blockType;
            this.x = x;
            this.y = y;
            this.z = z;
            this.lookX = lookX;
            this.lookY = lookY;
            this.lookZ = lookZ;
            this.playerX = playerX;
            this.playerY = playerY;
            this.playerZ = playerZ;
            this.completed = completed;
        }

        /**
         * 获取实际挖掘耗时（毫秒），未完成则返回 -1。
         */
        long getBreakTimeMs() {
            if (!completed || endTime == null) return -1;
            return endTime.toEpochMilli() - startTime.toEpochMilli();
        }
    }

    // ==================== 检测结果类 ====================

    /**
     * 加速挖掘检测结果。
     */
    public static class DetectionResult {
        private final boolean flagged;
        private final boolean suspicious;
        private final int score;
        private final List<String> reasons;

        private DetectionResult(boolean flagged, boolean suspicious, int score, List<String> reasons) {
            this.flagged = flagged;
            this.suspicious = suspicious;
            this.score = score;
            this.reasons = reasons;
        }

        /** 无异常：挖掘行为正常 */
        public static DetectionResult clean() {
            return new DetectionResult(false, false, 0, List.of());
        }

        /** 可疑行为：存在加速挖掘特征但置信度不足 */
        public static DetectionResult suspicious(int score, List<String> reasons) {
            return new DetectionResult(false, true, score, reasons);
        }

        /** 已标记：检测到高置信度加速挖掘行为 */
        public static DetectionResult flagged(List<String> reasons) {
            return new DetectionResult(true, true, 100, reasons);
        }

        public boolean isFlagged() { return flagged; }
        public boolean isSuspicious() { return suspicious; }
        public boolean isClean() { return !flagged && !suspicious; }
        public int getScore() { return score; }
        public List<String> getReasons() { return reasons; }
    }
}
