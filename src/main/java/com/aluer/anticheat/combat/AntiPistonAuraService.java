package com.aluer.anticheat.combat;

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
 * 活塞陷阱自动化检测 (PistonAura) — V5.3 世界/玩家/杂物安全模块
 *
 * 检测原理：
 *   Meteor Client 的 PistonAura 模块在 PvP 战斗中自动在对手周围放置并激活活塞，
 *   将对手推入陷阱或限制其移动。正常玩家的活塞使用是偶发性、手工操作的，
 *   有明显的放置-激活时间差。PistonAura 则是快速连续的自动化操作。
 *   本模块通过以下维度检测：
 *   1. 活塞激活速率——正常玩家每秒很少激活超过 1 个活塞，
 *      PistonAura 可以在一秒内放置并激活多个活塞。
 *   2. 放置与激活同 tick——正常玩家放置活塞后需要切换红石信号源并手动激活，
 *      间隔通常 > 200ms。PistonAura 放置与红石激活发生在同 tick（0-50ms）。
 *   3. 活塞朝向精确对准其他玩家——检查活塞头方向是否精确指向附近玩家坐标。
 *      正常玩家手动放置活塞很难做到 100% 精准朝向对手。
 *   4. 战斗上下文中活塞密集使用——当附近存在其他玩家时活塞激活密度显著升高。
 *      正常情况下活塞在建筑/红石机械中使用，而非战斗。
 *
 * 配置开关：serverguard.security.super-evolution.anti-piston-aura
 */
@Service
public class AntiPistonAuraService {

    private final ServerGuardConfig config;
    /** 每个玩家的活塞放置记录 */
    private final Map<String, List<PistonEvent>> playerPistonEvents = new ConcurrentHashMap<>();
    /** 每个玩家的红石激活记录 */
    private final Map<String, List<RedstoneActivation>> playerRedstoneActivations = new ConcurrentHashMap<>();
    /** 每个玩家的近战玩家接触记录 */
    private final Map<String, List<PlayerEncounter>> playerEncounters = new ConcurrentHashMap<>();
    /** 已标记的玩家 */
    private final Map<String, Instant> flaggedPlayers = new ConcurrentHashMap<>();
    private final ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor();

    private final AtomicLong totalPistonEvents = new AtomicLong(0);
    private final AtomicLong pistonAuraViolations = new AtomicLong(0);

    /** 活塞激活速率阈值（每分钟激活次数）——超过此值即为异常 */
    private static final int PISTON_RATE_PER_MINUTE_THRESHOLD = 12;
    /** 同 tick 放置与激活判定阈值（毫秒） */
    private static final long PLACE_POWER_SAME_TICK_MS = 50;
    /** 活塞对准玩家方位检查——活塞头指向与玩家方向的最大夹角（度） */
    private static final double PISTON_AIM_ANGLE_THRESHOLD = 15.0;
    /** 战斗上下文中活塞激活检测——附近有玩家时的活塞频率倍率阈值 */
    private static final double COMBAT_PISTON_MULTIPLIER = 3.0;
    /** 近战判定距离（格）——玩家在此范围内视为在战斗上下文 */
    private static final double NEARBY_PLAYER_DISTANCE = 8.0;
    /** 最少活塞事件数用于速率分析 */
    private static final int MIN_PISTON_EVENTS = 3;

    /** 记录保留时间（秒） */
    private static final long RECORD_RETENTION_SECONDS = 600;
    /** 标记持续时间（秒） */
    private static final long FLAG_DURATION_SECONDS = 1800;

    /** 活塞方块类型关键词 */
    private static final String PISTON_KEYWORD = "PISTON";
    /** 红石信号源类型关键词 */
    private static final Set<String> REDSTONE_ACTIVATORS = Set.of(
        "REDSTONE_BLOCK", "REDSTONE_TORCH", "REDSTONE_WALL_TORCH",
        "LEVER", "BUTTON", "PRESSURE_PLATE", "OBSERVER",
        "DETECTOR_RAIL", "TRIPWIRE_HOOK", "DAYLIGHT_DETECTOR",
        "SCULK_SENSOR", "TARGET", "TRAPPED_CHEST",
        "REPEATER", "COMPARATOR", "REDSTONE_WIRE"
    );

    public AntiPistonAuraService() {
        this(new ServerGuardConfig());
    }

    @Autowired
    public AntiPistonAuraService(ServerGuardConfig config) {
        this.config = config;
        scheduler.scheduleAtFixedRate(this::cleanupOldRecords, 120, 300, TimeUnit.SECONDS);
    }

    /**
     * 记录一次活塞放置事件——玩家放置活塞方块时调用。
     *
     * @param playerName 玩家名称
     * @param playerUUID 玩家 UUID
     * @param pistonX    活塞 X 坐标
     * @param pistonY    活塞 Y 坐标
     * @param pistonZ    活塞 Z 坐标
     * @param facing     活塞朝向（facing 方向：north/south/east/west/up/down）
     * @param isSticky   是否为粘性活塞
     */
    public void recordPistonPlace(String playerName, String playerUUID,
                                   int pistonX, int pistonY, int pistonZ,
                                   String facing, boolean isSticky) {
        if (!config.getSecurity().getSuperEvolution().isAntiPistonAura()) {
            return;
        }

        Instant now = Instant.now();
        List<PistonEvent> events = playerPistonEvents.computeIfAbsent(playerName,
            k -> Collections.synchronizedList(new ArrayList<>()));
        events.add(new PistonEvent(now, pistonX, pistonY, pistonZ, facing, isSticky, true));
        totalPistonEvents.incrementAndGet();
    }

    /**
     * 记录一次活塞激活事件——活塞被红石信号激活推动/拉动方块时调用。
     *
     * @param playerName 活塞块所属玩家名称（放置者）
     * @param pistonX    活塞 X 坐标
     * @param pistonY    活塞 Y 坐标
     * @param pistonZ    活塞 Z 坐标
     * @param facing     活塞朝向
     */
    public void recordPistonActivate(String playerName,
                                      int pistonX, int pistonY, int pistonZ,
                                      String facing) {
        if (!config.getSecurity().getSuperEvolution().isAntiPistonAura()) {
            return;
        }

        Instant now = Instant.now();
        List<PistonEvent> events = playerPistonEvents.computeIfAbsent(playerName,
            k -> Collections.synchronizedList(new ArrayList<>()));
        // 查找匹配的活塞放置事件并标记为激活
        for (int i = events.size() - 1; i >= 0; i--) {
            PistonEvent e = events.get(i);
            if (e.x == pistonX && e.y == pistonY && e.z == pistonZ) {
                e.activated = true;
                e.activationTime = now;
                break;
            }
        }
        // 同时记录这条激活事件（防止未匹配放置事件的独立激活）
        events.add(new PistonEvent(now, pistonX, pistonY, pistonZ, facing, false, false));
    }

    /**
     * 记录一次红石信号源激活——玩家放置/触发红石信号源时调用。
     *
     * @param playerName   玩家名称
     * @param playerUUID   玩家 UUID
     * @param sourceType   红石信号源类型
     * @param sourceX      信号源 X 坐标
     * @param sourceY      信号源 Y 坐标
     * @param sourceZ      信号源 Z 坐标
     */
    public void recordRedstoneActivation(String playerName, String playerUUID,
                                          String sourceType,
                                          int sourceX, int sourceY, int sourceZ) {
        if (!config.getSecurity().getSuperEvolution().isAntiPistonAura()) {
            return;
        }

        Instant now = Instant.now();
        List<RedstoneActivation> activations = playerRedstoneActivations.computeIfAbsent(playerName,
            k -> Collections.synchronizedList(new ArrayList<>()));
        activations.add(new RedstoneActivation(now, sourceType, sourceX, sourceY, sourceZ));
    }

    /**
     * 记录一次玩家间的近距离接触——用于构建战斗上下文。
     *
     * @param subjectPlayerName  被检测的玩家
     * @param nearbyPlayerName   附近的玩家名称
     * @param nearbyX            附近玩家 X 坐标
     * @param nearbyY            附近玩家 Y 坐标
     * @param nearbyZ            附近玩家 Z 坐标
     */
    public void recordPlayerEncounter(String subjectPlayerName,
                                       String nearbyPlayerName,
                                       double nearbyX, double nearbyY, double nearbyZ) {
        if (!config.getSecurity().getSuperEvolution().isAntiPistonAura()) {
            return;
        }

        List<PlayerEncounter> encounters = playerEncounters.computeIfAbsent(subjectPlayerName,
            k -> Collections.synchronizedList(new ArrayList<>()));
        encounters.add(new PlayerEncounter(Instant.now(), nearbyPlayerName,
            nearbyX, nearbyY, nearbyZ));
    }

    /**
     * 全面检测活塞陷阱自动化——综合多个维度判断是否为 PistonAura。
     *
     * @param playerName 玩家名称
     * @param playerUUID 玩家 UUID
     * @return 检测结果
     */
    public DetectionResult detectPistonAura(String playerName, String playerUUID) {
        if (!config.getSecurity().getSuperEvolution().isAntiPistonAura()) {
            return DetectionResult.clean();
        }

        Instant flaggedUntil = flaggedPlayers.get(playerName);
        if (flaggedUntil != null) {
            if (Instant.now().isAfter(flaggedUntil)) {
                flaggedPlayers.remove(playerName);
            } else {
                return DetectionResult.flagged(List.of(
                    "PLAYER_ALREADY_FLAGGED: " + playerName + " under piston-aura investigation"));
            }
        }

        Instant now = Instant.now();
        List<PistonEvent> pistonEvents = playerPistonEvents.get(playerName);
        List<RedstoneActivation> redstoneActs = playerRedstoneActivations.get(playerName);
        List<PlayerEncounter> encounters = playerEncounters.get(playerName);

        int score = 0;
        List<String> reasons = new ArrayList<>();

        if (pistonEvents == null || pistonEvents.size() < MIN_PISTON_EVENTS) {
            return DetectionResult.clean();
        }

        // === 检测 1: 活塞激活速率 ===
        long oneMinuteAgo = now.toEpochMilli() - 60000;
        long recentActivations = pistonEvents.stream()
            .filter(e -> e.activated && e.activationTime != null &&
                e.activationTime.toEpochMilli() > oneMinuteAgo)
            .count();
        if (recentActivations > PISTON_RATE_PER_MINUTE_THRESHOLD) {
            score += 30;
            reasons.add("HIGH_PISTON_RATE: " + recentActivations +
                " piston activations in last minute (threshold=" +
                PISTON_RATE_PER_MINUTE_THRESHOLD + "/min)");
        }

        // === 检测 2: 放置与激活同 tick ===
        int sameTickCount = 0;
        // 同时遍历活塞事件和红石激活事件，检查同 tick 匹配
        for (PistonEvent pe : pistonEvents) {
            if (pe.isPlacement && pe.activated && pe.activationTime != null) {
                long gap = pe.activationTime.toEpochMilli() - pe.time.toEpochMilli();
                if (gap >= 0 && gap <= PLACE_POWER_SAME_TICK_MS) {
                    sameTickCount++;
                }
            }
        }
        if (sameTickCount >= 2) {
            score += 35;
            reasons.add("SAME_TICK_PLACE_POWER: " + sameTickCount +
                " pistons placed and activated within " + PLACE_POWER_SAME_TICK_MS +
                "ms (automated piston trap)");
        }

        // === 检测 3: 活塞对准玩家精确度 ===
        if (encounters != null && !encounters.isEmpty()) {
            int aimedAtPlayers = 0;
            for (PistonEvent pe : pistonEvents) {
                if (!pe.isPlacement) continue;
                // 检查活塞是否对准附近任何一个玩家
                for (PlayerEncounter enc : encounters) {
                    if (Math.abs(enc.time.toEpochMilli() - pe.time.toEpochMilli()) > 5000) {
                        continue; // 时间差超过 5 秒，忽略
                    }
                    double dist = Math.sqrt(
                        Math.pow(enc.nearbyX - pe.x, 2) +
                        Math.pow(enc.nearbyY - pe.y, 2) +
                        Math.pow(enc.nearbyZ - pe.z, 2));
                    if (dist > NEARBY_PLAYER_DISTANCE) continue;

                    // 计算活塞朝向与玩家方向的夹角
                    double angle = calculateAimAngle(
                        pe.x, pe.y, pe.z, pe.facing,
                        enc.nearbyX, enc.nearbyY, enc.nearbyZ);
                    if (angle < PISTON_AIM_ANGLE_THRESHOLD) {
                        aimedAtPlayers++;
                        break; // 每个活塞只计一次
                    }
                }
            }
            if (aimedAtPlayers >= 3) {
                score += 25;
                reasons.add("AIMED_AT_PLAYERS: " + aimedAtPlayers +
                    " pistons precisely aimed at nearby player positions" +
                    " (angle < " + PISTON_AIM_ANGLE_THRESHOLD + " deg)");
            }
        }

        // === 检测 4: 战斗上下文活塞密集使用 ===
        boolean isInCombat = false;
        if (encounters != null && !encounters.isEmpty()) {
            long recentEncounters = encounters.stream()
                .filter(e -> e.time.toEpochMilli() > oneMinuteAgo)
                .count();
            isInCombat = recentEncounters >= 1;
        }

        if (isInCombat && recentActivations >= 3) {
            // 战斗上下文中 3+ 次活塞激活已经非常可疑
            // 即使速率不超标，在战斗中使用活塞即为显著特征
            if (recentActivations < PISTON_RATE_PER_MINUTE_THRESHOLD) {
                score += 15;
                reasons.add("COMBAT_PISTON_USE: " + recentActivations +
                    " piston activations during nearby-player encounters" +
                    " (pistons used in combat context)");
            }
        }

        if (score >= 50) {
            flaggedPlayers.put(playerName, Instant.now().plusSeconds(FLAG_DURATION_SECONDS));
            pistonAuraViolations.incrementAndGet();
            return DetectionResult.flagged(reasons);
        } else if (score >= 30) {
            return DetectionResult.suspicious(score, reasons);
        }

        return DetectionResult.clean();
    }

    /**
     * 计算活塞朝向方向与目标玩家方向之间的夹角（度）。
     *
     * @param px       活塞 X 坐标
     * @param py       活塞 Y 坐标
     * @param pz       活塞 Z 坐标
     * @param facing   活塞朝向字符串
     * @param targetX  目标玩家 X 坐标
     * @param targetY  目标玩家 Y 坐标
     * @param targetZ  目标玩家 Z 坐标
     * @return 夹角（度），0 表示完全对准
     */
    private double calculateAimAngle(int px, int py, int pz, String facing,
                                      double targetX, double targetY, double targetZ) {
        // 活塞朝向向量
        double fx = 0, fy = 0, fz = 0;
        if (facing == null) return 180.0;
        switch (facing.toLowerCase()) {
            case "north" -> fz = -1;
            case "south" -> fz = 1;
            case "west"  -> fx = -1;
            case "east"  -> fx = 1;
            case "up"    -> fy = 1;
            case "down"  -> fy = -1;
            default -> { return 180.0; }
        }

        // 从活塞到目标的方向向量（活塞推出一格，从推出面的前方计算）
        double pushX = px + 0.5 + fx;
        double pushY = py + 0.5 + fy;
        double pushZ = pz + 0.5 + fz;
        double dx = targetX - pushX;
        double dy = targetY - pushY;
        double dz = targetZ - pushZ;

        double dist = Math.sqrt(dx * dx + dy * dy + dz * dz);
        if (dist < 0.001) return 0.0; // 目标在推出位置

        // 方向向量归一化
        double nx = dx / dist;
        double ny = dy / dist;
        double nz = dz / dist;

        // 活塞朝向向量长度
        double fLen = Math.sqrt(fx * fx + fy * fy + fz * fz);
        double dot = (fx / fLen) * nx + (fy / fLen) * ny + (fz / fLen) * nz;

        // 限制在 [-1, 1] 范围
        dot = Math.max(-1.0, Math.min(1.0, dot));
        return Math.toDegrees(Math.acos(dot));
    }

    public void clearPlayer(String playerName) {
        playerPistonEvents.remove(playerName);
        playerRedstoneActivations.remove(playerName);
        playerEncounters.remove(playerName);
        flaggedPlayers.remove(playerName);
    }

    public Map<String, Object> getStatus() {
        Map<String, Object> s = new LinkedHashMap<>();
        s.put("totalPistonEvents", totalPistonEvents.get());
        s.put("pistonAuraViolations", pistonAuraViolations.get());
        s.put("trackedPlayers", playerPistonEvents.size());
        s.put("flaggedPlayers", flaggedPlayers.size());
        s.put("enabled", config.getSecurity().getSuperEvolution().isAntiPistonAura());
        return s;
    }

    public long getTotalPistonEvents() { return totalPistonEvents.get(); }
    public long getPistonAuraViolations() { return pistonAuraViolations.get(); }

    private void cleanupOldRecords() {
        Instant cutoff = Instant.now().minusSeconds(RECORD_RETENTION_SECONDS);
        playerPistonEvents.entrySet().removeIf(e -> {
            List<PistonEvent> list = e.getValue();
            list.removeIf(pe -> pe.time.isBefore(cutoff));
            return list.isEmpty();
        });
        playerRedstoneActivations.entrySet().removeIf(e -> {
            List<RedstoneActivation> list = e.getValue();
            list.removeIf(ra -> ra.time.isBefore(cutoff));
            return list.isEmpty();
        });
        playerEncounters.entrySet().removeIf(e -> {
            List<PlayerEncounter> list = e.getValue();
            list.removeIf(enc -> enc.time.isBefore(cutoff));
            return list.isEmpty();
        });
        flaggedPlayers.entrySet().removeIf(e -> e.getValue().isBefore(Instant.now()));
    }

    // ==================== 内部数据类 ====================

    /**
     * 活塞事件——追踪活塞的放置与激活全流程。
     */
    private static class PistonEvent {
        final Instant time;
        final int x, y, z;
        final String facing;     // 活塞朝向
        final boolean isSticky;  // 是否粘性活塞
        final boolean isPlacement; // 是否为放置事件（false 表示激活事件）
        boolean activated;       // 是否已被激活
        Instant activationTime;  // 激活时间

        PistonEvent(Instant time, int x, int y, int z,
                   String facing, boolean isSticky, boolean isPlacement) {
            this.time = time;
            this.x = x;
            this.y = y;
            this.z = z;
            this.facing = facing;
            this.isSticky = isSticky;
            this.isPlacement = isPlacement;
            this.activated = false;
        }
    }

    /**
     * 红石信号源激活记录——追踪红石信号源的触发。
     */
    private static class RedstoneActivation {
        final Instant time;
        final String sourceType;
        final int x, y, z;

        RedstoneActivation(Instant time, String sourceType, int x, int y, int z) {
            this.time = time;
            this.sourceType = sourceType;
            this.x = x;
            this.y = y;
            this.z = z;
        }
    }

    /**
     * 玩家接触记录——追踪检测目标与附近玩家的时空关系。
     */
    private static class PlayerEncounter {
        final Instant time;
        final String nearbyPlayerName;
        final double nearbyX, nearbyY, nearbyZ;

        PlayerEncounter(Instant time, String nearbyPlayerName,
                       double nearbyX, double nearbyY, double nearbyZ) {
            this.time = time;
            this.nearbyPlayerName = nearbyPlayerName;
            this.nearbyX = nearbyX;
            this.nearbyY = nearbyY;
            this.nearbyZ = nearbyZ;
        }
    }

    // ==================== 检测结果类 ====================

    /**
     * 活塞陷阱自动化检测结果。
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

        /** 无异常：活塞使用行为正常 */
        public static DetectionResult clean() {
            return new DetectionResult(false, false, 0, List.of());
        }

        /** 可疑行为：存在 PistonAura 特征但置信度不足 */
        public static DetectionResult suspicious(int score, List<String> reasons) {
            return new DetectionResult(false, true, score, reasons);
        }

        /** 已标记：检测到高置信度 PistonAura 行为 */
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
