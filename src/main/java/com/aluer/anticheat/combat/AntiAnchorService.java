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
 * 洞穴锚定反击退检测 (Anchor) — V5.3 世界/玩家/杂物安全模块
 *
 * 检测原理：
 *   Meteor Client 的 Anchor 模块使玩家在基岩/黑曜石洞穴（俗称"hole"）中免疫击退。
 *   正常 Minecraft 物理：玩家受到伤害时会受到击退——速度和位置同时发生变化。
 *   Anchor 模块通过向服务端发送虚假的位置/速度数据包，使玩家在实际受击时
 *   保持位置和速度不变，从而实现"锚定"效果。本模块通过以下维度检测：
 *   1. 密闭空间检测——检查玩家是否处于 1x1 或 1x2 的封闭空间（hole 特征）。
 *      只有在这种空间中 Anchor 才有战术意义。
 *   2. 零击退位移——检测玩家受到伤害后位置变化为零或极小（< 0.01 格）。
 *      正常击退最小位移约 0.3-0.5 格，即使在 hole 中受墙壁阻挡也有微小位移。
 *   3. 零速度残留——检测玩家受击后速度是否立即归零。
 *      正常击退速度需要数个 tick 才能衰减到零，Anchor 会瞬间清零。
 *   4. 重复锚定事件——检测在同一坐标是否多次发生锚定行为。
 *      单次偶发可能是网络延迟，但重复在同一 hole 发生即为故意使用。
 *   5. 连击零位移——检测在被多个攻击者连续打击时是否始终保持零位移。
 *      这是 Anchor 最明显的特征——无论多少攻击都无法推动玩家。
 *
 * 配置开关：serverguard.security.super-evolution.anti-anchor
 */
@Service
public class AntiAnchorService {

    private final ServerGuardConfig config;
    /** 每个玩家的位置历史 */
    private final Map<String, List<PositionRecord>> playerPositions = new ConcurrentHashMap<>();
    /** 每个玩家的速度历史（速度分量） */
    private final Map<String, List<VelocityRecord>> playerVelocities = new ConcurrentHashMap<>();
    /** 每个玩家的伤害事件记录 */
    private final Map<String, List<DamageEvent>> playerDamageEvents = new ConcurrentHashMap<>();
    /** 每个玩家的锚定事件坐标统计 */
    private final Map<String, Map<String, AtomicLong>> playerAnchorPositions = new ConcurrentHashMap<>();
    /** 已标记的玩家 */
    private final Map<String, Instant> flaggedPlayers = new ConcurrentHashMap<>();
    private final ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor();

    private final AtomicLong totalDamageEvents = new AtomicLong(0);
    private final AtomicLong anchorViolations = new AtomicLong(0);

    /** 零位移判定阈值（格）——受击后位移小于此值即判定为锚定 */
    private static final double ZERO_DISPLACEMENT_THRESHOLD = 0.01;
    /** 零速度判定阈值（格/秒）——受击后速度小于此值即判定为零速度 */
    private static final double ZERO_VELOCITY_THRESHOLD = 0.05;
    /** 密闭空间判定——hole 中零位移的合理范围（格） */
    private static final double CONFINED_SPACE_THRESHOLD = 0.15;
    /** 最小锚定事件次数——至少 N 次零位移才能标记 */
    private static final int MIN_ANCHOR_EVENTS = 3;
    /** 锚定位置重复判定——同一坐标锚定 N 次以上加重计分 */
    private static final int SAME_POS_ANCHOR_THRESHOLD = 2;
    /** 受击前位置采样窗口（毫秒）——取受击前此窗口内的位置作为参考 */
    private static final long PRE_DAMAGE_WINDOW_MS = 200;
    /** 受击后位置采样窗口（毫秒）——取受击后此窗口内的位置作为参考 */
    private static final long POST_DAMAGE_WINDOW_MS = 300;
    /** 密闭空间检测——检查周围半径（格） */
    private static final int CONFINED_CHECK_RADIUS = 1;
    /** 连击零位移判定——短时间内受多次攻击且全部零位移 */
    private static final long COMBO_WINDOW_MS = 2000;
    private static final int COMBO_MIN_HITS = 3;

    /** 记录保留时间（秒） */
    private static final long RECORD_RETENTION_SECONDS = 900;
    /** 标记持续时间（秒） */
    private static final long FLAG_DURATION_SECONDS = 1800;

    public AntiAnchorService() {
        this(new ServerGuardConfig());
    }

    @Autowired
    public AntiAnchorService(ServerGuardConfig config) {
        this.config = config;
        scheduler.scheduleAtFixedRate(this::cleanupOldRecords, 120, 300, TimeUnit.SECONDS);
    }

    /**
     * 记录一次玩家位置更新——每个移动包到来时调用。
     *
     * @param playerName 玩家名称
     * @param playerUUID 玩家 UUID
     * @param x          玩家 X 坐标
     * @param y          玩家 Y 坐标
     * @param z          玩家 Z 坐标
     */
    public void recordPosition(String playerName, String playerUUID,
                                double x, double y, double z) {
        if (!config.getSecurity().getSuperEvolution().isAntiAnchor()) {
            return;
        }

        Instant now = Instant.now();
        List<PositionRecord> positions = playerPositions.computeIfAbsent(playerName,
            k -> Collections.synchronizedList(new ArrayList<>()));
        positions.add(new PositionRecord(now, x, y, z));
    }

    /**
     * 记录一次玩家速度变更——玩家收到 velocity（击退）数据包时调用。
     *
     * @param playerName 玩家名称
     * @param playerUUID 玩家 UUID
     * @param vx         X 方向速度分量
     * @param vy         Y 方向速度分量
     * @param vz         Z 方向速度分量
     */
    public void recordVelocity(String playerName, String playerUUID,
                                double vx, double vy, double vz) {
        if (!config.getSecurity().getSuperEvolution().isAntiAnchor()) {
            return;
        }

        Instant now = Instant.now();
        List<VelocityRecord> velocities = playerVelocities.computeIfAbsent(playerName,
            k -> Collections.synchronizedList(new ArrayList<>()));
        velocities.add(new VelocityRecord(now, vx, vy, vz));
    }

    /**
     * 记录一次玩家受到伤害事件——当玩家受到攻击/环境伤害时调用。
     * 此方法是 Anchor 检测的核心入口，通过对比受伤前后的位置变化判断锚定行为。
     *
     * @param playerName  玩家名称
     * @param playerUUID  玩家 UUID
     * @param damageAmount 伤害值
     * @param damageX     受伤发生时的 X 坐标
     * @param damageY     受伤发生时的 Y 坐标
     * @param damageZ     受伤发生时的 Z 坐标
     * @param isConfined  玩家当前是否处于密闭空间（外部判断结果，可为 null）
     * @return 检测结果
     */
    public DetectionResult detectDamageWithAnchor(String playerName, String playerUUID,
                                                    double damageAmount,
                                                    double damageX, double damageY, double damageZ,
                                                    Boolean isConfined) {
        if (!config.getSecurity().getSuperEvolution().isAntiAnchor()) {
            return DetectionResult.clean();
        }

        Instant flaggedUntil = flaggedPlayers.get(playerName);
        if (flaggedUntil != null) {
            if (Instant.now().isAfter(flaggedUntil)) {
                flaggedPlayers.remove(playerName);
            } else {
                return DetectionResult.flagged(List.of(
                    "PLAYER_ALREADY_FLAGGED: " + playerName + " under anchor investigation"));
            }
        }

        Instant now = Instant.now();
        List<DamageEvent> dmgEvents = playerDamageEvents.computeIfAbsent(playerName,
            k -> Collections.synchronizedList(new ArrayList<>()));
        DamageEvent event = new DamageEvent(now, damageAmount, damageX, damageY, damageZ);
        dmgEvents.add(event);
        totalDamageEvents.incrementAndGet();

        int score = 0;
        List<String> reasons = new ArrayList<>();

        // === 检测 1: 密闭空间判定 ===
        // 如果玩家不在 hole 中，Anchor 的战术意义不大
        // 外部可以传入 isConfined 判断，或通过位置记录自己判断
        boolean confined = isConfined != null ? isConfined :
            isInConfinedSpace(playerName, playerUUID, damageX, damageY, damageZ);

        // === 检测 2: 零击退位移 ===
        // 获取受击前后的位置
        PositionRecord posBefore = getPositionBefore(playerName, now);
        PositionRecord posAfter = getPositionAfter(playerName, now);

        if (posBefore != null && posAfter != null) {
            double displacement = Math.sqrt(
                Math.pow(posAfter.x - posBefore.x, 2) +
                Math.pow(posAfter.y - posBefore.y, 2) +
                Math.pow(posAfter.z - posBefore.z, 2));

            if (displacement < ZERO_DISPLACEMENT_THRESHOLD) {
                // 受击后零位移——Anchor 的核心特征
                score += 30;
                reasons.add("ZERO_DISPLACEMENT: took " + String.format("%.1f", damageAmount) +
                    " damage with " + String.format("%.4f", displacement) +
                    " blocks displacement (threshold < " + ZERO_DISPLACEMENT_THRESHOLD + ")");

                // 记录锚定位置
                String posKey = anchorPosKey(damageX, damageY, damageZ);
                Map<String, AtomicLong> posCounts = playerAnchorPositions.computeIfAbsent(playerName,
                    k -> new ConcurrentHashMap<>());
                posCounts.computeIfAbsent(posKey, k -> new AtomicLong(0)).incrementAndGet();

                // 密闭空间中零位移加重计分
                if (confined) {
                    score += 15;
                    reasons.add("CONFINED_ZERO_DISPLACEMENT: zero movement in confined space" +
                        " (hole anchor behavior)");
                }
            } else if (confined && displacement < CONFINED_SPACE_THRESHOLD) {
                // 在 hole 中有微小位移也算是锚定特征
                score += 15;
                reasons.add("CONFINED_MINIMAL_DISPLACEMENT: only " +
                    String.format("%.4f", displacement) +
                    " blocks moved after damage in hole");
            }
        }

        // === 检测 3: 零速度残留 ===
        List<VelocityRecord> velocities = playerVelocities.get(playerName);
        if (velocities != null && !velocities.isEmpty()) {
            // 找到受伤后最近的几次速度记录
            double lastSpeed = 0;
            int velCount = 0;
            long windowEnd = now.toEpochMilli() + POST_DAMAGE_WINDOW_MS;
            for (int i = velocities.size() - 1; i >= 0 && velCount < 3; i--) {
                VelocityRecord vr = velocities.get(i);
                if (vr.time.toEpochMilli() <= windowEnd &&
                    vr.time.toEpochMilli() >= now.toEpochMilli()) {
                    double speed = Math.sqrt(vr.vx * vr.vx + vr.vy * vr.vy + vr.vz * vr.vz);
                    lastSpeed += speed;
                    velCount++;
                }
            }
            if (velCount > 0) {
                double avgSpeed = lastSpeed / velCount;
                if (avgSpeed < ZERO_VELOCITY_THRESHOLD) {
                    score += 20;
                    reasons.add("ZERO_POST_DAMAGE_VELOCITY: avg velocity " +
                        String.format("%.4f", avgSpeed) +
                        " after taking damage (knockback suppressed)");
                }
            }
        }

        // === 检测 4: 重复锚定事件 ===
        // 检查同一坐标上的锚定次数
        String posKey = anchorPosKey(damageX, damageY, damageZ);
        Map<String, AtomicLong> posCounts = playerAnchorPositions.get(playerName);
        if (posCounts != null) {
            AtomicLong count = posCounts.get(posKey);
            if (count != null && count.get() >= SAME_POS_ANCHOR_THRESHOLD) {
                score += 20;
                reasons.add("REPEATED_ANCHOR: anchored " + count.get() +
                    " times at same position (" + posKey + ")");
            }
        }

        // === 检测 5: 连击零位移 ===
        if (dmgEvents.size() >= COMBO_MIN_HITS) {
            int zeroDisplacementStrike = countConsecutiveZeroDisplacement(dmgEvents, playerName);
            if (zeroDisplacementStrike >= COMBO_MIN_HITS) {
                score += 35;
                reasons.add("COMBO_ZERO_DISPLACEMENT: " + zeroDisplacementStrike +
                    " consecutive hits with zero knockback displacement" +
                    " (anchor completely negating all knockback)");
            }
        }

        if (score >= 50) {
            flaggedPlayers.put(playerName, Instant.now().plusSeconds(FLAG_DURATION_SECONDS));
            anchorViolations.incrementAndGet();
            return DetectionResult.flagged(reasons);
        } else if (score >= 30) {
            return DetectionResult.suspicious(score, reasons);
        }

        return DetectionResult.clean();
    }

    /**
     * 判断玩家当前是否处于密闭空间（1x1 或 1x2 hole）。
     *
     * 简化实现：通过分析最近的位置历史，如果玩家的水平活动范围
     * 在一个极小的区域内（< 1 格变化）且高度变化也很小，则判为密闭空间。
     */
    private boolean isInConfinedSpace(String playerName, String playerUUID,
                                       double x, double y, double z) {
        List<PositionRecord> positions = playerPositions.get(playerName);
        if (positions == null || positions.size() < 5) return false;

        // 取最近 20 个位置点分析活动范围
        int start = Math.max(0, positions.size() - 20);
        double minX = Double.MAX_VALUE, maxX = -Double.MAX_VALUE;
        double minZ = Double.MAX_VALUE, maxZ = -Double.MAX_VALUE;
        double minY = Double.MAX_VALUE, maxY = -Double.MAX_VALUE;

        for (int i = start; i < positions.size(); i++) {
            PositionRecord p = positions.get(i);
            if (p.x < minX) minX = p.x;
            if (p.x > maxX) maxX = p.x;
            if (p.z < minZ) minZ = p.z;
            if (p.z > maxZ) maxZ = p.z;
            if (p.y < minY) minY = p.y;
            if (p.y > maxY) maxY = p.y;
        }

        double xRange = maxX - minX;
        double zRange = maxZ - minZ;
        double yRange = maxY - minY;

        // 1x1 hole：XZ 范围 < 0.3 且 Y 范围 < 1.5（不能站起）
        // 1x2 hole：XZ 范围 < 0.3 且 Y 范围 < 2.5（可以站起但不能跳跃）
        return xRange < 0.3 && zRange < 0.3 && yRange < 2.5;
    }

    /**
     * 获取受击前指定窗口内的位置记录。
     */
    private PositionRecord getPositionBefore(String playerName, Instant damageTime) {
        List<PositionRecord> positions = playerPositions.get(playerName);
        if (positions == null || positions.isEmpty()) return null;

        long windowStart = damageTime.toEpochMilli() - PRE_DAMAGE_WINDOW_MS;
        // 从后往前找最近的受击前位置
        for (int i = positions.size() - 1; i >= 0; i--) {
            PositionRecord p = positions.get(i);
            if (p.time.toEpochMilli() <= damageTime.toEpochMilli() &&
                p.time.toEpochMilli() >= windowStart) {
                return p;
            }
        }
        // 如果窗口内没找到，取最接近的一个
        return positions.get(positions.size() - 1);
    }

    /**
     * 获取受击后指定窗口内的位置记录。
     */
    private PositionRecord getPositionAfter(String playerName, Instant damageTime) {
        List<PositionRecord> positions = playerPositions.get(playerName);
        if (positions == null || positions.isEmpty()) return null;

        long windowEnd = damageTime.toEpochMilli() + POST_DAMAGE_WINDOW_MS;
        // 从前往后找最近的受击后位置
        for (PositionRecord p : positions) {
            if (p.time.toEpochMilli() >= damageTime.toEpochMilli() &&
                p.time.toEpochMilli() <= windowEnd) {
                return p;
            }
        }
        return null;
    }

    /**
     * 统计最近的连续零位移伤害事件次数。
     */
    private int countConsecutiveZeroDisplacement(List<DamageEvent> events, String playerName) {
        int count = 0;
        List<PositionRecord> positions = playerPositions.get(playerName);
        if (positions == null) return 0;

        for (int i = events.size() - 1; i >= 0; i--) {
            DamageEvent e = events.get(i);
            PositionRecord before = getPositionBefore(playerName, e.time);
            PositionRecord after = getPositionAfter(playerName, e.time);
            if (before != null && after != null) {
                double disp = Math.sqrt(
                    Math.pow(after.x - before.x, 2) +
                    Math.pow(after.y - before.y, 2) +
                    Math.pow(after.z - before.z, 2));
                if (disp < ZERO_DISPLACEMENT_THRESHOLD) {
                    count++;
                } else {
                    break; // 遇到有正常位移的事件则停止
                }
            }
        }
        return count;
    }

    /**
     * 生成锚定位置的标识字符串（用于统计同一坐标重复锚定）。
     */
    private String anchorPosKey(double x, double y, double z) {
        // 量化到整数坐标（锚定在同一格内）
        return (int) Math.floor(x) + "," + (int) Math.floor(y) + "," + (int) Math.floor(z);
    }

    public void clearPlayer(String playerName) {
        playerPositions.remove(playerName);
        playerVelocities.remove(playerName);
        playerDamageEvents.remove(playerName);
        playerAnchorPositions.remove(playerName);
        flaggedPlayers.remove(playerName);
    }

    public Map<String, Object> getStatus() {
        Map<String, Object> s = new LinkedHashMap<>();
        s.put("totalDamageEvents", totalDamageEvents.get());
        s.put("anchorViolations", anchorViolations.get());
        s.put("trackedPlayers", playerPositions.size());
        s.put("flaggedPlayers", flaggedPlayers.size());
        s.put("enabled", config.getSecurity().getSuperEvolution().isAntiAnchor());
        return s;
    }

    public long getTotalDamageEvents() { return totalDamageEvents.get(); }
    public long getAnchorViolations() { return anchorViolations.get(); }

    private void cleanupOldRecords() {
        Instant cutoff = Instant.now().minusSeconds(RECORD_RETENTION_SECONDS);
        playerPositions.entrySet().removeIf(e -> {
            List<PositionRecord> list = e.getValue();
            list.removeIf(p -> p.time.isBefore(cutoff));
            return list.isEmpty();
        });
        playerVelocities.entrySet().removeIf(e -> {
            List<VelocityRecord> list = e.getValue();
            list.removeIf(v -> v.time.isBefore(cutoff));
            return list.isEmpty();
        });
        playerDamageEvents.entrySet().removeIf(e -> {
            List<DamageEvent> list = e.getValue();
            list.removeIf(d -> d.time.isBefore(cutoff));
            return list.isEmpty();
        });
        playerAnchorPositions.entrySet().removeIf(e ->
            !playerDamageEvents.containsKey(e.getKey()));
        flaggedPlayers.entrySet().removeIf(e -> e.getValue().isBefore(Instant.now()));
    }

    // ==================== 内部数据类 ====================

    /**
     * 位置记录——追踪玩家每个 tick 的精确位置。
     */
    private static class PositionRecord {
        final Instant time;
        final double x, y, z;

        PositionRecord(Instant time, double x, double y, double z) {
            this.time = time;
            this.x = x;
            this.y = y;
            this.z = z;
        }
    }

    /**
     * 速度记录——追踪玩家受到的击退速度（服务器下发 velocity 包）。
     */
    private static class VelocityRecord {
        final Instant time;
        final double vx, vy, vz;

        VelocityRecord(Instant time, double vx, double vy, double vz) {
            this.time = time;
            this.vx = vx;
            this.vy = vy;
            this.vz = vz;
        }
    }

    /**
     * 伤害事件——记录一次伤害及其发生时的位置。
     */
    private static class DamageEvent {
        final Instant time;
        final double damageAmount;
        final double x, y, z; // 伤害发生时的坐标

        DamageEvent(Instant time, double damageAmount, double x, double y, double z) {
            this.time = time;
            this.damageAmount = damageAmount;
            this.x = x;
            this.y = y;
            this.z = z;
        }
    }

    // ==================== 检测结果类 ====================

    /**
     * 洞穴锚定检测结果。
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

        /** 无异常：受击行为正常 */
        public static DetectionResult clean() {
            return new DetectionResult(false, false, 0, List.of());
        }

        /** 可疑行为：存在 Anchor 特征但置信度不足 */
        public static DetectionResult suspicious(int score, List<String> reasons) {
            return new DetectionResult(false, true, score, reasons);
        }

        /** 已标记：检测到高置信度 Anchor 行为 */
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
