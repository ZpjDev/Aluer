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
 * 假人实体检测 (FakePlayer) — V5.3 世界/玩家/杂物安全模块
 *
 * 检测原理：
 *   Meteor Client 的 FakePlayer 模块在客户端生成一个虚拟玩家实体，用于迷惑对手、
 *   吸引攻击火力或测试 PvP 策略。这个假人在服务端不存在，但某些变体通过数据包注入
 *   可以让假人在服务端短暂出现。本模块通过以下维度检测假人实体：
 *   1. Keep-Alive 响应缺失——正常玩家会定期响应服务端的 keep-alive 数据包，
 *      假人实体从不响应或响应延迟极度稳定（机器人特征）。
 *   2. 零交互行为——检测出现在玩家列表中但从未移动、从未挖掘/放置方块、
 *      从未打开容器、从未发言的实体。
 *   3. 认证流程不完整——检测进入服务器但从未完成完整 Mojang 认证流程的实体。
 *   4. 伤害零反应——检测受到伤害但零位移（无击退）、零视角变化（无转头）的实体。
 *   5. 完全静止或完美循环移动——假人常见的移动模式为原地不动或精确重复的巡逻路径。
 *
 * 配置开关：serverguard.security.super-evolution.anti-fake-player
 */
@Service
public class AntiFakePlayerService {

    private final ServerGuardConfig config;
    /** 每个玩家的 keep-alive 应答记录 */
    private final Map<String, List<KeepAliveRecord>> playerKeepAlive = new ConcurrentHashMap<>();
    /** 每个玩家的认证状态追踪 */
    private final Map<String, AuthTracking> playerAuthTracking = new ConcurrentHashMap<>();
    /** 每个玩家的移动历史 */
    private final Map<String, List<MovementPoint>> playerMovements = new ConcurrentHashMap<>();
    /** 每个玩家的交互计数 */
    private final Map<String, PlayerInteractionCounts> playerInteractions = new ConcurrentHashMap<>();
    /** 每个玩家的受伤记录 */
    private final Map<String, List<DamageEvent>> playerDamageEvents = new ConcurrentHashMap<>();
    /** 已标记的玩家 */
    private final Map<String, Instant> flaggedPlayers = new ConcurrentHashMap<>();
    private final ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor();

    private final AtomicLong totalEntitiesTracked = new AtomicLong(0);
    private final AtomicLong fakePlayerViolations = new AtomicLong(0);

    /** Keep-Alive 响应超时（秒）——超过此时间未收到响应即标记 */
    private static final long KEEP_ALIVE_TIMEOUT_SECONDS = 30;
    /** Keep-Alive 响应时间波动阈值（变异系数）——低于此值视为机器人 */
    private static final double KEEP_ALIVE_COV_THRESHOLD = 0.05;
    /** 最少需要 keep-alive 样本数 */
    private static final int MIN_KEEP_ALIVE_SAMPLES = 5;

    /** 零交互判定时间（秒）——玩家存在超过此时间但无任何交互即为可疑 */
    private static final long ZERO_INTERACTION_SECONDS = 120;
    /** 零交互时最少需要的存在时间（秒） */
    private static final long MIN_EXISTENCE_SECONDS = 60;

    /** 移动静止判定——位移小于此距离视为静止（格） */
    private static final double STILL_THRESHOLD = 0.01;
    /** 移动完美循环判定——路径在多少格误差内视为重复 */
    private static final double CYCLE_TOLERANCE = 0.1;
    /** 完美重复的最小路径点数 */
    private static final int MIN_CYCLE_POINTS = 5;

    /** 伤害零反应检测——受伤后位置/视角变化阈值 */
    private static final double DAMAGE_REACTION_THRESHOLD = 0.01;
    /** 认证超时（秒）——登录后超过此时间未完成认证即为异常 */
    private static final long AUTH_TIMEOUT_SECONDS = 15;

    /** 记录保留时间（秒） */
    private static final long RECORD_RETENTION_SECONDS = 900;
    /** 标记持续时间（秒） */
    private static final long FLAG_DURATION_SECONDS = 1800;

    public AntiFakePlayerService() {
        this(new ServerGuardConfig());
    }

    @Autowired
    public AntiFakePlayerService(ServerGuardConfig config) {
        this.config = config;
        scheduler.scheduleAtFixedRate(this::cleanupOldRecords, 120, 300, TimeUnit.SECONDS);
    }

    /**
     * 记录一次玩家认证开始——当玩家进入 LOGIN 状态时调用。
     *
     * @param playerName 玩家名称
     * @param playerUUID 玩家 UUID
     */
    public void recordAuthStart(String playerName, String playerUUID) {
        if (!config.getSecurity().getSuperEvolution().isAntiFakePlayer()) {
            return;
        }
        playerAuthTracking.put(playerName,
            new AuthTracking(Instant.now(), false, false));
        totalEntitiesTracked.incrementAndGet();
    }

    /**
     * 记录认证完成——当玩家成功切换到 PLAY 状态时调用。
     *
     * @param playerName 玩家名称
     * @param playerUUID 玩家 UUID
     * @param isPremium  是否为正版（Mojang 认证）玩家
     */
    public void recordAuthComplete(String playerName, String playerUUID, boolean isPremium) {
        if (!config.getSecurity().getSuperEvolution().isAntiFakePlayer()) {
            return;
        }
        AuthTracking tracking = playerAuthTracking.get(playerName);
        if (tracking != null) {
            tracking.completed = true;
            tracking.isPremium = isPremium;
            tracking.completionTime = Instant.now();
        }
    }

    /**
     * 记录一次 keep-alive 响应——玩家返回 keep-alive 数据包时调用。
     *
     * @param playerName 玩家名称
     * @param responseTimeMs 从发送 keep-alive 到收到响应的延迟（毫秒）
     */
    public void recordKeepAliveResponse(String playerName, long responseTimeMs) {
        if (!config.getSecurity().getSuperEvolution().isAntiFakePlayer()) {
            return;
        }
        List<KeepAliveRecord> records = playerKeepAlive.computeIfAbsent(playerName,
            k -> Collections.synchronizedList(new ArrayList<>()));
        records.add(new KeepAliveRecord(Instant.now(), responseTimeMs));
    }

    /**
     * 记录 keep-alive 超时——服务端发送 keep-alive 后超时未收到响应时调用。
     *
     * @param playerName 玩家名称
     */
    public void recordKeepAliveTimeout(String playerName) {
        if (!config.getSecurity().getSuperEvolution().isAntiFakePlayer()) {
            return;
        }
        List<KeepAliveRecord> records = playerKeepAlive.computeIfAbsent(playerName,
            k -> Collections.synchronizedList(new ArrayList<>()));
        records.add(new KeepAliveRecord(Instant.now(), -1)); // -1 表示超时
    }

    /**
     * 记录一次玩家位置更新。
     *
     * @param playerName 玩家名称
     * @param x          玩家 X 坐标
     * @param y          玩家 Y 坐标
     * @param z          玩家 Z 坐标
     * @param yaw        水平视角
     * @param pitch      垂直视角
     */
    public void recordMovement(String playerName, double x, double y, double z,
                                float yaw, float pitch) {
        if (!config.getSecurity().getSuperEvolution().isAntiFakePlayer()) {
            return;
        }
        List<MovementPoint> movements = playerMovements.computeIfAbsent(playerName,
            k -> Collections.synchronizedList(new ArrayList<>()));
        movements.add(new MovementPoint(Instant.now(), x, y, z, yaw, pitch));
    }

    /**
     * 记录一次玩家交互（挖掘、放置、开箱等任意有意义的游戏交互）。
     *
     * @param playerName 玩家名称
     * @param interactionType 交互类型描述
     */
    public void recordInteraction(String playerName, String interactionType) {
        if (!config.getSecurity().getSuperEvolution().isAntiFakePlayer()) {
            return;
        }
        PlayerInteractionCounts counts = playerInteractions.computeIfAbsent(playerName,
            k -> new PlayerInteractionCounts());
        counts.totalInteractions.incrementAndGet();
        counts.lastInteractionTime = Instant.now();
    }

    /**
     * 记录一次玩家受到伤害事件。
     *
     * @param playerName 玩家名称
     * @param damageAmount 伤害值
     * @param afterX      受伤后 X 坐标（用于检测击退反应）
     * @param afterY      受伤后 Y 坐标
     * @param afterZ      受伤后 Z 坐标
     * @param afterYaw    受伤后水平视角
     * @param afterPitch  受伤后垂直视角
     */
    public void recordDamage(String playerName, double damageAmount,
                              double afterX, double afterY, double afterZ,
                              float afterYaw, float afterPitch) {
        if (!config.getSecurity().getSuperEvolution().isAntiFakePlayer()) {
            return;
        }
        List<DamageEvent> events = playerDamageEvents.computeIfAbsent(playerName,
            k -> Collections.synchronizedList(new ArrayList<>()));
        events.add(new DamageEvent(Instant.now(), damageAmount,
            afterX, afterY, afterZ, afterYaw, afterPitch));
    }

    /**
     * 全面检测假人实体——综合多个维度判断是否为 FakePlayer。
     *
     * @param playerName 玩家名称
     * @param playerUUID 玩家 UUID
     * @return 检测结果
     */
    public DetectionResult detectFakePlayer(String playerName, String playerUUID) {
        if (!config.getSecurity().getSuperEvolution().isAntiFakePlayer()) {
            return DetectionResult.clean();
        }

        Instant flaggedUntil = flaggedPlayers.get(playerName);
        if (flaggedUntil != null) {
            if (Instant.now().isAfter(flaggedUntil)) {
                flaggedPlayers.remove(playerName);
            } else {
                return DetectionResult.flagged(List.of(
                    "PLAYER_ALREADY_FLAGGED: " + playerName + " under fake-player investigation"));
            }
        }

        Instant now = Instant.now();
        int score = 0;
        List<String> reasons = new ArrayList<>();

        // === 检测 1: Keep-Alive 响应缺失或异常 ===
        List<KeepAliveRecord> kaRecords = playerKeepAlive.get(playerName);
        if (kaRecords != null && !kaRecords.isEmpty()) {
            // 检查最近一次 keep-alive 是否超时
            long timeoutCount = kaRecords.stream()
                .filter(r -> r.responseTimeMs < 0)
                .count();
            if (timeoutCount >= 2) {
                score += 30;
                reasons.add("KEEP_ALIVE_TIMEOUT: " + timeoutCount +
                    " consecutive keep-alive timeouts (entity not responding to server)");
            }

            // 检查响应时间的完美一致性（机器人特征）
            if (kaRecords.size() >= MIN_KEEP_ALIVE_SAMPLES) {
                List<Long> validResponses = kaRecords.stream()
                    .filter(r -> r.responseTimeMs >= 0)
                    .map(r -> r.responseTimeMs)
                    .toList();
                if (validResponses.size() >= MIN_KEEP_ALIVE_SAMPLES) {
                    double cov = calculateCOV(validResponses);
                    if (cov < KEEP_ALIVE_COV_THRESHOLD) {
                        score += 25;
                        reasons.add("KEEP_ALIVE_UNIFORM: response time COV=" +
                            String.format("%.4f", cov) +
                            " (perfectly uniform, bot-like timing)");
                    }
                }
            }
        }

        // === 检测 2: 零交互行为 ===
        AuthTracking auth = playerAuthTracking.get(playerName);
        if (auth != null && auth.joinTime != null) {
            long existenceSeconds = now.getEpochSecond() - auth.joinTime.getEpochSecond();
            PlayerInteractionCounts interactions = playerInteractions.get(playerName);
            long totalInteractions = interactions != null ?
                interactions.totalInteractions.get() : 0;

            if (existenceSeconds > MIN_EXISTENCE_SECONDS && totalInteractions == 0) {
                score += 30;
                reasons.add("ZERO_INTERACTION: existed for " + existenceSeconds +
                    "s with zero world interactions (mining/placing/chat/container)");
            }

            if (existenceSeconds > ZERO_INTERACTION_SECONDS && totalInteractions <= 1) {
                score += 20;
                reasons.add("NEAR_ZERO_INTERACTION: existed for " + existenceSeconds +
                    "s with only " + totalInteractions + " interactions (spectator-like behavior)");
            }
        }

        // === 检测 3: 认证流程不完整 ===
        if (auth != null && !auth.completed) {
            long sinceJoin = now.getEpochSecond() - auth.joinTime.getEpochSecond();
            if (sinceJoin > AUTH_TIMEOUT_SECONDS) {
                score += 35;
                reasons.add("AUTH_INCOMPLETE: " + sinceJoin +
                    "s since join without full authentication completion");
            }
        }

        // === 检测 4: 伤害零反应——受到伤害但零位移/零视角变化 ===
        List<DamageEvent> dmgEvents = playerDamageEvents.get(playerName);
        if (dmgEvents != null && dmgEvents.size() >= 2) {
            int noReactionCount = 0;
            for (int i = 1; i < dmgEvents.size(); i++) {
                DamageEvent curr = dmgEvents.get(i);
                DamageEvent prev = dmgEvents.get(i - 1);
                double posDelta = Math.sqrt(
                    Math.pow(curr.x - prev.x, 2) +
                    Math.pow(curr.y - prev.y, 2) +
                    Math.pow(curr.z - prev.z, 2));
                float lookDelta = Math.abs(curr.yaw - prev.yaw) + Math.abs(curr.pitch - prev.pitch);
                if (posDelta < DAMAGE_REACTION_THRESHOLD && lookDelta < 0.5f) {
                    noReactionCount++;
                }
            }
            if (noReactionCount >= 2) {
                score += 25;
                reasons.add("DAMAGE_NO_REACTION: " + noReactionCount +
                    " damage events with zero position/view change (no knockback response)");
            }
        }

        // === 检测 5: 完全静止或完美循环移动 ===
        List<MovementPoint> movements = playerMovements.get(playerName);
        if (movements != null && movements.size() >= 10) {
            // 检查是否完全静止
            boolean completelyStill = isCompletelyStill(movements);
            if (completelyStill && movements.size() >= 20) {
                score += 20;
                reasons.add("COMPLETELY_STILL: " + movements.size() +
                    " movement updates all at the same position (immobile entity)");
            }

            // 检查完美循环移动模式
            if (movements.size() >= MIN_CYCLE_POINTS * 2) {
                boolean hasCycle = detectMovementCycle(movements);
                if (hasCycle) {
                    score += 25;
                    reasons.add("MOVEMENT_CYCLE: repeating movement pattern detected" +
                        " (precise loop, fake-player patrol mode)");
                }
            }
        }

        if (score >= 50) {
            flaggedPlayers.put(playerName, Instant.now().plusSeconds(FLAG_DURATION_SECONDS));
            fakePlayerViolations.incrementAndGet();
            return DetectionResult.flagged(reasons);
        } else if (score >= 30) {
            return DetectionResult.suspicious(score, reasons);
        }

        return DetectionResult.clean();
    }

    /**
     * 计算一组数值的变异系数（COV = 标准差 / 均值）。
     */
    private double calculateCOV(List<Long> values) {
        if (values == null || values.isEmpty()) return 1.0;
        double mean = values.stream().mapToLong(Long::longValue).average().orElse(0);
        if (mean == 0) return 1.0;
        double variance = values.stream()
            .mapToDouble(v -> Math.pow(v - mean, 2))
            .average().orElse(0);
        return Math.sqrt(variance) / mean;
    }

    /**
     * 检查最近的移动记录是否完全静止（所有点在同一位置）。
     */
    private boolean isCompletelyStill(List<MovementPoint> movements) {
        if (movements.size() < 10) return false;
        int start = Math.max(0, movements.size() - 20);
        MovementPoint first = movements.get(start);
        for (int i = start + 1; i < movements.size(); i++) {
            MovementPoint p = movements.get(i);
            double dist = Math.sqrt(
                Math.pow(p.x - first.x, 2) +
                Math.pow(p.y - first.y, 2) +
                Math.pow(p.z - first.z, 2));
            if (dist > STILL_THRESHOLD) return false;
        }
        return true;
    }

    /**
     * 检测移动历史中是否有重复的循环模式。
     * 将移动路径编码为方向序列并在序列中寻找重复子序列。
     */
    private boolean detectMovementCycle(List<MovementPoint> movements) {
        int size = movements.size();
        if (size < MIN_CYCLE_POINTS * 2) return false;

        // 取最近两段路径进行比较
        int halfSize = size / 2;
        List<double[]> firstHalf = extractPositions(movements, 0, halfSize);
        List<double[]> secondHalf = extractPositions(movements, halfSize, size);

        // 如果两半路径高度相似，可能存在循环
        double similarity = comparePaths(firstHalf, secondHalf);
        return similarity > 0.85; // 85% 相似度即判定为循环
    }

    /**
     * 提取连续坐标列表（标准化为相对于起点的坐标）。
     */
    private List<double[]> extractPositions(List<MovementPoint> movements,
                                              int from, int to) {
        List<double[]> positions = new ArrayList<>();
        double baseX = movements.get(from).x;
        double baseY = movements.get(from).y;
        double baseZ = movements.get(from).z;
        for (int i = from; i < to && i < movements.size(); i++) {
            MovementPoint p = movements.get(i);
            positions.add(new double[]{p.x - baseX, p.y - baseY, p.z - baseZ});
        }
        return positions;
    }

    /**
     * 计算两条路径的相似度（0.0 - 1.0），基于点对点的欧几里得距离。
     */
    private double comparePaths(List<double[]> path1, List<double[]> path2) {
        int minLen = Math.min(path1.size(), path2.size());
        if (minLen == 0) return 0;
        int matchCount = 0;
        for (int i = 0; i < minLen; i++) {
            double dx = path1.get(i)[0] - path2.get(i)[0];
            double dy = path1.get(i)[1] - path2.get(i)[1];
            double dz = path1.get(i)[2] - path2.get(i)[2];
            double dist = Math.sqrt(dx * dx + dy * dy + dz * dz);
            if (dist < CYCLE_TOLERANCE) matchCount++;
        }
        return (double) matchCount / minLen;
    }

    public void clearPlayer(String playerName) {
        playerKeepAlive.remove(playerName);
        playerAuthTracking.remove(playerName);
        playerMovements.remove(playerName);
        playerInteractions.remove(playerName);
        playerDamageEvents.remove(playerName);
        flaggedPlayers.remove(playerName);
    }

    public Map<String, Object> getStatus() {
        Map<String, Object> s = new LinkedHashMap<>();
        s.put("totalEntitiesTracked", totalEntitiesTracked.get());
        s.put("fakePlayerViolations", fakePlayerViolations.get());
        s.put("trackedPlayers", playerAuthTracking.size());
        s.put("flaggedPlayers", flaggedPlayers.size());
        s.put("enabled", config.getSecurity().getSuperEvolution().isAntiFakePlayer());
        return s;
    }

    public long getTotalEntitiesTracked() { return totalEntitiesTracked.get(); }
    public long getFakePlayerViolations() { return fakePlayerViolations.get(); }

    private void cleanupOldRecords() {
        Instant cutoff = Instant.now().minusSeconds(RECORD_RETENTION_SECONDS);
        playerKeepAlive.entrySet().removeIf(e -> {
            List<KeepAliveRecord> list = e.getValue();
            list.removeIf(r -> r.time.isBefore(cutoff));
            return list.isEmpty();
        });
        playerMovements.entrySet().removeIf(e -> {
            List<MovementPoint> list = e.getValue();
            list.removeIf(p -> p.time.isBefore(cutoff));
            return list.isEmpty();
        });
        playerDamageEvents.entrySet().removeIf(e -> {
            List<DamageEvent> list = e.getValue();
            list.removeIf(d -> d.time.isBefore(cutoff));
            return list.isEmpty();
        });
        flaggedPlayers.entrySet().removeIf(e -> e.getValue().isBefore(Instant.now()));
    }

    // ==================== 内部数据类 ====================

    /**
     * Keep-Alive 应答记录。
     */
    private static class KeepAliveRecord {
        final Instant time;
        final long responseTimeMs; // -1 表示超时

        KeepAliveRecord(Instant time, long responseTimeMs) {
            this.time = time;
            this.responseTimeMs = responseTimeMs;
        }
    }

    /**
     * 认证追踪——记录玩家从登录到完成认证的完整流程。
     */
    private static class AuthTracking {
        final Instant joinTime;
        boolean completed;        // 是否已完成认证
        boolean isPremium;        // 是否为正版认证
        Instant completionTime;   // 认证完成时间

        AuthTracking(Instant joinTime, boolean completed, boolean isPremium) {
            this.joinTime = joinTime;
            this.completed = completed;
            this.isPremium = isPremium;
        }
    }

    /**
     * 移动位置点——追踪玩家每个 tick 的位置和视角。
     */
    private static class MovementPoint {
        final Instant time;
        final double x, y, z;
        final float yaw, pitch;

        MovementPoint(Instant time, double x, double y, double z, float yaw, float pitch) {
            this.time = time;
            this.x = x;
            this.y = y;
            this.z = z;
            this.yaw = yaw;
            this.pitch = pitch;
        }
    }

    /**
     * 玩家交互计数——追踪任意有意义的游戏内交互。
     */
    private static class PlayerInteractionCounts {
        final AtomicLong totalInteractions = new AtomicLong(0);
        Instant lastInteractionTime;
    }

    /**
     * 伤害事件——记录一次伤害及其后的玩家状态。
     */
    private static class DamageEvent {
        final Instant time;
        final double damageAmount;
        final double x, y, z;     // 受伤后位置
        final float yaw, pitch;   // 受伤后视角

        DamageEvent(Instant time, double damageAmount,
                   double x, double y, double z, float yaw, float pitch) {
            this.time = time;
            this.damageAmount = damageAmount;
            this.x = x;
            this.y = y;
            this.z = z;
            this.yaw = yaw;
            this.pitch = pitch;
        }
    }

    // ==================== 检测结果类 ====================

    /**
     * 假人实体检测结果。
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

        /** 无异常：实体行为正常 */
        public static DetectionResult clean() {
            return new DetectionResult(false, false, 0, List.of());
        }

        /** 可疑行为：存在 FakePlayer 特征但置信度不足 */
        public static DetectionResult suspicious(int score, List<String> reasons) {
            return new DetectionResult(false, true, score, reasons);
        }

        /** 已标记：检测到高置信度 FakePlayer 实体 */
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
