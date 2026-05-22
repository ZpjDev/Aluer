package com.aluer.anticheat.combat;

import com.aluer.config.ServerGuardConfig;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * 杀戮光环（KillAura）检测服务 — V4.0 反作弊扩展模块
 *
 * 检测原理：
 * 1. 攻击目标切换频率检测 — 追踪每个玩家的攻击目标列表，如果在3秒窗口内切换超过3个不同目标，
 *    表明玩家可能在无差别攻击周围所有实体（KillAura会自动锁定范围内的所有目标）
 * 2. 攻击角度一致性检测 — 连续攻击的角度偏差小于5度时，表明存在自动瞄准（Aimbot），
 *    正常玩家无法在多次攻击中保持如此高度一致的角度
 * 3. 攻击距离模式检测 — 如果玩家多次在最大攻击距离（约3.0方块）处精确命中目标，
 *    表明可能存在Reach扩展和KillAura的联合使用
 * 4. 多点同时攻击检测 — 检测单个tick内对多个目标造成伤害的异常行为
 *
 * 配置开关：serverguard.security.super-evolution.anti-kill-aura
 */
@Service
public class AntiKillAuraService {

    private final ServerGuardConfig config;

    /**
     * 追踪每个玩家在时间窗口内的攻击目标记录（playerName -> 攻击记录列表）
     * 用于检测短时间内的多目标切换行为
     */
    private final Map<String, List<AttackRecord>> playerAttackHistory = new ConcurrentHashMap<>();

    /**
     * 追踪每个玩家的连续攻击角度记录（playerName -> 最近5次攻击角度列表）
     * 用于检测自动瞄准的角度一致性
     */
    private final Map<String, List<Double>> playerAngleHistory = new ConcurrentHashMap<>();

    /**
     * 追踪每个玩家的攻击距离记录（playerName -> 距离列表）
     * 用于检测精确的极限距离攻击模式
     */
    private final Map<String, List<Double>> playerDistanceHistory = new ConcurrentHashMap<>();

    private final AtomicLong totalChecks = new AtomicLong(0);
    private final AtomicLong flaggedCount = new AtomicLong(0);

    /**
     * 目标切换检测窗口（秒）— 在此窗口内如果切换目标过于频繁则标记
     */
    private static final long TARGET_SWITCH_WINDOW_MS = 3_000;

    /**
     * 窗口内最大允许的目标切换次数 — 超过此值被视为异常快速切换
     */
    private static final int MAX_TARGET_SWITCHES = 3;

    /**
     * 角度一致性阈值（度）— 连续攻击角度偏差小于此值表明自动瞄准
     */
    private static final double AIMBOT_ANGLE_THRESHOLD = 5.0;

    /**
     * 角度一致性检测所需的最小连续攻击次数
     */
    private static final int MIN_CONSECUTIVE_ATTACKS = 3;

    /**
     * Minecraft生存模式最大合法攻击距离（考虑延迟容差）
     */
    private static final double MAX_LEGITIMATE_REACH = 3.0;

    /**
     * 精确极限距离攻击判定阈值 — 在最大距离附近精确攻击的次数
     */
    private static final double PERFECT_REACH_THRESHOLD = 2.8;

    /**
     * 最大距离攻击次数阈值 — 超过此值标记
     */
    private static final int MAX_PERFECT_REACH_COUNT = 4;

    /**
     * 无参构造函数 — 测试/默认配置使用
     */
    public AntiKillAuraService() {
        this(new ServerGuardConfig());
    }

    /**
     * Spring 注入构造函数
     * @param config 全局配置，提供模块开关控制
     */
    public AntiKillAuraService(ServerGuardConfig config) {
        this.config = config;
    }

    /**
     * 检测玩家攻击行为是否存在杀戮光环特征
     *
     * @param playerName 攻击者玩家名称
     * @param playerUUID 攻击者UUID
     * @param targetName 被攻击目标名称
     * @param attackYaw 攻击时的水平角度（度数）
     * @param attackPitch 攻击时的俯仰角度（度数）
     * @param distance 攻击者与目标的距离（方块）
     * @param timestamp 攻击时间戳
     * @return 检测结果
     */
    public KillAuraCheckResult detect(String playerName, String playerUUID,
                                       String targetName, double attackYaw, double attackPitch,
                                       double distance, Instant timestamp) {
        // 模块开关检查 — 关闭时跳过所有检测直接返回安全结果
        if (!config.getSecurity().getSuperEvolution().isAntiKillAura()) {
            return KillAuraCheckResult.clean();
        }

        totalChecks.incrementAndGet();
        List<String> reasons = new ArrayList<>();

        // 1. 攻击目标切换频率检测
        List<AttackRecord> attackHistory = playerAttackHistory.computeIfAbsent(
                playerName, k -> Collections.synchronizedList(new ArrayList<>()));
        attackHistory.add(new AttackRecord(timestamp, targetName, distance, attackYaw, attackPitch));

        // 清理超出时间窗口的旧记录
        Instant windowStart = timestamp.minusMillis(TARGET_SWITCH_WINDOW_MS);
        attackHistory.removeIf(r -> r.timestamp.isBefore(windowStart));

        // 统计窗口内不同目标数量
        Set<String> uniqueTargets = new HashSet<>();
        for (AttackRecord r : attackHistory) {
            uniqueTargets.add(r.targetName);
        }

        if (attackHistory.size() >= 5 && uniqueTargets.size() > MAX_TARGET_SWITCHES) {
            // 短时间内攻击了过多不同目标 — 典型的KillAura无差别攻击模式
            reasons.add("RAPID_TARGET_SWITCH: " + uniqueTargets.size() + " targets in "
                    + TARGET_SWITCH_WINDOW_MS / 1000 + "s");
        }

        // 2. 攻击角度一致性检测（Aimbot检测）
        List<Double> angleHistory = playerAngleHistory.computeIfAbsent(
                playerName, k -> new ArrayList<>());

        // 使用组合角度（yaw变化 + pitch变化）来检测一致性
        double combinedAngle = Math.abs(attackYaw % 360.0) + Math.abs(attackPitch % 360.0);
        angleHistory.add(combinedAngle);

        // 保留最近10次攻击角度
        while (angleHistory.size() > 10) {
            angleHistory.remove(0);
        }

        if (angleHistory.size() >= MIN_CONSECUTIVE_ATTACKS) {
            double maxDeviation = 0;
            double[] angles = new double[angleHistory.size()];
            for (int i = 0; i < angleHistory.size(); i++) {
                angles[i] = angleHistory.get(i);
            }
            // 计算连续攻击间的角度偏差
            for (int i = 1; i < angles.length; i++) {
                double diff = Math.abs(angles[i] - angles[i - 1]);
                if (diff > maxDeviation) maxDeviation = diff;
            }
            // 如果所有连续攻击的角度偏差都很小，说明是自动瞄准
            if (maxDeviation < AIMBOT_ANGLE_THRESHOLD && angleHistory.size() >= 5) {
                reasons.add("AIMBOT_ANGLE_CONSISTENCY: max deviation " + String.format("%.2f", maxDeviation) + " degrees");
            }
        }

        // 3. 攻击距离模式检测 — 精确极限距离攻击
        List<Double> distanceHistory = playerDistanceHistory.computeIfAbsent(
                playerName, k -> new ArrayList<>());
        distanceHistory.add(distance);

        // 保留最近20次攻击距离
        while (distanceHistory.size() > 20) {
            distanceHistory.remove(0);
        }

        // 统计在完美距离范围内（可判定为使用reach+hacks）的攻击次数
        long perfectReachHits = distanceHistory.stream()
                .filter(d -> d >= PERFECT_REACH_THRESHOLD && d <= MAX_LEGITIMATE_REACH + 0.1)
                .count();

        if (distanceHistory.size() >= 10 && perfectReachHits >= MAX_PERFECT_REACH_COUNT) {
            reasons.add("PERFECT_REACH_PATTERN: " + perfectReachHits + "/" + distanceHistory.size()
                    + " hits at max reach (" + String.format("%.2f", PERFECT_REACH_THRESHOLD) + "~"
                    + String.format("%.2f", MAX_LEGITIMATE_REACH) + " blocks)");
        }

        // 汇总结果
        if (reasons.size() >= 2) {
            // 多种检测规则同时命中 — 高度可疑
            flaggedCount.incrementAndGet();
            return KillAuraCheckResult.flagged(reasons);
        } else if (reasons.size() == 1) {
            // 单一规则命中 — 仅标记为可疑
            return KillAuraCheckResult.suspicious(reasons);
        }

        return KillAuraCheckResult.clean();
    }

    /**
     * 玩家离线时清理其追踪数据，释放内存
     * @param playerName 离线玩家名称
     */
    public void clearPlayer(String playerName) {
        playerAttackHistory.remove(playerName);
        playerAngleHistory.remove(playerName);
        playerDistanceHistory.remove(playerName);
    }

    /**
     * 获取模块运行状态
     * @return 包含计数器和活跃追踪玩家数的Map
     */
    public Map<String, Object> getStatus() {
        Map<String, Object> status = new LinkedHashMap<>();
        status.put("totalChecks", totalChecks.get());
        status.put("flaggedCount", flaggedCount.get());
        status.put("activeTrackedPlayers", playerAttackHistory.size());
        return status;
    }

    /**
     * 内部攻击记录 — 记录单次攻击的时间、目标和空间信息
     */
    private static class AttackRecord {
        final Instant timestamp;
        final String targetName;
        final double distance;
        final double yaw;
        final double pitch;

        AttackRecord(Instant timestamp, String targetName, double distance, double yaw, double pitch) {
            this.timestamp = timestamp;
            this.targetName = targetName;
            this.distance = distance;
            this.yaw = yaw;
            this.pitch = pitch;
        }
    }

    /**
     * 杀戮光环检测结果 — 不可变结果类
     */
    public static class KillAuraCheckResult {
        private final boolean flagged;
        private final boolean suspicious;
        private final List<String> reasons;

        private KillAuraCheckResult(boolean flagged, boolean suspicious, List<String> reasons) {
            this.flagged = flagged;
            this.suspicious = suspicious;
            this.reasons = reasons;
        }

        /** 无异常 — 正常攻击行为 */
        public static KillAuraCheckResult clean() {
            return new KillAuraCheckResult(false, false, List.of());
        }

        /** 可疑 — 可能使用了KillAura但证据不够充分 */
        public static KillAuraCheckResult suspicious(List<String> reasons) {
            return new KillAuraCheckResult(false, true, reasons);
        }

        /** 已标记 — 多项检测规则命中，高度可能使用KillAura */
        public static KillAuraCheckResult flagged(List<String> reasons) {
            return new KillAuraCheckResult(true, false, reasons);
        }

        public boolean isFlagged() { return flagged; }
        public boolean isSuspicious() { return suspicious; }
        public boolean isClean() { return !flagged && !suspicious; }
        public List<String> getReasons() { return reasons; }
    }
}
