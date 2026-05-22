package com.aluer.anticheat.combat;

import com.aluer.config.ServerGuardConfig;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * 扩大碰撞箱（Hitboxes）检测服务 — V5.1 反作弊战斗模块
 *
 * 检测原理：
 * 1. 边缘命中比例追踪 — Meteor Client的Hitboxes模块在客户端将实体碰撞箱扩大
 *    （通常从0.6x1.8扩大到1.2x2.4或更大），使玩家更容易命中目标。
 *    服务器无法直接检测客户端渲染，但可以通过分析攻击射线与实体碰撞箱的
 *    交点位置来推断。合法攻击通常命中实体中心附近（碰撞箱内部0.3-1.2范围）。
 *    Hack攻击大量命中碰撞箱的极端边缘位置（距离中心>1.5即超出合法碰撞箱）。
 *    追踪每个玩家的"边缘命中率"（edgeHitRatio）。
 * 2. 攻击射线最小距离分析 — 计算每次攻击中攻击者视线射线与目标碰撞箱
 *    中心点的最小距离。标准玩家碰撞箱为0.6宽x1.8高，从中心到边缘最大距离
 *    约为sqrt(0.3^2+0.9^2)=0.95。如果最小距离持续超过1.0（合法碰撞箱外），
 *    说明客户端使用了扩大的碰撞箱。
 * 3. 攻击位置分布分析 — 合法玩家的攻击命中点在目标碰撞箱内呈正态分布
 *    （中心区域最密集）。Hitboxes用户的命中点集中在扩展边缘区域，
 *    形成外围环状分布。统计攻击命中点与目标中心的距离分布，
 *    如果平均值远超正常范围（合法约0.3-0.6，Hack约0.8-1.5），标记。
 * 4. 转角攻击验证 — Hitboxes用户可以在不可能命中的角度攻击目标。
 *    如果攻击者与目标的视线被实体或方块阻挡但仍能"命中"，
 *    这是因为扩大的碰撞箱超出了合法遮挡物。结合遮挡检测进行验证。
 *    如果攻击射线在到达合法碰撞箱之前穿过了另一个实体或非透明方块，
 *    但服务器仍判定命中，说明碰撞箱被非法扩大。
 *
 * 配置开关：serverguard.security.super-evolution.anti-hitboxes
 */
@Service
public class AntiHitboxesService {

    private final ServerGuardConfig config;

    /**
     * 追踪每个玩家的攻击命中点数据分析（playerName -> 命中数据分析器）
     */
    private final Map<String, HitboxStats> playerHitboxStats = new ConcurrentHashMap<>();

    /**
     * 追踪每个玩家的攻击历史记录（playerName -> 攻击记录列表）
     */
    private final Map<String, List<AttackHitRecord>> playerAttackHistory = new ConcurrentHashMap<>();

    /**
     * 追踪疑似Hitboxes的事件（playerName -> 可疑事件列表）
     */
    private final Map<String, List<Map<String, Object>>> hitboxEvents = new ConcurrentHashMap<>();

    private final AtomicLong totalAttacks = new AtomicLong(0);
    private final AtomicLong edgeHits = new AtomicLong(0);
    private final AtomicLong flaggedCount = new AtomicLong(0);

    /**
     * 标准玩家碰撞箱尺寸（宽x高，单位：方块）
     * 0.6 宽 = 每个方向从中心延伸 0.3
     * 1.8 高，从脚底（Y偏移 -0.9）到头顶（Y偏移 +0.9）
     */
    private static final double PLAYER_WIDTH = 0.6;
    private static final double PLAYER_HEIGHT = 1.8;

    /**
     * 合法碰撞箱从中心到边缘的最大水平距离
     * sqrt((0.6/2)^2) = 0.3
     */
    private static final double MAX_LEGAL_HORIZONTAL_DISTANCE = PLAYER_WIDTH / 2.0; // 0.3

    /**
     * 合法碰撞箱从中心到边缘的最大3D距离
     * sqrt((0.3)^2 + (0.9)^2) ≈ 0.949
     */
    private static final double MAX_LEGAL_3D_DISTANCE = Math.sqrt(
            (PLAYER_WIDTH / 2.0) * (PLAYER_WIDTH / 2.0)
                    + (PLAYER_HEIGHT / 2.0) * (PLAYER_HEIGHT / 2.0));

    /**
     * 边缘命中判定阈值 — 最短距离超过合法最大值的比例
     * 如果最小距离超过合法距离的此倍率，判定为边缘命中
     */
    private static final double EDGE_HIT_RATIO_THRESHOLD = 0.90;

    /**
     * 异常边缘命中率阈值 — 如果玩家的边缘命中比例超过此值则标记
     * 正常玩家约5-20%的边缘命中率（玩家移动/跳动导致）。
     * Hitboxes用户可高达60-90%。
     */
    private static final double ABNORMAL_EDGE_RATIO = 0.45;

    /**
     * 最小攻击样本数 — 收集到此数量的攻击记录后才进行比例分析
     */
    private static final int MIN_ATTACK_SAMPLE = 15;

    /**
     * 命中距离均值异常阈值 — 平均最短距离超过合法值的此倍率即标记
     */
    private static final double MEAN_DISTANCE_ANOMALY_RATIO = 0.85;

    /**
     * 每个玩家保留的最大攻击记录数
     */
    private static final int MAX_RECORDS = 50;

    /**
     * 无参构造函数 — 测试/默认配置使用
     */
    public AntiHitboxesService() {
        this(new ServerGuardConfig());
    }

    /**
     * Spring 注入构造函数
     * @param config 全局配置，提供模块开关控制
     */
    public AntiHitboxesService(ServerGuardConfig config) {
        this.config = config;
    }

    /**
     * 检测一次攻击事件是否为Hitboxes作弊
     * 应用于EntityDamageByEntityEvent（玩家攻击实体）监听
     *
     * @param attackerName 攻击者名称
     * @param attackerUUID 攻击者UUID
     * @param targetName 目标实体名称
     * @param attackerX/Y/Z 攻击者的眼睛位置坐标
     * @param targetX/Y/Z 目标实体的脚底位置坐标
     * @param rayOriginX/Y/Z 攻击射线的起点（攻击者眼睛位置）
     * @param rayHitX/Y/Z 攻击射线的命中点（检测到的碰撞点）
     * @param isLineOfSightBlocked 攻击者与目标之间是否有方块遮挡
     * @param timestamp 时间戳
     * @return 检测结果
     */
    public HitboxesCheckResult detect(String attackerName, String attackerUUID,
                                       String targetName,
                                       double attackerX, double attackerY, double attackerZ,
                                       double targetX, double targetY, double targetZ,
                                       double rayOriginX, double rayOriginY, double rayOriginZ,
                                       double rayHitX, double rayHitY, double rayHitZ,
                                       boolean isLineOfSightBlocked, Instant timestamp) {
        // 模块开关检查
        if (!config.getSecurity().getSuperEvolution().isAntiHitboxes()) {
            return HitboxesCheckResult.clean();
        }

        totalAttacks.incrementAndGet();
        List<String> reasons = new ArrayList<>();

        HitboxStats stats = playerHitboxStats.computeIfAbsent(
                attackerName, k -> new HitboxStats());

        // 计算目标碰撞箱的中心点
        // 脚底Y + 身高的一半 = 中心Y
        double targetCenterX = targetX;
        double targetCenterY = targetY + (PLAYER_HEIGHT / 2.0);
        double targetCenterZ = targetZ;

        // 计算攻击射线到碰撞箱中心点的最短距离（点到线段距离）
        double minDistance = pointToLineSegmentDistance(
                targetCenterX, targetCenterY, targetCenterZ,
                rayOriginX, rayOriginY, rayOriginZ,
                rayHitX, rayHitY, rayHitZ);

        // 记录此攻击
        AttackHitRecord hitRecord = new AttackHitRecord(
                minDistance, rayHitX, rayHitY, rayHitZ,
                targetCenterX, targetCenterY, targetCenterZ,
                isLineOfSightBlocked, timestamp);

        List<AttackHitRecord> history = playerAttackHistory.computeIfAbsent(
                attackerName, k -> new ArrayList<>());
        history.add(hitRecord);
        while (history.size() > MAX_RECORDS) {
            history.remove(0);
        }

        // 更新统计数据
        stats.totalHits++;
        if (minDistance > MAX_LEGAL_3D_DISTANCE * EDGE_HIT_RATIO_THRESHOLD) {
            stats.edgeHits++;
            edgeHits.incrementAndGet();
        }
        stats.sumDistance += minDistance;
        stats.sumSqDistance += minDistance * minDistance;

        // 检测1：边缘命中 — 最短距离超过合法碰撞箱边界
        if (minDistance > MAX_LEGAL_3D_DISTANCE) {
            reasons.add("EDGE_HIT_BEYOND_BOX: shortest ray-to-center distance="
                    + String.format("%.3f", minDistance)
                    + " (max legal at bounding box edge="
                    + String.format("%.3f", MAX_LEGAL_3D_DISTANCE) + ")");
        } else if (minDistance > MAX_LEGAL_3D_DISTANCE * EDGE_HIT_RATIO_THRESHOLD) {
            reasons.add("EDGE_HIT_NEAR_LIMIT: shortest ray-to-center distance="
                    + String.format("%.3f", minDistance)
                    + " (" + String.format("%.0f", (minDistance / MAX_LEGAL_3D_DISTANCE) * 100)
                    + "% of legal maximum)");
        }

        // 检测2：视线遮挡穿透命中 — 射线穿过了方块但命中了
        if (isLineOfSightBlocked && minDistance > MAX_LEGAL_3D_DISTANCE * EDGE_HIT_RATIO_THRESHOLD) {
            reasons.add("BLOCKED_LOS_HITBOX: hit target with blocked line-of-sight"
                    + " at distance=" + String.format("%.3f", minDistance)
                    + " (expanded hitbox bypassed obstacle)");
        }

        // 检测3：攻击命中水平偏移过大 — 碰撞箱宽度仅为0.6
        double horizontalDist = Math.sqrt(
                (rayHitX - targetCenterX) * (rayHitX - targetCenterX)
                        + (rayHitZ - targetCenterZ) * (rayHitZ - targetCenterZ));

        if (horizontalDist > MAX_LEGAL_HORIZONTAL_DISTANCE * 1.2) {
            reasons.add("HORIZONTAL_OVERREACH: hit horizontal offset="
                    + String.format("%.3f", horizontalDist)
                    + " (player width half="
                    + String.format("%.3f", MAX_LEGAL_HORIZONTAL_DISTANCE) + ")");
        }

        // 检测4：边缘命中比例分析 — 累计足够样本后分析
        if (stats.totalHits >= MIN_ATTACK_SAMPLE) {
            double edgeRatio = (double) stats.edgeHits / stats.totalHits;

            if (edgeRatio >= ABNORMAL_EDGE_RATIO) {
                reasons.add("ABNORMAL_EDGE_RATIO: " + String.format("%.0f", edgeRatio * 100)
                        + "% edge hits ( " + stats.edgeHits + "/" + stats.totalHits
                        + " attacks, threshold: " + String.format("%.0f", ABNORMAL_EDGE_RATIO * 100) + "%)");
            }

            // 检测5：平均命中距离异常
            double meanDistance = stats.sumDistance / stats.totalHits;
            if (meanDistance > MAX_LEGAL_3D_DISTANCE * MEAN_DISTANCE_ANOMALY_RATIO) {
                reasons.add("MEAN_DISTANCE_ANOMALY: average ray distance="
                        + String.format("%.3f", meanDistance)
                        + " (" + String.format("%.0f", (meanDistance / MAX_LEGAL_3D_DISTANCE) * 100)
                        + "% of legal max, typical human: 30-50%)");
            }
        }

        // 记录可疑事件
        if (!reasons.isEmpty()) {
            List<Map<String, Object>> events = hitboxEvents.computeIfAbsent(
                    attackerName, k -> new ArrayList<>());
            Map<String, Object> event = new LinkedHashMap<>();
            event.put("time", timestamp.toString());
            event.put("target", targetName);
            event.put("minDistance", String.format("%.3f", minDistance));
            event.put("legalMaxDistance", String.format("%.3f", MAX_LEGAL_3D_DISTANCE));
            event.put("horizontalOffset", String.format("%.3f", horizontalDist));
            event.put("blockedLoS", isLineOfSightBlocked);
            event.put("reasons", reasons);
            events.add(event);
            while (events.size() > 20) {
                events.remove(0);
            }
        }

        // 汇总结果
        if (reasons.size() >= 2) {
            flaggedCount.incrementAndGet();
            return HitboxesCheckResult.flagged(reasons);
        } else if (reasons.size() == 1) {
            return HitboxesCheckResult.suspicious(reasons);
        }

        return HitboxesCheckResult.clean();
    }

    /**
     * 计算点到线段的最短距离（3D）
     * 用于计算碰撞箱中心到攻击射线的最近距离
     *
     * @param px/py/pz 目标点（碰撞箱中心）坐标
     * @param ax/ay/az 线段起点（射线原点 = 攻击者眼睛）
     * @param bx/by/bz 线段终点（射线命中点）
     * @return 点到线段的最短距离
     */
    private double pointToLineSegmentDistance(
            double px, double py, double pz,
            double ax, double ay, double az,
            double bx, double by, double bz) {

        // 向量 AP = P - A
        double apx = px - ax;
        double apy = py - ay;
        double apz = pz - az;

        // 向量 AB = B - A
        double abx = bx - ax;
        double aby = by - ay;
        double abz = bz - az;

        // 线段长度的平方
        double abLengthSq = abx * abx + aby * aby + abz * abz;

        // 如果线段退化为一个点（即A和B重合），返回点到A的距离
        if (abLengthSq < 1e-12) {
            return Math.sqrt(apx * apx + apy * apy + apz * apz);
        }

        // 投影参数 t = (AP·AB) / |AB|^2，clamp到[0,1]以限制在线段上
        double t = (apx * abx + apy * aby + apz * abz) / abLengthSq;
        t = Math.max(0.0, Math.min(1.0, t));

        // 线段上的最近点 = A + t * AB
        double closestX = ax + t * abx;
        double closestY = ay + t * aby;
        double closestZ = az + t * abz;

        // 返回到最近点的距离
        double dx = px - closestX;
        double dy = py - closestY;
        double dz = pz - closestZ;

        return Math.sqrt(dx * dx + dy * dy + dz * dz);
    }

    /**
     * 玩家离线时清理追踪数据
     * @param playerName 离线玩家名称
     */
    public void clearPlayer(String playerName) {
        playerHitboxStats.remove(playerName);
        playerAttackHistory.remove(playerName);
        hitboxEvents.remove(playerName);
    }

    /**
     * 获取模块运行状态
     * @return 包含计数器和活跃追踪玩家数的Map
     */
    public Map<String, Object> getStatus() {
        Map<String, Object> status = new LinkedHashMap<>();
        status.put("totalAttacks", totalAttacks.get());
        status.put("edgeHits", edgeHits.get());
        status.put("flaggedCount", flaggedCount.get());
        status.put("activeTrackedPlayers", playerHitboxStats.size());

        // 计算全局边缘命中率
        long totalA = totalAttacks.get();
        long totalE = edgeHits.get();
        if (totalA > 0) {
            status.put("globalEdgeHitRatio", String.format("%.1f%%",
                    100.0 * totalE / totalA));
        }

        // 列出高边缘命中率玩家
        List<Map<String, Object>> highEdgePlayers = new ArrayList<>();
        for (Map.Entry<String, HitboxStats> entry : playerHitboxStats.entrySet()) {
            HitboxStats stats = entry.getValue();
            if (stats.totalHits >= MIN_ATTACK_SAMPLE) {
                double ratio = (double) stats.edgeHits / stats.totalHits;
                if (ratio >= ABNORMAL_EDGE_RATIO) {
                    Map<String, Object> info = new LinkedHashMap<>();
                    info.put("player", entry.getKey());
                    info.put("edgeHitRatio", String.format("%.1f%%", ratio * 100));
                    info.put("edgeHits", stats.edgeHits);
                    info.put("totalHits", stats.totalHits);
                    info.put("meanDistance", String.format("%.3f",
                            stats.sumDistance / stats.totalHits));
                    highEdgePlayers.add(info);
                }
            }
        }
        highEdgePlayers.sort((a, b) -> {
            String ra = (String) a.get("edgeHitRatio");
            String rb = (String) b.get("edgeHitRatio");
            return rb.compareTo(ra);
        });
        status.put("highEdgeHitPlayers", highEdgePlayers);

        return status;
    }

    /**
     * 内部命中统计分析器 — 追踪单个玩家的攻击命中统计
     */
    private static class HitboxStats {
        long totalHits = 0;
        long edgeHits = 0;
        double sumDistance = 0.0;
        double sumSqDistance = 0.0;
    }

    /**
     * 内部攻击命中记录 — 记录单次攻击的命中参数信息
     */
    private static class AttackHitRecord {
        final double minDistanceToCenter;   // 射线到碰撞箱中心的最短距离
        final double rayHitX, rayHitY, rayHitZ;       // 命中点坐标
        final double targetCenterX, targetCenterY, targetCenterZ; // 目标中心坐标
        final boolean isLineOfSightBlocked; // 是否有方块遮挡
        final Instant timestamp;

        AttackHitRecord(double minDistanceToCenter,
                        double rayHitX, double rayHitY, double rayHitZ,
                        double targetCenterX, double targetCenterY, double targetCenterZ,
                        boolean isLineOfSightBlocked, Instant timestamp) {
            this.minDistanceToCenter = minDistanceToCenter;
            this.rayHitX = rayHitX;
            this.rayHitY = rayHitY;
            this.rayHitZ = rayHitZ;
            this.targetCenterX = targetCenterX;
            this.targetCenterY = targetCenterY;
            this.targetCenterZ = targetCenterZ;
            this.isLineOfSightBlocked = isLineOfSightBlocked;
            this.timestamp = timestamp;
        }
    }

    /**
     * Hitboxes检测结果 — 不可变结果类
     */
    public static class HitboxesCheckResult {
        private final boolean flagged;
        private final boolean suspicious;
        private final List<String> reasons;

        private HitboxesCheckResult(boolean flagged, boolean suspicious, List<String> reasons) {
            this.flagged = flagged;
            this.suspicious = suspicious;
            this.reasons = reasons;
        }

        /** 无异常 — 合法攻击命中 */
        public static HitboxesCheckResult clean() {
            return new HitboxesCheckResult(false, false, List.of());
        }

        /** 可疑 — 单一边缘命中 */
        public static HitboxesCheckResult suspicious(List<String> reasons) {
            return new HitboxesCheckResult(false, true, reasons);
        }

        /** 已标记 — 确定使用了Hitboxes hack */
        public static HitboxesCheckResult flagged(List<String> reasons) {
            return new HitboxesCheckResult(true, false, reasons);
        }

        public boolean isFlagged() { return flagged; }
        public boolean isSuspicious() { return suspicious; }
        public boolean isClean() { return !flagged && !suspicious; }
        public List<String> getReasons() { return reasons; }
    }
}
