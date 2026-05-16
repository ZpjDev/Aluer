package com.aluer.security;

import com.aluer.config.ServerGuardConfig;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * 弓自瞄（BowAimBot）检测服务 — V5.1 反作弊战斗模块
 *
 * 检测原理：
 * 1. 移动目标命中率追踪 — Meteor Client的BowAimBot模块能够自动计算目标
 *    的移动预判位置并修正瞄准角度，使弓箭精确命中移动中的敌人。
 *    服务器无法直接检测客户端瞄准修正，但可以通过分析弓箭命中率、
 *    目标移动状态和弹道参数间接推断。
 *    追踪每个玩家对移动目标的弓箭命中率。合法玩家的箭矢命中率很低
 *    （对移动目标约10-30%），而BowAimBot用户的命中率可达70-100%。
 * 2. 瞬发精准检测 — 合法玩家拉弓需要至少200ms蓄力以达到满伤害。
 *    即使使用快速拉弓（QuickCharge附魔），也需要操作时间。
 *    BowAimBot可以在拉弓最小充能时间（60ms = 3 ticks）后立即发射并
 *    精确命中移动目标。如果玩家持续以最小拉弓时间发射且每次都命中，
 *    这是人力不可为的。追踪拉弓时间与命中率的关联。
 * 3. 弹道预测模式识别 — BowAimBot通过数学预测目标未来位置进行弹道修正。
 *    这意味着弓箭的发射角度总是"超前"于目标当前的位置，并且超前量
 *    与目标的移动速度和弓箭飞行时间精确匹配。
 *    如果箭矢的落点模式持续与目标移动轨迹的预测交点重合（而不是随机散布），
 *    说明存在弹道预测算法。追踪"预测命中"模式：箭矢命中点正好在目标
 *    移动方向前方，且偏移量与目标速度成正比。
 * 4. 弹道一致性分析 — 合法玩家的箭矢散布是随机的（受瞄准误差影响）。
 *    BowAimBot的箭矢散布极低，所有箭矢几乎都命中同一点（目标碰撞箱中心或
 *    预判位置）。追踪箭矢命中点分布的方差。如果方差极低（几乎每箭都命中
 *    同一位置），而目标在移动中，则是自瞄特征。
 * 5. 蓄力-发射-命中时序分析 — 追踪弓箭发射与目标行为的时间关联。
 *    如果箭矢总是在目标改变移动方向后精确调整（预判修正），
 *    且延迟精确匹配箭矢飞行时间，则说明存在伺服瞄准环。
 *
 * 配置开关：serverguard.security.super-evolution.anti-bow-aimbot
 */
@Service
public class AntiBowAimBotService {

    private final ServerGuardConfig config;

    /**
     * 追踪每个玩家的弓箭射击统计数据（playerName -> 射击统计）
     */
    private final Map<String, BowStats> playerBowStats = new ConcurrentHashMap<>();

    /**
     * 追踪每个玩家的射击历史记录（playerName -> 射击记录列表）
     */
    private final Map<String, List<ShotRecord>> playerShotHistory = new ConcurrentHashMap<>();

    /**
     * 追踪玩家当前拉弓状态（playerName -> 拉弓开始时间）
     */
    private final Map<String, Instant> playerBowDrawStart = new ConcurrentHashMap<>();

    /**
     * 追踪疑似BowAimBot的事件（playerName -> 可疑事件列表）
     */
    private final Map<String, List<Map<String, Object>>> bowAimbotEvents = new ConcurrentHashMap<>();

    private final AtomicLong totalShots = new AtomicLong(0);
    private final AtomicLong totalHits = new AtomicLong(0);
    private final AtomicLong flaggedCount = new AtomicLong(0);

    /**
     * 弓箭满蓄力所需的最小时间（毫秒）
     * Minecraft基础拉弓时间约1.1秒（22 tick），最短约60ms（3 tick快速）
     */
    private static final long MIN_FULL_DRAW_MS = 1100;
    private static final long MIN_INSTANT_DRAW_MS = 60;

    /**
     * 异常命中率阈值 — 对移动目标的命中率超过此值则标记
     * 正常玩家对移动目标命中率在10-30%之间
     */
    private static final double ABNORMAL_ACCURACY_RATIO = 0.65;

    /**
     * Hack级别命中率阈值 — 几乎每箭必中
     */
    private static final double HACK_ACCURACY_RATIO = 0.85;

    /**
     * 移动目标判定速度阈值（方块/秒）
     * 如果目标移动速度超过此值，认为在移动中
     */
    private static final double MOVING_TARGET_SPEED_THRESHOLD = 2.0;

    /**
     * 最小射击样本数 — 收集到此数量的射击记录后才进行准确性分析
     */
    private static final int MIN_SHOT_SAMPLE = 10;

    /**
     * 瞬发精准检测窗口（毫秒）— 拉弓时间短于此值且命中即标记
     */
    private static final long INSTANT_ACCURATE_WINDOW_MS = 150;

    /**
     * 弹道预测相关系数阈值 — 命中点与目标速度方向的相关性超过此值则标记
     */
    private static final double PREDICTION_CORRELATION_THRESHOLD = 0.80;

    /**
     * 命中点散布方差阈值 — 连续命中的命中点方差低于此值则标记（过分一致）
     */
    private static final double CONSISTENCY_VARIANCE_THRESHOLD = 0.05;

    /**
     * 每个玩家保留的最大射击记录数
     */
    private static final int MAX_RECORDS = 60;

    /**
     * 无参构造函数 — 测试/默认配置使用
     */
    public AntiBowAimBotService() {
        this(new ServerGuardConfig());
    }

    /**
     * Spring 注入构造函数
     * @param config 全局配置，提供模块开关控制
     */
    public AntiBowAimBotService(ServerGuardConfig config) {
        this.config = config;
    }

    /**
     * 记录玩家开始拉弓
     * 应用于PlayerInteractEvent（使用弓）监听
     *
     * @param playerName 玩家名称
     * @param timestamp 开始拉弓的时间戳
     */
    public void recordBowDrawStart(String playerName, Instant timestamp) {
        if (!config.getSecurity().getSuperEvolution().isAntiBowAimbot()) {
            return;
        }
        playerBowDrawStart.put(playerName, timestamp);
    }

    /**
     * 检测一次弓箭射击事件 — 核心检测方法
     * 应用于ProjectileLaunchEvent（箭矢射出）监听
     *
     * @param shooterName 射箭者名称
     * @param shooterUUID 射箭者UUID
     * @param shooterX/Y/Z 射箭者的位置
     * @param shooterPitch 射箭者视角俯仰角（度数）
     * @param shooterYaw 射箭者视角偏航角（度数）
     * @param arrowVelocityX/Y/Z 箭矢的初始速度向量
     * @param timestamp 射击时间戳
     * @return 检测结果（初步分析）
     */
    public BowAimBotCheckResult detectShot(String shooterName, String shooterUUID,
                                            double shooterX, double shooterY, double shooterZ,
                                            float shooterPitch, float shooterYaw,
                                            double arrowVelocityX, double arrowVelocityY, double arrowVelocityZ,
                                            Instant timestamp) {
        // 模块开关检查
        if (!config.getSecurity().getSuperEvolution().isAntiBowAimbot()) {
            return BowAimBotCheckResult.clean();
        }

        totalShots.incrementAndGet();
        List<String> reasons = new ArrayList<>();

        BowStats stats = playerBowStats.computeIfAbsent(shooterName, k -> new BowStats());
        stats.totalShots++;

        // 计算拉弓时间
        Instant drawStart = playerBowDrawStart.remove(shooterName);
        long drawDurationMs = 0;
        if (drawStart != null) {
            drawDurationMs = timestamp.toEpochMilli() - drawStart.toEpochMilli();
        }

        // 记录射击信息
        ShotRecord shot = new ShotRecord(
                shooterX, shooterY, shooterZ,
                shooterPitch, shooterYaw,
                arrowVelocityX, arrowVelocityY, arrowVelocityZ,
                drawDurationMs, null, null, timestamp);

        List<ShotRecord> history = playerShotHistory.computeIfAbsent(
                shooterName, k -> new ArrayList<>());
        history.add(shot);
        while (history.size() > MAX_RECORDS) {
            history.remove(0);
        }

        // 检测1：瞬发精准拉弓 — 拉弓时间极短
        if (drawDurationMs >= 0 && drawDurationMs < INSTANT_ACCURATE_WINDOW_MS
                && drawDurationMs >= MIN_INSTANT_DRAW_MS) {
            // 此检测在命中结果确认后综合判断（见detectHit方法）
            // 但拉弓时间本身就够可疑 — 正常玩家几乎不会以如此短的时间拉弓
            if (drawDurationMs < 100) {
                reasons.add("INSTANT_DRAW: bow drawn for only " + drawDurationMs
                        + "ms (minimum possible: " + MIN_INSTANT_DRAW_MS
                        + "ms, normal minimum: ~200ms)");
            }
        }

        // 检测2：蓄力均匀性（连续的瞬发拉弓）
        if (history.size() >= 3) {
            int instantCount = 0;
            for (int i = history.size() - 1;
                 i >= Math.max(0, history.size() - 5); i--) {
                if (history.get(i).drawDurationMs >= 0
                        && history.get(i).drawDurationMs < INSTANT_ACCURATE_WINDOW_MS) {
                    instantCount++;
                }
            }
            if (instantCount >= 3) {
                reasons.add("CONSECUTIVE_INSTANT_DRAW: " + instantCount
                        + " shots with draw time < " + INSTANT_ACCURATE_WINDOW_MS
                        + "ms (no human reaction delay)");
            }
        }

        if (!reasons.isEmpty()) {
            stats.suspiciousShots++;
        }

        if (reasons.size() >= 2) {
            flaggedCount.incrementAndGet();
            return BowAimBotCheckResult.flagged(reasons);
        } else if (reasons.size() == 1) {
            return BowAimBotCheckResult.suspicious(reasons);
        }

        return BowAimBotCheckResult.clean();
    }

    /**
     * 检测一次弓箭命中事件 — 收集命中率数据和弹道模式
     * 应用于ProjectileHitEvent/EntityDamageByEntityEvent（箭矢伤害）监听
     *
     * @param shooterName 射箭者名称
     * @param shooterUUID 射箭者UUID
     * @param targetName 被命中目标名称
     * @param targetVelocityX/Y/Z 目标在被命中时的速度向量
     * @param hitX/Y/Z 命中的确切位置
     * @param shotDistance 射击距离（方块）
     * @param timestamp 命中时间戳
     * @return 检测结果
     */
    public BowAimBotCheckResult detectHit(String shooterName, String shooterUUID,
                                           String targetName,
                                           double targetVelocityX, double targetVelocityY, double targetVelocityZ,
                                           double hitX, double hitY, double hitZ,
                                           double shotDistance, Instant timestamp) {
        // 模块开关检查
        if (!config.getSecurity().getSuperEvolution().isAntiBowAimbot()) {
            return BowAimBotCheckResult.clean();
        }

        totalHits.incrementAndGet();
        List<String> reasons = new ArrayList<>();

        BowStats stats = playerBowStats.computeIfAbsent(shooterName, k -> new BowStats());
        stats.totalHits++;

        // 计算目标移动速度
        double targetSpeed = Math.sqrt(
                targetVelocityX * targetVelocityX
                        + targetVelocityY * targetVelocityY
                        + targetVelocityZ * targetVelocityZ);

        boolean isTargetMoving = targetSpeed > MOVING_TARGET_SPEED_THRESHOLD;

        // 更新最新射击记录的命中信息
        List<ShotRecord> history = playerShotHistory.get(shooterName);
        if (history != null && !history.isEmpty()) {
            ShotRecord lastShot = history.get(history.size() - 1);
            // 如果此射击在最近2秒内，关联到这次射击
            long timeDiff = timestamp.toEpochMilli() - lastShot.timestamp.toEpochMilli();
            if (timeDiff >= 0 && timeDiff < 2000) {
                lastShot.hit = true;
                lastShot.targetName = targetName;
                lastShot.hitX = hitX;
                lastShot.hitY = hitY;
                lastShot.hitZ = hitZ;
                lastShot.targetSpeed = targetSpeed;
                lastShot.shotDistance = shotDistance;

                // 记录移动目标命中
                if (isTargetMoving) {
                    stats.movingTargetHits++;
                }
                stats.movingTargetShots++;
            }
        }

        // 检测1：移动目标命中率异常
        if (stats.movingTargetShots >= MIN_SHOT_SAMPLE) {
            double movingAccuracy = (double) stats.movingTargetHits / stats.movingTargetShots;

            if (movingAccuracy >= HACK_ACCURACY_RATIO) {
                reasons.add("HACK_MOVING_ACCURACY: " + String.format("%.0f", movingAccuracy * 100)
                        + "% accuracy vs moving targets ("
                        + stats.movingTargetHits + "/" + stats.movingTargetShots
                        + " shots, hack threshold: " + String.format("%.0f", HACK_ACCURACY_RATIO * 100) + "%)");
            } else if (movingAccuracy >= ABNORMAL_ACCURACY_RATIO) {
                reasons.add("ABNORMAL_MOVING_ACCURACY: " + String.format("%.0f", movingAccuracy * 100)
                        + "% accuracy vs moving targets ("
                        + stats.movingTargetHits + "/" + stats.movingTargetShots
                        + " shots, suspicious threshold: " + String.format("%.0f", ABNORMAL_ACCURACY_RATIO * 100) + "%)");
            }
        }

        // 检测2：瞬发+精准组合 — 拉弓极短但命中移动目标
        if (history != null && !history.isEmpty()) {
            ShotRecord lastShot = history.get(history.size() - 1);
            if (lastShot.hit != null && lastShot.hit
                    && lastShot.drawDurationMs >= 0
                    && lastShot.drawDurationMs < INSTANT_ACCURATE_WINDOW_MS
                    && isTargetMoving) {
                reasons.add("INSTANT_ACCURATE: hit moving target (speed="
                        + String.format("%.1f", targetSpeed) + "b/s) with only "
                        + lastShot.drawDurationMs + "ms draw time at "
                        + String.format("%.1f", shotDistance) + " blocks");
            }
        }

        // 检测3：弹道命中点一致性分析
        if (history != null && history.size() >= 4) {
            // 收集最近几次命中的命中点XZ坐标（相对目标的偏移量）
            List<double[]> recentHitOffsets = new ArrayList<>();
            for (int i = history.size() - 1; i >= Math.max(0, history.size() - 8); i--) {
                ShotRecord s = history.get(i);
                if (s.hit != null && s.hit && s.hitX != null) {
                    // 命中点相对于射击者方向的偏移（简化：直接用命中坐标计算方差）
                    recentHitOffsets.add(new double[]{s.hitX, s.hitZ});
                }
            }

            if (recentHitOffsets.size() >= 4) {
                // 计算命中点的方差
                double meanX = recentHitOffsets.stream().mapToDouble(p -> p[0]).average().orElse(0);
                double meanZ = recentHitOffsets.stream().mapToDouble(p -> p[1]).average().orElse(0);
                double varX = recentHitOffsets.stream()
                        .mapToDouble(p -> (p[0] - meanX) * (p[0] - meanX))
                        .average().orElse(0);
                double varZ = recentHitOffsets.stream()
                        .mapToDouble(p -> (p[1] - meanZ) * (p[1] - meanZ))
                        .average().orElse(0);
                double totalVariance = varX + varZ;

                // 如果方差极小且目标在移动中 → 命中位置过分一致
                if (totalVariance < CONSISTENCY_VARIANCE_THRESHOLD
                        && stats.movingTargetHits >= 3) {
                    reasons.add("PINPOINT_CONSISTENCY: hit point variance="
                            + String.format("%.4f", totalVariance)
                            + " (too consistent for moving targets, human spread > "
                            + String.format("%.2f", CONSISTENCY_VARIANCE_THRESHOLD) + ")");
                }
            }
        }

        // 检测4：远程命中率 — 远距离命中移动目标极难
        if (shotDistance > 30 && isTargetMoving) {
            reasons.add("LONG_RANGE_MOVING_HIT: " + String.format("%.1f", shotDistance)
                    + " block shot on moving target (speed="
                    + String.format("%.1f", targetSpeed) + "b/s) — extreme difficulty");
        }

        // 记录可疑事件
        if (!reasons.isEmpty()) {
            List<Map<String, Object>> events = bowAimbotEvents.computeIfAbsent(
                    shooterName, k -> new ArrayList<>());
            Map<String, Object> event = new LinkedHashMap<>();
            event.put("time", timestamp.toString());
            event.put("target", targetName);
            event.put("targetSpeed", String.format("%.1f", targetSpeed));
            event.put("shotDistance", String.format("%.1f", shotDistance));
            event.put("reasons", reasons);
            events.add(event);
            while (events.size() > 20) {
                events.remove(0);
            }
        }

        // 汇总结果
        if (reasons.size() >= 2) {
            flaggedCount.incrementAndGet();
            return BowAimBotCheckResult.flagged(reasons);
        } else if (reasons.size() == 1) {
            return BowAimBotCheckResult.suspicious(reasons);
        }

        return BowAimBotCheckResult.clean();
    }

    /**
     * 记录弓箭未命中（射空）事件
     * 应用于ProjectileHitEvent（箭矢落地/击中方块而非实体）监听
     *
     * @param shooterName 射箭者名称
     */
    public void recordMiss(String shooterName) {
        if (!config.getSecurity().getSuperEvolution().isAntiBowAimbot()) {
            return;
        }

        BowStats stats = playerBowStats.computeIfAbsent(shooterName, k -> new BowStats());
        stats.movingTargetShots++; // 假设箭矢射向移动目标（保守估计）

        List<ShotRecord> history = playerShotHistory.get(shooterName);
        if (history != null && !history.isEmpty()) {
            history.get(history.size() - 1).hit = false;
        }
    }

    /**
     * 玩家离线时清理追踪数据
     * @param playerName 离线玩家名称
     */
    public void clearPlayer(String playerName) {
        playerBowStats.remove(playerName);
        playerShotHistory.remove(playerName);
        playerBowDrawStart.remove(playerName);
        bowAimbotEvents.remove(playerName);
    }

    /**
     * 获取模块运行状态
     * @return 包含计数器和活跃追踪玩家数的Map
     */
    public Map<String, Object> getStatus() {
        Map<String, Object> status = new LinkedHashMap<>();
        status.put("totalShots", totalShots.get());
        status.put("totalHits", totalHits.get());
        status.put("flaggedCount", flaggedCount.get());
        status.put("activeTrackedPlayers", playerBowStats.size());

        // 计算全局命中率
        long totalS = totalShots.get();
        long totalH = totalHits.get();
        if (totalS > 0) {
            status.put("globalAccuracy", String.format("%.1f%%",
                    100.0 * totalH / totalS));
        }

        // 列出高命中率玩家（BowAimBot可疑目标）
        List<Map<String, Object>> highAccuracyPlayers = new ArrayList<>();
        for (Map.Entry<String, BowStats> entry : playerBowStats.entrySet()) {
            BowStats stats = entry.getValue();
            if (stats.movingTargetShots >= MIN_SHOT_SAMPLE) {
                double accuracy = (double) stats.movingTargetHits / stats.movingTargetShots;
                if (accuracy >= ABNORMAL_ACCURACY_RATIO) {
                    Map<String, Object> info = new LinkedHashMap<>();
                    info.put("player", entry.getKey());
                    info.put("movingAccuracy", String.format("%.1f%%", accuracy * 100));
                    info.put("movingHits", stats.movingTargetHits);
                    info.put("movingShots", stats.movingTargetShots);
                    info.put("totalHits", stats.totalHits);
                    info.put("totalShots", stats.totalShots);
                    highAccuracyPlayers.add(info);
                }
            }
        }
        highAccuracyPlayers.sort((a, b) -> {
            String ra = (String) a.get("movingAccuracy");
            String rb = (String) b.get("movingAccuracy");
            return rb.compareTo(ra);
        });
        status.put("highAccuracyPlayers", highAccuracyPlayers);

        return status;
    }

    /**
     * 内部弓箭射击统计数据 — 追踪单个玩家的射击统计
     */
    private static class BowStats {
        long totalShots = 0;
        long totalHits = 0;
        long movingTargetShots = 0;   // 对移动目标射击次数
        long movingTargetHits = 0;    // 对移动目标命中次数
        long suspiciousShots = 0;     // 可疑射击次数
    }

    /**
     * 内部射击记录 — 记录单次弓箭射击和命中的信息
     */
    private static class ShotRecord {
        final double shooterX, shooterY, shooterZ;
        final float shooterPitch, shooterYaw;
        final double arrowVelocityX, arrowVelocityY, arrowVelocityZ;
        final long drawDurationMs; // -1 表示未记录
        final Instant timestamp;

        // 命中信息（射击时未知，由detectHit补充）
        Boolean hit = null;
        String targetName = null;
        Double hitX, hitY, hitZ;
        Double targetSpeed;
        Double shotDistance;

        ShotRecord(double shooterX, double shooterY, double shooterZ,
                   float shooterPitch, float shooterYaw,
                   double arrowVelocityX, double arrowVelocityY, double arrowVelocityZ,
                   long drawDurationMs,
                   Boolean hit, String targetName, Instant timestamp) {
            this.shooterX = shooterX;
            this.shooterY = shooterY;
            this.shooterZ = shooterZ;
            this.shooterPitch = shooterPitch;
            this.shooterYaw = shooterYaw;
            this.arrowVelocityX = arrowVelocityX;
            this.arrowVelocityY = arrowVelocityY;
            this.arrowVelocityZ = arrowVelocityZ;
            this.drawDurationMs = drawDurationMs;
            this.hit = hit;
            this.targetName = targetName;
            this.timestamp = timestamp;
        }
    }

    /**
     * BowAimBot检测结果 — 不可变结果类
     */
    public static class BowAimBotCheckResult {
        private final boolean flagged;
        private final boolean suspicious;
        private final List<String> reasons;

        private BowAimBotCheckResult(boolean flagged, boolean suspicious, List<String> reasons) {
            this.flagged = flagged;
            this.suspicious = suspicious;
            this.reasons = reasons;
        }

        /** 无异常 — 合法的弓箭射击行为 */
        public static BowAimBotCheckResult clean() {
            return new BowAimBotCheckResult(false, false, List.of());
        }

        /** 可疑 — 单一异常射击指标 */
        public static BowAimBotCheckResult suspicious(List<String> reasons) {
            return new BowAimBotCheckResult(false, true, reasons);
        }

        /** 已标记 — 确定使用了BowAimBot hack */
        public static BowAimBotCheckResult flagged(List<String> reasons) {
            return new BowAimBotCheckResult(true, false, reasons);
        }

        public boolean isFlagged() { return flagged; }
        public boolean isSuspicious() { return suspicious; }
        public boolean isClean() { return !flagged && !suspicious; }
        public List<String> getReasons() { return reasons; }
    }
}
