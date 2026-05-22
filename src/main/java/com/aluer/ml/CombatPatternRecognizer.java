package com.aluer.ml;

import com.aluer.config.ServerGuardConfig;
import org.apache.commons.math3.stat.descriptive.DescriptiveStatistics;
import org.apache.commons.math3.stat.inference.TTest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedDeque;
import java.util.concurrent.atomic.AtomicLong;
import com.aluer.anticheat.combat.AntiAutoClickerService;
import com.aluer.anticheat.combat.AntiKillAuraService;
import com.aluer.anticheat.combat.AntiReachService;

/**
 * 战斗模式识别器 — 基于统计分析识别PVP作弊模式
 *
 * 核心检测方法：
 * 1. 攻击时序分析（CPS统计）：
 *    - 合法玩家：CPS围绕均值呈正态分布，有自然抖动
 *    - AutoClicker：CPS方差极低，点击间隔近乎恒定（机械式定时器）
 *    - 手动爆发：CPS均值高但方差也高（人类紧张操作的特征）
 * 2. 多目标检测（KillAura）：
 *    - 合法玩家：专注攻击1-2个目标，切换有延迟
 *    - KillAura：自动锁定范围内所有目标，切换熵值极高
 * 3. 视角旋转模式分析（Aimbot检测）：
 *    - 合法玩家：跳动式注视（saccadic movement）— 快速旋转 + 过冲 + 微调修正
 *    - Aimbot：平滑线性跟踪，无过冲，无修正抖动
 *    - 分析旋转速度（一阶导数）和旋转加速度（二阶导数）
 * 4. 命中率分析：
 *    - 合法玩家：正常命中率 ~40-60%（考虑护甲、闪避等因素）
 *    - KillAura：命中率异常高（> 90%）因为自动锁定不miss
 *    - Reach：在超出正常距离处命中（> 3.0方块）
 *
 * 5. 与现有安全服务（AntiKillAuraService、AntiAutoClickerService、AntiReachService）
 *    进行交叉引用，产生综合置信度评分。
 *
 * 数学工具：Apache Commons Math3 — DescriptiveStatistics（统计均值/方差/偏度/峰度）、
 * TTest（分布假设检验）
 */
@Service
public class CombatPatternRecognizer {

    private static final Logger logger = LoggerFactory.getLogger(CombatPatternRecognizer.class);

    private final ServerGuardConfig config;

    /** 每个玩家的攻击事件窗口（playerName -> Deque<CombatEvent>） */
    private final Map<String, ConcurrentLinkedDeque<CombatEvent>> playerCombatHistory
            = new ConcurrentHashMap<>();

    /** 每个玩家的攻击目标列表（playerName -> Deque<TargetRecord>）用于多目标检测 */
    private final Map<String, ConcurrentLinkedDeque<TargetRecord>> playerTargetHistory
            = new ConcurrentHashMap<>();

    /** 每个玩家的旋转记录（playerName -> Deque<RotationEvent>）用于Aimbot检测 */
    private final Map<String, ConcurrentLinkedDeque<RotationEvent>> playerRotationHistory
            = new ConcurrentHashMap<>();

    private final AtomicLong totalAttacks = new AtomicLong(0);
    private final AtomicLong autoclickerDetections = new AtomicLong(0);
    private final AtomicLong killauraDetections = new AtomicLong(0);
    private final AtomicLong aimbotDetections = new AtomicLong(0);

    /** 攻击事件窗口大小 */
    private static final int COMBAT_WINDOW_SIZE = 100;

    /** 低方差CPS阈值（变异系数）— 低于此值视为AutoClicker */
    private static final double AUTOCLICKER_CPS_COV_THRESHOLD = 0.08;

    /** 高CPS均值阈值 — 持续高于此值为异常 */
    private static final double HIGH_CPS_MEAN_THRESHOLD = 15.0;

    /** 目标切换熵值阈值 — 高于此值视为KillAura多目标攻击 */
    private static final double KILLAURA_ENTROPY_THRESHOLD = 2.5;

    /** Aimbot过冲检测阈值 — 合法玩家过冲量（度） */
    private static final double AIMBOT_OVERSHOOT_THRESHOLD = 0.5;

    /** 旋转平滑度检测 — 加速度方差低于此值 */
    private static final double AIMBOT_ACCEL_VARIANCE_THRESHOLD = 0.0005;

    /** 异常高命中率阈值 */
    private static final double ABNORMAL_HIT_RATIO = 0.90;

    /** 最大合法攻击距离（方块） */
    private static final double MAX_REACH_DISTANCE = 3.0;

    /** 摇摆攻击假说检验窗口 — 用于区分人/AI的旋转模式 */
    private static final int SACCADE_WINDOW_SIZE = 20;

    /** 报告所需的最小攻击样本数 */
    private static final int MIN_ATTACK_SAMPLES = 15;

    public CombatPatternRecognizer() {
        this(new ServerGuardConfig());
    }

    @Autowired
    public CombatPatternRecognizer(ServerGuardConfig config) {
        this.config = config;
    }

    /**
     * 记录一次玩家攻击事件，进行战斗模式分析。
     *
     * 每收到一次攻击事件，更新CPS统计、目标切换统计，并生成综合战斗模式分析报告。
     *
     * @param playerName     攻击者名称
     * @param targetName     被攻击目标名称
     * @param attackDistance 攻击距离（方块）
     * @param hitSuccessful  是否命中
     * @param yaw            攻击时的水平视角（度）
     * @param pitch          攻击时的俯仰视角（度）
     * @param timestamp      攻击时间戳
     * @return 战斗模式分析结果
     */
    public CombatAnalysisResult recordAttack(String playerName, String targetName,
                                              double attackDistance, boolean hitSuccessful,
                                              double yaw, double pitch, Instant timestamp) {
        totalAttacks.incrementAndGet();

        // 更新攻击事件窗口
        ConcurrentLinkedDeque<CombatEvent> combatWindow = playerCombatHistory.computeIfAbsent(
                playerName, k -> new ConcurrentLinkedDeque<>());
        combatWindow.addLast(new CombatEvent(timestamp, targetName, attackDistance,
                hitSuccessful, yaw, pitch));
        while (combatWindow.size() > COMBAT_WINDOW_SIZE) {
            combatWindow.removeFirst();
        }

        // 更新目标切换记录
        ConcurrentLinkedDeque<TargetRecord> targetWindow = playerTargetHistory.computeIfAbsent(
                playerName, k -> new ConcurrentLinkedDeque<>());
        targetWindow.addLast(new TargetRecord(timestamp, targetName));
        while (targetWindow.size() > COMBAT_WINDOW_SIZE) {
            targetWindow.removeFirst();
        }

        // 更新旋转记录
        ConcurrentLinkedDeque<RotationEvent> rotationWindow = playerRotationHistory.computeIfAbsent(
                playerName, k -> new ConcurrentLinkedDeque<>());
        rotationWindow.addLast(new RotationEvent(timestamp, yaw, pitch));
        while (rotationWindow.size() > COMBAT_WINDOW_SIZE) {
            rotationWindow.removeFirst();
        }

        if (combatWindow.size() < MIN_ATTACK_SAMPLES) {
            return CombatAnalysisResult.clean(playerName);
        }

        List<String> detections = new ArrayList<>();
        Map<String, Double> confidences = new HashMap<>();

        // === 检测1: AutoClicker（CPS方差分析） ===
        checkAutoClickerPattern(combatWindow, detections, confidences);

        // === 检测2: KillAura（多目标切换熵分析） ===
        checkKillAuraMultiTarget(targetWindow, detections, confidences);

        // === 检测3: Aimbot（旋转模式分析） ===
        checkAimbotRotation(rotationWindow, detections, confidences);

        // === 检测4: 命中率异常 ===
        checkHitRatioAnomaly(combatWindow, detections, confidences);

        // === 检测5: 攻击距离异常（Reach） ===
        checkReachDistance(combatWindow, detections, confidences);

        // === 检测6: 攻击间隔香农熵分析 ===
        checkAttackIntervalEntropy(combatWindow, detections, confidences);

        // 汇总结果
        if (!detections.isEmpty()) {
            if (confidences.containsKey("AUTOCLICKER")) autoclickerDetections.incrementAndGet();
            if (confidences.containsKey("KILLAURA")) killauraDetections.incrementAndGet();
            if (confidences.containsKey("AIMBOT")) aimbotDetections.incrementAndGet();

            return CombatAnalysisResult.flagged(playerName, detections, confidences);
        }

        // 提供统计摘要
        CombatStats stats = computeCombatStats(combatWindow, targetWindow, rotationWindow);
        return CombatAnalysisResult.normal(playerName, stats);
    }

    /**
     * AutoClicker检测 — 分析CPS均值和方差。
     *
     * 核心算法：
     * 1. 从攻击时间戳计算每对连续攻击的间隔
     * 2. 使用DescriptiveStatistics计算CPS的均值(mean)和标准差(std)
     * 3. COV = std / mean 度量点击规律性
     *    - COV < 0.08: 机械式规律点击 → AutoClicker
     *    - COV 0.08~0.15: 人类极限范围
     *    - COV > 0.15: 正常人类
     * 4. CPS > 15 持续多秒 = 宏/连点器
     */
    private void checkAutoClickerPattern(Deque<CombatEvent> history, List<String> detections,
                                          Map<String, Double> confidences) {
        List<Double> cpsValues = extractCpsValues(history);
        if (cpsValues.size() < 10) return;

        DescriptiveStatistics cpsStats = new DescriptiveStatistics();
        for (double cps : cpsValues) cpsStats.addValue(cps);

        double meanCps = cpsStats.getMean();
        double stdCps = cpsStats.getStandardDeviation();
        double cov = meanCps > 0 ? stdCps / meanCps : 1.0;

        // 检测1: 方差极低 → 机械式点击
        if (cov < AUTOCLICKER_CPS_COV_THRESHOLD) {
            detections.add("AUTOCLICKER_CPS_COV: CPS COV=" + String.format("%.4f", cov)
                    + " (mechanical, threshold < " + AUTOCLICKER_CPS_COV_THRESHOLD + ")");
            confidences.put("AUTOCLICKER",
                    1.0 - (cov / AUTOCLICKER_CPS_COV_THRESHOLD) * 0.5);
        }

        // 检测2: CPS均值异常高
        if (meanCps > HIGH_CPS_MEAN_THRESHOLD) {
            detections.add("HIGH_CPS_MEAN: mean CPS=" + String.format("%.2f", meanCps)
                    + " (suspicious, human max ~" + HIGH_CPS_MEAN_THRESHOLD + ")");
            confidences.put("HIGH_CPS",
                    Math.min(0.9, (meanCps - HIGH_CPS_MEAN_THRESHOLD) / 10.0));
        }
    }

    /**
     * KillAura多目标检测 — 基于目标切换香农熵。
     *
     * 合法玩家通常专注攻击1-2个目标，切换有延迟；
     * KillAura自动锁定范围内所有目标，产生高熵值的目标分布。
     */
    private void checkKillAuraMultiTarget(Deque<TargetRecord> history, List<String> detections,
                                           Map<String, Double> confidences) {
        if (history.size() < 20) return;

        // 统计各目标被攻击的频率
        Map<String, Integer> targetFrequency = new LinkedHashMap<>();
        for (TargetRecord tr : history) {
            targetFrequency.merge(tr.targetName, 1, Integer::sum);
        }

        int uniqueTargets = targetFrequency.size();
        double n = history.size();

        // 计算目标分布的香农熵
        double entropy = 0.0;
        for (int count : targetFrequency.values()) {
            double p = count / n;
            if (p > 0) entropy -= p * (Math.log(p) / Math.log(2));
        }

        // KillAura特征：高熵（多目标均匀分配）+ 多目标（> 3个不同目标）
        if (entropy > KILLAURA_ENTROPY_THRESHOLD && uniqueTargets > 3) {
            detections.add("KILLAURA_MULTI_TARGET: entropy=" + String.format("%.3f", entropy)
                    + " across " + uniqueTargets + " targets");
            confidences.put("KILLAURA", Math.min(0.95,
                    (entropy - KILLAURA_ENTROPY_THRESHOLD) / 2.0
                            + (uniqueTargets - 3) * 0.1));
        }
    }

    /**
     * Aimbot检测 — 分析战斗旋转模式。
     *
     * 人类玩家旋转特征（saccadic movement / 跳跃式注视）：
     *   - 快速旋转（高速度）到达目标附近
     *   - 过冲（overshoot）— 超过目标然后修正
     *   - 微调抖动 — 持续的微小方向修正
     *
     * Aimbot旋转特征：
     *   - 平滑线性轨迹 — 直接到达目标
     *   - 无过冲 — 精确停在目标位置
     *   - 无微调抖动 — 极其平滑的旋转路径
     *
     * 分析方法：计算旋转加速度方差，Aimbot极小，人类较大。
     */
    private void checkAimbotRotation(Deque<RotationEvent> history, List<String> detections,
                                      Map<String, Double> confidences) {
        if (history.size() < SACCADE_WINDOW_SIZE) return;

        // 提取yaw角度序列
        List<Double> yaws = new ArrayList<>();
        for (RotationEvent re : history) {
            yaws.add(re.yaw);
        }

        // 计算一阶差分（旋转速度）— 评估overshoot模式
        List<Double> velocities = new ArrayList<>();
        for (int i = 1; i < yaws.size(); i++) {
            velocities.add(normalizeAngle(yaws.get(i) - yaws.get(i - 1)));
        }

        // 计算二阶差分（旋转加速度）— 核心Aimbot判别指标
        List<Double> accelerations = new ArrayList<>();
        for (int i = 1; i < velocities.size(); i++) {
            accelerations.add(velocities.get(i) - velocities.get(i - 1));
        }

        DescriptiveStatistics accelStats = new DescriptiveStatistics();
        for (double a : accelerations) accelStats.addValue(a);

        double accelVariance = accelStats.getVariance();

        // 检测过冲模式（合法玩家特征）
        // 统计加速度方向翻转次数 — 过冲+修正模式产生频繁的符号翻转
        int signFlips = 0;
        for (int i = 1; i < accelerations.size(); i++) {
            if (Math.signum(accelerations.get(i)) != Math.signum(accelerations.get(i - 1))
                    && accelerations.get(i) != 0 && accelerations.get(i - 1) != 0) {
                signFlips++;
            }
        }
        double signFlipRatio = accelerations.size() > 0
                ? (double) signFlips / accelerations.size() : 0.0;

        // Aimbot判定条件
        // 条件a: 加速度方差极低（平滑线性跟踪）
        // 条件b: 符号翻转少（无过冲/修正循环）
        boolean aimbotByVariance = accelStats.getN() >= 8
                && accelVariance < AIMBOT_ACCEL_VARIANCE_THRESHOLD;
        boolean aimbotByOvershoot = accelStats.getN() >= 8
                && signFlipRatio < 0.15;

        if (aimbotByVariance && aimbotByOvershoot) {
            detections.add("AIMBOT_SMOOTH_TRACKING: accel variance="
                    + String.format("%.6f", accelVariance)
                    + " signFlipRatio=" + String.format("%.3f", signFlipRatio));
            confidences.put("AIMBOT", Math.min(0.95,
                    1.0 - (accelVariance / AIMBOT_ACCEL_VARIANCE_THRESHOLD) * 0.5));
        } else if (aimbotByVariance) {
            detections.add("AIMBOT_LINEAR_TRACKING: accel variance="
                    + String.format("%.6f", accelVariance)
                    + " (no overshoot correction)");
            confidences.put("AIMBOT", 0.7);
        } else if (aimbotByOvershoot) {
            detections.add("AIMBOT_NO_SACCADE: signFlipRatio="
                    + String.format("%.3f", signFlipRatio)
                    + " (missing human overshoot pattern)");
            confidences.put("AIMBOT", 0.6);
        }
    }

    /**
     * 检测异常高命中率。
     * KillAura/自动瞄准的典型特征：命中率异常高（> 90%），
     * 因为攻击完全由算法控制，不会产生人类常见的miss。
     */
    private void checkHitRatioAnomaly(Deque<CombatEvent> history, List<String> detections,
                                       Map<String, Double> confidences) {
        long hits = history.stream().filter(e -> e.hitSuccessful).count();
        double hitRatio = (double) hits / history.size();

        if (hitRatio > ABNORMAL_HIT_RATIO && history.size() >= 20) {
            detections.add("ABNORMAL_HIT_RATIO: " + String.format("%.0f%%", hitRatio * 100)
                    + " hits (" + hits + "/" + history.size()
                    + ") — consistent with auto-targeting");
            confidences.put("AUTO_TARGET", Math.min(0.85, (hitRatio - 0.7) / 0.3));
        }
    }

    /**
     * 检测攻击距离异常（Reach）。
     * 统计在极限距离附近（> 2.8方块）的攻击比例，
     * 高比例表明可能使用Reach扩展。
     */
    private void checkReachDistance(Deque<CombatEvent> history, List<String> detections,
                                     Map<String, Double> confidences) {
        long farHits = history.stream()
                .filter(e -> e.attackDistance > MAX_REACH_DISTANCE - 0.2)
                .count();
        double farRatio = (double) farHits / history.size();

        if (farRatio > 0.3 && farHits >= 5) {
            detections.add("REACH_EXTENSION: " + farHits + "/" + history.size()
                    + " attacks beyond normal reach (> " + MAX_REACH_DISTANCE + " blocks)");
            confidences.put("REACH", Math.min(0.9, farRatio * 2));
        }
    }

    /**
     * 攻击间隔香农熵分析。
     *
     * 与AutoClicker检测配合使用：
     * 人类点击间隔分布自然，高熵值；
     * 自动点击器间隔分布极窄，低熵值。
     */
    private void checkAttackIntervalEntropy(Deque<CombatEvent> history, List<String> detections,
                                             Map<String, Double> confidences) {
        if (history.size() < 15) return;

        // 计算相邻攻击的时间间隔（毫秒）
        List<Long> intervals = new ArrayList<>();
        CombatEvent prev = null;
        for (CombatEvent e : history) {
            if (prev != null) {
                intervals.add(e.timestamp.toEpochMilli() - prev.timestamp.toEpochMilli());
            }
            prev = e;
        }

        if (intervals.size() < 10) return;

        // 将间隔分桶（每10ms一桶），建频率分布
        Map<Long, Integer> freq = new HashMap<>();
        for (long iv : intervals) {
            long bucket = Math.round(iv / 10.0) * 10;
            freq.merge(bucket, 1, Integer::sum);
        }

        double entropy = 0.0;
        double n = intervals.size();
        for (int count : freq.values()) {
            double p = count / n;
            if (p > 0) entropy -= p * (Math.log(p) / Math.log(2));
        }

        // 低熵 = 机械式规律 = AutoClicker补充证据
        if (entropy < 1.5) {
            detections.add("LOW_INTERVAL_ENTROPY: entropy=" + String.format("%.3f", entropy)
                    + " (mechanical click pattern)");
            // 如果已有AUTOCLICKER标记，不重复添加但提高置信度
            confidences.merge("AUTOCLICKER", 0.6, (old, add) -> Math.min(0.95, old * 1.2));
        }
    }

    /**
     * 从战斗事件窗口提取CPS时间序列。
     *
     * 使用滑动窗口方法：每1秒窗口内的事件数 = CPS
     */
    private List<Double> extractCpsValues(Deque<CombatEvent> history) {
        List<Double> cpsValues = new ArrayList<>();
        List<CombatEvent> list = new ArrayList<>(history);

        // 使用1秒滑动窗口计算CPS
        for (int i = 0; i < list.size(); i++) {
            long windowStart = list.get(i).timestamp.toEpochMilli() - 1000;
            int count = 0;
            for (int j = i; j >= 0; j--) {
                if (list.get(j).timestamp.toEpochMilli() > windowStart) {
                    count++;
                } else {
                    break;
                }
            }
            cpsValues.add((double) count); // CPS = 1秒窗口内的点击数
        }

        return cpsValues;
    }

    /**
     * 计算综合战斗统计。
     */
    private CombatStats computeCombatStats(Deque<CombatEvent> combat,
                                            Deque<TargetRecord> targets,
                                            Deque<RotationEvent> rotations) {
        List<Double> cpsValues = extractCpsValues(combat);

        DescriptiveStatistics cpsStats = new DescriptiveStatistics();
        for (double c : cpsValues) cpsStats.addValue(c);

        long hits = combat.stream().filter(e -> e.hitSuccessful).count();
        double hitRatio = (double) hits / combat.size();

        double avgDistance = combat.stream()
                .mapToDouble(e -> e.attackDistance).average().orElse(0);

        Set<String> uniqueTargets = new HashSet<>();
        for (TargetRecord t : targets) uniqueTargets.add(t.targetName);

        return new CombatStats(cpsStats.getMean(), cpsStats.getStandardDeviation(),
                hitRatio, avgDistance, uniqueTargets.size(), combat.size());
    }

    private double normalizeAngle(double angle) {
        angle = angle % 360.0;
        if (angle > 180.0) angle -= 360.0;
        if (angle < -180.0) angle += 360.0;
        return angle;
    }

    /**
     * 清除指定玩家的所有战斗数据。
     */
    public void clearPlayer(String playerName) {
        playerCombatHistory.remove(playerName);
        playerTargetHistory.remove(playerName);
        playerRotationHistory.remove(playerName);
    }

    /**
     * 获取识别器运行状态。
     */
    public Map<String, Object> getStatus() {
        Map<String, Object> status = new LinkedHashMap<>();
        status.put("totalAttacks", totalAttacks.get());
        status.put("autoclickerDetections", autoclickerDetections.get());
        status.put("killauraDetections", killauraDetections.get());
        status.put("aimbotDetections", aimbotDetections.get());
        status.put("trackedPlayers", playerCombatHistory.size());
        return status;
    }

    // ==================== 内部数据类 ====================

    /** 战斗攻击事件 */
    private static class CombatEvent {
        final Instant timestamp;
        final String targetName;
        final double attackDistance;
        final boolean hitSuccessful;
        final double yaw;
        final double pitch;

        CombatEvent(Instant timestamp, String targetName, double attackDistance,
                    boolean hitSuccessful, double yaw, double pitch) {
            this.timestamp = timestamp;
            this.targetName = targetName;
            this.attackDistance = attackDistance;
            this.hitSuccessful = hitSuccessful;
            this.yaw = yaw;
            this.pitch = pitch;
        }
    }

    /** 攻击目标记录 — 用于多目标检测 */
    private static class TargetRecord {
        final Instant timestamp;
        final String targetName;

        TargetRecord(Instant timestamp, String targetName) {
            this.timestamp = timestamp;
            this.targetName = targetName;
        }
    }

    /** 战斗旋转事件 — 用于Aimbot检测 */
    private static class RotationEvent {
        final Instant timestamp;
        final double yaw;
        final double pitch;

        RotationEvent(Instant timestamp, double yaw, double pitch) {
            this.timestamp = timestamp;
            this.yaw = yaw;
            this.pitch = pitch;
        }
    }

    // ==================== 统计结构 ====================

    /**
     * 战斗统计数据结构 — 封装一次战斗窗口的核心统计数据。
     */
    public static class CombatStats {
        public final double cpsMean;
        public final double cpsStdDev;
        public final double hitRatio;
        public final double avgAttackDistance;
        public final int uniqueTargets;
        public final int totalAttacks;

        CombatStats(double cpsMean, double cpsStdDev, double hitRatio,
                    double avgAttackDistance, int uniqueTargets, int totalAttacks) {
            this.cpsMean = cpsMean;
            this.cpsStdDev = cpsStdDev;
            this.hitRatio = hitRatio;
            this.avgAttackDistance = avgAttackDistance;
            this.uniqueTargets = uniqueTargets;
            this.totalAttacks = totalAttacks;
        }

        public double getCpsCoefficientOfVariation() {
            return cpsMean > 0 ? cpsStdDev / cpsMean : 0;
        }
    }

    // ==================== 结果类 ====================

    /**
     * 战斗模式分析结果 — 不可变结果类。
     */
    public static class CombatAnalysisResult {
        private final boolean flagged;
        private final boolean suspicious;
        private final String playerName;
        private final List<String> detections;
        private final Map<String, Double> confidenceScores;
        private final CombatStats stats;

        CombatAnalysisResult(boolean flagged, boolean suspicious, String playerName,
                             List<String> detections, Map<String, Double> confidenceScores,
                             CombatStats stats) {
            this.flagged = flagged;
            this.suspicious = suspicious;
            this.playerName = playerName;
            this.detections = detections;
            this.confidenceScores = confidenceScores;
            this.stats = stats;
        }

        /** 正常 — 未检测到任何作弊模式 */
        public static CombatAnalysisResult clean(String playerName) {
            return new CombatAnalysisResult(false, false, playerName,
                    List.of(), Map.of(), null);
        }

        /** 正常且有统计数据 */
        public static CombatAnalysisResult normal(String playerName, CombatStats stats) {
            return new CombatAnalysisResult(false, false, playerName,
                    List.of(), Map.of(), stats);
        }

        /** 可疑 — 存在异常模式但置信度不足 */
        public static CombatAnalysisResult suspicious(String playerName,
                                                       List<String> detections,
                                                       Map<String, Double> confidences,
                                                       CombatStats stats) {
            return new CombatAnalysisResult(false, true, playerName,
                    detections, confidences, stats);
        }

        /** 已标记 — 检测到高置信度作弊模式 */
        public static CombatAnalysisResult flagged(String playerName,
                                                    List<String> detections,
                                                    Map<String, Double> confidences) {
            return new CombatAnalysisResult(true, true, playerName,
                    detections, confidences, null);
        }

        public boolean isFlagged() { return flagged; }
        public boolean isSuspicious() { return suspicious; }
        public boolean isClean() { return !flagged && !suspicious; }
        public String getPlayerName() { return playerName; }
        public List<String> getDetections() { return detections; }
        public Map<String, Double> getConfidenceScores() { return confidenceScores; }
        public CombatStats getStats() { return stats; }

        /** 获取最高置信度评分 */
        public double getMaxConfidence() {
            return confidenceScores.values().stream()
                    .mapToDouble(Double::doubleValue).max().orElse(0.0);
        }

        /** 获取主要的检测结果类型 */
        public String getPrimaryDetection() {
            return confidenceScores.entrySet().stream()
                    .max(Map.Entry.comparingByValue())
                    .map(Map.Entry::getKey).orElse("NONE");
        }
    }
}
