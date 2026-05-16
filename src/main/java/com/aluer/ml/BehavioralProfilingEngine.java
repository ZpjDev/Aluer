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

/**
 * 玩家行为画像引擎 — 基于统计分析的玩家行为模式识别
 *
 * 核心算法：
 * 1. 对每个在线玩家维护5维行为特征向量（移动熵、战斗率、资源采集率、社交率、探索率）
 * 2. 使用滑动窗口（~200事件）计算每个特征的统计分布
 * 3. 将玩家特征与全服基线进行Z-score比较，计算复合异常分数（0-100）
 * 4. 将玩家行为分类为六种画像：NORMAL / GRINDER / EXPLORER / PVPER / SUSPICIOUS / BOT_LIKE
 * 5. 追踪画像转换序列 — NORMAL→SUSPICIOUS 是高风险信号
 * 6. 30分钟无活动自动清除玩家画像数据
 *
 * 数学基础：
 * - 香农熵：H(X) = -Sum(p_i * log2(p_i)) 用于度量移动方向随机性
 * - Z-score: z = (x - mu_pop) / sigma_pop 衡量玩家偏离全服均值的标准差倍数
 * - 复合异常分数：加权各维度的Z-score绝对值，映射到0-100区间
 *
 * 依赖：Apache Commons Math3 — DescriptiveStatistics（统计描述）、TTest（假设检验）
 */
@Service
public class BehavioralProfilingEngine {

    private static final Logger logger = LoggerFactory.getLogger(BehavioralProfilingEngine.class);

    private final ServerGuardConfig config;

    /** 每个玩家的行为事件滑动窗口（playerName -> Deque<BehaviorEvent>） */
    private final Map<String, ConcurrentLinkedDeque<BehaviorEvent>> playerEventWindows = new ConcurrentHashMap<>();

    /** 每个玩家的当前画像（playerName -> 画像枚举） */
    private final Map<String, PlayerProfile> playerProfiles = new ConcurrentHashMap<>();

    /** 每个玩家最近一次画像及转换时间（playerName -> ProfileTransition） */
    private final Map<String, List<ProfileTransition>> profileTransitions = new ConcurrentHashMap<>();

    /** 全服各维度的基线统计量 — 使用 DescriptiveStatistics 增量维护 */
    private final Map<String, DescriptiveStatistics> populationBaselines = new ConcurrentHashMap<>();

    private final AtomicLong totalEventsProcessed = new AtomicLong(0);
    private final AtomicLong anomalyFlags = new AtomicLong(0);

    /** 滑动窗口最大事件数 */
    private static final int MAX_WINDOW_SIZE = 200;

    /** 画像计算所需最小样本数 */
    private static final int MIN_SAMPLES_FOR_PROFILE = 30;

    /** 非活跃玩家清理超时（毫秒） */
    private static final long INACTIVITY_CLEANUP_MS = 30 * 60 * 1000L;

    /** 异常Z-score阈值 — 超过此值认为该维度显著偏离 */
    private static final double ANOMALY_Z_THRESHOLD = 2.5;

    /** 各维度的异常分数权重（总和为1.0，可根据业务调整） */
    private static final double[] FEATURE_WEIGHTS = {0.25, 0.20, 0.15, 0.15, 0.25};

    /** 画像转换风险权重乘数 — NORMAL→SUSPICIOUS 方向性加分 */
    private static final double TRANSITION_RISK_MULTIPLIER = 1.5;

    public BehavioralProfilingEngine() {
        this(new ServerGuardConfig());
    }

    @Autowired
    public BehavioralProfilingEngine(ServerGuardConfig config) {
        this.config = config;
        // 初始化全服基线统计容器
        for (String feature : FeatureDimension.FEATURE_NAMES) {
            populationBaselines.put(feature, new DescriptiveStatistics());
        }
    }

    /**
     * 记录一次玩家行为事件，更新玩家特征向量并触发画像评估。
     *
     * 调用时机：每次玩家产生可观测行为（移动、攻击、挖掘、发言、探索新区块）时调用。
     *
     * @param playerName 玩家名称
     * @param eventType  事件类型（MOVE / ATTACK / BREAK_BLOCK / CHAT / EXPLORE）
     * @param eventValue 事件关联数值（如移动距离、攻击次数等）
     * @param timestamp  事件时间戳
     * @return 画像评估结果
     */
    public ProfilingResult recordEvent(String playerName, String eventType,
                                       double eventValue, Instant timestamp) {
        totalEventsProcessed.incrementAndGet();

        // 获取或创建玩家事件窗口
        ConcurrentLinkedDeque<BehaviorEvent> window = playerEventWindows.computeIfAbsent(
                playerName, k -> new ConcurrentLinkedDeque<>());

        // 添加新事件并维护窗口大小
        window.addLast(new BehaviorEvent(timestamp, eventType, eventValue));
        while (window.size() > MAX_WINDOW_SIZE) {
            window.removeFirst();
        }

        // 样本不足时返回正常（避免小样本误判）
        if (window.size() < MIN_SAMPLES_FOR_PROFILE) {
            return ProfilingResult.clean(playerName, PlayerProfile.NORMAL, 0.0);
        }

        // 从滑动窗口中提取5维特征向量
        double[] features = extractFeatureVector(window, timestamp);

        // 将当前特征向量加入全服基线
        updatePopulationBaselines(features);

        // 计算各维度Z-score
        double[] zScores = calculateZScores(features);

        // 计算加权复合异常分数（0-100）
        double anomalyScore = computeCompositeAnomalyScore(zScores);

        // 基于特征向量确定玩家画像
        PlayerProfile newProfile = classifyProfile(features, anomalyScore);

        // 追踪画像转换并检测异常转换
        PlayerProfile previousProfile = playerProfiles.get(playerName);
        playerProfiles.put(playerName, newProfile);

        boolean isSuspiciousTransition = false;
        List<String> flags = new ArrayList<>();

        if (previousProfile != null && previousProfile != newProfile) {
            // 记录画像转换
            List<ProfileTransition> transitions = profileTransitions.computeIfAbsent(
                    playerName, k -> new ArrayList<>());
            transitions.add(new ProfileTransition(previousProfile, newProfile, timestamp));

            // 保留最近20次转换记录
            while (transitions.size() > 20) {
                transitions.remove(0);
            }

            // 检测高风险转换：NORMAL/GRINDER → SUSPICIOUS/BOT_LIKE
            if (isRiskyTransition(previousProfile, newProfile)) {
                isSuspiciousTransition = true;
                anomalyScore = Math.min(100.0, anomalyScore * TRANSITION_RISK_MULTIPLIER);
                flags.add("RISKY_TRANSITION: " + previousProfile + " -> " + newProfile);
            }
        }

        // 检查各维度是否超过异常阈值
        for (int i = 0; i < zScores.length; i++) {
            if (Math.abs(zScores[i]) > ANOMALY_Z_THRESHOLD) {
                flags.add("FEATURE_ANOMALY[" + FeatureDimension.FEATURE_NAMES[i]
                        + "]: z-score=" + String.format("%.2f", zScores[i]));
            }
        }

        if (anomalyScore > 60.0 || isSuspiciousTransition || !flags.isEmpty()) {
            anomalyFlags.incrementAndGet();
            return ProfilingResult.flagged(playerName, newProfile, anomalyScore, flags);
        }

        if (anomalyScore > 30.0) {
            return ProfilingResult.suspicious(playerName, newProfile, anomalyScore, flags);
        }

        return ProfilingResult.clean(playerName, newProfile, anomalyScore);
    }

    /**
     * 从玩家事件滑动窗口提取5维特征向量。
     *
     * 特征维度：
     * [0] 移动熵 — 方向变化的香农熵（正常玩家方向多变，bot方向高度一致）
     * [1] 战斗参与率 — 每秒攻击次数（PVPer高，普通玩家低）
     * [2] 资源采集率 — 每秒方块破坏数（矿工/挂机脚本高）
     * [3] 社交交互率 — 每秒聊天消息数
     * [4] 探索率 — 每分钟新探索区块数
     */
    private double[] extractFeatureVector(Deque<BehaviorEvent> window, Instant now) {
        double moveCount = 0, attackCount = 0, breakCount = 0, chatCount = 0, exploreCount = 0;
        List<Double> moveDeltas = new ArrayList<>();

        Instant oldest = window.isEmpty() ? now : window.peekFirst().timestamp;
        double durationMinutes = Math.max(1.0 / 60.0,
                (now.toEpochMilli() - oldest.toEpochMilli()) / 60000.0);

        for (BehaviorEvent e : window) {
            switch (e.eventType) {
                case "MOVE":
                    moveCount++;
                    moveDeltas.add(e.eventValue);
                    break;
                case "ATTACK":
                    attackCount++;
                    break;
                case "BREAK_BLOCK":
                    breakCount++;
                    break;
                case "CHAT":
                    chatCount++;
                    break;
                case "EXPLORE":
                    exploreCount++;
                    break;
            }
        }

        // [0] 移动熵 — 方向变化的信息熵
        double movementEntropy = calculateDirectionEntropy(moveDeltas);

        // [1] 战斗参与率 = 攻击次数 / 分钟
        double combatRate = attackCount / durationMinutes;

        // [2] 资源采集率 = 方块破坏数 / 分钟
        double gatheringRate = breakCount / durationMinutes;

        // [3] 社交交互率 = 聊天消息数 / 分钟
        double socialRate = chatCount / durationMinutes;

        // [4] 探索率 = 新区块探索数 / 分钟
        double explorationRate = exploreCount / durationMinutes;

        return new double[]{movementEntropy, combatRate, gatheringRate, socialRate, explorationRate};
    }

    /**
     * 计算移动方向变量的香农熵。
     * 将方向值离散化到12个桶（每30度一个桶），计算频率分布的熵。
     * 高熵 = 方向随机多变 = 人类玩家；低熵 = 方向单一 = bot/脚本。
     */
    private double calculateDirectionEntropy(List<Double> deltas) {
        if (deltas.size() < 10) return 0.0;

        int[] buckets = new int[12]; // 360度 / 30度 = 12个方向桶
        for (double d : deltas) {
            int idx = ((int) (Math.abs(d) % 360.0) / 30) % 12;
            buckets[idx]++;
        }

        double entropy = 0.0;
        double n = deltas.size();
        for (int count : buckets) {
            if (count > 0) {
                double p = count / n;
                entropy -= p * (Math.log(p) / Math.log(2));
            }
        }
        return entropy;
    }

    /**
     * 将当前特征向量更新至全服基线DescriptiveStatistics。
     * DescriptiveStatistics 自动维护均值、方差、百分位数等统计量。
     */
    private void updatePopulationBaselines(double[] features) {
        for (int i = 0; i < features.length; i++) {
            DescriptiveStatistics stats = populationBaselines.get(
                    FeatureDimension.FEATURE_NAMES[i]);
            if (stats != null && !Double.isNaN(features[i]) && !Double.isInfinite(features[i])) {
                stats.addValue(features[i]);
            }
        }
    }

    /**
     * 计算各特征维度的Z-score（标准分数）。
     * Z = (x - mu_population) / sigma_population
     * 如果总体标准差为0（所有玩家值相同），Z-score设为0。
     */
    private double[] calculateZScores(double[] features) {
        double[] zScores = new double[features.length];
        for (int i = 0; i < features.length; i++) {
            DescriptiveStatistics stats = populationBaselines.get(
                    FeatureDimension.FEATURE_NAMES[i]);
            if (stats != null && stats.getN() >= MIN_SAMPLES_FOR_PROFILE) {
                double mu = stats.getMean();
                double sigma = stats.getStandardDeviation();
                zScores[i] = (sigma > 1e-10) ? (features[i] - mu) / sigma : 0.0;
            } else {
                zScores[i] = 0.0;
            }
        }
        return zScores;
    }

    /**
     * 计算加权复合异常分数（0-100）。
     * 将各维度Z-score的绝对值加权求和，再通过sigmoid-like函数映射到0-100区间。
     */
    private double computeCompositeAnomalyScore(double[] zScores) {
        double weightedSum = 0.0;
        for (int i = 0; i < zScores.length; i++) {
            weightedSum += Math.abs(zScores[i]) * FEATURE_WEIGHTS[i];
        }
        // 使用双曲正切映射到0-100：score = 100 * tanh(weightedSum / 2)
        // tanh(0) = 0, tanh(1.5) ≈ 0.9, tanh(3) ≈ 0.995
        return Math.min(100.0, 100.0 * Math.tanh(weightedSum / 2.0));
    }

    /**
     * 基于特征向量和异常分数对玩家画像进行分类。
     *
     * 分类规则（启发式阈值）：
     * - BOT_LIKE: 移动熵极低（< 0.5）且资源采集率极高（> 30/min）
     * - SUSPICIOUS: 异常分数 > 50
     * - PVPER: 战斗参与率 > 5/min
     * - GRINDER: 资源采集率 > 20/min 或 探索率 > 15/min
     * - EXPLORER: 探索率 > 10/min
     * - NORMAL: 以上均不满足
     */
    private PlayerProfile classifyProfile(double[] features, double anomalyScore) {
        double movementEntropy = features[0];
        double combatRate = features[1];
        double gatheringRate = features[2];
        double socialRate = features[3];
        double explorationRate = features[4];

        // Bot特征：移动高度规律 + 高采集频率
        if (movementEntropy < 0.5 && gatheringRate > 30.0) {
            return PlayerProfile.BOT_LIKE;
        }

        // 显著异常
        if (anomalyScore > 50.0) {
            return PlayerProfile.SUSPICIOUS;
        }

        // 高战斗率 = PVP玩家
        if (combatRate > 5.0) {
            return PlayerProfile.PVPER;
        }

        // 高采集率 = 刷资源型
        if (gatheringRate > 20.0) {
            return PlayerProfile.GRINDER;
        }

        // 高探索率 = 探险型
        if (explorationRate > 10.0) {
            return PlayerProfile.EXPLORER;
        }

        return PlayerProfile.NORMAL;
    }

    /**
     * 判断画像转换是否为高风险转换。
     * 从无害画像(NORMAL/GRINDER/EXPLORER)跳转到可疑画像(SUSPICIOUS/BOT_LIKE)视为危险信号。
     */
    private boolean isRiskyTransition(PlayerProfile from, PlayerProfile to) {
        Set<PlayerProfile> benignSet = EnumSet.of(PlayerProfile.NORMAL,
                PlayerProfile.GRINDER, PlayerProfile.EXPLORER, PlayerProfile.PVPER);
        Set<PlayerProfile> maliciousSet = EnumSet.of(PlayerProfile.SUSPICIOUS,
                PlayerProfile.BOT_LIKE);

        return benignSet.contains(from) && maliciousSet.contains(to);
    }

    /**
     * 清理超过30分钟无活动的玩家数据，释放内存。
     */
    public void cleanupInactiveProfiles() {
        Instant cutoff = Instant.now().minusMillis(INACTIVITY_CLEANUP_MS);

        Iterator<Map.Entry<String, ConcurrentLinkedDeque<BehaviorEvent>>> it =
                playerEventWindows.entrySet().iterator();
        while (it.hasNext()) {
            Map.Entry<String, ConcurrentLinkedDeque<BehaviorEvent>> entry = it.next();
            ConcurrentLinkedDeque<BehaviorEvent> window = entry.getValue();
            if (window.isEmpty() || window.peekLast().timestamp.isBefore(cutoff)) {
                it.remove();
                playerProfiles.remove(entry.getKey());
                profileTransitions.remove(entry.getKey());
            }
        }
    }

    /**
     * 获取指定玩家的当前画像。
     */
    public PlayerProfile getPlayerProfile(String playerName) {
        return playerProfiles.getOrDefault(playerName, PlayerProfile.NORMAL);
    }

    /**
     * 获取指定玩家的行为特征向量快照。
     */
    public double[] getPlayerFeatureVector(String playerName) {
        ConcurrentLinkedDeque<BehaviorEvent> window = playerEventWindows.get(playerName);
        if (window == null || window.isEmpty()) {
            return new double[]{0, 0, 0, 0, 0};
        }
        return extractFeatureVector(window, Instant.now());
    }

    /**
     * 获取指定玩家的画像转换历史。
     */
    public List<ProfileTransition> getTransitionHistory(String playerName) {
        return profileTransitions.getOrDefault(playerName, Collections.emptyList());
    }

    /**
     * 清除指定玩家的所有数据。
     */
    public void clearPlayer(String playerName) {
        playerEventWindows.remove(playerName);
        playerProfiles.remove(playerName);
        profileTransitions.remove(playerName);
    }

    /**
     * 获取引擎运行状态统计。
     */
    public Map<String, Object> getStatus() {
        Map<String, Object> status = new LinkedHashMap<>();
        status.put("totalEvents", totalEventsProcessed.get());
        status.put("anomalyFlags", anomalyFlags.get());
        status.put("activePlayers", playerEventWindows.size());
        status.put("populationSampleSize",
                populationBaselines.values().iterator().next().getN());
        // 各画像玩家分布
        Map<PlayerProfile, Long> profileDistribution = new EnumMap<>(PlayerProfile.class);
        for (PlayerProfile p : playerProfiles.values()) {
            profileDistribution.merge(p, 1L, Long::sum);
        }
        status.put("profileDistribution", profileDistribution);
        return status;
    }

    // ==================== 内部数据类 ====================

    /**
     * 行为事件记录 — 包含时间戳、事件类型和关联数值。
     */
    private static class BehaviorEvent {
        final Instant timestamp;
        final String eventType;
        final double eventValue;

        BehaviorEvent(Instant timestamp, String eventType, double eventValue) {
            this.timestamp = timestamp;
            this.eventType = eventType;
            this.eventValue = eventValue;
        }
    }

    /**
     * 特征维度常量定义。
     */
    private static final class FeatureDimension {
        static final String[] FEATURE_NAMES = {
                "MOVEMENT_ENTROPY", "COMBAT_RATE", "GATHERING_RATE",
                "SOCIAL_RATE", "EXPLORATION_RATE"
        };
    }

    /**
     * 画像转换记录 — 记录从哪个画像切换到哪个画像及时间。
     */
    public static class ProfileTransition {
        public final PlayerProfile from;
        public final PlayerProfile to;
        public final Instant timestamp;

        ProfileTransition(PlayerProfile from, PlayerProfile to, Instant timestamp) {
            this.from = from;
            this.to = to;
            this.timestamp = timestamp;
        }

        @Override
        public String toString() {
            return from + " -> " + to + " @ " + timestamp;
        }
    }

    // ==================== 枚举与结果类 ====================

    /**
     * 玩家行为画像枚举。
     */
    public enum PlayerProfile {
        NORMAL,     // 正常玩家 — 无异常行为模式
        GRINDER,    // 刷资源型 — 高频率采集/挖掘
        EXPLORER,   // 探险型 — 高频率新区块探索
        PVPER,      // PVP型 — 高频率战斗参与
        SUSPICIOUS, // 可疑 — 多维度偏离基线
        BOT_LIKE    // Bot特征 — 移动极度规律 + 自动化采集
    }

    /**
     * 行为画像评估结果 — 不可变结果类。
     */
    public static class ProfilingResult {
        private final boolean flagged;
        private final boolean suspicious;
        private final String playerName;
        private final PlayerProfile profile;
        private final double anomalyScore;
        private final List<String> flags;

        private ProfilingResult(boolean flagged, boolean suspicious, String playerName,
                                PlayerProfile profile, double anomalyScore, List<String> flags) {
            this.flagged = flagged;
            this.suspicious = suspicious;
            this.playerName = playerName;
            this.profile = profile;
            this.anomalyScore = anomalyScore;
            this.flags = flags;
        }

        /** 正常 — 无任何异常信号 */
        public static ProfilingResult clean(String playerName, PlayerProfile profile,
                                             double anomalyScore) {
            return new ProfilingResult(false, false, playerName, profile,
                    anomalyScore, List.of());
        }

        /** 可疑 — 存在异常信号但未达到标记阈值 */
        public static ProfilingResult suspicious(String playerName, PlayerProfile profile,
                                                  double anomalyScore, List<String> flags) {
            return new ProfilingResult(false, true, playerName, profile,
                    anomalyScore, flags);
        }

        /** 已标记 — 检测到显著异常行为 */
        public static ProfilingResult flagged(String playerName, PlayerProfile profile,
                                               double anomalyScore, List<String> flags) {
            return new ProfilingResult(true, true, playerName, profile,
                    anomalyScore, flags);
        }

        public boolean isFlagged() { return flagged; }
        public boolean isSuspicious() { return suspicious; }
        public boolean isClean() { return !flagged && !suspicious; }
        public String getPlayerName() { return playerName; }
        public PlayerProfile getProfile() { return profile; }
        public double getAnomalyScore() { return anomalyScore; }
        public List<String> getFlags() { return flags; }
    }
}
