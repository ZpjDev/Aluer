package com.aluer.ml;

import com.aluer.config.ServerGuardConfig;
import com.aluer.model.AlertType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * 威胁分数聚合器 — 将各安全模块的告警信号汇总为统一的威胁评分
 *
 * 核心算法：
 * 1. 时间衰减加权聚合 — 最近告警权重高，历史告警按指数递减
 * 2. 指数衰减公式：weight = e^(-lambda * t)，lambda控制衰减速率
 * 3. 每个AlertType有基础严重度权重（severity weight），不同告警类型贡献不同
 * 4. 两项聚合维度：
 *    - 玩家维度：sum(alert_confidence * type_weight * time_decay)
 *    - IP维度：连接层威胁独立聚合
 * 5. 阈值升级机制：
 *    0-30  = MONITOR  （监控观察）
 *    31-60 = WARN     （警告通知）
 *    61-85 = ACTION   （主动防御）
 *    86-100= LOCKDOWN （最高警戒/锁定）
 * 6. 维护Top-N威胁实体排名
 * 7. 自动衰减陈旧条目并清理过期数据
 */
@Service
public class ThreatScoreAggregator {

    private static final Logger logger = LoggerFactory.getLogger(ThreatScoreAggregator.class);

    private final ServerGuardConfig config;

    /** 每个玩家的加权威胁条目列表（playerName -> List<WeightedAlert>） */
    private final Map<String, List<WeightedAlert>> playerAlertEntries = new ConcurrentHashMap<>();

    /** 每个IP的加权威胁条目列表（ip -> List<WeightedAlert>） */
    private final Map<String, List<WeightedAlert>> ipAlertEntries = new ConcurrentHashMap<>();

    /** 每个玩家当前聚合威胁分数缓存 */
    private final Map<String, Double> playerScores = new ConcurrentHashMap<>();

    /** 每个IP当前聚合威胁分数缓存 */
    private final Map<String, Double> ipScores = new ConcurrentHashMap<>();

    /** 每个玩家的威胁升级级别 */
    private final Map<String, ThreatLevel> playerLevels = new ConcurrentHashMap<>();

    /** 每个IP的威胁升级级别 */
    private final Map<String, ThreatLevel> ipLevels = new ConcurrentHashMap<>();

    private final AtomicLong totalAlertsProcessed = new AtomicLong(0);
    private final AtomicLong escalationsTriggered = new AtomicLong(0);

    /** 指数衰减系数 lambda — 控制衰减速率，值越大衰减越快 */
    private static final double DECAY_LAMBDA = 0.001;

    /** 自动清理间隔（毫秒） */
    private static final long CLEANUP_INTERVAL_MS = 5 * 60 * 1000L;

    /** 陈旧条目过期时间（毫秒）— 超过此时间无更新的条目被清理 */
    private static final long STALE_ENTRY_TTL_MS = 30 * 60 * 1000L;

    /** 默认Top-N 返回数量 */
    private static final int DEFAULT_TOP_N = 10;

    /** 用于分数平滑的EMA系数（指数移动平均） */
    private static final double EMA_ALPHA = 0.3;

    public ThreatScoreAggregator() {
        this(new ServerGuardConfig());
    }

    @Autowired
    public ThreatScoreAggregator(ServerGuardConfig config) {
        this.config = config;
    }

    /**
     * 添加一次安全告警，更新对应玩家/IP的威胁分数。
     *
     * 每次告警到达时：
     * 1. 计算告警的时间衰减加权值
     * 2. 累加入玩家和IP的告警条目列表
     * 3. 重新计算聚合分数
     * 4. 检查是否需要升级威胁级别
     *
     * @param playerName 关联玩家名称（可为null，如连接层威胁）
     * @param ipAddress  关联IP地址（可为null，如玩家行为威胁）
     * @param alertType  告警类型
     * @param confidence 告警置信度（0.0-1.0）
     * @param timestamp  告警时间戳
     */
    public void addAlert(String playerName, String ipAddress,
                         AlertType alertType, double confidence, Instant timestamp) {
        totalAlertsProcessed.incrementAndGet();

        // 获取告警类型的基础严重度权重
        double typeWeight = getAlertTypeWeight(alertType);

        // 初始时间衰减因子 = 1.0（刚产生的告警无衰减）
        double timeDecay = 1.0;
        double weightedScore = confidence * typeWeight * timeDecay;

        WeightedAlert entry = new WeightedAlert(alertType, confidence, typeWeight,
                weightedScore, timestamp);

        // 更新玩家维度
        if (playerName != null && !playerName.isEmpty()) {
            List<WeightedAlert> entries = playerAlertEntries.computeIfAbsent(
                    playerName, k -> Collections.synchronizedList(new ArrayList<>()));
            entries.add(entry);
            recalculatePlayerScore(playerName);
        }

        // 更新IP维度
        if (ipAddress != null && !ipAddress.isEmpty()) {
            List<WeightedAlert> entries = ipAlertEntries.computeIfAbsent(
                    ipAddress, k -> Collections.synchronizedList(new ArrayList<>()));
            entries.add(entry);
            recalculateIpScore(ipAddress);
        }
    }

    /**
     * 获取指定玩家当前的威胁分数（0-100）。
     * 在查询时自动应用时间衰减后返回最新分数。
     */
    public double getThreatScore(String playerName) {
        recalculatePlayerScore(playerName);
        return playerScores.getOrDefault(playerName, 0.0);
    }

    /**
     * 获取指定IP当前的威胁分数（0-100）。
     */
    public double getIpThreatScore(String ipAddress) {
        recalculateIpScore(ipAddress);
        return ipScores.getOrDefault(ipAddress, 0.0);
    }

    /**
     * 获取指定玩家的威胁升级级别。
     */
    public ThreatLevel getThreatLevel(String playerName) {
        return playerLevels.getOrDefault(playerName, ThreatLevel.MONITOR);
    }

    /**
     * 获取Top-N最具威胁的玩家实体。
     *
     * @param limit 返回数量上限
     * @return 按威胁分数降序排列的玩家名-分数列表
     */
    public List<Map.Entry<String, Double>> getTopThreats(int limit) {
        // 重新计算所有玩家分数（应用时间衰减）
        for (String player : playerAlertEntries.keySet()) {
            recalculatePlayerScore(player);
        }

        return playerScores.entrySet().stream()
                .sorted(Map.Entry.<String, Double>comparingByValue().reversed())
                .limit(Math.max(1, limit))
                .toList();
    }

    /**
     * 获取Top-N最具威胁的IP实体。
     */
    public List<Map.Entry<String, Double>> getTopIpThreats(int limit) {
        for (String ip : ipAlertEntries.keySet()) {
            recalculateIpScore(ip);
        }

        return ipScores.entrySet().stream()
                .sorted(Map.Entry.<String, Double>comparingByValue().reversed())
                .limit(Math.max(1, limit))
                .toList();
    }

    /**
     * 重新计算指定玩家的聚合威胁分数。
     *
     * 算法：
     * 1. 遍历该玩家所有历史告警条目
     * 2. 对每个条目应用指数时间衰减：weight = e^(-lambda * age_ms)
     * 3. 累加：score = sum(confidence * type_weight * time_decay)
     * 4. 通过EMA平滑避免分数突变
     * 5. 将原始分数映射到 0-100 区间
     * 6. 根据最终分数确定威胁级别
     */
    private void recalculatePlayerScore(String playerName) {
        List<WeightedAlert> entries = playerAlertEntries.get(playerName);
        if (entries == null || entries.isEmpty()) {
            playerScores.put(playerName, 0.0);
            playerLevels.put(playerName, ThreatLevel.MONITOR);
            return;
        }

        Instant now = Instant.now();
        synchronized (entries) {
            // 清除过期条目（超过TTL）
            entries.removeIf(e -> now.toEpochMilli() - e.timestamp.toEpochMilli()
                    > STALE_ENTRY_TTL_MS);

            if (entries.isEmpty()) {
                playerScores.put(playerName, 0.0);
                playerLevels.put(playerName, ThreatLevel.MONITOR);
                return;
            }

            double rawScore = 0.0;
            for (WeightedAlert entry : entries) {
                long ageMs = now.toEpochMilli() - entry.timestamp.toEpochMilli();
                double timeDecay = Math.exp(-DECAY_LAMBDA * ageMs);
                rawScore += entry.confidence * entry.typeWeight * timeDecay;
            }

            // 将原始累积分数映射到0-100（sigmoid-like归一化）
            double normalized = Math.min(100.0, 100.0 * Math.tanh(rawScore / 0.5));

            // EMA平滑处理
            double previousScore = playerScores.getOrDefault(playerName, normalized);
            double smoothedScore = EMA_ALPHA * normalized + (1 - EMA_ALPHA) * previousScore;

            playerScores.put(playerName, smoothedScore);

            // 确定威胁级别
            ThreatLevel newLevel = classifyThreatLevel(smoothedScore);
            ThreatLevel oldLevel = playerLevels.put(playerName, newLevel);

            // 检测升级
            if (oldLevel != null && newLevel.ordinal() > oldLevel.ordinal()
                    && newLevel.ordinal() >= ThreatLevel.WARN.ordinal()) {
                escalationsTriggered.incrementAndGet();
                logger.warn("Player {} threat escalated: {} -> {} (score: {})",
                        playerName, oldLevel, newLevel, String.format("%.1f", smoothedScore));
            }
        }
    }

    /**
     * 重新计算指定IP的聚合威胁分数。
     * 算法与玩家维度相同，独立统计。
     */
    private void recalculateIpScore(String ipAddress) {
        List<WeightedAlert> entries = ipAlertEntries.get(ipAddress);
        if (entries == null || entries.isEmpty()) {
            ipScores.put(ipAddress, 0.0);
            ipLevels.put(ipAddress, ThreatLevel.MONITOR);
            return;
        }

        Instant now = Instant.now();
        synchronized (entries) {
            entries.removeIf(e -> now.toEpochMilli() - e.timestamp.toEpochMilli()
                    > STALE_ENTRY_TTL_MS);

            if (entries.isEmpty()) {
                ipScores.put(ipAddress, 0.0);
                ipLevels.put(ipAddress, ThreatLevel.MONITOR);
                return;
            }

            double rawScore = 0.0;
            for (WeightedAlert entry : entries) {
                long ageMs = now.toEpochMilli() - entry.timestamp.toEpochMilli();
                double timeDecay = Math.exp(-DECAY_LAMBDA * ageMs);
                rawScore += entry.confidence * entry.typeWeight * timeDecay;
            }

            double normalized = Math.min(100.0, 100.0 * Math.tanh(rawScore / 0.5));
            double previousScore = ipScores.getOrDefault(ipAddress, normalized);
            double smoothedScore = EMA_ALPHA * normalized + (1 - EMA_ALPHA) * previousScore;

            ipScores.put(ipAddress, smoothedScore);

            ThreatLevel newLevel = classifyThreatLevel(smoothedScore);
            ThreatLevel oldLevel = ipLevels.put(ipAddress, newLevel);

            if (oldLevel != null && newLevel.ordinal() > oldLevel.ordinal()
                    && newLevel.ordinal() >= ThreatLevel.WARN.ordinal()) {
                escalationsTriggered.incrementAndGet();
                logger.warn("IP {} threat escalated: {} -> {} (score: {})",
                        ipAddress, oldLevel, newLevel, String.format("%.1f", smoothedScore));
            }
        }
    }

    /**
     * 根据威胁分数确定威胁级别。
     * 阈值分界：
     *   0-30  = MONITOR   监控观察，无需干预
     *  31-60 = WARN      警告级别，需关注
     *  61-85 = ACTION    主动防御，触发自动化响应
     *  86-100= LOCKDOWN  最高警戒，全面封锁
     */
    private ThreatLevel classifyThreatLevel(double score) {
        if (score >= 86.0) return ThreatLevel.LOCKDOWN;
        if (score >= 61.0) return ThreatLevel.ACTION;
        if (score >= 31.0) return ThreatLevel.WARN;
        return ThreatLevel.MONITOR;
    }

    /**
     * 获取AlertType对应的基础严重度权重。
     *
     * 不同类别的告警类型具有不同的基础权重：
     * - MOJANG API级别的反作弊类（KillAura等）：权重 1.0
     * - 行为异常检测类：权重 0.8
     * - 聊天/社交类：权重 0.5
     * - 系统监控类：权重 0.3
     */
    private double getAlertTypeWeight(AlertType alertType) {
        if (alertType == null) return 0.5;

        String name = alertType.name();

        // AI/ML检测类 — 高权重
        if (name.startsWith("ML_")) return 0.9;

        // 反作弊核心模块 — 最高权重
        if (name.startsWith("SECURITY_")) {
            // 战斗类作弊权重最高
            if (name.contains("KILL_AURA") || name.contains("REACH")
                    || name.contains("SPEED") || name.contains("TIMER")) {
                return 1.0;
            }
            // 其他反作弊权重中等偏高
            if (name.contains("AUTO_CLICKER") || name.contains("NUKER")
                    || name.contains("SCAFFOLD") || name.contains("FLY")) {
                return 0.9;
            }
            // 服务器保护类
            if (name.contains("SIGN") || name.contains("BOOK")
                    || name.contains("DDOS") || name.contains("BRUTE")) {
                return 0.8;
            }
            // 访问控制/其他
            return 0.7;
        }

        // 聊天与社交类 — 中等权重
        if (name.startsWith("CHAT_") || name.startsWith("COMMAND_")) {
            return 0.5;
        }

        // AI/系统监控类 — 较低权重（辅助参考）
        if (name.startsWith("AI_") || name.contains("ANOMALY")) {
            return 0.6;
        }

        return 0.5; // 默认中等权重
    }

    /**
     * 清除指定玩家的所有历史告警数据。
     */
    public void clearPlayer(String playerName) {
        playerAlertEntries.remove(playerName);
        playerScores.remove(playerName);
        playerLevels.remove(playerName);
    }

    /**
     * 清除指定IP的所有历史告警数据。
     */
    public void clearIp(String ipAddress) {
        ipAlertEntries.remove(ipAddress);
        ipScores.remove(ipAddress);
        ipLevels.remove(ipAddress);
    }

    /**
     * 获取聚合器运行状态统计。
     */
    public Map<String, Object> getStatus() {
        Map<String, Object> status = new LinkedHashMap<>();
        status.put("totalAlerts", totalAlertsProcessed.get());
        status.put("escalations", escalationsTriggered.get());
        status.put("trackedPlayers", playerAlertEntries.size());
        status.put("trackedIps", ipAlertEntries.size());

        // 威胁级别分布
        Map<ThreatLevel, Long> levelDistribution = new EnumMap<>(ThreatLevel.class);
        for (ThreatLevel level : playerLevels.values()) {
            levelDistribution.merge(level, 1L, Long::sum);
        }
        status.put("playerLevelDistribution", levelDistribution);

        // Top-5 威胁玩家
        List<Map.Entry<String, Double>> topThreats = getTopThreats(5);
        status.put("topThreats", topThreats.stream()
                .map(e -> Map.of("name", e.getKey(), "score",
                        String.format("%.1f", e.getValue())))
                .toList());

        return status;
    }

    // ==================== 内部数据类 ====================

    /**
     * 加权告警条目 — 记录单次告警的分量计算信息。
     */
    private static class WeightedAlert {
        final AlertType alertType;
        final double confidence;
        final double typeWeight;
        final double weightedScore;
        final Instant timestamp;

        WeightedAlert(AlertType alertType, double confidence, double typeWeight,
                      double weightedScore, Instant timestamp) {
            this.alertType = alertType;
            this.confidence = confidence;
            this.typeWeight = typeWeight;
            this.weightedScore = weightedScore;
            this.timestamp = timestamp;
        }
    }

    // ==================== 枚举与结果类 ====================

    /**
     * 威胁升级级别枚举。
     */
    public enum ThreatLevel {
        /** 监控观察 — 分数 0-30，无需干预 */
        MONITOR,
        /** 警告通知 — 分数 31-60，需人工关注 */
        WARN,
        /** 主动防御 — 分数 61-85，触发自动化响应 */
        ACTION,
        /** 最高警戒 — 分数 86-100，全面封锁 */
        LOCKDOWN
    }

    /**
     * 威胁聚合结果 — 不可变结果类。
     */
    public static class ThreatAggregateResult {
        private final double score;
        private final ThreatLevel level;
        private final int alertCount;
        private final double averageConfidence;
        private final String topAlertType;

        ThreatAggregateResult(double score, ThreatLevel level, int alertCount,
                              double averageConfidence, String topAlertType) {
            this.score = score;
            this.level = level;
            this.alertCount = alertCount;
            this.averageConfidence = averageConfidence;
            this.topAlertType = topAlertType;
        }

        /** 创建聚合结果 */
        public static ThreatAggregateResult of(double score, ThreatLevel level,
                                                int alertCount, double averageConfidence,
                                                String topAlertType) {
            return new ThreatAggregateResult(score, level, alertCount,
                    averageConfidence, topAlertType);
        }

        public double getScore() { return score; }
        public ThreatLevel getLevel() { return level; }
        public int getAlertCount() { return alertCount; }
        public double getAverageConfidence() { return averageConfidence; }
        public String getTopAlertType() { return topAlertType; }

        /** 是否需要立即干预 */
        public boolean requiresImmediateAction() {
            return level == ThreatLevel.ACTION || level == ThreatLevel.LOCKDOWN;
        }

        @Override
        public String toString() {
            return String.format("ThreatResult[score=%.1f, level=%s, alerts=%d, avgConf=%.2f]",
                    score, level, alertCount, averageConfidence);
        }
    }
}
