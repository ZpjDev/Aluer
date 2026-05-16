package com.aluer.ml;

import com.aluer.config.ServerGuardConfig;
import org.apache.commons.math3.stat.descriptive.DescriptiveStatistics;
import org.apache.commons.math3.stat.inference.TTest;
import org.apache.commons.math3.complex.Complex;
import org.apache.commons.math3.transform.DftNormalization;
import org.apache.commons.math3.transform.FastFourierTransformer;
import org.apache.commons.math3.transform.TransformType;
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
 * 移动模式分析器 — 基于深度移动向量分析检测作弊行为
 *
 * 检测原理：
 * 1. 移动向量追踪 — 每tick记录(dx, dy, dz)偏移，构建移动轨迹时间序列
 * 2. 速度统计 — 均值、方差分析。合法玩家速度方差高（走走停停），加速作弊方差极低（恒定速度）
 * 3. 方向变化频率 — Bot自动移动呈直线（低频方向变化），人类玩家频繁微调方向
 * 4. 跳跃模式 — 自动跳跃与人工跳跃的时机分布差异（人工跳跃在间隔上有自然抖动）
 * 5. 视角平滑度 — 分析旋转增量(yaw/pitch delta)的分布。
 *    Aimbot产生反常平滑（低方差），人类有微抖动（高方差+高频噪声）
 * 6. FFT频域分析 — 将速度时间序列转换到频域，检测周期性速度模式
 *    Timer hack表现为特定频率的恒定速度峰值
 * 7. 特定作弊模式识别：
 *    - Timer Hack: 恒定速度 + 低方差 + 特定频谱峰值
 *    - SnapAim/Aimbot: 完美45/90度转角 + 无旋转抖动
 *    - Macro/Script: 重复相同的移动序列向量
 *
 * 数学工具：Apache Commons Math3 — DescriptiveStatistics（统计）、TTest（假设检验）、
 * FastFourierTransformer（频域分析）
 */
@Service
public class MovementPatternAnalyzer {

    private static final Logger logger = LoggerFactory.getLogger(MovementPatternAnalyzer.class);

    private final ServerGuardConfig config;

    /** 每个玩家的移动向量滑动窗口（playerName -> Deque<MovementSample>） */
    private final Map<String, ConcurrentLinkedDeque<MovementSample>> playerMovementHistory
            = new ConcurrentHashMap<>();

    /** 每个玩家的视角旋转历史（playerName -> Deque<RotationSample>） */
    private final Map<String, ConcurrentLinkedDeque<RotationSample>> playerRotationHistory
            = new ConcurrentHashMap<>();

    /** 每个玩家的跳跃时间戳历史（playerName -> Deque<JumpRecord>） */
    private final Map<String, ConcurrentLinkedDeque<JumpRecord>> playerJumpHistory
            = new ConcurrentHashMap<>();

    private final AtomicLong totalSamples = new AtomicLong(0);
    private final AtomicLong hackDetections = new AtomicLong(0);

    /** 移动向量窗口大小（tick数） */
    private static final int MOVEMENT_WINDOW_SIZE = 100;

    /** 视角窗口大小 */
    private static final int ROTATION_WINDOW_SIZE = 60;

    /** 跳跃记录窗口大小 */
    private static final int JUMP_WINDOW_SIZE = 40;

    /** 速度方差阈值 — 低于此值视为恒定速度（疑似Timer Hack） */
    private static final double CONSTANT_SPEED_VARIANCE_THRESHOLD = 0.0005;

    /** 方向变化频率阈值 — 低于此值视为Bot直线移动 */
    private static final double DIRECTION_CHANGE_FREQ_THRESHOLD = 0.05;

    /** Aimbot视角平滑度阈值 — 旋转加速度方差低于此值视为自动瞄准 */
    private static final double AIMBOT_SMOOTHNESS_THRESHOLD = 0.001;

    /** 完美角度容忍度（度）— 转角在此范围内视为完美45/90度 */
    private static final double PERFECT_ANGLE_TOLERANCE = 1.5;

    /** 跳跃间隔变异系数阈值 — 低于此值视为自动跳跃 */
    private static final double JUMP_INTERVAL_COV_THRESHOLD = 0.1;

    /** 重复序列检测的最小序列长度 */
    private static final int MIN_SEQUENCE_LENGTH = 5;

    /** 重复序列检测的容忍误差 */
    private static final double SEQUENCE_TOLERANCE = 0.01;

    public MovementPatternAnalyzer() {
        this(new ServerGuardConfig());
    }

    @Autowired
    public MovementPatternAnalyzer(ServerGuardConfig config) {
        this.config = config;
    }

    /**
     * 记录一次玩家移动向量样本。
     *
     * @param playerName 玩家名称
     * @param dx         X轴位移（前后）
     * @param dy         Y轴位移（上下/跳跃）
     * @param dz         Z轴位移（左右）
     * @param timestamp  采样时间戳
     * @return 移动模式分析结果
     */
    public MovementAnalysisResult recordMovement(String playerName, double dx, double dy,
                                                  double dz, Instant timestamp) {
        totalSamples.incrementAndGet();

        ConcurrentLinkedDeque<MovementSample> history = playerMovementHistory.computeIfAbsent(
                playerName, k -> new ConcurrentLinkedDeque<>());

        // 计算即时速度 = sqrt(dx^2 + dy^2 + dz^2)
        double instantSpeed = Math.sqrt(dx * dx + dy * dy + dz * dz);
        history.addLast(new MovementSample(timestamp, dx, dy, dz, instantSpeed));

        while (history.size() > MOVEMENT_WINDOW_SIZE) {
            history.removeFirst();
        }

        if (history.size() < 30) {
            return MovementAnalysisResult.clean(playerName);
        }

        List<String> detections = new ArrayList<>();
        Map<String, Double> confidenceScores = new HashMap<>();

        // === 检测1: 恒定速度检测（Timer Hack） ===
        checkConstantSpeed(history, detections, confidenceScores);

        // === 检测2: 方向变化频率检测（Bot移动） ===
        checkDirectionChangeFrequency(history, detections, confidenceScores);

        // === 检测3: 完美角度移动（SnapAim特征） ===
        checkPerfectAngles(history, detections, confidenceScores);

        // === 检测4: 重复序列检测（Macro/Script） ===
        checkRepeatedSequences(history, detections, confidenceScores);

        // === 检测5: 频域分析（FFT检测周期性速度模式） ===
        checkSpeedFrequencyPattern(history, detections, confidenceScores);

        if (!detections.isEmpty()) {
            hackDetections.incrementAndGet();
            return MovementAnalysisResult.flagged(playerName, detections, confidenceScores);
        }

        // 即使未标记，也返回统计摘要供参考
        return MovementAnalysisResult.suspicious(playerName, detections, confidenceScores);
    }

    /**
     * 记录一次玩家视角旋转样本。
     *
     * @param playerName 玩家名称
     * @param yaw        水平旋转角（度）
     * @param pitch      俯仰角（度）
     * @param timestamp  采样时间戳
     */
    public RotationAnalysisResult recordRotation(String playerName, double yaw, double pitch,
                                                   Instant timestamp) {
        ConcurrentLinkedDeque<RotationSample> history = playerRotationHistory.computeIfAbsent(
                playerName, k -> new ConcurrentLinkedDeque<>());

        history.addLast(new RotationSample(timestamp, yaw, pitch));

        while (history.size() > ROTATION_WINDOW_SIZE) {
            history.removeFirst();
        }

        if (history.size() < 20) {
            return RotationAnalysisResult.clean(playerName);
        }

        List<String> detections = new ArrayList<>();
        double smoothnessScore = 0.0;

        // 计算旋转加速度（yaw delta的二阶差分）
        List<Double> yawDeltas = new ArrayList<>();
        RotationSample prev = null;
        for (RotationSample s : history) {
            if (prev != null) {
                double delta = normalizeAngle(s.yaw - prev.yaw);
                yawDeltas.add(delta);
            }
            prev = s;
        }

        if (yawDeltas.size() >= 10) {
            // 一阶差分（旋转速度）
            DescriptiveStatistics speedStats = new DescriptiveStatistics();
            for (double d : yawDeltas) speedStats.addValue(d);

            // 二阶差分（旋转加速度）— Aimbot表现为加速度方差极低
            List<Double> accelerations = new ArrayList<>();
            for (int i = 1; i < yawDeltas.size(); i++) {
                accelerations.add(yawDeltas.get(i) - yawDeltas.get(i - 1));
            }

            DescriptiveStatistics accelStats = new DescriptiveStatistics();
            for (double a : accelerations) accelStats.addValue(a);

            smoothnessScore = accelStats.getVariance();

            // 人类玩家旋转存在微抖动 = 高加速度方差
            // Aimbot平滑跟踪 = 极低加速度方差
            if (accelStats.getN() >= 8 && accelStats.getVariance() < AIMBOT_SMOOTHNESS_THRESHOLD) {
                detections.add("AIMBOT_SMOOTHNESS: rotation acceleration variance="
                        + String.format("%.6f", accelStats.getVariance())
                        + " (human > " + AIMBOT_SMOOTHNESS_THRESHOLD + ")");
            }

            // 检测无旋转抖动 — 连续多次旋转delta完全一致
            int noJitterStreak = detectNoJitterStreak(yawDeltas);
            if (noJitterStreak >= 8) {
                detections.add("NO_ROTATION_JITTER: " + noJitterStreak
                        + " consecutive identical deltas (human always has micro-jitter)");
            }
        }

        if (!detections.isEmpty()) {
            hackDetections.incrementAndGet();
            return RotationAnalysisResult.flagged(playerName, detections, smoothnessScore);
        }

        return RotationAnalysisResult.clean(playerName);
    }

    /**
     * 记录一次玩家跳跃事件。
     */
    public JumpAnalysisResult recordJump(String playerName, Instant timestamp) {
        ConcurrentLinkedDeque<JumpRecord> history = playerJumpHistory.computeIfAbsent(
                playerName, k -> new ConcurrentLinkedDeque<>());

        history.addLast(new JumpRecord(timestamp));

        while (history.size() > JUMP_WINDOW_SIZE) {
            history.removeFirst();
        }

        if (history.size() < 10) {
            return JumpAnalysisResult.clean(playerName);
        }

        List<String> detections = new ArrayList<>();
        List<Long> intervals = new ArrayList<>();
        JumpRecord prev = null;
        for (JumpRecord j : history) {
            if (prev != null) {
                intervals.add(j.timestamp.toEpochMilli() - prev.timestamp.toEpochMilli());
            }
            prev = j;
        }

        if (intervals.size() >= 8) {
            DescriptiveStatistics intervalStats = new DescriptiveStatistics();
            for (long iv : intervals) intervalStats.addValue(iv);

            double mean = intervalStats.getMean();
            double std = intervalStats.getStandardDeviation();

            // 变异系数 = std/mean
            double cov = mean > 0 ? std / mean : 1.0;

            if (cov < JUMP_INTERVAL_COV_THRESHOLD) {
                detections.add("AUTO_JUMP: interval COV=" + String.format("%.4f", cov)
                        + " (mechanical rhythm, human > " + JUMP_INTERVAL_COV_THRESHOLD + ")");
            }
        }

        if (!detections.isEmpty()) {
            hackDetections.incrementAndGet();
            return JumpAnalysisResult.flagged(playerName, detections);
        }

        return JumpAnalysisResult.clean(playerName);
    }

    /**
     * 检测恒定速度模式 — Timer Hack特征。
     * 合法玩家在走动和奔跑之间速度自然波动，Timer hack以恒定速率推进游戏tick。
     */
    private void checkConstantSpeed(Deque<MovementSample> history, List<String> detections,
                                     Map<String, Double> confidences) {
        DescriptiveStatistics speedStats = new DescriptiveStatistics();
        for (MovementSample s : history) {
            if (s.instantSpeed > 0.01) { // 忽略静止帧
                speedStats.addValue(s.instantSpeed);
            }
        }

        if (speedStats.getN() >= 20 && speedStats.getVariance() < CONSTANT_SPEED_VARIANCE_THRESHOLD) {
            double confidence = 1.0 - (speedStats.getVariance() / CONSTANT_SPEED_VARIANCE_THRESHOLD);
            detections.add("TIMER_HACK: constant speed detected, mean="
                    + String.format("%.4f", speedStats.getMean())
                    + " variance=" + String.format("%.6f", speedStats.getVariance()));
            confidences.put("TIMER_HACK", Math.min(0.95, confidence));
        }
    }

    /**
     * 检测方向变化频率 — Bot倾向于走直线，人类频繁微调方向。
     */
    private void checkDirectionChangeFrequency(Deque<MovementSample> history,
                                                List<String> detections,
                                                Map<String, Double> confidences) {
        int directionChanges = 0;
        MovementSample prev = null;
        for (MovementSample s : history) {
            if (prev != null && s.instantSpeed > 0.01 && prev.instantSpeed > 0.01) {
                // 计算方向变化角度（水平面）
                double prevAngle = Math.atan2(prev.dz, prev.dx);
                double currAngle = Math.atan2(s.dz, s.dx);
                double angleDiff = Math.abs(normalizeAngle(Math.toDegrees(currAngle - prevAngle)));
                if (angleDiff > 10.0) { // 超过10度视为方向变化
                    directionChanges++;
                }
            }
            prev = s;
        }

        double changeFreq = history.size() > 0
                ? (double) directionChanges / history.size() : 1.0;

        if (changeFreq < DIRECTION_CHANGE_FREQ_THRESHOLD && history.size() >= 40) {
            double confidence = 1.0 - (changeFreq / DIRECTION_CHANGE_FREQ_THRESHOLD);
            detections.add("BOT_MOVEMENT: low direction change freq="
                    + String.format("%.4f", changeFreq)
                    + " (human > " + DIRECTION_CHANGE_FREQ_THRESHOLD + ")");
            confidences.put("BOT_MOVEMENT", Math.min(0.9, confidence));
        }
    }

    /**
     * 检测完美角度移动 — SnapAim/Aimbot特征。
     * 人类玩家几乎不可能在多次移动中精确产生45度或90度的方向变化，
     * 但Aimbot可能产生非常接近完美角度的转向。
     */
    private void checkPerfectAngles(Deque<MovementSample> history, List<String> detections,
                                     Map<String, Double> confidences) {
        int perfectAngleCount = 0;
        MovementSample prev = null;
        for (MovementSample s : history) {
            if (prev != null && s.instantSpeed > 0.01 && prev.instantSpeed > 0.01) {
                double prevAngle = Math.atan2(prev.dz, prev.dx);
                double currAngle = Math.atan2(s.dz, s.dx);
                double angleDiff = Math.abs(Math.toDegrees(currAngle - prevAngle));
                angleDiff = normalizeAngle(angleDiff);

                // 检查是否接近45度或其倍数
                double remainder = angleDiff % 45.0;
                if (remainder <= PERFECT_ANGLE_TOLERANCE
                        || remainder >= (45.0 - PERFECT_ANGLE_TOLERANCE)) {
                    perfectAngleCount++;
                }
            }
            prev = s;
        }

        double perfectAngleRatio = history.size() > 1
                ? (double) perfectAngleCount / (history.size() - 1) : 0.0;

        // 如果超过40%的方向变化是完美角度，高度可疑
        if (perfectAngleRatio > 0.4 && perfectAngleCount >= 5) {
            detections.add("SNAP_AIM: perfect 45/90 degree turns ratio="
                    + String.format("%.2f", perfectAngleRatio)
                    + " (" + perfectAngleCount + " precise angles)");
            confidences.put("SNAP_AIM", Math.min(0.85, perfectAngleRatio * 2));
        }
    }

    /**
     * 检测重复移动序列 — Macro/Script检测。
     * 使用滑动窗口比较最近的移动序列与历史序列，检测完全相同的移动模式。
     */
    private void checkRepeatedSequences(Deque<MovementSample> history, List<String> detections,
                                         Map<String, Double> confidences) {
        if (history.size() < MIN_SEQUENCE_LENGTH * 3) return;

        // 提取速度序列用于比较
        List<Double> speedSequence = new ArrayList<>();
        for (MovementSample s : history) {
            speedSequence.add(s.instantSpeed);
        }

        // 检查最近MIN_SEQUENCE_LENGTH个样本是否在历史中重复出现
        int lastIdx = speedSequence.size() - MIN_SEQUENCE_LENGTH;
        List<Double> recent = speedSequence.subList(lastIdx, speedSequence.size());
        int matchCount = 0;

        for (int i = 0; i <= lastIdx - MIN_SEQUENCE_LENGTH; i++) {
            boolean match = true;
            for (int j = 0; j < recent.size(); j++) {
                if (Math.abs(speedSequence.get(i + j) - recent.get(j)) > SEQUENCE_TOLERANCE) {
                    match = false;
                    break;
                }
            }
            if (match) matchCount++;
        }

        if (matchCount >= 2) {
            detections.add("MACRO_SCRIPT: repeated movement sequence detected ("
                    + matchCount + " identical patterns)");
            confidences.put("MACRO_SCRIPT", Math.min(0.9, matchCount * 0.3));
        }
    }

    /**
     * 使用FFT频域分析检测周期性速度模式。
     * Timer Hack在频域中表现为特定频率的尖锐峰值。
     */
    private void checkSpeedFrequencyPattern(Deque<MovementSample> history,
                                             List<String> detections,
                                             Map<String, Double> confidences) {
        if (history.size() < 32) return;

        // 提取速度序列，填充到2的幂次（FFT要求）
        List<Double> speeds = new ArrayList<>();
        for (MovementSample s : history) {
            speeds.add(s.instantSpeed);
        }

        // 填充到2的幂次
        int paddedSize = 1;
        while (paddedSize < speeds.size()) paddedSize <<= 1;

        double[] fftInput = new double[paddedSize];
        for (int i = 0; i < speeds.size(); i++) {
            fftInput[i] = speeds.get(i);
        }

        try {
            FastFourierTransformer fft = new FastFourierTransformer(DftNormalization.STANDARD);
            Complex[] result = fft.transform(fftInput, TransformType.FORWARD);

            // 计算幅度谱
            double[] magnitudes = new double[result.length / 2];
            double totalMagnitude = 0;
            for (int i = 0; i < magnitudes.length; i++) {
                magnitudes[i] = result[i].abs();
                totalMagnitude += magnitudes[i];
            }

            // 寻找主导频率 — 如果某个频率的幅度超过总能量的40%，则为周期性模式
            double maxMagnitude = 0;
            int maxFreqIndex = 0;
            for (int i = 1; i < magnitudes.length; i++) { // 跳过DC分量(i=0)
                if (magnitudes[i] > maxMagnitude) {
                    maxMagnitude = magnitudes[i];
                    maxFreqIndex = i;
                }
            }

            double dominantRatio = totalMagnitude > 0 ? maxMagnitude / totalMagnitude : 0;

            if (dominantRatio > 0.35 && maxFreqIndex > 0) {
                detections.add("FREQ_PATTERN: dominant frequency detected, ratio="
                        + String.format("%.3f", dominantRatio)
                        + " at bin=" + maxFreqIndex + " (periodic speed pattern)");
                confidences.put("TIMER_FREQ", Math.min(0.8, dominantRatio * 2));
            }
        } catch (Exception e) {
            logger.debug("FFT analysis failed: {}", e.getMessage());
        }
    }

    /**
     * 检测无旋转抖动连续序列长度。
     * 人类玩家在任何持续视角移动中都有微小的自然抖动（微米级），
     * 连续多次完全相同的旋转delta说明是自动瞄准。
     */
    private int detectNoJitterStreak(List<Double> yawDeltas) {
        int maxStreak = 0;
        int currentStreak = 1;
        for (int i = 1; i < yawDeltas.size(); i++) {
            if (Math.abs(yawDeltas.get(i) - yawDeltas.get(i - 1)) < 0.0001) {
                currentStreak++;
            } else {
                maxStreak = Math.max(maxStreak, currentStreak);
                currentStreak = 1;
            }
        }
        return Math.max(maxStreak, currentStreak);
    }

    /**
     * 规范化角度到[-180, 180]范围。
     */
    private double normalizeAngle(double angle) {
        angle = angle % 360.0;
        if (angle > 180.0) angle -= 360.0;
        if (angle < -180.0) angle += 360.0;
        return angle;
    }

    /**
     * 清除指定玩家的所有移动分析数据。
     */
    public void clearPlayer(String playerName) {
        playerMovementHistory.remove(playerName);
        playerRotationHistory.remove(playerName);
        playerJumpHistory.remove(playerName);
    }

    /**
     * 获取分析器运行状态。
     */
    public Map<String, Object> getStatus() {
        Map<String, Object> status = new LinkedHashMap<>();
        status.put("totalSamples", totalSamples.get());
        status.put("hackDetections", hackDetections.get());
        status.put("trackedPlayers", playerMovementHistory.size());
        return status;
    }

    // ==================== 内部数据类 ====================

    /** 移动向量采样记录 */
    private static class MovementSample {
        final Instant timestamp;
        final double dx, dy, dz;
        final double instantSpeed;

        MovementSample(Instant timestamp, double dx, double dy, double dz, double instantSpeed) {
            this.timestamp = timestamp;
            this.dx = dx;
            this.dy = dy;
            this.dz = dz;
            this.instantSpeed = instantSpeed;
        }
    }

    /** 视角旋转采样记录 */
    private static class RotationSample {
        final Instant timestamp;
        final double yaw;
        final double pitch;

        RotationSample(Instant timestamp, double yaw, double pitch) {
            this.timestamp = timestamp;
            this.yaw = yaw;
            this.pitch = pitch;
        }
    }

    /** 跳跃事件记录 */
    private static class JumpRecord {
        final Instant timestamp;

        JumpRecord(Instant timestamp) {
            this.timestamp = timestamp;
        }
    }

    // ==================== 枚举与结果类 ====================

    /** 移动分析结果 */
    public static class MovementAnalysisResult {
        private final boolean flagged;
        private final String playerName;
        private final List<String> detections;
        private final Map<String, Double> confidenceScores;

        MovementAnalysisResult(boolean flagged, String playerName,
                               List<String> detections, Map<String, Double> confidenceScores) {
            this.flagged = flagged;
            this.playerName = playerName;
            this.detections = detections;
            this.confidenceScores = confidenceScores;
        }

        public static MovementAnalysisResult clean(String playerName) {
            return new MovementAnalysisResult(false, playerName, List.of(), Map.of());
        }

        public static MovementAnalysisResult suspicious(String playerName,
                                                         List<String> detections,
                                                         Map<String, Double> confidenceScores) {
            return new MovementAnalysisResult(false, playerName, detections, confidenceScores);
        }

        public static MovementAnalysisResult flagged(String playerName,
                                                      List<String> detections,
                                                      Map<String, Double> confidenceScores) {
            return new MovementAnalysisResult(true, playerName, detections, confidenceScores);
        }

        public boolean isFlagged() { return flagged; }
        public boolean isClean() { return !flagged && detections.isEmpty(); }
        public String getPlayerName() { return playerName; }
        public List<String> getDetections() { return detections; }
        public Map<String, Double> getConfidenceScores() { return confidenceScores; }
    }

    /** 视角分析结果 */
    public static class RotationAnalysisResult {
        private final boolean flagged;
        private final String playerName;
        private final List<String> detections;
        private final double smoothnessScore;

        RotationAnalysisResult(boolean flagged, String playerName,
                               List<String> detections, double smoothnessScore) {
            this.flagged = flagged;
            this.playerName = playerName;
            this.detections = detections;
            this.smoothnessScore = smoothnessScore;
        }

        public static RotationAnalysisResult clean(String playerName) {
            return new RotationAnalysisResult(false, playerName, List.of(), 0.0);
        }

        public static RotationAnalysisResult flagged(String playerName,
                                                      List<String> detections,
                                                      double smoothnessScore) {
            return new RotationAnalysisResult(true, playerName, detections, smoothnessScore);
        }

        public boolean isFlagged() { return flagged; }
        public boolean isClean() { return !flagged; }
        public String getPlayerName() { return playerName; }
        public List<String> getDetections() { return detections; }
        public double getSmoothnessScore() { return smoothnessScore; }
    }

    /** 跳跃分析结果 */
    public static class JumpAnalysisResult {
        private final boolean flagged;
        private final String playerName;
        private final List<String> detections;

        JumpAnalysisResult(boolean flagged, String playerName, List<String> detections) {
            this.flagged = flagged;
            this.playerName = playerName;
            this.detections = detections;
        }

        public static JumpAnalysisResult clean(String playerName) {
            return new JumpAnalysisResult(false, playerName, List.of());
        }

        public static JumpAnalysisResult flagged(String playerName, List<String> detections) {
            return new JumpAnalysisResult(true, playerName, detections);
        }

        public boolean isFlagged() { return flagged; }
        public boolean isClean() { return !flagged; }
        public String getPlayerName() { return playerName; }
        public List<String> getDetections() { return detections; }
    }
}
