package com.aluer.anticheat.world;

import com.aluer.config.ServerGuardConfig;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

/**
 * AI 寻路机器人检测 (Baritone Bot) — V4.0 玩家行为安全模块
 *
 * 检测原理：
 *   Baritone 是 Minecraft 生态系统中最流行的开源 AI 寻路机器人框架，
 *   广泛应用于各类外挂客户端（如 Impact、Lambda、Aristois 等）。
 *   虽然 Baritone 功能强大，但其行为模式具有可识别的特征：
 *   1. 路径平滑度——Baritone 的 A* 寻路算法生成的路径极其平滑，
 *      转角半径几乎恒定，人类移动路径有自然的随机偏差和微调。
 *   2. 行为重复率——Baritone 在执行挖掘/放置任务时有精确的间隔模式，
 *      不在人类的自然节律范围内（标准差 < 5%）。
 *   3. 机械式视角移动——Baritone 的视角移动使用线性插值（Lerp），
 *      角速度为恒定值，人类视角移动有加速/减速阶段。
 *   4. 聊天特征——Baritone 有自动聊天功能（AutoChat），
 *      响应速度极快（< 500ms）且文本模式高度固定。
 *   5. 持续在线时间——Bot 通常持续在线远超人类（> 6 小时不间歇活动），
 *      无社交互动，无挂机行为。
 *   6. 无聊天/无社交行为——Bot 长时间在线但不聊天、不交互，仅执行机械任务。
 *
 * 配置开关：serverguard.security.super-evolution.anti-baritone
 */
@Service
public class AntiBaritoneService {

    private final ServerGuardConfig config;
    private final Map<String, PlayerProfile> playerProfiles = new ConcurrentHashMap<>();
    private final Map<String, List<MovementSample>> movementRecords = new ConcurrentHashMap<>();
    private final Map<String, List<LookSample>> lookRecords = new ConcurrentHashMap<>();
    private final Map<String, List<InteractRecord>> interactionRecords = new ConcurrentHashMap<>();
    private final Map<String, Instant> flaggedPlayers = new ConcurrentHashMap<>();
    private final ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor();

    /** 追踪的玩家总数 */
    private final AtomicLong totalTracked = new AtomicLong(0);
    /** Baritone 疑似次数 */
    private final AtomicLong baritoneSuspected = new AtomicLong(0);

    /** 路径平滑度检测——转角半径标准差上限 */
    private static final double MAX_TURN_RADIUS_STDDEV = 1.5;

    /** 行为间隔变异系数上限——低于此值说明间隔过于规律 */
    private static final double MAX_ACTION_INTERVAL_COV = 0.05;

    /** 视角移动恒定角速度判定——角加速度（角速度变化率）阈值 */
    private static final double MAX_ANGULAR_ACCELERATION = 0.02;

    /** 聊天响应速度阈值（毫秒）——低于此值为自动响应 */
    private static final long AUTO_CHAT_RESPONSE_MS = 500;

    /** Bot 持续在线时间阈值（分钟）——超过此时间且无社交交互为可疑 */
    private static final long BOT_SESSION_MINUTES = 360;

    /** 移动样本最少记录数（用于有效分析） */
    private static final int MIN_MOVEMENT_SAMPLES = 30;

    /** 视角样本最少记录数（用于有效分析） */
    private static final int MIN_LOOK_SAMPLES = 20;

    /** 记录保留时间（秒） */
    private static final long RECORD_RETENTION_SECONDS = 1200;

    /** 标记持续时间（秒） */
    private static final long FLAG_DURATION_SECONDS = 7200;

    public AntiBaritoneService() {
        this(new ServerGuardConfig());
    }

    @Autowired
    public AntiBaritoneService(ServerGuardConfig config) {
        this.config = config;
        scheduler.scheduleAtFixedRate(this::cleanupOldRecords, 300, 600, TimeUnit.SECONDS);
    }

    /**
     * 检测玩家移动事件——分析路径平滑度和移动模式。
     *
     * 通过持续追踪玩家的移动轨迹，计算转角半径、路径偏差等指标。
     * Baritone 的路径由 A* 算法生成，角点经过平滑处理，路径极其规整。
     *
     * @param playerName 玩家名称
     * @param playerUUID 玩家 UUID
     * @param x          当前 X 坐标
     * @param y          当前 Y 坐标
     * @param z          当前 Z 坐标
     * @param yaw        当前偏航角（水平视角）
     * @param isSprinting 是否在冲刺
     * @param isSneaking  是否在潜行
     * @return 检测结果
     */
    public DetectionResult detectMovement(String playerName, String playerUUID,
                                           double x, double y, double z, float yaw,
                                           boolean isSprinting, boolean isSneaking) {
        if (!config.getSecurity().getSuperEvolution().isAntiBaritone()) {
            return DetectionResult.clean();
        }

        Instant now = Instant.now();
        List<MovementSample> samples = movementRecords.computeIfAbsent(playerName,
            k -> Collections.synchronizedList(new ArrayList<>()));

        MovementSample sample = new MovementSample(now, x, y, z, yaw, isSprinting, isSneaking);
        samples.add(sample);

        // 更新玩家在线状态
        PlayerProfile profile = playerProfiles.computeIfAbsent(playerName,
            k -> new PlayerProfile());
        profile.lastActivity = now;
        if (profile.joinTime == null) {
            profile.joinTime = now;
            totalTracked.incrementAndGet();
        }

        // 需要足够样本才能分析
        if (samples.size() < MIN_MOVEMENT_SAMPLES) {
            return DetectionResult.clean();
        }

        int score = 0;
        List<String> reasons = new ArrayList<>();

        // === 检测 1: 路径平滑度分析 ===
        // 计算路径中每个转角的半径，分析其标准差
        double turnRadiusStdDev = calculateTurnRadiusStdDev(samples);
        if (turnRadiusStdDev >= 0 && turnRadiusStdDev < MAX_TURN_RADIUS_STDDEV) {
            score += 25;
            reasons.add("SMOOTH_PATH: turn radius stddev=" +
                String.format("%.3f", turnRadiusStdDev) +
                " (Baritone A* path smoothing, human > " + MAX_TURN_RADIUS_STDDEV + ")");
        }

        // === 检测 2: 移动模式一致性 ===
        // 检查连续移动的速度变化——人类会自然有速度波动
        double speedVariationCOV = calculateSpeedVariationCOV(samples);
        if (speedVariationCOV >= 0 && speedVariationCOV < 0.03) {
            score += 20;
            reasons.add("CONSTANT_SPEED: speed variation COV=" +
                String.format("%.4f", speedVariationCOV) +
                " (mechanical movement pattern)");
        }

        // === 检测 3: 持续在线时间检查 ===
        long onlineMinutes = Duration.between(profile.joinTime, now).toMinutes();
        // 检查社交交互情况
        List<InteractRecord> interactions = interactionRecords.get(playerName);
        boolean hasSocialInteraction = interactions != null && !interactions.isEmpty();

        if (onlineMinutes > BOT_SESSION_MINUTES && !hasSocialInteraction) {
            score += 30;
            reasons.add("LONG_SESSION_NO_SOCIAL: " + onlineMinutes +
                " min online without social interaction (bot threshold=" +
                BOT_SESSION_MINUTES + " min)");
        }

        // === 检测 4: 移动路径无明显目的 ===
        // Bot 常做重复性移动（如挖矿 bot 在固定区域往返）
        if (samples.size() >= 100) {
            double patternRepeatScore = detectRepeatMovementPattern(samples);
            if (patternRepeatScore > 0.7) {
                score += 20;
                reasons.add("REPETITIVE_PATH: " +
                    String.format("%.1f%%", patternRepeatScore * 100) +
                    " movement pattern repetition");
            }
        }

        if (score >= 50) {
            flaggedPlayers.put(playerName, Instant.now().plusSeconds(FLAG_DURATION_SECONDS));
            baritoneSuspected.incrementAndGet();
            return DetectionResult.flagged(reasons);
        } else if (score >= 30) {
            return DetectionResult.suspicious(score, reasons);
        }

        return DetectionResult.clean();
    }

    /**
     * 检测玩家视角移动——分析是否为机械式线性插值。
     *
     * Baritone 使用线性插值（Lerp）来控制视角旋转，角速度为恒定值，
     * 而人类视角移动有自然的加速/减速阶段（先快后慢或先慢后快）。
     *
     * @param playerName 玩家名称
     * @param playerUUID 玩家 UUID
     * @param yaw        当前水平视角（偏航角）
     * @param pitch      当前垂直视角（俯仰角）
     * @return 检测结果
     */
    public DetectionResult detectLook(String playerName, String playerUUID,
                                       float yaw, float pitch) {
        if (!config.getSecurity().getSuperEvolution().isAntiBaritone()) {
            return DetectionResult.clean();
        }

        Instant now = Instant.now();
        List<LookSample> samples = lookRecords.computeIfAbsent(playerName,
            k -> Collections.synchronizedList(new ArrayList<>()));

        LookSample sample = new LookSample(now, yaw, pitch);
        samples.add(sample);

        // 更新活跃状态
        PlayerProfile profile = playerProfiles.computeIfAbsent(playerName,
            k -> new PlayerProfile());
        profile.lastActivity = now;

        if (samples.size() < MIN_LOOK_SAMPLES) {
            return DetectionResult.clean();
        }

        int score = 0;
        List<String> reasons = new ArrayList<>();

        // === 检测: 视角角加速度恒定 ===
        // 计算连续视角变化之间的角速度变化率
        double angularAccel = calculateAngularAcceleration(samples);
        if (angularAccel >= 0 && angularAccel < MAX_ANGULAR_ACCELERATION) {
            score += 25;
            reasons.add("MECHANICAL_LOOK: angular acceleration=" +
                String.format("%.4f", angularAccel) +
                " (constant angular velocity / lerp, threshold < " +
                MAX_ANGULAR_ACCELERATION + ")");
        }

        // === 检测: 视角变化的机械精确度 ===
        // 检查视角变化是否过于精确（不含自然微抖）
        double yawPrecision = calculateLookPrecision(samples);
        if (yawPrecision > 0.90) {
            score += 15;
            reasons.add("PRECISE_AIM: look precision=" +
                String.format("%.2f", yawPrecision) +
                " (mechanical aim, no natural micro-jitter)");
        }

        if (score >= 30) {
            return DetectionResult.suspicious(score, reasons);
        }

        return DetectionResult.clean();
    }

    /**
     * 检测聊天活动——识别 Baritone 自动聊天特征。
     *
     * Baritone AutoChat 功能可自动回复消息，其特点为：
     * 响应速度极快、文本模式高度固定、回复内容模板化。
     *
     * @param playerName 玩家名称
     * @param playerUUID 玩家 UUID
     * @param message    玩家发送的消息
     * @param isResponse 是否为对他人消息的响应
     * @param responseTimeMs 响应时间（毫秒），仅当 isResponse=true 时有效
     * @return 检测结果
     */
    public DetectionResult detectChat(String playerName, String playerUUID,
                                       String message, boolean isResponse,
                                       long responseTimeMs) {
        if (!config.getSecurity().getSuperEvolution().isAntiBaritone()) {
            return DetectionResult.clean();
        }

        Instant now = Instant.now();
        List<InteractRecord> interactions = interactionRecords.computeIfAbsent(playerName,
            k -> Collections.synchronizedList(new ArrayList<>()));

        interactions.add(new InteractRecord(now, "CHAT", message));

        // 更新社交交互标记
        PlayerProfile profile = playerProfiles.computeIfAbsent(playerName,
            k -> new PlayerProfile());
        profile.lastSocialActivity = now;
        profile.chatCount++;

        int score = 0;
        List<String> reasons = new ArrayList<>();

        // === 检测: 自动响应速度 ===
        if (isResponse && responseTimeMs < AUTO_CHAT_RESPONSE_MS) {
            score += 30;
            reasons.add("AUTO_CHAT_RESPONSE: " + responseTimeMs +
                "ms (Baritone AutoChat threshold=" + AUTO_CHAT_RESPONSE_MS + "ms)");
        }

        // === 检测: 重复消息模式 ===
        if (message != null && interactions.size() >= 5) {
            double contentSimilarity = calculateContentSimilarity(interactions, message);
            if (contentSimilarity > 0.85) {
                score += 20;
                reasons.add("REPETITIVE_CHAT: " +
                    String.format("%.1f%%", contentSimilarity * 100) +
                    " message similarity (bot chat pattern)");
            }
        }

        if (score >= 30) {
            baritoneSuspected.incrementAndGet();
            flaggedPlayers.put(playerName, Instant.now().plusSeconds(FLAG_DURATION_SECONDS));
            return DetectionResult.flagged(reasons);
        } else if (score >= 15) {
            return DetectionResult.suspicious(score, reasons);
        }

        return DetectionResult.clean();
    }

    /**
     * 记录玩家交互事件（与方块/实体互动）。
     *
     * Bot 的交互有精确的节奏模式，通过分析交互间隔的变异系数来检测。
     *
     * @param playerName    玩家名称
     * @param playerUUID    玩家 UUID
     * @param interactionType 交互类型（"BLOCK_BREAK" / "BLOCK_PLACE" / "ENTITY"）
     * @return 检测结果
     */
    public DetectionResult detectInteract(String playerName, String playerUUID,
                                           String interactionType) {
        if (!config.getSecurity().getSuperEvolution().isAntiBaritone()) {
            return DetectionResult.clean();
        }

        Instant now = Instant.now();
        List<InteractRecord> interactions = interactionRecords.computeIfAbsent(playerName,
            k -> Collections.synchronizedList(new ArrayList<>()));

        interactions.add(new InteractRecord(now, interactionType, null));

        // 更新活跃状态
        PlayerProfile profile = playerProfiles.computeIfAbsent(playerName,
            k -> new PlayerProfile());
        profile.lastActivity = now;

        if (interactions.size() < 10) {
            return DetectionResult.clean();
        }

        int score = 0;
        List<String> reasons = new ArrayList<>();

        // === 检测: 交互间隔规律性 ===
        double intervalCov = calculateInteractionIntervalCOV(interactions);
        if (intervalCov < MAX_ACTION_INTERVAL_COV) {
            score += 35;
            reasons.add("MECHANICAL_INTERVAL: interaction interval COV=" +
                String.format("%.4f", intervalCov) +
                " (Baritone precise action rhythm, threshold < " +
                MAX_ACTION_INTERVAL_COV + ")");
        }

        if (score >= 30) {
            flaggedPlayers.put(playerName, Instant.now().plusSeconds(FLAG_DURATION_SECONDS));
            baritoneSuspected.incrementAndGet();
            return DetectionResult.flagged(reasons);
        } else if (score >= 20) {
            return DetectionResult.suspicious(score, reasons);
        }

        return DetectionResult.clean();
    }

    /**
     * 清除指定玩家的所有追踪数据。
     *
     * @param playerName 玩家名称
     */
    public void clearPlayer(String playerName) {
        playerProfiles.remove(playerName);
        movementRecords.remove(playerName);
        lookRecords.remove(playerName);
        interactionRecords.remove(playerName);
        flaggedPlayers.remove(playerName);
    }

    /**
     * 获取模块运行状态。
     *
     * @return 包含统计数据和置信度分数的 LinkedHashMap
     */
    public Map<String, Object> getStatus() {
        Map<String, Object> s = new LinkedHashMap<>();
        s.put("totalTracked", totalTracked.get());
        s.put("baritoneSuspected", baritoneSuspected.get());
        s.put("flaggedPlayers", flaggedPlayers.size());
        s.put("movementTracked", movementRecords.size());
        s.put("lookTracked", lookRecords.size());
        s.put("interactionTracked", interactionRecords.size());
        s.put("enabled", config.getSecurity().getSuperEvolution().isAntiBaritone());

        // === 置信度分数 ===
        Map<String, Object> confidenceScores = new LinkedHashMap<>();
        // 计算每个可疑玩家的综合置信度
        for (Map.Entry<String, PlayerProfile> e : playerProfiles.entrySet()) {
            String player = e.getKey();
            PlayerProfile profile = e.getValue();

            double confidence = 0;

            // 在线时长分数
            long onlineMin = Duration.between(profile.joinTime, Instant.now()).toMinutes();
            if (onlineMin > BOT_SESSION_MINUTES) {
                confidence += 30;
            } else if (onlineMin > 120) {
                confidence += 15;
            }

            // 无社交交互分数
            if (profile.chatCount == 0 && onlineMin > 60) {
                confidence += 25;
            }

            // 采样数量分数（更长的追踪周期 = 更高的置信度）
            List<MovementSample> moveSamples = movementRecords.get(player);
            if (moveSamples != null && moveSamples.size() > 200) {
                confidence += 20;
            } else if (moveSamples != null && moveSamples.size() > 50) {
                confidence += 10;
            }

            if (confidence > 0) {
                Map<String, Object> score = new LinkedHashMap<>();
                score.put("confidence", Math.min(100, confidence));
                score.put("onlineMinutes", onlineMin);
                score.put("chatCount", profile.chatCount);
                score.put("moveSamples", moveSamples != null ? moveSamples.size() : 0);
                confidenceScores.put(player, score);
            }
        }
        s.put("confidenceScores", confidenceScores);

        // 被标记玩家列表
        List<Map<String, Object>> flagged = new ArrayList<>();
        for (Map.Entry<String, Instant> e : flaggedPlayers.entrySet()) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("player", e.getKey());
            m.put("flaggedUntil", e.getValue().toString());
            PlayerProfile profile = playerProfiles.get(e.getKey());
            if (profile != null) {
                m.put("onlineMinutes",
                    Duration.between(profile.joinTime, Instant.now()).toMinutes());
                m.put("chatCount", profile.chatCount);
            }
            flagged.add(m);
        }
        s.put("flaggedPlayersList", flagged);

        return s;
    }

    public long getTotalTracked() { return totalTracked.get(); }
    public long getBaritoneSuspected() { return baritoneSuspected.get(); }

    /**
     * 计算路径转角半径的标准差。
     *
     * 从移动样本中提取连续三个点的转角，计算转角半径。
     * Baritone 的 A* 路径经过平滑处理，转角半径非常接近恒定值。
     *
     * @param samples 移动样本列表（按时间排序）
     * @return 转角半径的标准差，无法计算时返回 -1
     */
    private double calculateTurnRadiusStdDev(List<MovementSample> samples) {
        if (samples.size() < 5) return -1;

        List<Double> radii = new ArrayList<>();
        // 取最近 30 个样本
        int startIdx = Math.max(0, samples.size() - 30);

        for (int i = startIdx + 2; i < samples.size(); i++) {
            MovementSample p1 = samples.get(i - 2);
            MovementSample p2 = samples.get(i - 1);
            MovementSample p3 = samples.get(i);

            // 计算三个连续点的转角曲率
            // 使用向量叉积/点积计算转向角
            double dx1 = p2.x - p1.x;
            double dz1 = p2.z - p1.z;
            double dx2 = p3.x - p2.x;
            double dz2 = p3.z - p2.z;

            double dot = dx1 * dx2 + dz1 * dz2;
            double mag1 = Math.sqrt(dx1 * dx1 + dz1 * dz1);
            double mag2 = Math.sqrt(dx2 * dx2 + dz2 * dz2);

            if (mag1 > 0.01 && mag2 > 0.01) {
                double cosAngle = dot / (mag1 * mag2);
                // Clamp to [-1, 1] to avoid NaN
                cosAngle = Math.max(-1, Math.min(1, cosAngle));
                double angle = Math.acos(cosAngle);
                // 转角半径 = 弧长 / 角度变化
                double avgStep = (mag1 + mag2) / 2;
                double radius = angle > 0.001 ? avgStep / angle : Double.MAX_VALUE;
                radii.add(Math.min(radius, 100)); // 限制最大值
            }
        }

        if (radii.size() < 3) return -1;

        double mean = radii.stream().mapToDouble(Double::doubleValue).average().orElse(0);
        if (mean == 0) return -1;
        double variance = radii.stream()
            .mapToDouble(r -> Math.pow(r - mean, 2))
            .average().orElse(0);
        return Math.sqrt(variance);
    }

    /**
     * 计算移动速度变化的变异系数。
     *
     * @param samples 移动样本列表
     * @return 速度变化的 COV，无法计算时返回 -1
     */
    private double calculateSpeedVariationCOV(List<MovementSample> samples) {
        if (samples.size() < 4) return -1;

        List<Double> speeds = new ArrayList<>();
        int startIdx = Math.max(0, samples.size() - 20);

        for (int i = startIdx + 1; i < samples.size(); i++) {
            MovementSample prev = samples.get(i - 1);
            MovementSample curr = samples.get(i);
            long timeDiff = curr.time.toEpochMilli() - prev.time.toEpochMilli();
            if (timeDiff > 0) {
                double dist = Math.sqrt(
                    Math.pow(curr.x - prev.x, 2) +
                    Math.pow(curr.z - prev.z, 2));
                speeds.add(dist / (timeDiff / 1000.0));
            }
        }

        if (speeds.size() < 3) return -1;

        double mean = speeds.stream().mapToDouble(Double::doubleValue).average().orElse(0);
        if (mean == 0) return -1;
        double variance = speeds.stream()
            .mapToDouble(s -> Math.pow(s - mean, 2))
            .average().orElse(0);
        return Math.sqrt(variance) / mean;
    }

    /**
     * 计算视角变化的角加速度（角速度的变化率）。
     *
     * Baritone 使用线性插值控制视角，角加速度为零（恒定角速度）。
     * 人类视角移动有自然的加速和减速，角加速度不为零。
     *
     * @param samples 视角样本列表
     * @return 平均角加速度，无法计算时返回 -1
     */
    private double calculateAngularAcceleration(List<LookSample> samples) {
        if (samples.size() < 3) return -1;

        List<Double> angularVelocities = new ArrayList<>();
        int startIdx = Math.max(0, samples.size() - 30);

        // 先计算角速度序列
        for (int i = startIdx + 1; i < samples.size(); i++) {
            LookSample prev = samples.get(i - 1);
            LookSample curr = samples.get(i);
            long timeDiff = curr.time.toEpochMilli() - prev.time.toEpochMilli();
            if (timeDiff > 0) {
                double yawDiff = Math.abs(curr.yaw - prev.yaw);
                // 处理角度环绕
                if (yawDiff > 180) yawDiff = 360 - yawDiff;
                angularVelocities.add(yawDiff / (timeDiff / 1000.0));
            }
        }

        if (angularVelocities.size() < 2) return -1;

        // 计算角加速度（角速度的差分）
        double totalAccel = 0;
        int accelCount = 0;
        for (int i = 1; i < angularVelocities.size(); i++) {
            double accel = Math.abs(angularVelocities.get(i) - angularVelocities.get(i - 1));
            totalAccel += accel;
            accelCount++;
        }

        return accelCount > 0 ? totalAccel / accelCount : -1;
    }

    /**
     * 计算视角移动的精确度（反映是否存在自然微抖）。
     *
     * 人类在目标锁定时有自然的微小手部抖动（micro-jitter），
     * 机械式移动完全不会有抖动。
     *
     * @param samples 视角样本列表
     * @return 精确度分数（0-1），1 表示完全无抖动（机械式）
     */
    private double calculateLookPrecision(List<LookSample> samples) {
        if (samples.size() < 5) return 0;

        List<Double> yawDiffs = new ArrayList<>();
        int startIdx = Math.max(0, samples.size() - 20);
        for (int i = startIdx + 1; i < samples.size(); i++) {
            double diff = Math.abs(samples.get(i).yaw - samples.get(i - 1).yaw);
            if (diff > 180) diff = 360 - diff;
            yawDiffs.add(diff);
        }

        if (yawDiffs.isEmpty()) return 0;

        // 精确度 = 微小变化的占比（微小变化 = 接近零的变化，无抖动）
        long tinyChanges = yawDiffs.stream().filter(d -> d < 0.01).count();
        return (double) tinyChanges / yawDiffs.size();
    }

    /**
     * 检测重复移动模式（往返或固定区域循环）。
     *
     * @param samples 移动样本列表
     * @return 重复度分数（0-1），1 表示完全重复
     */
    private double detectRepeatMovementPattern(List<MovementSample> samples) {
        if (samples.size() < 50) return 0;

        // 检查过去 100 个位置样本是否出现在相似的区域内
        int windowSize = Math.min(samples.size(), 100);
        int startIdx = samples.size() - windowSize;

        // 计算位置分布的中心
        double sumX = 0, sumZ = 0;
        for (int i = startIdx; i < samples.size(); i++) {
            sumX += samples.get(i).x;
            sumZ += samples.get(i).z;
        }
        double centerX = sumX / windowSize;
        double centerZ = sumZ / windowSize;

        // 计算距离中心在一定范围内的样本比例
        double maxDist = 10; // 10 格半径
        int withinRange = 0;
        for (int i = startIdx; i < samples.size(); i++) {
            double dist = Math.sqrt(
                Math.pow(samples.get(i).x - centerX, 2) +
                Math.pow(samples.get(i).z - centerZ, 2));
            if (dist < maxDist) withinRange++;
        }

        return (double) withinRange / windowSize;
    }

    /**
     * 计算交互间隔的变异系数。
     *
     * @param interactions 交互记录列表
     * @return 间隔的 COV
     */
    private double calculateInteractionIntervalCOV(List<InteractRecord> interactions) {
        if (interactions.size() < 4) return 1.0;

        List<Long> intervals = new ArrayList<>();
        int startIdx = Math.max(0, interactions.size() - 20);
        for (int i = startIdx + 1; i < interactions.size(); i++) {
            long interval = interactions.get(i).time.toEpochMilli() -
                interactions.get(i - 1).time.toEpochMilli();
            intervals.add(interval);
        }

        if (intervals.size() < 3) return 1.0;

        double mean = intervals.stream().mapToLong(Long::longValue).average().orElse(0);
        if (mean == 0) return 1.0;
        double variance = intervals.stream()
            .mapToDouble(i -> Math.pow(i - mean, 2))
            .average().orElse(0);
        return Math.sqrt(variance) / mean;
    }

    /**
     * 计算聊天消息的内容相似度。
     *
     * 通过比较最近消息的内容重复程度来识别自动回复模板。
     *
     * @param interactions 交互记录列表
     * @param newMessage   新消息
     * @return 相似度分数（0-1）
     */
    private double calculateContentSimilarity(List<InteractRecord> interactions,
                                               String newMessage) {
        if (newMessage == null || newMessage.isEmpty()) return 0;

        List<String> recentMessages = new ArrayList<>();
        int count = 0;
        for (int i = interactions.size() - 1; i >= 0 && count < 5; i--) {
            InteractRecord r = interactions.get(i);
            if ("CHAT".equals(r.interactionType) && r.content != null) {
                recentMessages.add(r.content);
                count++;
            }
        }

        if (recentMessages.isEmpty()) return 0;

        // 简单的 Jaccard 词级相似度
        Set<String> newWords = new HashSet<>(Arrays.asList(
            newMessage.toLowerCase().split("\\s+")));
        double totalSimilarity = 0;
        for (String msg : recentMessages) {
            Set<String> msgWords = new HashSet<>(Arrays.asList(
                msg.toLowerCase().split("\\s+")));
            Set<String> intersection = new HashSet<>(newWords);
            intersection.retainAll(msgWords);
            Set<String> union = new HashSet<>(newWords);
            union.addAll(msgWords);
            if (!union.isEmpty()) {
                totalSimilarity += (double) intersection.size() / union.size();
            }
        }

        return recentMessages.size() > 0 ? totalSimilarity / recentMessages.size() : 0;
    }

    /**
     * 定期清理过期记录。
     */
    private void cleanupOldRecords() {
        Instant cutoff = Instant.now().minusSeconds(RECORD_RETENTION_SECONDS);
        movementRecords.entrySet().removeIf(e -> {
            List<MovementSample> samples = e.getValue();
            samples.removeIf(s -> s.time.isBefore(cutoff));
            return samples.isEmpty();
        });
        lookRecords.entrySet().removeIf(e -> {
            List<LookSample> samples = e.getValue();
            samples.removeIf(s -> s.time.isBefore(cutoff));
            return samples.isEmpty();
        });
        interactionRecords.entrySet().removeIf(e -> {
            List<InteractRecord> records = e.getValue();
            records.removeIf(r -> r.time.isBefore(cutoff));
            return records.isEmpty();
        });
        // 清理长时间不活跃且无数据的 profile
        Instant staleCutoff = Instant.now().minusSeconds(RECORD_RETENTION_SECONDS * 2);
        playerProfiles.entrySet().removeIf(e -> {
            PlayerProfile p = e.getValue();
            return p.lastActivity.isBefore(staleCutoff)
                && !movementRecords.containsKey(e.getKey())
                && !lookRecords.containsKey(e.getKey());
        });
        flaggedPlayers.entrySet().removeIf(e -> e.getValue().isBefore(Instant.now()));
    }

    // ==================== 内部数据类 ====================

    /**
     * 玩家画像——记录长期的在线行为和社交交互数据。
     */
    private static class PlayerProfile {
        Instant joinTime;
        Instant lastActivity = Instant.now();
        Instant lastSocialActivity = Instant.now();
        int chatCount = 0;
    }

    /**
     * 移动样本——记录每帧的坐标和视角数据。
     */
    private static class MovementSample {
        final Instant time;
        final double x, y, z;
        final float yaw;
        final boolean isSprinting;
        final boolean isSneaking;

        MovementSample(Instant time, double x, double y, double z, float yaw,
                      boolean isSprinting, boolean isSneaking) {
            this.time = time;
            this.x = x;
            this.y = y;
            this.z = z;
            this.yaw = yaw;
            this.isSprinting = isSprinting;
            this.isSneaking = isSneaking;
        }
    }

    /**
     * 视角样本——记录每帧的水平/垂直视角。
     */
    private static class LookSample {
        final Instant time;
        final float yaw;
        final float pitch;

        LookSample(Instant time, float yaw, float pitch) {
            this.time = time;
            this.yaw = yaw;
            this.pitch = pitch;
        }
    }

    /**
     * 交互记录——记录聊天、方块挖掘/放置、实体交互等事件。
     */
    private static class InteractRecord {
        final Instant time;
        final String interactionType;
        final String content;

        InteractRecord(Instant time, String interactionType, String content) {
            this.time = time;
            this.interactionType = interactionType;
            this.content = content;
        }
    }

    // ==================== 检测结果类 ====================

    /**
     * Baritone Bot 检测结果。
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

        /** 无异常：玩家行为正常 */
        public static DetectionResult clean() {
            return new DetectionResult(false, false, 0, List.of());
        }

        /** 可疑行为：存在 Baritone 特征但置信度不足 */
        public static DetectionResult suspicious(int score, List<String> reasons) {
            return new DetectionResult(false, true, score, reasons);
        }

        /** 已标记：检测到高置信度 Baritone Bot 行为 */
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
