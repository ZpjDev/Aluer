package com.aluer.security;

import com.aluer.config.ServerGuardConfig;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * 机器人行为指纹检测器 — 多维度行为分析识别自动化机器人账号
 *
 * 检测原理：
 * 通过综合分析多个行为维度来识别非人类玩家（机器人），而非依赖单一信号。
 *
 * 1. 登录时序指纹 — 机器人经常以精确的固定间隔登录，或者在极端短时间内大量涌入。
 *    正常玩家登录时间间隔呈自然随机分布。
 * 2. 命名模式指纹 — 机器人通常使用随机字母数字组合、已知Bot命名规范
 *    （如 Baritone 默认名称模式）、或无意义字符串作为用户名。
 * 3. 移动熵值指纹 — 机器人移动模式极度机械化：Pathfinding机器人路径平滑度极高，
 *    Idle机器人则完全不动，二者都偏离正常玩家的自然移动熵值。
 * 4. 聊天模式指纹 — 机器人要么发送完全相同的垃圾广告（SpamBot），
 *    要么从不发送任何聊天消息（SilentBot），正常玩家聊天频率和内容都有自然变化。
 * 5. 延迟指纹 — 机器人通常运行在高延迟代理/VPN后面，或运行在极低延迟的服务器托管环境，
 *    其ping值的分布模式与正常家庭网络玩家有显著差异。
 *
 * 多信号融合：每个信号产生0-25的子分数，五个维度总分100。
 * 总分 >= 60 视为可疑机器人，>= 80 视为高置信度机器人。
 *
 * 配置开关：serverguard.security.super-evolution.bot-fingerprint
 */
@Service
public class BotFingerprintDetector {

    private final ServerGuardConfig config;

    /**
     * 每个玩家的行为指纹档案（playerName → BotProfile）
     * BotProfile累积各维度的行为数据和评分
     */
    private final Map<String, BotProfile> playerProfiles = new ConcurrentHashMap<>();

    /**
     * 追踪IP下的所有玩家名称（IP → 玩家名称集合）
     * 用于检测代理Bot（一个IP大量不同账号）
     */
    private final Map<String, Set<String>> ipPlayerMap = new ConcurrentHashMap<>();

    private final AtomicLong totalEvaluations = new AtomicLong(0);
    private final AtomicLong flaggedCount = new AtomicLong(0);
    private final AtomicLong highConfidenceCount = new AtomicLong(0);

    /**
     * 各维度最大子分数 — 满分100
     */
    private static final int MAX_TIMING_SCORE = 25;
    private static final int MAX_NAME_SCORE = 25;
    private static final int MAX_MOVEMENT_SCORE = 20;
    private static final int MAX_CHAT_SCORE = 15;
    private static final int MAX_PING_SCORE = 15;

    /**
     * 机器人判定阈值
     */
    private static final int SUSPICIOUS_THRESHOLD = 60;  // 可疑
    private static final int BOT_THRESHOLD = 80;          // 确认Bot

    /**
     * 批量登录检测窗口（毫秒）— 此窗口内从同一IP登录 >= 阈值 个账号视为批量Bot
     */
    private static final long BATCH_LOGIN_WINDOW_MS = 30_000;
    private static final int BATCH_LOGIN_THRESHOLD = 4;

    /**
     * 登录间隔精确度阈值（毫秒）— 连续登录间隔偏差小于此值视为时间Bot模式
     */
    private static final long PRECISE_INTERVAL_THRESHOLD_MS = 500;

    /**
     * 无参构造函数 — 测试/默认配置使用
     */
    public BotFingerprintDetector() {
        this(new ServerGuardConfig());
    }

    /**
     * Spring 注入构造函数
     * @param config 全局配置，提供模块开关控制
     */
    public BotFingerprintDetector(ServerGuardConfig config) {
        this.config = config;
    }

    /**
     * 记录玩家登录事件 — 分析登录时序和命名模式
     *
     * @param playerName 玩家名称
     * @param playerUUID 玩家UUID
     * @param ip         登录IP地址
     * @param timestamp  登录时间戳
     * @return 如果玩家已被判定为Bot且达到阈值，返回检测结果
     */
    public FingerprintResult recordLogin(String playerName, String playerUUID, String ip, Instant timestamp) {
        if (!config.getSecurity().getSuperEvolution().isBotFingerprint()) {
            return FingerprintResult.clean();
        }

        totalEvaluations.incrementAndGet();
        BotProfile profile = playerProfiles.computeIfAbsent(playerName, k -> new BotProfile(playerName, playerUUID));

        // 1. 登录时序指纹分析
        int timingScore = analyzeLoginTiming(profile, ip, timestamp);

        // 2. 命名模式指纹分析
        int nameScore = analyzeNamePattern(playerName);

        // 3. IP关联分析 — 同一IP下的账号数量
        Set<String> sameIpPlayers = ipPlayerMap.computeIfAbsent(ip, k -> ConcurrentHashMap.newKeySet());
        sameIpPlayers.add(playerName);
        int ipAssociationBonus = Math.min(15, sameIpPlayers.size() * 5); // 同一IP下账号越多，越可疑

        // 更新档案
        profile.lastLoginTime = timestamp;
        profile.loginCount++;
        profile.timingScore = timingScore;
        profile.nameScore = nameScore;
        profile.ipAssociationScore = ipAssociationBonus;

        // 计算当前总分
        profile.recalculateTotal();

        return evaluateProfile(profile);
    }

    /**
     * 记录玩家移动数据 — 分析移动熵值
     *
     * @param playerName 玩家名称
     * @param deltaX     X轴位移量
     * @param deltaZ     Z轴位移量
     * @param onGround   是否在地面
     * @param timestamp  移动时间戳
     * @return 检测结果
     */
    public FingerprintResult recordMovement(String playerName, double deltaX, double deltaZ,
                                             boolean onGround, Instant timestamp) {
        if (!config.getSecurity().getSuperEvolution().isBotFingerprint()) {
            return FingerprintResult.clean();
        }

        BotProfile profile = playerProfiles.get(playerName);
        if (profile == null) return FingerprintResult.clean();

        double distance = Math.sqrt(deltaX * deltaX + deltaZ * deltaZ);
        profile.addMovementSample(distance, timestamp);

        // 分析移动熵值
        int movementScore = analyzeMovementEntropy(profile);
        profile.movementScore = movementScore;
        profile.recalculateTotal();

        return evaluateProfile(profile);
    }

    /**
     * 记录玩家聊天消息 — 分析聊天模式
     *
     * @param playerName 玩家名称
     * @param message    聊天消息内容
     * @param timestamp  消息时间戳
     * @return 检测结果
     */
    public FingerprintResult recordChat(String playerName, String message, Instant timestamp) {
        if (!config.getSecurity().getSuperEvolution().isBotFingerprint()) {
            return FingerprintResult.clean();
        }

        BotProfile profile = playerProfiles.get(playerName);
        if (profile == null) return FingerprintResult.clean();

        profile.addChatMessage(message, timestamp);

        // 分析聊天模式
        int chatScore = analyzeChatPattern(profile);
        profile.chatScore = chatScore;
        profile.recalculateTotal();

        return evaluateProfile(profile);
    }

    /**
     * 记录玩家延迟数据 — 分析ping指纹
     *
     * @param playerName 玩家名称
     * @param latencyMs  延迟（毫秒）
     * @param timestamp  时间戳
     * @return 检测结果
     */
    public FingerprintResult recordPing(String playerName, long latencyMs, Instant timestamp) {
        if (!config.getSecurity().getSuperEvolution().isBotFingerprint()) {
            return FingerprintResult.clean();
        }

        BotProfile profile = playerProfiles.get(playerName);
        if (profile == null) return FingerprintResult.clean();

        profile.addPingSample(latencyMs, timestamp);

        // 分析延迟模式
        int pingScore = analyzePingPattern(profile);
        profile.pingScore = pingScore;
        profile.recalculateTotal();

        return evaluateProfile(profile);
    }

    /**
     * 获取玩家的当前Bot评分
     *
     * @param playerName 玩家名称
     * @return 0-100的Bot评分，-1表示无数据
     */
    public int getBotScore(String playerName) {
        BotProfile profile = playerProfiles.get(playerName);
        return (profile != null) ? profile.totalScore : -1;
    }

    /**
     * 判断玩家是否为机器人（达到高置信度阈值）
     *
     * @param playerName 玩家名称
     * @return true=高置信度机器人
     */
    public boolean isBot(String playerName) {
        BotProfile profile = playerProfiles.get(playerName);
        return profile != null && profile.totalScore >= BOT_THRESHOLD;
    }

    /**
     * 判断玩家是否为可疑（达到可疑阈值但未达确信阈值）
     *
     * @param playerName 玩家名称
     * @return true=可疑
     */
    public boolean isSuspicious(String playerName) {
        BotProfile profile = playerProfiles.get(playerName);
        return profile != null && profile.totalScore >= SUSPICIOUS_THRESHOLD && profile.totalScore < BOT_THRESHOLD;
    }

    /**
     * 玩家离线时清理追踪数据
     *
     * @param playerName 离线玩家名称
     */
    public void clearPlayer(String playerName) {
        playerProfiles.remove(playerName);
    }

    /**
     * 获取模块运行状态
     *
     * @return 包含计数器、活跃玩家数、Bot判定数的Map
     */
    public Map<String, Object> getStatus() {
        Map<String, Object> status = new LinkedHashMap<>();
        status.put("totalEvaluations", totalEvaluations.get());
        status.put("flaggedCount", flaggedCount.get());
        status.put("highConfidenceCount", highConfidenceCount.get());
        status.put("activeTrackedPlayers", playerProfiles.size());
        status.put("trackedIPs", ipPlayerMap.size());
        return status;
    }

    /**
     * 分析登录时序 — 检测批量登录和精确间隔登录
     * 同一IP在短时间内登录大量账号 → 机器人集群
     * 连续登录时间间隔高度一致 → 脚本化操作
     */
    private int analyzeLoginTiming(BotProfile profile, String ip, Instant timestamp) {
        int score = 0;

        // 检测同一IP的批量登录
        Set<String> sameIpPlayers = ipPlayerMap.getOrDefault(ip, Set.of());
        if (sameIpPlayers.size() >= BATCH_LOGIN_THRESHOLD) {
            // 统计此IP在批量窗口内的登录数
            long windowStart = timestamp.toEpochMilli() - BATCH_LOGIN_WINDOW_MS;
            long recentLogins = sameIpPlayers.stream()
                    .filter(name -> {
                        BotProfile p = playerProfiles.get(name);
                        return p != null && p.lastLoginTime != null
                                && p.lastLoginTime.toEpochMilli() > windowStart;
                    })
                    .count();
            if (recentLogins >= BATCH_LOGIN_THRESHOLD) {
                score += 20; // 批量登录 — 高嫌疑
            }
        }

        // 检测登录间隔精确度
        profile.loginTimestamps.add(timestamp.toEpochMilli());
        while (profile.loginTimestamps.size() > 10) {
            profile.loginTimestamps.remove(0);
        }

        if (profile.loginTimestamps.size() >= 3) {
            List<Long> timestamps = profile.loginTimestamps;
            List<Long> intervals = new ArrayList<>();
            for (int i = 1; i < timestamps.size(); i++) {
                intervals.add(timestamps.get(i) - timestamps.get(i - 1));
            }

            // 计算间隔的变化程度（方差）
            double mean = intervals.stream().mapToLong(Long::longValue).average().orElse(0);
            double variance = intervals.stream()
                    .mapToDouble(v -> Math.pow(v - mean, 2))
                    .average().orElse(0);
            double stdDev = Math.sqrt(variance);

            // 标准差极小 → 登录间隔高度一致 → 脚本化行为
            if (stdDev < PRECISE_INTERVAL_THRESHOLD_MS && intervals.size() >= 3) {
                score += 15;
            }
        }

        return Math.min(score, MAX_TIMING_SCORE);
    }

    /**
     * 分析玩家名称模式 — 检测随机字符串和已知Bot命名规范
     * Bot命名特征：
     * - 高比例的数字/随机字符
     * - 全部小写/大写无意义字符串
     * - 已知Bot前缀/后缀模式
     */
    private int analyzeNamePattern(String playerName) {
        int score = 0;

        if (playerName == null || playerName.isEmpty()) {
            return score;
        }

        // 统计字符组成
        int digitCount = 0;
        int upperCount = 0;
        int lowerCount = 0;
        for (char c : playerName.toCharArray()) {
            if (Character.isDigit(c)) digitCount++;
            else if (Character.isUpperCase(c)) upperCount++;
            else if (Character.isLowerCase(c)) lowerCount++;
        }

        int totalChars = playerName.length();

        // 数字比例过高（如 "Player12345"）
        if (totalChars > 0 && (double) digitCount / totalChars > 0.5) {
            score += 10;
        }

        // 名称熵值分析 — 统计唯一字符比例
        Set<Character> uniqueChars = new HashSet<>();
        for (char c : playerName.toCharArray()) uniqueChars.add(c);
        double uniqueness = (double) uniqueChars.size() / totalChars;

        // 重复字符比例过高（如 "aaaabbbb"）或唯一性过高（如 "qwerty123"）
        // 都是Bot命名的常见特征
        if (uniqueness < 0.4 || uniqueness > 0.9) {
            score += 8;
        }

        // 已知Bot命名模式检测
        String lower = playerName.toLowerCase();
        if (lower.contains("bot") || lower.contains("robot") || lower.contains("auto")
                || lower.contains("hack") || lower.contains("cheat") || lower.startsWith("player_")
                || lower.matches(".*[0-9]{4,}$")  // 末尾4个以上数字
                || lower.matches("^[a-z]{1,3}[0-9]{4,}$")) { // 短字母+多个数字
            score += 12;
        }

        // 名称长度异常（过短或过长）
        if (playerName.length() < 3 || playerName.length() > 16) {
            score += 5;
        }

        return Math.min(score, MAX_NAME_SCORE);
    }

    /**
     * 分析移动熵值 — 检测机械性移动模式
     * 正常玩家的移动速度、方向变化有自然波动
     * Baritone等Pathfinding机器人的路径极度平滑
     * Idle机器人则完全静止
     */
    private int analyzeMovementEntropy(BotProfile profile) {
        int score = 0;
        List<Double> samples = profile.movementSamples;

        if (samples.size() < 20) {
            return 0; // 样本不足，无法判断
        }

        // 计算移动量的均值和标准差
        double sum = 0;
        int nonZeroCount = 0;
        for (double d : samples) {
            sum += d;
            if (d > 0.001) nonZeroCount++;
        }
        double mean = sum / samples.size();
        double variance = samples.stream()
                .mapToDouble(d -> Math.pow(d - mean, 2))
                .average().orElse(0);
        double stdDev = Math.sqrt(variance);

        // 几乎完全不动 — 可能是不移动的Idle机器人
        double movementRatio = (double) nonZeroCount / samples.size();
        if (movementRatio < 0.1) {
            score += 12;
        }

        // 移动极其规律（标准差极小且均值非零）— Pathfinding机器人
        if (stdDev < 0.05 && mean > 0.1 && nonZeroCount > samples.size() * 0.8) {
            score += 15;
        }

        // 移动模式极度一致 — 全部样本几乎完全相同的移动量
        if (stdDev < 0.01 && movementRatio > 0.9 && nonZeroCount > 10) {
            score += 18;
        }

        return Math.min(score, MAX_MOVEMENT_SCORE);
    }

    /**
     * 分析聊天模式 — 检测垃圾消息和完全静默
     * SpamBot：发送完全相同的消息
     * SilentBot：从不聊天
     */
    private int analyzeChatPattern(BotProfile profile) {
        int score = 0;

        if (profile.chatMessages.isEmpty()) {
            return 0;
        }

        // 检测重复消息（完全相同的内容多次发送）
        Map<String, Integer> messageCounts = new HashMap<>();
        for (String msg : profile.chatMessages) {
            messageCounts.merge(msg.toLowerCase().trim(), 1, Integer::sum);
        }

        int maxRepeat = messageCounts.values().stream().max(Integer::compareTo).orElse(0);
        double repeatRatio = (double) maxRepeat / profile.chatMessages.size();

        // 同一消息重复超过70% — 垃圾广告机器人
        if (repeatRatio > 0.7 && profile.chatMessages.size() >= 5) {
            score += 12;
        }

        // 消息发送速度异常 — 短时间大量消息
        int recentCount = 0;
        long now = System.currentTimeMillis();
        for (long ts : profile.chatTimestamps) {
            if (now - ts < 10_000) recentCount++;
        }
        if (recentCount > 10) {
            score += 8;
        }

        return Math.min(score, MAX_CHAT_SCORE);
    }

    /**
     * 分析延迟指纹 — 检测非正常网络环境的ping模式
     * 机器人常见特征：极高延迟（代理/VPN）、极低且稳定延迟（托管数据中心）、
     * ping波动极低（说明是托管环境而非家庭网络）
     */
    private int analyzePingPattern(BotProfile profile) {
        int score = 0;
        List<Long> pings = profile.pingSamples;

        if (pings.size() < 5) {
            return 0; // 样本不足
        }

        double mean = pings.stream().mapToLong(Long::longValue).average().orElse(0);
        double variance = pings.stream()
                .mapToDouble(p -> Math.pow(p - mean, 2))
                .average().orElse(0);
        double stdDev = Math.sqrt(variance);

        // 极低且极度稳定的延迟（波动<5ms）— 数据中心托管环境特征
        if (mean < 20 && stdDev < 5) {
            score += 12;
        }

        // 极高延迟（>300ms）— 可能是海外代理/VPN
        if (mean > 300) {
            score += 8;
        }

        // 延迟波动极低但均值正常 — 非住宅网络特征
        // 正常家庭网络ping波动通常在10-50ms之间
        if (stdDev < 3 && pings.size() >= 10) {
            score += 10;
        }

        return Math.min(score, MAX_PING_SCORE);
    }

    /**
     * 评估玩家档案，生成检测结果
     */
    private FingerprintResult evaluateProfile(BotProfile profile) {
        if (profile.totalScore >= BOT_THRESHOLD) {
            highConfidenceCount.incrementAndGet();
            List<String> reasons = new ArrayList<>();
            reasons.add("TOTAL_SCORE: " + profile.totalScore + "/100 >= " + BOT_THRESHOLD + " (BOT)");
            reasons.add("TIMING: " + profile.timingScore + "/" + MAX_TIMING_SCORE);
            reasons.add("NAME: " + profile.nameScore + "/" + MAX_NAME_SCORE);
            reasons.add("MOVEMENT: " + profile.movementScore + "/" + MAX_MOVEMENT_SCORE);
            reasons.add("CHAT: " + profile.chatScore + "/" + MAX_CHAT_SCORE);
            reasons.add("PING: " + profile.pingScore + "/" + MAX_PING_SCORE);
            return FingerprintResult.blocked(reasons);
        }

        if (profile.totalScore >= SUSPICIOUS_THRESHOLD) {
            flaggedCount.incrementAndGet();
            List<String> reasons = new ArrayList<>();
            reasons.add("TOTAL_SCORE: " + profile.totalScore + "/100 >= " + SUSPICIOUS_THRESHOLD + " (SUSPICIOUS)");
            return FingerprintResult.flagged(reasons);
        }

        return FingerprintResult.clean();
    }

    /**
     * 内部机器人行为档案 — 累积每个玩家的多维度行为数据
     * 使用非线程安全容器，通过外部 ConcurrentHashMap 保护访问
     */
    private static class BotProfile {
        final String playerName;
        final String playerUUID;

        int loginCount = 0;
        Instant lastLoginTime;

        // 各维度子分数
        int timingScore = 0;
        int nameScore = 0;
        int ipAssociationScore = 0;
        int movementScore = 0;
        int chatScore = 0;
        int pingScore = 0;
        int totalScore = 0;

        // 行为数据采样
        final List<Long> loginTimestamps = new ArrayList<>();
        final List<Double> movementSamples = new ArrayList<>();
        final List<String> chatMessages = new ArrayList<>();
        final List<Long> chatTimestamps = new ArrayList<>();
        final List<Long> pingSamples = new ArrayList<>();

        BotProfile(String playerName, String playerUUID) {
            this.playerName = playerName;
            this.playerUUID = playerUUID;
        }

        void addMovementSample(double distance, Instant timestamp) {
            movementSamples.add(distance);
            // 保留最近100个移动样本
            while (movementSamples.size() > 100) {
                movementSamples.remove(0);
            }
        }

        void addChatMessage(String message, Instant timestamp) {
            chatMessages.add(message);
            chatTimestamps.add(timestamp.toEpochMilli());
            // 保留最近50条消息
            while (chatMessages.size() > 50) {
                chatMessages.remove(0);
                chatTimestamps.remove(0);
            }
        }

        void addPingSample(long latencyMs, Instant timestamp) {
            pingSamples.add(latencyMs);
            // 保留最近30个延迟样本
            while (pingSamples.size() > 30) {
                pingSamples.remove(0);
            }
        }

        /**
         * 重新计算总分 — 各维度分数加权求和，上限100
         */
        void recalculateTotal() {
            totalScore = Math.min(100,
                    timingScore + nameScore + ipAssociationScore + movementScore + chatScore + pingScore);
        }
    }

    /**
     * 机器人指纹检测结果 — 不可变结果类
     */
    public static class FingerprintResult {
        private final boolean clean;
        private final boolean flagged;
        private final boolean blocked;
        private final List<String> reasons;

        private FingerprintResult(boolean clean, boolean flagged, boolean blocked, List<String> reasons) {
            this.clean = clean;
            this.flagged = flagged;
            this.blocked = blocked;
            this.reasons = reasons;
        }

        /** 无异常 — 正常玩家行为模式 */
        public static FingerprintResult clean() {
            return new FingerprintResult(true, false, false, List.of());
        }

        /** 可疑 — 部分行为模式可疑但未达Bot阈值 */
        public static FingerprintResult flagged(List<String> reasons) {
            return new FingerprintResult(false, true, false, reasons);
        }

        /** 已确认 — 多维度行为特征匹配机器人指纹，建议封禁 */
        public static FingerprintResult blocked(List<String> reasons) {
            return new FingerprintResult(false, false, true, reasons);
        }

        public boolean isClean() { return clean; }
        public boolean isFlagged() { return flagged; }
        public boolean isBlocked() { return blocked; }
        public List<String> getReasons() { return reasons; }
    }
}
