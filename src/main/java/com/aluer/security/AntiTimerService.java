package com.aluer.security;

import com.aluer.config.ServerGuardConfig;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * 游戏加速（Timer）检测服务 — V5.0 反作弊扩展模块
 *
 * 检测原理：
 * 1. 移动Tick间隔检测 — Minecraft标准时钟频率为20 ticks/秒（50ms/tick）。
 *    Timer hack通过修改游戏客户端时钟加速游戏速度，使客户端以>20 ticks/秒
 *    的频率发送移动数据包。本模块追踪每个玩家相邻两次移动的时间间隔，
 *    如果间隔持续低于45ms（对应约22.2 ticks/秒），表明存在Timer加速。
 * 2. 连续异常计数 — 单次短间隔可能由网络抖动造成，需要连续检测到多次
 *    异常短间隔才标记，防止误报。
 * 3. 间隔模式分析 — 正常玩家的移动间隔有自然波动（网络延迟、TPS波动），
 *    而Timer hack会产生高度一致的加速间隔，通过标准差分析检测机械性加速。
 * 4. 时间戳跳跃检测 — 检测客户端时间戳是否快于服务器时间，
 *    这是Timer hack的典型特征（客户端时间比服务器时间推进更快）。
 *
 * 配置开关：serverguard.security.super-evolution.anti-timer
 */
@Service
public class AntiTimerService {

    private final ServerGuardConfig config;

    /**
     * 追踪每个玩家的移动时间间隔历史（playerName -> 间隔记录列表）
     * 用于计算滑动窗口内的平均tick间隔
     */
    private final Map<String, List<MovementInterval>> playerIntervalHistory = new ConcurrentHashMap<>();

    /**
     * 追踪每个玩家连续异常短间隔的次数（playerName -> 连续异常计数）
     * 用于判断是偶发延迟还是持续加速
     */
    private final Map<String, Integer> playerConsecutiveAnomalies = new ConcurrentHashMap<>();

    /**
     * 追踪每个玩家最近的绝对时间戳（playerName -> 上次移动的Instant）
     * 用于计算两次移动之间的真实时间间隔
     */
    private final Map<String, Instant> playerLastMoveTime = new ConcurrentHashMap<>();

    private final AtomicLong totalChecks = new AtomicLong(0);
    private final AtomicLong flaggedCount = new AtomicLong(0);

    /**
     * 正常tick间隔（毫秒）— Minecraft标准为50ms/tick
     */
    private static final double NORMAL_TICK_INTERVAL_MS = 50.0;

    /**
     * 异常短间隔阈值（毫秒）— 间隔低于此值表明加速
     * 45ms对应约22.2 ticks/秒，留有一定检测余量
     */
    private static final double MIN_TICK_INTERVAL_MS = 45.0;

    /**
     * 触发标记所需的最小连续异常次数
     * 至少需要3次连续异常才能排除网络抖动
     */
    private static final int MIN_CONSECUTIVE_ANOMALIES = 3;

    /**
     * 间隔分析窗口大小 — 取最近N次移动进行分析
     */
    private static final int ANALYSIS_WINDOW_SIZE = 20;

    /**
     * 标准差阈值 — 间隔标准差低于此值表明机械性加速
     * 正常玩家由于网络波动，间隔标准差通常在5ms以上
     */
    private static final double STD_DEV_THRESHOLD = 3.0;

    /**
     * 每个玩家保留的最大间隔记录数
     */
    private static final int MAX_INTERVAL_RECORDS = 50;

    /**
     * 时间戳跳跃检测阈值（毫秒）— 客户端时间快于服务器时间的容差
     * 如果累计超前超过此值，表明存在Timer加速
     */
    private static final long TIMESTAMP_JUMP_THRESHOLD_MS = 500;

    /**
     * 无参构造函数 — 测试/默认配置使用
     */
    public AntiTimerService() {
        this(new ServerGuardConfig());
    }

    /**
     * Spring 注入构造函数
     * @param config 全局配置，提供模块开关控制
     */
    public AntiTimerService(ServerGuardConfig config) {
        this.config = config;
    }

    /**
     * 检测玩家移动tick间隔是否异常（Timer加速检测）
     *
     * @param playerName 玩家名称
     * @param playerUUID 玩家UUID
     * @param clientTimestamp 客户端报告的时间戳（用于检测时间跳跃）
     * @param serverTimestamp 服务器接收时间戳
     * @return 检测结果
     */
    public TimerCheckResult detect(String playerName, String playerUUID,
                                    Instant clientTimestamp, Instant serverTimestamp) {
        // 模块开关检查 — 关闭时跳过所有检测直接返回安全结果
        if (!config.getSecurity().getSuperEvolution().isAntiTimer()) {
            return TimerCheckResult.clean();
        }

        totalChecks.incrementAndGet();
        List<String> reasons = new ArrayList<>();

        // 获取或创建玩家间隔历史
        List<MovementInterval> intervalHistory = playerIntervalHistory.computeIfAbsent(
                playerName, k -> new ArrayList<>());

        // 计算与上次移动的时间间隔
        Instant lastMove = playerLastMoveTime.get(playerName);
        if (lastMove != null) {
            long intervalMs = serverTimestamp.toEpochMilli() - lastMove.toEpochMilli();

            // 记录合理的间隔（跳过异常大的间隔，如玩家长时间不动）
            if (intervalMs > 0 && intervalMs < 5000) {
                MovementInterval mi = new MovementInterval(serverTimestamp, intervalMs, clientTimestamp);
                intervalHistory.add(mi);
                // 控制列表大小
                while (intervalHistory.size() > MAX_INTERVAL_RECORDS) {
                    intervalHistory.remove(0);
                }

                // 1. Tick间隔检测 — 检查当前间隔是否过短
                if (intervalMs < MIN_TICK_INTERVAL_MS) {
                    // 连续异常计数递增
                    int consecutive = playerConsecutiveAnomalies.merge(playerName, 1, Integer::sum);

                    if (consecutive >= MIN_CONSECUTIVE_ANOMALIES) {
                        // 连续多次短间隔 — 确认为Timer加速
                        flaggedCount.incrementAndGet();
                        reasons.add("SUSTAINED_TIMER: " + consecutive + " consecutive moves at "
                                + intervalMs + "ms intervals (threshold: "
                                + String.format("%.1f", MIN_TICK_INTERVAL_MS) + "ms)");
                    } else {
                        // 短间隔但次数不够 — 仅标记可疑
                        reasons.add("FAST_TICK: interval " + intervalMs + "ms (consecutive: "
                                + consecutive + "/" + MIN_CONSECUTIVE_ANOMALIES + ")");
                    }
                } else {
                    // 间隔正常，重置连续异常计数
                    playerConsecutiveAnomalies.put(playerName, 0);
                }
            }
        }
        // 更新最后移动时间
        playerLastMoveTime.put(playerName, serverTimestamp);

        // 2. 间隔模式分析 — 检测机械性加速
        if (intervalHistory.size() >= ANALYSIS_WINDOW_SIZE) {
            List<MovementInterval> recentIntervals = intervalHistory.subList(
                    intervalHistory.size() - ANALYSIS_WINDOW_SIZE, intervalHistory.size());

            double sum = 0;
            double sumSq = 0;
            int count = 0;

            for (MovementInterval mi : recentIntervals) {
                double ms = mi.intervalMs;
                sum += ms;
                sumSq += ms * ms;
                count++;
            }

            double mean = sum / count;
            double variance = (sumSq / count) - (mean * mean);
            double stdDev = Math.sqrt(Math.max(0, variance));

            // 平均间隔显著低于正常值且标准差极小 — 机械性Timer加速
            if (mean < MIN_TICK_INTERVAL_MS && stdDev < STD_DEV_THRESHOLD) {
                reasons.add("MECHANICAL_TIMER: avg interval " + String.format("%.2f", mean)
                        + "ms, stdDev " + String.format("%.3f", stdDev) + "ms (normal: "
                        + String.format("%.1f", NORMAL_TICK_INTERVAL_MS) + "ms)");
            }
        }

        // 3. 时间戳跳跃检测 — 检测客户端时间是否超前服务器时间
        // 累积计算客户端时间戳与服务器时间戳的偏差
        long clientAheadMs = clientTimestamp.toEpochMilli() - serverTimestamp.toEpochMilli();
        if (clientAheadMs > TIMESTAMP_JUMP_THRESHOLD_MS) {
            reasons.add("TIMESTAMP_JUMP: client ahead of server by " + clientAheadMs
                    + "ms (threshold: " + TIMESTAMP_JUMP_THRESHOLD_MS + "ms)");
        }

        // 汇总结果
        if (reasons.size() >= 2) {
            flaggedCount.incrementAndGet();
            return TimerCheckResult.flagged(reasons);
        } else if (reasons.size() == 1) {
            return TimerCheckResult.suspicious(reasons);
        }

        return TimerCheckResult.clean();
    }

    /**
     * 玩家离线时清理其追踪数据，释放内存
     * @param playerName 离线玩家名称
     */
    public void clearPlayer(String playerName) {
        playerIntervalHistory.remove(playerName);
        playerConsecutiveAnomalies.remove(playerName);
        playerLastMoveTime.remove(playerName);
    }

    /**
     * 获取模块运行状态
     * @return 包含计数器和活跃追踪玩家数的Map
     */
    public Map<String, Object> getStatus() {
        Map<String, Object> status = new LinkedHashMap<>();
        status.put("totalChecks", totalChecks.get());
        status.put("flaggedCount", flaggedCount.get());
        status.put("activeTrackedPlayers", playerIntervalHistory.size());
        return status;
    }

    /**
     * 内部移动间隔记录 — 记录单次移动间隔的时间和客户端信息
     */
    private static class MovementInterval {
        final Instant serverTimestamp;
        final long intervalMs;
        final Instant clientTimestamp;

        MovementInterval(Instant serverTimestamp, long intervalMs, Instant clientTimestamp) {
            this.serverTimestamp = serverTimestamp;
            this.intervalMs = intervalMs;
            this.clientTimestamp = clientTimestamp;
        }
    }

    /**
     * Timer检测结果 — 不可变结果类
     */
    public static class TimerCheckResult {
        private final boolean flagged;
        private final boolean suspicious;
        private final List<String> reasons;

        private TimerCheckResult(boolean flagged, boolean suspicious, List<String> reasons) {
            this.flagged = flagged;
            this.suspicious = suspicious;
            this.reasons = reasons;
        }

        /** 无异常 — 正常tick速度 */
        public static TimerCheckResult clean() {
            return new TimerCheckResult(false, false, List.of());
        }

        /** 可疑 — 间隔较短但证据不足（次数不够或可能为网络延迟） */
        public static TimerCheckResult suspicious(List<String> reasons) {
            return new TimerCheckResult(false, true, reasons);
        }

        /** 已标记 — 多项规则命中，高度可能使用Timer加速 */
        public static TimerCheckResult flagged(List<String> reasons) {
            return new TimerCheckResult(true, false, reasons);
        }

        public boolean isFlagged() { return flagged; }
        public boolean isSuspicious() { return suspicious; }
        public boolean isClean() { return !flagged && !suspicious; }
        public List<String> getReasons() { return reasons; }
    }
}
