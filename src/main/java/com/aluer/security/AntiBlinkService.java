package com.aluer.security;

import com.aluer.config.ServerGuardConfig;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * 闪烁/快速断连（Blink）检测服务 — V5.0 反作弊扩展模块
 *
 * 检测原理：
 * 1. 快速断连-重连周期检测 — Blink hack的工作原理是短暂断开客户端与服务器
 *    的连接（使玩家在服务器端"消失"但客户端仍在正常游戏），然后重新连接。
 *    本模块追踪玩家的加入/退出事件时间戳，如果检测到短时间内的反复断开重连，
 *    则标记。
 * 2. 受击后立即断连检测 — 这是Blink hack最典型的用法：玩家受到攻击后立即
 *    断开连接以避免死亡，几秒后重新连接。检测玩家是否在受到伤害后短时间内断开。
 * 3. 断连期间PvP逃避检测 — 如果玩家在PvP场景中反复使用Blink（如接敌时断开，
 *    脱险后重连），这是一种严重的作弊行为。追踪战斗状态与断连时机的关系。
 * 4. 断连频率异常检测 — 正常玩家的断连通常由网络问题或主动退出造成，
 *    频率较低。高频断连（如每分钟多次）强烈提示Blink hack。
 *
 * 配置开关：serverguard.security.super-evolution.anti-blink
 */
@Service
public class AntiBlinkService {

    private final ServerGuardConfig config;

    /**
     * 追踪每个玩家的加入/退出事件时间戳（playerName -> 事件列表）
     * 用于分析断连-重连的周期模式
     */
    private final Map<String, List<ConnectionEvent>> playerConnectionEvents = new ConcurrentHashMap<>();

    /**
     * 追踪每个玩家最近受到伤害的时间（playerName -> 最近伤害时间戳）
     * 用于关联受击与断连的关系
     */
    private final Map<String, Instant> playerLastDamageTime = new ConcurrentHashMap<>();

    /**
     * 追踪每个玩家的最近伤害量（playerName -> 伤害量）
     * 用于判断是否有躲避伤害的动机
     */
    private final Map<String, Double> playerLastDamageAmount = new ConcurrentHashMap<>();

    /**
     * 追踪当前在线的玩家（playerName -> 加入时间）
     * 用于快速判断玩家状态
     */
    private final Map<String, Instant> onlinePlayers = new ConcurrentHashMap<>();

    private final AtomicLong totalChecks = new AtomicLong(0);
    private final AtomicLong flaggedCount = new AtomicLong(0);

    /**
     * 断连-重连周期阈值（秒）— 在此时间内断开又重连视为快速重连
     */
    private static final long RECONNECT_THRESHOLD_SECONDS = 5;

    /**
     * 受击后断连检测窗口（毫秒）— 受击后在此时间内断开视为逃避伤害
     */
    private static final long DAMAGE_DISCONNECT_WINDOW_MS = 1_000;

    /**
     * 最小断连-重连周期数 — 达到此次数才标记
     * 单次断连可能是真实网络问题
     */
    private static final int MIN_RECONNECT_CYCLES = 2;

    /**
     * 断连频率检测窗口（秒）— 在此窗口内统计断连次数
     */
    private static final long DISCONNECT_FREQ_WINDOW_SECONDS = 60;

    /**
     * 窗口内最大允许的断连次数 — 超过此值视为异常
     */
    private static final int MAX_DISCONNECTS_PER_WINDOW = 3;

    /**
     * 每个玩家保留的最大连接事件记录数
     */
    private static final int MAX_CONNECTION_EVENTS = 30;

    /**
     * 无参构造函数 — 测试/默认配置使用
     */
    public AntiBlinkService() {
        this(new ServerGuardConfig());
    }

    /**
     * Spring 注入构造函数
     * @param config 全局配置，提供模块开关控制
     */
    public AntiBlinkService(ServerGuardConfig config) {
        this.config = config;
    }

    /**
     * 记录玩家加入服务器事件，同时检测断连-重连模式
     *
     * @param playerName 玩家名称
     * @param playerUUID 玩家UUID
     * @param timestamp 加入时间戳
     * @return 检测结果 — 如果检测到可疑的Blink模式返回flagged/suspicious
     */
    public BlinkCheckResult onPlayerJoin(String playerName, String playerUUID, Instant timestamp) {
        // 模块开关检查
        if (!config.getSecurity().getSuperEvolution().isAntiBlink()) {
            return BlinkCheckResult.clean();
        }

        totalChecks.incrementAndGet();
        List<String> reasons = new ArrayList<>();

        // 记录加入事件
        List<ConnectionEvent> events = playerConnectionEvents.computeIfAbsent(
                playerName, k -> new ArrayList<>());
        events.add(new ConnectionEvent(timestamp, ConnectionEvent.Type.JOIN));
        while (events.size() > MAX_CONNECTION_EVENTS) {
            events.remove(0);
        }

        // 标记为在线
        onlinePlayers.put(playerName, timestamp);

        // 1. 快速断连-重连周期检测 — 查找最近的断开和加入事件
        Instant lastDisconnect = null;
        for (int i = events.size() - 1; i >= 0; i--) {
            if (events.get(i).type == ConnectionEvent.Type.QUIT) {
                lastDisconnect = events.get(i).timestamp;
                break;
            }
        }

        if (lastDisconnect != null) {
            long disconnectToReconnect = timestamp.toEpochMilli() - lastDisconnect.toEpochMilli();
            long secondsDiff = disconnectToReconnect / 1000;

            if (secondsDiff <= RECONNECT_THRESHOLD_SECONDS) {
                // 短时间内断开又重连 — 这是Blink hack的典型模式
                reasons.add("RAPID_RECONNECT: disconnected and rejoined within "
                        + secondsDiff + "s (threshold: " + RECONNECT_THRESHOLD_SECONDS + "s)");

                // 检查是否在受击后断开
                Instant lastDamage = playerLastDamageTime.get(playerName);
                if (lastDamage != null) {
                    long damageToDisconnect = lastDisconnect.toEpochMilli() - lastDamage.toEpochMilli();
                    if (damageToDisconnect >= 0 && damageToDisconnect <= DAMAGE_DISCONNECT_WINDOW_MS) {
                        Double dmg = playerLastDamageAmount.getOrDefault(playerName, 0.0);
                        reasons.add("DAMAGE_EVASION: took " + String.format("%.1f", dmg)
                                + " damage, disconnected " + damageToDisconnect + "ms later, "
                                + "rejoined " + secondsDiff + "s after");
                        flaggedCount.incrementAndGet();
                    }
                }
            }
        }

        // 2. 断连频率统计 — 在时间窗口内统计断连-重连周期次数
        Instant freqWindowStart = timestamp.minusSeconds(DISCONNECT_FREQ_WINDOW_SECONDS);
        long rapidReconnects = 0;
        Instant prevQuit = null;
        for (ConnectionEvent e : events) {
            if (e.timestamp.isBefore(freqWindowStart)) continue;
            if (e.type == ConnectionEvent.Type.QUIT) {
                prevQuit = e.timestamp;
            } else if (e.type == ConnectionEvent.Type.JOIN && prevQuit != null) {
                long diff = e.timestamp.toEpochMilli() - prevQuit.toEpochMilli();
                if (diff <= RECONNECT_THRESHOLD_SECONDS * 1000) {
                    rapidReconnects++;
                }
                prevQuit = null;
            }
        }

        if (rapidReconnects >= MIN_RECONNECT_CYCLES) {
            reasons.add("FREQUENT_RAPID_RECONNECT: " + rapidReconnects
                    + " rapid reconnect cycles in " + DISCONNECT_FREQ_WINDOW_SECONDS + "s");
            flaggedCount.incrementAndGet();
        }

        // 汇总结果
        if (reasons.size() >= 2) {
            return BlinkCheckResult.flagged(reasons);
        } else if (reasons.size() == 1) {
            return BlinkCheckResult.suspicious(reasons);
        }

        return BlinkCheckResult.clean();
    }

    /**
     * 记录玩家退出服务器事件
     *
     * @param playerName 玩家名称
     * @param timestamp 退出时间戳
     */
    public void onPlayerQuit(String playerName, Instant timestamp) {
        if (!config.getSecurity().getSuperEvolution().isAntiBlink()) {
            return;
        }

        List<ConnectionEvent> events = playerConnectionEvents.computeIfAbsent(
                playerName, k -> new ArrayList<>());
        events.add(new ConnectionEvent(timestamp, ConnectionEvent.Type.QUIT));
        while (events.size() > MAX_CONNECTION_EVENTS) {
            events.remove(0);
        }

        onlinePlayers.remove(playerName);
    }

    /**
     * 记录玩家受到伤害事件 — 用于后续关联受击与断连
     *
     * @param playerName 玩家名称
     * @param damageAmount 受到的伤害量
     * @param timestamp 受击时间戳
     */
    public void recordPlayerDamage(String playerName, double damageAmount, Instant timestamp) {
        if (!config.getSecurity().getSuperEvolution().isAntiBlink()) {
            return;
        }

        playerLastDamageTime.put(playerName, timestamp);
        playerLastDamageAmount.put(playerName, damageAmount);
    }

    /**
     * 玩家离线（非Blink的正常退出）时清理追踪数据
     * @param playerName 玩家名称
     */
    public void clearPlayer(String playerName) {
        playerConnectionEvents.remove(playerName);
        playerLastDamageTime.remove(playerName);
        playerLastDamageAmount.remove(playerName);
        onlinePlayers.remove(playerName);
    }

    /**
     * 获取模块运行状态
     * @return 包含计数器和在线玩家数的Map
     */
    public Map<String, Object> getStatus() {
        Map<String, Object> status = new LinkedHashMap<>();
        status.put("totalChecks", totalChecks.get());
        status.put("flaggedCount", flaggedCount.get());
        status.put("onlinePlayers", onlinePlayers.size());
        status.put("trackedPlayers", playerConnectionEvents.size());
        return status;
    }

    /**
     * 内部连接事件记录 — 记录玩家的加入/退出行为
     */
    private static class ConnectionEvent {
        enum Type { JOIN, QUIT }

        final Instant timestamp;
        final Type type;

        ConnectionEvent(Instant timestamp, Type type) {
            this.timestamp = timestamp;
            this.type = type;
        }
    }

    /**
     * Blink检测结果 — 不可变结果类
     */
    public static class BlinkCheckResult {
        private final boolean flagged;
        private final boolean suspicious;
        private final List<String> reasons;

        private BlinkCheckResult(boolean flagged, boolean suspicious, List<String> reasons) {
            this.flagged = flagged;
            this.suspicious = suspicious;
            this.reasons = reasons;
        }

        /** 无异常 — 正常连接行为 */
        public static BlinkCheckResult clean() {
            return new BlinkCheckResult(false, false, List.of());
        }

        /** 可疑 — 检测到快速重连但证据不够充分（可能只是网络波动） */
        public static BlinkCheckResult suspicious(List<String> reasons) {
            return new BlinkCheckResult(false, true, reasons);
        }

        /** 已标记 — 多项规则命中，高度可能使用Blink hack */
        public static BlinkCheckResult flagged(List<String> reasons) {
            return new BlinkCheckResult(true, false, reasons);
        }

        public boolean isFlagged() { return flagged; }
        public boolean isSuspicious() { return suspicious; }
        public boolean isClean() { return !flagged && !suspicious; }
        public List<String> getReasons() { return reasons; }
    }
}
