package com.aluer.security;

import com.aluer.config.ServerGuardConfig;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * 自动断线（AutoLog）检测服务 — V5.1 反作弊战斗模块
 *
 * 检测原理：
 * 1. 受伤后立即断线检测 — Meteor Client的AutoLog模块在玩家血量降至预设阈值
 *    以下时自动触发/disconnect。合法玩家断线需要：
 *    意识到危险 → 决定退出 → 按键打开聊天 → 输入/disconnect → 回车，至少
 *    需要500-1500ms。AutoLog在血量下降后1-50ms内即完成退出。
 *    如果玩家在受到伤害后500ms内断开连接且当时的血量低于8 HP（4颗心），
 *    则是自动化断线行为。
 * 2. 低血量脱战模式检测 — 追踪玩家血量趋势与断线事件的关联。正常玩家在网络
 *    超时时断开，时间随机分布。AutoLog用户总是恰好在血量降到危险区域时断开，
 *    形成"受伤→血量下降→断线"的固定因果链。如果玩家多次在血量降到
 *    某个固定阈值附近时断线（如每次都在3-5 HP区间），显示自动化触发。
 * 3. 重连循环检测 — AutoLog用户断线后经常快速重连以继续游戏。
 *    如果玩家在5秒内反复"断开→连接→断开"，且每次断线都发生在
 *    受伤后500ms内，则是AutoLog模式。追踪断线→重连的时间间隔循环。
 * 4. 区分合法断线 — 需要排除以下合法场景：
 *    - 网络超时（TCP连接需30秒无响应才超时，远超检测窗口）
 *    - 战斗日志（CombatLog）插件给予击杀信用（玩家会等待至少10秒后退出）
 *    - 正常退出（血量正常、非战斗状态）
 *    通过多重指标排除合法断线场景。
 *
 * 配置开关：serverguard.security.super-evolution.anti-auto-log
 */
@Service
public class AntiAutoLogService {

    private final ServerGuardConfig config;

    /**
     * 追踪每个玩家的血量历史（playerName -> 血量记录列表）
     * 记录最近的血量变化，用于分析断线前的血量趋势
     */
    private final Map<String, List<HealthRecord>> playerHealthHistory = new ConcurrentHashMap<>();

    /**
     * 追踪每个玩家最近的受伤事件（playerName -> 最近受伤记录）
     */
    private final Map<String, DamageRecord> playerLastDamage = new ConcurrentHashMap<>();

    /**
     * 追踪每个玩家的连接状态变化历史
     */
    private final Map<String, List<ConnectionEvent>> playerConnectionHistory = new ConcurrentHashMap<>();

    /**
     * 追踪每个玩家的当前在线状态
     */
    private final Map<String, Boolean> playerOnline = new ConcurrentHashMap<>();

    /**
     * 追踪疑似AutoLog的事件（playerName -> 可疑事件列表）
     */
    private final Map<String, List<Map<String, Object>>> autoLogEvents = new ConcurrentHashMap<>();

    private final AtomicLong totalDisconnects = new AtomicLong(0);
    private final AtomicLong flaggedCount = new AtomicLong(0);

    /**
     * 受伤后断线的可疑时间窗口（毫秒）
     * 在受伤后500ms内断线则标记 — 人类无法在此时间内做出退出决定
     */
    private static final long DAMAGE_DISCONNECT_WINDOW_MS = 500;

    /**
     * AutoLog触发的血量阈值（HP = 半心数）
     * 如果玩家在血量低于8 HP（4颗心）时断线，高度吻合AutoLog模式
     */
    private static final double AUTO_LOG_HP_THRESHOLD = 8.0;

    /**
     * 网络超时排除阈值（毫秒）
     * TCP连接超时至少需要30秒，所以30秒内的断线不是网络超时
     */
    private static final long NETWORK_TIMEOUT_FLOOR_MS = 30_000;

    /**
     * 断线-重连循环检测窗口（毫秒）
     * 5秒内反复断线重连即标记
     */
    private static final long RECONNECT_CYCLE_WINDOW_MS = 5_000;

    /**
     * 断线-重连循环最大标记次数
     */
    private static final int MAX_RECONNECT_CYCLES = 3;

    /**
     * 血量阈值一致性窗口（HP）
     * 如果玩家多次断线时血量都在同一狭窄范围内（±此值），显示自动化触发
     */
    private static final double CONSISTENT_THRESHOLD_RANGE = 2.0;

    /**
     * 每个玩家保留的最大记录数
     */
    private static final int MAX_RECORDS = 50;

    /**
     * 血量记录保留时间窗口（毫秒）
     */
    private static final long HEALTH_RECORD_WINDOW_MS = 60_000;

    /**
     * 无参构造函数 — 测试/默认配置使用
     */
    public AntiAutoLogService() {
        this(new ServerGuardConfig());
    }

    /**
     * Spring 注入构造函数
     * @param config 全局配置，提供模块开关控制
     */
    public AntiAutoLogService(ServerGuardConfig config) {
        this.config = config;
    }

    /**
     * 记录玩家当前血量
     * 应用于定期血量同步或血量变化事件
     *
     * @param playerName 玩家名称
     * @param health 当前血量（HP，1.0 = 半心，20.0 = 满血）
     * @param timestamp 时间戳
     */
    public void recordHealth(String playerName, double health, Instant timestamp) {
        if (!config.getSecurity().getSuperEvolution().isAntiAutoLog()) {
            return;
        }

        List<HealthRecord> history = playerHealthHistory.computeIfAbsent(
                playerName, k -> new ArrayList<>());
        history.add(new HealthRecord(health, timestamp));

        // 清理过期记录
        Instant cutoff = timestamp.minusMillis(HEALTH_RECORD_WINDOW_MS);
        history.removeIf(r -> r.timestamp.isBefore(cutoff));
        while (history.size() > MAX_RECORDS) {
            history.remove(0);
        }
    }

    /**
     * 记录玩家受到伤害
     * 应用于EntityDamageEvent监听
     *
     * @param playerName 玩家名称
     * @param damage 伤害量（HP，1.0 = 半心）
     * @param healthAfter 受伤后血量
     * @param timestamp 时间戳
     */
    public void recordDamage(String playerName, double damage, double healthAfter, Instant timestamp) {
        if (!config.getSecurity().getSuperEvolution().isAntiAutoLog()) {
            return;
        }

        playerLastDamage.put(playerName, new DamageRecord(damage, healthAfter, timestamp));

        // 同时更新血量追踪
        List<HealthRecord> history = playerHealthHistory.computeIfAbsent(
                playerName, k -> new ArrayList<>());
        history.add(new HealthRecord(healthAfter, timestamp));
        while (history.size() > MAX_RECORDS) {
            history.remove(0);
        }
    }

    /**
     * 记录玩家连接事件（上线）
     * 应用于PlayerJoinEvent监听
     *
     * @param playerName 玩家名称
     * @param timestamp 时间戳
     */
    public void recordConnect(String playerName, Instant timestamp) {
        if (!config.getSecurity().getSuperEvolution().isAntiAutoLog()) {
            return;
        }

        playerOnline.put(playerName, true);

        List<ConnectionEvent> connHistory = playerConnectionHistory.computeIfAbsent(
                playerName, k -> new ArrayList<>());
        connHistory.add(new ConnectionEvent(true, timestamp));
        while (connHistory.size() > MAX_RECORDS) {
            connHistory.remove(0);
        }
    }

    /**
     * 检测玩家断线事件 — 核心检测方法
     * 应用于PlayerQuitEvent/PlayerKickEvent/PlayerDisconnectEvent监听
     *
     * @param playerName 玩家名称
     * @param playerUUID 玩家UUID
     * @param isKicked 是否被踢出（true=服务器主动踢出，false=客户端主动断开）
     * @param timestamp 断线时间戳
     * @return 检测结果
     */
    public AutoLogCheckResult detectDisconnect(String playerName, String playerUUID,
                                                boolean isKicked, Instant timestamp) {
        // 模块开关检查
        if (!config.getSecurity().getSuperEvolution().isAntiAutoLog()) {
            return AutoLogCheckResult.clean();
        }

        // 如果是服务器踢出，不是客户端主动断线，跳过检测
        if (isKicked) {
            playerOnline.put(playerName, false);
            return AutoLogCheckResult.clean();
        }

        totalDisconnects.incrementAndGet();
        playerOnline.put(playerName, false);
        List<String> reasons = new ArrayList<>();

        List<ConnectionEvent> connHistory = playerConnectionHistory.computeIfAbsent(
                playerName, k -> new ArrayList<>());
        connHistory.add(new ConnectionEvent(false, timestamp));
        while (connHistory.size() > MAX_RECORDS) {
            connHistory.remove(0);
        }

        // 检测1：受伤后立即断线 — 核心检测指标
        DamageRecord lastDamage = playerLastDamage.get(playerName);
        if (lastDamage != null) {
            long timeSinceDamage = timestamp.toEpochMilli() - lastDamage.timestamp.toEpochMilli();

            if (timeSinceDamage >= 0 && timeSinceDamage < DAMAGE_DISCONNECT_WINDOW_MS) {
                boolean lowHealth = lastDamage.healthAfter <= AUTO_LOG_HP_THRESHOLD;

                if (lowHealth) {
                    reasons.add("LOW_HP_AUTO_LOG: disconnected " + timeSinceDamage
                            + "ms after taking damage (HP: " + String.format("%.1f", lastDamage.healthAfter)
                            + " <= threshold: " + String.format("%.1f", AUTO_LOG_HP_THRESHOLD) + ")");
                } else {
                    reasons.add("DAMAGE_DISCONNECT: disconnected " + timeSinceDamage
                            + "ms after taking " + String.format("%.1f", lastDamage.damage)
                            + " damage (suspicious timing)");
                }
            }

            // 排除网络超时 — 如果断线距上次数据包超过30秒，可能是网络问题
            // 注意：此检测在伤害窗口内时仍然标记，因为受伤后立刻"恰好"网络超时概率极低
            if (timeSinceDamage >= 0 && timeSinceDamage < DAMAGE_DISCONNECT_WINDOW_MS
                    && timeSinceDamage > NETWORK_TIMEOUT_FLOOR_MS) {
                // 距受伤时间较长但超过网络超时阈值 — 减弱标记
                reasons.clear();
                reasons.add("POSSIBLE_NETWORK_TIMEOUT: disconnect " + timeSinceDamage
                        + "ms after damage (may be network, not AutoLog)");
            }
        }

        // 检测2：低血量阈值一致性检测
        List<HealthRecord> healthHistory = playerHealthHistory.get(playerName);
        if (healthHistory != null && healthHistory.size() >= 2) {
            // 找到断线前最后记录的血量值
            double lastHealth = 0;
            for (int i = healthHistory.size() - 1; i >= 0; i--) {
                if (!healthHistory.get(i).timestamp.isAfter(timestamp)) {
                    lastHealth = healthHistory.get(i).health;
                    break;
                }
            }

            if (lastHealth > 0 && lastHealth <= AUTO_LOG_HP_THRESHOLD) {
                reasons.add("THRESHOLD_DISCONNECT: disconnected at " + String.format("%.1f", lastHealth)
                        + " HP (matches AutoLog trigger threshold " + String.format("%.1f", AUTO_LOG_HP_THRESHOLD) + ")");
            }

            // 检测本次断线血量与历史上其他断线时血量的一致性
            List<Double> disconnectHealthValues = new ArrayList<>();
            for (ConnectionEvent ce : connHistory) {
                if (!ce.isConnect) {
                    // 查找此断线前的血量
                    for (int i = healthHistory.size() - 1; i >= 0; i--) {
                        HealthRecord hr = healthHistory.get(i);
                        if (!hr.timestamp.isAfter(ce.timestamp)
                                && Math.abs(hr.timestamp.toEpochMilli() - ce.timestamp.toEpochMilli()) < 2000) {
                            disconnectHealthValues.add(hr.health);
                            break;
                        }
                    }
                }
            }

            if (disconnectHealthValues.size() >= 2) {
                double min = disconnectHealthValues.stream().mapToDouble(Double::doubleValue).min().orElse(0);
                double max = disconnectHealthValues.stream().mapToDouble(Double::doubleValue).max().orElse(0);
                if ((max - min) <= CONSISTENT_THRESHOLD_RANGE && max <= AUTO_LOG_HP_THRESHOLD) {
                    reasons.add("CONSISTENT_THRESHOLD: " + disconnectHealthValues.size()
                            + " disconnects at " + String.format("%.1f", min) + "-"
                            + String.format("%.1f", max) + " HP (automated trigger pattern)");
                }
            }
        }

        // 检测3：断线-重连循环检测
        if (connHistory.size() >= 3) {
            int rapidCycles = 0;
            for (int i = connHistory.size() - 1; i > 0; i--) {
                ConnectionEvent current = connHistory.get(i);
                ConnectionEvent previous = connHistory.get(i - 1);

                // 如果一个连接事件是上线，前一个是断线
                if (current.isConnect && !previous.isConnect) {
                    long gap = current.timestamp.toEpochMilli() - previous.timestamp.toEpochMilli();
                    if (gap >= 0 && gap < RECONNECT_CYCLE_WINDOW_MS) {
                        // 再检查这个上线后续是否有快速断线
                        if (i + 1 < connHistory.size() && !connHistory.get(i + 1).isConnect) {
                            long reconnectDisconnectGap = connHistory.get(i + 1).timestamp.toEpochMilli()
                                    - current.timestamp.toEpochMilli();
                            if (reconnectDisconnectGap >= 0 && reconnectDisconnectGap < RECONNECT_CYCLE_WINDOW_MS) {
                                rapidCycles++;
                            }
                        }
                    }
                }
            }

            if (rapidCycles >= MAX_RECONNECT_CYCLES) {
                reasons.add("RECONNECT_CYCLE: " + rapidCycles
                        + " disconnect-reconnect cycles within " + (RECONNECT_CYCLE_WINDOW_MS / 1000) + "s windows");
            }
        }

        // 记录可疑事件
        if (!reasons.isEmpty()) {
            List<Map<String, Object>> events = autoLogEvents.computeIfAbsent(
                    playerName, k -> new ArrayList<>());
            Map<String, Object> event = new LinkedHashMap<>();
            event.put("time", timestamp.toString());
            event.put("isKicked", isKicked);
            if (lastDamage != null) {
                event.put("lastDamageTime", lastDamage.timestamp.toString());
                event.put("lastDamageAmount", lastDamage.damage);
                event.put("healthAfterDamage", lastDamage.healthAfter);
            }
            event.put("reasons", reasons);
            events.add(event);
            while (events.size() > 20) {
                events.remove(0);
            }
        }

        // 汇总结果
        if (reasons.size() >= 2) {
            flaggedCount.incrementAndGet();
            return AutoLogCheckResult.flagged(reasons);
        } else if (reasons.size() == 1) {
            return AutoLogCheckResult.suspicious(reasons);
        }

        return AutoLogCheckResult.clean();
    }

    /**
     * 获取玩家当前在线状态
     *
     * @param playerName 玩家名称
     * @return 是否在线
     */
    public boolean isPlayerOnline(String playerName) {
        return playerOnline.getOrDefault(playerName, false);
    }

    /**
     * 玩家离线时清理追踪数据
     * @param playerName 离线玩家名称
     */
    public void clearPlayer(String playerName) {
        playerHealthHistory.remove(playerName);
        playerLastDamage.remove(playerName);
        playerConnectionHistory.remove(playerName);
        playerOnline.remove(playerName);
        autoLogEvents.remove(playerName);
    }

    /**
     * 获取模块运行状态
     * @return 包含计数器和活跃追踪玩家数的Map
     */
    public Map<String, Object> getStatus() {
        Map<String, Object> status = new LinkedHashMap<>();
        status.put("totalDisconnects", totalDisconnects.get());
        status.put("flaggedCount", flaggedCount.get());
        status.put("activeTrackedPlayers", playerConnectionHistory.size());

        // 列出近期有断线-重连循环的可疑玩家
        List<Map<String, Object>> cyclePlayers = new ArrayList<>();
        Instant now = Instant.now();

        for (Map.Entry<String, List<ConnectionEvent>> entry : playerConnectionHistory.entrySet()) {
            List<ConnectionEvent> history = entry.getValue();
            int recentCycles = 0;
            for (int i = history.size() - 1; i > 0; i--) {
                ConnectionEvent current = history.get(i);
                ConnectionEvent previous = history.get(i - 1);
                if (current.isConnect && !previous.isConnect) {
                    long gap = current.timestamp.toEpochMilli() - previous.timestamp.toEpochMilli();
                    if (gap >= 0 && gap < RECONNECT_CYCLE_WINDOW_MS) {
                        recentCycles++;
                    }
                }
            }

            if (recentCycles >= 2) {
                Map<String, Object> info = new LinkedHashMap<>();
                info.put("player", entry.getKey());
                info.put("recentCycles", recentCycles);
                cyclePlayers.add(info);
            }
        }
        cyclePlayers.sort((a, b) ->
                Integer.compare((Integer) b.get("recentCycles"), (Integer) a.get("recentCycles")));
        status.put("reconnectCyclePlayers", cyclePlayers);

        return status;
    }

    /**
     * 内部血量记录
     */
    private static class HealthRecord {
        final double health;
        final Instant timestamp;

        HealthRecord(double health, Instant timestamp) {
            this.health = health;
            this.timestamp = timestamp;
        }
    }

    /**
     * 内部受伤记录
     */
    private static class DamageRecord {
        final double damage;
        final double healthAfter;
        final Instant timestamp;

        DamageRecord(double damage, double healthAfter, Instant timestamp) {
            this.damage = damage;
            this.healthAfter = healthAfter;
            this.timestamp = timestamp;
        }
    }

    /**
     * 内部连接事件记录
     */
    private static class ConnectionEvent {
        final boolean isConnect; // true=上线, false=断线
        final Instant timestamp;

        ConnectionEvent(boolean isConnect, Instant timestamp) {
            this.isConnect = isConnect;
            this.timestamp = timestamp;
        }
    }

    /**
     * AutoLog检测结果 — 不可变结果类
     */
    public static class AutoLogCheckResult {
        private final boolean flagged;
        private final boolean suspicious;
        private final List<String> reasons;

        private AutoLogCheckResult(boolean flagged, boolean suspicious, List<String> reasons) {
            this.flagged = flagged;
            this.suspicious = suspicious;
            this.reasons = reasons;
        }

        /** 无异常 — 合法断线行为 */
        public static AutoLogCheckResult clean() {
            return new AutoLogCheckResult(false, false, List.of());
        }

        /** 可疑 — 单一异常断线指标 */
        public static AutoLogCheckResult suspicious(List<String> reasons) {
            return new AutoLogCheckResult(false, true, reasons);
        }

        /** 已标记 — 确定使用了AutoLog hack */
        public static AutoLogCheckResult flagged(List<String> reasons) {
            return new AutoLogCheckResult(true, false, reasons);
        }

        public boolean isFlagged() { return flagged; }
        public boolean isSuspicious() { return suspicious; }
        public boolean isClean() { return !flagged && !suspicious; }
        public List<String> getReasons() { return reasons; }
    }
}
