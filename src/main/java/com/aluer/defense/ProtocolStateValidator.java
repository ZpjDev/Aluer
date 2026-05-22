package com.aluer.defense;

import com.aluer.config.ServerGuardConfig;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Minecraft协议状态机验证器 — 检测协议状态违规的攻击探测行为
 *
 * 检测原理：
 * Minecraft协议有严格的状态转换规则：HANDSHAKE → STATUS → LOGIN → PLAY
 * 攻击者经常在错误的状态下发送数据包以探测漏洞，例如：
 * 1. 状态跳跃检测 — 在STATUS状态下发送LOGIN数据包（如AuthBypass探测），
 *    在LOGIN状态下发送PLAY数据包（如提前注入攻击）
 * 2. 状态回退检测 — 在PLAY状态下发送STATUS请求（如Ping洪水干扰服务器性能）
 * 3. 状态滞留检测 — 长期停留在HANDSHAKE或LOGIN状态不完成（如SlowLoris式连接耗尽）
 * 4. 序列错乱检测 — 未经过HANDSHAKE直接跳到LOGIN/PLAY状态（如协议重放攻击）
 *
 * 配置开关：serverguard.security.super-evolution.protocol-validator
 */
@Service
public class ProtocolStateValidator {

    private final ServerGuardConfig config;

    /**
     * Minecraft 协议状态枚举 — 对应 nextState 字段的标准取值
     */
    public enum ProtocolState {
        /** 初始状态，连接建立但尚未收到握手包 */
        CONNECTED,
        /** HANDSHAKE — 握手阶段，客户端发送握手包声明意图 */
        HANDSHAKE,
        /** STATUS — 服务器列表查询状态 */
        STATUS,
        /** LOGIN — 登录认证状态 */
        LOGIN,
        /** PLAY — 游戏进行状态 */
        PLAY,
        /** 连接已断开 */
        DISCONNECTED
    }

    /**
     * 追踪每个IP的当前协议状态（IP → 连接状态记录）
     * 一个IP可能有多个连接（如多账号），使用列表追踪
     */
    private final Map<String, List<ConnectionState>> ipStateMap = new ConcurrentHashMap<>();

    /**
     * 追踪每个IP的协议违规次数（IP → 累计违规次数）
     * 达到阈值时触发告警
     */
    private final Map<String, AtomicLong> violationCounters = new ConcurrentHashMap<>();

    /**
     * 被临时封禁的IP及其封禁到期时间（IP → 封禁到期毫秒时间戳）
     */
    private final Map<String, Long> blockedUntil = new ConcurrentHashMap<>();

    private final AtomicLong totalValidations = new AtomicLong(0);
    private final AtomicLong totalViolations = new AtomicLong(0);
    private final AtomicLong totalBlocks = new AtomicLong(0);

    /**
     * 每种违规类型对应的违规分值 — 不同类型严重程度不同
     * 协议违规比状态滞留更严重
     */
    private static final int VIOLATION_SCORE_STATE_JUMP = 3;    // 状态跳跃 — 严重
    private static final int VIOLATION_SCORE_STATE_BACK = 2;    // 状态回退 — 中等
    private static final int VIOLATION_SCORE_STALE = 1;         // 状态滞留 — 轻度
    private static final int VIOLATION_SCORE_OUT_OF_ORDER = 3;  // 序列错乱 — 严重

    /**
     * 违规分数阈值 — 超过此值封禁IP（默认10分钟）
     */
    private static final int BLOCK_THRESHOLD = 10;

    /**
     * 封禁时长（毫秒）— 默认10分钟
     */
    private static final long BLOCK_DURATION_MS = 10 * 60 * 1000;

    /**
     * 状态滞留超时时间（毫秒）— HANDSHAKE/LOGIN状态超过30秒未完成视为滞留
     */
    private static final long STATE_STALE_TIMEOUT_MS = 30_000;

    /**
     * 每个IP最大并发连接状态追踪数 — 超过则清理最早的
     */
    private static final int MAX_CONNECTIONS_PER_IP = 10;

    /**
     * 无参构造函数 — 测试/默认配置使用
     */
    public ProtocolStateValidator() {
        this(new ServerGuardConfig());
    }

    /**
     * Spring 注入构造函数
     * @param config 全局配置，提供模块开关控制
     */
    public ProtocolStateValidator(ServerGuardConfig config) {
        this.config = config;
    }

    /**
     * 记录客户端连接建立事件 — 状态进入 CONNECTED
     *
     * @param ip        客户端IP地址
     * @param timestamp 连接时间戳
     */
    public void recordConnection(String ip, Instant timestamp) {
        if (!config.getSecurity().getSuperEvolution().isProtocolValidator()) {
            return;
        }
        List<ConnectionState> states = ipStateMap.computeIfAbsent(ip,
                k -> Collections.synchronizedList(new ArrayList<>()));

        // 限制每个IP追踪的连接数，防止内存耗尽
        if (states.size() >= MAX_CONNECTIONS_PER_IP) {
            // 移除最旧的连接状态（可能是僵尸连接）
            states.remove(0);
        }
        states.add(new ConnectionState(ProtocolState.CONNECTED, timestamp));
    }

    /**
     * 记录握手数据包 — 状态转换至 HANDSHAKE，然后根据 nextState 跳转到 STATUS 或 LOGIN
     *
     * @param ip        客户端IP地址
     * @param nextState 握手包中的 nextState 字段（1=STATUS, 2=LOGIN）
     * @param timestamp 握手时间戳
     * @return 验证结果
     */
    public ValidationResult recordHandshake(String ip, int nextState, Instant timestamp) {
        totalValidations.incrementAndGet();

        if (!config.getSecurity().getSuperEvolution().isProtocolValidator()) {
            return ValidationResult.clean();
        }

        // 检查IP是否已被封禁
        if (isBlocked(ip, timestamp)) {
            return ValidationResult.blocked("IP is temporarily blocked for protocol violations");
        }

        List<String> reasons = new ArrayList<>();
        List<ConnectionState> states = getOrCreateStates(ip);
        ConnectionState current = getLatestState(states);

        // 验证握手包应该在 CONNECTED 状态下接收
        if (current != null && current.state == ProtocolState.CONNECTED) {
            // 正常路径：CONNECTED → HANDSHAKE
            current.state = ProtocolState.HANDSHAKE;
            current.lastUpdate = timestamp;

            // 根据 nextState 决定后续状态
            if (nextState == 1) {
                current.state = ProtocolState.STATUS;
            } else if (nextState == 2) {
                current.state = ProtocolState.LOGIN;
            } else {
                // 非法的 nextState 值（Minecraft协议只允许1或2）
                reasons.add("INVALID_NEXT_STATE: value=" + nextState + " (expected 1=STATUS or 2=LOGIN)");
            }
        } else if (current != null && current.state == ProtocolState.HANDSHAKE) {
            // 重复握手 — 可能是探测行为
            reasons.add("DUPLICATE_HANDSHAKE: already in HANDSHAKE state");
        } else if (current != null) {
            // 在其他状态下收到握手包 — 协议违规
            reasons.add("STATE_JUMP: received handshake while in " + current.state + " state");
        }

        // 清理过期状态
        cleanupStaleStates(states, timestamp);

        return evaluateViolations(ip, reasons, timestamp);
    }

    /**
     * 记录STATUS请求（服务器列表查询）
     * 在 PLAY 状态下不应出现 STATUS 请求（Ping洪水攻击）
     *
     * @param ip        客户端IP地址
     * @param timestamp 请求时间戳
     * @return 验证结果
     */
    public ValidationResult recordStatusRequest(String ip, Instant timestamp) {
        totalValidations.incrementAndGet();

        if (!config.getSecurity().getSuperEvolution().isProtocolValidator()) {
            return ValidationResult.clean();
        }

        if (isBlocked(ip, timestamp)) {
            return ValidationResult.blocked("IP is temporarily blocked for protocol violations");
        }

        List<String> reasons = new ArrayList<>();
        List<ConnectionState> states = getOrCreateStates(ip);
        ConnectionState current = getLatestState(states);

        if (current == null) {
            // 未连接状态下的STATUS请求 — 正常（首次连接列出服务器）
            states.add(new ConnectionState(ProtocolState.STATUS, timestamp));
        } else if (current.state == ProtocolState.STATUS) {
            // STATUS状态下重复请求 — 正常（MOTD刷新的常规行为）
            current.lastUpdate = timestamp;
        } else if (current.state == ProtocolState.PLAY) {
            // PLAY状态下收到STATUS请求 — 严重的协议违规（Ping洪水或探测）
            reasons.add("STATE_BACK: STATUS request received during PLAY state — possible ping flood or probe");
        } else if (current.state == ProtocolState.LOGIN) {
            // LOGIN状态下收到STATUS请求 — 状态跳跃
            reasons.add("STATE_JUMP: STATUS request during LOGIN state — protocol order violation");
        }

        cleanupStaleStates(states, timestamp);
        return evaluateViolations(ip, reasons, timestamp);
    }

    /**
     * 记录LOGIN数据包 — 应在 HANDSHAKE(nextState=2) 后接收
     *
     * @param ip        客户端IP地址
     * @param timestamp 登录包时间戳
     * @return 验证结果
     */
    public ValidationResult recordLoginStart(String ip, Instant timestamp) {
        totalValidations.incrementAndGet();

        if (!config.getSecurity().getSuperEvolution().isProtocolValidator()) {
            return ValidationResult.clean();
        }

        if (isBlocked(ip, timestamp)) {
            return ValidationResult.blocked("IP is temporarily blocked for protocol violations");
        }

        List<String> reasons = new ArrayList<>();
        List<ConnectionState> states = getOrCreateStates(ip);
        ConnectionState current = getLatestState(states);

        if (current != null && current.state == ProtocolState.LOGIN) {
            // 正常路径：LOGIN状态下接收登录包
            current.lastUpdate = timestamp;
        } else if (current == null || current.state == ProtocolState.CONNECTED) {
            // 未通过HANDSHAKE直接发送LOGIN — 协议序列错乱
            reasons.add("OUT_OF_ORDER: LOGIN packet without prior handshake");
        } else if (current.state == ProtocolState.STATUS) {
            // STATUS状态下发送LOGIN — 状态跳跃（可能的认证绕过探测）
            reasons.add("STATE_JUMP: LOGIN packet during STATUS state — possible auth bypass probe");
        } else if (current.state == ProtocolState.PLAY) {
            // 已经在游戏中又发LOGIN — 重连或攻击
            reasons.add("STATE_JUMP: LOGIN packet during PLAY state");
        }

        cleanupStaleStates(states, timestamp);
        return evaluateViolations(ip, reasons, timestamp);
    }

    /**
     * 记录玩家进入PLAY状态（登录成功）
     *
     * @param ip        客户端IP地址
     * @param timestamp 进入PLAY状态的时间戳
     * @return 验证结果
     */
    public ValidationResult recordPlayEnter(String ip, Instant timestamp) {
        totalValidations.incrementAndGet();

        if (!config.getSecurity().getSuperEvolution().isProtocolValidator()) {
            return ValidationResult.clean();
        }

        List<String> reasons = new ArrayList<>();
        List<ConnectionState> states = getOrCreateStates(ip);
        ConnectionState current = getLatestState(states);

        if (current != null && current.state == ProtocolState.LOGIN) {
            // 正常路径：LOGIN → PLAY
            current.state = ProtocolState.PLAY;
            current.lastUpdate = timestamp;
        } else if (current != null && current.state == ProtocolState.PLAY) {
            // 可能是重复的Play确认（重新生成事件等），正常
            current.lastUpdate = timestamp;
        } else {
            // 非LOGIN状态下进入PLAY — 序列异常
            String fromState = (current != null) ? current.state.name() : "null";
            reasons.add("OUT_OF_ORDER: entering PLAY from " + fromState + " instead of LOGIN");
        }

        cleanupStaleStates(states, timestamp);
        return evaluateViolations(ip, reasons, timestamp);
    }

    /**
     * 记录连接断开事件
     *
     * @param ip        客户端IP地址
     * @param timestamp 断开时间戳
     */
    public void recordDisconnect(String ip, Instant timestamp) {
        if (!config.getSecurity().getSuperEvolution().isProtocolValidator()) {
            return;
        }
        List<ConnectionState> states = ipStateMap.get(ip);
        if (states != null) {
            ConnectionState current = getLatestState(states);
            if (current != null) {
                current.state = ProtocolState.DISCONNECTED;
                current.lastUpdate = timestamp;
            }
        }
    }

    /**
     * 检测状态滞留 — 应在外部定时调用（如每15秒一次）
     * 检查是否有连接在HANDSHAKE或LOGIN状态停留过久
     *
     * @param now 当前时间戳
     * @return 因滞留被标记的IP列表
     */
    public Set<String> detectStaleStates(Instant now) {
        if (!config.getSecurity().getSuperEvolution().isProtocolValidator()) {
            return Set.of();
        }
        Set<String> staleIPs = new HashSet<>();
        long staleCutoff = now.toEpochMilli() - STATE_STALE_TIMEOUT_MS;

        for (Map.Entry<String, List<ConnectionState>> entry : ipStateMap.entrySet()) {
            List<ConnectionState> states = entry.getValue();
            synchronized (states) {
                for (ConnectionState cs : states) {
                    if ((cs.state == ProtocolState.HANDSHAKE || cs.state == ProtocolState.LOGIN)
                            && cs.lastUpdate.toEpochMilli() < staleCutoff) {
                        // HANDSHAKE或LOGIN状态滞留超过30秒 — 标记
                        staleIPs.add(entry.getKey());
                        AtomicLong counter = violationCounters.computeIfAbsent(entry.getKey(),
                                k -> new AtomicLong(0));
                        counter.addAndGet(VIOLATION_SCORE_STALE);
                        totalViolations.incrementAndGet();

                        if (counter.get() >= BLOCK_THRESHOLD) {
                            blockedUntil.put(entry.getKey(), now.toEpochMilli() + BLOCK_DURATION_MS);
                            totalBlocks.incrementAndGet();
                        }
                        break;
                    }
                }
            }
        }
        return staleIPs;
    }

    /**
     * 手动重置IP的违规计数（如管理员解封）
     *
     * @param ip 要重置的IP地址
     */
    public void resetViolations(String ip) {
        violationCounters.remove(ip);
        blockedUntil.remove(ip);
    }

    /**
     * 获取模块运行状态
     *
     * @return 包含计数器、活跃追踪IP数、封禁IP数的Map
     */
    public Map<String, Object> getStatus() {
        Map<String, Object> status = new LinkedHashMap<>();
        status.put("totalValidations", totalValidations.get());
        status.put("totalViolations", totalViolations.get());
        status.put("totalBlocks", totalBlocks.get());
        status.put("activeTrackedIPs", ipStateMap.size());
        status.put("blockedIPs", blockedUntil.size());
        return status;
    }

    /**
     * 检查IP是否处于封禁状态
     */
    private boolean isBlocked(String ip, Instant now) {
        Long unblockTime = blockedUntil.get(ip);
        if (unblockTime != null) {
            if (now.toEpochMilli() < unblockTime) {
                return true;
            }
            // 封禁已过期，移除
            blockedUntil.remove(ip);
        }
        return false;
    }

    /**
     * 获取或创建IP的状态记录列表
     */
    private List<ConnectionState> getOrCreateStates(String ip) {
        return ipStateMap.computeIfAbsent(ip,
                k -> Collections.synchronizedList(new ArrayList<>()));
    }

    /**
     * 获取最新的连接状态（列表中最后一个活跃状态）
     */
    private ConnectionState getLatestState(List<ConnectionState> states) {
        synchronized (states) {
            if (states.isEmpty()) return null;
            // 返回最后一个非DISCONNECTED的状态
            for (int i = states.size() - 1; i >= 0; i--) {
                if (states.get(i).state != ProtocolState.DISCONNECTED) {
                    return states.get(i);
                }
            }
            return null;
        }
    }

    /**
     * 清理超过60秒没有活动的状态记录
     */
    private void cleanupStaleStates(List<ConnectionState> states, Instant now) {
        long cutoff = now.toEpochMilli() - 60_000;
        synchronized (states) {
            states.removeIf(cs -> cs.state == ProtocolState.DISCONNECTED
                    && cs.lastUpdate.toEpochMilli() < cutoff);
        }
    }

    /**
     * 评估违规原因列表，累加分数并判断是否需要封禁
     */
    private ValidationResult evaluateViolations(String ip, List<String> reasons, Instant timestamp) {
        if (reasons.isEmpty()) {
            return ValidationResult.clean();
        }

        // 计算本次违规总分
        int totalScore = 0;
        for (String reason : reasons) {
            if (reason.startsWith("STATE_JUMP")) {
                totalScore += VIOLATION_SCORE_STATE_JUMP;
            } else if (reason.startsWith("STATE_BACK")) {
                totalScore += VIOLATION_SCORE_STATE_BACK;
            } else if (reason.startsWith("OUT_OF_ORDER")) {
                totalScore += VIOLATION_SCORE_OUT_OF_ORDER;
            } else if (reason.startsWith("DUPLICATE")) {
                totalScore += VIOLATION_SCORE_STALE;
            } else {
                totalScore += 1;
            }
        }

        AtomicLong counter = violationCounters.computeIfAbsent(ip, k -> new AtomicLong(0));
        long newTotal = counter.addAndGet(totalScore);
        totalViolations.addAndGet(reasons.size());

        if (newTotal >= BLOCK_THRESHOLD) {
            blockedUntil.put(ip, timestamp.toEpochMilli() + BLOCK_DURATION_MS);
            totalBlocks.incrementAndGet();
            reasons.add("BLOCK_THRESHOLD_REACHED: violation score=" + newTotal + " >= " + BLOCK_THRESHOLD);
            return ValidationResult.blocked(reasons);
        }

        // 分数接近阈值 — 标记为标记
        return ValidationResult.flagged(reasons);
    }

    /**
     * 内部连接状态记录 — 追踪单个连接的协议状态和时间信息
     */
    private static class ConnectionState {
        ProtocolState state;
        Instant lastUpdate;

        ConnectionState(ProtocolState state, Instant lastUpdate) {
            this.state = state;
            this.lastUpdate = lastUpdate;
        }
    }

    /**
     * 协议状态验证结果 — 不可变结果类
     */
    public static class ValidationResult {
        private final boolean clean;
        private final boolean flagged;
        private final boolean blocked;
        private final List<String> reasons;

        private ValidationResult(boolean clean, boolean flagged, boolean blocked, List<String> reasons) {
            this.clean = clean;
            this.flagged = flagged;
            this.blocked = blocked;
            this.reasons = reasons;
        }

        /** 无异常 — 协议状态转换正常 */
        public static ValidationResult clean() {
            return new ValidationResult(true, false, false, List.of());
        }

        /** 已标记 — 检测到协议违规但未达封禁阈值 */
        public static ValidationResult flagged(List<String> reasons) {
            return new ValidationResult(false, true, false, reasons);
        }

        /** 已封禁 — 违规得分超过阈值，IP被临时封禁 */
        public static ValidationResult blocked(List<String> reasons) {
            return new ValidationResult(false, false, true, reasons);
        }

        /** 带自定义消息的封禁结果 — 用于已封禁IP的快捷返回 */
        private static ValidationResult blocked(String reason) {
            return new ValidationResult(false, false, true, List.of(reason));
        }

        public boolean isClean() { return clean; }
        public boolean isFlagged() { return flagged; }
        public boolean isBlocked() { return blocked; }
        public List<String> getReasons() { return reasons; }
    }
}
