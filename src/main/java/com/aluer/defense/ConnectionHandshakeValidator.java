package com.aluer.defense;

import com.aluer.config.ServerGuardConfig;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Minecraft连接握手验证器 — 检测握手阶段的异常行为和攻击探测
 *
 * 检测原理：
 * Minecraft客户端在连接到服务器时首先发送一个握手包（Handshake packet），其中包含：
 * - Protocol Version: 客户端支持的协议版本号
 * - Server Address: 目标服务器地址（用于虚拟主机识别）
 * - Server Port: 目标端口
 * - Next State: 下一个状态（1=STATUS服务器列表查询，2=LOGIN登录）
 *
 * 攻击者通过在握手阶段发送异常数据来探测或攻击服务器：
 *
 * 1. 协议版本异常 — 发送不存在或极端的协议版本号（如-1、99999），试图触发
 *    PaperMC的未知协议处理逻辑漏洞
 * 2. 主机名恶意构造 — 超长或畸形的主机名字段，可能导致日志注入或缓冲区溢出
 * 3. Next State 异常 — 发送超过标准范围（1-2）的nextState值，
 *    试图触发意外的状态机行为
 * 4. Ping洪水探测 — 大量快速的STATUS请求（服务器列表ping），
 *    攻击者用此扫描开放的Minecraft服务器
 * 5. 握手超时 — 发送握手包后长时间不继续后续流程，
 *    占用连接槽位（类似SlowLoris攻击）
 * 6. 端口扫描 — 在不同端口上发送握手包以确认服务器存在（跨端口探测）
 *
 * 配置开关：serverguard.security.super-evolution.handshake-validator
 */
@Service
public class ConnectionHandshakeValidator {

    private final ServerGuardConfig config;

    /**
     * 追踪每个IP的握手状态（IP → 握手跟踪记录）
     * 记录未完成的握手以检测超时
     */
    private final Map<String, HandshakeRecord> pendingHandshakes = new ConcurrentHashMap<>();

    /**
     * 追踪每个IP的握手完成率（IP → 统计记录）
     * 正常玩家的完成率接近100%，扫描器的完成率极低
     */
    private final Map<String, ConnectionStats> connectionStats = new ConcurrentHashMap<>();

    /**
     * 追踪每个IP的服务器列表Ping记录（IP → ping时间戳列表）
     * 用于检测Ping洪水
     */
    private final Map<String, List<Long>> pingTimestamps = new ConcurrentHashMap<>();

    /**
     * 封禁IP及其封禁到期时间（IP → 解除封禁的毫秒时间戳）
     */
    private final Map<String, Long> blockedIPs = new ConcurrentHashMap<>();

    private final AtomicLong totalHandshakes = new AtomicLong(0);
    private final AtomicLong totalCompletions = new AtomicLong(0);
    private final AtomicLong totalViolations = new AtomicLong(0);
    private final AtomicLong totalBlocks = new AtomicLong(0);

    /**
     * Minecraft支持的协议版本范围
     * PaperMC 1.21.1 的协议版本约为 767
     */
    private static final int MIN_PROTOCOL_VERSION = 750;
    private static final int MAX_PROTOCOL_VERSION = 770;

    /**
     * nextState字段合法值
     */
    private static final int NEXT_STATE_STATUS = 1;
    private static final int NEXT_STATE_LOGIN = 2;

    /**
     * 主机名最大长度 — 正常域名不超过253字符，FQDN限制
     * 超过此值可能是缓冲区溢出探测
     */
    private static final int MAX_HOSTNAME_LENGTH = 255;

    /**
     * Ping洪水检测阈值 — 在检测窗口内超过此数量的Ping视为扫描
     */
    private static final int PING_FLOOD_THRESHOLD = 30;

    /**
     * Ping洪水检测窗口（毫秒）— 10秒
     */
    private static final long PING_FLOOD_WINDOW_MS = 10_000;

    /**
     * 握手超时时间（毫秒）— 发送握手包后30秒未完成登录视为超时
     */
    private static final long HANDSHAKE_TIMEOUT_MS = 30_000;

    /**
     * 握手完成率阈值 — 低于此比例的IP视为可疑扫描器
     * 扫描器通常只有ping没有login，完成率接近于0
     */
    private static final double MIN_COMPLETION_RATE = 0.1;

    /**
     * 最低握手次数（用于完成率评估）— 至少需要此数量的握手才能评估完成率
     */
    private static final int MIN_HANDSHAKES_FOR_EVAL = 5;

    /**
     * 端口扫描检测 — 同一IP在多个端口上的握手
     */
    private static final int PORT_SCAN_THRESHOLD = 3;

    /**
     * Ping间隔过短阈值 — 两次Ping间隔低于此值视为异常
     */
    private static final long ABNORMAL_PING_INTERVAL_MS = 200;

    /**
     * 封禁时长（毫秒）— 默认30分钟
     */
    private static final long BLOCK_DURATION_MS = 30 * 60 * 1000L;

    /**
     * 无参构造函数 — 测试/默认配置使用
     */
    public ConnectionHandshakeValidator() {
        this(new ServerGuardConfig());
    }

    /**
     * Spring 注入构造函数
     * @param config 全局配置，提供模块开关控制
     */
    public ConnectionHandshakeValidator(ServerGuardConfig config) {
        this.config = config;
    }

    /**
     * 记录握手包接收事件
     *
     * @param ip             客户端IP地址
     * @param protocolVersion 客户端声明的协议版本
     * @param nextState      握手包中声明的nextState（1=STATUS, 2=LOGIN）
     * @param hostname       握手包中声明的目标主机名
     * @param timestamp      握手时间戳
     * @return 验证结果
     */
    public HandshakeValidationResult recordHandshake(String ip, int protocolVersion,
                                                      int nextState, String hostname,
                                                      Instant timestamp) {
        totalHandshakes.incrementAndGet();

        if (!config.getSecurity().getSuperEvolution().isHandshakeValidator()) {
            return HandshakeValidationResult.clean();
        }

        // 检查IP是否已被封禁
        if (isBlocked(ip, timestamp)) {
            return HandshakeValidationResult.blocked("IP is temporarily blocked for handshake anomalies");
        }

        List<String> reasons = new ArrayList<>();

        // 1. 验证协议版本
        if (protocolVersion < MIN_PROTOCOL_VERSION || protocolVersion > MAX_PROTOCOL_VERSION) {
            reasons.add("ABNORMAL_PROTOCOL_VERSION: " + protocolVersion
                    + " (expected " + MIN_PROTOCOL_VERSION + "~" + MAX_PROTOCOL_VERSION + ")");
        }

        // 2. 验证 nextState 字段
        if (nextState != NEXT_STATE_STATUS && nextState != NEXT_STATE_LOGIN) {
            reasons.add("INVALID_NEXT_STATE: " + nextState
                    + " (expected 1=STATUS or 2=LOGIN) — possible protocol fuzzing");
        }

        // 3. 验证主机名长度
        if (hostname != null && hostname.length() > MAX_HOSTNAME_LENGTH) {
            reasons.add("OVERSIZED_HOSTNAME: " + hostname.length() + " chars > max=" + MAX_HOSTNAME_LENGTH
                    + " — possible buffer overflow probe");
        }

        // 4. 检测主机名中的可疑字符（空字符注入等）
        if (hostname != null && (hostname.contains("\0") || hostname.contains("\n") || hostname.contains("\r"))) {
            reasons.add("MALFORMED_HOSTNAME: contains null/newline characters — possible injection attempt");
        }

        // 5. 记录握手等待（用于超时检测）
        HandshakeRecord record = new HandshakeRecord(protocolVersion, nextState, hostname, timestamp);
        pendingHandshakes.put(ip, record);

        // 6. 更新连接统计
        ConnectionStats stats = connectionStats.computeIfAbsent(ip, k -> new ConnectionStats());
        stats.totalHandshakes++;

        if (!reasons.isEmpty()) {
            totalViolations.addAndGet(reasons.size());
            // 检查是否需要封禁
            stats.violationCount++;
            if (stats.violationCount >= 5) {
                blockIP(ip, timestamp, "Repeated handshake violations: " + stats.violationCount);
                return HandshakeValidationResult.blocked(reasons);
            }
            return HandshakeValidationResult.flagged(reasons);
        }

        return HandshakeValidationResult.clean();
    }

    /**
     * 记录玩家登录成功（握手完成）事件
     *
     * @param ip         客户端IP地址
     * @param playerName 登录成功的玩家名称
     * @param timestamp  完成时间戳
     */
    public void recordHandshakeCompletion(String ip, String playerName, Instant timestamp) {
        if (!config.getSecurity().getSuperEvolution().isHandshakeValidator()) {
            return;
        }

        totalCompletions.incrementAndGet();

        // 移除等待中的握手记录
        pendingHandshakes.remove(ip);

        // 更新连接统计
        ConnectionStats stats = connectionStats.get(ip);
        if (stats != null) {
            stats.successfulLogins++;
        }

        // 清理过期的ping记录
        cleanupPingTimestamps(ip, timestamp.toEpochMilli());
    }

    /**
     * 记录服务器列表Ping事件
     * 在短时间内大量Ping是端口探测的典型特征
     *
     * @param ip        客户端IP地址
     * @param port      目标端口
     * @param timestamp Ping时间戳
     * @return 验证结果
     */
    public HandshakeValidationResult recordServerListPing(String ip, int port, Instant timestamp) {
        if (!config.getSecurity().getSuperEvolution().isHandshakeValidator()) {
            return HandshakeValidationResult.clean();
        }

        if (isBlocked(ip, timestamp)) {
            return HandshakeValidationResult.blocked("IP is temporarily blocked for handshake anomalies");
        }

        List<String> reasons = new ArrayList<>();
        long nowMs = timestamp.toEpochMilli();

        // 记录Ping时间戳
        List<Long> timestamps = pingTimestamps.computeIfAbsent(ip,
                k -> Collections.synchronizedList(new ArrayList<>()));
        timestamps.add(nowMs);

        // 检测Ping洪水 — 在窗口内超过阈值
        long cutoff = nowMs - PING_FLOOD_WINDOW_MS;
        long recentPings = timestamps.stream().filter(t -> t > cutoff).count();

        if (recentPings > PING_FLOOD_THRESHOLD) {
            reasons.add("PING_FLOOD: " + recentPings + " pings in " + PING_FLOOD_WINDOW_MS / 1000
                    + "s (threshold: " + PING_FLOOD_THRESHOLD + ")");
        }

        // 检测Ping间隔过于规律 — 自动化扫描特征
        if (timestamps.size() >= 5) {
            // 取最近5个时间戳计算间隔
            int size = timestamps.size();
            List<Long> recent = new ArrayList<>(timestamps.subList(Math.max(0, size - 6), size));
            if (recent.size() >= 3) {
                long minInterval = Long.MAX_VALUE;
                long maxInterval = Long.MIN_VALUE;
                for (int i = 1; i < recent.size(); i++) {
                    long interval = recent.get(i) - recent.get(i - 1);
                    minInterval = Math.min(minInterval, interval);
                    maxInterval = Math.max(maxInterval, interval);
                }
                // 间隔一致性过高 → 脚本化扫描
                if (maxInterval - minInterval < ABNORMAL_PING_INTERVAL_MS && recent.size() >= 5) {
                    reasons.add("AUTOMATED_PING_PATTERN: ping intervals "
                            + minInterval + "~" + maxInterval + "ms — automated scanner detected");
                }
            }
        }

        // 检测端口扫描 — 同一IP在多个端口上ping
        if (port != 25565) {
            ConnectionStats stats = connectionStats.computeIfAbsent(ip, k -> new ConnectionStats());
            stats.scannedPorts.add(port);
            if (stats.scannedPorts.size() >= PORT_SCAN_THRESHOLD) {
                reasons.add("PORT_SCAN: " + stats.scannedPorts.size() + " different ports probed: "
                        + stats.scannedPorts);
            }
        }

        // 清理过期时间戳
        cleanupPingTimestamps(ip, nowMs);

        if (!reasons.isEmpty()) {
            totalViolations.addAndGet(reasons.size());
            ConnectionStats stats = connectionStats.computeIfAbsent(ip, k -> new ConnectionStats());
            stats.violationCount++;
            if (stats.violationCount >= 3) {
                blockIP(ip, timestamp, "Port scan / ping flood: " + stats.violationCount + " violations");
                return HandshakeValidationResult.blocked(reasons);
            }
            return HandshakeValidationResult.flagged(reasons);
        }

        return HandshakeValidationResult.clean();
    }

    /**
     * 检测超时的握手 — 应在外部定时调用（如每15秒一次）
     * 握手包发送后30秒内未完成登录的连接将被标记
     *
     * @param now 当前时间戳
     * @return 超时握手的IP集合
     */
    public Set<String> detectHandshakeTimeouts(Instant now) {
        if (!config.getSecurity().getSuperEvolution().isHandshakeValidator()) {
            return Set.of();
        }

        Set<String> timeoutIPs = new HashSet<>();
        long cutoff = now.toEpochMilli() - HANDSHAKE_TIMEOUT_MS;

        for (Map.Entry<String, HandshakeRecord> entry : pendingHandshakes.entrySet()) {
            HandshakeRecord record = entry.getValue();
            if (record.timestamp.toEpochMilli() < cutoff) {
                // 握手超时 — 占用连接槽位但不完成登录，类似SlowLoris行为
                timeoutIPs.add(entry.getKey());
                totalViolations.incrementAndGet();

                ConnectionStats stats = connectionStats.computeIfAbsent(entry.getKey(), k -> new ConnectionStats());
                stats.timeoutCount++;

                if (stats.timeoutCount >= 5) {
                    blockIP(entry.getKey(), now, "Repeated handshake timeouts: " + stats.timeoutCount);
                }
            }
        }

        // 清理已超时的记录
        for (String ip : timeoutIPs) {
            pendingHandshakes.remove(ip);
        }

        return timeoutIPs;
    }

    /**
     * 检查IP的握手完成率是否异常
     * 扫描器的完成率极低（大量Ping但几乎不登录）
     *
     * @param ip 要检查的IP地址
     * @return 完成率是否异常（false=异常低，true=正常）
     */
    public boolean hasNormalCompletionRate(String ip) {
        if (!config.getSecurity().getSuperEvolution().isHandshakeValidator()) {
            return true;
        }

        ConnectionStats stats = connectionStats.get(ip);
        if (stats == null || stats.totalHandshakes < MIN_HANDSHAKES_FOR_EVAL) {
            return true; // 样本不足，放行
        }

        double rate = (double) stats.successfulLogins / stats.totalHandshakes;
        return rate >= MIN_COMPLETION_RATE;
    }

    /**
     * 获取指定IP的连接统计信息
     *
     * @param ip 要查询的IP地址
     * @return 连接统计，无记录时返回null
     */
    public ConnectionStats getConnectionStats(String ip) {
        return connectionStats.get(ip);
    }

    /**
     * 重置指定IP的所有追踪数据
     *
     * @param ip 要重置的IP地址
     */
    public void resetIP(String ip) {
        pendingHandshakes.remove(ip);
        connectionStats.remove(ip);
        pingTimestamps.remove(ip);
        blockedIPs.remove(ip);
    }

    /**
     * 获取模块运行状态
     *
     * @return 包含计数器、活跃追踪IP数、封禁IP数的Map
     */
    public Map<String, Object> getStatus() {
        Map<String, Object> status = new LinkedHashMap<>();
        status.put("totalHandshakes", totalHandshakes.get());
        status.put("totalCompletions", totalCompletions.get());
        status.put("totalViolations", totalViolations.get());
        status.put("totalBlocks", totalBlocks.get());
        status.put("pendingHandshakes", pendingHandshakes.size());
        status.put("trackedIPs", connectionStats.size());
        status.put("blockedIPs", blockedIPs.size());

        double completionRate = 0;
        long total = totalHandshakes.get();
        if (total > 0) {
            completionRate = (double) totalCompletions.get() / total * 100.0;
        }
        status.put("globalCompletionRate", String.format("%.2f%%", completionRate));
        return status;
    }

    /**
     * 检查IP是否处于封禁状态
     */
    private boolean isBlocked(String ip, Instant now) {
        Long unblockTime = blockedIPs.get(ip);
        if (unblockTime != null) {
            if (now.toEpochMilli() < unblockTime) {
                return true;
            }
            blockedIPs.remove(ip);
        }
        return false;
    }

    /**
     * 封禁指定IP
     */
    private void blockIP(String ip, Instant timestamp, String reason) {
        blockedIPs.put(ip, timestamp.toEpochMilli() + BLOCK_DURATION_MS);
        totalBlocks.incrementAndGet();
    }

    /**
     * 清理过期的Ping时间戳记录
     */
    private void cleanupPingTimestamps(String ip, long nowMs) {
        List<Long> timestamps = pingTimestamps.get(ip);
        if (timestamps != null) {
            long cutoff = nowMs - PING_FLOOD_WINDOW_MS * 3; // 保留3倍窗口数据
            synchronized (timestamps) {
                timestamps.removeIf(t -> t < cutoff);
            }
            if (timestamps.isEmpty()) {
                pingTimestamps.remove(ip);
            }
        }
    }

    /**
     * 内部握手跟踪记录 — 记录未完成握手的客户端信息
     */
    private static class HandshakeRecord {
        final int protocolVersion;
        final int nextState;
        final String hostname;
        final Instant timestamp;

        HandshakeRecord(int protocolVersion, int nextState, String hostname, Instant timestamp) {
            this.protocolVersion = protocolVersion;
            this.nextState = nextState;
            this.hostname = hostname;
            this.timestamp = timestamp;
        }
    }

    /**
     * IP连接统计 — 追踪每个IP的握手行为和违规历史
     */
    public static class ConnectionStats {
        public int totalHandshakes = 0;
        public int successfulLogins = 0;
        public int violationCount = 0;
        public int timeoutCount = 0;
        public final Set<Integer> scannedPorts = new HashSet<>();

        /**
         * 计算握手完成率
         * @return 0.0 ~ 1.0，样本不足时返回-1
         */
        public double getCompletionRate() {
            if (totalHandshakes < MIN_HANDSHAKES_FOR_EVAL) return -1;
            return (double) successfulLogins / totalHandshakes;
        }

        /**
         * 判断是否为可疑扫描器（低完成率 + 多端口扫描 + 高违规）
         */
        public boolean isSuspiciousScanner() {
            double rate = getCompletionRate();
            return (rate >= 0 && rate < MIN_COMPLETION_RATE)
                    || scannedPorts.size() >= PORT_SCAN_THRESHOLD
                    || violationCount >= 3;
        }
    }

    /**
     * 握手验证结果 — 不可变结果类
     */
    public static class HandshakeValidationResult {
        private final boolean clean;
        private final boolean flagged;
        private final boolean blocked;
        private final List<String> reasons;

        private HandshakeValidationResult(boolean clean, boolean flagged, boolean blocked, List<String> reasons) {
            this.clean = clean;
            this.flagged = flagged;
            this.blocked = blocked;
            this.reasons = reasons;
        }

        /** 无异常 — 握手数据正常 */
        public static HandshakeValidationResult clean() {
            return new HandshakeValidationResult(true, false, false, List.of());
        }

        /** 已标记 — 握手数据可疑，但未达封禁阈值 */
        public static HandshakeValidationResult flagged(List<String> reasons) {
            return new HandshakeValidationResult(false, true, false, reasons);
        }

        /** 已封禁 — 多次违规或严重异常，IP被临时封禁 */
        public static HandshakeValidationResult blocked(List<String> reasons) {
            return new HandshakeValidationResult(false, false, true, reasons);
        }

        /** 带自定义消息的封禁结果 — 用于已封禁IP的快捷返回 */
        private static HandshakeValidationResult blocked(String reason) {
            return new HandshakeValidationResult(false, false, true, List.of(reason));
        }

        public boolean isClean() { return clean; }
        public boolean isFlagged() { return flagged; }
        public boolean isBlocked() { return blocked; }
        public List<String> getReasons() { return reasons; }
    }
}
