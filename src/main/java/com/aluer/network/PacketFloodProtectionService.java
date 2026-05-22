package com.aluer.network;

import com.aluer.config.ServerGuardConfig;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

/**
 * 数据包洪水防护服务 — V4.0 服务器保护模块
 *
 * 检测原理：
 *   Minecraft协议中，某些数据包类型的洪水攻击可导致服务器CPU/带宽耗尽。
 *   本服务按数据包类型追踪每个IP/玩家的发送频率，在5秒滑动窗口内统计，
 *   超过正常阈值则触发限流。对品牌包（Brand channel）进行特殊检测，
 *   因为多次品牌声明通常意味着恶意客户端试图触发协议层漏洞。
 *
 * 攻击模式识别：
 *   - CustomPayload洪水（>50/s）：插件通道洪水，常被用于BungeeCord漏洞利用
 *   - SetCreativeSlot洪水（>30/s）：创造模式物品栏洪水，可导致客户端崩溃
 *   - ChatMessage洪水（>20/s）：聊天洪水，消耗服务器带宽
 *   - Brand包异常（>3次/60s）：品牌通道重复声明，通常为恶意客户端行为
 *
 * 递增式惩罚机制：
 *   首次超限 → 100ms延迟
 *   第二次   → 2秒延迟
 *   第三次   → 10秒延迟
 *   第四次+  → 30秒延迟（并上报为攻击事件）
 *
 * 配置开关：serverguard.security.super-evolution.packet-flood-protection
 */
@Service
public class PacketFloodProtectionService {

    private final ServerGuardConfig config;

    /** 按 playerKey 存储数据包事件历史（5秒窗口内有效） */
    private final Map<String, List<PacketEvent>> packetHistory = new ConcurrentHashMap<>();
    /** 按 packetType 统计各类型数量 */
    private final Map<String, AtomicLong> packetTypeStats = new ConcurrentHashMap<>();
    /** 记录每个来源的违规次数，用于递增惩罚 */
    private final Map<String, AtomicLong> violationCounts = new ConcurrentHashMap<>();
    /** 记录每个来源当前被封锁到的截止时间 */
    private final Map<String, Instant> blockedUntil = new ConcurrentHashMap<>();

    private final AtomicLong totalPackets = new AtomicLong(0);
    private final AtomicLong blockedCount = new AtomicLong(0);

    private final ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor();

    /** 数据包统计窗口大小（秒） */
    private static final long WINDOW_SECONDS = 5;
    /** 品牌包检测窗口（秒），比普通窗口更长 */
    private static final long BRAND_WINDOW_SECONDS = 60;

    /** 各数据包类型的每秒阈值 */
    private static final int CUSTOM_PAYLOAD_THRESHOLD = 50;
    private static final int SET_CREATIVE_SLOT_THRESHOLD = 30;
    private static final int CHAT_MESSAGE_THRESHOLD = 20;
    /** 品牌包重复声明阈值：60秒内超过3次视为异常 */
    private static final int BRAND_DECLARATION_THRESHOLD = 3;

    /** 递增惩罚层级（毫秒） */
    private static final long[] PENALTY_TIERS_MS = {100, 2000, 10000, 30000};

    public PacketFloodProtectionService() {
        this(new ServerGuardConfig());
    }

    @Autowired
    public PacketFloodProtectionService(ServerGuardConfig config) {
        this.config = config;
        // 每30秒清理一次过期数据，避免内存泄漏
        scheduler.scheduleAtFixedRate(this::cleanupExpiredData, 30, 30, TimeUnit.SECONDS);
    }

    /**
     * 检查一个数据包是否构成洪水攻击。
     *
     * @param playerKey 玩家标识（IP或玩家名）
     * @param packetType 数据包类型（如 CustomPayload、ChatMessage 等）
     * @param channel 数据包的频道名（Brand/CustomPayload时有效），可为null
     * @return 检查结果，包含是否被阻止及原因
     */
    public PacketFloodResult check(String playerKey, String packetType, String channel) {
        // 配置开关：如果模块被禁用，直接放行
        if (!config.getSecurity().getSuperEvolution().isPacketFloodProtection()) {
            return PacketFloodResult.clean();
        }

        totalPackets.incrementAndGet();

        // 记录数据包事件（先记录再做检查，确保本次数据包也被统计）
        PacketEvent event = new PacketEvent(Instant.now(), playerKey, packetType, channel);
        packetHistory.computeIfAbsent(playerKey, k -> Collections.synchronizedList(new ArrayList<>())).add(event);

        // 更新各类型统计计数器
        packetTypeStats.computeIfAbsent(packetType, k -> new AtomicLong(0)).incrementAndGet();

        // 清理过期的封锁记录（但不提前返回，让下面的频率检测先运行）
        if (blockedUntil.containsKey(playerKey)) {
            if (Instant.now().isAfter(blockedUntil.get(playerKey))) {
                blockedUntil.remove(playerKey);
                violationCounts.remove(playerKey);
            }
        }

        Instant now = Instant.now();
        List<String> reasons = new ArrayList<>();
        boolean shouldBlock = false;
        long penaltyMs = 0;

        // ---- 检测1：品牌包（Brand channel）特殊检测 ----
        // 品牌包通常在登录时只发送一次，60秒内超过3次为异常行为
        // 多次品牌声明可能用于探测或触发协议层漏洞
        if ("Brand".equalsIgnoreCase(channel) || "minecraft:brand".equalsIgnoreCase(channel)) {
            List<PacketEvent> playerEvents = packetHistory.get(playerKey);
            long brandCount = playerEvents.stream()
                    .filter(e -> e.time.isAfter(now.minusSeconds(BRAND_WINDOW_SECONDS)))
                    .filter(e -> "Brand".equalsIgnoreCase(e.channel) || "minecraft:brand".equalsIgnoreCase(e.channel))
                    .count();
            if (brandCount > BRAND_DECLARATION_THRESHOLD) {
                reasons.add("BRAND_FLOOD: " + brandCount + " brand declarations in 60s window (threshold: "
                        + BRAND_DECLARATION_THRESHOLD + ")");
                shouldBlock = true;
                penaltyMs = PENALTY_TIERS_MS[1]; // 直接从第2级开始
            }
        }

        // ---- 检测2：按数据包类型进行频率检测（5秒滑动窗口） ----
        if (!shouldBlock) {
            List<PacketEvent> playerEvents = packetHistory.get(playerKey);
            long typeCount = playerEvents.stream()
                    .filter(e -> e.time.isAfter(now.minusSeconds(WINDOW_SECONDS)))
                    .filter(e -> e.packetType.equalsIgnoreCase(packetType))
                    .count();

            int threshold;
            String desc;

            // 确定该数据包类型的阈值
            String upperType = packetType.toUpperCase();
            if (upperType.contains("CUSTOMPAYLOAD") || upperType.contains("PLUGIN_MESSAGE")) {
                threshold = CUSTOM_PAYLOAD_THRESHOLD;
                desc = "CustomPayload";
                // CustomPayload洪水：插件通道滥用，5秒窗口内超过50次
                // 常见于BungeeCord漏洞利用或恶意客户端插件通道轰炸
            } else if (upperType.contains("SET_CREATIVE_SLOT") || upperType.contains("CREATIVE_INVENTORY")) {
                threshold = SET_CREATIVE_SLOT_THRESHOLD;
                desc = "SetCreativeSlot";
                // SetCreativeSlot洪水：创造模式物品栏操作洪水，可能用于物品复制或客户端DoS
            } else if (upperType.contains("CHAT") || upperType.contains("CHAT_MESSAGE")) {
                threshold = CHAT_MESSAGE_THRESHOLD;
                desc = "ChatMessage";
                // ChatMessage洪水：聊天消息洪水，消耗服务器带宽和处理资源
            } else {
                // 未知类型：默认阈值100/s（5秒窗口内500）
                threshold = 100;
                desc = packetType;
            }

            if (typeCount > threshold * WINDOW_SECONDS) {
                reasons.add(desc + "_FLOOD: " + typeCount + " packets in " + WINDOW_SECONDS
                        + "s window (threshold: " + (threshold * WINDOW_SECONDS) + ")");
                shouldBlock = true;
            }
        }

        // ---- 递增式惩罚 ----
        if (shouldBlock) {
            long violations = violationCounts.computeIfAbsent(playerKey, k -> new AtomicLong(0))
                    .incrementAndGet();

            // 根据违规次数选择惩罚层级
            int tier = (int) Math.min(violations - 1, PENALTY_TIERS_MS.length - 1);
            penaltyMs = Math.max(penaltyMs, PENALTY_TIERS_MS[tier]);

            // 第4级+（30秒惩罚）标记为严重攻击
            if (tier >= 3) {
                reasons.add("ESCALATED: tier " + (tier + 1) + " penalty, " + violations + " violations");
            }

            blockedCount.incrementAndGet();
            blockedUntil.put(playerKey, Instant.now().plusMillis(penaltyMs));

            return PacketFloodResult.blocked(reasons, penaltyMs);
        }

        return PacketFloodResult.clean();
    }

    /**
     * 获取当前服务运行状态。
     * 用于仪表盘展示实时统计数据。
     */
    public Map<String, Object> getStatus() {
        Map<String, Object> s = new LinkedHashMap<>();
        s.put("totalPackets", totalPackets.get());
        s.put("blockedCount", blockedCount.get());
        s.put("currentlyBlocked", blockedUntil.size());
        s.put("trackedPlayers", packetHistory.size());

        // 数据包类型统计（Top 20）
        Map<String, Object> typeStats = new LinkedHashMap<>();
        packetTypeStats.entrySet().stream()
                .sorted((a, b) -> Long.compare(b.getValue().get(), a.getValue().get()))
                .limit(20)
                .forEach(e -> typeStats.put(e.getKey(), e.getValue().get()));
        s.put("packetTypeStats", typeStats);

        // 当前封锁列表（Top 10）
        List<Map<String, Object>> blocked = new ArrayList<>();
        Instant now = Instant.now();
        for (Map.Entry<String, Instant> e : blockedUntil.entrySet()) {
            if (e.getValue().isAfter(now)) {
                Map<String, Object> m = new LinkedHashMap<>();
                m.put("player", e.getKey());
                m.put("until", e.getValue().toString());
                m.put("violations", violationCounts.getOrDefault(e.getKey(), new AtomicLong(0)).get());
                blocked.add(m);
            }
        }
        blocked.sort((a, b) -> b.get("until").toString().compareTo(a.get("until").toString()));
        s.put("activeBlocks", blocked.subList(0, Math.min(blocked.size(), 10)));
        return s;
    }

    /**
     * 清理过期数据，防止内存泄漏。
     * 删除超时的封锁记录和超过2倍窗口期的历史事件。
     */
    private void cleanupExpiredData() {
        Instant now = Instant.now();

        // 清理过期封锁
        blockedUntil.entrySet().removeIf(e -> e.getValue().isBefore(now));

        // 清理过期数据包历史（保留2倍品牌窗口长度）
        Instant cutoff = now.minusSeconds(BRAND_WINDOW_SECONDS * 2);
        for (List<PacketEvent> events : packetHistory.values()) {
            events.removeIf(e -> e.time.isBefore(cutoff));
        }
        // 移除空玩家记录
        packetHistory.entrySet().removeIf(e -> e.getValue().isEmpty());
    }

    private static class PacketEvent {
        final Instant time;
        final String player;
        final String packetType;
        final String channel;

        PacketEvent(Instant t, String p, String pt, String c) {
            this.time = t;
            this.player = p;
            this.packetType = pt;
            this.channel = c;
        }
    }

    public static class PacketFloodResult {
        private final boolean blocked;
        private final List<String> reasons;
        private final long penaltyMs;

        private PacketFloodResult(boolean blocked, List<String> reasons, long penaltyMs) {
            this.blocked = blocked;
            this.reasons = reasons;
            this.penaltyMs = penaltyMs;
        }

        /** 正常放行 */
        public static PacketFloodResult clean() {
            return new PacketFloodResult(false, List.of(), 0);
        }

        /** 阻止该数据包，带原因和惩罚延迟（毫秒） */
        public static PacketFloodResult blocked(List<String> reasons, long penaltyMs) {
            return new PacketFloodResult(true, reasons, penaltyMs);
        }

        /** 阻止该数据包，带原因 */
        public static PacketFloodResult blocked(List<String> reasons) {
            return new PacketFloodResult(true, reasons, 0);
        }

        public boolean isBlocked() { return blocked; }
        public boolean isClean() { return !blocked; }
        public List<String> getReasons() { return reasons; }
        public long getPenaltyMs() { return penaltyMs; }
    }
}
