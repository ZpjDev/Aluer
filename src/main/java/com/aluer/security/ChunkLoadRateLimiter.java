package com.aluer.security;

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
 * 区块加载速率限制器 — V5.0 服务器保护模块
 *
 * 检测原理：
 *   Minecraft 区块加载是服务器最消耗 CPU 和内存的操作之一。正常玩家移动
 *   时每秒加载约 1-5 个区块（视距 8-12）。Xray 透视、自动化探索 Bot 或
 *   恶意玩家的区块轰炸可在单秒内加载 50+ 个区块，导致服务器严重卡顿甚至崩溃。
 *
 * 三类危险场景：
 *   1. Xray / 矿物透视 — 客户端通过快速遍历区块定位钻石/远古残骸等稀有矿物，
 *      需要极快速的区块加载来暴露地下结构。
 *   2. Chunk Ban 攻击 — 攻击者故意飞行到世界边缘（X/Z 超过 3000 万），
 *      利用极端坐标的区块生成计算量使服务器 OOM 或永久崩溃。
 *   3. 自动化探索 Bot — Baritone 等 AI 寻路程序在极短时间内覆盖大片区域，
 *      区块加载频率远超正常人类玩家。
 *
 * 三级梯次响应：
 *   WARN (>20区块/秒)  — 记录警告日志，继续观察
 *   LIMIT (>40区块/秒) — 跳过部分区块加载请求，对玩家发送速率受限通知
 *   BLOCK (>60区块/秒) — 完全阻止该玩家的区块加载，踢出玩家
 *
 * 特殊豁免：
 *   - 出生点区块加载（登录瞬间的初始加载）
 *   - 服务器内部区块加载（非玩家触发的世界生成/实体 AI）
 *   - 管理员白名单玩家
 *
 * 配置开关：serverguard.security.super-evolution.chunk-load-rate-limiter
 */
@Service
public class ChunkLoadRateLimiter {

    private final ServerGuardConfig config;

    /** 每个玩家的滑动窗口区块加载记录（保留最近 60 秒） */
    private final Map<String, List<ChunkLoadEvent>> playerLoadHistory = new ConcurrentHashMap<>();

    /** 每个玩家当前所处的阶段（WARN / LIMIT / BLOCK） */
    private final Map<String, Stage> playerStage = new ConcurrentHashMap<>();

    /** 每个玩家的限流冷却截止时间 */
    private final Map<String, Instant> playerCooldownUntil = new ConcurrentHashMap<>();

    /** 每个世界的总区块加载计数（用于服务器健康监控） */
    private final Map<String, AtomicLong> worldChunkLoadTotal = new ConcurrentHashMap<>();

    /** 极端坐标区块加载事件（X或Z超过30M），用于 chunk ban 检测 */
    private final Map<String, List<ExtremeCoordEvent>> extremeCoordEvents = new ConcurrentHashMap<>();

    /** 总区块加载请求计数 */
    private final AtomicLong totalChunkLoads = new AtomicLong(0);
    /** 被阻止的区块加载计数 */
    private final AtomicLong blockedChunkLoads = new AtomicLong(0);
    /** chunk ban 攻击检测次数 */
    private final AtomicLong chunkBanDetections = new AtomicLong(0);

    private final ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor();

    /** 区块加载速率阈值（区块/秒） */
    private static final int WARN_THRESHOLD = 20;
    private static final int LIMIT_THRESHOLD = 40;
    private static final int BLOCK_THRESHOLD = 60;

    /** 滑窗大小（秒） */
    private static final long WINDOW_SECONDS = 5;

    /** 限流冷却时间（秒） */
    private static final long COOLDOWN_WARN_SECONDS = 10;
    private static final long COOLDOWN_LIMIT_SECONDS = 30;
    private static final long COOLDOWN_BLOCK_SECONDS = 120;

    /** 极端坐标阈值（距原点超30M格的区块） */
    private static final int EXTREME_COORD_THRESHOLD = 30_000_000;

    /** 记录保留时间（秒） */
    private static final long RECORD_RETENTION_SECONDS = 300;

    /** 区块加载响应阶段 */
    public enum Stage {
        NORMAL,    // 正常
        WARN,      // 警告
        LIMIT,     // 限流
        BLOCK      // 阻断
    }

    public ChunkLoadRateLimiter() {
        this(new ServerGuardConfig());
    }

    @Autowired
    public ChunkLoadRateLimiter(ServerGuardConfig config) {
        this.config = config;
        // 每 60 秒清理一次过期数据，防止内存泄漏
        scheduler.scheduleAtFixedRate(this::cleanupOldRecords, 60, 60, TimeUnit.SECONDS);
    }

    /**
     * 检查一次区块加载请求是否应该被允许。
     *
     * 调用时机：Paper 的 ChunkLoadEvent 触发时，或代理拦截到区块数据包时。
     *
     * @param playerName 触发加载的玩家名称（可为 null 表示服务器内部加载）
     * @param playerUUID 玩家 UUID
     * @param worldName  世界名称
     * @param chunkX     区块 X 坐标
     * @param chunkZ     区块 Z 坐标
     * @param isServerInternal 是否为服务器内部触发的加载（非玩家移动所致）
     * @return 限流检查结果
     */
    public ChunkLimitResult checkChunkLoad(String playerName, String playerUUID,
                                           String worldName, int chunkX, int chunkZ,
                                           boolean isServerInternal) {
        // 配置开关检查
        if (!config.getSecurity().getSuperEvolution().isChunkLoadRateLimiter()) {
            return ChunkLimitResult.clean();
        }

        totalChunkLoads.incrementAndGet();

        // 更新世界级别统计（所有加载都计数，包括服务器内部）
        worldChunkLoadTotal.computeIfAbsent(worldName, k -> new AtomicLong(0)).incrementAndGet();

        // 服务器内部加载直接放行（世界生成、实体AI导致的被动加载）
        if (isServerInternal || playerName == null) {
            return ChunkLimitResult.clean();
        }

        // 检查玩家是否处于冷却期
        Instant cooldownUntil = playerCooldownUntil.get(playerName);
        if (cooldownUntil != null) {
            if (Instant.now().isBefore(cooldownUntil)) {
                // 仍在冷却期，直接返回当前阶段的阻止状态
                Stage currentStage = playerStage.getOrDefault(playerName, Stage.NORMAL);
                if (currentStage == Stage.BLOCK) {
                    blockedChunkLoads.incrementAndGet();
                    return ChunkLimitResult.blocked(List.of(
                        "COOLDOWN_BLOCK: player " + playerName + " is blocked until " + cooldownUntil));
                } else if (currentStage == Stage.LIMIT) {
                    // 限流阶段：随机拒绝 50% 的请求
                    if (Math.random() < 0.5) {
                        blockedChunkLoads.incrementAndGet();
                        return ChunkLimitResult.blocked(List.of(
                            "COOLDOWN_LIMIT: throttled load for " + playerName));
                    }
                }
            } else {
                // 冷却已过期，清除记录
                playerCooldownUntil.remove(playerName);
                playerStage.remove(playerName);
            }
        }

        // 记录本次区块加载
        Instant now = Instant.now();
        ChunkLoadEvent event = new ChunkLoadEvent(now, chunkX, chunkZ, worldName);
        List<ChunkLoadEvent> events = playerLoadHistory.computeIfAbsent(playerName,
            k -> Collections.synchronizedList(new ArrayList<>()));
        events.add(event);

        // === 检测1：极端坐标 Chunk Ban 攻击检测 ===
        // 区块坐标超过 30M 格（1875000 个区块）为极端坐标
        // 攻击者通过 TP 或飞行到达这些位置使服务器尝试生成不可能的地形
        if (Math.abs(chunkX) > EXTREME_COORD_THRESHOLD || Math.abs(chunkZ) > EXTREME_COORD_THRESHOLD) {
            ExtremeCoordEvent extremeEvent = new ExtremeCoordEvent(now, playerName, chunkX, chunkZ, worldName);
            extremeCoordEvents.computeIfAbsent(playerName, k -> new ArrayList<>()).add(extremeEvent);
            chunkBanDetections.incrementAndGet();

            // 极端坐标无需等待速率累积，直接 BLOCK
            playerStage.put(playerName, Stage.BLOCK);
            playerCooldownUntil.put(playerName, Instant.now().plusSeconds(COOLDOWN_BLOCK_SECONDS));
            blockedChunkLoads.incrementAndGet();
            return ChunkLimitResult.flagged(List.of(
                "CHUNK_BAN_ATTACK: extreme coordinate chunk load at (" + chunkX + ", " + chunkZ
                + "), distance from origin exceeds " + EXTREME_COORD_THRESHOLD + " blocks"));
        }

        // === 检测2：区块加载速率检测（5 秒滑动窗口） ===
        long windowStart = now.toEpochMilli() - (WINDOW_SECONDS * 1000);
        long chunksInWindow = events.stream()
            .filter(e -> e.timestamp.toEpochMilli() > windowStart)
            .count();

        // 计算每秒速率
        double ratePerSecond = (double) chunksInWindow / WINDOW_SECONDS;
        List<String> reasons = new ArrayList<>();
        Stage newStage = Stage.NORMAL;

        if (ratePerSecond > BLOCK_THRESHOLD) {
            // 严重超限：直接阻断
            reasons.add("CRITICAL_RATE: " + String.format("%.1f", ratePerSecond)
                + " chunks/sec (block threshold: " + BLOCK_THRESHOLD + ")");
            newStage = Stage.BLOCK;
        } else if (ratePerSecond > LIMIT_THRESHOLD) {
            // 中度超限：限制加载
            reasons.add("HIGH_RATE: " + String.format("%.1f", ratePerSecond)
                + " chunks/sec (limit threshold: " + LIMIT_THRESHOLD + ")");
            newStage = Stage.LIMIT;
        } else if (ratePerSecond > WARN_THRESHOLD) {
            // 轻度超限：警告记录
            reasons.add("ELEVATED_RATE: " + String.format("%.1f", ratePerSecond)
                + " chunks/sec (warn threshold: " + WARN_THRESHOLD + ")");
            newStage = Stage.WARN;
        }

        // === 检测3：方向一致性检测（区分正常探索和自动化扫描） ===
        // 正常玩家移动有方向惯性，Bot 扫描呈网格状来回跳跃
        if (events.size() >= 10) {
            double directionChanges = countDirectionChanges(events);
            double dirChangeRatio = directionChanges / Math.min(events.size(), 10);
            // 如果方向变化率 > 80%，说明是扫描式加载而非线性移动
            if (dirChangeRatio > 0.8 && ratePerSecond > WARN_THRESHOLD) {
                reasons.add("SCAN_PATTERN: " + String.format("%.0f%%", dirChangeRatio * 100)
                    + " direction changes, bot-like scanning detected");
                // 扫描模式升级响应等级
                if (newStage == Stage.WARN) newStage = Stage.LIMIT;
            }
        }

        // 应用响应阶段
        if (newStage != Stage.NORMAL) {
            playerStage.put(playerName, newStage);
            long cooldownSeconds = switch (newStage) {
                case WARN -> COOLDOWN_WARN_SECONDS;
                case LIMIT -> COOLDOWN_LIMIT_SECONDS;
                case BLOCK -> COOLDOWN_BLOCK_SECONDS;
                default -> 0;
            };
            playerCooldownUntil.put(playerName, Instant.now().plusSeconds(cooldownSeconds));
        }

        // 返回结果
        if (newStage == Stage.BLOCK) {
            blockedChunkLoads.incrementAndGet();
            return ChunkLimitResult.flagged(reasons);
        } else if (newStage == Stage.LIMIT) {
            blockedChunkLoads.incrementAndGet();
            return ChunkLimitResult.blocked(reasons);
        } else if (newStage == Stage.WARN) {
            return ChunkLimitResult.suspicious((int) ratePerSecond, reasons);
        }

        return ChunkLimitResult.clean();
    }

    /**
     * 计算最近区块加载事件的方向变化次数。
     * 相邻两次加载的区块坐标变化方向不同计为一次方向变化。
     */
    private double countDirectionChanges(List<ChunkLoadEvent> events) {
        if (events.size() < 3) return 0;
        int changes = 0;
        int count = Math.min(events.size(), 12);
        int start = Math.max(0, events.size() - count);
        for (int i = start + 2; i < events.size(); i++) {
            int dx1 = events.get(i - 1).chunkX - events.get(i - 2).chunkX;
            int dz1 = events.get(i - 1).chunkZ - events.get(i - 2).chunkZ;
            int dx2 = events.get(i).chunkX - events.get(i - 1).chunkX;
            int dz2 = events.get(i).chunkZ - events.get(i - 1).chunkZ;
            // 方向变化：X 或 Z 方向的正负号发生变化
            if (Integer.signum(dx1) != Integer.signum(dx2)
                || Integer.signum(dz1) != Integer.signum(dz2)) {
                changes++;
            }
        }
        return changes;
    }

    /**
     * 清除指定玩家的所有追踪数据（玩家退出时调用）。
     */
    public void clearPlayer(String playerName) {
        playerLoadHistory.remove(playerName);
        playerStage.remove(playerName);
        playerCooldownUntil.remove(playerName);
        extremeCoordEvents.remove(playerName);
    }

    /**
     * 获取当前模块运行状态与统计。
     */
    public Map<String, Object> getStatus() {
        Map<String, Object> s = new LinkedHashMap<>();
        s.put("totalChunkLoads", totalChunkLoads.get());
        s.put("blockedChunkLoads", blockedChunkLoads.get());
        s.put("chunkBanDetections", chunkBanDetections.get());
        s.put("trackedPlayers", playerLoadHistory.size());
        s.put("activeStages", playerStage.size());
        s.put("enabled", config.getSecurity().getSuperEvolution().isChunkLoadRateLimiter());

        // 世界级别统计
        Map<String, Object> worldStats = new LinkedHashMap<>();
        worldChunkLoadTotal.forEach((world, count) -> worldStats.put(world, count.get()));
        s.put("worldStats", worldStats);

        // 当前受限玩家列表
        List<Map<String, Object>> limitedPlayers = new ArrayList<>();
        for (Map.Entry<String, Stage> e : playerStage.entrySet()) {
            if (e.getValue() != Stage.NORMAL) {
                Map<String, Object> m = new LinkedHashMap<>();
                m.put("player", e.getKey());
                m.put("stage", e.getValue().name());
                Instant cooldown = playerCooldownUntil.get(e.getKey());
                m.put("cooldownUntil", cooldown != null ? cooldown.toString() : "N/A");
                List<ChunkLoadEvent> events = playerLoadHistory.get(e.getKey());
                if (events != null) {
                    long recent = events.stream()
                        .filter(ev -> ev.timestamp.isAfter(Instant.now().minusSeconds(WINDOW_SECONDS)))
                        .count();
                    m.put("recentLoads", recent);
                }
                limitedPlayers.add(m);
            }
        }
        s.put("limitedPlayers", limitedPlayers);

        // 最近极端坐标事件
        List<Map<String, Object>> extremeEvents = new ArrayList<>();
        for (Map.Entry<String, List<ExtremeCoordEvent>> e : extremeCoordEvents.entrySet()) {
            for (ExtremeCoordEvent ev : e.getValue()) {
                Map<String, Object> m = new LinkedHashMap<>();
                m.put("player", ev.playerName);
                m.put("chunkX", ev.chunkX);
                m.put("chunkZ", ev.chunkZ);
                m.put("world", ev.worldName);
                m.put("time", ev.timestamp.toString());
                extremeEvents.add(m);
            }
        }
        extremeEvents.sort((a, b) -> b.get("time").toString().compareTo(a.get("time").toString()));
        s.put("extremeCoordEvents", extremeEvents.subList(0, Math.min(extremeEvents.size(), 10)));
        return s;
    }

    public long getTotalChunkLoads() { return totalChunkLoads.get(); }
    public long getBlockedChunkLoads() { return blockedChunkLoads.get(); }
    public long getChunkBanDetections() { return chunkBanDetections.get(); }

    /**
     * 定期清理过期记录。
     */
    private void cleanupOldRecords() {
        Instant cutoff = Instant.now().minusSeconds(RECORD_RETENTION_SECONDS);
        playerLoadHistory.entrySet().removeIf(e -> {
            List<ChunkLoadEvent> events = e.getValue();
            events.removeIf(ev -> ev.timestamp.isBefore(cutoff));
            return events.isEmpty();
        });
        extremeCoordEvents.entrySet().removeIf(e -> {
            List<ExtremeCoordEvent> events = e.getValue();
            events.removeIf(ev -> ev.timestamp.isBefore(cutoff));
            return events.isEmpty();
        });
        // 清理已过期的冷却
        playerCooldownUntil.entrySet().removeIf(e -> e.getValue().isBefore(Instant.now()));
        // 同步清理已过期冷却的阶段记录
        playerStage.keySet().removeIf(k -> !playerCooldownUntil.containsKey(k));
    }

    // ==================== 内部数据类 ====================

    /**
     * 区块加载事件记录。
     */
    private static class ChunkLoadEvent {
        final Instant timestamp;
        final int chunkX;
        final int chunkZ;
        final String worldName;

        ChunkLoadEvent(Instant timestamp, int chunkX, int chunkZ, String worldName) {
            this.timestamp = timestamp;
            this.chunkX = chunkX;
            this.chunkZ = chunkZ;
            this.worldName = worldName;
        }
    }

    /**
     * 极端坐标加载事件记录 — 用于 Chunk Ban 攻击溯源。
     */
    private static class ExtremeCoordEvent {
        final Instant timestamp;
        final String playerName;
        final int chunkX;
        final int chunkZ;
        final String worldName;

        ExtremeCoordEvent(Instant timestamp, String playerName, int chunkX, int chunkZ, String worldName) {
            this.timestamp = timestamp;
            this.playerName = playerName;
            this.chunkX = chunkX;
            this.chunkZ = chunkZ;
            this.worldName = worldName;
        }
    }

    // ==================== 检测结果类 ====================

    /**
     * 区块加载限流检测结果。
     */
    public static class ChunkLimitResult {
        private final boolean blocked;
        private final boolean flagged;
        private final boolean suspicious;
        private final int score;
        private final List<String> reasons;

        private ChunkLimitResult(boolean blocked, boolean flagged, boolean suspicious,
                                 int score, List<String> reasons) {
            this.blocked = blocked;
            this.flagged = flagged;
            this.suspicious = suspicious;
            this.score = score;
            this.reasons = reasons;
        }

        /** 正常放行 */
        public static ChunkLimitResult clean() {
            return new ChunkLimitResult(false, false, false, 0, List.of());
        }

        /** 可疑行为（警告阶段） */
        public static ChunkLimitResult suspicious(int score, List<String> reasons) {
            return new ChunkLimitResult(false, false, true, score, reasons);
        }

        /** 阻止加载但不标记玩家 */
        public static ChunkLimitResult blocked(List<String> reasons) {
            return new ChunkLimitResult(true, false, true, 0, reasons);
        }

        /** 已标记（严重违规，需要干预） */
        public static ChunkLimitResult flagged(List<String> reasons) {
            return new ChunkLimitResult(true, true, true, 100, reasons);
        }

        public boolean isBlocked() { return blocked; }
        public boolean isFlagged() { return flagged; }
        public boolean isSuspicious() { return suspicious; }
        public boolean isClean() { return !blocked && !flagged && !suspicious; }
        public int getScore() { return score; }
        public List<String> getReasons() { return reasons; }
    }
}
