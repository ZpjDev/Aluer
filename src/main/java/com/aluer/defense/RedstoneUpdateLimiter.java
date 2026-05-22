package com.aluer.defense;

import com.aluer.config.ServerGuardConfig;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedDeque;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

/**
 * 红石更新频率限制器 — V5.0 服务器保护模块
 *
 * 检测原理：
 *   Minecraft 红石系统是服务器 TPS 杀手的第一大来源。单个红石机器（如
 *   高速刷石机、大型分类机或恶意卡服机）可以在单个 tick 内产生数千次
 *   方块更新，导致服务器 TPS 急剧下降至个位数。本模块在 tick 级别追踪
 *   每个区块的红石更新频率，识别并抑制异常活跃的红石区块。
 *
 * 已知的恶意红石模式：
 *   1. Observer 时钟循环 — 两个 Observer 面对面形成无限循环，每 tick 产生更新
 *   2. 红石粉能量循环 — 红石粉通过 Comparator 形成自激振荡回路
 *   3. 活塞更新链 — 大量活塞首尾相连，一次触发导致数百个活塞依次激活
 *   4. Comparator 时钟电路 — 减法模式 Comparator 自反馈回路高速振荡
 *   5. 漏斗矿车收集链 — 大量漏斗矿车在铁轨上形成的实体 tick 风暴
 *
 * 递进式响应策略：
 *   WARN (>200 更新/tick/区块)  — 监控记录，发送 TPS 关联告警
 *   SLOW (>500 更新/tick/区块)  — 跳过交替 tick 的红石更新（降频 50%）
 *   FREEZE (>1000 更新/tick/区块) — 完全禁用该区块红石更新，进入冷却期
 *
 * 自动恢复机制：
 *   SLOW 冷却 30 秒后恢复正常
 *   FREEZE 冷却 120 秒后恢复正常
 *   如果在冷却期再次触发，冷却时间翻倍（指数退避）
 *
 * 配置开关：serverguard.security.super-evolution.redstone-update-limiter
 */
@Service
public class RedstoneUpdateLimiter {

    private final ServerGuardConfig config;

    /** 按区块键追踪红石更新计数：chunkKey -> RedstoneChunkStats */
    private final Map<String, RedstoneChunkStats> chunkStatsMap = new ConcurrentHashMap<>();

    /** 按区块键追踪最近的 tick 级别红石更新次数（滑动窗口，保留 20 ticks） */
    private final Map<String, ConcurrentLinkedDeque<Integer>> chunkUpdateWindow = new ConcurrentHashMap<>();

    /** 区块当前受限状态 */
    private final Map<String, RestrictionState> chunkRestrictionState = new ConcurrentHashMap<>();

    /** 区块冷却到期时间 */
    private final Map<String, Instant> chunkCooldownUntil = new ConcurrentHashMap<>();

    /** 每区块冷却次数（用于指数退避） */
    private final Map<String, AtomicLong> chunkCooldownCount = new ConcurrentHashMap<>();

    /** 总红石更新计数 */
    private final AtomicLong totalRedstoneUpdates = new AtomicLong(0);
    /** 被抑制的红石更新计数 */
    private final AtomicLong suppressedUpdates = new AtomicLong(0);
    /** 红石风暴检测次数 */
    private final AtomicLong redstoneStormDetections = new AtomicLong(0);

    private final ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor();

    /** per tick 红石更新阈值（单区块） */
    private static final int WARN_THRESHOLD_PER_TICK = 200;
    private static final int SLOW_THRESHOLD_PER_TICK = 500;
    private static final int FREEZE_THRESHOLD_PER_TICK = 1000;

    /** 滑动窗口大小（ticks），约 1 秒 = 20 ticks */
    private static final int TICK_WINDOW_SIZE = 20;

    /** 冷却时间（秒） */
    private static final long COOLDOWN_SLOW_SECONDS = 30;
    private static final long COOLDOWN_FREEZE_SECONDS = 120;

    /** 最大冷却时间（秒，指数退避上限） */
    private static final long MAX_COOLDOWN_SECONDS = 600;

    /** 记录保留时间（秒） */
    private static final long RECORD_RETENTION_SECONDS = 600;

    /** 已知卡服红石方块类型（优先级更高的监控对象） */
    private static final Set<String> HIGH_PRIORITY_REDSTONE = Set.of(
        "OBSERVER", "PISTON", "STICKY_PISTON", "REDSTONE_WIRE",
        "COMPARATOR", "REPEATER", "REDSTONE_TORCH", "HOPPER",
        "DISPENSER", "DROPPER", "NOTE_BLOCK", "BELL",
        "SCULK_SENSOR", "CALIBRATED_SCULK_SENSOR", "SCULK_SHRIEKER"
    );

    /** 区块红石受限状态 */
    public enum RestrictionState {
        NORMAL,   // 正常
        WARN,     // 警告监控中
        SLOW,     // 降频（50% 跳过率）
        FREEZE    // 冻结（100% 跳过）
    }

    public RedstoneUpdateLimiter() {
        this(new ServerGuardConfig());
    }

    @Autowired
    public RedstoneUpdateLimiter(ServerGuardConfig config) {
        this.config = config;
        // 每 60 秒清理过期数据
        scheduler.scheduleAtFixedRate(this::cleanupOldRecords, 60, 60, TimeUnit.SECONDS);
    }

    /**
     * 检查一次红石更新是否应该被允许执行。
     *
     * 调用时机：Paper 的红石更新事件监听器中，每次方块接收红石更新时调用。
     *
     * @param chunkKey      区块键（chunkX:chunkZ:world）
     * @param blockType     触发更新的方块类型
     * @param currentTick   当前服务器 tick 编号
     * @param sourcePlayer  触发更新的玩家名称（可为 null，如自然红石信号传播）
     * @return 红石更新检查结果
     */
    public RedstoneUpdateResult checkUpdate(String chunkKey, String blockType,
                                             long currentTick, String sourcePlayer) {
        if (!config.getSecurity().getSuperEvolution().isRedstoneUpdateLimiter()) {
            return RedstoneUpdateResult.clean();
        }

        totalRedstoneUpdates.incrementAndGet();

        // 获取或创建区块统计
        RedstoneChunkStats stats = chunkStatsMap.computeIfAbsent(chunkKey,
            k -> new RedstoneChunkStats(chunkKey));
        stats.totalUpdates++;
        stats.lastTick = currentTick;
        stats.lastActivity = Instant.now();

        // 更新方块类型计数
        String upperType = blockType.toUpperCase();
        stats.blockTypeCount.merge(upperType, 1, Integer::sum);

        // 高优先级红石组件单独追踪（已知的卡服方块）
        if (HIGH_PRIORITY_REDSTONE.contains(upperType)) {
            stats.highPriorityUpdateCount++;
        }

        // 维护 tick 级别滑动窗口
        ConcurrentLinkedDeque<Integer> window = chunkUpdateWindow.computeIfAbsent(chunkKey,
            k -> new ConcurrentLinkedDeque<>());

        // 使用 ThreadLocal tick 追踪器避免同一 tick 多次增长窗口
        // 此处简化为直接使用 tick 编号判断是否需要增加窗口条目
        if (window.isEmpty() || stats.lastProcessedTick != currentTick) {
            // 新 tick：将本 tick 更新数重置并加入窗口
            if (!window.isEmpty()) {
                // 将上一个 tick 的计数加入窗口
                int prevTickCount = (int) stats.currentTickUpdates;
                window.addLast(prevTickCount);
                // 保持窗口大小
                while (window.size() > TICK_WINDOW_SIZE) {
                    window.pollFirst();
                }
            }
            stats.currentTickUpdates = 1;
            stats.lastProcessedTick = currentTick;
        } else {
            // 同一 tick：累加计数
            stats.currentTickUpdates++;
        }

        // 如果窗口数据不足，暂不做判断
        if (window.size() < 3) {
            return RedstoneUpdateResult.clean();
        }

        // === 检查当前冷却状态 ===
        Instant now = Instant.now();
        RestrictionState currentState = chunkRestrictionState.getOrDefault(chunkKey, RestrictionState.NORMAL);
        Instant cooldownUntil = chunkCooldownUntil.get(chunkKey);

        if (currentState != RestrictionState.NORMAL && cooldownUntil != null) {
            if (now.isBefore(cooldownUntil)) {
                // 仍在冷却期
                if (currentState == RestrictionState.FREEZE) {
                    suppressedUpdates.incrementAndGet();
                    return RedstoneUpdateResult.blocked(List.of(
                        "FREEZE_COOLDOWN: chunk " + chunkKey + " redstone frozen until " + cooldownUntil));
                } else if (currentState == RestrictionState.SLOW) {
                    // SLOW 模式：50% 跳过率
                    if (Math.random() < 0.5) {
                        suppressedUpdates.incrementAndGet();
                        return RedstoneUpdateResult.blocked(List.of(
                            "SLOW_COOLDOWN: throttled redstone update in chunk " + chunkKey));
                    }
                }
                // WARN 模式不阻止，继续往下检测
            } else {
                // 冷却到期，恢复正常
                chunkRestrictionState.remove(chunkKey);
                chunkCooldownUntil.remove(chunkKey);
                currentState = RestrictionState.NORMAL;
            }
        }

        // === 实时速率检测：计算最近几个 tick 的平均更新频率 ===
        long totalRecentUpdates = window.stream().mapToLong(Integer::longValue).sum();
        double avgPerTick = (double) totalRecentUpdates / window.size();

        // 同时考虑当前 tick 的实时更新数
        long currentTickUpdates = stats.currentTickUpdates;

        List<String> reasons = new ArrayList<>();
        RestrictionState newState = RestrictionState.NORMAL;
        boolean shouldRestrict = false;

        // FREEZE 检测：当前 tick 更新数超 1000 或平均超 1000
        if (currentTickUpdates > FREEZE_THRESHOLD_PER_TICK || avgPerTick > FREEZE_THRESHOLD_PER_TICK) {
            reasons.add("REDSTONE_STORM: currentTick=" + currentTickUpdates
                + " updates, avgPerTick=" + String.format("%.1f", avgPerTick)
                + " (freeze threshold: " + FREEZE_THRESHOLD_PER_TICK + ")");
            newState = RestrictionState.FREEZE;
            shouldRestrict = true;
            redstoneStormDetections.incrementAndGet();
        }
        // SLOW 检测：当前 tick 更新数超 500 或平均超 500
        else if (currentTickUpdates > SLOW_THRESHOLD_PER_TICK || avgPerTick > SLOW_THRESHOLD_PER_TICK) {
            reasons.add("HIGH_REDSTONE_ACTIVITY: currentTick=" + currentTickUpdates
                + " updates, avgPerTick=" + String.format("%.1f", avgPerTick)
                + " (slow threshold: " + SLOW_THRESHOLD_PER_TICK + ")");
            newState = RestrictionState.SLOW;
            shouldRestrict = true;
        }
        // WARN 检测
        else if (currentTickUpdates > WARN_THRESHOLD_PER_TICK || avgPerTick > WARN_THRESHOLD_PER_TICK) {
            reasons.add("ELEVATED_REDSTONE: currentTick=" + currentTickUpdates
                + " updates, avgPerTick=" + String.format("%.1f", avgPerTick)
                + " (warn threshold: " + WARN_THRESHOLD_PER_TICK + ")");
            newState = RestrictionState.WARN;
        }

        // === Observer 时钟循环专项检测 ===
        // 如果高优先级红石组件占比超过总更新的 80%，很可能存在时钟回路
        if (stats.totalUpdates > 100 && stats.highPriorityUpdateCount > stats.totalUpdates * 0.8) {
            reasons.add("CLOCK_LOOP_PATTERN: " + stats.highPriorityUpdateCount
                + "/" + stats.totalUpdates + " high-priority updates ("
                + String.format("%.0f%%", 100.0 * stats.highPriorityUpdateCount / stats.totalUpdates)
                + "), suspected observer/redstone clock loop");
            // 时钟回路模式升级响应
            if (newState == RestrictionState.WARN) newState = RestrictionState.SLOW;
            shouldRestrict = true;
        }

        // === 应用限制 ===
        if (shouldRestrict) {
            long cooldownCount = chunkCooldownCount
                .computeIfAbsent(chunkKey, k -> new AtomicLong(0))
                .incrementAndGet();

            long baseCooldown = switch (newState) {
                case SLOW -> COOLDOWN_SLOW_SECONDS;
                case FREEZE -> COOLDOWN_FREEZE_SECONDS;
                default -> COOLDOWN_SLOW_SECONDS;
            };

            // 指数退避：每次重复触发冷却翻倍，上限 MAX_COOLDOWN_SECONDS
            long actualCooldown = Math.min(baseCooldown * (1L << Math.min(cooldownCount - 1, 4)),
                MAX_COOLDOWN_SECONDS);

            chunkRestrictionState.put(chunkKey, newState);
            chunkCooldownUntil.put(chunkKey, now.plusSeconds(actualCooldown));

            if (newState == RestrictionState.FREEZE) {
                suppressedUpdates.incrementAndGet();
                return RedstoneUpdateResult.flagged(reasons);
            } else if (newState == RestrictionState.SLOW) {
                // SLOW 状态的首次更新仍然放行，后续才开始跳过
                return RedstoneUpdateResult.blocked(reasons);
            }
        }

        if (!reasons.isEmpty()) {
            return RedstoneUpdateResult.suspicious(reasons.size() * 10, reasons);
        }

        return RedstoneUpdateResult.clean();
    }

    /**
     * 获取前 N 个红石最活跃的区块（供管理员审查）。
     *
     * @param topN 返回数量
     * @return 按活跃度排序的区块列表
     */
    public List<Map<String, Object>> getTopActiveChunks(int topN) {
        List<Map<String, Object>> result = new ArrayList<>();
        chunkStatsMap.entrySet().stream()
            .sorted((a, b) -> Long.compare(b.getValue().totalUpdates, a.getValue().totalUpdates))
            .limit(topN)
            .forEach(e -> {
                Map<String, Object> m = new LinkedHashMap<>();
                m.put("chunk", e.getKey());
                m.put("totalUpdates", e.getValue().totalUpdates);
                m.put("highPriorityUpdates", e.getValue().highPriorityUpdateCount);
                RestrictionState state = chunkRestrictionState.get(e.getKey());
                m.put("restrictionState", state != null ? state.name() : "NORMAL");
                m.put("blockTypeCount", new LinkedHashMap<>(e.getValue().blockTypeCount));
                result.add(m);
            });
        return result;
    }

    /**
     * 手动解除区块的红石限制（管理员命令）。
     */
    public void liftRestriction(String chunkKey) {
        chunkRestrictionState.remove(chunkKey);
        chunkCooldownUntil.remove(chunkKey);
        chunkCooldownCount.remove(chunkKey);
    }

    /**
     * 获取区块当前的红石活动统计。
     */
    public Map<String, Object> getChunkStats(String chunkKey) {
        RedstoneChunkStats stats = chunkStatsMap.get(chunkKey);
        if (stats == null) return Map.of("exists", false);

        Map<String, Object> m = new LinkedHashMap<>();
        m.put("exists", true);
        m.put("chunk", chunkKey);
        m.put("totalUpdates", stats.totalUpdates);
        m.put("highPriorityUpdates", stats.highPriorityUpdateCount);
        m.put("currentTickUpdates", stats.currentTickUpdates);
        m.put("lastTick", stats.lastTick);
        RestrictionState state = chunkRestrictionState.getOrDefault(chunkKey, RestrictionState.NORMAL);
        m.put("restrictionState", state.name());
        Instant cooldown = chunkCooldownUntil.get(chunkKey);
        m.put("cooldownUntil", cooldown != null ? cooldown.toString() : "N/A");
        AtomicLong count = chunkCooldownCount.get(chunkKey);
        m.put("cooldownCount", count != null ? count.get() : 0);
        return m;
    }

    /**
     * 获取当前模块运行状态。
     */
    public Map<String, Object> getStatus() {
        Map<String, Object> s = new LinkedHashMap<>();
        s.put("totalRedstoneUpdates", totalRedstoneUpdates.get());
        s.put("suppressedUpdates", suppressedUpdates.get());
        s.put("redstoneStormDetections", redstoneStormDetections.get());
        s.put("trackedChunks", chunkStatsMap.size());
        s.put("restrictedChunks", chunkRestrictionState.size());
        s.put("enabled", config.getSecurity().getSuperEvolution().isRedstoneUpdateLimiter());

        // 当前受限区块详情
        List<Map<String, Object>> restrictedChunks = new ArrayList<>();
        for (Map.Entry<String, RestrictionState> e : chunkRestrictionState.entrySet()) {
            if (e.getValue() != RestrictionState.NORMAL) {
                Map<String, Object> m = new LinkedHashMap<>();
                m.put("chunk", e.getKey());
                m.put("state", e.getValue().name());
                Instant cooldown = chunkCooldownUntil.get(e.getKey());
                m.put("cooldownUntil", cooldown != null ? cooldown.toString() : "N/A");
                restrictedChunks.add(m);
            }
        }
        s.put("activeRestrictions", restrictedChunks);

        // Top-10 活跃区块
        s.put("topActiveChunks", getTopActiveChunks(10));

        return s;
    }

    public long getTotalRedstoneUpdates() { return totalRedstoneUpdates.get(); }
    public long getSuppressedUpdates() { return suppressedUpdates.get(); }
    public long getRedstoneStormDetections() { return redstoneStormDetections.get(); }

    /**
     * 清理过期记录。
     */
    private void cleanupOldRecords() {
        Instant cutoff = Instant.now().minusSeconds(RECORD_RETENTION_SECONDS);
        chunkStatsMap.entrySet().removeIf(e -> e.getValue().lastActivity.isBefore(cutoff));
        // 清理相应的窗口数据
        chunkUpdateWindow.keySet().removeIf(k -> !chunkStatsMap.containsKey(k));
        // 清理冷却及相关记录
        chunkCooldownUntil.entrySet().removeIf(e -> e.getValue().isBefore(Instant.now()));
        chunkRestrictionState.keySet().removeIf(k -> !chunkCooldownUntil.containsKey(k));
        chunkCooldownCount.keySet().removeIf(k -> !chunkCooldownUntil.containsKey(k));
    }

    // ==================== 内部数据类 ====================

    /**
     * 区块红石统计数据。
     */
    private static class RedstoneChunkStats {
        final String chunkKey;
        long totalUpdates = 0;
        long highPriorityUpdateCount = 0;
        long currentTickUpdates = 0;
        long lastTick = 0;
        long lastProcessedTick = -1;
        final Map<String, Integer> blockTypeCount = new ConcurrentHashMap<>();
        Instant lastActivity = Instant.now();

        RedstoneChunkStats(String chunkKey) {
            this.chunkKey = chunkKey;
        }
    }

    // ==================== 检测结果类 ====================

    /**
     * 红石更新检查结果。
     */
    public static class RedstoneUpdateResult {
        private final boolean blocked;
        private final boolean flagged;
        private final boolean suspicious;
        private final int score;
        private final List<String> reasons;

        private RedstoneUpdateResult(boolean blocked, boolean flagged, boolean suspicious,
                                     int score, List<String> reasons) {
            this.blocked = blocked;
            this.flagged = flagged;
            this.suspicious = suspicious;
            this.score = score;
            this.reasons = reasons;
        }

        /** 正常：红石活动在安全范围内 */
        public static RedstoneUpdateResult clean() {
            return new RedstoneUpdateResult(false, false, false, 0, List.of());
        }

        /** 可疑：红石活动偏高但未达到限制阈值 */
        public static RedstoneUpdateResult suspicious(int score, List<String> reasons) {
            return new RedstoneUpdateResult(false, false, true, score, reasons);
        }

        /** 阻止：本次红石更新被跳过（降频模式） */
        public static RedstoneUpdateResult blocked(List<String> reasons) {
            return new RedstoneUpdateResult(true, false, true, 0, reasons);
        }

        /** 已标记：红石风暴，区块红石已被冻结 */
        public static RedstoneUpdateResult flagged(List<String> reasons) {
            return new RedstoneUpdateResult(true, true, true, 100, reasons);
        }

        public boolean isBlocked() { return blocked; }
        public boolean isFlagged() { return flagged; }
        public boolean isSuspicious() { return suspicious; }
        public boolean isClean() { return !blocked && !flagged && !suspicious; }
        public int getScore() { return score; }
        public List<String> getReasons() { return reasons; }
    }
}
