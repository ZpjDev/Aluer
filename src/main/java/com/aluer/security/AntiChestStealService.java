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
 * 自动偷箱检测 (Chest Stealer) — V4.0 玩家行为安全模块
 *
 * 检测原理：
 *   Chest Stealer 是一种常见的外挂功能，能在打开箱子的瞬间自动取走所有有价值的物品，
 *   让正常玩家来不及反应。本模块通过分析容器交互行为来识别自动化偷箱：
 *   1. 取物速度检测——正常玩家打开箱子后会有浏览/选择时间（数百ms到数秒），
 *      Chest Stealer 在打开 GUI 瞬间（< 50ms）开始取物。
 *   2. 单 tick 取物数量检测——正常每 tick（50ms）最多操作 1-2 个物品，
 *      单 tick 从容器取出超过 3 个物品为异常（需要发包修改才能实现）。
 *   3. 瞬间清空检测——打开容器后 100ms 内取出 5+ 物品，是 Chest Stealer 的典型特征。
 *   4. 容器交互频率——短时间内连续打开多个容器，可能是扫描高价值物品的行为。
 *   5. 物品价值分析——追踪被取走物品的类型和价值，高价值物品被快速取走增加置信度。
 *
 * 配置开关：serverguard.security.super-evolution.anti-chest-steal
 */
@Service
public class AntiChestStealService {

    private final ServerGuardConfig config;
    private final Map<String, List<ChestInteraction>> playerInteractions = new ConcurrentHashMap<>();
    private final Map<String, Instant> flaggedPlayers = new ConcurrentHashMap<>();
    private final ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor();

    /** 容器打开总次数 */
    private final AtomicLong totalChestOpens = new AtomicLong(0);
    /** 偷箱违规次数 */
    private final AtomicLong stealViolations = new AtomicLong(0);
    /** 瞬间清空行为计数 */
    private final AtomicLong instantLootCount = new AtomicLong(0);

    /** 单 tick 最大允许取物数量（正常玩家每 tick 最多操作 1-2 个物品） */
    private static final int MAX_ITEMS_PER_TICK = 2;

    /** 打开容器到开始取物的最小人类反应时间（毫秒） */
    private static final long MIN_HUMAN_REACTION_MS = 200;

    /** 瞬间清空检测窗口（毫秒）——打开后此时间内取走大量物品 */
    private static final long INSTANT_LOOT_WINDOW_MS = 100;

    /** 瞬间清空最少物品数阈值——在窗口内取走超过此数触发检测 */
    private static final int INSTANT_LOOT_MIN_ITEMS = 5;

    /** 短时间内连续打开容器检测窗口（秒） */
    private static final long CONTAINER_SPAM_WINDOW_SEC = 5;

    /** 短时间内容器打开次数上限 */
    private static final int MAX_CONTAINER_OPENS_SHORT = 8;

    /** 高价值物品列表——这些物品被快速取走时权重更高 */
    private static final Set<String> HIGH_VALUE_ITEMS = Set.of(
        "DIAMOND", "DIAMOND_BLOCK", "NETHERITE_INGOT", "NETHERITE_BLOCK",
        "NETHERITE_SCRAP", "ANCIENT_DEBRIS", "EMERALD", "EMERALD_BLOCK",
        "TOTEM_OF_UNDYING", "ELYTRA", "BEACON", "NETHER_STAR",
        "ENCHANTED_GOLDEN_APPLE", "GOLDEN_APPLE", "ENDER_PEARL",
        "SHULKER_SHELL", "SHULKER_BOX", "ENDER_CHEST"
    );

    /** 记录保留时间（秒） */
    private static final long RECORD_RETENTION_SECONDS = 300;

    /** 标记持续时间（秒） */
    private static final long FLAG_DURATION_SECONDS = 1800;

    public AntiChestStealService() {
        this(new ServerGuardConfig());
    }

    @Autowired
    public AntiChestStealService(ServerGuardConfig config) {
        this.config = config;
        scheduler.scheduleAtFixedRate(this::cleanupOldRecords, 60, 120, TimeUnit.SECONDS);
    }

    /**
     * 检测容器打开事件——记录并分析是否为 Chest Stealer 行为。
     *
     * @param playerName    玩家名称
     * @param playerUUID    玩家 UUID
     * @param containerType 容器类型（CHEST、ENDER_CHEST、SHULKER_BOX 等）
     * @param x             容器 X 坐标
     * @param y             容器 Y 坐标
     * @param z             容器 Z 坐标
     * @return 检测结果
     */
    public DetectionResult detectOpen(String playerName, String playerUUID,
                                       String containerType, int x, int y, int z) {
        if (!config.getSecurity().getSuperEvolution().isAntiChestSteal()) {
            return DetectionResult.clean();
        }

        // 检查标记状态
        Instant flaggedUntil = flaggedPlayers.get(playerName);
        if (flaggedUntil != null) {
            if (Instant.now().isAfter(flaggedUntil)) {
                flaggedPlayers.remove(playerName);
            } else {
                return DetectionResult.flagged(List.of(
                    "PLAYER_ALREADY_FLAGGED: " + playerName + " is under chest steal investigation"));
            }
        }

        Instant now = Instant.now();
        List<ChestInteraction> records = playerInteractions.computeIfAbsent(playerName,
            k -> Collections.synchronizedList(new ArrayList<>()));

        // 记录打开事件
        ChestInteraction interaction = new ChestInteraction(now, "OPEN", containerType,
            x, y, z, null, 0);
        records.add(interaction);
        totalChestOpens.incrementAndGet();

        // === 检测: 容器交互频率 ===
        // 短时间内连续打开多个容器可能是扫描行为
        long spamWindowStart = now.toEpochMilli() - (CONTAINER_SPAM_WINDOW_SEC * 1000);
        long opensInWindow = records.stream()
            .filter(r -> "OPEN".equals(r.actionType))
            .filter(r -> r.time.toEpochMilli() > spamWindowStart)
            .count();

        if (opensInWindow > MAX_CONTAINER_OPENS_SHORT) {
            int score = 20;
            List<String> reasons = List.of("CONTAINER_SPAM: " + opensInWindow
                + " containers opened in " + CONTAINER_SPAM_WINDOW_SEC + "s");
            return DetectionResult.suspicious(score, reasons);
        }

        return DetectionResult.clean();
    }

    /**
     * 检测从容器取出物品的操作——分析取物速度和模式。
     *
     * 这是 Chest Stealer 检测的核心方法，每次从容器取出物品时调用。
     * 通过追踪取物时间戳、物品数量和价值来构建行为画像。
     *
     * @param playerName    玩家名称
     * @param playerUUID    玩家 UUID
     * @param itemType      被取出物品的类型
     * @param itemCount     取出数量
     * @param containerType 容器类型
     * @param slot          物品所在的槽位
     * @return 检测结果
     */
    public DetectionResult detectTakeItem(String playerName, String playerUUID,
                                           String itemType, int itemCount,
                                           String containerType, int slot) {
        if (!config.getSecurity().getSuperEvolution().isAntiChestSteal()) {
            return DetectionResult.clean();
        }

        // 检查标记状态
        Instant flaggedUntil = flaggedPlayers.get(playerName);
        if (flaggedUntil != null) {
            if (Instant.now().isAfter(flaggedUntil)) {
                flaggedPlayers.remove(playerName);
            } else {
                return DetectionResult.flagged(List.of(
                    "PLAYER_ALREADY_FLAGGED"));
            }
        }

        Instant now = Instant.now();
        List<ChestInteraction> records = playerInteractions.computeIfAbsent(playerName,
            k -> Collections.synchronizedList(new ArrayList<>()));

        // 记录取物事件
        ChestInteraction interaction = new ChestInteraction(now, "TAKE", containerType,
            0, 0, 0, itemType, itemCount);
        records.add(interaction);

        int score = 0;
        List<String> reasons = new ArrayList<>();

        // === 检测 1: 单 tick 取物数量 ===
        // 在同一 50ms tick 内取出多个物品是发包修改的典型行为
        long tickStart = now.toEpochMilli() - 50;
        long sameTickTakes = records.stream()
            .filter(r -> "TAKE".equals(r.actionType))
            .filter(r -> r.time.toEpochMilli() > tickStart)
            .count();

        if (sameTickTakes > MAX_ITEMS_PER_TICK) {
            score += 35;
            reasons.add("SAME_TICK_MULTI_TAKE: " + sameTickTakes +
                " items taken in single tick (max normal=" + MAX_ITEMS_PER_TICK + ")");
        }

        // === 检测 2: 高价值物品快速取走 ===
        if (itemType != null && HIGH_VALUE_ITEMS.contains(itemType.toUpperCase())) {
            // 查找最近的 OPEN 事件
            Optional<ChestInteraction> lastOpen = records.stream()
                .filter(r -> "OPEN".equals(r.actionType))
                .reduce((first, second) -> second);

            if (lastOpen.isPresent()) {
                long reactionTime = now.toEpochMilli() - lastOpen.get().time.toEpochMilli();
                if (reactionTime < MIN_HUMAN_REACTION_MS) {
                    score += 25;
                    reasons.add("FAST_HIGH_VALUE_TAKE: " + itemType +
                        " taken in " + reactionTime + "ms (min human reaction="
                        + MIN_HUMAN_REACTION_MS + "ms)");
                }
            }
        }

        // === 检测 3: 瞬间清空模式 ===
        // 查找最近一次 OPEN 事件，计算打开后在短窗口内取走的物品数量
        Optional<ChestInteraction> lastOpen = records.stream()
            .filter(r -> "OPEN".equals(r.actionType))
            .reduce((first, second) -> second);

        if (lastOpen.isPresent()) {
            long openTime = lastOpen.get().time.toEpochMilli();
            long itemsSinceOpen = records.stream()
                .filter(r -> "TAKE".equals(r.actionType))
                .filter(r -> r.time.toEpochMilli() > openTime)
                .filter(r -> r.time.toEpochMilli() < openTime + INSTANT_LOOT_WINDOW_MS)
                .count();

            if (itemsSinceOpen >= INSTANT_LOOT_MIN_ITEMS) {
                score += 40;
                reasons.add("INSTANT_LOOT: " + itemsSinceOpen + " items taken in "
                    + INSTANT_LOOT_WINDOW_MS + "ms after open (chest stealer signature)");
                instantLootCount.incrementAndGet();
            }
        }

        // === 检测 4: 取物总量异常 ===
        // 检查最近一次打开容器后的总取物数量是否异常
        if (lastOpen.isPresent()) {
            long openTime = lastOpen.get().time.toEpochMilli();
            long totalItemsTaken = records.stream()
                .filter(r -> "TAKE".equals(r.actionType))
                .filter(r -> r.time.toEpochMilli() > openTime)
                .filter(r -> r.time.toEpochMilli() < openTime + 200)
                .count();

            if (totalItemsTaken >= 8) {
                score += 30;
                reasons.add("MASS_TAKE: " + totalItemsTaken + " items taken from single container");
            }
        }

        if (score >= 50) {
            flaggedPlayers.put(playerName, Instant.now().plusSeconds(FLAG_DURATION_SECONDS));
            stealViolations.incrementAndGet();
            return DetectionResult.flagged(reasons);
        } else if (score >= 25) {
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
        playerInteractions.remove(playerName);
        flaggedPlayers.remove(playerName);
    }

    /**
     * 获取模块运行状态。
     *
     * @return 包含统计数据的 LinkedHashMap
     */
    public Map<String, Object> getStatus() {
        Map<String, Object> s = new LinkedHashMap<>();
        s.put("totalChestOpens", totalChestOpens.get());
        s.put("stealViolations", stealViolations.get());
        s.put("instantLootCount", instantLootCount.get());
        s.put("trackedPlayers", playerInteractions.size());
        s.put("flaggedPlayers", flaggedPlayers.size());
        s.put("enabled", config.getSecurity().getSuperEvolution().isAntiChestSteal());

        List<Map<String, Object>> flagged = new ArrayList<>();
        for (Map.Entry<String, Instant> e : flaggedPlayers.entrySet()) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("player", e.getKey());
            m.put("flaggedUntil", e.getValue().toString());
            List<ChestInteraction> records = playerInteractions.get(e.getKey());
            if (records != null) {
                m.put("totalInteractions", records.size());
            }
            flagged.add(m);
        }
        s.put("flaggedPlayersList", flagged);

        return s;
    }

    public long getTotalChestOpens() { return totalChestOpens.get(); }
    public long getStealViolations() { return stealViolations.get(); }
    public long getInstantLootCount() { return instantLootCount.get(); }

    /**
     * 定期清理过期记录。
     */
    private void cleanupOldRecords() {
        Instant cutoff = Instant.now().minusSeconds(RECORD_RETENTION_SECONDS);
        playerInteractions.entrySet().removeIf(e -> {
            List<ChestInteraction> records = e.getValue();
            records.removeIf(r -> r.time.isBefore(cutoff));
            return records.isEmpty();
        });
        flaggedPlayers.entrySet().removeIf(e -> e.getValue().isBefore(Instant.now()));
    }

    // ==================== 内部数据类 ====================

    /**
     * 容器交互记录——记录 OPEN（打开）/ TAKE（取物）/ CLOSE（关闭）等操作。
     */
    private static class ChestInteraction {
        final Instant time;
        final String actionType;
        final String containerType;
        final int x, y, z;
        final String itemType;
        final int itemCount;

        ChestInteraction(Instant time, String actionType, String containerType,
                        int x, int y, int z, String itemType, int itemCount) {
            this.time = time;
            this.actionType = actionType;
            this.containerType = containerType;
            this.x = x;
            this.y = y;
            this.z = z;
            this.itemType = itemType;
            this.itemCount = itemCount;
        }
    }

    // ==================== 检测结果类 ====================

    /**
     * Chest Stealer 检测结果。
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

        /** 无异常：容器交互行为正常 */
        public static DetectionResult clean() {
            return new DetectionResult(false, false, 0, List.of());
        }

        /** 可疑行为：存在异常容器交互模式 */
        public static DetectionResult suspicious(int score, List<String> reasons) {
            return new DetectionResult(false, true, score, reasons);
        }

        /** 已标记：检测到高置信度 Chest Stealer 行为 */
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
