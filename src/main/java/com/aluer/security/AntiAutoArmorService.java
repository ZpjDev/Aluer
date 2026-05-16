package com.aluer.security;

import com.aluer.config.ServerGuardConfig;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * 自动盔甲（AutoArmor）检测服务 — V5.1 反作弊战斗模块
 *
 * 检测原理：
 * 1. 多槽位装甲切换速度检测 — Meteor Client的AutoArmor模块在玩家打开背包后
 *    自动将背包中最优品质的盔甲装备到对应槽位。正常玩家每个盔甲槽位切换需要
 *    200-500ms（鼠标移动+点击），而hack可以在单tick（0-50ms）内完成所有4个
 *    槽位的装备。追踪同一tick或极短时间窗口内的多槽位装备变更次数。
 * 2. 背包开关与盔甲更换时序关联 — 追踪背包打开（InventoryOpenEvent/InventoryClickEvent）
 *    到背包关闭（InventoryCloseEvent）的时间窗口，以及在此期间发生的装备槽位变更。
 *    正常的流程：打开背包 → 逐个操作（每个操作100-400ms间隔） → 关闭背包。
 *    Hack流程：打开背包 → 同一tick内所有槽位变更 → 立即关闭背包。
 *    如果背包从打开到关闭仅持续1-2 tick，但期间发生了多个装备槽位变更，确定作弊。
 * 3. 登录即时装备检测 — 玩家加入游戏后，正常玩家需要数秒才会打开背包检查装备。
 *    AutoArmor用户在加入后首tick内即完成全套盔甲装备。追踪玩家加入时间与首次
 *    装备槽位变更的时间间隔。如果加入后500ms内完成了3个以上槽位的装备变更，
 *    则是自动化装备行为。
 * 4. 装备变更间隔分析 — 追踪同一玩家连续两次装备槽位变更之间的时间间隔。
 *    正常玩家：100-500ms的随机间隔。Hack：所有槽位在0-50ms内连续切换，
 *    间隔高度一致（标准差极低），呈现机械化的均匀节奏。
 *
 * 配置开关：serverguard.security.super-evolution.anti-auto-armor
 */
@Service
public class AntiAutoArmorService {

    private final ServerGuardConfig config;

    /**
     * 追踪每个玩家的装备槽位变更记录（playerName -> 变更事件列表）
     */
    private final Map<String, List<ArmorChangeEvent>> playerArmorChanges = new ConcurrentHashMap<>();

    /**
     * 追踪每个玩家最近的背包操作状态（playerName -> 背包状态记录）
     */
    private final Map<String, InventoryState> playerInventoryState = new ConcurrentHashMap<>();

    /**
     * 追踪每个玩家的加入时间（playerName -> 加入时间戳）
     */
    private final Map<String, Instant> playerJoinTime = new ConcurrentHashMap<>();

    /**
     * 追踪疑似AutoArmor的事件（playerName -> 可疑事件列表）
     */
    private final Map<String, List<Map<String, Object>>> autoArmorEvents = new ConcurrentHashMap<>();

    private final AtomicLong totalArmorEquips = new AtomicLong(0);
    private final AtomicLong flaggedCount = new AtomicLong(0);

    /**
     * 单tick内多槽位装备阈值 — 同一tick内装备超过此数量的槽位即标记
     * 正常玩家每tick最多操作1-2个槽位（通常是1个）
     */
    private static final int MAX_SLOTS_PER_TICK = 2;

    /**
     * 装甲槽位变更最小人类间隔（毫秒）
     * 200ms = 视觉定位（~100ms）+ 鼠标移动（~50ms）+ 点击（~50ms）
     */
    private static final long MIN_HUMAN_ARMOR_INTERVAL_MS = 150;

    /**
     * Hack级别装备时间阈值（毫秒）
     * 50ms以下几乎确定是作弊（同tick内机械操作）
     */
    private static final long HACK_LEVEL_INTERVAL_MS = 50;

    /**
     * 背包操作可疑最大持续时间（毫秒）
     * 如果背包从打开到关闭在此时间内且完成了多个装备槽位变更，高度可疑
     */
    private static final long SUSPICIOUS_INVENTORY_DURATION_MS = 100;

    /**
     * 登录后装备检测窗口（毫秒）
     * 在登录后此时间窗口内完成大量装备变更即标记
     */
    private static final long JOIN_EQUIP_WINDOW_MS = 500;

    /**
     * 登录后窗口内最大允许的装备槽位数（正常水平）
     */
    private static final int MAX_EQUIPS_ON_JOIN = 2;

    /**
     * 连续快速装备次数阈值 — 连续N次间隔都小于最小人类间隔即标记
     */
    private static final int MAX_CONSECUTIVE_FAST_EQUIPS = 3;

    /**
     * 单槽位连续装备间隔标准差阈值 — 低于此值说明机械化节奏
     */
    private static final double MECHANICAL_STDEV_THRESHOLD_MS = 10.0;

    /**
     * 每个玩家保留的最大记录数
     */
    private static final int MAX_RECORDS = 60;

    /** 已知的盔甲槽位类型 */
    public enum ArmorSlot {
        HEAD,      // 头盔槽
        CHEST,     // 胸甲槽
        LEGS,      // 护腿槽
        FEET       // 靴子槽
    }

    /**
     * 无参构造函数 — 测试/默认配置使用
     */
    public AntiAutoArmorService() {
        this(new ServerGuardConfig());
    }

    /**
     * Spring 注入构造函数
     * @param config 全局配置，提供模块开关控制
     */
    public AntiAutoArmorService(ServerGuardConfig config) {
        this.config = config;
    }

    /**
     * 记录玩家加入服务器事件
     * 应在新玩家连接时调用，用于登录即时装备检测
     *
     * @param playerName 玩家名称
     * @param timestamp 加入时间戳
     */
    public void recordPlayerJoin(String playerName, Instant timestamp) {
        if (!config.getSecurity().getSuperEvolution().isAntiAutoArmor()) {
            return;
        }
        playerJoinTime.put(playerName, timestamp);
    }

    /**
     * 记录一次装备槽位变更事件
     * 应在检测到头盔/胸甲/护腿/靴子槽位物品变化时调用
     *
     * @param playerName 玩家名称
     * @param playerUUID 玩家UUID
     * @param slot 变更的盔甲槽位类型
     * @param itemType 装备的物品类型名称
     * @param isInventoryOpen 此时背包是否打开
     * @param timestamp 时间戳
     * @return 检测结果
     */
    public AutoArmorCheckResult recordArmorChange(String playerName, String playerUUID,
                                                   ArmorSlot slot, String itemType,
                                                   boolean isInventoryOpen, Instant timestamp) {
        // 模块开关检查
        if (!config.getSecurity().getSuperEvolution().isAntiAutoArmor()) {
            return AutoArmorCheckResult.clean();
        }

        totalArmorEquips.incrementAndGet();
        List<String> reasons = new ArrayList<>();

        List<ArmorChangeEvent> changes = playerArmorChanges.computeIfAbsent(
                playerName, k -> new ArrayList<>());
        changes.add(new ArmorChangeEvent(slot, itemType, isInventoryOpen, timestamp));
        while (changes.size() > MAX_RECORDS) {
            changes.remove(0);
        }

        // 检测1：同一tick内多槽位装备
        long currentTick = timestamp.toEpochMilli() / 50; // Minecraft tick ≈ 50ms
        long tickSlotsEquipped = changes.stream()
                .filter(e -> Math.abs(e.timestamp.toEpochMilli() - timestamp.toEpochMilli()) < 50)
                .count();

        if (tickSlotsEquipped >= MAX_SLOTS_PER_TICK) {
            reasons.add("MULTI_SLOT_SAME_TICK: " + tickSlotsEquipped
                    + " armor slots changed in one tick (max human: 1-2)");
        }

        // 检测2：装备变更间隔分析
        if (changes.size() >= 2) {
            ArmorChangeEvent prev = changes.get(changes.size() - 2);
            long intervalMs = timestamp.toEpochMilli() - prev.timestamp.toEpochMilli();

            if (intervalMs >= 0 && intervalMs < MIN_HUMAN_ARMOR_INTERVAL_MS) {
                if (intervalMs < HACK_LEVEL_INTERVAL_MS) {
                    reasons.add("HACK_SPEED_ARMOR: " + intervalMs
                            + "ms armor swap (hack threshold: " + HACK_LEVEL_INTERVAL_MS + "ms)");
                } else {
                    reasons.add("SUBHUMAN_ARMOR_SWAP: " + intervalMs
                            + "ms armor swap interval (human minimum: " + MIN_HUMAN_ARMOR_INTERVAL_MS + "ms)");
                }
            }

            // 检测3：连续快速装备模式（机械化的均匀间隔）
            if (changes.size() >= MAX_CONSECUTIVE_FAST_EQUIPS + 2) {
                int recentCount = Math.min(changes.size(), MAX_CONSECUTIVE_FAST_EQUIPS + 2);
                double[] intervals = new double[recentCount - 1];
                int fastCount = 0;
                for (int i = changes.size() - recentCount + 1; i < changes.size(); i++) {
                    long interval = changes.get(i).timestamp.toEpochMilli()
                            - changes.get(i - 1).timestamp.toEpochMilli();
                    intervals[i - (changes.size() - recentCount + 1)] = interval;
                    if (interval < MIN_HUMAN_ARMOR_INTERVAL_MS) {
                        fastCount++;
                    }
                }

                if (fastCount >= MAX_CONSECUTIVE_FAST_EQUIPS) {
                    // 计算间隔标准差，机械化操作标准差极低
                    double mean = Arrays.stream(intervals).average().orElse(0);
                    double variance = Arrays.stream(intervals)
                            .map(d -> (d - mean) * (d - mean))
                            .average().orElse(0);
                    double stdev = Math.sqrt(variance);

                    reasons.add("CONSECUTIVE_FAST_ARMOR: " + fastCount
                            + " consecutive sub-" + MIN_HUMAN_ARMOR_INTERVAL_MS
                            + "ms armors (stdev=" + String.format("%.1f", stdev) + "ms)");

                    if (stdev < MECHANICAL_STDEV_THRESHOLD_MS && stdev > 0) {
                        reasons.add("MECHANICAL_RHYTHM: armor swap intervals stdev="
                                + String.format("%.1f", stdev) + "ms (mechanical pattern)");
                    }
                }
            }
        }

        // 检测4：背包操作与盔甲更换时序
        InventoryState invState = playerInventoryState.get(playerName);
        if (invState != null && invState.isOpen) {
            long inventoryOpenDuration = timestamp.toEpochMilli() - invState.openTime.toEpochMilli();

            if (inventoryOpenDuration < SUSPICIOUS_INVENTORY_DURATION_MS
                    && tickSlotsEquipped >= 2) {
                reasons.add("RAPID_INVENTORY_ARMOR: " + tickSlotsEquipped
                        + " slots swapped within " + inventoryOpenDuration
                        + "ms inventory session (suspicious speed)");
            }
        }

        // 检测5：登录即时装备
        Instant joinTime = playerJoinTime.get(playerName);
        if (joinTime != null) {
            long timeSinceJoin = timestamp.toEpochMilli() - joinTime.toEpochMilli();
            if (timeSinceJoin >= 0 && timeSinceJoin < JOIN_EQUIP_WINDOW_MS) {
                long equipsOnJoin = changes.stream()
                        .filter(e -> {
                            long t = e.timestamp.toEpochMilli() - joinTime.toEpochMilli();
                            return t >= 0 && t < JOIN_EQUIP_WINDOW_MS;
                        })
                        .count();

                if (equipsOnJoin >= MAX_EQUIPS_ON_JOIN) {
                    reasons.add("JOIN_INSTANT_EQUIP: " + equipsOnJoin
                            + " armor slots equipped within " + JOIN_EQUIP_WINDOW_MS
                            + "ms of joining (auto-equip on spawn)");
                }
            }
        }

        // 记录可疑事件
        if (!reasons.isEmpty()) {
            List<Map<String, Object>> events = autoArmorEvents.computeIfAbsent(
                    playerName, k -> new ArrayList<>());
            Map<String, Object> event = new LinkedHashMap<>();
            event.put("time", timestamp.toString());
            event.put("slot", slot.name());
            event.put("itemType", itemType);
            event.put("inventoryOpen", isInventoryOpen);
            event.put("tickSlotsEquipped", tickSlotsEquipped);
            event.put("reasons", reasons);
            events.add(event);
            while (events.size() > 20) {
                events.remove(0);
            }
        }

        // 汇总结果
        if (reasons.size() >= 2) {
            flaggedCount.incrementAndGet();
            return AutoArmorCheckResult.flagged(reasons);
        } else if (reasons.size() == 1) {
            return AutoArmorCheckResult.suspicious(reasons);
        }

        return AutoArmorCheckResult.clean();
    }

    /**
     * 记录背包打开事件
     * 应用于InventoryOpenEvent监听
     *
     * @param playerName 玩家名称
     * @param timestamp 打开时间戳
     */
    public void recordInventoryOpen(String playerName, Instant timestamp) {
        if (!config.getSecurity().getSuperEvolution().isAntiAutoArmor()) {
            return;
        }
        InventoryState state = playerInventoryState.computeIfAbsent(
                playerName, k -> new InventoryState());
        state.isOpen = true;
        state.openTime = timestamp;
        state.clickCount = 0;
    }

    /**
     * 记录背包点击事件
     * 应用于InventoryClickEvent监听
     *
     * @param playerName 玩家名称
     * @param timestamp 点击时间戳
     */
    public void recordInventoryClick(String playerName, Instant timestamp) {
        if (!config.getSecurity().getSuperEvolution().isAntiAutoArmor()) {
            return;
        }
        InventoryState state = playerInventoryState.get(playerName);
        if (state != null && state.isOpen) {
            state.clickCount++;
            state.lastClickTime = timestamp;
        }
    }

    /**
     * 记录背包关闭事件
     * 应用于InventoryCloseEvent监听
     * 关闭时进行背包会话完整性分析
     *
     * @param playerName 玩家名称
     * @param timestamp 关闭时间戳
     * @return 检测结果（基于整个背包会话的分析）
     */
    public AutoArmorCheckResult recordInventoryClose(String playerName, Instant timestamp) {
        if (!config.getSecurity().getSuperEvolution().isAntiAutoArmor()) {
            return AutoArmorCheckResult.clean();
        }

        InventoryState state = playerInventoryState.get(playerName);
        if (state == null || !state.isOpen) {
            return AutoArmorCheckResult.clean();
        }

        long sessionDuration = timestamp.toEpochMilli() - state.openTime.toEpochMilli();
        List<String> reasons = new ArrayList<>();

        // 检查在此背包会话期间发生的装备变更
        List<ArmorChangeEvent> changes = playerArmorChanges.get(playerName);
        if (changes != null && sessionDuration >= 0) {
            long armorChangesInSession = changes.stream()
                    .filter(e -> {
                        long t = e.timestamp.toEpochMilli() - state.openTime.toEpochMilli();
                        return t >= 0 && t < sessionDuration;
                    })
                    .count();

            // 背包持续时间极短但装备变更很多 → hack
            if (sessionDuration < SUSPICIOUS_INVENTORY_DURATION_MS
                    && armorChangesInSession >= 2) {
                reasons.add("TURBO_INVENTORY_SESSION: " + armorChangesInSession
                        + " armor changes in " + sessionDuration
                        + "ms inventory session");
            }

            // 背包持续时间很短，但装备了全套盔甲
            if (sessionDuration < MIN_HUMAN_ARMOR_INTERVAL_MS * 4
                    && armorChangesInSession >= 3) {
                reasons.add("FULL_SET_SPEED_EQUIP: " + armorChangesInSession
                        + " armor pieces swapped in " + sessionDuration
                        + "ms (full set re-equip detected)");
            }
        }

        // 清空背包状态
        state.isOpen = false;
        state.openTime = null;

        if (reasons.size() >= 2) {
            flaggedCount.incrementAndGet();
            return AutoArmorCheckResult.flagged(reasons);
        } else if (reasons.size() == 1) {
            return AutoArmorCheckResult.suspicious(reasons);
        }

        return AutoArmorCheckResult.clean();
    }

    /**
     * 玩家离线时清理追踪数据
     * @param playerName 离线玩家名称
     */
    public void clearPlayer(String playerName) {
        playerArmorChanges.remove(playerName);
        playerInventoryState.remove(playerName);
        playerJoinTime.remove(playerName);
        autoArmorEvents.remove(playerName);
    }

    /**
     * 获取模块运行状态
     * @return 包含计数器和活跃追踪玩家数的Map
     */
    public Map<String, Object> getStatus() {
        Map<String, Object> status = new LinkedHashMap<>();
        status.put("totalArmorEquips", totalArmorEquips.get());
        status.put("flaggedCount", flaggedCount.get());
        status.put("activeTrackedPlayers", playerArmorChanges.size());

        // 列出近期高频装备变更玩家
        List<Map<String, Object>> highActivityPlayers = new ArrayList<>();
        Instant now = Instant.now();
        Instant windowStart = now.minusMillis(10_000);

        for (Map.Entry<String, List<ArmorChangeEvent>> entry : playerArmorChanges.entrySet()) {
            long recentChanges = entry.getValue().stream()
                    .filter(e -> !e.timestamp.isBefore(windowStart))
                    .count();
            if (recentChanges >= 4) {
                Map<String, Object> info = new LinkedHashMap<>();
                info.put("player", entry.getKey());
                info.put("recentArmorChanges", recentChanges);
                highActivityPlayers.add(info);
            }
        }
        highActivityPlayers.sort((a, b) ->
                Long.compare((Long) b.get("recentArmorChanges"), (Long) a.get("recentArmorChanges")));
        status.put("highActivityPlayers", highActivityPlayers);

        return status;
    }

    /**
     * 内部装备变更事件记录 — 记录单个盔甲槽位的变更信息
     */
    private static class ArmorChangeEvent {
        final ArmorSlot slot;
        final String itemType;
        final boolean isInventoryOpen;
        final Instant timestamp;

        ArmorChangeEvent(ArmorSlot slot, String itemType, boolean isInventoryOpen, Instant timestamp) {
            this.slot = slot;
            this.itemType = itemType;
            this.isInventoryOpen = isInventoryOpen;
            this.timestamp = timestamp;
        }
    }

    /**
     * 内部背包状态追踪 — 记录玩家背包的开关状态和操作信息
     */
    private static class InventoryState {
        boolean isOpen = false;
        Instant openTime = null;
        int clickCount = 0;
        Instant lastClickTime = null;
    }

    /**
     * AutoArmor检测结果 — 不可变结果类
     */
    public static class AutoArmorCheckResult {
        private final boolean flagged;
        private final boolean suspicious;
        private final List<String> reasons;

        private AutoArmorCheckResult(boolean flagged, boolean suspicious, List<String> reasons) {
            this.flagged = flagged;
            this.suspicious = suspicious;
            this.reasons = reasons;
        }

        /** 无异常 — 合法的盔甲装备行为 */
        public static AutoArmorCheckResult clean() {
            return new AutoArmorCheckResult(false, false, List.of());
        }

        /** 可疑 — 单一快速装备事件 */
        public static AutoArmorCheckResult suspicious(List<String> reasons) {
            return new AutoArmorCheckResult(false, true, reasons);
        }

        /** 已标记 — 确定使用了AutoArmor hack */
        public static AutoArmorCheckResult flagged(List<String> reasons) {
            return new AutoArmorCheckResult(true, false, reasons);
        }

        public boolean isFlagged() { return flagged; }
        public boolean isSuspicious() { return suspicious; }
        public boolean isClean() { return !flagged && !suspicious; }
        public List<String> getReasons() { return reasons; }
    }
}
