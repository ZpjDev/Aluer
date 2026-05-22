package com.aluer.anticheat.combat;

import com.aluer.config.ServerGuardConfig;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * 快速胸甲切换（ChestSwap）检测服务 — V5.1 反作弊战斗模块
 *
 * 检测原理：
 * 1. 胸甲槽位变化速度检测 — Meteor Client的ChestSwap模块允许玩家一键将胸甲
 *    与快捷栏/背包中的另一个胸甲或鞘翅互换。合法玩家执行此操作需要：
 *    打开背包 → 定位物品 → Shift点击或拖拽 → 关闭背包，耗时500-1500ms。
 *    Hack在同一tick（0-50ms）内完成交换。如果胸甲槽位物品在1 tick内
 *    变为另一个物品且背包未打开，则是自动化交换。
 * 2. 鞘翅-胸甲互换检测 — 战斗中常见的作弊模式：玩家穿戴胸甲、受伤后立即
 *    切换为鞘翅逃跑、摆脱伤害后再切换回胸甲。正常玩家此过程需要1-3秒。
 *    ChestSwap用户可以50ms内完成交换。追踪胸甲槽位在"CHESTPLATE"与"ELYTRA"
 *    之间的快速循环切换。
 * 3. 战斗中的连续胸甲交换 — 追踪玩家在受到攻击后立即切换胸甲的模式。
 *    如果玩家在受伤后200ms内改变了胸甲槽位，然后1秒内又切换回来，
 *    且重复此模式多次，则是自动化战斗装备管理。
 * 4. 热键栏直接交换检测 — 正常玩家通过热键栏（1-9键）与胸甲槽位交换物品
 *    仍需要可检测的响应时间（至少100ms+）。ChestSwap通过shift+点击从热键栏
 *    立即替换，中间没有玩家可见的延迟。如果热键栏物品出现在胸甲槽位，
 *    且两个变化之间没有背包交互记录，标记。
 *
 * 配置开关：serverguard.security.super-evolution.anti-chest-swap
 */
@Service
public class AntiChestSwapService {

    private final ServerGuardConfig config;

    /**
     * 追踪每个玩家的胸甲槽位变更记录（playerName -> 变更事件列表）
     */
    private final Map<String, List<ChestplateChange>> playerChestChanges = new ConcurrentHashMap<>();

    /**
     * 追踪每个玩家最近一次受伤事件（playerName -> 受伤时间戳和伤害量）
     */
    private final Map<String, DamageEvent> playerLastDamage = new ConcurrentHashMap<>();

    /**
     * 追踪每个玩家的背包打开状态
     */
    private final Map<String, Boolean> playerInventoryOpen = new ConcurrentHashMap<>();

    /**
     * 追踪疑似ChestSwap的事件（playerName -> 可疑事件列表）
     */
    private final Map<String, List<Map<String, Object>>> chestSwapEvents = new ConcurrentHashMap<>();

    private final AtomicLong totalChestSwaps = new AtomicLong(0);
    private final AtomicLong flaggedCount = new AtomicLong(0);

    /**
     * 胸甲槽位单次交换的Hack级别时间阈值（毫秒）
     * 50ms = 在同1tick内完成交换，完全无法由人类操作
     */
    private static final long HACK_SWAP_TIME_MS = 50;

    /**
     * 胸甲交换的最小人类间隔（毫秒）
     * 正常玩家需要打开背包、定位物品、拖拽/点击，至少300ms
     */
    private static final long MIN_HUMAN_CHEST_SWAP_MS = 300;

    /**
     * 战斗胸甲交换检测窗口（毫秒）
     * 受伤后在此时间窗口内切换胸甲视为战斗逃避交换
     */
    private static final long COMBAT_SWAP_WINDOW_MS = 200;

    /**
     * 鞘翅-胸甲循环交换的最小间隔（毫秒）
     * 连续在胸甲和鞘翅之间切换，间隔低于此值即标记
     */
    private static final long ELYTRA_CYCLE_THRESHOLD_MS = 1000;

    /**
     * 连续快速交换次数阈值 — 连续N次低于最小人类间隔则标记
     */
    private static final int MAX_CONSECUTIVE_FAST_SWAPS = 2;

    /**
     * 短时间内连续交换次数阈值 — 在战斗窗口内连续交换超过此次数即标记
     */
    private static final int MAX_COMBAT_SWAPS_IN_WINDOW = 3;

    /**
     * 战斗中连续交换时间窗口（毫秒）
     */
    private static final long COMBAT_SWAP_CHAIN_WINDOW_MS = 5_000;

    /**
     * 每个玩家保留的最大记录数
     */
    private static final int MAX_RECORDS = 40;

    /**
     * 无参构造函数 — 测试/默认配置使用
     */
    public AntiChestSwapService() {
        this(new ServerGuardConfig());
    }

    /**
     * Spring 注入构造函数
     * @param config 全局配置，提供模块开关控制
     */
    public AntiChestSwapService(ServerGuardConfig config) {
        this.config = config;
    }

    /**
     * 记录一次胸甲槽位物品变更事件
     * 应在检测到玩家胸甲槽位（chestplate slot）物品类型发生变化时调用
     *
     * @param playerName 玩家名称
     * @param playerUUID 玩家UUID
     * @param oldItemType 变更前的物品类型（"CHESTPLATE"/"ELYTRA"或其他）
     * @param newItemType 变更后的物品类型
     * @param isInventoryOpen 此时背包是否打开
     * @param isHotbarSwap 是否来自热键栏直接交换
     * @param timestamp 时间戳
     * @return 检测结果
     */
    public ChestSwapCheckResult detect(String playerName, String playerUUID,
                                        String oldItemType, String newItemType,
                                        boolean isInventoryOpen, boolean isHotbarSwap,
                                        Instant timestamp) {
        // 模块开关检查
        if (!config.getSecurity().getSuperEvolution().isAntiChestSwap()) {
            return ChestSwapCheckResult.clean();
        }

        totalChestSwaps.incrementAndGet();
        List<String> reasons = new ArrayList<>();

        List<ChestplateChange> changes = playerChestChanges.computeIfAbsent(
                playerName, k -> new ArrayList<>());
        ChestplateChange change = new ChestplateChange(oldItemType, newItemType,
                isInventoryOpen, isHotbarSwap, timestamp);
        changes.add(change);
        while (changes.size() > MAX_RECORDS) {
            changes.remove(0);
        }

        // 检测1：交换速度 — 与上次胸甲槽位变化的时间间隔
        if (changes.size() >= 2) {
            ChestplateChange prev = changes.get(changes.size() - 2);
            long swapInterval = timestamp.toEpochMilli() - prev.timestamp.toEpochMilli();

            if (swapInterval >= 0 && swapInterval < MIN_HUMAN_CHEST_SWAP_MS) {
                if (swapInterval < HACK_SWAP_TIME_MS) {
                    reasons.add("HACK_SPEED_CHESTSWAP: " + swapInterval
                            + "ms chestplate swap (hack threshold: " + HACK_SWAP_TIME_MS + "ms)");
                } else {
                    reasons.add("SUBHUMAN_CHESTSWAP: " + swapInterval
                            + "ms chestplate swap interval (human minimum: " + MIN_HUMAN_CHEST_SWAP_MS + "ms)");
                }
            }

            // 检测2：无背包交互的快速交换 — 没有打开背包但胸甲变了
            if (swapInterval < HACK_SWAP_TIME_MS && !isInventoryOpen && !isHotbarSwap) {
                reasons.add("NO_INTERFACE_CHESTSWAP: chestplate changed without inventory or hotbar interaction");
            }

            // 检测3：热键栏直接交换 — 热键栏交换需要人类按键间隔
            if (swapInterval < HACK_SWAP_TIME_MS && isHotbarSwap && !isInventoryOpen) {
                reasons.add("HOTBAR_TELEPORT: hotbar-to-chest swap in " + swapInterval
                        + "ms without inventory (no human keypress delay)");
            }
        }

        // 检测4：鞘翅-胸甲循环交换（Elytra ↔ Chestplate ping-pong）
        if (isElytraChestplateCycle(oldItemType, newItemType) && changes.size() >= 4) {
            int recentCount = Math.min(changes.size(), 8);
            int cycleCount = 0;
            for (int i = changes.size() - recentCount + 1; i < changes.size(); i++) {
                ChestplateChange curr = changes.get(i);
                ChestplateChange prev = changes.get(i - 1);
                if (isElytraChestplateCycle(prev.newItemType, curr.newItemType)) {
                    long interval = curr.timestamp.toEpochMilli() - prev.timestamp.toEpochMilli();
                    if (interval < ELYTRA_CYCLE_THRESHOLD_MS) {
                        cycleCount++;
                    }
                }
            }

            if (cycleCount >= 3) {
                reasons.add("ELYTRA_CHESTPLATE_CYCLE: " + cycleCount
                        + " rapid elytra/chestplate swaps in "
                        + (recentCount * ELYTRA_CYCLE_THRESHOLD_MS / 1000) + "s cycle window");
            }
        }

        // 检测5：战斗中的即时胸甲交换 — 受伤后立即交换
        DamageEvent lastDamage = playerLastDamage.get(playerName);
        if (lastDamage != null) {
            long timeSinceDamage = timestamp.toEpochMilli() - lastDamage.timestamp.toEpochMilli();

            if (timeSinceDamage >= 0 && timeSinceDamage < COMBAT_SWAP_WINDOW_MS) {
                reasons.add("COMBAT_INSTANT_SWAP: chestplate swap " + timeSinceDamage
                        + "ms after taking " + String.format("%.1f", lastDamage.damage)
                        + " damage (swap to avoid damage)");
            }

            // 检测战斗中短时间内多次胸甲交换
            if (timeSinceDamage >= 0 && timeSinceDamage < COMBAT_SWAP_CHAIN_WINDOW_MS) {
                long swapsInCombat = changes.stream()
                        .filter(e -> {
                            long t = e.timestamp.toEpochMilli() - lastDamage.timestamp.toEpochMilli();
                            return t >= 0 && t < COMBAT_SWAP_CHAIN_WINDOW_MS;
                        })
                        .count();

                if (swapsInCombat >= MAX_COMBAT_SWAPS_IN_WINDOW) {
                    reasons.add("COMBAT_MULTI_SWAP: " + swapsInCombat
                            + " chestplate swaps in " + (COMBAT_SWAP_CHAIN_WINDOW_MS / 1000)
                            + "s after taking damage");
                }
            }
        }

        // 检测6：连续快速交换模式 — 模式化重复行为
        if (changes.size() >= MAX_CONSECUTIVE_FAST_SWAPS + 1) {
            int fastCount = 0;
            for (int i = changes.size() - 1;
                 i >= Math.max(0, changes.size() - MAX_CONSECUTIVE_FAST_SWAPS - 1) && i > 0;
                 i--) {
                long interval = changes.get(i).timestamp.toEpochMilli()
                        - changes.get(i - 1).timestamp.toEpochMilli();
                if (interval < MIN_HUMAN_CHEST_SWAP_MS) {
                    fastCount++;
                }
            }
            if (fastCount >= MAX_CONSECUTIVE_FAST_SWAPS) {
                reasons.add("CONSECUTIVE_FAST_SWAPS: " + fastCount
                        + " consecutive sub-" + MIN_HUMAN_CHEST_SWAP_MS
                        + "ms chestplate swaps");
            }
        }

        // 记录可疑事件
        if (!reasons.isEmpty()) {
            List<Map<String, Object>> events = chestSwapEvents.computeIfAbsent(
                    playerName, k -> new ArrayList<>());
            Map<String, Object> event = new LinkedHashMap<>();
            event.put("time", timestamp.toString());
            event.put("oldItem", oldItemType);
            event.put("newItem", newItemType);
            event.put("inventoryOpen", isInventoryOpen);
            event.put("hotbarSwap", isHotbarSwap);
            event.put("reasons", reasons);
            events.add(event);
            while (events.size() > 20) {
                events.remove(0);
            }
        }

        // 汇总结果
        if (reasons.size() >= 2) {
            flaggedCount.incrementAndGet();
            return ChestSwapCheckResult.flagged(reasons);
        } else if (reasons.size() == 1) {
            return ChestSwapCheckResult.suspicious(reasons);
        }

        return ChestSwapCheckResult.clean();
    }

    /**
     * 记录玩家受伤事件
     * 应用于EntityDamageEvent监听
     *
     * @param playerName 玩家名称
     * @param damage 伤害量（半心为单位，1.0 = 半心）
     * @param timestamp 时间戳
     */
    public void recordDamage(String playerName, double damage, Instant timestamp) {
        if (!config.getSecurity().getSuperEvolution().isAntiChestSwap()) {
            return;
        }
        playerLastDamage.put(playerName, new DamageEvent(damage, timestamp));
    }

    /**
     * 更新玩家背包打开状态
     *
     * @param playerName 玩家名称
     * @param isOpen 背包是否打开
     */
    public void setInventoryOpen(String playerName, boolean isOpen) {
        if (!config.getSecurity().getSuperEvolution().isAntiChestSwap()) {
            return;
        }
        playerInventoryOpen.put(playerName, isOpen);
    }

    /**
     * 玩家离线时清理追踪数据
     * @param playerName 离线玩家名称
     */
    public void clearPlayer(String playerName) {
        playerChestChanges.remove(playerName);
        playerLastDamage.remove(playerName);
        playerInventoryOpen.remove(playerName);
        chestSwapEvents.remove(playerName);
    }

    /**
     * 获取模块运行状态
     * @return 包含计数器和活跃追踪玩家数的Map
     */
    public Map<String, Object> getStatus() {
        Map<String, Object> status = new LinkedHashMap<>();
        status.put("totalChestSwaps", totalChestSwaps.get());
        status.put("flaggedCount", flaggedCount.get());
        status.put("activeTrackedPlayers", playerChestChanges.size());

        // 列出近期高频胸甲交换玩家
        List<Map<String, Object>> highActivityPlayers = new ArrayList<>();
        Instant now = Instant.now();
        Instant windowStart = now.minusMillis(10_000);

        for (Map.Entry<String, List<ChestplateChange>> entry : playerChestChanges.entrySet()) {
            long recentSwaps = entry.getValue().stream()
                    .filter(e -> !e.timestamp.isBefore(windowStart))
                    .count();
            if (recentSwaps >= 3) {
                Map<String, Object> info = new LinkedHashMap<>();
                info.put("player", entry.getKey());
                info.put("recentSwaps", recentSwaps);
                highActivityPlayers.add(info);
            }
        }
        highActivityPlayers.sort((a, b) ->
                Long.compare((Long) b.get("recentSwaps"), (Long) a.get("recentSwaps")));
        status.put("highActivityPlayers", highActivityPlayers);

        return status;
    }

    /**
     * 判断是否为鞘翅-胸甲循环交换模式
     * 即一个变更是 胸甲→鞘翅，另一个变更是 鞘翅→胸甲
     */
    private boolean isElytraChestplateCycle(String oldType, String newType) {
        if (oldType == null || newType == null) return false;
        return (oldType.toUpperCase().contains("CHEST") && newType.toUpperCase().contains("ELYTRA"))
                || (oldType.toUpperCase().contains("ELYTRA") && newType.toUpperCase().contains("CHEST"));
    }

    /**
     * 内部胸甲变更事件记录
     */
    private static class ChestplateChange {
        final String oldItemType;
        final String newItemType;
        final boolean isInventoryOpen;
        final boolean isHotbarSwap;
        final Instant timestamp;

        ChestplateChange(String oldItemType, String newItemType,
                         boolean isInventoryOpen, boolean isHotbarSwap, Instant timestamp) {
            this.oldItemType = oldItemType;
            this.newItemType = newItemType;
            this.isInventoryOpen = isInventoryOpen;
            this.isHotbarSwap = isHotbarSwap;
            this.timestamp = timestamp;
        }
    }

    /**
     * 内部受伤事件记录
     */
    private static class DamageEvent {
        final double damage;
        final Instant timestamp;

        DamageEvent(double damage, Instant timestamp) {
            this.damage = damage;
            this.timestamp = timestamp;
        }
    }

    /**
     * ChestSwap检测结果 — 不可变结果类
     */
    public static class ChestSwapCheckResult {
        private final boolean flagged;
        private final boolean suspicious;
        private final List<String> reasons;

        private ChestSwapCheckResult(boolean flagged, boolean suspicious, List<String> reasons) {
            this.flagged = flagged;
            this.suspicious = suspicious;
            this.reasons = reasons;
        }

        /** 无异常 — 合法的胸甲交换行为 */
        public static ChestSwapCheckResult clean() {
            return new ChestSwapCheckResult(false, false, List.of());
        }

        /** 可疑 — 单次快速交换 */
        public static ChestSwapCheckResult suspicious(List<String> reasons) {
            return new ChestSwapCheckResult(false, true, reasons);
        }

        /** 已标记 — 确定使用了ChestSwap hack */
        public static ChestSwapCheckResult flagged(List<String> reasons) {
            return new ChestSwapCheckResult(true, false, reasons);
        }

        public boolean isFlagged() { return flagged; }
        public boolean isSuspicious() { return suspicious; }
        public boolean isClean() { return !flagged && !suspicious; }
        public List<String> getReasons() { return reasons; }
    }
}
