package com.aluer.security;

import com.aluer.config.ServerGuardConfig;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * 自动不死图腾（AutoTotem）检测服务 — V5.1 反作弊战斗模块
 *
 * 检测原理：
 * 1. 图腾重新装备速度检测 — Meteor Client的AutoTotem模块在玩家不死图腾被消耗（"pop"）
 *    后自动将背包中新的不死图腾移动到副手。合法玩家操作速度下限约200ms（按键响应+
 *    鼠标移动+点击），而hack可以在0-20ms内完成（通常在同一tick内）。
 *    追踪图腾消耗时间点到副手出现新图腾的时间间隔。
 * 2. 连续图腾使用检测 — 正常玩家在PvP中可能使用1-2个不死图腾，间隔数秒。
 *    AutoTotem用户可以在极短时间内连续消耗5+个图腾，每个都以非人类速度重新装备。
 *    如果玩家的图腾消耗频率极高且每次都配合亚100ms的重新装备时间，则标记。
 * 3. 副手槽位变化模式追踪 — 监控副手槽位的物品变化序列。
 *    正常玩家：偶尔切换副手物品，有明确的停顿间隔。
 *    AutoTotem：图腾被消耗后立即出现新图腾，然后在同一tick被消耗再出现新图腾，
 *    形成高频的"消失-出现-消失-出现"模式。
 * 4. 背包操作与副手变化的关联 — 如果副手出现新图腾的同时没有检测到背包打开事件，
 *    说明物品转移没有经过正常的UI交互，高度可能是hack直接操作槽位。
 *
 * 配置开关：serverguard.security.super-evolution.anti-auto-totem
 */
@Service
public class AntiAutoTotemService {

    private final ServerGuardConfig config;

    /**
     * 追踪每个玩家不死图腾消耗的时间点（playerName -> 图腾消耗时间戳列表）
     * 每次图腾被消耗触发时记录
     */
    private final Map<String, List<Instant>> playerTotemPopTimes = new ConcurrentHashMap<>();

    /**
     * 追踪每个玩家副手槽位变化的记录（playerName -> 槽位变化记录列表）
     */
    private final Map<String, List<OffhandChange>> playerOffhandHistory = new ConcurrentHashMap<>();

    /**
     * 追踪每个玩家最近一次图腾消耗的确切时间（用于与新图腾出现的间隔计算）
     */
    private final Map<String, Instant> playerLastTotemPop = new ConcurrentHashMap<>();

    /**
     * 追踪疑似AutoTotem的事件（playerName -> 可疑事件列表）
     */
    private final Map<String, List<Map<String, Object>>> autoTotemEvents = new ConcurrentHashMap<>();

    private final AtomicLong totalTotemPops = new AtomicLong(0);
    private final AtomicLong flaggedCount = new AtomicLong(0);

    /**
     * 图腾重新装备的人类最小反应时间（毫秒）
     * 200ms = 人类最快视觉反应（~150ms）+ 点击操作延迟（~50ms）
     * 任何低于此值的重新装备时间都是非人类速度
     */
    private static final long MIN_HUMAN_REEQUIP_MS = 200;

    /**
     * Hack级别的重新装备时间阈值（毫秒）
     * 50ms以下几乎确定是作弊（在同一tick内完成）
     */
    private static final long HACK_LEVEL_REQUIP_MS = 50;

    /**
     * 短时间内连续图腾使用阈值 — 在时间窗口内消耗N个图腾即标记
     */
    private static final long RAPID_TOTEM_WINDOW_MS = 10_000;

    /**
     * 窗口内最大允许的图腾使用次数（正常PvP水平）
     */
    private static final int MAX_TOTEMS_IN_WINDOW = 4;

    /**
     * 连续快速装备次数阈值 — 连续N次都小于100ms即标记
     */
    private static final int MAX_CONSECUTIVE_FAST_EQUIPS = 3;

    /**
     * 每个玩家保留的最大记录数
     */
    private static final int MAX_RECORDS = 50;

    /**
     * 无参构造函数 — 测试/默认配置使用
     */
    public AntiAutoTotemService() {
        this(new ServerGuardConfig());
    }

    /**
     * Spring 注入构造函数
     * @param config 全局配置，提供模块开关控制
     */
    public AntiAutoTotemService(ServerGuardConfig config) {
        this.config = config;
    }

    /**
     * 记录一次不死图腾被消耗（"pop"）事件
     * 此方法应在检测到图腾从副手被移除/消耗时调用
     *
     * @param playerName 玩家名称
     * @param playerUUID 玩家UUID
     * @param timestamp 图腾消耗的时间戳
     */
    public void recordTotemPop(String playerName, String playerUUID, Instant timestamp) {
        if (!config.getSecurity().getSuperEvolution().isAntiAutoTotem()) {
            return;
        }

        totalTotemPops.incrementAndGet();
        playerLastTotemPop.put(playerName, timestamp);

        List<Instant> popTimes = playerTotemPopTimes.computeIfAbsent(
                playerName, k -> new ArrayList<>());
        popTimes.add(timestamp);
        while (popTimes.size() > MAX_RECORDS) {
            popTimes.remove(0);
        }
    }

    /**
     * 检测玩家副手图腾重新装备事件
     * 此方法应在检测到副手槽位出现新的不死图腾时调用
     *
     * @param playerName 玩家名称
     * @param playerUUID 玩家UUID
     * @param newItemType 副手新物品类型（"TOTEM_OF_UNDYING"或其他）
     * @param isInventoryOpen 此时背包是否打开（打开说明有正常UI交互）
     * @param timestamp 时间戳
     * @return 检测结果
     */
    public AutoTotemCheckResult detect(String playerName, String playerUUID,
                                        String newItemType, boolean isInventoryOpen,
                                        Instant timestamp) {
        // 模块开关检查
        if (!config.getSecurity().getSuperEvolution().isAntiAutoTotem()) {
            return AutoTotemCheckResult.clean();
        }

        List<String> reasons = new ArrayList<>();

        // 仅检测图腾物品
        if (!"TOTEM_OF_UNDYING".equalsIgnoreCase(newItemType)) {
            return AutoTotemCheckResult.clean();
        }

        Instant lastPop = playerLastTotemPop.get(playerName);
        List<OffhandChange> history = playerOffhandHistory.computeIfAbsent(
                playerName, k -> new ArrayList<>());

        long reequipTimeMs = 0;
        if (lastPop != null) {
            reequipTimeMs = timestamp.toEpochMilli() - lastPop.toEpochMilli();

            // 忽略超过合理时间的重新装备（可能是玩家手动操作）
            // 但记录所有副手变化以进行模式分析
            OffhandChange change = new OffhandChange(timestamp, "TOTEM_OF_UNDYING",
                    reequipTimeMs, isInventoryOpen);
            history.add(change);
            while (history.size() > MAX_RECORDS) {
                history.remove(0);
            }

            // 检测：图腾重新装备时间低于人类极限
            if (reequipTimeMs >= 0 && reequipTimeMs < MIN_HUMAN_REEQUIP_MS) {
                if (reequipTimeMs < HACK_LEVEL_REQUIP_MS) {
                    // 50ms内重新装备 — 几乎确定是AutoTotem hack
                    reasons.add("HACK_SPEED_REQUIP: " + reequipTimeMs
                            + "ms totem re-equip (hack threshold: " + HACK_LEVEL_REQUIP_MS + "ms)");
                } else {
                    reasons.add("SUBHUMAN_REQUIP: " + reequipTimeMs
                            + "ms totem re-equip (human minimum: " + MIN_HUMAN_REEQUIP_MS + "ms)");
                }
            }

            // 检测：没有打开背包的情况下图腾出现了
            // 正常玩家需要打开背包或使用热键栏来交换副手物品
            if (reequipTimeMs >= 0 && reequipTimeMs < MIN_HUMAN_REEQUIP_MS && !isInventoryOpen) {
                reasons.add("NO_INVENTORY_REQUIP: totem appeared in offhand without inventory interaction");
            }
        }

        // 检测：时间窗口内的高频图腾使用
        List<Instant> popTimes = playerTotemPopTimes.get(playerName);
        if (popTimes != null && popTimes.size() >= 2) {
            Instant windowStart = timestamp.minusMillis(RAPID_TOTEM_WINDOW_MS);
            long recentPops = popTimes.stream()
                    .filter(t -> !t.isBefore(windowStart))
                    .count();

            if (recentPops >= MAX_TOTEMS_IN_WINDOW) {
                reasons.add("RAPID_TOTEM_CHAIN: " + recentPops + " totems popped in "
                        + (RAPID_TOTEM_WINDOW_MS / 1000) + "s");
            }
        }

        // 检测：连续快速装备模式
        if (history.size() >= MAX_CONSECUTIVE_FAST_EQUIPS) {
            int fastCount = 0;
            for (int i = history.size() - 1; i >= Math.max(0, history.size() - MAX_CONSECUTIVE_FAST_EQUIPS); i--) {
                if (history.get(i).reequipTimeMs >= 0 && history.get(i).reequipTimeMs < 100) {
                    fastCount++;
                }
            }
            if (fastCount >= MAX_CONSECUTIVE_FAST_EQUIPS) {
                reasons.add("CONSECUTIVE_FAST_REQUIP: " + fastCount
                        + " consecutive sub-100ms totem equips");
            }
        }

        // 记录可疑事件
        if (!reasons.isEmpty()) {
            List<Map<String, Object>> events = autoTotemEvents.computeIfAbsent(
                    playerName, k -> new ArrayList<>());
            Map<String, Object> event = new LinkedHashMap<>();
            event.put("time", timestamp.toString());
            event.put("reequipTimeMs", reequipTimeMs);
            event.put("isInventoryOpen", isInventoryOpen);
            event.put("reasons", reasons);
            events.add(event);
            while (events.size() > 20) {
                events.remove(0);
            }
        }

        if (reasons.size() >= 2) {
            flaggedCount.incrementAndGet();
            return AutoTotemCheckResult.flagged(reasons);
        } else if (reasons.size() == 1) {
            return AutoTotemCheckResult.suspicious(reasons);
        }

        return AutoTotemCheckResult.clean();
    }

    /**
     * 玩家离线时清理追踪数据
     * @param playerName 离线玩家名称
     */
    public void clearPlayer(String playerName) {
        playerTotemPopTimes.remove(playerName);
        playerOffhandHistory.remove(playerName);
        playerLastTotemPop.remove(playerName);
        autoTotemEvents.remove(playerName);
    }

    /**
     * 获取模块运行状态
     * @return 包含计数器和活跃追踪玩家数的Map
     */
    public Map<String, Object> getStatus() {
        Map<String, Object> status = new LinkedHashMap<>();
        status.put("totalTotemPops", totalTotemPops.get());
        status.put("flaggedCount", flaggedCount.get());
        status.put("activeTrackedPlayers", playerOffhandHistory.size());

        // 列出近期高频图腾使用玩家
        List<Map<String, Object>> highFrequencyPlayers = new ArrayList<>();
        Instant now = Instant.now();
        Instant windowStart = now.minusMillis(RAPID_TOTEM_WINDOW_MS);

        for (Map.Entry<String, List<Instant>> entry : playerTotemPopTimes.entrySet()) {
            long recentPops = entry.getValue().stream()
                    .filter(t -> !t.isBefore(windowStart))
                    .count();
            if (recentPops >= MAX_TOTEMS_IN_WINDOW / 2) {
                Map<String, Object> info = new LinkedHashMap<>();
                info.put("player", entry.getKey());
                info.put("recentPops", recentPops);
                highFrequencyPlayers.add(info);
            }
        }
        highFrequencyPlayers.sort((a, b) ->
                Long.compare((Long) b.get("recentPops"), (Long) a.get("recentPops")));
        status.put("highFrequencyPlayers", highFrequencyPlayers);

        return status;
    }

    /**
     * 内部副手变化记录 — 记录副手槽位物品变化的时间和来源信息
     */
    private static class OffhandChange {
        final Instant timestamp;
        final String itemType;
        final long reequipTimeMs;      // 与上次图腾消耗的时间间隔，-1表示无法计算
        final boolean isInventoryOpen; // 背包是否打开（正常UI交互标志）

        OffhandChange(Instant timestamp, String itemType, long reequipTimeMs, boolean isInventoryOpen) {
            this.timestamp = timestamp;
            this.itemType = itemType;
            this.reequipTimeMs = reequipTimeMs;
            this.isInventoryOpen = isInventoryOpen;
        }
    }

    /**
     * AutoTotem检测结果 — 不可变结果类
     */
    public static class AutoTotemCheckResult {
        private final boolean flagged;
        private final boolean suspicious;
        private final List<String> reasons;

        private AutoTotemCheckResult(boolean flagged, boolean suspicious, List<String> reasons) {
            this.flagged = flagged;
            this.suspicious = suspicious;
            this.reasons = reasons;
        }

        /** 无异常 — 正常的图腾重新装备行为 */
        public static AutoTotemCheckResult clean() {
            return new AutoTotemCheckResult(false, false, List.of());
        }

        /** 可疑 — 单次快速装备可能是巧合 */
        public static AutoTotemCheckResult suspicious(List<String> reasons) {
            return new AutoTotemCheckResult(false, true, reasons);
        }

        /** 已标记 — 确定使用了AutoTotem hack */
        public static AutoTotemCheckResult flagged(List<String> reasons) {
            return new AutoTotemCheckResult(true, false, reasons);
        }

        public boolean isFlagged() { return flagged; }
        public boolean isSuspicious() { return suspicious; }
        public boolean isClean() { return !flagged && !suspicious; }
        public List<String> getReasons() { return reasons; }
    }
}
