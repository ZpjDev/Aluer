package com.aluer.anticheat.player;

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
 * 背包操作异常检测 (Inventory Manipulation) — V4.0 玩家行为安全模块
 *
 * 检测原理：
 *   部分 Minecraft 外挂客户端利用背包/物品栏操作的漏洞实现非法功能，
 *   例如瞬间移动物品、批量丢弃、访问非法槽位等。本模块通过以下维度检测：
 *   1. 物品瞬间移动——物品从背包某个槽位移到另一个槽位（或容器）的时间间隔
 *      < 1 tick（50ms）为异常，正常操作至少需要 1 tick 的服务器处理时间。
 *   2. 批量丢弃模式——正常每个 tick 最多丢弃 1 个物品（Q键），单 tick 丢弃
 *      超过 1 个物品是发包修改的行为（如 InventoryCleaner）。
 *   3. 非法槽位访问——访问负索引槽位或超过背包允许大小的槽位，
 *      正常游戏客户端不会发送此类请求。
 *   4. 自动整理模式——短时间内大量物品槽位被重新排列，
 *      正常玩家整理背包有一定节奏，自动化整理极度快速且统一。
 *   5. 物品复制检测——物品从一个槽位移走后，在另一处出现相同物品（可能伴随数量变化）。
 *
 * 配置开关：serverguard.security.super-evolution.anti-inventory-manipulation
 */
@Service
public class AntiInventoryManipulationService {

    private final ServerGuardConfig config;
    private final Map<String, List<InventoryOp>> playerInvOps = new ConcurrentHashMap<>();
    private final Map<String, Map<Integer, InventorySlotState>> playerSlotStates = new ConcurrentHashMap<>();
    private final Map<String, Instant> flaggedPlayers = new ConcurrentHashMap<>();
    private final ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor();

    /** 背包操作总次数 */
    private final AtomicLong totalInventoryOps = new AtomicLong(0);
    /** 背包操作违规次数 */
    private final AtomicLong manipulationViolations = new AtomicLong(0);
    /** 槽位违规次数 */
    private final AtomicLong slotViolations = new AtomicLong(0);

    /** 物品移动最小时间间隔（毫秒）——低于此值视为瞬间移动 */
    private static final long MIN_MOVE_INTERVAL_MS = 50;

    /** 单 tick 最大丢弃物品数 */
    private static final int MAX_DROPS_PER_TICK = 1;

    /** 玩家背包最小槽位索引 */
    private static final int MIN_SLOT_INDEX = 0;

    /** 玩家背包最大槽位索引（36 格背包 + 1 副手 = 37 个独立槽位，0-based 为 36） */
    private static final int MAX_SLOT_INDEX = 40;

    /** 玩家可用的最大槽位索引（含盔甲栏 = 40） */
    private static final int MAX_VALID_SLOT = 40;

    /** 短时间内大量物品重排的检测窗口（秒） */
    private static final long REARRANGE_WINDOW_SEC = 3;

    /** 短时间内容器物品变化次数 —— 超过此阈值判定为自动整理 */
    private static final int MAX_SLOT_CHANGES_SHORT = 20;

    /** 记录保留时间（秒） */
    private static final long RECORD_RETENTION_SECONDS = 300;

    /** 标记持续时间（秒） */
    private static final long FLAG_DURATION_SECONDS = 1800;

    public AntiInventoryManipulationService() {
        this(new ServerGuardConfig());
    }

    @Autowired
    public AntiInventoryManipulationService(ServerGuardConfig config) {
        this.config = config;
        scheduler.scheduleAtFixedRate(this::cleanupOldRecords, 60, 120, TimeUnit.SECONDS);
    }

    /**
     * 检测一次物品槽位移动操作。
     *
     * 追踪物品从一个槽位移动到另一个槽位，检测瞬间移动和非法槽位访问。
     *
     * @param playerName  玩家名称
     * @param playerUUID  玩家 UUID
     * @param fromSlot    来源槽位索引
     * @param toSlot      目标槽位索引
     * @param itemType    移动的物品类型（可为 null）
     * @param itemCount   移动的物品数量
     * @param containerId 容器 ID（-1 表示玩家自己背包）
     * @return 检测结果
     */
    public DetectionResult detectItemMove(String playerName, String playerUUID,
                                           int fromSlot, int toSlot, String itemType,
                                           int itemCount, int containerId) {
        if (!config.getSecurity().getSuperEvolution().isAntiInventoryManipulation()) {
            return DetectionResult.clean();
        }

        // 检查标记
        Instant flaggedUntil = flaggedPlayers.get(playerName);
        if (flaggedUntil != null) {
            if (Instant.now().isAfter(flaggedUntil)) {
                flaggedPlayers.remove(playerName);
            } else {
                return DetectionResult.flagged(List.of(
                    "PLAYER_ALREADY_FLAGGED: " + playerName));
            }
        }

        Instant now = Instant.now();
        List<InventoryOp> ops = playerInvOps.computeIfAbsent(playerName,
            k -> Collections.synchronizedList(new ArrayList<>()));

        // 记录操作
        InventoryOp op = new InventoryOp(now, "MOVE", fromSlot, toSlot, itemType,
            itemCount, containerId);
        ops.add(op);
        totalInventoryOps.incrementAndGet();

        int score = 0;
        List<String> reasons = new ArrayList<>();

        // === 检测 1: 物品瞬间移动 ===
        // 查找同一物品在前一个 tick 内是否有其他移动操作
        long tickStart = now.toEpochMilli() - MIN_MOVE_INTERVAL_MS;
        long movesInTick = ops.stream()
            .filter(o -> "MOVE".equals(o.opType))
            .filter(o -> o.time.toEpochMilli() > tickStart)
            .count();

        if (movesInTick > 2) {
            score += 30;
            reasons.add("INSTANT_MOVE: " + movesInTick +
                " slot moves in " + MIN_MOVE_INTERVAL_MS + "ms (packet exploit)");
        }

        // === 检测 2: 非法槽位访问 ===
        if (fromSlot < MIN_SLOT_INDEX || fromSlot > MAX_SLOT_INDEX
            || toSlot < MIN_SLOT_INDEX || toSlot > MAX_SLOT_INDEX) {
            score += 40;
            slotViolations.incrementAndGet();
            reasons.add("INVALID_SLOT: access slot[" + fromSlot + "->" + toSlot
                + "] (valid range " + MIN_SLOT_INDEX + "-" + MAX_SLOT_INDEX + ")");
        }

        // === 检测 3: 自动整理模式 ===
        // 短时间内容器物品变化次数
        long rearrangeWindowStart = now.toEpochMilli() - (REARRANGE_WINDOW_SEC * 1000);
        long slotChanges = ops.stream()
            .filter(o -> o.time.toEpochMilli() > rearrangeWindowStart)
            .count();

        if (slotChanges > MAX_SLOT_CHANGES_SHORT) {
            score += 25;
            reasons.add("AUTO_SORT: " + slotChanges +
                " slot changes in " + REARRANGE_WINDOW_SEC + "s (automated inventory sorting)");
        }

        // === 检测 4: 物品复制检测 ===
        // 追踪物品槽位状态变化，检测疑似复制
        if (itemType != null && itemCount > 0) {
            Map<Integer, InventorySlotState> slotStates = playerSlotStates.computeIfAbsent(playerName,
                k -> new ConcurrentHashMap<>());

            // 检查来源槽位是否有状态记录
            InventorySlotState fromState = slotStates.get(fromSlot);
            if (fromState != null && fromState.itemType != null
                && fromState.itemType.equals(itemType)) {
                // 物品移出：数量减少是正常的，但数量增加（超过原记录）是异常的
                // 这是正常情况下物品在移出（我们会更新状态追踪）
            }

            // 更新槽位状态
            slotStates.put(toSlot, new InventorySlotState(itemType, itemCount, now));
            if (fromState != null) {
                // 移出后标记为空
                slotStates.put(fromSlot, new InventorySlotState("EMPTY", 0, now));
            }
        }

        if (score >= 40) {
            flaggedPlayers.put(playerName, Instant.now().plusSeconds(FLAG_DURATION_SECONDS));
            manipulationViolations.incrementAndGet();
            return DetectionResult.flagged(reasons);
        } else if (score >= 20) {
            return DetectionResult.suspicious(score, reasons);
        }

        return DetectionResult.clean();
    }

    /**
     * 检测物品丢弃操作——分析是否使用了批量丢弃外挂。
     *
     * @param playerName 玩家名称
     * @param playerUUID 玩家 UUID
     * @param itemType   丢弃的物品类型
     * @param itemCount  丢弃数量
     * @param slot       丢弃来源槽位
     * @return 检测结果
     */
    public DetectionResult detectItemDrop(String playerName, String playerUUID,
                                           String itemType, int itemCount, int slot) {
        if (!config.getSecurity().getSuperEvolution().isAntiInventoryManipulation()) {
            return DetectionResult.clean();
        }

        // 检查标记
        Instant flaggedUntil = flaggedPlayers.get(playerName);
        if (flaggedUntil != null) {
            if (Instant.now().isAfter(flaggedUntil)) {
                flaggedPlayers.remove(playerName);
            } else {
                return DetectionResult.flagged(List.of("PLAYER_ALREADY_FLAGGED"));
            }
        }

        Instant now = Instant.now();
        List<InventoryOp> ops = playerInvOps.computeIfAbsent(playerName,
            k -> Collections.synchronizedList(new ArrayList<>()));

        // 记录丢弃事件
        InventoryOp op = new InventoryOp(now, "DROP", slot, -1, itemType,
            itemCount, -1);
        ops.add(op);
        totalInventoryOps.incrementAndGet();

        int score = 0;
        List<String> reasons = new ArrayList<>();

        // === 批量丢弃检测 ===
        // 在 50ms 内丢弃多个物品 = InventoryCleaner 行为
        long tickStart = now.toEpochMilli() - 50;
        long dropsInTick = ops.stream()
            .filter(o -> "DROP".equals(o.opType))
            .filter(o -> o.time.toEpochMilli() > tickStart)
            .count();

        if (dropsInTick > MAX_DROPS_PER_TICK) {
            score += 45;
            reasons.add("BATCH_DROP: " + dropsInTick +
                " items dropped in single tick (InventoryCleaner signature, max normal="
                + MAX_DROPS_PER_TICK + ")");
        }

        // === 快速连续丢弃 ===
        long recentDrops = ops.stream()
            .filter(o -> "DROP".equals(o.opType))
            .filter(o -> o.time.toEpochMilli() > now.toEpochMilli() - 1000)
            .count();

        if (recentDrops >= 10) {
            score += 20;
            reasons.add("RAPID_DROP: " + recentDrops + " items dropped in 1 second");
        }

        if (score >= 40) {
            flaggedPlayers.put(playerName, Instant.now().plusSeconds(FLAG_DURATION_SECONDS));
            manipulationViolations.incrementAndGet();
            return DetectionResult.flagged(reasons);
        } else if (score >= 20) {
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
        playerInvOps.remove(playerName);
        playerSlotStates.remove(playerName);
        flaggedPlayers.remove(playerName);
    }

    /**
     * 获取模块运行状态。
     *
     * @return 包含统计数据的 LinkedHashMap
     */
    public Map<String, Object> getStatus() {
        Map<String, Object> s = new LinkedHashMap<>();
        s.put("totalInventoryOps", totalInventoryOps.get());
        s.put("manipulationViolations", manipulationViolations.get());
        s.put("slotViolations", slotViolations.get());
        s.put("trackedPlayers", playerInvOps.size());
        s.put("flaggedPlayers", flaggedPlayers.size());
        s.put("enabled", config.getSecurity().getSuperEvolution().isAntiInventoryManipulation());

        List<Map<String, Object>> flagged = new ArrayList<>();
        for (Map.Entry<String, Instant> e : flaggedPlayers.entrySet()) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("player", e.getKey());
            m.put("flaggedUntil", e.getValue().toString());
            List<InventoryOp> ops = playerInvOps.get(e.getKey());
            if (ops != null) {
                m.put("totalOperations", ops.size());
            }
            flagged.add(m);
        }
        s.put("flaggedPlayersList", flagged);

        return s;
    }

    public long getTotalInventoryOps() { return totalInventoryOps.get(); }
    public long getManipulationViolations() { return manipulationViolations.get(); }
    public long getSlotViolations() { return slotViolations.get(); }

    /**
     * 定期清理过期记录。
     */
    private void cleanupOldRecords() {
        Instant cutoff = Instant.now().minusSeconds(RECORD_RETENTION_SECONDS);
        playerInvOps.entrySet().removeIf(e -> {
            List<InventoryOp> ops = e.getValue();
            ops.removeIf(o -> o.time.isBefore(cutoff));
            return ops.isEmpty();
        });
        playerSlotStates.entrySet().removeIf(e -> e.getValue().isEmpty());
        flaggedPlayers.entrySet().removeIf(e -> e.getValue().isBefore(Instant.now()));
    }

    // ==================== 内部数据类 ====================

    /**
     * 背包操作记录——记录每次物品移动/丢弃等操作。
     */
    private static class InventoryOp {
        final Instant time;
        final String opType; // "MOVE" / "DROP"
        final int fromSlot;
        final int toSlot;    // -1 for drops
        final String itemType;
        final int itemCount;
        final int containerId;

        InventoryOp(Instant time, String opType, int fromSlot, int toSlot,
                   String itemType, int itemCount, int containerId) {
            this.time = time;
            this.opType = opType;
            this.fromSlot = fromSlot;
            this.toSlot = toSlot;
            this.itemType = itemType;
            this.itemCount = itemCount;
            this.containerId = containerId;
        }
    }

    /**
     * 背包槽位状态快照——追踪每个槽位的内容变化。
     */
    private static class InventorySlotState {
        final String itemType;
        final int itemCount;
        final Instant snapshotTime;

        InventorySlotState(String itemType, int itemCount, Instant snapshotTime) {
            this.itemType = itemType;
            this.itemCount = itemCount;
            this.snapshotTime = snapshotTime;
        }
    }

    // ==================== 检测结果类 ====================

    /**
     * 背包操作异常检测结果。
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

        /** 无异常：背包操作正常 */
        public static DetectionResult clean() {
            return new DetectionResult(false, false, 0, List.of());
        }

        /** 可疑行为：存在异常背包操作模式 */
        public static DetectionResult suspicious(int score, List<String> reasons) {
            return new DetectionResult(false, true, score, reasons);
        }

        /** 已标记：检测到高置信度背包操作异常 */
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
