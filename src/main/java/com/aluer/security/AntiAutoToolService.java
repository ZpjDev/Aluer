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
 * 自动工具切换检测 (AutoTool) — V5.3 世界/玩家/杂物安全模块
 *
 * 检测原理：
 *   Meteor Client 的 AutoTool 模块在被破坏方块发生变化时，在同一 tick 内自动将手持物品
 *   切换为对该方块类型最优的工具。正常玩家切换工具后会有 200-500ms 的反应间隔才开始挖掘，
 *   而 AutoTool 切换工具和开始挖掘发生在同一 tick（0ms 间隔）。本模块通过以下维度检测：
 *   1. 零间隔检测——记录手持物品变更时间与方块开始破坏时间，如果间隙在 1 tick 内
 *      （≤ 50ms），则高度可疑。正常玩家的最小间隔约为 150-200ms。
 *   2. 完美工具率——统计玩家挖掘各种方块时使用最优工具的命中率。
 *      正常玩家会偶尔用错工具（如用镐挖木头），AutoTool 则 100% 总是最优工具。
 *   3. 切换频率异常——在密集挖矿过程中，正常玩家不会频繁切换工具类型，
 *      AutoTool 在遇到不同方块时每次都会切换。
 *   4. 工具与方块类型对应关系验证：
 *      - 镐：石头、矿石类 → 最优
 *      - 斧：原木、木板类 → 最优
 *      - 铲：泥土、沙子、沙砾 → 最优
 *      - 锄：树叶、干草块、菌光体 → 最优
 *
 * 配置开关：serverguard.security.super-evolution.anti-auto-tool
 */
@Service
public class AntiAutoToolService {

    private final ServerGuardConfig config;
    /** 每个玩家的工具切换记录：playerName -> 切换事件列表 */
    private final Map<String, List<ToolSwitchEvent>> playerToolSwitches = new ConcurrentHashMap<>();
    /** 每个玩家的方块破坏记录：playerName -> 破坏事件列表 */
    private final Map<String, List<BlockBreakRecord>> playerBreakRecords = new ConcurrentHashMap<>();
    /** 每个玩家的最优工具命中计数 */
    private final Map<String, AtomicLong> playerPerfectToolCount = new ConcurrentHashMap<>();
    /** 每个玩家的总挖掘次数 */
    private final Map<String, AtomicLong> playerTotalBreaks = new ConcurrentHashMap<>();
    /** 已标记的玩家 */
    private final Map<String, Instant> flaggedPlayers = new ConcurrentHashMap<>();
    private final ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor();

    private final AtomicLong totalSwitchEvents = new AtomicLong(0);
    private final AtomicLong autoToolViolations = new AtomicLong(0);

    /** 工具切换与挖掘开始的最短间隔阈值（毫秒）——低于此值判定为同 tick 切换 */
    private static final long ZERO_INTERVAL_THRESHOLD_MS = 50;
    /** 正常切换最小间隔（毫秒）——用于对比判断 */
    private static final long NORMAL_SWITCH_MIN_MS = 150;
    /** 完美工具率阈值——超过此比例即怀疑自动化 */
    private static final double PERFECT_TOOL_RATIO_THRESHOLD = 0.92;
    /** 最少挖掘次数用于计算完美工具率 */
    private static final int MIN_BREAKS_FOR_RATIO = 15;
    /** 一分钟内工具切换次数阈值——超过即异常频繁 */
    private static final int MAX_SWITCHES_PER_MINUTE = 30;

    /** 记录保留时间（秒） */
    private static final long RECORD_RETENTION_SECONDS = 600;
    /** 标记持续时间（秒） */
    private static final long FLAG_DURATION_SECONDS = 1800;

    // === 工具类型枚举（基于 Minecraft 物品 ID 约定） ===

    /** 镐类工具——用于石头、矿石 */
    private static final Set<String> PICKAXE_TOOLS = Set.of(
        "WOODEN_PICKAXE", "STONE_PICKAXE", "IRON_PICKAXE", "GOLDEN_PICKAXE",
        "DIAMOND_PICKAXE", "NETHERITE_PICKAXE"
    );
    /** 斧类工具——用于原木、木板 */
    private static final Set<String> AXE_TOOLS = Set.of(
        "WOODEN_AXE", "STONE_AXE", "IRON_AXE", "GOLDEN_AXE",
        "DIAMOND_AXE", "NETHERITE_AXE"
    );
    /** 铲类工具——用于泥土、沙子、沙砾 */
    private static final Set<String> SHOVEL_TOOLS = Set.of(
        "WOODEN_SHOVEL", "STONE_SHOVEL", "IRON_SHOVEL", "GOLDEN_SHOVEL",
        "DIAMOND_SHOVEL", "NETHERITE_SHOVEL"
    );
    /** 锄类工具——用于树叶、干草块 */
    private static final Set<String> HOE_TOOLS = Set.of(
        "WOODEN_HOE", "STONE_HOE", "IRON_HOE", "GOLDEN_HOE",
        "DIAMOND_HOE", "NETHERITE_HOE"
    );

    /** 需要镐的方块类型关键词 */
    private static final Set<String> PICKAXE_BLOCKS = Set.of(
        "STONE", "COBBLESTONE", "DEEPSLATE", "GRANITE", "DIORITE", "ANDESITE",
        "ORE", "OBSIDIAN", "NETHERRACK", "END_STONE", "IRON", "GOLD",
        "DIAMOND", "EMERALD", "REDSTONE", "LAPIS", "COPPER", "COAL",
        "QUARTZ", "BLACKSTONE", "BASALT", "ICE", "PACKED_ICE", "BLUE_ICE",
        "CONCRETE", "TERRACOTTA", "SANDSTONE", "PRISMARINE", "PURPUR",
        "NETHER_BRICKS", "ANCIENT_DEBRIS", "GILDED_BLACKSTONE",
        "FURNACE", "DISPENSER", "DROPPER", "HOPPER", "OBSERVER",
        "PISTON", "STICKY_PISTON", "BREWING_STAND", "CAULDRON",
        "ANVIL", "ENCHANTING_TABLE", "ENDER_CHEST", "SPAWNER",
        "BELL", "GRINDSTONE", "SMITHING_TABLE", "STONECUTTER",
        "LODESTONE", "RESPAWN_ANCHOR", "CONDUIT", "LECTERN",
        "LIGHTNING_ROD", "POINTED_DRIPSTONE", "DRIPSTONE_BLOCK",
        "AMETHYST", "BUDDING_AMETHYST", "CALCITE", "TUFF"
    );
    /** 需要斧的方块类型关键词 */
    private static final Set<String> AXE_BLOCKS = Set.of(
        "LOG", "WOOD", "PLANKS", "BAMBOO", "FENCE", "GATE",
        "DOOR", "TRAPDOOR", "CHEST", "BARREL", "CRAFTING_TABLE",
        "BOOKSHELF", "LADDER", "SIGN", "LOOM", "COMPOSTER",
        "CARTOGRAPHY_TABLE", "FLETCHING_TABLE", "SMITHING",
        "BEEHIVE", "BEE_NEST", "CAMPFIRE", "NOTE_BLOCK",
        "JUKEBOX", "DAYLIGHT_DETECTOR", "MANGROVE_ROOTS",
        "MUDDY_MANGROVE_ROOTS", "CHISELED_BOOKSHELF",
        "HANGING_SIGN", "BAMBOO_MOSAIC", "BAMBOO_PLANKS"
    );
    /** 需要铲的方块类型关键词 */
    private static final Set<String> SHOVEL_BLOCKS = Set.of(
        "DIRT", "GRASS_BLOCK", "MYCELIUM", "PODZOL", "COARSE_DIRT",
        "ROOTED_DIRT", "SAND", "RED_SAND", "GRAVEL", "SOUL_SAND",
        "SOUL_SOIL", "CLAY", "SNOW", "SNOW_BLOCK", "MUD",
        "PACKED_MUD", "FARMLAND", "DIRT_PATH"
    );
    /** 需要锄的方块类型关键词 */
    private static final Set<String> HOE_BLOCKS = Set.of(
        "LEAVES", "HAY_BLOCK", "TARGET", "SHROOMLIGHT",
        "NETHER_WART_BLOCK", "WARPED_WART_BLOCK", "SCULK",
        "SCULK_CATALYST", "SCULK_SHRIEKER", "SCULK_SENSOR",
        "MOSS_BLOCK", "SPONGE", "WET_SPONGE"
    );

    public AntiAutoToolService() {
        this(new ServerGuardConfig());
    }

    @Autowired
    public AntiAutoToolService(ServerGuardConfig config) {
        this.config = config;
        scheduler.scheduleAtFixedRate(this::cleanupOldRecords, 120, 300, TimeUnit.SECONDS);
    }

    /**
     * 记录一次手持物品变更事件——当玩家切换快捷栏或手持物品时调用。
     *
     * @param playerName 玩家名称
     * @param playerUUID 玩家 UUID
     * @param fromItem   切换前的物品类型（可为空字符串表示空手）
     * @param toItem     切换后的物品类型
     */
    public void recordToolSwitch(String playerName, String playerUUID,
                                 String fromItem, String toItem) {
        if (!config.getSecurity().getSuperEvolution().isAntiAutoTool()) {
            return;
        }

        Instant now = Instant.now();
        List<ToolSwitchEvent> switches = playerToolSwitches.computeIfAbsent(playerName,
            k -> Collections.synchronizedList(new ArrayList<>()));
        switches.add(new ToolSwitchEvent(now, fromItem, toItem));
        totalSwitchEvents.incrementAndGet();
    }

    /**
     * 记录一次方块开始破坏事件——在玩家开始挖掘某个方块时调用。
     * 此方法与最近一次工具切换时间进行对比，检测零间隔自动切换。
     *
     * @param playerName 玩家名称
     * @param playerUUID 玩家 UUID
     * @param blockType  被挖掘的方块类型
     * @param heldItem   当前手持物品类型
     * @param x          方块 X 坐标
     * @param y          方块 Y 坐标
     * @param z          方块 Z 坐标
     */
    public void recordStartBreak(String playerName, String playerUUID,
                                  String blockType, String heldItem,
                                  int x, int y, int z) {
        if (!config.getSecurity().getSuperEvolution().isAntiAutoTool()) {
            return;
        }

        Instant now = Instant.now();
        List<BlockBreakRecord> breaks = playerBreakRecords.computeIfAbsent(playerName,
            k -> Collections.synchronizedList(new ArrayList<>()));
        breaks.add(new BlockBreakRecord(now, blockType, heldItem, x, y, z));

        // 检查最近一次工具切换是否与本次挖掘开始间隔极短
        List<ToolSwitchEvent> switches = playerToolSwitches.get(playerName);
        if (switches != null && !switches.isEmpty()) {
            ToolSwitchEvent lastSwitch = switches.get(switches.size() - 1);
            long gapMs = now.toEpochMilli() - lastSwitch.time.toEpochMilli();
            if (gapMs >= 0 && gapMs <= ZERO_INTERVAL_THRESHOLD_MS) {
                // 切换与破坏开始发生在同一 tick 内——AutoTool 的显著特征
                lastSwitch.instantBreakStart = true;
            }
        }

        playerTotalBreaks.computeIfAbsent(playerName, k -> new AtomicLong(0)).incrementAndGet();

        // 检查当前手持工具是否对该方块是最优工具
        if (heldItem != null && !heldItem.isEmpty() && blockType != null) {
            if (isOptimalTool(heldItem, blockType)) {
                playerPerfectToolCount.computeIfAbsent(playerName, k -> new AtomicLong(0))
                    .incrementAndGet();
            }
        }
    }

    /**
     * 对玩家的工具切换行为进行全面检测——综合分析零间隔切换、完美工具率、
     * 切换频率等指标。
     *
     * @param playerName 玩家名称
     * @param playerUUID 玩家 UUID
     * @return 检测结果
     */
    public DetectionResult detectAutoTool(String playerName, String playerUUID) {
        if (!config.getSecurity().getSuperEvolution().isAntiAutoTool()) {
            return DetectionResult.clean();
        }

        Instant flaggedUntil = flaggedPlayers.get(playerName);
        if (flaggedUntil != null) {
            if (Instant.now().isAfter(flaggedUntil)) {
                flaggedPlayers.remove(playerName);
            } else {
                return DetectionResult.flagged(List.of(
                    "PLAYER_ALREADY_FLAGGED: " + playerName + " under auto-tool investigation"));
            }
        }

        Instant now = Instant.now();
        List<ToolSwitchEvent> switches = playerToolSwitches.get(playerName);
        List<BlockBreakRecord> breaks = playerBreakRecords.get(playerName);

        int score = 0;
        List<String> reasons = new ArrayList<>();

        // === 检测 1: 零间隔工具切换（同一 tick 内切换并开始挖掘） ===
        if (switches != null && !switches.isEmpty()) {
            long zeroIntervalCount = switches.stream()
                .filter(s -> s.instantBreakStart)
                .count();
            long recentSwitches = switches.stream()
                .filter(s -> s.time.isAfter(now.minusSeconds(60)))
                .count();

            if (zeroIntervalCount >= 3) {
                score += 35;
                reasons.add("ZERO_INTERVAL_SWITCH: " + zeroIntervalCount +
                    " tool switches followed by block break within " +
                    ZERO_INTERVAL_THRESHOLD_MS + "ms (same-tick auto-switch)");
            }

            // 分析最近一分钟内的切换-挖掘间隔分布
            if (breaks != null && breaks.size() >= 5) {
                long recentInstantSwitches = countRecentInstantSwitches(switches, breaks, now);
                if (recentInstantSwitches >= 5) {
                    score += 25;
                    reasons.add("INSTANT_SWITCH_PATTERN: " + recentInstantSwitches +
                        " recent tool switches with zero gap before mining");
                }
            }

            // === 检测 3: 切换频率异常 ===
            if (recentSwitches > MAX_SWITCHES_PER_MINUTE) {
                score += 20;
                reasons.add("EXCESSIVE_SWITCHING: " + recentSwitches +
                    " tool switches in last 60s (threshold=" + MAX_SWITCHES_PER_MINUTE + ")");
            }
        }

        // === 检测 2: 完美工具率 ===
        long totalBreaks = playerTotalBreaks.getOrDefault(playerName, new AtomicLong(0)).get();
        long perfectTools = playerPerfectToolCount.getOrDefault(playerName, new AtomicLong(0)).get();
        if (totalBreaks >= MIN_BREAKS_FOR_RATIO) {
            double ratio = (double) perfectTools / totalBreaks;
            if (ratio > PERFECT_TOOL_RATIO_THRESHOLD) {
                score += 30;
                reasons.add("PERFECT_TOOL_RATIO: " + String.format("%.1f%%", ratio * 100) +
                    " of " + totalBreaks + " blocks mined with optimal tool" +
                    " (threshold " + String.format("%.1f%%", PERFECT_TOOL_RATIO_THRESHOLD * 100) +
                    ", indicative of auto-tool selection)");
            }
        }

        // === 检测 4: 方块类型变化时的工具匹配分析 ===
        if (breaks != null && breaks.size() >= 5) {
            long autoToolScore = analyzeToolBlockMatching(breaks);
            if (autoToolScore >= 5) {
                score += 20;
                reasons.add("TOOL_BLOCK_MATCH: " + autoToolScore +
                    " rapid block-type changes with perfect tool adaptation (auto-tool signature)");
            }
        }

        if (score >= 50) {
            flaggedPlayers.put(playerName, Instant.now().plusSeconds(FLAG_DURATION_SECONDS));
            autoToolViolations.incrementAndGet();
            return DetectionResult.flagged(reasons);
        } else if (score >= 30) {
            return DetectionResult.suspicious(score, reasons);
        }

        return DetectionResult.clean();
    }

    /**
     * 统计最近一段时间内，工具切换后立即开始挖掘的次数（同 tick）。
     */
    private long countRecentInstantSwitches(List<ToolSwitchEvent> switches,
                                             List<BlockBreakRecord> breaks,
                                             Instant now) {
        long count = 0;
        long windowStart = now.toEpochMilli() - 60000; // 最近 60 秒
        for (ToolSwitchEvent s : switches) {
            if (s.instantBreakStart && s.time.toEpochMilli() > windowStart) {
                count++;
            }
        }
        return count;
    }

    /**
     * 分析方块破坏记录中工具与方块的匹配模式。
     * 如果在不同方块类型之间切换时始终保持完美工具匹配，即为自动化特征。
     */
    private long analyzeToolBlockMatching(List<BlockBreakRecord> breaks) {
        int autoMatches = 0;
        int start = Math.max(0, breaks.size() - 15);
        String lastBlockCategory = null;
        for (int i = start; i < breaks.size(); i++) {
            BlockBreakRecord r = breaks.get(i);
            if (r.heldItem == null || r.heldItem.isEmpty()) continue;
            String currentCategory = getBlockCategory(r.blockType);
            // 如果方块类型类别发生了变化，检查工具是否随之正确切换
            if (lastBlockCategory != null && !lastBlockCategory.equals(currentCategory)) {
                if (isOptimalToolForCategory(r.heldItem, currentCategory)) {
                    autoMatches++;
                }
            }
            lastBlockCategory = currentCategory;
        }
        return autoMatches;
    }

    /**
     * 判断指定工具对指定方块是否是该方块类别的最优工具。
     */
    private boolean isOptimalTool(String heldItem, String blockType) {
        if (heldItem == null || blockType == null) return false;
        String upperItem = heldItem.toUpperCase();
        String upperBlock = blockType.toUpperCase();

        if (matchesKeyword(upperBlock, PICKAXE_BLOCKS) && PICKAXE_TOOLS.contains(upperItem))
            return true;
        if (matchesKeyword(upperBlock, AXE_BLOCKS) && AXE_TOOLS.contains(upperItem))
            return true;
        if (matchesKeyword(upperBlock, SHOVEL_BLOCKS) && SHOVEL_TOOLS.contains(upperItem))
            return true;
        if (matchesKeyword(upperBlock, HOE_BLOCKS) && HOE_TOOLS.contains(upperItem))
            return true;

        return false;
    }

    /**
     * 判断工具是否属于指定方块类别的最优工具类型。
     */
    private boolean isOptimalToolForCategory(String heldItem, String blockCategory) {
        if (heldItem == null || blockCategory == null) return false;
        String upperItem = heldItem.toUpperCase();
        return switch (blockCategory) {
            case "PICKAXE" -> PICKAXE_TOOLS.contains(upperItem);
            case "AXE" -> AXE_TOOLS.contains(upperItem);
            case "SHOVEL" -> SHOVEL_TOOLS.contains(upperItem);
            case "HOE" -> HOE_TOOLS.contains(upperItem);
            default -> false;
        };
    }

    /**
     * 获取方块所属的工具类别。
     */
    private String getBlockCategory(String blockType) {
        if (blockType == null) return null;
        String upper = blockType.toUpperCase();
        if (matchesKeyword(upper, PICKAXE_BLOCKS)) return "PICKAXE";
        if (matchesKeyword(upper, AXE_BLOCKS)) return "AXE";
        if (matchesKeyword(upper, SHOVEL_BLOCKS)) return "SHOVEL";
        if (matchesKeyword(upper, HOE_BLOCKS)) return "HOE";
        return null;
    }

    /**
     * 检查方块类型名称是否匹配关键词集合中的任意一项（子串匹配）。
     * 例如 "OAK_LOG" 匹配关键词 "LOG"。
     */
    private boolean matchesKeyword(String blockType, Set<String> keywords) {
        for (String kw : keywords) {
            if (blockType.contains(kw)) return true;
        }
        return false;
    }

    public void clearPlayer(String playerName) {
        playerToolSwitches.remove(playerName);
        playerBreakRecords.remove(playerName);
        playerPerfectToolCount.remove(playerName);
        playerTotalBreaks.remove(playerName);
        flaggedPlayers.remove(playerName);
    }

    public Map<String, Object> getStatus() {
        Map<String, Object> s = new LinkedHashMap<>();
        s.put("totalSwitchEvents", totalSwitchEvents.get());
        s.put("autoToolViolations", autoToolViolations.get());
        s.put("trackedPlayers", playerToolSwitches.size());
        s.put("flaggedPlayers", flaggedPlayers.size());
        s.put("enabled", config.getSecurity().getSuperEvolution().isAntiAutoTool());
        return s;
    }

    public long getTotalSwitchEvents() { return totalSwitchEvents.get(); }
    public long getAutoToolViolations() { return autoToolViolations.get(); }

    private void cleanupOldRecords() {
        Instant cutoff = Instant.now().minusSeconds(RECORD_RETENTION_SECONDS);
        playerToolSwitches.entrySet().removeIf(e -> {
            List<ToolSwitchEvent> list = e.getValue();
            list.removeIf(s -> s.time.isBefore(cutoff));
            return list.isEmpty();
        });
        playerBreakRecords.entrySet().removeIf(e -> {
            List<BlockBreakRecord> list = e.getValue();
            list.removeIf(r -> r.time.isBefore(cutoff));
            return list.isEmpty();
        });
        playerPerfectToolCount.entrySet().removeIf(e ->
            !playerBreakRecords.containsKey(e.getKey()));
        playerTotalBreaks.entrySet().removeIf(e ->
            !playerBreakRecords.containsKey(e.getKey()));
        flaggedPlayers.entrySet().removeIf(e -> e.getValue().isBefore(Instant.now()));
    }

    // ==================== 内部数据类 ====================

    /**
     * 工具切换事件——记录玩家手持物品变更的时间及前后物品信息。
     */
    private static class ToolSwitchEvent {
        final Instant time;
        final String fromItem;     // 切换前持有的物品
        final String toItem;       // 切换后持有的物品
        boolean instantBreakStart; // 切换后同一 tick 内是否开始挖掘

        ToolSwitchEvent(Instant time, String fromItem, String toItem) {
            this.time = time;
            this.fromItem = fromItem;
            this.toItem = toItem;
            this.instantBreakStart = false;
        }
    }

    /**
     * 方块破坏记录——追踪每次开始挖掘时的方块和手持工具信息。
     */
    private static class BlockBreakRecord {
        final Instant time;
        final String blockType;
        final String heldItem; // 开始破坏时手持的物品
        final int x, y, z;

        BlockBreakRecord(Instant time, String blockType, String heldItem,
                        int x, int y, int z) {
            this.time = time;
            this.blockType = blockType;
            this.heldItem = heldItem;
            this.x = x;
            this.y = y;
            this.z = z;
        }
    }

    // ==================== 检测结果类 ====================

    /**
     * 自动工具切换检测结果。
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

        /** 无异常：工具切换行为正常 */
        public static DetectionResult clean() {
            return new DetectionResult(false, false, 0, List.of());
        }

        /** 可疑行为：存在 AutoTool 特征但置信度不足 */
        public static DetectionResult suspicious(int score, List<String> reasons) {
            return new DetectionResult(false, true, score, reasons);
        }

        /** 已标记：检测到高置信度 AutoTool 行为 */
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
