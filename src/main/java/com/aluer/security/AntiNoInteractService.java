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
 * 交互绕过检测 (NoInteract) — V5.3 世界/玩家/杂物安全模块
 *
 * 检测原理：
 *   Meteor Client 的 NoInteract 模块允许玩家在手持方块类物品时仍然打开容器/使用功能方块。
 *   正常的 Minecraft 机制中，手持剑、弓、食物等物品时无法与容器或功能方块交互——
 *   只有空手、方块类物品，或潜行状态下才能与容器交互。
 *   NoInteract 就是绕过了这个检查。本模块通过以下维度检测：
 *   1. 手持物品类型检查——记录玩家打开容器/使用功能方块时手中持有什么物品。
 *      如果手持着应该阻止交互的物品（如剑、弓、食物），却成功交互了，即为作弊。
 *   2. 潜行状态验证——正常玩家可以通过潜行 + 手持物品来实现交互，但 NoInteract 不需要潜行。
 *      如果玩家没有潜行且手持非方块物品却能开容器，就是明确的作弊信号。
 *   3. 连续交互模式——单次可疑交互可能是插件冲突，但连续多次即为确认作弊。
 *
 * 阻止交互的物品类型：
 *   剑（SWORD）、弓（BOW）、弩（CROSSBOW）、三叉戟（TRIDENT）、
 *   食物（FOOD）、药水（POTION）、盾牌（SHIELD）、钓鱼竿（FISHING_ROD）、
 *   锄头（HOE）、打火石（FLINT_AND_STEEL）、烟花火箭（FIREWORK_ROCKET）等。
 *
 * 配置开关：serverguard.security.super-evolution.anti-no-interact
 */
@Service
public class AntiNoInteractService {

    private final ServerGuardConfig config;
    /** 每个玩家的交互事件记录 */
    private final Map<String, List<InteractEvent>> playerInteractHistory = new ConcurrentHashMap<>();
    /** 已标记的玩家 */
    private final Map<String, Instant> flaggedPlayers = new ConcurrentHashMap<>();
    private final ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor();

    private final AtomicLong totalInteractEvents = new AtomicLong(0);
    private final AtomicLong noInteractViolations = new AtomicLong(0);

    /** 连续可疑交互阈值 */
    private static final int CONSECUTIVE_SUSPICIOUS_THRESHOLD = 3;
    /** 记录保留时间（秒） */
    private static final long RECORD_RETENTION_SECONDS = 600;
    /** 标记持续时间（秒） */
    private static final long FLAG_DURATION_SECONDS = 1800;

    /** 应该阻止与容器/功能方块交互的物品类型集合 */
    private static final Set<String> BLOCKING_ITEMS = Set.of(
        "SWORD", "WOODEN_SWORD", "STONE_SWORD", "IRON_SWORD", "GOLDEN_SWORD",
        "DIAMOND_SWORD", "NETHERITE_SWORD",
        "BOW", "CROSSBOW", "TRIDENT",
        "POTION", "SPLASH_POTION", "LINGERING_POTION",
        "SHIELD", "FISHING_ROD",
        "WATER_BUCKET", "LAVA_BUCKET", "BUCKET", "POWDER_SNOW_BUCKET",
        "FLINT_AND_STEEL", "FIRE_CHARGE",
        "WOODEN_HOE", "STONE_HOE", "IRON_HOE", "GOLDEN_HOE", "DIAMOND_HOE", "NETHERITE_HOE",
        "FIREWORK_ROCKET",
        "EGG", "SNOWBALL", "ENDER_PEARL", "ENDER_EYE",
        "EXPERIENCE_BOTTLE", "BONE_MEAL"
    );

    /**
     * 可交互的功能方块类型（容器、工作台、功能性方块）
     */
    private static final Set<String> INTERACTABLE_BLOCKS = Set.of(
        "CHEST", "TRAPPED_CHEST", "ENDER_CHEST", "BARREL", "SHULKER_BOX",
        "CRAFTING_TABLE", "FURNACE", "BLAST_FURNACE", "SMOKER",
        "ENCHANTING_TABLE", "ANVIL", "CHIPPED_ANVIL", "DAMAGED_ANVIL",
        "BREWING_STAND", "BEACON", "SMITHING_TABLE", "GRINDSTONE",
        "CARTOGRAPHY_TABLE", "LOOM", "STONECUTTER",
        "HOPPER", "DISPENSER", "DROPPER",
        "JUKEBOX", "NOTE_BLOCK", "BELL", "LECTERN", "FLETCHING_TABLE",
        "OAK_DOOR", "IRON_DOOR", "SPRUCE_DOOR", "BIRCH_DOOR", "JUNGLE_DOOR",
        "ACACIA_DOOR", "DARK_OAK_DOOR", "CRIMSON_DOOR", "WARPED_DOOR",
        "OAK_TRAPDOOR", "IRON_TRAPDOOR",
        "OAK_FENCE_GATE", "SPRUCE_FENCE_GATE", "BIRCH_FENCE_GATE",
        "JUNGLE_FENCE_GATE", "ACACIA_FENCE_GATE", "DARK_OAK_FENCE_GATE",
        "CRIMSON_FENCE_GATE", "WARPED_FENCE_GATE",
        "LEVER", "BUTTON", "OAK_BUTTON", "STONE_BUTTON",
        "REPEATER", "COMPARATOR", "DAYLIGHT_DETECTOR",
        "CAKE", "SWEET_BERRY_BUSH", "FLOWER_POT", "ITEM_FRAME", "GLOW_ITEM_FRAME",
        "ARMOR_STAND"
    );

    public AntiNoInteractService() {
        this(new ServerGuardConfig());
    }

    @Autowired
    public AntiNoInteractService(ServerGuardConfig config) {
        this.config = config;
        scheduler.scheduleAtFixedRate(this::cleanupOldRecords, 120, 300, TimeUnit.SECONDS);
    }

    /**
     * 检测容器/功能方块交互事件——判断玩家是否绕过了交互限制。
     *
     * @param playerName   玩家名称
     * @param playerUUID   玩家 UUID
     * @param heldItemType 玩家手中持有的物品类型
     * @param blockType    被交互的方块类型
     * @param isSneaking   玩家是否处于潜行状态
     * @param isContainer  是否打开了容器类方块（有物品栏的）
     * @return 检测结果
     */
    public DetectionResult detectInteract(String playerName, String playerUUID,
                                           String heldItemType, String blockType,
                                           boolean isSneaking, boolean isContainer) {
        if (!config.getSecurity().getSuperEvolution().isAntiNoInteract()) {
            return DetectionResult.clean();
        }

        Instant flaggedUntil = flaggedPlayers.get(playerName);
        if (flaggedUntil != null) {
            if (Instant.now().isAfter(flaggedUntil)) {
                flaggedPlayers.remove(playerName);
            } else {
                return DetectionResult.flagged(List.of(
                    "PLAYER_ALREADY_FLAGGED: " + playerName + " under no-interact investigation"));
            }
        }

        Instant now = Instant.now();
        // 仅记录对功能方块/容器的交互
        if (blockType == null || !isInteractableBlock(blockType)) {
            return DetectionResult.clean();
        }

        // 仅检查手持阻止交互物品的情况
        if (!isBlockingItem(heldItemType)) {
            return DetectionResult.clean();
        }

        int score = 0;
        List<String> reasons = new ArrayList<>();

        // === 检测 1: 手持阻止交互物品 + 未潜行 → 明确作弊 ===
        if (!isSneaking) {
            score += 40;
            reasons.add("NO_INTERACT_BYPASS: opened " + blockType +
                " while holding " + heldItemType + " without sneaking");
        } else {
            // 潜行状态下允许交互是正常机制，不扣分
            // 但记录用于后续模式分析
        }

        // 记录交互事件
        List<InteractEvent> history = playerInteractHistory.computeIfAbsent(playerName,
            k -> Collections.synchronizedList(new ArrayList<>()));
        history.add(new InteractEvent(now, heldItemType, blockType, isSneaking, isContainer,
            !isSneaking)); // notSneakingWithBlocking = suspicious
        totalInteractEvents.incrementAndGet();

        // === 检测 2: 连续可疑交互检测 ===
        if (!isSneaking) {
            long consecutiveSuspicious = countConsecutiveSuspicious(history);
            if (consecutiveSuspicious >= CONSECUTIVE_SUSPICIOUS_THRESHOLD) {
                score += 35;
                reasons.add("CONSECUTIVE_NO_INTERACT: " + consecutiveSuspicious +
                    " consecutive container interactions while holding blocking items without sneaking");
            }
        }

        // === 检测 3: 容器类交互（有物品栏的）比功能方块交互更严重 ===
        if (isContainer && !isSneaking) {
            score += 10;
            reasons.add("CONTAINER_ACCESS: accessed container " + blockType +
                " (has inventory) while holding " + heldItemType);
        }

        if (score >= 50) {
            flaggedPlayers.put(playerName, Instant.now().plusSeconds(FLAG_DURATION_SECONDS));
            noInteractViolations.incrementAndGet();
            return DetectionResult.flagged(reasons);
        } else if (score >= 35) {
            return DetectionResult.suspicious(score, reasons);
        }

        return score > 0 ? DetectionResult.suspicious(score, reasons) : DetectionResult.clean();
    }

    /**
     * 判断指定物品是否属于阻止交互的物品类型。
     */
    private boolean isBlockingItem(String itemType) {
        if (itemType == null || itemType.isEmpty()) return false;
        String upper = itemType.toUpperCase();
        // 精确匹配或以关键词匹配
        if (BLOCKING_ITEMS.contains(upper)) return true;
        // 匹配任何以 _SWORD, _BOW, _HOE 结尾的物品
        if (upper.endsWith("_SWORD") || upper.endsWith("_BOW") || upper.endsWith("_HOE")) return true;
        // 匹配食物类（以 FOOD 或常见食物名结尾）
        if (upper.contains("POTION") || upper.equals("MILK_BUCKET")) return true;
        return false;
    }

    /**
     * 判断指定方块是否属于可交互的功能/容器方块。
     */
    private boolean isInteractableBlock(String blockType) {
        if (blockType == null) return false;
        String upper = blockType.toUpperCase();
        if (INTERACTABLE_BLOCKS.contains(upper)) return true;
        // 匹配任何箱子类（_CHEST, _SHULKER_BOX）和门类（_DOOR, _TRAPDOOR, _FENCE_GATE）
        if (upper.endsWith("_CHEST") || upper.endsWith("_SHULKER_BOX")) return true;
        if (upper.endsWith("_DOOR") || upper.endsWith("_TRAPDOOR") || upper.endsWith("_FENCE_GATE")) return true;
        if (upper.endsWith("_BUTTON")) return true;
        return false;
    }

    /**
     * 统计连续可疑交互次数。
     */
    private long countConsecutiveSuspicious(List<InteractEvent> history) {
        int count = 0;
        for (int i = history.size() - 1; i >= 0; i--) {
            if (history.get(i).suspicious) {
                count++;
            } else {
                break;
            }
        }
        return count;
    }

    public void clearPlayer(String playerName) {
        playerInteractHistory.remove(playerName);
        flaggedPlayers.remove(playerName);
    }

    public Map<String, Object> getStatus() {
        Map<String, Object> s = new LinkedHashMap<>();
        s.put("totalInteractEvents", totalInteractEvents.get());
        s.put("noInteractViolations", noInteractViolations.get());
        s.put("trackedPlayers", playerInteractHistory.size());
        s.put("flaggedPlayers", flaggedPlayers.size());
        s.put("enabled", config.getSecurity().getSuperEvolution().isAntiNoInteract());
        return s;
    }

    public long getTotalInteractEvents() { return totalInteractEvents.get(); }
    public long getNoInteractViolations() { return noInteractViolations.get(); }

    private void cleanupOldRecords() {
        Instant cutoff = Instant.now().minusSeconds(RECORD_RETENTION_SECONDS);
        playerInteractHistory.entrySet().removeIf(e -> {
            List<InteractEvent> events = e.getValue();
            events.removeIf(ev -> ev.time.isBefore(cutoff));
            return events.isEmpty();
        });
        flaggedPlayers.entrySet().removeIf(e -> e.getValue().isBefore(Instant.now()));
    }

    // ==================== 内部数据类 ====================

    /**
     * 交互事件记录——追踪每次容器/功能方块交互的详情。
     */
    private static class InteractEvent {
        final Instant time;
        final String heldItemType;     // 手中持有的物品
        final String blockType;        // 被交互的方块
        final boolean isSneaking;      // 是否潜行
        final boolean isContainer;     // 是否是有物品栏的容器方块
        final boolean suspicious;      // 是否为可疑交互

        InteractEvent(Instant time, String heldItemType, String blockType,
                     boolean isSneaking, boolean isContainer, boolean suspicious) {
            this.time = time;
            this.heldItemType = heldItemType;
            this.blockType = blockType;
            this.isSneaking = isSneaking;
            this.isContainer = isContainer;
            this.suspicious = suspicious;
        }
    }

    // ==================== 检测结果类 ====================

    /**
     * 交互绕过检测结果。
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

        public static DetectionResult clean() {
            return new DetectionResult(false, false, 0, List.of());
        }

        public static DetectionResult suspicious(int score, List<String> reasons) {
            return new DetectionResult(false, true, score, reasons);
        }

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
