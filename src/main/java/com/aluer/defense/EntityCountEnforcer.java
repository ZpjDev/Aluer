package com.aluer.defense;

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
 * 实体数量强制执行器 — V5.0 服务器保护模块
 *
 * 检测原理：
 *   Minecraft 的每个区块最多承载的实体数量直接影响服务器 TPS。恶意玩家可以
 *   通过批量放置矿车、船、盔甲架、物品展示框等实体类物品制造实体洪流，导致
 *   区块实体 tick 计算暴增，服务器 TPS 急剧下降。正常的刷怪塔（mob grinder）
 *   虽然也会产生大量实体，但其来源是自然生成而非玩家主动放置。
 *
 * 核心能力：
 *   1. 按区块追踪实体数量（从 ChunkLoadEvent 和 EntitySpawnEvent 获取）
 *   2. 区分自然生成实体与玩家放置实体（后者更可疑）
 *   3. 检测同一玩家快速放置同类实体的 spam 模式
 *   4. 超限时按优先级自动移除多余实体
 *
 * 实体优先级（数值越小越优先移除，因为对玩家影响最小）：
 *   0 = ITEM（掉落物，无限生成易造成卡顿）
 *   1 = EXPERIENCE_ORB（经验球，大量堆积影响渲染）
 *   2 = MINECART 系列（矿车，经典卡服手段）
 *   3 = BOAT（船，碰撞计算消耗高）
 *   4 = ARMOR_STAND（盔甲架，NBT 复杂）
 *   5 = ITEM_FRAME（物品展示框，每个都是独立 tile entity）
 *   6 = PAINTING / 其他
 *
 * 刷怪塔特殊处理：
 *   自然生成的生物（怪物/动物）不计入玩家放置统计；但如果在短时间内
 *   同一区块出现大量同种怪物且附近存在刷怪笼/水电梯等结构，则可能
 *   是正常的刷怪塔，不触发报警。
 *
 * 配置开关：serverguard.security.super-evolution.entity-count-enforcer
 */
@Service
public class EntityCountEnforcer {

    private final ServerGuardConfig config;

    /** 按区块键追踪实体信息：chunkKey -> ChunkEntityInfo */
    private final Map<String, ChunkEntityInfo> chunkEntityMap = new ConcurrentHashMap<>();

    /** 按玩家追踪其放置的可疑实体 */
    private final Map<String, List<PlayerEntityRecord>> playerEntityRecords = new ConcurrentHashMap<>();

    /** 按玩家追踪实体 spam 模式检测的最近放置时间 */
    private final Map<String, Map<String, List<Instant>>> playerEntitySpamTracker = new ConcurrentHashMap<>();

    /** 已被标记的玩家及其到期时间 */
    private final Map<String, Instant> flaggedPlayers = new ConcurrentHashMap<>();

    /** 已被自动移除的总实体计数 */
    private final AtomicLong totalRemovedEntities = new AtomicLong(0);
    /** 实体限制触发次数 */
    private final AtomicLong limitViolations = new AtomicLong(0);
    /** 实体 spam 检测次数 */
    private final AtomicLong spamDetections = new AtomicLong(0);

    private final ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor();

    /** 每个区块最大实体数量（默认值） */
    private static final int MAX_ENTITIES_PER_CHUNK = 30;

    /** 单个玩家最大可放置实体数（全局追踪） */
    private static final int MAX_PLAYER_SPAWNED_ENTITIES = 200;

    /** 单批次移除实体数量 */
    private static final int REMOVAL_BATCH_SIZE = 10;

    /** 实体 spam 检测窗口（秒）：同类实体在此窗口内放置超过阈值视为 spam */
    private static final long SPAM_WINDOW_SECONDS = 5;
    private static final int SPAM_THRESHOLD = 8;

    /** 实体记录保留时间（秒） */
    private static final long RECORD_RETENTION_SECONDS = 600;
    /** 标记持续时间（秒） */
    private static final long FLAG_DURATION_SECONDS = 1800;

    /**
     * 可被追踪的实体类型枚举（按卡服影响从高到低排列）。
     * 这些是玩家可以主动放置/创造的实体类型。
     */
    public enum TrackedEntityType {
        ITEM,           // 掉落物
        EXPERIENCE_ORB, // 经验球
        MINECART,       // 矿车（含箱子矿车、漏斗矿车、TNT矿车等）
        BOAT,           // 船（含运输船）
        ARMOR_STAND,    // 盔甲架
        ITEM_FRAME,     // 物品展示框
        PAINTING,       // 画
        END_CRYSTAL,    // 末影水晶
        TNT,            // 点燃的 TNT 实体
        FALLING_BLOCK,  // 下落方块（沙/沙砾/混凝土粉末）
        OTHER           // 其它玩家放置实体
    }

    /**
     * 获取实体类型的移除优先级（数字越小越优先移除）。
     */
    public static int getRemovalPriority(TrackedEntityType type) {
        return switch (type) {
            case ITEM -> 0;
            case EXPERIENCE_ORB -> 1;
            case MINECART -> 2;
            case BOAT -> 3;
            case ARMOR_STAND -> 4;
            case ITEM_FRAME -> 5;
            case PAINTING, END_CRYSTAL -> 6;
            default -> 7;
        };
    }

    public EntityCountEnforcer() {
        this(new ServerGuardConfig());
    }

    @Autowired
    public EntityCountEnforcer(ServerGuardConfig config) {
        this.config = config;
        // 每 120 秒清理过期记录
        scheduler.scheduleAtFixedRate(this::cleanupOldRecords, 120, 120, TimeUnit.SECONDS);
    }

    /**
     * 检查实体生成/放置是否超出区块容量限制。
     *
     * @param chunkKey       区块键（格式：chunkX:chunkZ:world）
     * @param entityType     实体类型
     * @param playerName     触发玩家名称（自然生成时为 "NATURAL"）
     * @param isNaturalSpawn 是否为自然生成（怪物/动物/环境）
     * @return 检查结果
     */
    public EntityEnforceResult checkEntitySpawn(String chunkKey, String entityType,
                                                 String playerName, boolean isNaturalSpawn) {
        if (!config.getSecurity().getSuperEvolution().isEntityCountEnforcer()) {
            return EntityEnforceResult.clean();
        }

        ChunkEntityInfo chunkInfo = chunkEntityMap.computeIfAbsent(chunkKey, k -> new ChunkEntityInfo(chunkKey));
        Instant now = Instant.now();

        // 增加区块实体计数
        chunkInfo.totalEntityCount++;
        chunkInfo.lastActivity = now;

        // 按类型统计
        chunkInfo.entityTypeCount.merge(entityType.toUpperCase(), 1, Integer::sum);

        // 跟踪玩家放置的实体（非自然生成）
        boolean isPlayerSpawned = !isNaturalSpawn && !"NATURAL".equals(playerName) && playerName != null;
        if (isPlayerSpawned) {
            chunkInfo.playerSpawnedCount++;
            // 记录到玩家实体历史
            PlayerEntityRecord record = new PlayerEntityRecord(now, entityType, chunkKey);
            playerEntityRecords.computeIfAbsent(playerName, k -> new ArrayList<>()).add(record);

            // 实体 spam 检测：同一玩家在短时间窗口内密集放置同类实体
            Map<String, List<Instant>> spamTracker = playerEntitySpamTracker
                .computeIfAbsent(playerName, k -> new ConcurrentHashMap<>());
            List<Instant> typeTimestamps = spamTracker.computeIfAbsent(
                entityType.toUpperCase(), k -> Collections.synchronizedList(new ArrayList<>()));
            typeTimestamps.add(now);

            long spamWindowStart = now.toEpochMilli() - (SPAM_WINDOW_SECONDS * 1000);
            long spamCount = typeTimestamps.stream()
                .filter(t -> t.toEpochMilli() > spamWindowStart)
                .count();
            if (spamCount > SPAM_THRESHOLD) {
                spamDetections.incrementAndGet();
                flaggedPlayers.put(playerName, now.plusSeconds(FLAG_DURATION_SECONDS));
                return EntityEnforceResult.flagged(List.of(
                    "ENTITY_SPAM: player " + playerName + " spawned " + spamCount
                    + " " + entityType + " entities in " + SPAM_WINDOW_SECONDS + "s window"));
            }
        }

        // 检查区块实体总量是否超限
        List<String> reasons = new ArrayList<>();
        boolean exceedsLimit = false;

        if (chunkInfo.totalEntityCount > MAX_ENTITIES_PER_CHUNK) {
            limitViolations.incrementAndGet();
            reasons.add("CHUNK_ENTITY_OVERFLOW: " + chunkInfo.totalEntityCount
                + " entities in chunk " + chunkKey + " (limit=" + MAX_ENTITIES_PER_CHUNK + ")");
            exceedsLimit = true;
        }

        // 检查玩家放置实体占比
        if (chunkInfo.playerSpawnedCount > MAX_ENTITIES_PER_CHUNK * 0.6) {
            reasons.add("HIGH_PLAYER_SPAWNED_RATIO: " + chunkInfo.playerSpawnedCount
                + "/" + chunkInfo.totalEntityCount + " player-spawned in chunk " + chunkKey);
        }

        // 检查该区块实体类型集中度（同一类型占比过高说明是 spam）
        int maxTypeCount = chunkInfo.entityTypeCount.values().stream()
            .mapToInt(Integer::intValue).max().orElse(0);
        if (chunkInfo.totalEntityCount > 10 && maxTypeCount > chunkInfo.totalEntityCount * 0.7) {
            String dominantType = chunkInfo.entityTypeCount.entrySet().stream()
                .filter(e -> e.getValue() == maxTypeCount)
                .map(Map.Entry::getKey).findFirst().orElse("UNKNOWN");
            reasons.add("ENTITY_TYPE_CONCENTRATION: " + dominantType + " accounts for "
                + maxTypeCount + "/" + chunkInfo.totalEntityCount + " (" +
                String.format("%.0f%%", 100.0 * maxTypeCount / chunkInfo.totalEntityCount) + ")");
        }

        if (exceedsLimit) {
            return EntityEnforceResult.blocked(reasons);
        }
        if (!reasons.isEmpty()) {
            return EntityEnforceResult.suspicious(reasons.size() * 20, reasons);
        }

        return EntityEnforceResult.clean();
    }

    /**
     * 生成实体移除建议列表（按优先级排序）。
     * 调用者（Paper 插件监听器）应根据此列表执行实际的实体移除操作。
     *
     * @param chunkKey      目标区块键
     * @param excessCount   需要移除的超额实体数量
     * @return 按优先级排序的实体移除建议列表
     */
    public List<EntityRemovalSuggestion> getRemovalSuggestions(String chunkKey, int excessCount) {
        ChunkEntityInfo chunkInfo = chunkEntityMap.get(chunkKey);
        if (chunkInfo == null) return List.of();

        List<EntityRemovalSuggestion> suggestions = new ArrayList<>();

        // 优先移除掉落物和经验球（对玩家游戏体验影响最小）
        if (chunkInfo.entityTypeCount.getOrDefault("ITEM", 0) > 0) {
            suggestions.add(new EntityRemovalSuggestion("ITEM",
                Math.min(excessCount, chunkInfo.entityTypeCount.get("ITEM")), 0));
        }
        if (chunkInfo.entityTypeCount.getOrDefault("EXPERIENCE_ORB", 0) > 0) {
            int remaining = excessCount - suggestions.stream().mapToInt(s -> s.count).sum();
            if (remaining > 0) {
                suggestions.add(new EntityRemovalSuggestion("EXPERIENCE_ORB",
                    Math.min(remaining, chunkInfo.entityTypeCount.getOrDefault("EXPERIENCE_ORB", 0)), 1));
            }
        }
        // 然后移除矿车类
        int remaining = excessCount - suggestions.stream().mapToInt(s -> s.count).sum();
        if (remaining > 0) {
            int minecartTotal = chunkInfo.entityTypeCount.getOrDefault("MINECART", 0)
                + chunkInfo.entityTypeCount.getOrDefault("CHEST_MINECART", 0)
                + chunkInfo.entityTypeCount.getOrDefault("HOPPER_MINECART", 0)
                + chunkInfo.entityTypeCount.getOrDefault("TNT_MINECART", 0);
            if (minecartTotal > 0) {
                suggestions.add(new EntityRemovalSuggestion("MINECART",
                    Math.min(remaining, minecartTotal), 2));
            }
        }
        // 然后移除盔甲架
        remaining = excessCount - suggestions.stream().mapToInt(s -> s.count).sum();
        if (remaining > 0 && chunkInfo.entityTypeCount.getOrDefault("ARMOR_STAND", 0) > 0) {
            suggestions.add(new EntityRemovalSuggestion("ARMOR_STAND",
                Math.min(remaining, chunkInfo.entityTypeCount.get("ARMOR_STAND")), 4));
        }

        totalRemovedEntities.addAndGet(suggestions.stream().mapToInt(s -> s.count).sum());
        return suggestions;
    }

    /**
     * 清除玩家追踪数据。
     */
    public void clearPlayer(String playerName) {
        playerEntityRecords.remove(playerName);
        playerEntitySpamTracker.remove(playerName);
        flaggedPlayers.remove(playerName);
    }

    /**
     * 移除区块的追踪数据（区块卸载时调用）。
     */
    public void removeChunk(String chunkKey) {
        chunkEntityMap.remove(chunkKey);
    }

    /**
     * 获取区块实体概览信息。
     */
    public Map<String, Object> getChunkInfo(String chunkKey) {
        ChunkEntityInfo info = chunkEntityMap.get(chunkKey);
        if (info == null) return Map.of("exists", false);

        Map<String, Object> m = new LinkedHashMap<>();
        m.put("exists", true);
        m.put("totalEntities", info.totalEntityCount);
        m.put("playerSpawned", info.playerSpawnedCount);
        m.put("typeBreakdown", new LinkedHashMap<>(info.entityTypeCount));
        m.put("lastActivity", info.lastActivity.toString());
        return m;
    }

    /**
     * 获取当前模块运行状态。
     */
    public Map<String, Object> getStatus() {
        Map<String, Object> s = new LinkedHashMap<>();
        s.put("totalRemovedEntities", totalRemovedEntities.get());
        s.put("limitViolations", limitViolations.get());
        s.put("spamDetections", spamDetections.get());
        s.put("trackedChunks", chunkEntityMap.size());
        s.put("trackedPlayers", playerEntityRecords.size());
        s.put("flaggedPlayers", flaggedPlayers.size());
        s.put("enabled", config.getSecurity().getSuperEvolution().isEntityCountEnforcer());

        // Top-10 实体最多的区块
        List<Map<String, Object>> topChunks = new ArrayList<>();
        chunkEntityMap.entrySet().stream()
            .sorted((a, b) -> Integer.compare(b.getValue().totalEntityCount, a.getValue().totalEntityCount))
            .limit(10)
            .forEach(e -> {
                Map<String, Object> m = new LinkedHashMap<>();
                m.put("chunk", e.getKey());
                m.put("totalEntities", e.getValue().totalEntityCount);
                m.put("playerSpawned", e.getValue().playerSpawnedCount);
                topChunks.add(m);
            });
        s.put("topEntityChunks", topChunks);

        return s;
    }

    public long getTotalRemovedEntities() { return totalRemovedEntities.get(); }
    public long getLimitViolations() { return limitViolations.get(); }
    public long getSpamDetections() { return spamDetections.get(); }

    /**
     * 清理过期记录。
     */
    private void cleanupOldRecords() {
        Instant cutoff = Instant.now().minusSeconds(RECORD_RETENTION_SECONDS);
        playerEntityRecords.entrySet().removeIf(e -> {
            List<PlayerEntityRecord> records = e.getValue();
            records.removeIf(r -> r.timestamp.isBefore(cutoff));
            return records.isEmpty();
        });
        playerEntitySpamTracker.entrySet().removeIf(e -> {
            Map<String, List<Instant>> typeMap = e.getValue();
            typeMap.values().forEach(list -> list.removeIf(t -> t.isBefore(cutoff)));
            typeMap.values().removeIf(List::isEmpty);
            return typeMap.isEmpty();
        });
        flaggedPlayers.entrySet().removeIf(e -> e.getValue().isBefore(Instant.now()));
    }

    // ==================== 内部数据类 ====================

    /**
     * 区块实体信息 — 追踪单个区块内所有实体的统计数据。
     */
    private static class ChunkEntityInfo {
        final String chunkKey;
        int totalEntityCount = 0;
        int playerSpawnedCount = 0;
        final Map<String, Integer> entityTypeCount = new ConcurrentHashMap<>();
        Instant lastActivity = Instant.now();

        ChunkEntityInfo(String chunkKey) {
            this.chunkKey = chunkKey;
        }
    }

    /**
     * 玩家实体放置记录。
     */
    private static class PlayerEntityRecord {
        final Instant timestamp;
        final String entityType;
        final String chunkKey;

        PlayerEntityRecord(Instant timestamp, String entityType, String chunkKey) {
            this.timestamp = timestamp;
            this.entityType = entityType;
            this.chunkKey = chunkKey;
        }
    }

    /**
     * 实体移除建议 — 指导插件层执行实际的实体移除操作。
     */
    public static class EntityRemovalSuggestion {
        public final String entityType;
        public final int count;
        public final int priority; // 0=最高优先级

        public EntityRemovalSuggestion(String entityType, int count, int priority) {
            this.entityType = entityType;
            this.count = count;
            this.priority = priority;
        }

        @Override
        public String toString() {
            return "Remove " + count + "x " + entityType + " (priority=" + priority + ")";
        }
    }

    // ==================== 检测结果类 ====================

    /**
     * 实体数量检查结果。
     */
    public static class EntityEnforceResult {
        private final boolean blocked;
        private final boolean flagged;
        private final boolean suspicious;
        private final int score;
        private final List<String> reasons;

        private EntityEnforceResult(boolean blocked, boolean flagged, boolean suspicious,
                                    int score, List<String> reasons) {
            this.blocked = blocked;
            this.flagged = flagged;
            this.suspicious = suspicious;
            this.score = score;
            this.reasons = reasons;
        }

        /** 正常：实体数量在安全范围内 */
        public static EntityEnforceResult clean() {
            return new EntityEnforceResult(false, false, false, 0, List.of());
        }

        /** 可疑：实体数量偏高但未触发直接干预 */
        public static EntityEnforceResult suspicious(int score, List<String> reasons) {
            return new EntityEnforceResult(false, false, true, score, reasons);
        }

        /** 阻止：实体数量超限，需要移除多余实体 */
        public static EntityEnforceResult blocked(List<String> reasons) {
            return new EntityEnforceResult(true, false, true, 0, reasons);
        }

        /** 已标记：检测到恶意实体 spam 行为 */
        public static EntityEnforceResult flagged(List<String> reasons) {
            return new EntityEnforceResult(true, true, true, 100, reasons);
        }

        public boolean isBlocked() { return blocked; }
        public boolean isFlagged() { return flagged; }
        public boolean isSuspicious() { return suspicious; }
        public boolean isClean() { return !blocked && !flagged && !suspicious; }
        public int getScore() { return score; }
        public List<String> getReasons() { return reasons; }
    }
}
