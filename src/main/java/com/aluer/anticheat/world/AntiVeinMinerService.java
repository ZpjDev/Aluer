package com.aluer.anticheat.world;

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
 * 矿脉自动挖掘检测 (VeinMiner) — V5.3 世界/玩家/杂物安全模块
 *
 * 检测原理：
 *   Meteor Client 的 VeinMiner 模块能自动找到并挖掘整条矿脉中所有相连的矿石方块。
 *   正常玩家只能挖掘视野中可见的矿石，可能会遗漏处于视野盲区或被其他方块遮挡的矿石。
 *   VeinMiner 会系统性地找到每一块相连的矿石并精确瞄准挖掘。本模块通过以下维度检测：
 *   1. 相连矿石定位——检测玩家是否连续挖掘了属于同一矿脉的多个矿石方块。
 *      VeinMiner 的特征是快速（< 1 秒间隔）连续挖掘相邻矿石。
 *   2. 视野盲区挖掘——检测玩家是否挖掘了被其他方块遮挡、无法直接看到的矿石。
 *      正常玩家看不到的矿石不可能手动瞄准。
 *   3. 钻石/珍稀矿石比例异常——如果玩家的钻石发掘率超过正常水平的 3 倍，
 *      结合矿脉模式检测，即为 Xray + VeinMiner 组合。
 *   4. 完美定位速度——VeinMiner 在找到矿脉后切换目标的速度极快（< 200ms），
 *      人类需要时间识别和移动准星。
 *
 * 配置开关：serverguard.security.super-evolution.anti-vein-miner
 */
@Service
public class AntiVeinMinerService {

    private final ServerGuardConfig config;
    /** 每个玩家的矿石挖掘记录 */
    private final Map<String, List<OreBreakRecord>> playerOreRecords = new ConcurrentHashMap<>();
    /** 每个玩家的总方块挖掘数（用于计算珍稀矿石发掘率） */
    private final Map<String, AtomicLong> playerTotalBlocksMined = new ConcurrentHashMap<>();
    /** 每个玩家的珍稀矿石挖掘数 */
    private final Map<String, AtomicLong> playerRareOresMined = new ConcurrentHashMap<>();
    /** 已标记的玩家 */
    private final Map<String, Instant> flaggedPlayers = new ConcurrentHashMap<>();
    private final ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor();

    private final AtomicLong totalOreEvents = new AtomicLong(0);
    private final AtomicLong veinMinerViolations = new AtomicLong(0);

    /** 相邻矿石最大间隔（格）——超过此距离认为不在同一矿脉 */
    private static final int VEIN_BLOCK_MAX_DISTANCE = 3;
    /** 矿脉挖掘最大间隔时间（毫秒）——超过此值认为不是连续矿脉挖掘 */
    private static final long VEIN_BREAK_MAX_INTERVAL_MS = 1000;
    /** 连续矿脉方块最低数量——至少 N 块连续矿石才触发检测 */
    private static final int MIN_VEIN_BLOCKS = 4;
    /** 钻石/珍稀矿石发掘率异常阈值——正常玩家约 0.5-2%，Xray 可达 8-25% */
    private static final double RARE_ORE_RATIO_THRESHOLD = 0.08;
    /** 最少总挖掘数用于计算发掘率 */
    private static final int MIN_TOTAL_BLOCKS_FOR_RATIO = 200;
    /** 完美定位间隔阈值（毫秒） */
    private static final long PERFECT_TARGET_MS = 200;

    /** 记录保留时间（秒） */
    private static final long RECORD_RETENTION_SECONDS = 900;
    /** 标记持续时间（秒） */
    private static final long FLAG_DURATION_SECONDS = 1800;

    /** 珍稀矿石方块集合 */
    private static final Set<String> RARE_ORES = Set.of(
        "DIAMOND_ORE", "DEEPSLATE_DIAMOND_ORE",
        "EMERALD_ORE", "DEEPSLATE_EMERALD_ORE",
        "ANCIENT_DEBRIS",
        "GOLD_ORE", "DEEPSLATE_GOLD_ORE",
        "NETHER_GOLD_ORE", "GILDED_BLACKSTONE"
    );

    /** 所有矿石方块集合（用于矿脉分析） */
    private static final Set<String> ALL_ORES = Set.of(
        "COAL_ORE", "DEEPSLATE_COAL_ORE",
        "IRON_ORE", "DEEPSLATE_IRON_ORE",
        "COPPER_ORE", "DEEPSLATE_COPPER_ORE",
        "GOLD_ORE", "DEEPSLATE_GOLD_ORE", "NETHER_GOLD_ORE",
        "REDSTONE_ORE", "DEEPSLATE_REDSTONE_ORE",
        "LAPIS_ORE", "DEEPSLATE_LAPIS_ORE",
        "DIAMOND_ORE", "DEEPSLATE_DIAMOND_ORE",
        "EMERALD_ORE", "DEEPSLATE_EMERALD_ORE",
        "NETHER_QUARTZ_ORE",
        "ANCIENT_DEBRIS", "GILDED_BLACKSTONE"
    );

    public AntiVeinMinerService() {
        this(new ServerGuardConfig());
    }

    @Autowired
    public AntiVeinMinerService(ServerGuardConfig config) {
        this.config = config;
        scheduler.scheduleAtFixedRate(this::cleanupOldRecords, 120, 300, TimeUnit.SECONDS);
    }

    /**
     * 检测矿石方块破坏事件——判断是否为矿脉自动化挖掘。
     *
     * @param playerName 玩家名称
     * @param playerUUID 玩家 UUID
     * @param blockType  被破坏的方块类型
     * @param x          方块 X 坐标
     * @param y          方块 Y 坐标
     * @param z          方块 Z 坐标
     * @param isVisible  该方块对玩家是否可见（未被其他方块遮挡）
     * @return 检测结果
     */
    public DetectionResult detectOreBreak(String playerName, String playerUUID,
                                           String blockType, int x, int y, int z,
                                           boolean isVisible) {
        if (!config.getSecurity().getSuperEvolution().isAntiVeinMiner()) {
            return DetectionResult.clean();
        }

        // 只处理矿石方块
        if (blockType == null || !isOreBlock(blockType)) {
            // 仍记录总挖掘数用于发掘率计算
            AtomicLong total = playerTotalBlocksMined.computeIfAbsent(playerName,
                k -> new AtomicLong(0));
            total.incrementAndGet();
            return DetectionResult.clean();
        }

        Instant flaggedUntil = flaggedPlayers.get(playerName);
        if (flaggedUntil != null) {
            if (Instant.now().isAfter(flaggedUntil)) {
                flaggedPlayers.remove(playerName);
            } else {
                return DetectionResult.flagged(List.of(
                    "PLAYER_ALREADY_FLAGGED: " + playerName + " under vein-miner investigation"));
            }
        }

        Instant now = Instant.now();
        List<OreBreakRecord> records = playerOreRecords.computeIfAbsent(playerName,
            k -> Collections.synchronizedList(new ArrayList<>()));
        OreBreakRecord record = new OreBreakRecord(now, blockType, x, y, z, isVisible);
        records.add(record);
        totalOreEvents.incrementAndGet();
        playerTotalBlocksMined.computeIfAbsent(playerName, k -> new AtomicLong(0)).incrementAndGet();

        // 珍稀矿石计数
        if (isRareOre(blockType)) {
            playerRareOresMined.computeIfAbsent(playerName, k -> new AtomicLong(0)).incrementAndGet();
        }

        int score = 0;
        List<String> reasons = new ArrayList<>();

        // === 检测 1: 连续矿脉挖掘模式 ===
        // 检查最近的连续矿石是否属于同一矿脉
        VeinCluster cluster = analyzeVeinCluster(records);
        if (cluster.veinBlockCount >= MIN_VEIN_BLOCKS && cluster.maxIntervalMs < VEIN_BREAK_MAX_INTERVAL_MS) {
            score += 30;
            reasons.add("VEIN_PATTERN: " + cluster.veinBlockCount +
                " connected ore blocks mined within " + cluster.maxIntervalMs +
                "ms window (vein-miner pattern)");
        }

        // === 检测 2: 视野盲区矿石挖掘 ===
        if (!isVisible && records.size() >= 2) {
            // 如果上一块矿石也是不可见的，则更可疑
            if (!records.get(records.size() - 2).isVisible) {
                score += 25;
                reasons.add("BLIND_ORE_MINING: " + blockType + " at (" + x + "," + y + "," + z +
                    ") not visible to player (behind blocks)");
            }
        }

        // === 检测 3: 钻石/珍稀矿石发掘率 ===
        long totalBlocks = playerTotalBlocksMined.getOrDefault(playerName, new AtomicLong(0)).get();
        long rareBlocks = playerRareOresMined.getOrDefault(playerName, new AtomicLong(0)).get();
        if (totalBlocks >= MIN_TOTAL_BLOCKS_FOR_RATIO) {
            double ratio = (double) rareBlocks / totalBlocks;
            if (ratio > RARE_ORE_RATIO_THRESHOLD) {
                score += 35;
                reasons.add("RARE_ORE_RATIO: " + String.format("%.1f%%", ratio * 100) +
                    " of mined blocks are rare ores (normal < " +
                    String.format("%.1f%%", RARE_ORE_RATIO_THRESHOLD * 100) +
                    ", possible Xray+VeinMiner combination)");
            }
        }

        // === 检测 4: 完美定位速度 ===
        if (records.size() >= 3) {
            long lastInterval = now.toEpochMilli() - records.get(records.size() - 2).time.toEpochMilli();
            if (lastInterval < PERFECT_TARGET_MS) {
                OreBreakRecord prev = records.get(records.size() - 2);
                double dist = Math.sqrt(Math.pow(x - prev.x, 2) + Math.pow(y - prev.y, 2) + Math.pow(z - prev.z, 2));
                if (dist > 1.0) {
                    // 矿石间隔超过 1 格但切换目标极快
                    score += 20;
                    reasons.add("INSTANT_TARGET: switched to ore " + String.format("%.1f", dist) +
                        " blocks away in " + lastInterval + "ms (inhuman targeting speed)");
                }
            }
        }

        if (score >= 50) {
            flaggedPlayers.put(playerName, Instant.now().plusSeconds(FLAG_DURATION_SECONDS));
            veinMinerViolations.incrementAndGet();
            return DetectionResult.flagged(reasons);
        } else if (score >= 30) {
            return DetectionResult.suspicious(score, reasons);
        }

        return DetectionResult.clean();
    }

    /**
     * 判断是否为矿石方块。
     */
    private boolean isOreBlock(String blockType) {
        if (blockType == null) return false;
        String upper = blockType.toUpperCase();
        return ALL_ORES.contains(upper) || upper.endsWith("_ORE");
    }

    /**
     * 判断是否为珍稀矿石。
     */
    private boolean isRareOre(String blockType) {
        if (blockType == null) return false;
        return RARE_ORES.contains(blockType.toUpperCase());
    }

    /**
     * 分析最近的矿石记录是否构成矿脉挖掘模式。
     *
     * 矿脉模式特征：
     *  - 连续的多块矿石在空间上相邻（彼此距离 <= VEIN_BLOCK_MAX_DISTANCE）
     *  - 时间上连续快速挖掘（间隔 < VEIN_BREAK_MAX_INTERVAL_MS）
     */
    private VeinCluster analyzeVeinCluster(List<OreBreakRecord> records) {
        int veinCount = 0;
        long maxInterval = 0;

        // 从最近的一批记录中分析
        int start = Math.max(0, records.size() - 15);
        List<OreBreakRecord> recentOres = new ArrayList<>();
        for (int i = records.size() - 1; i >= start; i--) {
            recentOres.add(0, records.get(i));
        }

        if (recentOres.size() < 2) return new VeinCluster(1, 0);

        // 连续矿脉分析：从最近开始回溯，检查相邻矿石是否符合矿脉特征
        int consecutiveVein = 1;
        long lastTime = recentOres.get(recentOres.size() - 1).time.toEpochMilli();
        int lastX = recentOres.get(recentOres.size() - 1).x;
        int lastY = recentOres.get(recentOres.size() - 1).y;
        int lastZ = recentOres.get(recentOres.size() - 1).z;

        for (int i = recentOres.size() - 2; i >= 0; i--) {
            OreBreakRecord r = recentOres.get(i);
            long interval = lastTime - r.time.toEpochMilli();
            double dist = Math.sqrt(
                Math.pow(lastX - r.x, 2) + Math.pow(lastY - r.y, 2) + Math.pow(lastZ - r.z, 2));

            if (dist <= VEIN_BLOCK_MAX_DISTANCE && interval < VEIN_BREAK_MAX_INTERVAL_MS) {
                consecutiveVein++;
                if (interval > maxInterval) maxInterval = interval;
                lastTime = r.time.toEpochMilli();
                lastX = r.x;
                lastY = r.y;
                lastZ = r.z;
            } else {
                break; // 矿脉中断
            }
        }

        return new VeinCluster(consecutiveVein, maxInterval);
    }

    public void clearPlayer(String playerName) {
        playerOreRecords.remove(playerName);
        playerTotalBlocksMined.remove(playerName);
        playerRareOresMined.remove(playerName);
        flaggedPlayers.remove(playerName);
    }

    public Map<String, Object> getStatus() {
        Map<String, Object> s = new LinkedHashMap<>();
        s.put("totalOreEvents", totalOreEvents.get());
        s.put("veinMinerViolations", veinMinerViolations.get());
        s.put("trackedPlayers", playerOreRecords.size());
        s.put("flaggedPlayers", flaggedPlayers.size());
        s.put("enabled", config.getSecurity().getSuperEvolution().isAntiVeinMiner());
        return s;
    }

    public long getTotalOreEvents() { return totalOreEvents.get(); }
    public long getVeinMinerViolations() { return veinMinerViolations.get(); }

    private void cleanupOldRecords() {
        Instant cutoff = Instant.now().minusSeconds(RECORD_RETENTION_SECONDS);
        playerOreRecords.entrySet().removeIf(e -> {
            List<OreBreakRecord> records = e.getValue();
            records.removeIf(r -> r.time.isBefore(cutoff));
            return records.isEmpty();
        });
        flaggedPlayers.entrySet().removeIf(e -> e.getValue().isBefore(Instant.now()));
    }

    // ==================== 内部数据类 ====================

    /**
     * 矿石破坏记录——追踪每次矿石挖掘的时空和可见性信息。
     */
    private static class OreBreakRecord {
        final Instant time;
        final String blockType;
        final int x, y, z;
        final boolean isVisible; // 该方块对玩家是否可见

        OreBreakRecord(Instant time, String blockType, int x, int y, int z, boolean isVisible) {
            this.time = time;
            this.blockType = blockType;
            this.x = x;
            this.y = y;
            this.z = z;
            this.isVisible = isVisible;
        }
    }

    /**
     * 矿脉簇分析结果——描述一组连续矿石挖掘的矿脉特征。
     */
    private static class VeinCluster {
        final int veinBlockCount;    // 连续矿脉方块数
        final long maxIntervalMs;    // 矿脉内最大间隔（毫秒）

        VeinCluster(int veinBlockCount, long maxIntervalMs) {
            this.veinBlockCount = veinBlockCount;
            this.maxIntervalMs = maxIntervalMs;
        }
    }

    // ==================== 检测结果类 ====================

    /**
     * 矿脉挖掘检测结果。
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
