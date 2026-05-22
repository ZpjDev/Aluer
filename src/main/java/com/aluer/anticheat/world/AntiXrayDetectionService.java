package com.aluer.anticheat.world;

import com.aluer.config.ServerGuardConfig;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

@Service
public class AntiXrayDetectionService {

    private final ServerGuardConfig config;

    private final Map<String, PlayerMiningData> miningData = new ConcurrentHashMap<>();
    private final Map<String, Instant> flaggedPlayers = new ConcurrentHashMap<>();
    private final ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor();
    private final AtomicLong totalDetections = new AtomicLong(0);

    private static final double DIAMOND_STONE_RATIO_THRESHOLD = 0.5;
    private static final double EMERALD_ORE_RATIO_THRESHOLD = 0.3;
    private static final int MIN_BLOCKS_FOR_ANALYSIS = 30;
    private static final int MAX_VALUABLE_STRAIGHT_LINE = 8;
    private static final long MINING_SESSION_WINDOW_MS = 300000;
    private static final long FLAG_DURATION_SECONDS = 3600;

    private static final Set<String> VALUABLE_ORES = Set.of(
            "DIAMOND_ORE", "DEEPSLATE_DIAMOND_ORE", "EMERALD_ORE", "DEEPSLATE_EMERALD_ORE",
            "ANCIENT_DEBRIS", "NETHER_GOLD_ORE", "GILDED_BLACKSTONE",
            "GOLD_ORE", "DEEPSLATE_GOLD_ORE"
    );

    private static final Set<String> COMMON_BLOCKS = Set.of(
            "STONE", "DEEPSLATE", "ANDESITE", "DIORITE", "GRANITE",
            "NETHERRACK", "BLACKSTONE", "BASALT", "TUFF", "CALCITE",
            "DIRT", "GRAVEL", "SAND", "SANDSTONE"
    );

    private static final Set<String> CONTAINER_BLOCKS = Set.of(
            "CHEST", "TRAPPED_CHEST", "ENDER_CHEST", "BARREL", "SHULKER_BOX",
            "WHITE_SHULKER_BOX", "ORANGE_SHULKER_BOX", "MAGENTA_SHULKER_BOX",
            "LIGHT_BLUE_SHULKER_BOX", "YELLOW_SHULKER_BOX", "LIME_SHULKER_BOX",
            "PINK_SHULKER_BOX", "GRAY_SHULKER_BOX", "LIGHT_GRAY_SHULKER_BOX",
            "CYAN_SHULKER_BOX", "PURPLE_SHULKER_BOX", "BLUE_SHULKER_BOX",
            "BROWN_SHULKER_BOX", "GREEN_SHULKER_BOX", "RED_SHULKER_BOX", "BLACK_SHULKER_BOX"
    );

    public AntiXrayDetectionService() {
        this(new ServerGuardConfig());
    }

    public AntiXrayDetectionService(ServerGuardConfig config) {
        this.config = config;
        scheduler.scheduleAtFixedRate(this::cleanupOldData, 120, 300, TimeUnit.SECONDS);
    }

    public XrayCheckResult checkBlockBreak(String playerName, String blockType, int x, int y, int z, String world) {
        if (!config.getSecurity().getSuperEvolution().isAntiXray()) {
            return XrayCheckResult.clean();
        }

        if (flaggedPlayers.containsKey(playerName)) {
            if (Instant.now().isAfter(flaggedPlayers.get(playerName))) {
                flaggedPlayers.remove(playerName);
            } else {
                return XrayCheckResult.flagged("Player is flagged for X-ray behavior");
            }
        }

        PlayerMiningData data = miningData.computeIfAbsent(playerName, k -> new PlayerMiningData());
        data.recordBreak(blockType, x, y, z);

        int score = 0;
        List<String> reasons = new ArrayList<>();

        // Rule 1: Diamond-to-stone ratio anomaly
        int valuableCount = data.valuableOresBroken;
        int commonCount = data.commonBlocksBroken;
        if (commonCount >= MIN_BLOCKS_FOR_ANALYSIS) {
            double ratio = (double) valuableCount / commonCount;
            if (ratio > DIAMOND_STONE_RATIO_THRESHOLD && valuableCount >= 5) {
                score += 30;
                reasons.add("HIGH_VALUABLE_RATIO: " + String.format("%.2f", ratio) + " (v:" + valuableCount + "/c:" + commonCount + ")");
            }
        }

        // Rule 2: Straight-line valuable mining (classic X-ray pattern)
        if (VALUABLE_ORES.contains(blockType.toUpperCase())) {
            data.lastValuableX = x;
            data.lastValuableY = y;
            data.lastValuableZ = z;
            data.consecutiveValuable++;
            if (data.consecutiveValuable > MAX_VALUABLE_STRAIGHT_LINE) {
                score += 30;
                reasons.add("STRAIGHT_LINE_MINING: " + data.consecutiveValuable + " consecutive valuable blocks");
            }
        } else {
            data.consecutiveValuable = 0;
        }

        // Rule 3: Mining directly to ores without exploring
        if (VALUABLE_ORES.contains(blockType.toUpperCase())) {
            // Check if there's a suspicious pattern of going directly to ores
            if (data.totalBlocksBroken > 20 && data.unusualPathCount > 5) {
                score += 20;
                reasons.add("DIRECT_ORE_PATHING: " + data.unusualPathCount + " unusual paths");
            }
        }

        // Rule 4: Mining containers behind walls
        if (CONTAINER_BLOCKS.contains(blockType.toUpperCase())) {
            if (data.isMiningThroughWalls()) {
                score += 15;
                reasons.add("WALL_CONTAINER_ACCESS: " + blockType);
            }
        }

        // Rule 5: Low light level mining precision
        if (VALUABLE_ORES.contains(blockType.toUpperCase()) && isMiningInDarkness(world, y)) {
            score += 10;
            reasons.add("DARK_MINING_PRECISION: y=" + y + " in " + world);
        }

        if (score >= 60) {
            flaggedPlayers.put(playerName, Instant.now().plusSeconds(FLAG_DURATION_SECONDS));
            totalDetections.incrementAndGet();
            return XrayCheckResult.flagged("X-ray detected: " + String.join("; ", reasons));
        } else if (score >= 30) {
            return XrayCheckResult.suspicious(score, reasons);
        }

        return XrayCheckResult.clean();
    }

    public void clearPlayer(String playerName) {
        miningData.remove(playerName);
        flaggedPlayers.remove(playerName);
    }

    public Map<String, Object> getStatus() {
        Map<String, Object> status = new LinkedHashMap<>();
        status.put("trackedPlayers", miningData.size());
        status.put("flaggedPlayers", flaggedPlayers.size());
        status.put("totalDetections", totalDetections.get());

        List<Map<String, Object>> topMiners = new ArrayList<>();
        for (Map.Entry<String, PlayerMiningData> e : miningData.entrySet()) {
            PlayerMiningData d = e.getValue();
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("player", e.getKey());
            m.put("valuableOres", d.valuableOresBroken);
            m.put("commonBlocks", d.commonBlocksBroken);
            double ratio = d.commonBlocksBroken > 0 ? (double) d.valuableOresBroken / d.commonBlocksBroken : 0;
            m.put("ratio", String.format("%.3f", ratio));
            m.put("consecutiveValuable", d.consecutiveValuable);
            topMiners.add(m);
        }
        topMiners.sort((a, b) -> Double.compare(
                Double.parseDouble(b.get("ratio").toString()),
                Double.parseDouble(a.get("ratio").toString())));
        status.put("topMiners", topMiners.subList(0, Math.min(topMiners.size(), 20)));
        return status;
    }

    public long getTotalDetections() { return totalDetections.get(); }

    private boolean isMiningInDarkness(String world, int y) {
        return (world.contains("_nether") || y < 10);
    }

    private void cleanupOldData() {
        Instant cutoff = Instant.now().minusSeconds(MINING_SESSION_WINDOW_MS * 2);
        miningData.entrySet().removeIf(e -> e.getValue().lastActivity.isBefore(cutoff));
        flaggedPlayers.entrySet().removeIf(e -> e.getValue().isBefore(Instant.now()));
    }

    private static class PlayerMiningData {
        int totalBlocksBroken;
        int valuableOresBroken;
        int commonBlocksBroken;
        int consecutiveValuable;
        int unusualPathCount;
        int lastValuableX, lastValuableY, lastValuableZ;
        Instant lastActivity = Instant.now();
        final List<BlockRecord> blockHistory = new ArrayList<>();

        void recordBreak(String blockType, int x, int y, int z) {
            totalBlocksBroken++;
            lastActivity = Instant.now();

            if (VALUABLE_ORES.contains(blockType.toUpperCase())) {
                valuableOresBroken++;
                if (lastValuableX != 0 || lastValuableY != 0 || lastValuableZ != 0) {
                    double dist = Math.sqrt(
                            Math.pow(x - lastValuableX, 2) +
                                    Math.pow(y - lastValuableY, 2) +
                                    Math.pow(z - lastValuableZ, 2));
                    if (dist > 20 && dist < 100) unusualPathCount++;
                }
            }
            if (COMMON_BLOCKS.contains(blockType.toUpperCase())) {
                commonBlocksBroken++;
            }

            blockHistory.add(new BlockRecord(blockType, x, y, z, Instant.now()));
            if (blockHistory.size() > 200) {
                blockHistory.remove(0);
            }
            consecutiveValuable = VALUABLE_ORES.contains(blockType.toUpperCase()) ? consecutiveValuable + 1 : 0;
        }

        boolean isMiningThroughWalls() {
            if (blockHistory.size() < 10) return false;
            int throughWallCount = 0;
            for (int i = 3; i < blockHistory.size(); i++) {
                if (CONTAINER_BLOCKS.contains(blockHistory.get(i).type.toUpperCase())) {
                    throughWallCount++;
                }
            }
            return throughWallCount >= 3;
        }
    }

    private static class BlockRecord {
        final String type;
        final int x, y, z;
        final Instant time;

        BlockRecord(String type, int x, int y, int z, Instant time) {
            this.type = type;
            this.x = x; this.y = y; this.z = z;
            this.time = time;
        }
    }

    public static class XrayCheckResult {
        private final boolean flagged;
        private final boolean suspicious;
        private final int score;
        private final List<String> reasons;

        private XrayCheckResult(boolean flagged, boolean suspicious, int score, List<String> reasons) {
            this.flagged = flagged;
            this.suspicious = suspicious;
            this.score = score;
            this.reasons = reasons;
        }

        public static XrayCheckResult clean() { return new XrayCheckResult(false, false, 0, List.of()); }
        public static XrayCheckResult suspicious(int score, List<String> reasons) { return new XrayCheckResult(false, true, score, reasons); }
        public static XrayCheckResult flagged(String msg) { return new XrayCheckResult(true, true, 100, List.of(msg)); }

        public boolean isFlagged() { return flagged; }
        public boolean isSuspicious() { return suspicious; }
        public int getScore() { return score; }
        public List<String> getReasons() { return reasons; }
    }
}
