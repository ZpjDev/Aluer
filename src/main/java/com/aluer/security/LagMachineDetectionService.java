package com.aluer.security;

import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

@Service
public class LagMachineDetectionService {

    private final Map<String, List<LagEvent>> lagEvents = new ConcurrentHashMap<>();
    private final Map<String, Instant> flaggedPlayers = new ConcurrentHashMap<>();
    private final Map<String, ChunkActivity> chunkActivity = new ConcurrentHashMap<>();
    private final ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor();
    private final AtomicLong totalDetections = new AtomicLong(0);

    private static final long FLAG_DURATION_SECONDS = 7200;

    // Lag machine indicators
    private static final int MAX_ENTITIES_PER_CHUNK = 50;
    private static final int MAX_TILE_ENTITIES_PER_CHUNK = 20;
    private static final int MAX_REDSTONE_UPDATES_PER_CHUNK = 100;
    private static final int MAX_MINECARTS_PER_CHUNK = 10;
    private static final int MAX_TNT_PER_CHUNK = 30;
    private static final int MAX_OBSERVER_UPDATES_PER_CHUNK = 50;
    private static final int MAX_FALLING_BLOCKS = 100;

    private static final Set<String> LAG_CAUSING_BLOCKS = Set.of(
            "OBSERVER", "PISTON", "STICKY_PISTON", "REDSTONE_BLOCK",
            "REDSTONE_WIRE", "REDSTONE_TORCH", "REPEATER", "COMPARATOR",
            "HOPPER", "DISPENSER", "DROPPER", "NOTE_BLOCK", "BELL",
            "TNT", "MINECART", "CHEST_MINECART", "HOPPER_MINECART",
            "TNT_MINECART", "COMMAND_BLOCK", "CHAIN_COMMAND_BLOCK",
            "REPEATING_COMMAND_BLOCK", "SCULK_SENSOR", "SCULK_SHRIEKER",
            "CALIBRATED_SCULK_SENSOR", "DAYLIGHT_DETECTOR", "TRIPWIRE_HOOK"
    );

    private static final Set<String> ENTITY_LAG_TYPES = Set.of(
            "ITEM_FRAME", "GLOW_ITEM_FRAME", "ARMOR_STAND", "PAINTING",
            "BOAT", "CHEST_BOAT", "MINECART", "CHEST_MINECART",
            "HOPPER_MINECART", "TNT_MINECART", "FURNACE_MINECART"
    );

    public LagMachineDetectionService() {
        scheduler.scheduleAtFixedRate(this::cleanupOldData, 120, 300, TimeUnit.SECONDS);
    }

    public LagCheckResult checkBlockPlace(String playerName, String blockType, int x, int y, int z, String world) {
        String chunkKey = (x >> 4) + ":" + (z >> 4) + ":" + world;
        ChunkActivity chunk = chunkActivity.computeIfAbsent(chunkKey, k -> new ChunkActivity());
        chunk.recordBlockPlace(blockType, playerName);

        int score = 0;
        List<String> reasons = new ArrayList<>();

        // Rule 1: Excessive redstone components per chunk
        if (LAG_CAUSING_BLOCKS.contains(blockType.toUpperCase())) {
            chunk.lagBlockCount++;
            if (chunk.lagBlockCount > MAX_REDSTONE_UPDATES_PER_CHUNK) {
                score += 25;
                reasons.add("REDSTONE_DENSITY: " + chunk.lagBlockCount + " lag blocks in chunk " + chunkKey);
            }
        }

        // Rule 2: Observer chain detection (classic lag machine)
        if ("OBSERVER".equalsIgnoreCase(blockType)) {
            chunk.observerCount++;
            if (chunk.observerCount > MAX_OBSERVER_UPDATES_PER_CHUNK) {
                score += 35;
                reasons.add("OBSERVER_CHAIN: " + chunk.observerCount + " observers in chunk");
            }
        }

        // Rule 3: Entity spam in one area
        if (ENTITY_LAG_TYPES.contains(blockType.toUpperCase())) {
            chunk.entityCount++;
            if (chunk.entityCount > MAX_ENTITIES_PER_CHUNK) {
                score += 30;
                reasons.add("ENTITY_SPAM: " + chunk.entityCount + " lag entities in chunk");
            }
        }

        // Rule 4: TNT stacking (lag machine component)
        if ("TNT".equalsIgnoreCase(blockType)) {
            chunk.tntCount++;
            if (chunk.tntCount > MAX_TNT_PER_CHUNK) {
                score += 40;
                reasons.add("TNT_STACK: " + chunk.tntCount + " TNT in chunk");
            }
        }

        // Rule 5: Rapid placement by one player
        chunk.playerBlockCount.merge(playerName, 1, Integer::sum);
        int playerBlocks = chunk.playerBlockCount.getOrDefault(playerName, 0);
        if (playerBlocks > 50 && LAG_CAUSING_BLOCKS.contains(blockType.toUpperCase())) {
            score += 20;
            reasons.add("RAPID_LAG_BUILD: " + playerBlocks + " blocks by " + playerName);
        }

        // Rule 6: Falling block cascade (sand/gravel lag)
        if (blockType.toUpperCase().contains("SAND") || blockType.toUpperCase().contains("GRAVEL")
                || blockType.toUpperCase().contains("CONCRETE_POWDER")) {
            chunk.fallingBlockSupports++;
            if (chunk.fallingBlockSupports > MAX_FALLING_BLOCKS) {
                score += 30;
                reasons.add("FALLING_BLOCK_CASCADE: " + chunk.fallingBlockSupports);
            }
        }

        if (score >= 40) {
            flaggedPlayers.put(playerName, Instant.now().plusSeconds(FLAG_DURATION_SECONDS));
            LagEvent event = new LagEvent(Instant.now(), playerName, chunkKey, blockType, reasons);
            lagEvents.computeIfAbsent(playerName, k -> new ArrayList<>()).add(event);
            totalDetections.incrementAndGet();
            return LagCheckResult.flagged("Lag machine detected: " + String.join("; ", reasons));
        } else if (score >= 30) {
            return LagCheckResult.suspicious(score, reasons);
        }

        return LagCheckResult.clean();
    }

    public LagCheckResult checkChunkTPS(double chunkTPS, String chunkKey) {
        if (chunkTPS < 10.0) {
            ChunkActivity chunk = chunkActivity.get(chunkKey);
            if (chunk != null && chunk.lagBlockCount > 20) {
                totalDetections.incrementAndGet();
                return LagCheckResult.flagged("Low TPS chunk with high lag block density: " + chunkKey + " TPS=" + chunkTPS);
            }
        }
        return LagCheckResult.clean();
    }

    public Map<String, Object> getStatus() {
        Map<String, Object> status = new LinkedHashMap<>();
        status.put("totalDetections", totalDetections.get());
        status.put("trackedChunks", chunkActivity.size());
        status.put("flaggedPlayers", flaggedPlayers.size());

        List<Map<String, Object>> topLagChunks = new ArrayList<>();
        for (Map.Entry<String, ChunkActivity> e : chunkActivity.entrySet()) {
            ChunkActivity c = e.getValue();
            if (c.lagBlockCount > 10) {
                Map<String, Object> m = new LinkedHashMap<>();
                m.put("chunk", e.getKey());
                m.put("lagBlockCount", c.lagBlockCount);
                m.put("observerCount", c.observerCount);
                m.put("tntCount", c.tntCount);
                m.put("entityCount", c.entityCount);
                topLagChunks.add(m);
            }
        }
        topLagChunks.sort((a, b) -> (int) b.get("lagBlockCount") - (int) a.get("lagBlockCount"));
        status.put("topLagChunks", topLagChunks.subList(0, Math.min(topLagChunks.size(), 20)));

        List<Map<String, Object>> recent = new ArrayList<>();
        for (Map.Entry<String, List<LagEvent>> e : lagEvents.entrySet()) {
            for (LagEvent event : e.getValue()) {
                Map<String, Object> m = new LinkedHashMap<>();
                m.put("player", e.getKey());
                m.put("chunk", event.chunkKey);
                m.put("blockType", event.blockType);
                m.put("reasons", event.reasons);
                m.put("time", event.timestamp.toString());
                recent.add(m);
            }
        }
        recent.sort((a, b) -> b.get("time").toString().compareTo(a.get("time").toString()));
        status.put("recentDetections", recent.subList(0, Math.min(recent.size(), 20)));
        return status;
    }

    public long getTotalDetections() { return totalDetections.get(); }

    private void cleanupOldData() {
        Instant cutoff = Instant.now().minusSeconds(3600);
        chunkActivity.entrySet().removeIf(e -> e.getValue().lastActivity.isBefore(cutoff));
        flaggedPlayers.entrySet().removeIf(e -> e.getValue().isBefore(Instant.now()));
    }

    private static class ChunkActivity {
        int lagBlockCount;
        int observerCount;
        int tntCount;
        int entityCount;
        int fallingBlockSupports;
        final Map<String, Integer> playerBlockCount = new HashMap<>();
        Instant lastActivity = Instant.now();

        void recordBlockPlace(String blockType, String playerName) {
            lastActivity = Instant.now();
        }
    }

    private static class LagEvent {
        final Instant timestamp;
        final String playerName;
        final String chunkKey;
        final String blockType;
        final List<String> reasons;

        LagEvent(Instant timestamp, String playerName, String chunkKey, String blockType, List<String> reasons) {
            this.timestamp = timestamp;
            this.playerName = playerName;
            this.chunkKey = chunkKey;
            this.blockType = blockType;
            this.reasons = reasons;
        }
    }

    public static class LagCheckResult {
        private final boolean flagged;
        private final boolean suspicious;
        private final int score;
        private final List<String> reasons;

        private LagCheckResult(boolean flagged, boolean suspicious, int score, List<String> reasons) {
            this.flagged = flagged;
            this.suspicious = suspicious;
            this.score = score;
            this.reasons = reasons;
        }

        public static LagCheckResult clean() { return new LagCheckResult(false, false, 0, List.of()); }
        public static LagCheckResult suspicious(int score, List<String> reasons) { return new LagCheckResult(false, true, score, reasons); }
        public static LagCheckResult flagged(String msg) { return new LagCheckResult(true, true, 100, List.of(msg)); }

        public boolean isFlagged() { return flagged; }
        public boolean isSuspicious() { return suspicious; }
        public int getScore() { return score; }
        public List<String> getReasons() { return reasons; }
    }
}
