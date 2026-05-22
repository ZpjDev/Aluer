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
public class AntiGriefDetectionService {

    private final ServerGuardConfig config;

    private final Map<String, PlayerActivity> playerActivities = new ConcurrentHashMap<>();
    private final Map<String, List<GriefEvent>> griefEvents = new ConcurrentHashMap<>();
    private final Map<String, Instant> flaggedPlayers = new ConcurrentHashMap<>();
    private final ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor();
    private final AtomicLong totalGriefDetections = new AtomicLong(0);

    // Grief detection thresholds
    private static final int MAX_BLOCKS_BROKEN_PER_MINUTE = 150;
    private static final int MAX_BLOCKS_PLACED_PER_MINUTE = 200;
    private static final int MAX_ENTITIES_KILLED_PER_MINUTE = 30;
    private static final int MAX_CONTAINERS_OPENED_PER_MINUTE = 60;
    private static final int MAX_CHAT_MESSAGES_PER_MINUTE = 20;
    private static final int MAX_SIGN_CHANGES_PER_MINUTE = 10;
    private static final long ACTIVITY_WINDOW_MS = 60000;

    private static final Set<String> GRIEF_BLOCKS = Set.of(
            "TNT", "LAVA", "WATER", "FIRE", "RESPAWN_ANCHOR", "END_CRYSTAL",
            "BED", "OBSIDIAN", "WITHER_SKULL", "WITHER_SUMMON"
    );

    private static final Set<String> PROTECTED_CONTAINERS = Set.of(
            "CHEST", "ENDER_CHEST", "SHULKER_BOX", "BARREL", "FURNACE",
            "HOPPER", "DISPENSER", "DROPPER", "BREWING_STAND", "BEACON"
    );

    public AntiGriefDetectionService() {
        this(new ServerGuardConfig());
    }

    public AntiGriefDetectionService(ServerGuardConfig config) {
        this.config = config;
        scheduler.scheduleAtFixedRate(this::cleanupOldData, 120, 300, TimeUnit.SECONDS);
    }

    public GriefCheckResult checkBlockBreak(String playerName, String blockType, int x, int y, int z, String world) {
        if (!config.getSecurity().getSuperEvolution().isAntiGrief()) {
            return GriefCheckResult.clean();
        }

        PlayerActivity activity = playerActivities.computeIfAbsent(playerName, k -> new PlayerActivity());
        activity.recordBlockBreak(blockType, x, y, z, world);

        int score = 0;
        List<String> reasons = new ArrayList<>();

        // Check block break rate
        if (activity.blocksBrokenPerMinute > MAX_BLOCKS_BROKEN_PER_MINUTE) {
            score += 30;
            reasons.add("RAPID_BREAK: " + activity.blocksBrokenPerMinute + "/min");
        }

        // Grief blocks
        if (GRIEF_BLOCKS.contains(blockType.toUpperCase())) {
            score += 15;
            reasons.add("GRIEF_BLOCK: " + blockType);
        }

        // Check for grief patterns (breaking many blocks in a line = tunnel grief)
        if (activity.isTunneling(x, y, z)) {
            score += 20;
            reasons.add("TUNNEL_PATTERN");
        }

        // Check for container theft
        if (PROTECTED_CONTAINERS.contains(blockType.toUpperCase())) {
            score += 10;
            reasons.add("CONTAINER_ACCESS: " + blockType);
        }

        if (score >= 40) {
            return flagPlayer(playerName, "block_break", score, reasons);
        }

        return score > 0 ? GriefCheckResult.suspicious(score, reasons) : GriefCheckResult.clean();
    }

    public GriefCheckResult checkBlockPlace(String playerName, String blockType, int x, int y, int z, String world) {
        PlayerActivity activity = playerActivities.computeIfAbsent(playerName, k -> new PlayerActivity());
        activity.recordBlockPlace(blockType, x, y, z, world);

        int score = 0;
        List<String> reasons = new ArrayList<>();

        if (activity.blocksPlacedPerMinute > MAX_BLOCKS_PLACED_PER_MINUTE) {
            score += 25;
            reasons.add("RAPID_PLACE: " + activity.blocksPlacedPerMinute + "/min");
        }

        if (GRIEF_BLOCKS.contains(blockType.toUpperCase())) {
            score += 20;
            reasons.add("GRIEF_BLOCK_PLACED: " + blockType);
        }

        if (score >= 30) {
            return flagPlayer(playerName, "block_place", score, reasons);
        }

        return score > 0 ? GriefCheckResult.suspicious(score, reasons) : GriefCheckResult.clean();
    }

    public GriefCheckResult checkEntityKill(String playerName, String entityType, String world) {
        PlayerActivity activity = playerActivities.computeIfAbsent(playerName, k -> new PlayerActivity());
        activity.recordEntityKill(entityType);

        int score = 0;
        List<String> reasons = new ArrayList<>();

        if (activity.entitiesKilledPerMinute > MAX_ENTITIES_KILLED_PER_MINUTE) {
            score += 25;
            reasons.add("ENTITY_SLAUGHTER: " + activity.entitiesKilledPerMinute + "/min");
        }

        if (score >= 25) {
            return flagPlayer(playerName, "entity_kill", score, reasons);
        }

        return GriefCheckResult.clean();
    }

    public GriefCheckResult checkContainerOpen(String playerName, String containerType, int x, int y, int z) {
        PlayerActivity activity = playerActivities.computeIfAbsent(playerName, k -> new PlayerActivity());
        activity.recordContainerOpen(containerType);

        int score = 0;
        List<String> reasons = new ArrayList<>();

        if (activity.containersOpenedPerMinute > MAX_CONTAINERS_OPENED_PER_MINUTE) {
            score += 20;
            reasons.add("CONTAINER_SPAM: " + activity.containersOpenedPerMinute + "/min");
        }

        if (score >= 20) {
            return flagPlayer(playerName, "container_spam", score, reasons);
        }

        return GriefCheckResult.clean();
    }

    public GriefCheckResult checkChatSpam(String playerName, String message) {
        PlayerActivity activity = playerActivities.computeIfAbsent(playerName, k -> new PlayerActivity());
        activity.recordChatMessage();

        if (activity.chatMessagesPerMinute > MAX_CHAT_MESSAGES_PER_MINUTE) {
            return flagPlayer(playerName, "chat_spam",
                    30, List.of("CHAT_SPAM: " + activity.chatMessagesPerMinute + "/min"));
        }

        return GriefCheckResult.clean();
    }

    public void clearPlayer(String playerName) {
        playerActivities.remove(playerName);
        flaggedPlayers.remove(playerName);
    }

    public Map<String, Object> getStatus() {
        Map<String, Object> status = new LinkedHashMap<>();
        status.put("trackedPlayers", playerActivities.size());
        status.put("flaggedPlayers", flaggedPlayers.size());
        status.put("totalGriefDetections", totalGriefDetections.get());

        List<Map<String, Object>> flagged = new ArrayList<>();
        for (Map.Entry<String, Instant> e : flaggedPlayers.entrySet()) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("player", e.getKey());
            m.put("flaggedUntil", e.getValue().toString());
            List<GriefEvent> events = griefEvents.get(e.getKey());
            if (events != null && !events.isEmpty()) {
                GriefEvent last = events.get(events.size() - 1);
                m.put("lastReason", last.reasons);
                m.put("lastScore", last.score);
            }
            PlayerActivity act = playerActivities.get(e.getKey());
            if (act != null) {
                m.put("blocksBrokenPerMinute", act.blocksBrokenPerMinute);
                m.put("blocksPlacedPerMinute", act.blocksPlacedPerMinute);
            }
            flagged.add(m);
        }
        status.put("flaggedPlayersList", flagged);
        return status;
    }

    public long getTotalGriefDetections() { return totalGriefDetections.get(); }

    private GriefCheckResult flagPlayer(String playerName, String actionType, int score, List<String> reasons) {
        GriefEvent event = new GriefEvent(Instant.now(), playerName, actionType, score, reasons);
        griefEvents.computeIfAbsent(playerName, k -> new ArrayList<>()).add(event);
        flaggedPlayers.put(playerName, Instant.now().plusSeconds(1800));
        totalGriefDetections.incrementAndGet();
        return GriefCheckResult.flagged(score, reasons);
    }

    private void cleanupOldData() {
        Instant cutoff = Instant.now().minusSeconds(3600);
        playerActivities.entrySet().removeIf(e -> {
            e.getValue().cleanupOldEvents(cutoff);
            return e.getValue().isEmpty();
        });
        flaggedPlayers.entrySet().removeIf(e -> e.getValue().isBefore(Instant.now()));
    }

    private static class PlayerActivity {
        final List<TimedEvent> blockBreaks = new ArrayList<>();
        final List<TimedEvent> blockPlaces = new ArrayList<>();
        final List<TimedEvent> entityKills = new ArrayList<>();
        final List<TimedEvent> containerOpens = new ArrayList<>();
        final List<TimedEvent> chatMessages = new ArrayList<>();

        int blocksBrokenPerMinute;
        int blocksPlacedPerMinute;
        int entitiesKilledPerMinute;
        int containersOpenedPerMinute;
        int chatMessagesPerMinute;

        private int lastBreakX, lastBreakY, lastBreakZ;

        void recordBlockBreak(String type, int x, int y, int z, String world) {
            blockBreaks.add(new TimedEvent(Instant.now(), type, x, y, z));
            lastBreakX = x; lastBreakY = y; lastBreakZ = z;
            updateRates();
        }

        void recordBlockPlace(String type, int x, int y, int z, String world) {
            blockPlaces.add(new TimedEvent(Instant.now(), type, x, y, z));
            updateRates();
        }

        void recordEntityKill(String type) {
            entityKills.add(new TimedEvent(Instant.now(), type, 0, 0, 0));
            updateRates();
        }

        void recordContainerOpen(String type) {
            containerOpens.add(new TimedEvent(Instant.now(), type, 0, 0, 0));
            updateRates();
        }

        void recordChatMessage() {
            chatMessages.add(new TimedEvent(Instant.now(), "", 0, 0, 0));
            updateRates();
        }

        boolean isTunneling(int x, int y, int z) {
            return Math.abs(x - lastBreakX) <= 1 && Math.abs(y - lastBreakY) <= 1
                    && Math.abs(z - lastBreakZ) <= 1 && blockBreaks.size() > 20;
        }

        void updateRates() {
            long cutoff = System.currentTimeMillis() - ACTIVITY_WINDOW_MS;
            blocksBrokenPerMinute = (int) blockBreaks.stream().filter(e -> e.time.toEpochMilli() > cutoff).count();
            blocksPlacedPerMinute = (int) blockPlaces.stream().filter(e -> e.time.toEpochMilli() > cutoff).count();
            entitiesKilledPerMinute = (int) entityKills.stream().filter(e -> e.time.toEpochMilli() > cutoff).count();
            containersOpenedPerMinute = (int) containerOpens.stream().filter(e -> e.time.toEpochMilli() > cutoff).count();
            chatMessagesPerMinute = (int) chatMessages.stream().filter(e -> e.time.toEpochMilli() > cutoff).count();
        }

        void cleanupOldEvents(Instant cutoff) {
            blockBreaks.removeIf(e -> e.time.isBefore(cutoff));
            blockPlaces.removeIf(e -> e.time.isBefore(cutoff));
            entityKills.removeIf(e -> e.time.isBefore(cutoff));
            containerOpens.removeIf(e -> e.time.isBefore(cutoff));
            chatMessages.removeIf(e -> e.time.isBefore(cutoff));
        }

        boolean isEmpty() {
            return blockBreaks.isEmpty() && blockPlaces.isEmpty() && entityKills.isEmpty()
                    && containerOpens.isEmpty() && chatMessages.isEmpty();
        }
    }

    private static class TimedEvent {
        final Instant time;
        final String type;
        final int x, y, z;

        TimedEvent(Instant time, String type, int x, int y, int z) {
            this.time = time;
            this.type = type;
            this.x = x;
            this.y = y;
            this.z = z;
        }
    }

    private static class GriefEvent {
        final Instant timestamp;
        final String playerName;
        final String actionType;
        final int score;
        final List<String> reasons;

        GriefEvent(Instant timestamp, String playerName, String actionType, int score, List<String> reasons) {
            this.timestamp = timestamp;
            this.playerName = playerName;
            this.actionType = actionType;
            this.score = score;
            this.reasons = reasons;
        }
    }

    public static class GriefCheckResult {
        private final boolean flagged;
        private final boolean suspicious;
        private final int score;
        private final List<String> reasons;

        private GriefCheckResult(boolean flagged, boolean suspicious, int score, List<String> reasons) {
            this.flagged = flagged;
            this.suspicious = suspicious;
            this.score = score;
            this.reasons = reasons;
        }

        public static GriefCheckResult clean() { return new GriefCheckResult(false, false, 0, List.of()); }
        public static GriefCheckResult suspicious(int score, List<String> reasons) {
            return new GriefCheckResult(false, true, score, reasons);
        }
        public static GriefCheckResult flagged(int score, List<String> reasons) {
            return new GriefCheckResult(true, true, score, reasons);
        }

        public boolean isFlagged() { return flagged; }
        public boolean isSuspicious() { return suspicious; }
        public int getScore() { return score; }
        public List<String> getReasons() { return reasons; }
    }
}
