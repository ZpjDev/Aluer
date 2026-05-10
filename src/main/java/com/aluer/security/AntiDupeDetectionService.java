package com.aluer.security;

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
public class AntiDupeDetectionService {

    private final ServerGuardConfig config;

    private final Map<String, PlayerInventorySnapshot> inventorySnapshots = new ConcurrentHashMap<>();
    private final Map<String, List<DupeEvent>> dupeEvents = new ConcurrentHashMap<>();
    private final Map<String, Instant> flaggedPlayers = new ConcurrentHashMap<>();
    private final ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor();
    private final AtomicLong totalDetections = new AtomicLong(0);

    private static final int MAX_ITEM_STACK_SIZE = 64;
    private static final int MAX_SHULKER_ITEMS = 27;
    private static final int MAX_DIAMOND_STACK = 64;
    private static final int MAX_NETHERITE_STACK = 64;
    private static final int MAX_TOTEM_STACK = 1;
    private static final long FLAG_DURATION_SECONDS = 7200;

    private static final Set<String> HIGH_VALUE_ITEMS = Set.of(
            "DIAMOND", "DIAMOND_BLOCK", "NETHERITE_INGOT", "NETHERITE_BLOCK",
            "NETHERITE_SCRAP", "ANCIENT_DEBRIS", "EMERALD", "EMERALD_BLOCK",
            "TOTEM_OF_UNDYING", "ELYTRA", "BEACON", "NETHER_STAR",
            "ENCHANTED_GOLDEN_APPLE", "DRAGON_EGG", "TRIDENT",
            "SHULKER_SHELL", "ENDER_PEARL", "BLAZE_ROD", "GUNPOWDER"
    );

    private static final Set<DupeMethod> KNOWN_DUPE_METHODS = new HashSet<>();
    static {
        KNOWN_DUPE_METHODS.add(new DupeMethod("BOOK_DUPE", "Book and quill crafting dupe", 85));
        KNOWN_DUPE_METHODS.add(new DupeMethod("DONKEY_DUPE", "Donkey/llama chest dupe", 90));
        KNOWN_DUPE_METHODS.add(new DupeMethod("ENDER_CHEST_DUPE", "Ender chest rapid open/close dupe", 80));
        KNOWN_DUPE_METHODS.add(new DupeMethod("PORTAL_DUPE", "Nether/End portal item dupe", 75));
        KNOWN_DUPE_METHODS.add(new DupeMethod("SHULKER_DUPE", "Shulker box stacking dupe", 90));
        KNOWN_DUPE_METHODS.add(new DupeMethod("DISPENSER_DUPE", "Dispenser/dropper dupe", 70));
        KNOWN_DUPE_METHODS.add(new DupeMethod("CHEST_BOAT_DUPE", "Chest boat item transfer dupe", 75));
        KNOWN_DUPE_METHODS.add(new DupeMethod("PISTON_DUPE", "Piston-based duplication", 80));
        KNOWN_DUPE_METHODS.add(new DupeMethod("ITEM_FRAME_DUPE", "Item frame duplication glitch", 85));
    }

    public AntiDupeDetectionService() {
        this(new ServerGuardConfig());
    }

    public AntiDupeDetectionService(ServerGuardConfig config) {
        this.config = config;
        scheduler.scheduleAtFixedRate(this::cleanupOldData, 300, 600, TimeUnit.SECONDS);
    }

    public DupeCheckResult checkInventoryChange(String playerName, String itemType, int newCount, int oldCount,
                                                 String containerType, int x, int y, int z) {
        if (!config.getSecurity().getSuperEvolution().isAntiDupe()) {
            return DupeCheckResult.clean();
        }

        if (flaggedPlayers.containsKey(playerName)) {
            if (Instant.now().isAfter(flaggedPlayers.get(playerName))) {
                flaggedPlayers.remove(playerName);
            } else {
                return DupeCheckResult.flagged("Player is flagged for duplication");
            }
        }

        int score = 0;
        List<String> reasons = new ArrayList<>();

        // Rule 1: Stack size violation
        int maxStack = getMaxStackSize(itemType);
        if (newCount > maxStack && !isShulkerBox(containerType)) {
            score += 40;
            reasons.add("STACK_OVERFLOW: " + itemType + " count=" + newCount + " (max=" + maxStack + ")");
        }

        // Rule 2: Rapid high-value item gain
        int gain = newCount - oldCount;
        if (gain > 0 && HIGH_VALUE_ITEMS.contains(itemType.toUpperCase())) {
            PlayerInventorySnapshot snap = inventorySnapshots.computeIfAbsent(playerName, k -> new PlayerInventorySnapshot());
            snap.recordGain(itemType, gain);

            if (snap.recentHighValueGain > 100) {
                score += 35;
                reasons.add("MASS_GAIN: " + snap.recentHighValueGain + " high-value items gained");
            }
        }

        // Rule 3: Impossible inventory transition
        if (newCount > oldCount * 3 && oldCount > 0 && newCount > 500) {
            score += 30;
            reasons.add("IMPOSSIBLE_INCREASE: " + itemType + " " + oldCount + " -> " + newCount);
        }

        // Rule 4: Container interaction frequency (dupe method indicator)
        PlayerInventorySnapshot snap = inventorySnapshots.computeIfAbsent(playerName, k -> new PlayerInventorySnapshot());
        snap.recordContainerOpen(containerType);
        if (snap.containerOpensPerMinute > 30) {
            score += 20;
            reasons.add("CONTAINER_SPAM: " + snap.containerOpensPerMinute + "/min");
        }

        // Rule 5: Netherite/Ancient Debris gain without mining (possible creative/give bypass)
        if (("NETHERITE_INGOT".equalsIgnoreCase(itemType) || "NETHERITE_BLOCK".equalsIgnoreCase(itemType)) && gain >= 64) {
            score += 50;
            reasons.add("NETHERITE_SURGE: +" + gain + " " + itemType);
        }

        if (score >= 40) {
            flaggedPlayers.put(playerName, Instant.now().plusSeconds(FLAG_DURATION_SECONDS));
            DupeEvent event = new DupeEvent(Instant.now(), playerName, itemType, oldCount, newCount, containerType, reasons);
            dupeEvents.computeIfAbsent(playerName, k -> new ArrayList<>()).add(event);
            totalDetections.incrementAndGet();
            return DupeCheckResult.flagged("Duplication detected: " + String.join("; ", reasons));
        } else if (score >= 25) {
            return DupeCheckResult.suspicious(score, reasons);
        }

        return DupeCheckResult.clean();
    }

    public DupeCheckResult checkItemDropPickup(String playerName, String itemType, int itemCount, double pickupTimeSeconds) {
        int score = 0;
        List<String> reasons = new ArrayList<>();

        // Extremely rapid pickup cycle (classic dupe pattern)
        if (pickupTimeSeconds < 0.05 && itemCount > 1000) {
            score += 40;
            reasons.add("RAPID_PICKUP_CYCLE: " + itemCount + " " + itemType + " in " + pickupTimeSeconds + "s");
        }

        if (itemCount > 10000) {
            score += 50;
            reasons.add("MASS_DUMP: " + itemCount + " " + itemType);
        }

        if (score >= 40) {
            totalDetections.incrementAndGet();
            flaggedPlayers.put(playerName, Instant.now().plusSeconds(FLAG_DURATION_SECONDS));
            return DupeCheckResult.flagged("Suspicious item pickup: " + String.join("; ", reasons));
        }
        return DupeCheckResult.clean();
    }

    public void clearPlayer(String playerName) {
        inventorySnapshots.remove(playerName);
        flaggedPlayers.remove(playerName);
    }

    public Map<String, Object> getStatus() {
        Map<String, Object> status = new LinkedHashMap<>();
        status.put("trackedPlayers", inventorySnapshots.size());
        status.put("flaggedPlayers", flaggedPlayers.size());
        status.put("totalDetections", totalDetections.get());
        status.put("knownDupeMethods", KNOWN_DUPE_METHODS.size());

        List<Map<String, Object>> recent = new ArrayList<>();
        for (Map.Entry<String, List<DupeEvent>> e : dupeEvents.entrySet()) {
            for (DupeEvent event : e.getValue()) {
                Map<String, Object> m = new LinkedHashMap<>();
                m.put("player", e.getKey());
                m.put("item", event.itemType);
                m.put("oldCount", event.oldCount);
                m.put("newCount", event.newCount);
                m.put("container", event.containerType);
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

    private int getMaxStackSize(String itemType) {
        if (itemType == null) return MAX_ITEM_STACK_SIZE;
        String upper = itemType.toUpperCase();
        if (upper.contains("TOTEM")) return MAX_TOTEM_STACK;
        if (upper.contains("PICKAXE") || upper.contains("SWORD") || upper.contains("AXE")
                || upper.contains("SHOVEL") || upper.contains("HOE")) return 1;
        if (upper.contains("BOOTS") || upper.contains("CHESTPLATE") || upper.contains("HELMET")
                || upper.contains("LEGGINGS") || upper.contains("ELYTRA")) return 1;
        if (upper.contains("BUCKET") || upper.contains("POTION") || upper.contains("BED")) return 1;
        return MAX_ITEM_STACK_SIZE;
    }

    private boolean isShulkerBox(String containerType) {
        return containerType != null && containerType.toUpperCase().contains("SHULKER");
    }

    private void cleanupOldData() {
        Instant cutoff = Instant.now().minusSeconds(1200);
        inventorySnapshots.entrySet().removeIf(e -> e.getValue().lastActivity.isBefore(cutoff));
        flaggedPlayers.entrySet().removeIf(e -> e.getValue().isBefore(Instant.now()));
    }

    private static class PlayerInventorySnapshot {
        int containerOpensPerMinute;
        int recentHighValueGain;
        Instant lastActivity = Instant.now();
        Instant minuteStart = Instant.now();

        void recordGain(String item, int gain) {
            lastActivity = Instant.now();
            if (HIGH_VALUE_ITEMS.contains(item.toUpperCase())) {
                recentHighValueGain += gain;
            }
            if (Instant.now().isAfter(minuteStart.plusSeconds(60))) {
                containerOpensPerMinute = 0;
                recentHighValueGain = 0;
                minuteStart = Instant.now();
            }
        }

        void recordContainerOpen(String container) {
            containerOpensPerMinute++;
            lastActivity = Instant.now();
        }
    }

    private static class DupeEvent {
        final Instant timestamp;
        final String playerName;
        final String itemType;
        final int oldCount;
        final int newCount;
        final String containerType;
        final List<String> reasons;

        DupeEvent(Instant timestamp, String playerName, String itemType, int oldCount, int newCount,
                  String containerType, List<String> reasons) {
            this.timestamp = timestamp;
            this.playerName = playerName;
            this.itemType = itemType;
            this.oldCount = oldCount;
            this.newCount = newCount;
            this.containerType = containerType;
            this.reasons = reasons;
        }
    }

    private static class DupeMethod {
        final String name;
        final String description;
        final int severity;

        DupeMethod(String name, String description, int severity) {
            this.name = name;
            this.description = description;
            this.severity = severity;
        }
    }

    public static class DupeCheckResult {
        private final boolean flagged;
        private final boolean suspicious;
        private final int score;
        private final List<String> reasons;

        private DupeCheckResult(boolean flagged, boolean suspicious, int score, List<String> reasons) {
            this.flagged = flagged;
            this.suspicious = suspicious;
            this.score = score;
            this.reasons = reasons;
        }

        public static DupeCheckResult clean() { return new DupeCheckResult(false, false, 0, List.of()); }
        public static DupeCheckResult suspicious(int score, List<String> reasons) { return new DupeCheckResult(false, true, score, reasons); }
        public static DupeCheckResult flagged(String msg) { return new DupeCheckResult(true, true, 100, List.of(msg)); }

        public boolean isFlagged() { return flagged; }
        public boolean isSuspicious() { return suspicious; }
        public int getScore() { return score; }
        public List<String> getReasons() { return reasons; }
    }
}
