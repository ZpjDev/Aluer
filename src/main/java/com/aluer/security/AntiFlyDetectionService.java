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
public class AntiFlyDetectionService {

    private final ServerGuardConfig config;

    private final Map<String, PlayerMovementData> movementData = new ConcurrentHashMap<>();
    private final Map<String, Instant> flaggedPlayers = new ConcurrentHashMap<>();
    private final ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor();
    private final AtomicLong totalDetections = new AtomicLong(0);

    private static final double MAX_VERTICAL_SPEED = 0.42;
    private static final double MAX_HORIZONTAL_SPEED_SURVIVAL = 9.0;
    private static final double MAX_HORIZONTAL_SPEED_CREATIVE = 15.0;
    private static final double MAX_VERTICAL_SPEED_ELYTRA = 3.0;
    private static final int MAX_CONSECUTIVE_AIR_TICKS = 20;
    private static final double IMPOSSIBLE_Y_CHANGE = 5.0;
    private static final int MOVEMENT_BUFFER_SIZE = 100;
    private static final int MIN_MOVEMENTS_FOR_ANALYSIS = 20;
    private static final long FLAG_DURATION_SECONDS = 3600;

    public AntiFlyDetectionService() {
        this(new ServerGuardConfig());
    }

    public AntiFlyDetectionService(ServerGuardConfig config) {
        this.config = config;
        scheduler.scheduleAtFixedRate(this::cleanupOldData, 120, 300, TimeUnit.SECONDS);
    }

    public FlyCheckResult checkMovement(String playerName, double fromX, double fromY, double fromZ,
                                        double toX, double toY, double toZ, boolean onGround, String gameMode) {
        if (!config.getSecurity().getSuperEvolution().isAntiFly()) {
            return FlyCheckResult.clean();
        }

        if (flaggedPlayers.containsKey(playerName)) {
            if (Instant.now().isAfter(flaggedPlayers.get(playerName))) {
                flaggedPlayers.remove(playerName);
            } else {
                return FlyCheckResult.flagged("Player is flagged for movement hacks");
            }
        }

        PlayerMovementData data = movementData.computeIfAbsent(playerName, k -> new PlayerMovementData());
        data.recordMovement(fromX, fromY, fromZ, toX, toY, toZ, onGround);

        int score = 0;
        List<String> reasons = new ArrayList<>();

        double dx = toX - fromX;
        double dy = toY - fromY;
        double dz = toZ - fromZ;
        double horizontalDist = Math.sqrt(dx * dx + dz * dz);
        double verticalSpeed = Math.abs(dy);

        // Rule 1: Impossible vertical movement (no fall + rapid rise, not elytra)
        boolean isCreative = "creative".equalsIgnoreCase(gameMode) || "spectator".equalsIgnoreCase(gameMode);
        if (!onGround && !isCreative && verticalSpeed > MAX_VERTICAL_SPEED * 3 && dy > 3.0) {
            score += 35;
            reasons.add("IMPOSSIBLE_VERTICAL: " + String.format("%.2f", verticalSpeed) + " blocks/tick (no ground)");
        }

        // Rule 2: Excessive horizontal speed
        double gameModeLimit = "creative".equalsIgnoreCase(gameMode) || "spectator".equalsIgnoreCase(gameMode)
                ? MAX_HORIZONTAL_SPEED_CREATIVE : MAX_HORIZONTAL_SPEED_SURVIVAL;
        if (horizontalDist > gameModeLimit) {
            score += 35;
            reasons.add("EXCESSIVE_HORIZONTAL: " + String.format("%.2f", horizontalDist) + " blocks/tick");
        }

        // Rule 3: Sustained air time (flying without elytra)
        if (!onGround) {
            data.consecutiveAirTicks++;
            if (data.consecutiveAirTicks > MAX_CONSECUTIVE_AIR_TICKS && verticalSpeed < 0.1 && verticalSpeed > -0.5) {
                score += 25;
                reasons.add("SUSTAINED_AIR: " + data.consecutiveAirTicks + " ticks");
            }
        } else {
            data.consecutiveAirTicks = 0;
        }

        // Rule 4: No fall damage (anti-knockback/anti-fall)
        if (!onGround && dy < -IMPOSSIBLE_Y_CHANGE && !data.prevOnGround) {
            data.freefallDistance += Math.abs(dy);
        }
        if (onGround && data.freefallDistance > 10) {
            score += 20;
            reasons.add("NO_FALL_DAMAGE: fell " + String.format("%.1f", data.freefallDistance) + " blocks");
            data.freefallDistance = 0;
        }

        // Rule 5: Phase detection (moving through blocks)
        if (data.totalMovements > MIN_MOVEMENTS_FOR_ANALYSIS) {
            double avgSpeed = data.totalDistance / Math.max(1, data.totalMovements);
            if (avgSpeed > MAX_HORIZONTAL_SPEED_SURVIVAL * 1.5 && !"creative".equalsIgnoreCase(gameMode)) {
                score += 15;
                reasons.add("HIGH_AVERAGE_SPEED: " + String.format("%.2f", avgSpeed) + " avg");
            }
        }

        // Rule 6: Teleport detection
        if (horizontalDist > 50 && "survival".equalsIgnoreCase(gameMode)) {
            score += 40;
            reasons.add("TELEPORT_DETECTED: " + String.format("%.1f", horizontalDist) + " blocks");
        }

        if (score >= 35) {
            flaggedPlayers.put(playerName, Instant.now().plusSeconds(FLAG_DURATION_SECONDS));
            totalDetections.incrementAndGet();
            return FlyCheckResult.flagged("Movement hack detected: " + String.join("; ", reasons));
        } else if (score >= 30) {
            return FlyCheckResult.suspicious(score, reasons);
        }

        return FlyCheckResult.clean();
    }

    public void clearPlayer(String playerName) {
        movementData.remove(playerName);
        flaggedPlayers.remove(playerName);
    }

    public Map<String, Object> getStatus() {
        Map<String, Object> status = new LinkedHashMap<>();
        status.put("trackedPlayers", movementData.size());
        status.put("flaggedPlayers", flaggedPlayers.size());
        status.put("totalDetections", totalDetections.get());

        List<Map<String, Object>> topSuspicious = new ArrayList<>();
        for (Map.Entry<String, PlayerMovementData> e : movementData.entrySet()) {
            PlayerMovementData d = e.getValue();
            double avgSpeed = d.totalMovements > 0 ? d.totalDistance / d.totalMovements : 0;
            if (avgSpeed > 1.0 || d.consecutiveAirTicks > 10) {
                Map<String, Object> m = new LinkedHashMap<>();
                m.put("player", e.getKey());
                m.put("avgSpeed", String.format("%.2f", avgSpeed));
                m.put("airTicks", d.consecutiveAirTicks);
                m.put("totalMovements", d.totalMovements);
                topSuspicious.add(m);
            }
        }
        topSuspicious.sort((a, b) -> {
            double sa = Double.parseDouble(a.get("avgSpeed").toString());
            double sb = Double.parseDouble(b.get("avgSpeed").toString());
            return Double.compare(sb, sa);
        });
        status.put("suspiciousPlayers", topSuspicious.subList(0, Math.min(topSuspicious.size(), 20)));
        return status;
    }

    public long getTotalDetections() { return totalDetections.get(); }

    private void cleanupOldData() {
        Instant cutoff = Instant.now().minusSeconds(600);
        movementData.entrySet().removeIf(e -> e.getValue().lastActivity.isBefore(cutoff));
        flaggedPlayers.entrySet().removeIf(e -> e.getValue().isBefore(Instant.now()));
    }

    private static class PlayerMovementData {
        int totalMovements;
        double totalDistance;
        int consecutiveAirTicks;
        double freefallDistance;
        boolean prevOnGround;
        Instant lastActivity = Instant.now();

        void recordMovement(double fx, double fy, double fz, double tx, double ty, double tz, boolean onGround) {
            totalMovements++;
            totalDistance += Math.sqrt(Math.pow(tx - fx, 2) + Math.pow(ty - fy, 2) + Math.pow(tz - fz, 2));
            lastActivity = Instant.now();
            prevOnGround = onGround;
        }
    }

    public static class FlyCheckResult {
        private final boolean flagged;
        private final boolean suspicious;
        private final int score;
        private final List<String> reasons;

        private FlyCheckResult(boolean flagged, boolean suspicious, int score, List<String> reasons) {
            this.flagged = flagged;
            this.suspicious = suspicious;
            this.score = score;
            this.reasons = reasons;
        }

        public static FlyCheckResult clean() { return new FlyCheckResult(false, false, 0, List.of()); }
        public static FlyCheckResult suspicious(int score, List<String> reasons) { return new FlyCheckResult(false, true, score, reasons); }
        public static FlyCheckResult flagged(String msg) { return new FlyCheckResult(true, true, 100, List.of(msg)); }

        public boolean isFlagged() { return flagged; }
        public boolean isSuspicious() { return suspicious; }
        public int getScore() { return score; }
        public List<String> getReasons() { return reasons; }
    }
}
