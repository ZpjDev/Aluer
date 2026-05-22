package com.aluer.anticheat.player;

import com.aluer.config.ServerGuardConfig;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;

@Service
public class AntiSkinSpoofService {

    private final ServerGuardConfig config;

    private final Map<String, List<Long>> skinChangeTimestamps = new ConcurrentHashMap<>();
    private final Map<String, String> lastKnownSkinHash = new ConcurrentHashMap<>();
    private final Map<String, Integer> spoofScoreByPlayer = new ConcurrentHashMap<>();

    private final AtomicLong totalChecks = new AtomicLong(0);
    private final AtomicLong spoofsDetected = new AtomicLong(0);
    private final AtomicLong knownImpersonators = new AtomicLong(0);
    private final AtomicLong suspiciousCount = new AtomicLong(0);

    private final ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor();

    // Known impersonation targets (famous Minecraft personalities)
    private static final Set<String> KNOWN_IMPERSONATION_TARGETS = Set.of(
            "Dream", "Technoblade", "TommyInnit", "GeorgeNotFound", "Sapnap",
            "Punz", "BadBoyHalo", "Philza", "WilburSoot", "Ranboo",
            "Tubbo", "CaptainPuffy", "Awesamdude", "Quackity", "KarlJacobs",
            "NikiNihachu", "Fundy", "Eret", "Hbomb94", "Antfrost",
            "Notch", "Jeb_", "Dinnerbone", "Mojang", "Herobrine"
    );

    // Known cheat client skin hashes (example patterns)
    private static final Set<String> KNOWN_CHEAT_SKIN_PREFIXES = Set.of(
            "deadbeef", "cafebabe", "0badc0de", "1337c0d3"
    );

    // Suspicious URL patterns
    private static final List<String> SUSPICIOUS_URL_PATTERNS = List.of(
            "data:", "localhost", "127.0.0.1", "0.0.0.0",
            "discord", "mediafire", "mega.nz", "dropbox",
            "pastebin", "gyazo", "imgur", "prnt.sc"
    );

    private static final String MOJANG_SKIN_URL_PREFIX = "http://textures.minecraft.net/texture/";
    private static final String MOJANG_SKIN_URL_HTTPS = "https://textures.minecraft.net/texture/";

    private static final int MAX_SKIN_CHANGES_IN_5MIN = 3;
    private static final int MAX_SKIN_CHANGES_IN_1HOUR = 10;
    private static final int SPOOF_SCORE_THRESHOLD = 60;

    public AntiSkinSpoofService() {
        this(new ServerGuardConfig());
    }

    @Autowired
    public AntiSkinSpoofService(ServerGuardConfig config) {
        this.config = config;
        scheduler.scheduleAtFixedRate(this::cleanupStale, 300, 300, TimeUnit.SECONDS);
    }

    public SkinSpoofResult checkSkin(String playerName, String skinUrl, String modelType, String skinHash) {
        if (!config.getSecurity().getSuperEvolution().isAntiSkinSpoof()) {
            return SkinSpoofResult.clean();
        }

        totalChecks.incrementAndGet();
        long now = System.currentTimeMillis();
        List<String> reasons = new ArrayList<>();
        int score = 0;

        // 1. Null/invalid skin detection
        if (skinUrl == null || skinUrl.isEmpty() || skinHash == null || skinHash.isEmpty()) {
            score += 20;
            reasons.add("NULL_SKIN: Missing skin data");
        }

        // 2. Suspicious skin URL detection
        if (skinUrl != null && isSuspiciousUrl(skinUrl)) {
            score += 25;
            reasons.add("SUSPICIOUS_URL: " + skinUrl);
        }

        // 3. Non-Mojang URL detection
        if (skinUrl != null && !skinUrl.isEmpty()
                && !skinUrl.startsWith(MOJANG_SKIN_URL_PREFIX)
                && !skinUrl.startsWith(MOJANG_SKIN_URL_HTTPS)) {
            score += 15;
            reasons.add("NON_MOJANG_URL: " + skinUrl);
        }

        // 4. Known cheat client skin
        if (skinHash != null && isKnownCheatSkinHash(skinHash)) {
            score += 30;
            reasons.add("CHEAT_CLIENT_SKIN_HASH: " + skinHash);
        }

        // 5. Skin change frequency monitoring
        List<Long> changes = skinChangeTimestamps.computeIfAbsent(playerName, k -> new CopyOnWriteArrayList<>());
        changes.add(now);

        long cutoff5Min = now - (5 * 60 * 1000L);
        long recent5Min = changes.stream().filter(t -> t > cutoff5Min).count();
        if (recent5Min > MAX_SKIN_CHANGES_IN_5MIN) {
            score += 20;
            reasons.add("RAPID_CHANGE_5MIN: " + recent5Min + " changes in 5 minutes");
        }

        long cutoff1Hour = now - (60 * 60 * 1000L);
        long recent1Hour = changes.stream().filter(t -> t > cutoff1Hour).count();
        if (recent1Hour > MAX_SKIN_CHANGES_IN_1HOUR) {
            score += 15;
            reasons.add("RAPID_CHANGE_1HOUR: " + recent1Hour + " changes in 1 hour");
        }

        // 6. Known impersonation target
        if (skinHash != null && isKnownImpersonationSkin(playerName, skinHash)) {
            score += 35;
            reasons.add("IMPERSONATION: Skin matches known personality " + playerName);
            knownImpersonators.incrementAndGet();
        }

        // 7. Slim vs Classic model mismatch (some hacked clients use wrong model)
        if (modelType != null && skinHash != null) {
            String lastHash = lastKnownSkinHash.get(playerName);
            if (lastHash != null && !lastHash.equals(skinHash)) {
                // hash changed but model type might be incorrect
                if ("slim".equalsIgnoreCase(modelType)) {
                    score += 10;
                    reasons.add("MODEL_SWITCH_SLIM: Possible spoofed slim model");
                }
            }
        }

        if (skinHash != null) {
            lastKnownSkinHash.put(playerName, skinHash);
        }

        // Cumulative spoof score
        int existingScore = spoofScoreByPlayer.getOrDefault(playerName, 0);
        spoofScoreByPlayer.put(playerName, existingScore + score);

        // Determine result
        if (score >= SPOOF_SCORE_THRESHOLD || (existingScore + score) >= SPOOF_SCORE_THRESHOLD) {
            spoofsDetected.incrementAndGet();
            return SkinSpoofResult.spoofed(reasons);
        }

        if (score > 0) {
            suspiciousCount.incrementAndGet();
            return SkinSpoofResult.suspicious(reasons);
        }

        return SkinSpoofResult.clean();
    }

    public void resetPlayer(String playerName) {
        skinChangeTimestamps.remove(playerName);
        lastKnownSkinHash.remove(playerName);
        spoofScoreByPlayer.remove(playerName);
    }

    public Map<String, Object> getStatus() {
        Map<String, Object> status = new LinkedHashMap<>();
        status.put("totalChecks", totalChecks.get());
        status.put("spoofsDetected", spoofsDetected.get());
        status.put("knownImpersonators", knownImpersonators.get());
        status.put("suspiciousCount", suspiciousCount.get());
        status.put("trackedPlayers", skinChangeTimestamps.size());
        status.put("configEnabled", config.getSecurity().getSuperEvolution().isAntiSkinSpoof());
        return status;
    }

    private boolean isSuspiciousUrl(String url) {
        if (url.startsWith("data:")) return true;
        String lower = url.toLowerCase();
        for (String pattern : SUSPICIOUS_URL_PATTERNS) {
            if (lower.contains(pattern)) return true;
        }
        return false;
    }

    private boolean isKnownCheatSkinHash(String hash) {
        if (hash == null) return false;
        String lower = hash.toLowerCase();
        for (String prefix : KNOWN_CHEAT_SKIN_PREFIXES) {
            if (lower.startsWith(prefix)) return true;
        }
        return false;
    }

    private boolean isKnownImpersonationSkin(String playerName, String skinHash) {
        // Check if the player name (lowercased) matches a known target
        // but the skin data is suspicious — flag it
        if (playerName == null) return false;
        for (String target : KNOWN_IMPERSONATION_TARGETS) {
            if (playerName.equalsIgnoreCase(target)) {
                // Player is using the exact name of a famous personality
                return true;
            }
            // Also detect impersonation-like names (e.g., "Dream_", "Notch123")
            String lowerName = playerName.toLowerCase();
            String lowerTarget = target.toLowerCase();
            if (lowerName.contains(lowerTarget) && !lowerName.equals(lowerTarget)) {
                return true;
            }
        }
        return false;
    }

    private void cleanupStale() {
        long cutoff = System.currentTimeMillis() - (2 * 60 * 60 * 1000L); // 2 hours
        skinChangeTimestamps.entrySet().removeIf(e -> {
            e.getValue().removeIf(t -> t < cutoff);
            return e.getValue().isEmpty();
        });
        // Also clear spoof scores for inactive players
        spoofScoreByPlayer.entrySet().removeIf(e -> !skinChangeTimestamps.containsKey(e.getKey()));
    }

    // -- SkinSpoofResult --
    public static class SkinSpoofResult {
        private final boolean clean;
        private final boolean suspicious;
        private final boolean spoofed;
        private final List<String> reasons;

        private SkinSpoofResult(boolean clean, boolean suspicious, boolean spoofed, List<String> reasons) {
            this.clean = clean;
            this.suspicious = suspicious;
            this.spoofed = spoofed;
            this.reasons = reasons;
        }

        public static SkinSpoofResult clean() {
            return new SkinSpoofResult(true, false, false, List.of());
        }

        public static SkinSpoofResult suspicious(List<String> reasons) {
            return new SkinSpoofResult(false, true, false, reasons);
        }

        public static SkinSpoofResult spoofed(List<String> reasons) {
            return new SkinSpoofResult(false, false, true, reasons);
        }

        public boolean isClean() { return clean; }
        public boolean isSuspicious() { return suspicious; }
        public boolean isSpoofed() { return spoofed; }
        public List<String> getReasons() { return reasons; }
    }
}
