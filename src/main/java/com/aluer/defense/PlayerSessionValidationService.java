package com.aluer.defense;

import com.aluer.config.ServerGuardConfig;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;

@Service
public class PlayerSessionValidationService {

    private final ServerGuardConfig config;

    private final Map<String, SessionRecord> activeSessions = new ConcurrentHashMap<>();
    private final Map<String, Set<String>> uuidToIPs = new ConcurrentHashMap<>();
    private final Map<String, Set<String>> ipToUUIDs = new ConcurrentHashMap<>();
    private final Map<String, Long> ipLastSwitch = new ConcurrentHashMap<>();
    private final ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor();

    private final AtomicLong totalValidations = new AtomicLong(0);
    private final AtomicLong totalSuspicious = new AtomicLong(0);
    private final AtomicLong totalInvalid = new AtomicLong(0);

    private static final String UUID_REGEX = "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$";
    private static final String OFFLINE_UUID_PREFIX = "00000000-0000-";
    private static final String PLAYER_NAME_REGEX = "^[a-zA-Z0-9_]{3,16}$";
    private static final long RAPID_SWITCH_WINDOW_MS = 30000;
    private static final int RAPID_SWITCH_THRESHOLD = 3;
    private static final long SESSION_CLEANUP_INTERVAL_MS = 600000;

    public PlayerSessionValidationService() {
        this(new ServerGuardConfig());
    }

    @Autowired
    public PlayerSessionValidationService(ServerGuardConfig config) {
        this.config = config;
        scheduler.scheduleAtFixedRate(this::cleanupOldData, 120, 300, TimeUnit.SECONDS);
    }

    public SessionValidationResult validateJoin(String uuid, String playerName, String ip, String sessionId) {
        totalValidations.incrementAndGet();

        if (!config.getSecurity().getSuperEvolution().isSessionValidation()) {
            return SessionValidationResult.valid();
        }

        List<String> reasons = new ArrayList<>();
        boolean suspicious = false;

        // Check 1: UUID format validation
        if (uuid == null || !uuid.matches(UUID_REGEX)) {
            totalInvalid.incrementAndGet();
            reasons.add("INVALID_UUID_FORMAT: " + uuid);
            return SessionValidationResult.invalid(reasons);
        }

        // Check 2: Offline-mode player detection
        if (uuid.startsWith(OFFLINE_UUID_PREFIX)) {
            suspicious = true;
            reasons.add("OFFLINE_MODE_UUID: Player likely using cracked/offline mode");
        }

        // Check 3: Premium/cracked detection patterns
        if (isCrackedPatternUUID(uuid)) {
            suspicious = true;
            reasons.add("CRACKED_UUID_PATTERN: UUID matches known cracked client patterns");
        }

        // Check 4: Player name regex validation
        if (playerName == null || !playerName.matches(PLAYER_NAME_REGEX)) {
            totalInvalid.incrementAndGet();
            reasons.add("INVALID_PLAYER_NAME: " + playerName);
            return SessionValidationResult.invalid(reasons);
        }

        // Check 5: Duplicate UUID detection (same UUID from different IPs)
        Set<String> ips = uuidToIPs.computeIfAbsent(uuid, k -> ConcurrentHashMap.newKeySet());
        if (!ips.isEmpty() && !ips.contains(ip)) {
            suspicious = true;
            reasons.add("DUPLICATE_UUID: UUID " + uuid + " seen from multiple IPs: " + ips.size());
        }
        ips.add(ip);

        // Check 6: Rapid account switching detection (same IP, different accounts)
        Set<String> uuids = ipToUUIDs.computeIfAbsent(ip, k -> ConcurrentHashMap.newKeySet());
        uuids.add(uuid);
        long now = System.currentTimeMillis();
        Long lastSwitch = ipLastSwitch.get(ip);
        if (lastSwitch != null && (now - lastSwitch) < RAPID_SWITCH_WINDOW_MS) {
            if (uuids.size() >= RAPID_SWITCH_THRESHOLD) {
                suspicious = true;
                reasons.add("RAPID_ACCOUNT_SWITCH: " + uuids.size() + " accounts from IP " + ip + " in " + RAPID_SWITCH_WINDOW_MS + "ms");
            }
        }
        ipLastSwitch.put(ip, now);

        // Check 7: Session replay attack detection (same session ID reused)
        SessionRecord existing = activeSessions.get(sessionId);
        if (existing != null) {
            if (!existing.uuid.equals(uuid) || !existing.ip.equals(ip)) {
                totalSuspicious.incrementAndGet();
                reasons.add("SESSION_REPLAY: Session ID " + sessionId + " reused by different player/IP");
                return SessionValidationResult.suspicious(reasons);
            }
        }

        // Store session
        SessionRecord record = new SessionRecord(uuid, playerName, ip, sessionId, now);
        activeSessions.put(sessionId, record);

        if (suspicious) {
            totalSuspicious.incrementAndGet();
            return SessionValidationResult.suspicious(reasons);
        }

        return SessionValidationResult.valid();
    }

    public void invalidateSession(String sessionId) {
        activeSessions.remove(sessionId);
    }

    public SessionRecord getSession(String sessionId) {
        return activeSessions.get(sessionId);
    }

    public Set<String> getIPsForUUID(String uuid) {
        Set<String> ips = uuidToIPs.get(uuid);
        return ips != null ? new HashSet<>(ips) : Collections.emptySet();
    }

    public Set<String> getUUIDsForIP(String ip) {
        Set<String> uuids = ipToUUIDs.get(ip);
        return uuids != null ? new HashSet<>(uuids) : Collections.emptySet();
    }

    public Map<String, Object> getStatus() {
        Map<String, Object> status = new LinkedHashMap<>();
        status.put("enabled", config.getSecurity().getSuperEvolution().isSessionValidation());
        status.put("activeSessions", activeSessions.size());
        status.put("trackedUUIDs", uuidToIPs.size());
        status.put("trackedIPs", ipToUUIDs.size());
        status.put("totalValidations", totalValidations.get());
        status.put("totalSuspicious", totalSuspicious.get());
        status.put("totalInvalid", totalInvalid.get());

        List<Map<String, Object>> sessions = new ArrayList<>();
        for (Map.Entry<String, SessionRecord> e : activeSessions.entrySet()) {
            Map<String, Object> s = new LinkedHashMap<>();
            s.put("sessionId", e.getKey());
            s.put("uuid", e.getValue().uuid);
            s.put("playerName", e.getValue().playerName);
            s.put("ip", e.getValue().ip);
            s.put("createdAt", e.getValue().createdAt);
            sessions.add(s);
        }
        status.put("activeSessionList", sessions);
        return status;
    }

    public long getTotalValidations() { return totalValidations.get(); }
    public long getTotalSuspicious() { return totalSuspicious.get(); }
    public long getTotalInvalid() { return totalInvalid.get(); }

    private boolean isCrackedPatternUUID(String uuid) {
        if (uuid == null) return false;
        String lower = uuid.toLowerCase();
        // Check for all-zeros pattern common in cracked clients
        String[] parts = lower.split("-");
        if (parts.length != 5) return false;
        // Check for segments that are all zeros or repeated digits
        for (String part : parts) {
            if (part.matches("^0+$")) return true;
            if (part.matches("^(.)\\1+$")) return true;
        }
        return false;
    }

    private void cleanupOldData() {
        long cutoff = System.currentTimeMillis() - SESSION_CLEANUP_INTERVAL_MS;
        activeSessions.entrySet().removeIf(e -> e.getValue().createdAt < cutoff);

        // Also clean up tracking maps for sessions no longer active
        Set<String> activeUUIDs = new HashSet<>();
        for (SessionRecord record : activeSessions.values()) {
            activeUUIDs.add(record.uuid);
        }
        uuidToIPs.keySet().retainAll(activeUUIDs);
    }

    public static class SessionRecord {
        public final String uuid;
        public final String playerName;
        public final String ip;
        public final String sessionId;
        public final long createdAt;

        public SessionRecord(String uuid, String playerName, String ip, String sessionId, long createdAt) {
            this.uuid = uuid;
            this.playerName = playerName;
            this.ip = ip;
            this.sessionId = sessionId;
            this.createdAt = createdAt;
        }
    }

    public static class SessionValidationResult {
        private final boolean valid;
        private final boolean suspicious;
        private final boolean invalid;
        private final List<String> reasons;

        private SessionValidationResult(boolean valid, boolean suspicious, boolean invalid, List<String> reasons) {
            this.valid = valid;
            this.suspicious = suspicious;
            this.invalid = invalid;
            this.reasons = reasons;
        }

        public static SessionValidationResult valid() {
            return new SessionValidationResult(true, false, false, List.of());
        }

        public static SessionValidationResult suspicious(List<String> reasons) {
            return new SessionValidationResult(true, true, false, reasons);
        }

        public static SessionValidationResult invalid(List<String> reasons) {
            return new SessionValidationResult(false, false, true, reasons);
        }

        public boolean isValid() { return valid; }
        public boolean isSuspicious() { return suspicious; }
        public boolean isInvalid() { return invalid; }
        public List<String> getReasons() { return reasons; }
    }
}
