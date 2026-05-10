package com.aluer.security;

import com.aluer.config.ServerGuardConfig;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;

@Service
public class GeoBlockService {

    private final ServerGuardConfig config;

    private final Set<String> allowlist = ConcurrentHashMap.newKeySet();
    private final Set<String> blocklist = ConcurrentHashMap.newKeySet();
    private final Map<String, String> ipCountryCache = new ConcurrentHashMap<>();
    private final Map<String, Long> ipCountryCacheTimestamps = new ConcurrentHashMap<>();
    private final ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor();

    private final AtomicLong totalChecked = new AtomicLong(0);
    private final AtomicLong totalBlocked = new AtomicLong(0);
    private final AtomicLong totalAllowed = new AtomicLong(0);

    private static final long CACHE_TTL_MS = 3600000;
    private volatile boolean defaultAllow = true;

    private static final Set<String> HIGH_RISK_COUNTRIES = Set.of("CN", "RU", "KP", "IR", "VN");

    public GeoBlockService() {
        this(new ServerGuardConfig());
    }

    @Autowired
    public GeoBlockService(ServerGuardConfig config) {
        this.config = config;
        scheduler.scheduleAtFixedRate(this::cleanupOldData, 120, 300, TimeUnit.SECONDS);
    }

    public GeoBlockResult checkConnection(String ip, String countryCode) {
        totalChecked.incrementAndGet();

        if (!config.getSecurity().getSuperEvolution().isGeoBlock()) {
            return GeoBlockResult.allowed();
        }

        if (ip == null || countryCode == null) {
            totalBlocked.incrementAndGet();
            return GeoBlockResult.blocked("Null IP or country code");
        }

        String normalizedCountry = countryCode.toUpperCase().trim();

        // Cache the IP-to-country mapping
        ipCountryCache.put(ip, normalizedCountry);
        ipCountryCacheTimestamps.put(ip, System.currentTimeMillis());

        // Check explicit blocklist first
        if (blocklist.contains(normalizedCountry)) {
            totalBlocked.incrementAndGet();
            return GeoBlockResult.blocked("Country " + normalizedCountry + " is explicitly blocked");
        }

        // Check explicit allowlist
        if (allowlist.contains(normalizedCountry)) {
            totalAllowed.incrementAndGet();
            return GeoBlockResult.allowed();
        }

        // Check high-risk countries
        if (HIGH_RISK_COUNTRIES.contains(normalizedCountry)) {
            totalBlocked.incrementAndGet();
            return GeoBlockResult.blocked("Country " + normalizedCountry + " is a high-risk region for Minecraft attacks");
        }

        // Default mode
        if (defaultAllow) {
            totalAllowed.incrementAndGet();
            return GeoBlockResult.allowed();
        } else {
            totalBlocked.incrementAndGet();
            return GeoBlockResult.blocked("Country " + normalizedCountry + " not in allowlist (default-deny mode)");
        }
    }

    public void addToAllowlist(String countryCode) {
        if (countryCode != null) {
            allowlist.add(countryCode.toUpperCase().trim());
            blocklist.remove(countryCode.toUpperCase().trim());
        }
    }

    public void removeFromAllowlist(String countryCode) {
        if (countryCode != null) {
            allowlist.remove(countryCode.toUpperCase().trim());
        }
    }

    public void addToBlocklist(String countryCode) {
        if (countryCode != null) {
            blocklist.add(countryCode.toUpperCase().trim());
            allowlist.remove(countryCode.toUpperCase().trim());
        }
    }

    public void removeFromBlocklist(String countryCode) {
        if (countryCode != null) {
            blocklist.remove(countryCode.toUpperCase().trim());
        }
    }

    public Set<String> getAllowlist() {
        return new HashSet<>(allowlist);
    }

    public Set<String> getBlocklist() {
        return new HashSet<>(blocklist);
    }

    public Set<String> getHighRiskCountries() {
        return new HashSet<>(HIGH_RISK_COUNTRIES);
    }

    public void setDefaultAllow(boolean defaultAllow) {
        this.defaultAllow = defaultAllow;
    }

    public boolean isDefaultAllow() {
        return defaultAllow;
    }

    public String getCachedCountry(String ip) {
        Long timestamp = ipCountryCacheTimestamps.get(ip);
        if (timestamp == null) {
            return null;
        }
        if (System.currentTimeMillis() - timestamp > CACHE_TTL_MS) {
            ipCountryCache.remove(ip);
            ipCountryCacheTimestamps.remove(ip);
            return null;
        }
        return ipCountryCache.get(ip);
    }

    public void cacheIpCountry(String ip, String countryCode) {
        ipCountryCache.put(ip, countryCode.toUpperCase().trim());
        ipCountryCacheTimestamps.put(ip, System.currentTimeMillis());
    }

    public Map<String, Object> getStatus() {
        Map<String, Object> status = new LinkedHashMap<>();
        status.put("enabled", config.getSecurity().getSuperEvolution().isGeoBlock());
        status.put("defaultAllow", defaultAllow);
        status.put("allowlistSize", allowlist.size());
        status.put("blocklistSize", blocklist.size());
        status.put("totalChecked", totalChecked.get());
        status.put("totalBlocked", totalBlocked.get());
        status.put("totalAllowed", totalAllowed.get());
        status.put("cachedIPs", ipCountryCache.size());
        status.put("allowlist", new ArrayList<>(allowlist));
        status.put("blocklist", new ArrayList<>(blocklist));
        status.put("highRiskCountries", new ArrayList<>(HIGH_RISK_COUNTRIES));
        return status;
    }

    public long getTotalBlocked() {
        return totalBlocked.get();
    }

    public long getTotalAllowed() {
        return totalAllowed.get();
    }

    private void cleanupOldData() {
        long cutoff = System.currentTimeMillis() - CACHE_TTL_MS;
        ipCountryCacheTimestamps.entrySet().removeIf(e -> {
            if (e.getValue() < cutoff) {
                ipCountryCache.remove(e.getKey());
                return true;
            }
            return false;
        });
    }

    public static class GeoBlockResult {
        private final boolean allowed;
        private final boolean blocked;
        private final String reason;

        private GeoBlockResult(boolean allowed, boolean blocked, String reason) {
            this.allowed = allowed;
            this.blocked = blocked;
            this.reason = reason;
        }

        public static GeoBlockResult allowed() {
            return new GeoBlockResult(true, false, null);
        }

        public static GeoBlockResult blocked(String reason) {
            return new GeoBlockResult(false, true, reason);
        }

        public boolean isAllowed() { return allowed; }
        public boolean isBlocked() { return blocked; }
        public String getReason() { return reason; }
    }
}
