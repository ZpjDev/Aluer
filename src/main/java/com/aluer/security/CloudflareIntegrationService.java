package com.aluer.security;

import com.aluer.config.ServerGuardConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.atomic.AtomicLong;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

@Component
public class CloudflareIntegrationService {
    private static final Logger logger = LoggerFactory.getLogger(CloudflareIntegrationService.class);

    private final ServerGuardConfig config;
    private final Map<String, CloudflareZone> zones = new ConcurrentHashMap<>();
    private final Queue<CloudflareEvent> eventLog = new ConcurrentLinkedQueue<>();
    private final AtomicLong totalAPIRequests = new AtomicLong(0);
    private final AtomicLong blockedRequests = new AtomicLong(0);
    private final AtomicLong challengeRequests = new AtomicLong(0);

    private String apiKey = "";
    private String apiEmail = "";
    private volatile boolean enabled = false;

    private static final DateTimeFormatter DATE_FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    public CloudflareIntegrationService() {
        this(new ServerGuardConfig());
    }

    @Autowired
    public CloudflareIntegrationService(ServerGuardConfig config) {
        this.config = config;
        bootstrapFromConfig();
        logger.info("Cloudflare Integration Service initialized");
    }

    private void bootstrapFromConfig() {
        ServerGuardConfig.CloudEdgeConfig cloudEdge = config.getSecurity().getCloudEdge();
        if (cloudEdge.getApiKey() != null && !cloudEdge.getApiKey().isBlank()) {
            this.apiKey = cloudEdge.getApiKey();
            this.apiEmail = cloudEdge.getApiEmail();
            this.enabled = cloudEdge.isEnabled();
        }
        if (cloudEdge.getZoneId() != null && !cloudEdge.getZoneId().isBlank()) {
            zones.putIfAbsent(cloudEdge.getZoneId(), new CloudflareZone(cloudEdge.getZoneId(), "configured-zone"));
        }
    }

    public void configure(String apiKey, String apiEmail) {
        this.apiKey = apiKey;
        this.apiEmail = apiEmail;
        this.enabled = true;
        logger.info("Cloudflare API configured for {}", apiEmail);
    }

    public void addZone(String zoneId, String domain) {
        CloudflareZone zone = new CloudflareZone(zoneId, domain);
        zones.put(zoneId, zone);
        logger.info("Added Cloudflare zone: {} for domain {}", zoneId, domain);
    }

    public CloudflareStats getZoneStats(String zoneId) {
        CloudflareZone zone = zones.get(zoneId);
        if (zone == null) {
            return null;
        }

        CloudflareStats stats = new CloudflareStats(zoneId);
        stats.setRequests(zone.getTotalRequests());
        stats.setBandwidth(zone.getTotalBandwidth());
        stats.setThreats(zone.getThreatsBlocked());
        stats.setCachedRequests(zone.getCachedRequests());
        stats.setUncachedRequests(zone.getUncachedRequests());

        return stats;
    }

    public boolean purgeCache(String zoneId) {
        totalAPIRequests.incrementAndGet();
        CloudflareZone zone = zones.get(zoneId);
        if (zone != null) {
            zone.clearCache();
            logEvent(zoneId, "PURGE", "Cache purged successfully");
            logger.info("Purged Cloudflare cache for zone: {}", zoneId);
            return true;
        }
        return false;
    }

    public boolean addIPToFirewall(String zoneId, String ip, String mode, String notes) {
        totalAPIRequests.incrementAndGet();
        CloudflareZone zone = zones.get(zoneId);
        if (zone != null) {
            zone.addFirewallRule(ip, mode, notes);
            logEvent(zoneId, "FIREWALL_ADD", "Added IP to firewall: " + ip);
            logger.info("Added firewall rule for IP: {} in zone: {}", ip, zoneId);
            return true;
        }
        return false;
    }

    public EdgeActionResult applyBlock(String ip, String reason) {
        return executeEdgeAction(new EdgeActionRequest(resolveZoneId(), ip,
            config.getSecurity().getCloudEdge().getDefaultBlockMode(), reason));
    }

    public EdgeActionResult applyChallenge(String ip, String reason) {
        return executeEdgeAction(new EdgeActionRequest(resolveZoneId(), ip,
            config.getSecurity().getCloudEdge().getDefaultChallengeMode(), reason));
    }

    public EdgeActionResult releaseAddress(String ip, String reason) {
        String zoneId = resolveZoneId();
        CloudflareZone zone = zones.computeIfAbsent(zoneId, id -> new CloudflareZone(id, "configured-zone"));
        zone.removeFirewallRule(ip);
        logEvent(zoneId, "FIREWALL_RELEASE", "Released " + ip + " reason=" + reason);
        if (isDryRun()) {
            return new EdgeActionResult(true, true, "release", zoneId, ip, "dry-run release");
        }
        totalAPIRequests.incrementAndGet();
        return new EdgeActionResult(removeIPFromFirewall(zoneId, ip), false, "release", zoneId, ip, reason);
    }

    public EdgeActionResult setUnderAttackMode(boolean enable, String reason) {
        String zoneId = resolveZoneId();
        if (isDryRun()) {
            logEvent(zoneId, "UNDER_ATTACK_DRY_RUN", reason);
            return new EdgeActionResult(true, true, enable ? "under-attack-on" : "under-attack-off", zoneId, "", reason);
        }
        enableUnderAttackMode(zoneId, enable);
        return new EdgeActionResult(true, false, enable ? "under-attack-on" : "under-attack-off", zoneId, "", reason);
    }

    public EdgeActionResult executeEdgeAction(EdgeActionRequest request) {
        String zoneId = request.zoneId == null || request.zoneId.isBlank() ? resolveZoneId() : request.zoneId;
        CloudflareZone zone = zones.computeIfAbsent(zoneId, id -> new CloudflareZone(id, "configured-zone"));
        zone.addFirewallRule(request.ip, request.mode, request.reason);

        if (isDryRun()) {
            logEvent(zoneId, "EDGE_DRY_RUN", request.mode + " " + request.ip);
            if ("challenge".equalsIgnoreCase(request.mode)) {
                challengeRequests.incrementAndGet();
            } else {
                blockedRequests.incrementAndGet();
            }
            return new EdgeActionResult(true, true, request.mode, zoneId, request.ip, request.reason);
        }

        totalAPIRequests.incrementAndGet();
        boolean success = sendFirewallRequest(zoneId, request.ip, request.mode, request.reason);
        if ("challenge".equalsIgnoreCase(request.mode)) {
            challengeRequests.incrementAndGet();
        } else {
            blockedRequests.incrementAndGet();
        }
        logEvent(zoneId, "EDGE_ACTION", request.mode + " " + request.ip);
        return new EdgeActionResult(success, false, request.mode, zoneId, request.ip, request.reason);
    }

    public boolean removeIPFromFirewall(String zoneId, String ip) {
        totalAPIRequests.incrementAndGet();
        CloudflareZone zone = zones.get(zoneId);
        if (zone != null) {
            zone.removeFirewallRule(ip);
            logEvent(zoneId, "FIREWALL_REMOVE", "Removed IP from firewall: " + ip);
            return true;
        }
        return false;
    }

    public void setSecurityLevel(String zoneId, String level) {
        CloudflareZone zone = zones.get(zoneId);
        if (zone != null) {
            zone.setSecurityLevel(level);
            logEvent(zoneId, "SECURITY_LEVEL", "Security level set to: " + level);
            logger.info("Set security level to {} for zone: {}", level, zoneId);
        }
    }

    public void enableUnderAttackMode(String zoneId, boolean enable) {
        CloudflareZone zone = zones.get(zoneId);
        if (zone != null) {
            zone.setUnderAttackMode(enable);
            logEvent(zoneId, "UNDER_ATTACK", "Under attack mode: " + enable);
            logger.info("Set under attack mode to {} for zone: {}", enable, zoneId);
        }
    }

    public void updatePageRules(String zoneId, String target, String action, Map<String, String> settings) {
        CloudflareZone zone = zones.get(zoneId);
        if (zone != null) {
            zone.addPageRule(target, action, settings);
            logEvent(zoneId, "PAGE_RULES", "Updated page rules for: " + target);
        }
    }

    public void enableAlwaysOnline(String zoneId, boolean enable) {
        CloudflareZone zone = zones.get(zoneId);
        if (zone != null) {
            zone.setAlwaysOnline(enable);
            logEvent(zoneId, "ALWAYS_ONLINE", "Always online: " + enable);
        }
    }

    public void enableAlwaysUseHTTPS(String zoneId, boolean enable) {
        CloudflareZone zone = zones.get(zoneId);
        if (zone != null) {
            zone.setAlwaysUseHTTPS(enable);
            logEvent(zoneId, "ALWAYS_HTTPS", "Always HTTPS: " + enable);
        }
    }

    public Map<String, Object> getStats() {
        Map<String, Object> stats = new HashMap<>();
        stats.put("enabled", enabled);
        stats.put("totalAPIRequests", totalAPIRequests.get());
        stats.put("blockedRequests", blockedRequests.get());
        stats.put("challengeRequests", challengeRequests.get());
        stats.put("zonesConfigured", zones.size());
        stats.put("dryRun", isDryRun());
        stats.put("zoneId", resolveZoneId());

        long totalRequests = 0;
        long totalThreats = 0;
        for (CloudflareZone zone : zones.values()) {
            totalRequests += zone.getTotalRequests();
            totalThreats += zone.getThreatsBlocked();
        }
        stats.put("totalRequests", totalRequests);
        stats.put("totalThreats", totalThreats);

        return stats;
    }

    public List<Map<String, Object>> getConfiguredRules() {
        List<Map<String, Object>> rules = new ArrayList<>();
        for (CloudflareZone zone : zones.values()) {
            for (FirewallRule rule : zone.getFirewallRules().values()) {
                Map<String, Object> item = new LinkedHashMap<>();
                item.put("zoneId", zone.getZoneId());
                item.put("ip", rule.getIp());
                item.put("mode", rule.getMode());
                item.put("notes", rule.getNotes());
                item.put("createdAt", rule.getCreatedAt());
                rules.add(item);
            }
        }
        return rules;
    }

    public List<CloudflareEvent> getRecentEvents(int limit) {
        List<CloudflareEvent> events = new ArrayList<>();
        int count = 0;
        for (CloudflareEvent event : eventLog) {
            if (count++ >= limit) break;
            events.add(event);
        }
        return events;
    }

    private void logEvent(String zoneId, String type, String details) {
        CloudflareEvent event = new CloudflareEvent(zoneId, type, details, LocalDateTime.now());
        eventLog.offer(event);
        if (eventLog.size() > 1000) {
            eventLog.poll();
        }
    }

    private boolean sendFirewallRequest(String zoneId, String ip, String mode, String reason) {
        if (!enabled || apiKey == null || apiKey.isBlank() || apiEmail == null || apiEmail.isBlank()) {
            return false;
        }

        try {
            URL url = new URL("https://api.cloudflare.com/client/v4/zones/" + zoneId + "/firewall/access_rules/rules");
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod("POST");
            connection.setRequestProperty("X-Auth-Key", apiKey);
            connection.setRequestProperty("X-Auth-Email", apiEmail);
            connection.setRequestProperty("Content-Type", "application/json");
            connection.setDoOutput(true);

            String body = "{\"mode\":\"" + mode + "\",\"configuration\":{\"target\":\"ip\",\"value\":\"" + ip + "\"},\"notes\":\"" + reason + "\"}";
            try (OutputStream outputStream = connection.getOutputStream()) {
                outputStream.write(body.getBytes());
            }
            return connection.getResponseCode() >= 200 && connection.getResponseCode() < 300;
        } catch (IOException e) {
            logger.warn("Cloudflare API request failed: {}", e.getMessage());
            return false;
        }
    }

    private boolean isDryRun() {
        return !config.getSecurity().getCloudEdge().isEnabled() || config.getSecurity().getCloudEdge().isDryRun();
    }

    private String resolveZoneId() {
        if (!config.getSecurity().getCloudEdge().getZoneId().isBlank()) {
            return config.getSecurity().getCloudEdge().getZoneId();
        }
        return zones.keySet().stream().findFirst().orElse("default-zone");
    }

    public static class CloudflareZone {
        private final String zoneId;
        private final String domain;
        private volatile long totalRequests = 0;
        private volatile long totalBandwidth = 0;
        private volatile long threatsBlocked = 0;
        private volatile long cachedRequests = 0;
        private volatile long uncachedRequests = 0;
        private volatile String securityLevel = "MEDIUM";
        private volatile boolean underAttackMode = false;
        private volatile boolean alwaysOnline = false;
        private volatile boolean alwaysUseHTTPS = false;
        private final Map<String, FirewallRule> firewallRules = new ConcurrentHashMap<>();
        private final Map<String, PageRule> pageRules = new ConcurrentHashMap<>();
        private volatile long lastUpdated;

        public CloudflareZone(String zoneId, String domain) {
            this.zoneId = zoneId;
            this.domain = domain;
            this.lastUpdated = System.currentTimeMillis();
        }

        public void clearCache() {
            lastUpdated = System.currentTimeMillis();
        }

        public void addFirewallRule(String ip, String mode, String notes) {
            firewallRules.put(ip, new FirewallRule(ip, mode, notes));
            lastUpdated = System.currentTimeMillis();
        }

        public void removeFirewallRule(String ip) {
            firewallRules.remove(ip);
            lastUpdated = System.currentTimeMillis();
        }

        public void addPageRule(String target, String action, Map<String, String> settings) {
            pageRules.put(target, new PageRule(target, action, settings));
            lastUpdated = System.currentTimeMillis();
        }

        public String getZoneId() { return zoneId; }
        public String getDomain() { return domain; }
        public long getTotalRequests() { return totalRequests; }
        public void setTotalRequests(long totalRequests) { this.totalRequests = totalRequests; }
        public long getTotalBandwidth() { return totalBandwidth; }
        public void setTotalBandwidth(long totalBandwidth) { this.totalBandwidth = totalBandwidth; }
        public long getThreatsBlocked() { return threatsBlocked; }
        public void setThreatsBlocked(long threatsBlocked) { this.threatsBlocked = threatsBlocked; }
        public long getCachedRequests() { return cachedRequests; }
        public void setCachedRequests(long cachedRequests) { this.cachedRequests = cachedRequests; }
        public long getUncachedRequests() { return uncachedRequests; }
        public void setUncachedRequests(long uncachedRequests) { this.uncachedRequests = uncachedRequests; }
        public String getSecurityLevel() { return securityLevel; }
        public void setSecurityLevel(String securityLevel) { this.securityLevel = securityLevel; }
        public boolean isUnderAttackMode() { return underAttackMode; }
        public void setUnderAttackMode(boolean underAttackMode) { this.underAttackMode = underAttackMode; }
        public boolean isAlwaysOnline() { return alwaysOnline; }
        public void setAlwaysOnline(boolean alwaysOnline) { this.alwaysOnline = alwaysOnline; }
        public boolean isAlwaysUseHTTPS() { return alwaysUseHTTPS; }
        public void setAlwaysUseHTTPS(boolean alwaysUseHTTPS) { this.alwaysUseHTTPS = alwaysUseHTTPS; }
        public Map<String, FirewallRule> getFirewallRules() { return firewallRules; }
        public Map<String, PageRule> getPageRules() { return pageRules; }
        public long getLastUpdated() { return lastUpdated; }
    }

    public static class FirewallRule {
        private final String ip;
        private final String mode;
        private final String notes;
        private final long createdAt;

        public FirewallRule(String ip, String mode, String notes) {
            this.ip = ip;
            this.mode = mode;
            this.notes = notes;
            this.createdAt = System.currentTimeMillis();
        }

        public String getIp() { return ip; }
        public String getMode() { return mode; }
        public String getNotes() { return notes; }
        public long getCreatedAt() { return createdAt; }
    }

    public static class PageRule {
        private final String target;
        private final String action;
        private final Map<String, String> settings;
        private final long createdAt;

        public PageRule(String target, String action, Map<String, String> settings) {
            this.target = target;
            this.action = action;
            this.settings = settings;
            this.createdAt = System.currentTimeMillis();
        }

        public String getTarget() { return target; }
        public String getAction() { return action; }
        public Map<String, String> getSettings() { return settings; }
        public long getCreatedAt() { return createdAt; }
    }

    public static class CloudflareStats {
        private final String zoneId;
        private long requests;
        private long bandwidth;
        private long threats;
        private long cachedRequests;
        private long uncachedRequests;

        public CloudflareStats(String zoneId) {
            this.zoneId = zoneId;
        }

        public String getZoneId() { return zoneId; }
        public long getRequests() { return requests; }
        public void setRequests(long requests) { this.requests = requests; }
        public long getBandwidth() { return bandwidth; }
        public void setBandwidth(long bandwidth) { this.bandwidth = bandwidth; }
        public long getThreats() { return threats; }
        public void setThreats(long threats) { this.threats = threats; }
        public long getCachedRequests() { return cachedRequests; }
        public void setCachedRequests(long cachedRequests) { this.cachedRequests = cachedRequests; }
        public long getUncachedRequests() { return uncachedRequests; }
        public void setUncachedRequests(long uncachedRequests) { this.uncachedRequests = uncachedRequests; }
    }

    public static class CloudflareEvent {
        private final String zoneId;
        private final String type;
        private final String details;
        private final LocalDateTime timestamp;

        public CloudflareEvent(String zoneId, String type, String details, LocalDateTime timestamp) {
            this.zoneId = zoneId;
            this.type = type;
            this.details = details;
            this.timestamp = timestamp;
        }

        public String getZoneId() { return zoneId; }
        public String getType() { return type; }
        public String getDetails() { return details; }
        public LocalDateTime getTimestamp() { return timestamp; }
    }

    public static class EdgeActionRequest {
        private final String zoneId;
        private final String ip;
        private final String mode;
        private final String reason;

        public EdgeActionRequest(String zoneId, String ip, String mode, String reason) {
            this.zoneId = zoneId;
            this.ip = ip;
            this.mode = mode;
            this.reason = reason;
        }

        public String getZoneId() { return zoneId; }
        public String getIp() { return ip; }
        public String getMode() { return mode; }
        public String getReason() { return reason; }
    }

    public static class EdgeActionResult {
        private final boolean success;
        private final boolean dryRun;
        private final String action;
        private final String zoneId;
        private final String ip;
        private final String reason;
        private final long timestamp = System.currentTimeMillis();

        public EdgeActionResult(boolean success, boolean dryRun, String action, String zoneId, String ip, String reason) {
            this.success = success;
            this.dryRun = dryRun;
            this.action = action;
            this.zoneId = zoneId;
            this.ip = ip;
            this.reason = reason;
        }

        public boolean isSuccess() { return success; }
        public boolean isDryRun() { return dryRun; }
        public String getAction() { return action; }
        public String getZoneId() { return zoneId; }
        public String getIp() { return ip; }
        public String getReason() { return reason; }
        public long getTimestamp() { return timestamp; }
    }
}
