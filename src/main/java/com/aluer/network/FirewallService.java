package com.aluer.network;

import org.springframework.stereotype.Service;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;
import java.security.MessageDigest;

@Service
public class FirewallService {

    private final Map<String, FirewallRule> rules = new ConcurrentHashMap<>();
    private final Map<String, FirewallProfile> profiles = new ConcurrentHashMap<>();
    private final Map<String, ConnectionState> connections = new ConcurrentHashMap<>();
    private final Queue<FirewallLog> logs = new ConcurrentLinkedQueue<>();
    private final Set<String> whitelist = ConcurrentHashMap.newKeySet();
    private final Set<String> blacklist = ConcurrentHashMap.newKeySet();
    private final ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(2);

    private volatile FirewallProfile activeProfile;
    private final AtomicLong ruleIdCounter = new AtomicLong(1);

    public static final int MAX_CONNECTIONS = 10000;
    public static final long CONNECTION_TIMEOUT = 120000;
    public static final int MAX_RULES = 500;

    public FirewallService() {
        initializeDefaultRules();
        initializeDefaultProfiles();
        startCleanupTask();
    }

    private void initializeDefaultProfiles() {
        FirewallProfile strict = new FirewallProfile("strict", "严格模式", true);
        strict.maxConnectionsPerIP = 10;
        strict.maxRequestsPerSecond = 20;
        strict.blockPingFlood = true;
        strict.blockPortScan = true;
        strict.blockSQLInjection = true;
        strict.blockXSS = true;
        profiles.put("strict", strict);

        FirewallProfile normal = new FirewallProfile("normal", "普通模式", false);
        normal.maxConnectionsPerIP = 50;
        normal.maxRequestsPerSecond = 100;
        normal.blockPingFlood = false;
        normal.blockPortScan = true;
        normal.blockSQLInjection = true;
        normal.blockXSS = true;
        profiles.put("normal", normal);

        FirewallProfile relaxed = new FirewallProfile("relaxed", "宽松模式", false);
        relaxed.maxConnectionsPerIP = 100;
        relaxed.maxRequestsPerSecond = 500;
        relaxed.blockPingFlood = false;
        relaxed.blockPortScan = false;
        relaxed.blockSQLInjection = false;
        relaxed.blockXSS = false;
        profiles.put("relaxed", relaxed);

        activeProfile = normal;
    }

    private void initializeDefaultRules() {
        addRule("DROP", "tcp", "0.0.0.0/0", "0.0.0.0/0", 23, "Telnet", "BLOCK_TELNET");
        addRule("DROP", "tcp", "0.0.0.0/0", "0.0.0.0/0", 445, "SMB", "BLOCK_SMB");
        addRule("DROP", "udp", "0.0.0.0/0", "0.0.0.0/0", 137, "NetBIOS", "BLOCK_NETBIOS");
        addRule("DROP", "udp", "0.0.0.0/0", "0.0.0.0/0", 138, "NetBIOS", "BLOCK_NETBIOS");
        addRule("DROP", "tcp", "0.0.0.0/0", "0.0.0.0/0", 1433, "MSSQL", "BLOCK_MSSQL");
        addRule("DROP", "tcp", "0.0.0.0/0", "0.0.0.0/0", 3306, "MySQL", "BLOCK_MYSQL");
        addRule("DROP", "tcp", "0.0.0.0/0", "0.0.0.0/0", 5432, "PostgreSQL", "BLOCK_POSTGRESQL");
        addRule("DROP", "tcp", "0.0.0.0/0", "0.0.0.0/0", 27017, "MongoDB", "BLOCK_MONGODB");
    }

    public long addRule(String action, String protocol, String sourceIP, String destIP, int port, String description, String category) {
        if (rules.size() >= MAX_RULES) {
            return -1;
        }

        long id = ruleIdCounter.getAndIncrement();
        FirewallRule rule = new FirewallRule(id, action, protocol, sourceIP, destIP, port, description, category);
        rules.put(String.valueOf(id), rule);
        
        logRuleChange("ADD", id, rule);
        return id;
    }

    public boolean removeRule(long ruleId) {
        String key = String.valueOf(ruleId);
        FirewallRule removed = rules.remove(key);
        if (removed != null) {
            logRuleChange("REMOVE", ruleId, removed);
            return true;
        }
        return false;
    }

    public FirewallRule getRule(long ruleId) {
        return rules.get(String.valueOf(ruleId));
    }

    public Collection<FirewallRule> getAllRules() {
        return rules.values();
    }

    public boolean updateRule(long ruleId, FirewallRule updated) {
        String key = String.valueOf(ruleId);
        if (!rules.containsKey(key)) {
            return false;
        }
        rules.put(key, updated);
        logRuleChange("UPDATE", ruleId, updated);
        return true;
    }

    public boolean checkConnection(String sourceIP, String destIP, int port, String protocol) {
        if (whitelist.contains(sourceIP)) {
            return true;
        }

        if (blacklist.contains(sourceIP)) {
            logBlock(sourceIP, destIP, port, "BLACKLIST");
            return false;
        }

        FirewallProfile profile = activeProfile;
        if (profile == null) {
            return true;
        }

        for (FirewallRule rule : rules.values()) {
            if (rule.matches(protocol, sourceIP, destIP, port)) {
                if ("DROP".equals(rule.action) || "DENY".equals(rule.action)) {
                    logBlock(sourceIP, destIP, port, rule.category);
                    return false;
                }
            }
        }

        if (profile.maxConnectionsPerIP > 0) {
            int connCount = getConnectionCount(sourceIP);
            if (connCount >= profile.maxConnectionsPerIP) {
                logBlock(sourceIP, destIP, port, "CONNECTION_LIMIT");
                return false;
            }
        }

        return true;
    }

    public boolean checkRequest(String ip, String request) {
        FirewallProfile profile = activeProfile;
        if (profile == null) {
            return true;
        }

        if (profile.blockSQLInjection && containsSQLInjection(request)) {
            logBlock(ip, "REQUEST", 0, "SQL_INJECTION");
            return false;
        }

        if (profile.blockXSS && containsXSS(request)) {
            logBlock(ip, "REQUEST", 0, "XSS");
            return false;
        }

        if (profile.blockPathTraversal && containsPathTraversal(request)) {
            logBlock(ip, "REQUEST", 0, "PATH_TRAVERSAL");
            return false;
        }

        return true;
    }

    private boolean containsSQLInjection(String input) {
        if (input == null) return false;
        String lower = input.toLowerCase();
        String[] sqlKeywords = {"union", "select", "insert", "update", "delete", "drop", 
                               "create", "alter", "exec", "execute", "script", "--", ";"};
        for (String keyword : sqlKeywords) {
            if (lower.contains(keyword)) {
                return true;
            }
        }
        return false;
    }

    private boolean containsXSS(String input) {
        if (input == null) return false;
        String[] xssPatterns = {"<script", "javascript:", "onerror=", "onload=", 
                                "<iframe", "eval(", "document.cookie"};
        for (String pattern : xssPatterns) {
            if (input.toLowerCase().contains(pattern)) {
                return true;
            }
        }
        return false;
    }

    private boolean containsPathTraversal(String input) {
        if (input == null) return false;
        return input.contains("../") || input.contains("..\\");
    }

    public void addToWhitelist(String ip) {
        whitelist.add(ip);
        logConfigChange("WHITELIST_ADD", ip);
    }

    public void removeFromWhitelist(String ip) {
        whitelist.remove(ip);
        logConfigChange("WHITELIST_REMOVE", ip);
    }

    public boolean isWhitelisted(String ip) {
        return whitelist.contains(ip);
    }

    public void addToBlacklist(String ip) {
        blacklist.add(ip);
        logConfigChange("BLACKLIST_ADD", ip);
    }

    public void removeFromBlacklist(String ip) {
        blacklist.remove(ip);
        logConfigChange("BLACKLIST_REMOVE", ip);
    }

    public boolean isBlacklisted(String ip) {
        return blacklist.contains(ip);
    }

    public boolean setActiveProfile(String profileName) {
        FirewallProfile profile = profiles.get(profileName);
        if (profile == null) {
            return false;
        }
        activeProfile = profile;
        logConfigChange("PROFILE_CHANGE", profileName);
        return true;
    }

    public FirewallProfile getActiveProfile() {
        return activeProfile;
    }

    public boolean createProfile(String name, String description) {
        if (profiles.containsKey(name)) {
            return false;
        }
        FirewallProfile profile = new FirewallProfile(name, description, false);
        profiles.put(name, profile);
        return true;
    }

    public boolean deleteProfile(String name) {
        FirewallProfile profile = profiles.get(name);
        if (profile == null) {
            return false;
        }
        if (profile.isDefault) {
            return false;
        }
        return profiles.remove(name) != null;
    }

    public Collection<FirewallProfile> getAllProfiles() {
        return profiles.values();
    }

    public void recordConnection(String ip, String destIP, int port, String protocol) {
        String key = ip + ":" + destIP + ":" + port;
        connections.put(key, new ConnectionState(ip, destIP, port, protocol));
    }

    public void closeConnection(String ip, String destIP, int port) {
        String key = ip + ":" + destIP + ":" + port;
        connections.remove(key);
    }

    public int getConnectionCount(String ip) {
        return (int) connections.keySet().stream()
            .filter(k -> k.startsWith(ip + ":"))
            .count();
    }

    public Collection<ConnectionState> getActiveConnections() {
        return connections.values();
    }

    private void logBlock(String sourceIP, String destIP, int port, String reason) {
        FirewallLog log = new FirewallLog("BLOCK", sourceIP, destIP, port, reason, System.currentTimeMillis());
        addLog(log);
    }

    private void logRuleChange(String action, long ruleId, FirewallRule rule) {
        FirewallLog log = new FirewallLog("RULE_" + action, rule.sourceIP, rule.destIP, rule.port, 
            ruleId + ":" + rule.description, System.currentTimeMillis());
        addLog(log);
    }

    private void logConfigChange(String action, String details) {
        FirewallLog log = new FirewallLog("CONFIG_" + action, "SYSTEM", details, 0, "", System.currentTimeMillis());
        addLog(log);
    }

    private void addLog(FirewallLog log) {
        logs.offer(log);
        while (logs.size() > 5000) {
            logs.remove();
        }
    }

    public List<FirewallLog> getLogs(int limit) {
        List<FirewallLog> result = new ArrayList<>();
        int count = 0;
        for (FirewallLog log : logs) {
            if (count++ >= limit) break;
            result.add(log);
        }
        return result;
    }

    public Map<String, Object> getStats() {
        Map<String, Object> stats = new HashMap<>();
        stats.put("totalRules", rules.size());
        stats.put("whitelistSize", whitelist.size());
        stats.put("blacklistSize", blacklist.size());
        stats.put("activeConnections", connections.size());
        stats.put("activeProfile", activeProfile != null ? activeProfile.name : "none");
        return stats;
    }

    private void startCleanupTask() {
        scheduler.scheduleAtFixedRate(() -> {
            long now = System.currentTimeMillis();
            connections.entrySet().removeIf(entry -> 
                now - entry.getValue().createdAt > CONNECTION_TIMEOUT);
        }, 60, 60, TimeUnit.SECONDS);
    }

    public static class FirewallRule {
        public final long id;
        public final String action;
        public final String protocol;
        public final String sourceIP;
        public final String destIP;
        public final int port;
        public final String description;
        public final String category;
        public final long createdAt;

        public FirewallRule(long id, String action, String protocol, String sourceIP, 
                          String destIP, int port, String description, String category) {
            this.id = id;
            this.action = action;
            this.protocol = protocol;
            this.sourceIP = sourceIP;
            this.destIP = destIP;
            this.port = port;
            this.description = description;
            this.category = category;
            this.createdAt = System.currentTimeMillis();
        }

        public boolean matches(String protocol, String sourceIP, String destIP, int port) {
            if (!this.protocol.equalsIgnoreCase(protocol) && !this.protocol.equals("*")) {
                return false;
            }
            if (this.port != 0 && this.port != port) {
                return false;
            }
            return true;
        }
    }

    public static class FirewallProfile {
        public final String name;
        public final String description;
        public final boolean isDefault;
        public int maxConnectionsPerIP = 50;
        public int maxRequestsPerSecond = 100;
        public boolean blockPingFlood = false;
        public boolean blockPortScan = false;
        public boolean blockSQLInjection = false;
        public boolean blockXSS = false;
        public boolean blockPathTraversal = false;

        public FirewallProfile(String name, String description, boolean isDefault) {
            this.name = name;
            this.description = description;
            this.isDefault = isDefault;
        }
    }

    public static class ConnectionState {
        public final String sourceIP;
        public final String destIP;
        public final int port;
        public final String protocol;
        public final long createdAt;
        public volatile long lastActivity;

        public ConnectionState(String sourceIP, String destIP, int port, String protocol) {
            this.sourceIP = sourceIP;
            this.destIP = destIP;
            this.port = port;
            this.protocol = protocol;
            this.createdAt = System.currentTimeMillis();
            this.lastActivity = System.currentTimeMillis();
        }
    }

    public static class FirewallLog {
        public final String type;
        public final String sourceIP;
        public final String destIP;
        public final int port;
        public final String reason;
        public final long timestamp;

        public FirewallLog(String type, String sourceIP, String destIP, int port, String reason, long timestamp) {
            this.type = type;
            this.sourceIP = sourceIP;
            this.destIP = destIP;
            this.port = port;
            this.reason = reason;
            this.timestamp = timestamp;
        }
    }
}
