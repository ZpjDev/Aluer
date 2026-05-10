package com.aluer.audit;

import com.aluer.config.ServerGuardConfig;
import com.aluer.service.RconClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedDeque;

@Component
public class SecurityAuditService {
    private static final Logger logger = LoggerFactory.getLogger(SecurityAuditService.class);
    
    private final ServerGuardConfig config;
    private final RconClient rconClient;
    private final ConcurrentLinkedDeque<AuditEvent> auditLog = new ConcurrentLinkedDeque<>();
    private final Map<String, SecurityAlert> activeAlerts = new ConcurrentHashMap<>();
    
    public SecurityAuditService(ServerGuardConfig config, RconClient rconClient) {
        this.config = config;
        this.rconClient = rconClient;
    }
    
    public void logEvent(String category, String player, String action, String details) {
        AuditEvent event = new AuditEvent(category, player, action, details);
        auditLog.add(event);
        
        cleanupOldEvents();
    }
    
    public void logPlayerCommand(String player, String command) {
        if (isSuspiciousCommand(command)) {
            logEvent("SUSPICIOUS_COMMAND", player, command, "Potentially dangerous command");
            
            if (isHighRiskCommand(command)) {
                triggerSecurityAlert("HIGH_RISK_COMMAND", player, command);
            }
        } else {
            logEvent("PLAYER_COMMAND", player, command, "Normal command execution");
        }
    }
    
    public void logPlayerLogin(String player, String ip) {
        logEvent("PLAYER_LOGIN", player, ip, "Player logged in");
        
        if (isKnownHacker(player)) {
            triggerSecurityAlert("KNOWN_HACKER", player, "Known hacker attempting login from " + ip);
        }
        
        if (isSuspiciousIp(ip)) {
            triggerSecurityAlert("SUSPICIOUS_IP", player, "Login from suspicious IP: " + ip);
        }
    }
    
    public void logPlayerLogout(String player, long sessionDuration) {
        logEvent("PLAYER_LOGOUT", player, String.valueOf(sessionDuration), "Player logged out");
    }
    
    public void logBlockInteraction(String player, String blockType, String coordinates) {
        if (isRestrictedBlock(blockType)) {
            logEvent("RESTRICTED_BLOCK", player, blockType, "Attempted interaction with: " + coordinates);
            triggerSecurityAlert("RESTRICTED_BLOCK", player, blockType);
        }
    }
    
    public void logInventoryChange(String player, String item, int quantity) {
        logEvent("INVENTORY_CHANGE", player, item, "Quantity: " + quantity);
    }
    
    public void logEntityKill(String killer, String victim, String entityType) {
        logEvent("ENTITY_KILL", killer, victim, "Entity type: " + entityType);
    }
    
    public void logTransaction(String player, double amount, String type) {
        logEvent("TRANSACTION", player, type, "Amount: " + amount);
    }
    
    public void logPermissionChange(String player, String permission, String action) {
        logEvent("PERMISSION_CHANGE", player, action, "Permission: " + permission);
    }
    
    public List<AuditEvent> getRecentEvents(int limit) {
        List<AuditEvent> events = new ArrayList<>(auditLog);
        Collections.reverse(events);
        return events.subList(0, Math.min(limit, events.size()));
    }
    
    public List<AuditEvent> getEventsByCategory(String category, int limit) {
        return auditLog.stream()
            .filter(e -> e.getCategory().equals(category))
            .limit(limit)
            .toList();
    }
    
    public List<AuditEvent> getEventsByPlayer(String player, int limit) {
        return auditLog.stream()
            .filter(e -> e.getPlayer().equals(player))
            .limit(limit)
            .toList();
    }
    
    public List<AuditEvent> getEventsByTimeRange(LocalDateTime start, LocalDateTime end) {
        return auditLog.stream()
            .filter(e -> e.getTimestamp().isAfter(start) && e.getTimestamp().isBefore(end))
            .toList();
    }
    
    public Map<String, Integer> getEventSummary() {
        Map<String, Integer> summary = new HashMap<>();
        
        for (AuditEvent event : auditLog) {
            summary.merge(event.getCategory(), 1, Integer::sum);
        }
        
        return summary;
    }
    
    public List<SecurityAlert> getActiveAlerts() {
        return new ArrayList<>(activeAlerts.values());
    }
    
    public void clearAlert(String alertId) {
        activeAlerts.remove(alertId);
    }
    
    private void triggerSecurityAlert(String type, String player, String details) {
        String alertId = type + "_" + System.currentTimeMillis();
        
        SecurityAlert alert = new SecurityAlert(type, player, details);
        activeAlerts.put(alertId, alert);
        
        logger.warn("SECURITY ALERT [{}]: Player: {}, Details: {}", type, player, details);
    }
    
    private boolean isSuspiciousCommand(String command) {
        String[] riskyCommands = {
            "/give", "/setblock", "/summon", "/fill", "/clone",
            "/weather", "/time", "/gamerule", "/spawnpoint",
            "/tp", "/teleport", "/effect", "/enchant"
        };
        
        String lower = command.toLowerCase();
        
        for (String cmd : riskyCommands) {
            if (lower.startsWith(cmd)) {
                return true;
            }
        }
        
        return false;
    }
    
    private boolean isHighRiskCommand(String command) {
        String[] highRisk = {
            "/op", "/deop", "/sudo", "/lp", "/luckperms",
            "/stop", "/restart", "/reload", "/pl", "/plugins"
        };
        
        String lower = command.toLowerCase();
        
        for (String cmd : highRisk) {
            if (lower.startsWith(cmd)) {
                return true;
            }
        }
        
        return false;
    }
    
    private boolean isKnownHacker(String playerName) {
        return false;
    }
    
    private boolean isSuspiciousIp(String ip) {
        String[] suspicious = {"1.2.3.4", "5.6.7.8"};
        
        for (String s : suspicious) {
            if (ip.equals(s)) {
                return true;
            }
        }
        
        return false;
    }
    
    private boolean isRestrictedBlock(String blockType) {
        String[] restricted = {"minecraft:bedrock", "minecraft:command_block", "minecraft:spawner"};
        
        for (String b : restricted) {
            if (blockType.toLowerCase().contains(b)) {
                return true;
            }
        }
        
        return false;
    }
    
    private void cleanupOldEvents() {
        while (auditLog.size() > 10000) {
            auditLog.removeFirst();
        }
        
        LocalDateTime cutoff = LocalDateTime.now().minusDays(7);
        auditLog.removeIf(e -> e.getTimestamp().isBefore(cutoff));
    }
    
    public static class AuditEvent {
        private final String category;
        private final String player;
        private final String action;
        private final String details;
        private final LocalDateTime timestamp;
        
        public AuditEvent(String category, String player, String action, String details) {
            this.category = category;
            this.player = player;
            this.action = action;
            this.details = details;
            this.timestamp = LocalDateTime.now();
        }
        
        public String getCategory() { return category; }
        public String getPlayer() { return player; }
        public String getAction() { return action; }
        public String getDetails() { return details; }
        public LocalDateTime getTimestamp() { return timestamp; }
    }
    
    public static class SecurityAlert {
        private final String type;
        private final String player;
        private final String details;
        private final LocalDateTime timestamp;
        private boolean resolved = false;
        
        public SecurityAlert(String type, String player, String details) {
            this.type = type;
            this.player = player;
            this.details = details;
            this.timestamp = LocalDateTime.now();
        }
        
        public String getType() { return type; }
        public String getPlayer() { return player; }
        public String getDetails() { return details; }
        public LocalDateTime getTimestamp() { return timestamp; }
        public boolean isResolved() { return resolved; }
        public void resolve() { this.resolved = true; }
    }
}
