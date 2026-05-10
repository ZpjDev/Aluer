package com.aluer.punishment;

import com.aluer.config.ServerGuardConfig;
import com.aluer.service.RconClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

@Component
public class PunishmentService {
    private static final Logger logger = LoggerFactory.getLogger(PunishmentService.class);
    
    private final ServerGuardConfig config;
    private final RconClient rconClient;
    private final Map<String, Punishment> punishments = new ConcurrentHashMap<>();
    private final Map<String, List<Punishment>> playerPunishments = new ConcurrentHashMap<>();
    
    public PunishmentService(ServerGuardConfig config, RconClient rconClient) {
        this.config = config;
        this.rconClient = rconClient;
    }
    
    public String banPlayer(String playerName, String reason, String duration, String moderator) {
        String command = duration == null 
            ? "ban " + playerName + " " + reason
            : "tempban " + playerName + " " + duration + " " + reason;
        
        rconClient.executeCommand(command);
        
        Punishment punishment = new Punishment(playerName, "BAN", reason, duration, moderator);
        punishments.put(punishment.getId(), punishment);
        
        playerPunishments.computeIfAbsent(playerName, k -> new ArrayList<>()).add(punishment);
        
        logger.info("Player {} banned by {} for {} - {}", playerName, moderator, duration, reason);
        
        return punishment.getId();
    }
    
    public String mutePlayer(String playerName, String reason, String duration, String moderator) {
        String command = duration == null
            ? "mute " + playerName + " " + reason
            : "tempmute " + playerName + " " + duration + " " + reason;
        
        rconClient.executeCommand(command);
        
        Punishment punishment = new Punishment(playerName, "MUTE", reason, duration, moderator);
        punishments.put(punishment.getId(), punishment);
        
        playerPunishments.computeIfAbsent(playerName, k -> new ArrayList<>()).add(punishment);
        
        logger.info("Player {} muted by {} for {} - {}", playerName, moderator, duration, reason);
        
        return punishment.getId();
    }
    
    public String kickPlayer(String playerName, String reason, String moderator) {
        rconClient.kickPlayer(playerName, reason);
        
        Punishment punishment = new Punishment(playerName, "KICK", reason, null, moderator);
        punishments.put(punishment.getId(), punishment);
        
        playerPunishments.computeIfAbsent(playerName, k -> new ArrayList<>()).add(punishment);
        
        logger.info("Player {} kicked by {} - {}", playerName, moderator, reason);
        
        return punishment.getId();
    }
    
    public String warnPlayer(String playerName, String reason, String moderator) {
        rconClient.executeCommand("warn " + playerName + " " + reason);
        
        Punishment punishment = new Punishment(playerName, "WARN", reason, null, moderator);
        punishments.put(punishment.getId(), punishment);
        
        playerPunishments.computeIfAbsent(playerName, k -> new ArrayList<>()).add(punishment);
        
        logger.info("Player {} warned by {} - {}", playerName, moderator, reason);
        
        return punishment.getId();
    }
    
    public boolean unbanPlayer(String playerName) {
        rconClient.executeCommand("pardon " + playerName);
        
        List<Punishment> playerPunishList = playerPunishments.get(playerName);
        if (playerPunishList != null) {
            for (Punishment p : playerPunishList) {
                if ("BAN".equals(p.getType())) {
                    p.setActive(false);
                    p.setUnbannedAt(LocalDateTime.now());
                }
            }
        }
        
        logger.info("Player {} unbanned", playerName);
        
        return true;
    }
    
    public boolean unmutePlayer(String playerName) {
        rconClient.executeCommand("unmute " + playerName);
        
        List<Punishment> playerPunishList = playerPunishments.get(playerName);
        if (playerPunishList != null) {
            for (Punishment p : playerPunishList) {
                if ("MUTE".equals(p.getType()) && p.isActive()) {
                    p.setActive(false);
                }
            }
        }
        
        logger.info("Player {} unmuted", playerName);
        
        return true;
    }
    
    public List<Punishment> getPlayerPunishments(String playerName) {
        return playerPunishments.getOrDefault(playerName, new ArrayList<>());
    }
    
    public List<Punishment> getActiveBans() {
        return punishments.values().stream()
            .filter(p -> "BAN".equals(p.getType()) && p.isActive())
            .toList();
    }
    
    public List<Punishment> getActiveMutes() {
        return punishments.values().stream()
            .filter(p -> "MUTE".equals(p.getType()) && p.isActive())
            .toList();
    }
    
    public Punishment getPunishment(String id) {
        return punishments.get(id);
    }
    
    public void removeExpiredPunishments() {
        LocalDateTime now = LocalDateTime.now();
        
        for (Punishment p : punishments.values()) {
            if (p.isActive() && p.getExpiresAt() != null && p.getExpiresAt().isBefore(now)) {
                p.setActive(false);
                
                if ("BAN".equals(p.getType())) {
                    unbanPlayer(p.getPlayerName());
                } else if ("MUTE".equals(p.getType())) {
                    unmutePlayer(p.getPlayerName());
                }
                
                logger.info("Expired punishment {} for player {}", p.getType(), p.getPlayerName());
            }
        }
    }
    
    public Map<String, Object> getPunishmentStatistics() {
        Map<String, Object> stats = new HashMap<>();
        
        stats.put("totalPunishments", punishments.size());
        stats.put("activeBans", getActiveBans().size());
        stats.put("activeMutes", getActiveMutes().size());
        stats.put("totalBans", punishments.values().stream().filter(p -> "BAN".equals(p.getType())).count());
        stats.put("totalMutes", punishments.values().stream().filter(p -> "MUTE".equals(p.getType())).count());
        stats.put("totalKicks", punishments.values().stream().filter(p -> "KICK".equals(p.getType())).count());
        stats.put("totalWarns", punishments.values().stream().filter(p -> "WARN".equals(p.getType())).count());
        
        return stats;
    }
    
    public static class Punishment {
        private final String id;
        private final String playerName;
        private final String type;
        private final String reason;
        private final String duration;
        private final String moderator;
        private final LocalDateTime createdAt;
        private LocalDateTime expiresAt;
        private LocalDateTime unbannedAt;
        private boolean active = true;
        
        public Punishment(String playerName, String type, String reason, String duration, String moderator) {
            this.id = type + "_" + System.currentTimeMillis();
            this.playerName = playerName;
            this.type = type;
            this.reason = reason;
            this.duration = duration;
            this.moderator = moderator;
            this.createdAt = LocalDateTime.now();
            
            if (duration != null) {
                this.expiresAt = calculateExpiry(duration);
            }
        }
        
        private LocalDateTime calculateExpiry(String duration) {
            try {
                int amount = Integer.parseInt(duration.replaceAll("[^0-9]", ""));
                String unit = duration.replaceAll("[0-9]", "").toLowerCase();
                
                if (unit.contains("m")) {
                    return createdAt.plusMinutes(amount);
                } else if (unit.contains("h")) {
                    return createdAt.plusHours(amount);
                } else if (unit.contains("d")) {
                    return createdAt.plusDays(amount);
                } else if (unit.contains("w")) {
                    return createdAt.plusWeeks(amount);
                } else if (unit.contains("y")) {
                    return createdAt.plusYears(amount);
                }
            } catch (Exception e) {
                logger.error("Failed to parse duration: {}", duration);
            }
            
            return null;
        }
        
        public String getId() { return id; }
        public String getPlayerName() { return playerName; }
        public String getType() { return type; }
        public String getReason() { return reason; }
        public String getDuration() { return duration; }
        public String getModerator() { return moderator; }
        public LocalDateTime getCreatedAt() { return createdAt; }
        public LocalDateTime getExpiresAt() { return expiresAt; }
        public LocalDateTime getUnbannedAt() { return unbannedAt; }
        public boolean isActive() { return active; }
        public void setActive(boolean active) { this.active = active; }
        public void setUnbannedAt(LocalDateTime unbannedAt) { this.unbannedAt = unbannedAt; }
    }
}
