package com.aluer.anticheat;

import com.aluer.config.ServerGuardConfig;
import com.aluer.service.RconClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

@Component
public class AntiCheatService {
    private static final Logger logger = LoggerFactory.getLogger(AntiCheatService.class);
    
    private final ServerGuardConfig config;
    private final RconClient rconClient;
    private final Map<String, PlayerCheatData> playerData = new ConcurrentHashMap<>();
    private final List<CheatAlert> alerts = new ArrayList<>();
    
    private static final String[] SUSPICIOUS_COMPOUNDS = {
        "diamond_sword", "diamond_helmet", "diamond_chestplate", 
        "diamond_leggings", "diamond_boots", "netherite_"
    };
    
    private static final String[] SPEED_HACK_PATTERNS = {
        "fly", "speed", "jesus", "waterwalk"
    };
    
    private static final String[] KILLAURA_PATTERNS = {
        "hit", "attack", "reach", "crit"
    };

    public AntiCheatService(ServerGuardConfig config, RconClient rconClient) {
        this.config = config;
        this.rconClient = rconClient;
    }
    
    public void recordPlayerMovement(String playerName, double x, double y, double z, boolean onGround) {
        PlayerCheatData data = playerData.computeIfAbsent(playerName, k -> new PlayerCheatData(playerName));
        
        data.recordPosition(x, y, z, onGround);
        
        checkSpeedHack(playerName, data);
        checkFlyHack(playerName, data);
    }
    
    public void recordPlayerCombat(String playerName, String target, double damage) {
        PlayerCheatData data = playerData.computeIfAbsent(playerName, k -> new PlayerCheatData(playerName));
        
        data.recordAttack(target, damage);
        
        checkReachHack(playerName, data);
        checkKillAura(data);
    }
    
    public void recordPlayerInventory(String playerName, String item, int slot) {
        PlayerCheatData data = playerData.computeIfAbsent(playerName, k -> new PlayerCheatData(playerName));
        
        data.recordInventoryChange(item, slot);
        
        checkInventoryHack(playerName, data);
    }
    
    public void recordBlockPlace(String playerName, String blockType, int x, int y, int z) {
        PlayerCheatData data = playerData.computeIfAbsent(playerName, k -> new PlayerCheatData(playerName));
        
        data.recordBlockPlace(blockType, x, y, z);
        
        checkScaffold(playerName, data);
    }
    
    private void checkSpeedHack(String playerName, PlayerCheatData data) {
        double speed = data.getMovementSpeed();
        
        if (speed > 0.5) {
            addAlert(playerName, "SpeedHack", "Movement speed: " + speed, 0.7);
        }
    }
    
    private void checkFlyHack(String playerName, PlayerCheatData data) {
        if (data.isFlying() && !data.hasBlockBelow()) {
            addAlert(playerName, "FlyHack", "Flying without ground", 0.8);
        }
        
        if (data.getVerticalSpeed() > 0.3) {
            addAlert(playerName, "FlyHack", "Vertical speed: " + data.getVerticalSpeed(), 0.6);
        }
    }
    
    private void checkReachHack(String playerName, PlayerCheatData data) {
        double reach = data.getAttackReach();
        
        if (reach > 3.5) {
            addAlert(playerName, "ReachHack", "Attack reach: " + reach, 0.75);
        }
    }
    
    private void checkKillAura(PlayerCheatData data) {
        int attacksPerSecond = data.getAttacksPerSecond();
        
        if (attacksPerSecond > 15) {
            addAlert(data.getPlayerName(), "KillAura", "APS: " + attacksPerSecond, 0.7);
        }
    }
    
    private void checkInventoryHack(String playerName, PlayerCheatData data) {
        for (String item : SUSPICIOUS_COMPOUNDS) {
            if (data.hasItem(item)) {
                addAlert(playerName, "InventoryHack", "Suspicious item: " + item, 0.5);
            }
        }
    }
    
    private void checkScaffold(String playerName, PlayerCheatData data) {
        int blocksPerSecond = data.getBlocksPerSecond();
        
        if (blocksPerSecond > 20) {
            addAlert(playerName, "Scaffold", "Blocks/sec: " + blocksPerSecond, 0.6);
        }
    }
    
    private void addAlert(String playerName, String cheatType, String details, double confidence) {
        CheatAlert alert = new CheatAlert(playerName, cheatType, details, confidence);
        alerts.add(alert);
        
        logger.warn("作弊检测 [{}]: 玩家: {}, 详情: {}, 置信度: {:.0f}%", 
            cheatType, playerName, details, confidence * 100);
        
        while (alerts.size() > 500) {
            alerts.remove(0);
        }
    }
    
    public List<CheatAlert> getAlerts() {
        return new ArrayList<>(alerts);
    }
    
    public List<CheatAlert> getAlerts(String playerName) {
        return alerts.stream()
            .filter(a -> a.getPlayerName().equals(playerName))
            .toList();
    }
    
    public PlayerCheatData getPlayerData(String playerName) {
        return playerData.get(playerName);
    }
    
    public static class PlayerCheatData {
        private final String playerName;
        private final List<PositionRecord> positions = new ArrayList<>();
        private final List<AttackRecord> attacks = new ArrayList<>();
        private final List<String> inventory = new ArrayList<>(36);
        private int blockPlacements = 0;
        
        public PlayerCheatData(String playerName) {
            this.playerName = playerName;
        }
        
        public void recordPosition(double x, double y, double z, boolean onGround) {
            positions.add(new PositionRecord(x, y, z, onGround));
            
            while (positions.size() > 100) {
                positions.remove(0);
            }
        }
        
        public void recordAttack(String target, double damage) {
            attacks.add(new AttackRecord(target, damage));
            
            while (attacks.size() > 50) {
                attacks.remove(0);
            }
        }
        
        public void recordInventoryChange(String item, int slot) {
            if (inventory.size() <= slot) {
                while (inventory.size() <= slot) {
                    inventory.add(null);
                }
            }
            inventory.set(slot, item);
        }
        
        public void recordBlockPlace(String blockType, int x, int y, int z) {
            blockPlacements++;
        }
        
        public double getMovementSpeed() {
            if (positions.size() < 2) return 0;
            
            PositionRecord last = positions.get(positions.size() - 1);
            PositionRecord prev = positions.get(positions.size() - 2);
            
            double dx = last.x - prev.x;
            double dz = last.z - prev.z;
            
            return Math.sqrt(dx * dx + dz * dz);
        }
        
        public double getVerticalSpeed() {
            if (positions.size() < 2) return 0;
            
            PositionRecord last = positions.get(positions.size() - 1);
            PositionRecord prev = positions.get(positions.size() - 2);
            
            return Math.abs(last.y - prev.y);
        }
        
        public boolean isFlying() {
            return positions.stream()
                .anyMatch(p -> p.y > 0.1);
        }
        
        public boolean hasBlockBelow() {
            return positions.stream()
                .anyMatch(p -> !p.onGround);
        }
        
        public double getAttackReach() {
            return 3.0 + Math.random() * 0.5;
        }
        
        public int getAttacksPerSecond() {
            return attacks.size();
        }
        
        public int getBlocksPerSecond() {
            return blockPlacements;
        }
        
        public boolean hasItem(String item) {
            return inventory.stream()
                .anyMatch(i -> i != null && i.contains(item));
        }
        
        public String getPlayerName() { return playerName; }
    }
    
    public static class PositionRecord {
        private final double x, y, z;
        private final boolean onGround;
        private final long timestamp;
        
        public PositionRecord(double x, double y, double z, boolean onGround) {
            this.x = x;
            this.y = y;
            this.z = z;
            this.onGround = onGround;
            this.timestamp = System.currentTimeMillis();
        }
        
        public double getX() { return x; }
        public double getY() { return y; }
        public double getZ() { return z; }
        public boolean isOnGround() { return onGround; }
        public long getTimestamp() { return timestamp; }
    }
    
    public static class AttackRecord {
        private final String target;
        private final double damage;
        private final long timestamp;
        
        public AttackRecord(String target, double damage) {
            this.target = target;
            this.damage = damage;
            this.timestamp = System.currentTimeMillis();
        }
        
        public String getTarget() { return target; }
        public double getDamage() { return damage; }
        public long getTimestamp() { return timestamp; }
    }
    
    public static class CheatAlert {
        private final String playerName;
        private final String cheatType;
        private final String details;
        private final double confidence;
        private final LocalDateTime timestamp;
        
        public CheatAlert(String playerName, String cheatType, String details, double confidence) {
            this.playerName = playerName;
            this.cheatType = cheatType;
            this.details = details;
            this.confidence = confidence;
            this.timestamp = LocalDateTime.now();
        }
        
        public String getPlayerName() { return playerName; }
        public String getCheatType() { return cheatType; }
        public String getDetails() { return details; }
        public double getConfidence() { return confidence; }
        public LocalDateTime getTimestamp() { return timestamp; }
    }
}
