package com.aluer.world;

import com.aluer.config.ServerGuardConfig;
import com.aluer.service.RconClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

@Component
public class WorldManagementService {
    private static final Logger logger = LoggerFactory.getLogger(WorldManagementService.class);
    
    private final ServerGuardConfig config;
    private final RconClient rconClient;
    private final Map<String, WorldInfo> worlds = new ConcurrentHashMap<>();
    private final List<WorldEdit> editHistory = new ArrayList<>();
    
    public WorldManagementService(ServerGuardConfig config, RconClient rconClient) {
        this.config = config;
        this.rconClient = rconClient;
    }
    
    public void loadWorlds() {
        String output = rconClient.executeCommand("worlds list");
        
        if (output != null && !output.isEmpty()) {
            parseWorldList(output);
        }
    }
    
    private void parseWorldList(String output) {
        String[] lines = output.split("\n");
        
        for (String line : lines) {
            if (line.contains("World:")) {
                String worldName = line.replace("World:", "").trim();
                worlds.put(worldName, new WorldInfo(worldName));
            }
        }
    }
    
    public boolean loadWorld(String worldName) {
        logger.info("Loading world: {}", worldName);
        
        String result = rconClient.executeCommand("world load " + worldName);
        
        WorldEdit edit = new WorldEdit("LOAD", worldName, "World loaded");
        editHistory.add(edit);
        
        return result != null && !result.contains("Error");
    }
    
    public boolean unloadWorld(String worldName) {
        logger.info("Unloading world: {}", worldName);
        
        String result = rconClient.executeCommand("world unload " + worldName);
        
        WorldEdit edit = new WorldEdit("UNLOAD", worldName, "World unloaded");
        editHistory.add(edit);
        
        return result != null && !result.contains("Error");
    }
    
    public boolean createWorld(String worldName, String generator) {
        logger.info("Creating world: {} with generator: {}", worldName, generator);
        
        String result = rconClient.executeCommand("world create " + worldName + " " + generator);
        
        WorldEdit edit = new WorldEdit("CREATE", worldName, "Generator: " + generator);
        editHistory.add(edit);
        
        worlds.put(worldName, new WorldInfo(worldName));
        
        return result != null && !result.contains("Error");
    }
    
    public boolean deleteWorld(String worldName) {
        logger.warn("Deleting world: {}", worldName);
        
        String result = rconClient.executeCommand("world delete " + worldName);
        
        WorldEdit edit = new WorldEdit("DELETE", worldName, "World deleted");
        editHistory.add(edit);
        
        worlds.remove(worldName);
        
        return result != null && !result.contains("Error");
    }
    
    public boolean setWorldBorder(String worldName, int size) {
        logger.info("Setting world border for {}: {}", worldName, size);
        
        rconClient.executeCommand("worldborder set " + size);
        
        WorldEdit edit = new WorldEdit("BORDER", worldName, "Size: " + size);
        editHistory.add(edit);
        
        return true;
    }
    
    public boolean setSpawnPosition(String worldName, int x, int y, int z) {
        logger.info("Setting spawn for {}: {},{},{}", worldName, x, y, z);
        
        rconClient.executeCommand("spawnpoint @a " + x + " " + y + " " + z);
        
        WorldEdit edit = new WorldEdit("SPAWN", worldName, "Position: " + x + "," + y + "," + z);
        editHistory.add(edit);
        
        return true;
    }
    
    public boolean setWorldDifficulty(String worldName, String difficulty) {
        logger.info("Setting difficulty for {}: {}", worldName, difficulty);
        
        rconClient.executeCommand("difficulty " + difficulty);
        
        WorldEdit edit = new WorldEdit("DIFFICULTY", worldName, "Difficulty: " + difficulty);
        editHistory.add(edit);
        
        return true;
    }
    
    public boolean setWorldGameRule(String worldName, String rule, String value) {
        logger.info("Setting gamerule {} = {} for {}", rule, value, worldName);
        
        rconClient.executeCommand("gamerule " + rule + " " + value);
        
        WorldEdit edit = new WorldEdit("GAMERULE", worldName, rule + " = " + value);
        editHistory.add(edit);
        
        return true;
    }
    
    public boolean weather(String worldName, String weather, int duration) {
        logger.info("Setting weather for {}: {} ({} ticks)", worldName, weather, duration);
        
        rconClient.executeCommand("weather " + weather + " " + duration);
        
        WorldEdit edit = new WorldEdit("WEATHER", worldName, weather + " for " + duration);
        editHistory.add(edit);
        
        return true;
    }
    
    public boolean time(String worldName, String time) {
        logger.info("Setting time for {}: {}", worldName, time);
        
        rconClient.executeCommand("time set " + time);
        
        WorldEdit edit = new WorldEdit("TIME", worldName, "Time: " + time);
        editHistory.add(edit);
        
        return true;
    }
    
    public Map<String, WorldInfo> getWorlds() {
        return new HashMap<>(worlds);
    }
    
    public WorldInfo getWorld(String worldName) {
        return worlds.get(worldName);
    }
    
    public List<WorldEdit> getEditHistory() {
        return new ArrayList<>(editHistory);
    }
    
    public List<WorldEdit> getEditHistory(String worldName) {
        return editHistory.stream()
            .filter(e -> e.getWorldName().equals(worldName))
            .toList();
    }
    
    public static class WorldInfo {
        private final String name;
        private int loadedChunks;
        private int loadedEntities;
        private int loadedTileEntities;
        private LocalDateTime lastLoaded;
        
        public WorldInfo(String name) {
            this.name = name;
            this.lastLoaded = LocalDateTime.now();
        }
        
        public String getName() { return name; }
        public int getLoadedChunks() { return loadedChunks; }
        public void setLoadedChunks(int loadedChunks) { this.loadedChunks = loadedChunks; }
        public int getLoadedEntities() { return loadedEntities; }
        public void setLoadedEntities(int loadedEntities) { this.loadedEntities = loadedEntities; }
        public int getLoadedTileEntities() { return loadedTileEntities; }
        public void setLoadedTileEntities(int loadedTileEntities) { this.loadedTileEntities = loadedTileEntities; }
        public LocalDateTime getLastLoaded() { return lastLoaded; }
        public void setLastLoaded(LocalDateTime lastLoaded) { this.lastLoaded = lastLoaded; }
    }
    
    public static class WorldEdit {
        private final String action;
        private final String worldName;
        private final String details;
        private final LocalDateTime timestamp;
        
        public WorldEdit(String action, String worldName, String details) {
            this.action = action;
            this.worldName = worldName;
            this.details = details;
            this.timestamp = LocalDateTime.now();
        }
        
        public String getAction() { return action; }
        public String getWorldName() { return worldName; }
        public String getDetails() { return details; }
        public LocalDateTime getTimestamp() { return timestamp; }
    }
}
