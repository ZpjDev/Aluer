package com.aluer.profiler;

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
public class PerformanceProfiler {
    private static final Logger logger = LoggerFactory.getLogger(PerformanceProfiler.class);
    
    private final ServerGuardConfig config;
    private final RconClient rconClient;
    private final ConcurrentLinkedDeque<TickData> tickHistory = new ConcurrentLinkedDeque<>();
    private final Map<String, ConcurrentLinkedDeque<EntityData>> entityHistory = new ConcurrentHashMap<>();
    private final ConcurrentLinkedDeque<MemorySnapshot> memoryHistory = new ConcurrentLinkedDeque<>();
    private final Map<String, ChunkData> chunkData = new ConcurrentHashMap<>();
    
    public PerformanceProfiler(ServerGuardConfig config, RconClient rconClient) {
        this.config = config;
        this.rconClient = rconClient;
    }
    
    public void recordTick(double tps, double tickTime) {
        TickData data = new TickData(tps, tickTime);
        tickHistory.add(data);
        
        while (tickHistory.size() > 1000) {
            tickHistory.removeFirst();
        }
    }
    
    public void recordEntityCount(String world, String entityType, int count) {
        EntityData data = new EntityData(world, entityType, count);
        
        entityHistory.computeIfAbsent(world, k -> new ConcurrentLinkedDeque<>()).add(data);
        
        ConcurrentLinkedDeque<EntityData> history = entityHistory.get(world);
        while (history.size() > 500) {
            history.removeFirst();
        }
    }
    
    public void recordMemory(long used, long max, long free) {
        MemorySnapshot snapshot = new MemorySnapshot(used, max, free);
        memoryHistory.add(snapshot);
        
        while (memoryHistory.size() > 500) {
            memoryHistory.removeFirst();
        }
    }
    
    public void recordChunkLoad(String world, int chunks) {
        ChunkData data = chunkData.computeIfAbsent(world, k -> new ChunkData(world));
        data.addLoadedChunks(chunks);
    }
    
    public TickStats getTickStats() {
        if (tickHistory.isEmpty()) {
            return new TickStats();
        }
        
        List<TickData> recent = new ArrayList<>(tickHistory);
        
        double avgTps = recent.stream().mapToDouble(TickData::getTps).average().orElse(20.0);
        double avgTickTime = recent.stream().mapToDouble(TickData::getTickTime).average().orElse(0.0);
        
        double minTps = recent.stream().mapToDouble(TickData::getTps).min().orElse(20.0);
        double maxTps = recent.stream().mapToDouble(TickData::getTps).max().orElse(20.0);
        
        int goodTicks = (int) recent.stream().filter(t -> t.getTps() >= 18).count();
        int lagTicks = (int) recent.stream().filter(t -> t.getTps() < 15).count();
        
        return new TickStats(avgTps, avgTickTime, minTps, maxTps, goodTicks, lagTicks);
    }
    
    public Map<String, EntityStats> getEntityStats() {
        Map<String, EntityStats> stats = new HashMap<>();
        
        entityHistory.forEach((world, dataList) -> {
            List<EntityData> recent = new ArrayList<>(dataList);
            
            if (!recent.isEmpty()) {
                double avg = recent.stream().mapToInt(EntityData::getCount).average().orElse(0);
                int max = recent.stream().mapToInt(EntityData::getCount).max().orElse(0);
                
                stats.put(world, new EntityStats(world, avg, max, recent.size()));
            }
        });
        
        return stats;
    }
    
    public MemoryStats getMemoryStats() {
        if (memoryHistory.isEmpty()) {
            return new MemoryStats();
        }
        
        List<MemorySnapshot> recent = new ArrayList<>(memoryHistory);
        
        long avgUsed = recent.stream().mapToLong(MemorySnapshot::getUsed).sum() / recent.size();
        long avgMax = recent.stream().mapToLong(MemorySnapshot::getMax).sum() / recent.size();
        
        double usagePercent = (avgUsed * 100.0) / avgMax;
        
        return new MemoryStats(avgUsed, avgMax, usagePercent);
    }
    
    public ChunkStats getChunkStats() {
        Map<String, ChunkStats> stats = new HashMap<>();
        
        chunkData.forEach((world, data) -> {
            stats.put(world, new ChunkStats(world, data.getLoadedChunks(), data.getUnloadedChunks()));
        });
        
        return new ChunkStats("total", 
            stats.values().stream().mapToInt(ChunkStats::getLoadedChunks).sum(),
            stats.values().stream().mapToInt(ChunkStats::getUnloadedChunks).sum()
        );
    }
    
    public List<String> getOptimizationSuggestions() {
        List<String> suggestions = new ArrayList<>();
        
        TickStats tick = getTickStats();
        
        if (tick.getAvgTps() < 15) {
            suggestions.add("CRITICAL: TPS is very low (<15). Consider reducing entity count or world load.");
        } else if (tick.getAvgTps() < 18) {
            suggestions.add("WARNING: TPS is below optimal (<18). Monitor entity spawn rates.");
        }
        
        MemoryStats mem = getMemoryStats();
        
        if (mem.getUsagePercent() > 85) {
            suggestions.add("CRITICAL: Memory usage is very high (" + (int)mem.getUsagePercent() + "%). Consider increasing JVM heap.");
        } else if (mem.getUsagePercent() > 70) {
            suggestions.add("WARNING: Memory usage is high (" + (int)mem.getUsagePercent() + "%). Monitor for leaks.");
        }
        
        getEntityStats().forEach((world, stats) -> {
            if (stats.getMaxCount() > 1000) {
                suggestions.add("World '" + world + "' has high entity count: " + stats.getMaxCount());
            }
        });
        
        if (suggestions.isEmpty()) {
            suggestions.add("Server performance is optimal.");
        }
        
        return suggestions;
    }
    
    public static class TickData {
        private final double tps;
        private final double tickTime;
        private final LocalDateTime timestamp;
        
        public TickData(double tps, double tickTime) {
            this.tps = tps;
            this.tickTime = tickTime;
            this.timestamp = LocalDateTime.now();
        }
        
        public double getTps() { return tps; }
        public double getTickTime() { return tickTime; }
        public LocalDateTime getTimestamp() { return timestamp; }
    }
    
    public static class EntityData {
        private final String world;
        private final String entityType;
        private final int count;
        private final LocalDateTime timestamp;
        
        public EntityData(String world, String entityType, int count) {
            this.world = world;
            this.entityType = entityType;
            this.count = count;
            this.timestamp = LocalDateTime.now();
        }
        
        public String getWorld() { return world; }
        public String getEntityType() { return entityType; }
        public int getCount() { return count; }
        public LocalDateTime getTimestamp() { return timestamp; }
    }
    
    public static class MemorySnapshot {
        private final long used;
        private final long max;
        private final long free;
        private final LocalDateTime timestamp;
        
        public MemorySnapshot(long used, long max, long free) {
            this.used = used;
            this.max = max;
            this.free = free;
            this.timestamp = LocalDateTime.now();
        }
        
        public long getUsed() { return used; }
        public long getMax() { return max; }
        public long getFree() { return free; }
        public LocalDateTime getTimestamp() { return timestamp; }
    }
    
    public static class ChunkData {
        private final String world;
        private int loadedChunks = 0;
        private int unloadedChunks = 0;
        
        public ChunkData(String world) {
            this.world = world;
        }
        
        public void addLoadedChunks(int count) { this.loadedChunks += count; }
        public void addUnloadedChunks(int count) { this.unloadedChunks += count; }
        public String getWorld() { return world; }
        public int getLoadedChunks() { return loadedChunks; }
        public int getUnloadedChunks() { return unloadedChunks; }
    }
    
    public static class TickStats {
        private final double avgTps;
        private final double avgTickTime;
        private final double minTps;
        private final double maxTps;
        private final int goodTicks;
        private final int lagTicks;
        
        public TickStats() {
            this(20.0, 0, 20.0, 20.0, 100, 0);
        }
        
        public TickStats(double avgTps, double avgTickTime, double minTps, double maxTps, int goodTicks, int lagTicks) {
            this.avgTps = avgTps;
            this.avgTickTime = avgTickTime;
            this.minTps = minTps;
            this.maxTps = maxTps;
            this.goodTicks = goodTicks;
            this.lagTicks = lagTicks;
        }
        
        public double getAvgTps() { return avgTps; }
        public double getAvgTickTime() { return avgTickTime; }
        public double getMinTps() { return minTps; }
        public double getMaxTps() { return maxTps; }
        public int getGoodTicks() { return goodTicks; }
        public int getLagTicks() { return lagTicks; }
    }
    
    public static class EntityStats {
        private final String world;
        private final double avgCount;
        private final int maxCount;
        private final int samples;
        
        public EntityStats(String world, double avgCount, int maxCount, int samples) {
            this.world = world;
            this.avgCount = avgCount;
            this.maxCount = maxCount;
            this.samples = samples;
        }
        
        public String getWorld() { return world; }
        public double getAvgCount() { return avgCount; }
        public int getMaxCount() { return maxCount; }
        public int getSamples() { return samples; }
    }
    
    public static class MemoryStats {
        private final long avgUsed;
        private final long avgMax;
        private final double usagePercent;
        
        public MemoryStats() {
            this(0, 1, 0);
        }
        
        public MemoryStats(long avgUsed, long avgMax, double usagePercent) {
            this.avgUsed = avgUsed;
            this.avgMax = avgMax;
            this.usagePercent = usagePercent;
        }
        
        public long getAvgUsed() { return avgUsed; }
        public long getAvgMax() { return avgMax; }
        public double getUsagePercent() { return usagePercent; }
    }
    
    public static class ChunkStats {
        private final String world;
        private final int loadedChunks;
        private final int unloadedChunks;
        
        public ChunkStats(String world, int loadedChunks, int unloadedChunks) {
            this.world = world;
            this.loadedChunks = loadedChunks;
            this.unloadedChunks = unloadedChunks;
        }
        
        public String getWorld() { return world; }
        public int getLoadedChunks() { return loadedChunks; }
        public int getUnloadedChunks() { return unloadedChunks; }
    }
}
