package com.aluer.metrics;

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
public class MetricsCollectionService {
    private static final Logger logger = LoggerFactory.getLogger(MetricsCollectionService.class);
    
    private final ServerGuardConfig config;
    private final RconClient rconClient;
    private final ConcurrentLinkedDeque<ServerMetrics> metricsHistory = new ConcurrentLinkedDeque<>();
    private final Map<String, Counter> counters = new ConcurrentHashMap<>();
    private final Map<String, Gauge> gauges = new ConcurrentHashMap<>();
    
    public MetricsCollectionService(ServerGuardConfig config, RconClient rconClient) {
        this.config = config;
        this.rconClient = rconClient;
    }
    
    public void collect() {
        ServerMetrics metrics = new ServerMetrics();
        
        metrics.setTps(collectTPS());
        metrics.setCpuUsage(collectCpuUsage());
        metrics.setMemoryUsage(collectMemoryUsage());
        metrics.setOnlinePlayers(collectOnlinePlayers());
        metrics.setTickTime(collectTickTime());
        
        metricsHistory.add(metrics);
        
        while (metricsHistory.size() > 10000) {
            metricsHistory.removeFirst();
        }
    }
    
    private double collectTPS() {
        try {
            String output = rconClient.getTps();
            if (output != null && output.contains("TPS:")) {
                String[] parts = output.replace("TPS:", "").split(",");
                return Double.parseDouble(parts[0].trim());
            }
        } catch (Exception e) {
            logger.debug("Failed to collect TPS: {}", e.getMessage());
        }
        return 20.0;
    }
    
    private double collectCpuUsage() {
        try {
            ProcessBuilder pb = new ProcessBuilder("top", "-bn1");
            pb.redirectErrorStream(true);
            Process p = pb.start();
            Scanner scanner = new Scanner(p.getInputStream());
            
            while (scanner.hasNextLine()) {
                String line = scanner.nextLine();
                if (line.contains("Cpu(s)") || line.contains("CPU")) {
                    String[] parts = line.split(",");
                    for (String part : parts) {
                        if (part.contains("id")) {
                            String idle = part.replaceAll("[^0-9.]", "").trim();
                            double idleVal = Double.parseDouble(idle);
                            return 100.0 - idleVal;
                        }
                    }
                }
            }
            scanner.close();
        } catch (Exception e) {
            logger.debug("Failed to collect CPU: {}", e.getMessage());
        }
        return 0.0;
    }
    
    private double collectMemoryUsage() {
        try {
            Runtime runtime = Runtime.getRuntime();
            long total = runtime.totalMemory();
            long free = runtime.freeMemory();
            long used = total - free;
            
            return (used * 100.0) / total;
        } catch (Exception e) {
            logger.debug("Failed to collect memory: {}", e.getMessage());
        }
        return 0.0;
    }
    
    private int collectOnlinePlayers() {
        try {
            String output = rconClient.getOnlinePlayers();
            if (output != null && output.contains("players online")) {
                String[] parts = output.split("of");
                if (parts.length > 0) {
                    String num = parts[0].replaceAll("[^0-9]", "").trim();
                    return Integer.parseInt(num);
                }
            }
        } catch (Exception e) {
            logger.debug("Failed to collect players: {}", e.getMessage());
        }
        return 0;
    }
    
    private double collectTickTime() {
        try {
            String output = rconClient.executeCommand("tick");
            if (output != null && output.contains("avg:")) {
                String[] parts = output.split("avg:");
                if (parts.length > 1) {
                    return Double.parseDouble(parts[1].replace("ms", "").trim());
                }
            }
        } catch (Exception e) {
            logger.debug("Failed to collect tick time: {}", e.getMessage());
        }
        return 0.0;
    }
    
    public void incrementCounter(String name) {
        counters.computeIfAbsent(name, k -> new Counter(name)).increment();
    }
    
    public void incrementCounter(String name, long delta) {
        counters.computeIfAbsent(name, k -> new Counter(name)).increment(delta);
    }
    
    public void setGauge(String name, double value) {
        gauges.put(name, new Gauge(name, value));
    }
    
    public List<ServerMetrics> getMetricsHistory(int limit) {
        List<ServerMetrics> all = new ArrayList<>(metricsHistory);
        Collections.reverse(all);
        return all.subList(0, Math.min(limit, all.size()));
    }
    
    public Map<String, Long> getCounters() {
        Map<String, Long> result = new HashMap<>();
        counters.forEach((name, counter) -> result.put(name, counter.getValue()));
        return result;
    }
    
    public Map<String, Double> getGauges() {
        Map<String, Double> result = new HashMap<>();
        gauges.forEach((name, gauge) -> result.put(name, gauge.getValue()));
        return result;
    }
    
    public Map<String, Object> getSummary() {
        Map<String, Object> summary = new HashMap<>();
        
        List<ServerMetrics> recent = getMetricsHistory(100);
        
        if (!recent.isEmpty()) {
            double avgTps = recent.stream().mapToDouble(ServerMetrics::getTps).average().orElse(20.0);
            double avgCpu = recent.stream().mapToDouble(ServerMetrics::getCpuUsage).average().orElse(0.0);
            double avgMem = recent.stream().mapToDouble(ServerMetrics::getMemoryUsage).average().orElse(0.0);
            int maxPlayers = recent.stream().mapToInt(ServerMetrics::getOnlinePlayers).max().orElse(0);
            
            summary.put("avgTps", avgTps);
            summary.put("avgCpu", avgCpu);
            summary.put("avgMemory", avgMem);
            summary.put("maxPlayers", maxPlayers);
        }
        
        summary.put("counters", getCounters());
        summary.put("gauges", getGauges());
        
        return summary;
    }
    
    public static class ServerMetrics {
        private double tps;
        private double cpuUsage;
        private double memoryUsage;
        private int onlinePlayers;
        private double tickTime;
        private LocalDateTime timestamp;
        
        public ServerMetrics() {
            this.timestamp = LocalDateTime.now();
        }
        
        public double getTps() { return tps; }
        public void setTps(double tps) { this.tps = tps; }
        public double getCpuUsage() { return cpuUsage; }
        public void setCpuUsage(double cpuUsage) { this.cpuUsage = cpuUsage; }
        public double getMemoryUsage() { return memoryUsage; }
        public void setMemoryUsage(double memoryUsage) { this.memoryUsage = memoryUsage; }
        public int getOnlinePlayers() { return onlinePlayers; }
        public void setOnlinePlayers(int onlinePlayers) { this.onlinePlayers = onlinePlayers; }
        public double getTickTime() { return tickTime; }
        public void setTickTime(double tickTime) { this.tickTime = tickTime; }
        public LocalDateTime getTimestamp() { return timestamp; }
    }
    
    public static class Counter {
        private final String name;
        private long value;
        private long lastUpdate;
        
        public Counter(String name) {
            this.name = name;
            this.lastUpdate = System.currentTimeMillis();
        }
        
        public void increment() {
            value++;
            lastUpdate = System.currentTimeMillis();
        }
        
        public void increment(long delta) {
            value += delta;
            lastUpdate = System.currentTimeMillis();
        }
        
        public String getName() { return name; }
        public long getValue() { return value; }
        public long getLastUpdate() { return lastUpdate; }
    }
    
    public static class Gauge {
        private final String name;
        private final double value;
        private final long lastUpdate;
        
        public Gauge(String name, double value) {
            this.name = name;
            this.value = value;
            this.lastUpdate = System.currentTimeMillis();
        }
        
        public String getName() { return name; }
        public double getValue() { return value; }
        public long getLastUpdate() { return lastUpdate; }
    }
}
