package com.aluer.monitor;

import com.aluer.config.ServerGuardConfig;
import com.aluer.model.AlertEvent;
import com.aluer.model.AlertType;
import com.aluer.model.MetricsData;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

@Component
public class ResourceMonitor {
    private static final Logger logger = LoggerFactory.getLogger(ResourceMonitor.class);
    
    private final ServerGuardConfig config;
    private static final Pattern CPU_PATTERN = Pattern.compile("(\\d+\\.?\\d*)%");
    private static final Pattern MEM_PATTERN = Pattern.compile("(\\d+)kB");

    public ResourceMonitor(ServerGuardConfig config) {
        this.config = config;
    }

    public MetricsData collectMetrics() {
        MetricsData data = new MetricsData();
        
        try {
            String javaProc = findJavaProcess();
            if (javaProc.isEmpty()) {
                logger.warn("No Java process found for Minecraft");
                return data;
            }

            data.setCpuUsage(getCpuUsage(javaProc));
            data.setMemoryUsage(getMemoryUsage(javaProc));
            data.setTps(collectTPS());
            data.setTickTime(collectTickTime());
            data.setConnections(countConnections());
            data.setOnlinePlayers(collectOnlinePlayers());
            
        } catch (Exception e) {
            logger.error("Error collecting metrics: {}", e.getMessage());
        }
        
        return data;
    }

    private String findJavaProcess() {
        try {
            ProcessBuilder pb = new ProcessBuilder("pgrep", "-f", config.getMinecraft().getProcessName());
            pb.redirectErrorStream(true);
            Process p = pb.start();
            BufferedReader reader = new BufferedReader(new InputStreamReader(p.getInputStream()));
            String pid = reader.readLine();
            p.waitFor();
            return pid != null ? pid.trim() : "";
        } catch (Exception e) {
            return "";
        }
    }

    private double getCpuUsage(String pid) {
        try {
            ProcessBuilder pb = new ProcessBuilder("ps", "-p", pid, "-o", "%cpu");
            pb.redirectErrorStream(true);
            Process p = pb.start();
            BufferedReader reader = new BufferedReader(new InputStreamReader(p.getInputStream()));
            List<String> lines = reader.lines().collect(Collectors.toList());
            p.waitFor();
            
            if (lines.size() >= 2) {
                String cpuStr = lines.get(1).trim();
                return Double.parseDouble(cpuStr);
            }
        } catch (Exception e) {
            logger.debug("Failed to get CPU usage: {}", e.getMessage());
        }
        return 0.0;
    }

    private double getMemoryUsage(String pid) {
        try {
            ProcessBuilder pb = new ProcessBuilder("ps", "-p", pid, "-o", "rss=");
            pb.redirectErrorStream(true);
            Process p = pb.start();
            BufferedReader reader = new BufferedReader(new InputStreamReader(p.getInputStream()));
            String memStr = reader.readLine();
            p.waitFor();
            
            if (memStr != null && !memStr.trim().isEmpty()) {
                long rssKb = Long.parseLong(memStr.trim());
                long totalMemKb = Runtime.getRuntime().totalMemory() / 1024;
                long usedMemKb = Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory();
                return (usedMemKb * 100.0) / totalMemKb;
            }
        } catch (Exception e) {
            logger.debug("Failed to get memory usage: {}", e.getMessage());
        }
        return 0.0;
    }

    private double collectTPS() {
        try {
            ProcessBuilder pb = new ProcessBuilder("rcon-cli", "tps");
            pb.redirectErrorStream(true);
            Process p = pb.start();
            BufferedReader reader = new BufferedReader(new InputStreamReader(p.getInputStream()));
            String output = reader.readLine();
            p.waitFor();
            
            if (output != null && output.contains("TPS")) {
                String[] parts = output.replace("TPS: ", "").split(",");
                return Double.parseDouble(parts[0].trim());
            }
        } catch (Exception e) {
            logger.debug("Failed to collect TPS via rcon: {}", e.getMessage());
        }
        return 20.0;
    }

    private double collectTickTime() {
        try {
            ProcessBuilder pb = new ProcessBuilder("rcon-cli", "tick");
            pb.redirectErrorStream(true);
            Process p = pb.start();
            BufferedReader reader = new BufferedReader(new InputStreamReader(p.getInputStream()));
            String output = reader.readLine();
            p.waitFor();
            
            if (output != null && output.contains("tick avg:")) {
                String[] parts = output.split("tick avg:");
                if (parts.length > 1) {
                    return Double.parseDouble(parts[1].trim().replace(" ms", ""));
                }
            }
        } catch (Exception e) {
            logger.debug("Failed to collect tick time: {}", e.getMessage());
        }
        return 0.0;
    }

    private int countConnections() {
        try {
            String logPath = config.getMonitor().getLogPath();
            ProcessBuilder pb = new ProcessBuilder("ss", "-tn");
            pb.redirectErrorStream(true);
            Process p = pb.start();
            BufferedReader reader = new BufferedReader(new InputStreamReader(p.getInputStream()));
            long count = reader.lines().filter(line -> line.contains("25565")).count();
            p.waitFor();
            return (int) count;
        } catch (Exception e) {
            logger.debug("Failed to count connections: {}", e.getMessage());
        }
        return 0;
    }

    private int collectOnlinePlayers() {
        try {
            ProcessBuilder pb = new ProcessBuilder("rcon-cli", "list");
            pb.redirectErrorStream(true);
            Process p = pb.start();
            BufferedReader reader = new BufferedReader(new InputStreamReader(p.getInputStream()));
            String output = reader.readLine();
            p.waitFor();
            
            if (output != null && output.contains("players online")) {
                Pattern pattern = Pattern.compile("(\\d+)\\s+of\\s+(\\d+)\\s+players");
                Matcher matcher = pattern.matcher(output);
                if (matcher.find()) {
                    return Integer.parseInt(matcher.group(1));
                }
            }
        } catch (Exception e) {
            logger.debug("Failed to collect online players: {}", e.getMessage());
        }
        return 0;
    }

    public List<AlertEvent> checkThresholds(MetricsData data) {
        List<AlertEvent> alerts = new ArrayList<>();
        
        if (data.getTps() < config.getMonitor().getTpsThreshold()) {
            AlertEvent alert = new AlertEvent(AlertType.TPS_LOW, 
                String.format("TPS %.1f below threshold %d", data.getTps(), config.getMonitor().getTpsThreshold()));
            alert.setConfidence(0.9);
            alerts.add(alert);
        }
        
        if (data.getCpuUsage() > config.getMonitor().getCpuThreshold()) {
            AlertEvent alert = new AlertEvent(AlertType.CPU_HIGH, 
                String.format("CPU %.1f%% above threshold %.0f%%", data.getCpuUsage(), config.getMonitor().getCpuThreshold()));
            alert.setConfidence(0.85);
            alerts.add(alert);
        }
        
        if (data.getMemoryUsage() > config.getMonitor().getMemoryThreshold()) {
            AlertEvent alert = new AlertEvent(AlertType.MEM_HIGH, 
                String.format("Memory %.1f%% above threshold %.0f%%", data.getMemoryUsage(), config.getMonitor().getMemoryThreshold()));
            alert.setConfidence(0.85);
            alerts.add(alert);
        }
        
        return alerts;
    }
}
