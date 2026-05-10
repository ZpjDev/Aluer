package com.aluer.monitor;

import com.aluer.config.ServerGuardConfig;
import com.aluer.model.AlertEvent;
import com.aluer.model.AlertType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

@Component
public class ConnectionMonitor {
    private static final Logger logger = LoggerFactory.getLogger(ConnectionMonitor.class);
    
    private final ServerGuardConfig config;
    private final Map<String, Integer> ipConnectionCount = new ConcurrentHashMap<>();
    private final Map<String, Long> lastConnectionTime = new ConcurrentHashMap<>();
    private final List<String> bannedIps = Collections.synchronizedList(new ArrayList<>());
    
    private static final Pattern IP_PATTERN = Pattern.compile("\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b");

    public ConnectionMonitor(ServerGuardConfig config) {
        this.config = config;
    }

    public Map<String, Integer> getActiveConnections() {
        Map<String, Integer> connections = new HashMap<>();
        try {
            ProcessBuilder pb = new ProcessBuilder("ss", "-tn", "sport", "=", "25565");
            pb.redirectErrorStream(true);
            Process p = pb.start();
            BufferedReader reader = new BufferedReader(new InputStreamReader(p.getInputStream()));
            
            String line;
            while ((line = reader.readLine()) != null) {
                Matcher matcher = IP_PATTERN.matcher(line);
                if (matcher.find()) {
                    String ip = matcher.group();
                    connections.merge(ip, 1, Integer::sum);
                }
            }
            p.waitFor();
            
        } catch (Exception e) {
            logger.error("Failed to get active connections: {}", e.getMessage());
        }
        return connections;
    }

    public int getTotalConnections() {
        return getActiveConnections().values().stream().mapToInt(Integer::intValue).sum();
    }

    public List<String> detectConnectionFlood() {
        List<String> floodIps = new ArrayList<>();
        Map<String, Integer> connections = getActiveConnections();
        int threshold = config.getMonitor().getConnectionThreshold();
        
        connections.forEach((ip, count) -> {
            if (count > threshold) {
                floodIps.add(ip);
                if (!bannedIps.contains(ip)) {
                    banIp(ip, "Connection flood detected: " + count + " connections");
                }
            }
        });
        
        return floodIps;
    }

    public boolean banIp(String ip, String reason) {
        try {
            ProcessBuilder pb = new ProcessBuilder("rcon-cli", "ban-ip", ip);
            pb.redirectErrorStream(true);
            Process p = pb.start();
            p.waitFor();
            
            if (p.exitValue() == 0) {
                bannedIps.add(ip);
                logger.warn("Banned IP {} - {}", ip, reason);
                return true;
            }
        } catch (Exception e) {
            logger.error("Failed to ban IP {}: {}", ip, e.getMessage());
        }
        return false;
    }

    public boolean unbanIp(String ip) {
        try {
            ProcessBuilder pb = new ProcessBuilder("rcon-cli", "pardon-ip", ip);
            pb.redirectErrorStream(true);
            Process p = pb.start();
            p.waitFor();
            
            if (p.exitValue() == 0) {
                bannedIps.remove(ip);
                return true;
            }
        } catch (Exception e) {
            logger.error("Failed to unban IP {}: {}", ip, e.getMessage());
        }
        return false;
    }

    public List<String> getBannedIps() {
        return new ArrayList<>(bannedIps);
    }

    public AlertEvent checkConnectionFlood() {
        List<String> floodIps = detectConnectionFlood();
        if (!floodIps.isEmpty()) {
            AlertEvent alert = new AlertEvent(AlertType.CONNECTION_FLOOD, 
                "Connection flood detected from IPs: " + String.join(", ", floodIps));
            alert.setConfidence(0.95);
            alert.setSuggestedAction("Auto-banned " + floodIps.size() + " IP addresses");
            return alert;
        }
        return null;
    }
}
