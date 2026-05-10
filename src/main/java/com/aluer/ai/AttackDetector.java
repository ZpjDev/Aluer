package com.aluer.ai;

import com.aluer.config.ServerGuardConfig;
import com.aluer.model.AlertEvent;
import com.aluer.model.AlertType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Component
public class AttackDetector {
    private static final Logger logger = LoggerFactory.getLogger(AttackDetector.class);
    
    private final ServerGuardConfig config;
    private final Map<String, ConnectionRecord> connectionHistory = new ConcurrentHashMap<>();
    private final Map<String, LoginAttemptRecord> loginAttempts = new ConcurrentHashMap<>();
    private final Map<String, PacketFrequencyRecord> packetFrequency = new ConcurrentHashMap<>();
    
    private static final Pattern IP_PATTERN = Pattern.compile("\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b");
    private static final long WINDOW_MS = 60000;
    private static final int LOGIN_THRESHOLD = 5;
    private static final int PACKET_THRESHOLD = 100;

    public AttackDetector(ServerGuardConfig config) {
        this.config = config;
    }

    public void recordConnection(String ip) {
        connectionHistory.computeIfAbsent(ip, k -> new ConnectionRecord());
        connectionHistory.get(ip).recordConnect();
    }

    public void recordLoginAttempt(String ip, boolean success) {
        loginAttempts.computeIfAbsent(ip, k -> new LoginAttemptRecord());
        loginAttempts.get(ip).recordAttempt(success);
    }

    public void recordPacket(String ip) {
        packetFrequency.computeIfAbsent(ip, k -> new PacketFrequencyRecord());
        packetFrequency.get(ip).recordPacket();
    }

    public List<AlertEvent> analyzeThreats() {
        List<AlertEvent> alerts = new ArrayList<>();
        long now = System.currentTimeMillis();
        
        connectionHistory.entrySet().removeIf(e -> (now - e.getValue().lastTime) > WINDOW_MS);
        loginAttempts.entrySet().removeIf(e -> (now - e.getValue().lastTime) > WINDOW_MS * 5);
        packetFrequency.entrySet().removeIf(e -> (now - e.getValue().lastTime) > WINDOW_MS);
        
        for (Map.Entry<String, LoginAttemptRecord> entry : loginAttempts.entrySet()) {
            if (entry.getValue().failedCount > LOGIN_THRESHOLD) {
                AlertEvent alert = new AlertEvent(AlertType.LOG_ATTACK, 
                    "Brute force attack detected from IP: " + entry.getKey() + 
                    " (" + entry.getValue().failedCount + " failed attempts)");
                alert.setConfidence(0.9);
                alert.setSuggestedAction("Auto-ban IP: " + entry.getKey());
                alerts.add(alert);
            }
        }
        
        for (Map.Entry<String, PacketFrequencyRecord> entry : packetFrequency.entrySet()) {
            if (entry.getValue().count > PACKET_THRESHOLD) {
                AlertEvent alert = new AlertEvent(AlertType.CONNECTION_FLOOD, 
                    "High packet frequency from IP: " + entry.getKey() + 
                    " (" + entry.getValue().count + " packets/min)");
                alert.setConfidence(0.85);
                alerts.add(alert);
            }
        }
        
        return alerts;
    }

    public List<String> getSuspiciousIps() {
        List<String> suspicious = new ArrayList<>();
        long now = System.currentTimeMillis();
        
        for (Map.Entry<String, LoginAttemptRecord> entry : loginAttempts.entrySet()) {
            if (entry.getValue().failedCount > 3) {
                suspicious.add(entry.getKey());
            }
        }
        
        for (Map.Entry<String, PacketFrequencyRecord> entry : packetFrequency.entrySet()) {
            if (entry.getValue().count > 50) {
                suspicious.add(entry.getKey());
            }
        }
        
        return suspicious;
    }

    private static class ConnectionRecord {
        int connectCount = 0;
        long lastTime = System.currentTimeMillis();
        
        void recordConnect() {
            connectCount++;
            lastTime = System.currentTimeMillis();
        }
    }

    private static class LoginAttemptRecord {
        int failedCount = 0;
        int successCount = 0;
        long lastTime = System.currentTimeMillis();
        
        void recordAttempt(boolean success) {
            if (success) {
                successCount++;
            } else {
                failedCount++;
            }
            lastTime = System.currentTimeMillis();
        }
    }

    private static class PacketFrequencyRecord {
        int count = 0;
        long lastTime = System.currentTimeMillis();
        
        void recordPacket() {
            count++;
            lastTime = System.currentTimeMillis();
        }
    }
}
