package com.aluer.monitor;

import com.aluer.config.ServerGuardConfig;
import com.aluer.model.AlertEvent;
import com.aluer.model.AlertType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.io.BufferedReader;
import java.io.FileReader;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Component
public class LogMonitor {
    private static final Logger logger = LoggerFactory.getLogger(LogMonitor.class);
    
    private final ServerGuardConfig config;
    private long lastReadPosition = 0;
    
    private static final Pattern LOGIN_FAILED_PATTERN = Pattern.compile("(\\d+\\.\\d+\\.\\d+\\.\\d+).*Login failed", Pattern.CASE_INSENSITIVE);
    private static final Pattern ATTACK_PATTERNS[] = {
        Pattern.compile("(?i).*invalid packet.*"),
        Pattern.compile("(?i).*exploit.*"),
        Pattern.compile("(?i).*hack.*"),
        Pattern.compile("(?i).*speedhack.*"),
        Pattern.compile("(?i).*x-ray.*"),
        Pattern.compile("(?i).*illegal block.*"),
        Pattern.compile("(?i).*too many packets.*"),
    };

    private final Map<String, Integer> failedLoginCounts = new ConcurrentHashMap<>();
    private final Map<String, Long> lastFailedLogin = new ConcurrentHashMap<>();

    public LogMonitor(ServerGuardConfig config) {
        this.config = config;
    }

    public List<String> watchLogs() {
        List<String> newLines = new ArrayList<>();
        String logPath = config.getMonitor().getLogPath();
        
        try (BufferedReader reader = new BufferedReader(new FileReader(logPath))) {
            reader.skip(lastReadPosition);
            String line;
            while ((line = reader.readLine()) != null) {
                newLines.add(line);
            }
            lastReadPosition = reader.skip(0);
            
            try (BufferedReader reader2 = new BufferedReader(new FileReader(logPath))) {
                long skipped = 0;
                while (skipped < lastReadPosition) {
                    skipped += reader2.skip(lastReadPosition - skipped);
                }
                String line2;
                while ((line2 = reader2.readLine()) != null) {
                    newLines.add(line2);
                }
                java.io.File file = new java.io.File(logPath);
                lastReadPosition = file.length();
            }
            
        } catch (Exception e) {
            logger.debug("Error reading logs: {}", e.getMessage());
            try {
                java.io.File file = new java.io.File(logPath);
                lastReadPosition = file.length();
            } catch (Exception ex) {
                logger.error("Failed to get file length: {}", ex.getMessage());
            }
        }
        
        return newLines;
    }

    public List<AlertEvent> analyzeLogs() {
        List<AlertEvent> alerts = new ArrayList<>();
        List<String> newLines = watchLogs();
        
        for (String line : newLines) {
            checkFailedLogin(line);
            AlertEvent attackAlert = checkAttackPatterns(line);
            if (attackAlert != null) {
                alerts.add(attackAlert);
            }
        }
        
        return alerts;
    }

    private void checkFailedLogin(String line) {
        Matcher matcher = LOGIN_FAILED_PATTERN.matcher(line);
        if (matcher.find()) {
            String ip = matcher.group(1);
            failedLoginCounts.merge(ip, 1, Integer::sum);
            lastFailedLogin.put(ip, System.currentTimeMillis());
            
            if (failedLoginCounts.get(ip) > 5) {
                logger.warn("Multiple failed login attempts from IP: {}", ip);
            }
        }
    }

    private AlertEvent checkAttackPatterns(String line) {
        for (Pattern pattern : ATTACK_PATTERNS) {
            if (pattern.matcher(line).matches()) {
                AlertEvent alert = new AlertEvent(AlertType.LOG_ATTACK, "Attack pattern detected: " + line);
                alert.setConfidence(0.85);
                alert.setSuggestedAction("Review server logs and consider IP ban");
                return alert;
            }
        }
        return null;
    }

    public List<String> getSuspiciousIps() {
        long now = System.currentTimeMillis();
        List<String> suspicious = new ArrayList<>();
        
        failedLoginCounts.entrySet().removeIf(entry -> {
            Long lastTime = lastFailedLogin.get(entry.getKey());
            if (lastTime != null && (now - lastTime) > 300000) {
                return true;
            }
            return false;
        });
        
        failedLoginCounts.forEach((ip, count) -> {
            if (count > 3) {
                suspicious.add(ip);
            }
        });
        
        return suspicious;
    }

    public void clearOldData() {
        long now = System.currentTimeMillis();
        lastFailedLogin.entrySet().removeIf(entry -> (now - entry.getValue()) > 300000);
    }
}
