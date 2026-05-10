package com.aluer.vpn;

import com.aluer.config.ServerGuardConfig;
import com.aluer.service.RconClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

@Component
public class VPNDetectionService {
    private static final Logger logger = LoggerFactory.getLogger(VPNDetectionService.class);

    private final ServerGuardConfig config;
    private final RconClient rconClient;
    private final Map<String, VPNCheckResult> cache = new ConcurrentHashMap<>();
    private final ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(1);
    private volatile boolean running = false;
    
    private static final String[] VPN_API_ENDPOINTS = {
        "http://ip-api.com/json/",
        "http://ipinfo.io/",
        "http://ip-api.com/json/"
    };
    
    public VPNDetectionService(ServerGuardConfig config, RconClient rconClient) {
        this.config = config;
        this.rconClient = rconClient;
    }
    
    public boolean checkAndBlockVPN(String ip) {
        if (!config.getSecurity().isEnabled()) {
            return false;
        }
        
        VPNCheckResult cached = cache.get(ip);
        
        if (cached != null && cached.isRecent()) {
            if (cached.isVpn()) {
                handleVPNAttempt(ip, cached);
                return true;
            }
            return false;
        }
        
        VPNCheckResult result = checkIP(ip);
        
        if (result != null) {
            cache.put(ip, result);
            
            if (result.isVpn()) {
                handleVPNAttempt(ip, result);
                return true;
            }
        }
        
        return false;
    }
    
    private VPNCheckResult checkIP(String ip) {
        try {
            URL url = new URL("http://ip-api.com/json/" + ip + "?fields=status,message,country,region,city,isp,as,proxy,vpn,hosting");
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");
            conn.setConnectTimeout(5000);
            conn.setReadTimeout(5000);
            
            BufferedReader reader = new BufferedReader(new InputStreamReader(conn.getInputStream()));
            StringBuilder response = new StringBuilder();
            String line;
            
            while ((line = reader.readLine()) != null) {
                response.append(line);
            }
            
            reader.close();
            
            String json = response.toString();
            
            boolean isVPN = json.contains("\"proxy\":true") || 
                          json.contains("\"vpn\":true") || 
                          json.contains("\"hosting\":true");
            
            String isp = extractField(json, "isp");
            String country = extractField(json, "country");
            
            return new VPNCheckResult(ip, isVPN, isp, country);
            
        } catch (Exception e) {
            logger.error("Failed to check IP {}: {}", ip, e.getMessage());
            return null;
        }
    }
    
    private String extractField(String json, String field) {
        String search = "\"" + field + "\":\"";
        int start = json.indexOf(search);
        
        if (start >= 0) {
            start += search.length();
            int end = json.indexOf("\"", start);
            
            if (end > start) {
                return json.substring(start, end);
            }
        }
        
        return "Unknown";
    }
    
    private void handleVPNAttempt(String ip, VPNCheckResult result) {
        logger.warn("VPN/Proxy detected from IP: {} (ISP: {}, Country: {})", 
            ip, result.getIsp(), result.getCountry());
        
        if (config.getSecurity().isAutoBanVPN()) {
            rconClient.banIp(ip);
            
            rconClient.executeCommand("say [Security] VPN/Proxy IP blocked: " + ip);
            
            logger.info("Auto-banned VPN IP: {}", ip);
        }
    }
    
    public void startPeriodicCheck() {
        if (!config.getSecurity().isEnabled()) {
            return;
        }

        running = true;
        scheduler.scheduleAtFixedRate(() -> {
            cleanupCache();
        }, 1, 1, TimeUnit.HOURS);
    }
    
    private void cleanupCache() {
        LocalDateTime cutoff = LocalDateTime.now().minusHours(24);
        cache.entrySet().removeIf(entry -> entry.getValue().getCheckedAt().isBefore(cutoff));
    }
    
    public Map<String, VPNCheckResult> getRecentChecks(int limit) {
        return cache.entrySet().stream()
            .sorted((a, b) -> b.getValue().getCheckedAt().compareTo(a.getValue().getCheckedAt()))
            .limit(limit)
            .collect(java.util.stream.Collectors.toMap(
                Map.Entry::getKey,
                Map.Entry::getValue
            ));
    }
    
    public int getVPNCount() {
        return (int) cache.values().stream()
            .filter(VPNCheckResult::isVpn)
            .count();
    }

    public boolean isRunning() {
        return running;
    }

    public static class VPNCheckResult {
        private final String ip;
        private final boolean vpn;
        private final String isp;
        private final String country;
        private final LocalDateTime checkedAt;
        
        public VPNCheckResult(String ip, boolean vpn, String isp, String country) {
            this.ip = ip;
            this.vpn = vpn;
            this.isp = isp;
            this.country = country;
            this.checkedAt = LocalDateTime.now();
        }
        
        public boolean isRecent() {
            return checkedAt.isAfter(LocalDateTime.now().minusHours(1));
        }
        
        public String getIp() { return ip; }
        public boolean isVpn() { return vpn; }
        public String getIsp() { return isp; }
        public String getCountry() { return country; }
        public LocalDateTime getCheckedAt() { return checkedAt; }
    }
}
