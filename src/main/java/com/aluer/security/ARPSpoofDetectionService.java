package com.aluer.security;

import org.springframework.stereotype.Service;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

@Service
public class ARPSpoofDetectionService {

    private final Map<String, String> arpCache = new ConcurrentHashMap<>();
    private final Map<String, List<ARPEvent>> arpEvents = new ConcurrentHashMap<>();
    private final ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor();
    private final AtomicLong totalSpoofDetections = new AtomicLong(0);

    private static final int BASELINE_SAMPLES = 3;

    public ARPSpoofDetectionService() {
        buildBaseline();
        scheduler.scheduleAtFixedRate(this::scanARPTable, 30, 60, TimeUnit.SECONDS);
    }

    private void buildBaseline() {
        Map<String, String> current = readARPTable();
        for (Map.Entry<String, String> e : current.entrySet()) {
            arpCache.put(e.getKey(), e.getValue());
        }
    }

    public ARPScanResult scanARPTable() {
        Map<String, String> current = readARPTable();
        List<ARPEvent> alerts = new ArrayList<>();

        for (Map.Entry<String, String> entry : current.entrySet()) {
            String ip = entry.getKey();
            String mac = entry.getValue();

            if (mac.equals("00:00:00:00:00:00") || mac.equals("ff:ff:ff:ff:ff:ff")) {
                continue;
            }

            String cachedMac = arpCache.get(ip);
            if (cachedMac != null && !cachedMac.equalsIgnoreCase(mac)) {
                ARPEvent event = new ARPEvent(
                        ARPEventType.MAC_CHANGE, ip, cachedMac, mac, Instant.now(),
                        "ARP spoofing: IP " + ip + " MAC changed from " + cachedMac + " to " + mac
                );
                alerts.add(event);
                arpEvents.computeIfAbsent(ip, k -> new ArrayList<>()).add(event);
                totalSpoofDetections.incrementAndGet();
            }

            // Check for duplicate MAC addresses (possible MITM)
            for (Map.Entry<String, String> other : current.entrySet()) {
                if (!other.getKey().equals(ip) && other.getValue().equalsIgnoreCase(mac)) {
                    ARPEvent event = new ARPEvent(
                            ARPEventType.DUPLICATE_MAC, ip, mac, other.getKey(), Instant.now(),
                            "Duplicate MAC: " + mac + " used by both " + ip + " and " + other.getKey()
                    );
                    alerts.add(event);
                    arpEvents.computeIfAbsent(ip, k -> new ArrayList<>()).add(event);
                    totalSpoofDetections.incrementAndGet();
                }
            }
        }

        // Check for gateway MAC spoofing
        String gatewayIP = detectGateway();
        if (gatewayIP != null) {
            String gatewayMac = current.get(gatewayIP);
            String cachedGatewayMac = arpCache.get(gatewayIP);
            if (gatewayMac != null && cachedGatewayMac != null && !gatewayMac.equalsIgnoreCase(cachedGatewayMac)) {
                ARPEvent event = new ARPEvent(
                        ARPEventType.GATEWAY_SPOOF, gatewayIP, cachedGatewayMac, gatewayMac, Instant.now(),
                        "Gateway ARP spoofing detected: " + gatewayIP
                );
                alerts.add(event);
                arpEvents.computeIfAbsent(gatewayIP, k -> new ArrayList<>()).add(event);
                totalSpoofDetections.incrementAndGet();
            }
        }

        arpCache.clear();
        arpCache.putAll(current);

        return new ARPScanResult(alerts, current.size(), totalSpoofDetections.get());
    }

    public Map<String, Object> getStatus() {
        Map<String, Object> status = new LinkedHashMap<>();
        status.put("arpCacheSize", arpCache.size());
        status.put("totalSpoofDetections", totalSpoofDetections.get());
        status.put("monitoredIPs", new ArrayList<>(arpCache.keySet()));
        List<Map<String, Object>> recentEvents = new ArrayList<>();
        for (Map.Entry<String, List<ARPEvent>> e : arpEvents.entrySet()) {
            for (ARPEvent event : e.getValue()) {
                Map<String, Object> m = new LinkedHashMap<>();
                m.put("ip", e.getKey());
                m.put("type", event.type.name());
                m.put("oldMac", event.oldMac);
                m.put("newMac", event.newMac);
                m.put("time", event.timestamp.toString());
                m.put("message", event.message);
                recentEvents.add(m);
            }
        }
        recentEvents.sort((a, b) -> b.get("time").toString().compareTo(a.get("time").toString()));
        status.put("recentEvents", recentEvents.subList(0, Math.min(recentEvents.size(), 20)));
        return status;
    }

    public long getTotalSpoofDetections() { return totalSpoofDetections.get(); }

    private Map<String, String> readARPTable() {
        Map<String, String> table = new LinkedHashMap<>();
        try {
            Process proc = Runtime.getRuntime().exec(new String[]{"arp", "-a"});
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(proc.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    line = line.trim();
                    if (line.isEmpty() || line.startsWith("Interface") || line.startsWith("Internet")) continue;
                    // Windows: "192.168.1.1          00-11-22-33-44-55     dynamic"
                    // Linux: "gateway (192.168.1.1) at 00:11:22:33:44:55 [ether] on eth0"
                    String[] tokens = line.split("\\s+");
                    String ip = null, mac = null;
                    for (String token : tokens) {
                        token = token.replaceAll("[()]", "");
                        if (token.matches("\\d+\\.\\d+\\.\\d+\\.\\d+")) {
                            ip = token;
                        }
                        if (token.matches("[0-9A-Fa-f]{1,2}[-:][0-9A-Fa-f]{1,2}[-:][0-9A-Fa-f]{1,2}[-:][0-9A-Fa-f]{1,2}[-:][0-9A-Fa-f]{1,2}[-:][0-9A-Fa-f]{1,2}")) {
                            mac = token.replace('-', ':').toLowerCase();
                        }
                    }
                    if (ip != null && mac != null) {
                        table.put(ip, mac);
                    }
                }
            }
        } catch (Exception ignored) {
            // arp command not available, silent fail
        }
        return table;
    }

    private String detectGateway() {
        try {
            Process proc = Runtime.getRuntime().exec(new String[]{"sh", "-c", "ip route | grep default | awk '{print $3}'"});
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(proc.getInputStream()))) {
                String line = reader.readLine();
                if (line != null && !line.trim().isEmpty()) return line.trim();
            }
            // Fallback to Windows
            proc = Runtime.getRuntime().exec(new String[]{"sh", "-c", "ipconfig | findstr /i \"Default Gateway\" | findstr /v \"::\""});
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(proc.getInputStream()))) {
                String line = reader.readLine();
                if (line != null) {
                    String[] parts = line.split(":");
                    if (parts.length >= 2) return parts[parts.length - 1].trim();
                }
            }
        } catch (Exception ignored) {
            // silent fail
        }
        return null;
    }

    public enum ARPEventType { MAC_CHANGE, DUPLICATE_MAC, GATEWAY_SPOOF }

    public static class ARPEvent {
        public final ARPEventType type;
        public final String ip;
        public final String oldMac;
        public final String newMac;
        public final Instant timestamp;
        public final String message;

        ARPEvent(ARPEventType type, String ip, String oldMac, String newMac, Instant timestamp, String message) {
            this.type = type;
            this.ip = ip;
            this.oldMac = oldMac;
            this.newMac = newMac;
            this.timestamp = timestamp;
            this.message = message;
        }
    }

    public static class ARPScanResult {
        public final List<ARPEvent> alerts;
        public final int tableSize;
        public final long totalDetections;

        ARPScanResult(List<ARPEvent> alerts, int tableSize, long totalDetections) {
            this.alerts = alerts;
            this.tableSize = tableSize;
            this.totalDetections = totalDetections;
        }

        public boolean hasAlerts() { return !alerts.isEmpty(); }
        public List<ARPEvent> getAlerts() { return alerts; }
        public int getTableSize() { return tableSize; }
        public long getTotalDetections() { return totalDetections; }
    }
}
