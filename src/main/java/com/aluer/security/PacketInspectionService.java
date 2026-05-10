package com.aluer.security;

import org.springframework.stereotype.Service;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;

@Service
public class PacketInspectionService {

    private final Map<String, PacketRule> rules = new ConcurrentHashMap<>();
    private final Map<String, List<PacketLog>> packetLogs = new ConcurrentHashMap<>();
    private final Queue<PacketAlert> alerts = new ConcurrentLinkedQueue<>();
    private final ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(2);

    private static final int MAX_PACKET_SIZE = 65535;
    private static final int MAX_LOGS_PER_IP = 1000;

    private final AtomicLong totalPacketsInspected = new AtomicLong(0);
    private final AtomicLong maliciousPacketsBlocked = new AtomicLong(0);

    public PacketInspectionService() {
        initializeDefaultRules();
        startCleanupTask();
    }

    private void initializeDefaultRules() {
        addRule("BLOCK_LARGE_PACKETS", "size", ">", 10000, true, "Block oversized packets");
        addRule("BLOCK_NULL_PACKETS", "size", "==", 0, true, "Block null size packets");
        addRule("BLOCK_FRAGMENTED", "fragmented", "==", true, true, "Block fragmented packets");
        addRule("ALERT_SYN_FLOOD", "tcp_flags", "==", "SYN", false, "Alert on SYN packets");
        addRule("BLOCK_MALFORMED", "malformed", "==", true, true, "Block malformed packets");
    }

    public void addRule(String name, String field, String operator, Object value, boolean block, String description) {
        PacketRule rule = new PacketRule(name, field, operator, value, block, description);
        rules.put(name, rule);
    }

    public boolean inspectPacket(String sourceIP, Map<String, Object> packetData) {
        totalPacketsInspected.incrementAndGet();

        int packetSize = getIntValue(packetData, "size");
        if (packetSize > MAX_PACKET_SIZE || packetSize < 0) {
            logPacket(sourceIP, "INVALID_SIZE", packetData);
            maliciousPacketsBlocked.incrementAndGet();
            return false;
        }

        for (PacketRule rule : rules.values()) {
            if (!rule.enabled) {
                continue;
            }
            if (matchesRule(packetData, rule)) {
                if (rule.block) {
                    logPacket(sourceIP, "BLOCKED:" + rule.name, packetData);
                    alerts.offer(new PacketAlert(sourceIP, rule.name, "Packet blocked by rule: " + rule.description, System.currentTimeMillis()));
                    maliciousPacketsBlocked.incrementAndGet();
                    return false;
                } else {
                    logPacket(sourceIP, "ALERT:" + rule.name, packetData);
                    alerts.offer(new PacketAlert(sourceIP, rule.name, "Alert: " + rule.description, System.currentTimeMillis()));
                }
            }
        }

        logPacket(sourceIP, "ALLOWED", packetData);
        return true;
    }

    private boolean matchesRule(Map<String, Object> packetData, PacketRule rule) {
        Object fieldValue = packetData.get(rule.field);
        if (fieldValue == null) {
            return false;
        }

        return switch (rule.operator) {
            case "==" -> fieldValue.equals(rule.value);
            case "!=" -> !fieldValue.equals(rule.value);
            case ">" -> compareValues(fieldValue, rule.value) > 0;
            case "<" -> compareValues(fieldValue, rule.value) < 0;
            case ">=" -> compareValues(fieldValue, rule.value) >= 0;
            case "<=" -> compareValues(fieldValue, rule.value) <= 0;
            case "contains" -> fieldValue.toString().contains(rule.value.toString());
            default -> false;
        };
    }

    private int compareValues(Object a, Object b) {
        if (a instanceof Number && b instanceof Number) {
            return Double.compare(((Number) a).doubleValue(), ((Number) b).doubleValue());
        }
        return 0;
    }

    private int getIntValue(Map<String, Object> data, String key) {
        Object value = data.get(key);
        if (value instanceof Number) {
            return ((Number) value).intValue();
        }
        return 0;
    }

    private void logPacket(String sourceIP, String status, Map<String, Object> packetData) {
        PacketLog log = new PacketLog(sourceIP, status, packetData, System.currentTimeMillis());
        List<PacketLog> logs = packetLogs.computeIfAbsent(sourceIP, k -> new CopyOnWriteArrayList<>());
        logs.add(log);

        while (logs.size() > MAX_LOGS_PER_IP) {
            logs.remove(0);
        }
    }

    public List<PacketLog> getPacketLogs(String sourceIP, int limit) {
        List<PacketLog> logs = packetLogs.get(sourceIP);
        if (logs == null) {
            return new ArrayList<>();
        }
        return logs.stream().limit(limit).toList();
    }

    public List<PacketAlert> getAlerts(int limit) {
        List<PacketAlert> result = new ArrayList<>();
        int count = 0;
        for (PacketAlert alert : alerts) {
            if (count++ >= limit) break;
            result.add(alert);
        }
        return result;
    }

    public void enableRule(String ruleName) {
        PacketRule rule = rules.get(ruleName);
        if (rule != null) {
            rule.enabled = true;
        }
    }

    public void disableRule(String ruleName) {
        PacketRule rule = rules.get(ruleName);
        if (rule != null) {
            rule.enabled = false;
        }
    }

    public Collection<PacketRule> getRules() {
        return rules.values();
    }

    private void startCleanupTask() {
        scheduler.scheduleAtFixedRate(() -> {
            long cutoff = System.currentTimeMillis() - 3600000;

            packetLogs.entrySet().removeIf(entry -> {
                List<PacketLog> logs = entry.getValue();
                logs.removeIf(log -> log.timestamp < cutoff);
                return logs.isEmpty();
            });

            alerts.removeIf(alert -> alert.timestamp < cutoff);

        }, 300, 300, TimeUnit.SECONDS);
    }

    public Map<String, Object> getStats() {
        Map<String, Object> stats = new HashMap<>();
        stats.put("totalInspected", totalPacketsInspected.get());
        stats.put("maliciousBlocked", maliciousPacketsBlocked.get());
        stats.put("activeRules", rules.size());
        return stats;
    }

    public static class PacketRule {
        public final String name;
        public final String field;
        public final String operator;
        public final Object value;
        public final boolean block;
        public final String description;
        public volatile boolean enabled = true;

        public PacketRule(String name, String field, String operator, Object value, boolean block, String description) {
            this.name = name;
            this.field = field;
            this.operator = operator;
            this.value = value;
            this.block = block;
            this.description = description;
        }
    }

    public static class PacketLog {
        public final String sourceIP;
        public final String status;
        public final Map<String, Object> packetData;
        public final long timestamp;

        public PacketLog(String sourceIP, String status, Map<String, Object> packetData, long timestamp) {
            this.sourceIP = sourceIP;
            this.status = status;
            this.packetData = packetData;
            this.timestamp = timestamp;
        }
    }

    public static class PacketAlert {
        public final String sourceIP;
        public final String ruleName;
        public final String details;
        public final long timestamp;

        public PacketAlert(String sourceIP, String ruleName, String details, long timestamp) {
            this.sourceIP = sourceIP;
            this.ruleName = ruleName;
            this.details = details;
            this.timestamp = timestamp;
        }
    }
}
