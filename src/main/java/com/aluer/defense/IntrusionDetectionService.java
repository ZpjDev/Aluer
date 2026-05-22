package com.aluer.defense;

import org.springframework.stereotype.Service;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;
import java.security.MessageDigest;
import java.nio.file.*;
import java.io.*;

@Service
public class IntrusionDetectionService {

    private final Map<String, IntrusionAlert> activeAlerts = new ConcurrentHashMap<>();
    private final Map<String, SuspiciousActivity> activityLog = new ConcurrentHashMap<>();
    private final Map<String, List<LoginAttempt>> loginAttempts = new ConcurrentHashMap<>();
    private final Map<String, UserBehavior> userBehaviors = new ConcurrentHashMap<>();
    private final Queue<IntrusionEvent> events = new ConcurrentLinkedQueue<>();
    private final ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(3);

    private static final int MAX_LOGIN_ATTEMPTS = 5;
    private static final long LOGIN_TIMEOUT = 300000;
    private static final int MAX_ALERTS = 1000;
    private static final double ANOMALY_THRESHOLD = 0.8;

    private final AtomicInteger alertLevel = new AtomicInteger(0);
    private final AtomicLong totalIntrusions = new AtomicLong(0);

    public IntrusionDetectionService() {
        startDetectionTask();
    }

    public boolean checkLoginAttempt(String username, String ip, boolean success) {
        List<LoginAttempt> attempts = loginAttempts.computeIfAbsent(username.toLowerCase(), k -> new CopyOnWriteArrayList<>());
        long now = System.currentTimeMillis();

        attempts.removeIf(a -> now - a.timestamp > LOGIN_TIMEOUT);

        if (!success) {
            LoginAttempt attempt = new LoginAttempt(username, ip, false, now);
            attempts.add(attempt);

            if (attempts.size() >= MAX_LOGIN_ATTEMPTS) {
                triggerAlert("BRUTE_FORCE", username, "Failed login attempts: " + attempts.size(), ip);
                return false;
            }
        } else {
            LoginAttempt attempt = new LoginAttempt(username, ip, true, now);
            attempts.clear();
            attempts.add(attempt);
        }

        return true;
    }

    public void recordFailedLogin(String username, String ip, String reason) {
        List<LoginAttempt> attempts = loginAttempts.computeIfAbsent(username.toLowerCase(), k -> new CopyOnWriteArrayList<>());
        attempts.add(new LoginAttempt(username, ip, false, System.currentTimeMillis()));

        recordActivity(username, "LOGIN_FAILED", reason, ip);

        if (attempts.size() >= MAX_LOGIN_ATTEMPTS) {
            triggerAlert("BRUTE_FORCE", username, "Account: " + username, ip);
        }
    }

    public void recordSuccessfulLogin(String username, String ip) {
        List<LoginAttempt> attempts = loginAttempts.get(username.toLowerCase());
        if (attempts != null) {
            attempts.clear();
        }

        recordActivity(username, "LOGIN_SUCCESS", "Login successful", ip);
    }

    public void recordActivity(String username, String activityType, String details, String ip) {
        String key = username + ":" + activityType;
        SuspiciousActivity activity = activityLog.computeIfAbsent(key, k -> new SuspiciousActivity(username, activityType));
        
        activity.addOccurrence(details, ip);

        if (activity.isSuspicious()) {
            triggerAlert("ANOMALY_DETECTED", username, activityType + ": " + details, ip);
        }
    }

    public void analyzeBehavior(String username, Map<String, Object> metrics) {
        UserBehavior behavior = userBehaviors.computeIfAbsent(username, k -> new UserBehavior(username));

        double cpuUsage = getMetricValue(metrics, "cpu");
        double memoryUsage = getMetricValue(metrics, "memory");
        double networkIn = getMetricValue(metrics, "network_in");
        double networkOut = getMetricValue(metrics, "network_out");
        int fileAccess = getMetricInt(metrics, "file_access");
        int processCount = getMetricInt(metrics, "processes");

        behavior.addSample(cpuUsage, memoryUsage, networkIn, networkOut, fileAccess, processCount);

        if (behavior.isAnomalous()) {
            triggerAlert("BEHAVIOR_ANOMALY", username, "Unusual behavior pattern detected", "system");
        }
    }

    private double getMetricValue(Map<String, Object> metrics, String key) {
        Object value = metrics.get(key);
        if (value instanceof Number) {
            return ((Number) value).doubleValue();
        }
        return 0.0;
    }

    private int getMetricInt(Map<String, Object> metrics, String key) {
        Object value = metrics.get(key);
        if (value instanceof Number) {
            return ((Number) value).intValue();
        }
        return 0;
    }

    public void checkFileAccess(String username, String filePath, String operation) {
        if (isSensitivePath(filePath)) {
            recordActivity(username, "SENSITIVE_FILE_ACCESS", operation + ": " + filePath, "system");
            triggerAlert("FILE_ACCESS_VIOLATION", username, "Access to sensitive file: " + filePath, "system");
        }
    }

    private boolean isSensitivePath(String path) {
        String[] sensitive = {"/etc/passwd", "/etc/shadow", "/root", "/var/log", 
                            "C:\\Windows\\System32", "C:\\Windows\\System", "config"};
        for (String s : sensitive) {
            if (path.contains(s)) {
                return true;
            }
        }
        return false;
    }

    public void checkProcessActivity(String username, String processName, boolean isNew) {
        if (isSuspiciousProcess(processName)) {
            recordActivity(username, "SUSPICIOUS_PROCESS", processName, "system");
            triggerAlert("MALICIOUS_PROCESS", username, "Suspicious process: " + processName, "system");
        }
    }

    private boolean isSuspiciousProcess(String processName) {
        String[] suspicious = {"nc ", "netcat", "ncat", "socat", "meterpreter", 
                             "mimikatz", "pwdump", "lsass", "procmon"};
        for (String s : suspicious) {
            if (processName.toLowerCase().contains(s.toLowerCase())) {
                return true;
            }
        }
        return false;
    }

    public void checkNetworkConnection(String username, String remoteIP, int port) {
        if (isSuspiciousPort(port)) {
            recordActivity(username, "SUSPICIOUS_CONNECTION", remoteIP + ":" + port, remoteIP);
            triggerAlert("SUSPICIOUS_CONNECTION", username, "Connection to suspicious port: " + port, remoteIP);
        }

        if (isKnownMaliciousIP(remoteIP)) {
            triggerAlert("MALICIOUS_IP", username, "Known malicious IP: " + remoteIP, remoteIP);
        }
    }

    private boolean isSuspiciousPort(int port) {
        int[] suspicious = {4444, 5555, 6666, 7777, 8888, 31337, 12345, 54321};
        for (int p : suspicious) {
            if (port == p) {
                return true;
            }
        }
        return false;
    }

    private boolean isKnownMaliciousIP(String ip) {
        return false;
    }

    public void checkCommandExecution(String username, String command) {
        if (isDangerousCommand(command)) {
            recordActivity(username, "DANGEROUS_COMMAND", command, "system");
            triggerAlert("COMMAND_INJECTION", username, "Dangerous command: " + command, "system");
        }
    }

    private boolean isDangerousCommand(String command) {
        String[] dangerous = {"rm -rf", "dd if", "mkfs", "shutdown", "reboot", 
                            "wget |", "curl |", "nc -e", "bash -i"};
        for (String d : dangerous) {
            if (command.toLowerCase().contains(d.toLowerCase())) {
                return true;
            }
        }
        return false;
    }

    public void checkPrivilegeEscalation(String username, String attemptedAction) {
        recordActivity(username, "PRIVILEGE_ESCALATION", attemptedAction, "system");
        triggerAlert("PRIVILEGE_ESCALATION", username, "Privilege escalation attempt: " + attemptedAction, "system");
    }

    public void triggerAlert(String type, String username, String details, String sourceIP) {
        String alertKey = type + ":" + username + ":" + System.currentTimeMillis();
        
        IntrusionAlert alert = new IntrusionAlert(type, username, details, sourceIP);
        activeAlerts.put(alertKey, alert);

        totalIntrusions.incrementAndGet();

        logEvent(type, username, details, sourceIP);

        updateAlertLevel(type);

        while (activeAlerts.size() > MAX_ALERTS) {
            String firstKey = activeAlerts.keySet().iterator().next();
            activeAlerts.remove(firstKey);
        }
    }

    private void updateAlertLevel(String alertType) {
        int current = alertLevel.get();
        int newLevel = switch (alertType) {
            case "BRUTE_FORCE", "FILE_ACCESS_VIOLATION" -> Math.min(current + 1, 3);
            case "MALICIOUS_PROCESS", "MALICIOUS_IP" -> Math.min(current + 2, 3);
            case "PRIVILEGE_ESCALATION", "COMMAND_INJECTION" -> 3;
            default -> current;
        };
        alertLevel.set(newLevel);
    }

    public IntrusionAlert getAlert(String alertKey) {
        return activeAlerts.get(alertKey);
    }

    public Collection<IntrusionAlert> getActiveAlerts() {
        return activeAlerts.values();
    }

    public boolean acknowledgeAlert(String alertKey) {
        return activeAlerts.remove(alertKey) != null;
    }

    public void clearAlerts() {
        activeAlerts.clear();
    }

    public void logEvent(String type, String username, String details, String sourceIP) {
        IntrusionEvent event = new IntrusionEvent(type, username, details, sourceIP, System.currentTimeMillis());
        events.offer(event);

        while (events.size() > 10000) {
            events.poll();
        }
    }

    public List<IntrusionEvent> getEvents(int limit) {
        List<IntrusionEvent> result = new ArrayList<>();
        int count = 0;
        for (IntrusionEvent event : events) {
            if (count++ >= limit) break;
            result.add(event);
        }
        return result;
    }

    public int getAlertLevel() {
        return alertLevel.get();
    }

    public void setAlertLevel(int level) {
        alertLevel.set(Math.max(0, Math.min(3, level)));
    }

    private void startDetectionTask() {
        scheduler.scheduleAtFixedRate(() -> {
            long now = System.currentTimeMillis();

            activityLog.entrySet().removeIf(entry -> 
                now - entry.getValue().lastActivity > 3600000);

            loginAttempts.entrySet().removeIf(entry -> {
                entry.getValue().removeIf(a -> now - a.timestamp > LOGIN_TIMEOUT);
                return entry.getValue().isEmpty();
            });

            if (alertLevel.get() > 0) {
                alertLevel.decrementAndGet();
            }
        }, 60, 60, TimeUnit.SECONDS);
    }

    public Map<String, Object> getStats() {
        Map<String, Object> stats = new HashMap<>();
        stats.put("activeAlerts", activeAlerts.size());
        stats.put("totalIntrusions", totalIntrusions.get());
        stats.put("alertLevel", alertLevel.get());
        stats.put("trackedUsers", userBehaviors.size());
        return stats;
    }

    public static class IntrusionAlert {
        public final String type;
        public final String username;
        public final String details;
        public final String sourceIP;
        public final long timestamp;
        public boolean acknowledged = false;

        public IntrusionAlert(String type, String username, String details, String sourceIP) {
            this.type = type;
            this.username = username;
            this.details = details;
            this.sourceIP = sourceIP;
            this.timestamp = System.currentTimeMillis();
        }
    }

    public static class LoginAttempt {
        public final String username;
        public final String ip;
        public final boolean success;
        public final long timestamp;

        public LoginAttempt(String username, String ip, boolean success, long timestamp) {
            this.username = username;
            this.ip = ip;
            this.success = success;
            this.timestamp = timestamp;
        }
    }

    public static class SuspiciousActivity {
        public final String username;
        public final String activityType;
        public final List<ActivityOccurrence> occurrences = new ArrayList<>();
        public volatile long lastActivity;
        private int suspiciousCount = 0;

        public SuspiciousActivity(String username, String activityType) {
            this.username = username;
            this.activityType = activityType;
            this.lastActivity = System.currentTimeMillis();
        }

        public void addOccurrence(String details, String ip) {
            occurrences.add(new ActivityOccurrence(details, ip, System.currentTimeMillis()));
            lastActivity = System.currentTimeMillis();

            if (occurrences.size() > 10) {
                occurrences.remove(0);
            }

            if (isRapidFire()) {
                suspiciousCount++;
            }
        }

        private boolean isRapidFire() {
            if (occurrences.size() < 3) return false;
            long timeSpan = occurrences.get(occurrences.size()-1).timestamp - occurrences.get(0).timestamp;
            return timeSpan < 1000;
        }

        public boolean isSuspicious() {
            return suspiciousCount > 3 || occurrences.size() > 10;
        }
    }

    public static class ActivityOccurrence {
        public final String details;
        public final String ip;
        public final long timestamp;

        public ActivityOccurrence(String details, String ip, long timestamp) {
            this.details = details;
            this.ip = ip;
            this.timestamp = timestamp;
        }
    }

    public static class UserBehavior {
        public final String username;
        public final List<BehaviorSample> samples = new ArrayList<>();
        private double avgCpu = 0, avgMemory = 0, avgNetworkIn = 0, avgNetworkOut = 0;
        private double stdCpu = 0, stdMemory = 0;

        public UserBehavior(String username) {
            this.username = username;
        }

        public void addSample(double cpu, double memory, double networkIn, double networkOut, int fileAccess, int processes) {
            samples.add(new BehaviorSample(cpu, memory, networkIn, networkOut, fileAccess, processes));

            if (samples.size() > 100) {
                samples.remove(0);
            }

            recalculateBaselines();
        }

        private void recalculateBaselines() {
            if (samples.isEmpty()) return;

            avgCpu = samples.stream().mapToDouble(s -> s.cpu).average().orElse(0);
            avgMemory = samples.stream().mapToDouble(s -> s.memory).average().orElse(0);
            avgNetworkIn = samples.stream().mapToDouble(s -> s.networkIn).average().orElse(0);
            avgNetworkOut = samples.stream().mapToDouble(s -> s.networkOut).average().orElse(0);

            double varianceCpu = samples.stream()
                .mapToDouble(s -> Math.pow(s.cpu - avgCpu, 2))
                .average().orElse(0);
            stdCpu = Math.sqrt(varianceCpu);

            double varianceMemory = samples.stream()
                .mapToDouble(s -> Math.pow(s.memory - avgMemory, 2))
                .average().orElse(0);
            stdMemory = Math.sqrt(varianceMemory);
        }

        public boolean isAnomalous() {
            if (samples.isEmpty()) return false;

            BehaviorSample latest = samples.get(samples.size() - 1);

            double cpuDeviation = stdCpu > 0 ? Math.abs(latest.cpu - avgCpu) / stdCpu : 0;
            double memDeviation = stdMemory > 0 ? Math.abs(latest.memory - avgMemory) / stdMemory : 0;

            return cpuDeviation > ANOMALY_THRESHOLD || memDeviation > ANOMALY_THRESHOLD;
        }
    }

    public static class BehaviorSample {
        public final double cpu;
        public final double memory;
        public final double networkIn;
        public final double networkOut;
        public final int fileAccess;
        public final int processes;

        public BehaviorSample(double cpu, double memory, double networkIn, double networkOut, int fileAccess, int processes) {
            this.cpu = cpu;
            this.memory = memory;
            this.networkIn = networkIn;
            this.networkOut = networkOut;
            this.fileAccess = fileAccess;
            this.processes = processes;
        }
    }

    public static class IntrusionEvent {
        public final String type;
        public final String username;
        public final String details;
        public final String sourceIP;
        public final long timestamp;

        public IntrusionEvent(String type, String username, String details, String sourceIP, long timestamp) {
            this.type = type;
            this.username = username;
            this.details = details;
            this.sourceIP = sourceIP;
            this.timestamp = timestamp;
        }
    }
}
