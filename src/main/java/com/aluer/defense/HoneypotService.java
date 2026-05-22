package com.aluer.defense;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.atomic.AtomicLong;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

@Component
public class HoneypotService {
    private static final Logger logger = LoggerFactory.getLogger(HoneypotService.class);

    private final Map<String, HoneypotInstance> honeypots = new ConcurrentHashMap<>();
    private final Queue<HoneyPotEvent> eventLog = new ConcurrentLinkedQueue<>();
    private final Map<String, List<AttackAttempt>> attackHistory = new ConcurrentHashMap<>();
    private final Map<String, AttackerProfile> attackerProfiles = new ConcurrentHashMap<>();
    private final AtomicLong totalInteractions = new AtomicLong(0);
    private final AtomicLong uniqueAttackers = new AtomicLong(0);
    private final AtomicLong attacksRecorded = new AtomicLong(0);

    private volatile boolean enabled = false;
    private static final int MAX_HISTORY = 10000;
    private static final DateTimeFormatter DATE_FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    public HoneypotService() {
        initializeDefaultHoneypots();
        logger.info("Honeypot Service initialized");
    }

    private void initializeDefaultHoneypots() {
        addHoneypot("ssh-honeypot", "SSH", 2222, "OpenSSH 7.4");
        addHoneypot("ftp-honeypot", "FTP", 2121, "ProFTPD 1.3.5");
        addHoneypot("http-honeypot", "HTTP", 8080, "Apache 2.4.29");
        addHoneypot("mysql-honeypot", "MySQL", 3307, "MySQL 5.7");
        addHoneypot("minecraft-honeypot", "MINECRAFT", 25566, "PaperSpigot 1.19");
        logger.info("Initialized {} honeypot instances", honeypots.size());
    }

    public void addHoneypot(String name, String type, int port, String fakeVersion) {
        HoneypotInstance honeypot = new HoneypotInstance(name, type, port, fakeVersion);
        honeypots.put(name, honeypot);
        logger.info("Added honeypot: {} on port {}", name, port);
    }

    public void recordInteraction(String honeypotName, String sourceIP, String username, String password, String command) {
        if (!enabled) return;

        totalInteractions.incrementAndGet();

        HoneypotInstance honeypot = honeypots.get(honeypotName);
        if (honeypot != null) {
            honeypot.incrementInteractionCount();
        }

        AttackerProfile profile = attackerProfiles.computeIfAbsent(sourceIP, k -> {
            uniqueAttackers.incrementAndGet();
            return new AttackerProfile(sourceIP);
        });
        profile.recordAttempt(honeypotName);

        AttackAttempt attempt = new AttackAttempt(honeypotName, sourceIP, username, password, command, LocalDateTime.now());
        List<AttackAttempt> history = attackHistory.computeIfAbsent(sourceIP, k -> new ArrayList<>());
        history.add(attempt);
        attacksRecorded.incrementAndGet();

        if (history.size() > MAX_HISTORY) {
            history.remove(0);
        }

        logEvent(sourceIP, honeypotName, "INTERACTION", "Recorded interaction: " + command);

        logger.info("Recorded honeypot interaction from {} on {}", sourceIP, honeypotName);
    }

    public List<AttackAttempt> getAttackHistory(String ip, int limit) {
        List<AttackAttempt> history = attackHistory.getOrDefault(ip, new ArrayList<>());
        return history.subList(0, Math.min(limit, history.size()));
    }

    public Map<String, AttackerProfile> getTopAttackers(int limit) {
        List<AttackerProfile> sorted = new ArrayList<>(attackerProfiles.values());
        sorted.sort((a, b) -> Integer.compare(b.getTotalAttempts(), a.getTotalAttempts()));
        
        Map<String, AttackerProfile> top = new LinkedHashMap<>();
        for (int i = 0; i < Math.min(limit, sorted.size()); i++) {
            top.put(sorted.get(i).getIp(), sorted.get(i));
        }
        return top;
    }

    public Map<String, Object> getStats() {
        Map<String, Object> stats = new HashMap<>();
        stats.put("enabled", enabled);
        stats.put("totalInteractions", totalInteractions.get());
        stats.put("uniqueAttackers", uniqueAttackers.get());
        stats.put("attacksRecorded", attacksRecorded.get());
        stats.put("honeypotsConfigured", honeypots.size());

        Map<String, Long> honeypotStats = new HashMap<>();
        for (HoneypotInstance hp : honeypots.values()) {
            honeypotStats.put(hp.getName(), hp.getInteractionCount());
        }
        stats.put("honeypotInteractions", honeypotStats);

        return stats;
    }

    public void enable() {
        enabled = true;
        logger.info("Honeypot service enabled");
    }

    public void disable() {
        enabled = false;
        logger.info("Honeypot service disabled");
    }

    public Map<String, HoneypotInstance> getHoneypots() {
        return new HashMap<>(honeypots);
    }

    public List<HoneyPotEvent> getRecentEvents(int limit) {
        List<HoneyPotEvent> events = new ArrayList<>();
        int count = 0;
        for (HoneyPotEvent event : eventLog) {
            if (count++ >= limit) break;
            events.add(event);
        }
        return events;
    }

    private void logEvent(String ip, String honeypot, String action, String details) {
        HoneyPotEvent event = new HoneyPotEvent(ip, honeypot, action, details, LocalDateTime.now());
        eventLog.offer(event);
        if (eventLog.size() > 5000) {
            eventLog.poll();
        }
    }

    public static class HoneypotInstance {
        private final String name;
        private final String type;
        private final int port;
        private final String fakeVersion;
        private final AtomicLong interactionCount = new AtomicLong(0);

        public HoneypotInstance(String name, String type, int port, String fakeVersion) {
            this.name = name;
            this.type = type;
            this.port = port;
            this.fakeVersion = fakeVersion;
        }

        public void incrementInteractionCount() { interactionCount.incrementAndGet(); }

        public String getName() { return name; }
        public String getType() { return type; }
        public int getPort() { return port; }
        public String getFakeVersion() { return fakeVersion; }
        public long getInteractionCount() { return interactionCount.get(); }
    }

    public static class AttackAttempt {
        private final String honeypotName;
        private final String sourceIP;
        private final String username;
        private final String password;
        private final String command;
        private final LocalDateTime timestamp;

        public AttackAttempt(String honeypotName, String sourceIP, String username, String password, String command, LocalDateTime timestamp) {
            this.honeypotName = honeypotName;
            this.sourceIP = sourceIP;
            this.username = username;
            this.password = password;
            this.command = command;
            this.timestamp = timestamp;
        }

        public String getHoneypotName() { return honeypotName; }
        public String getSourceIP() { return sourceIP; }
        public String getUsername() { return username; }
        public String getPassword() { return password; }
        public String getCommand() { return command; }
        public LocalDateTime getTimestamp() { return timestamp; }
    }

    public static class AttackerProfile {
        private final String ip;
        private final Map<String, Integer> honeypotAttempts = new HashMap<>();
        private volatile int totalAttempts = 0;
        private volatile long firstSeen;
        private volatile long lastSeen;

        public AttackerProfile(String ip) {
            this.ip = ip;
            this.firstSeen = System.currentTimeMillis();
            this.lastSeen = firstSeen;
        }

        public void recordAttempt(String honeypotName) {
            honeypotAttempts.merge(honeypotName, 1, Integer::sum);
            totalAttempts++;
            lastSeen = System.currentTimeMillis();
        }

        public String getIp() { return ip; }
        public Map<String, Integer> getHoneypotAttempts() { return honeypotAttempts; }
        public int getTotalAttempts() { return totalAttempts; }
        public long getFirstSeen() { return firstSeen; }
        public long getLastSeen() { return lastSeen; }
    }

    public static class HoneyPotEvent {
        private final String ip;
        private final String honeypot;
        private final String action;
        private final String details;
        private final LocalDateTime timestamp;

        public HoneyPotEvent(String ip, String honeypot, String action, String details, LocalDateTime timestamp) {
            this.ip = ip;
            this.honeypot = honeypot;
            this.action = action;
            this.details = details;
            this.timestamp = timestamp;
        }

        public String getIp() { return ip; }
        public String getHoneypot() { return honeypot; }
        public String getAction() { return action; }
        public String getDetails() { return details; }
        public LocalDateTime getTimestamp() { return timestamp; }
    }
}
