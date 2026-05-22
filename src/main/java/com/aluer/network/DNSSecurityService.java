package com.aluer.network;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.atomic.AtomicLong;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.net.InetAddress;

@Component
public class DNSSecurityService {
    private static final Logger logger = LoggerFactory.getLogger(DNSSecurityService.class);

    private final Map<String, DNSQueryRecord> queryCache = new ConcurrentHashMap<>();
    private final Map<String, List<ClientQueryHistory>> clientQueryHistory = new ConcurrentHashMap<>();
    private final Map<String, DNSZone> zones = new ConcurrentHashMap<>();
    private final Queue<DNSEvent> eventLog = new ConcurrentLinkedQueue<>();
    private final AtomicLong totalQueries = new AtomicLong(0);
    private final AtomicLong blockedQueries = new AtomicLong(0);
    private final AtomicLong suspiciousQueries = new AtomicLong(0);

    private static final int MAX_QUERIES_PER_MINUTE = 60;
    private static final int MAX_QUERIES_PER_HOUR = 1000;
    private static final int CACHE_TTL_SECONDS = 300;
    private static final DateTimeFormatter DATE_FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    private final Set<String> blockedDomains = new HashSet<>(Arrays.asList(
        "malware.com", "phishing.com", "ransomware.com", "trojan.com",
        "coinminer.com", "adservice.com", "tracker.com", "spyware.com"
    ));

    private final Set<String> suspiciousTLDs = new HashSet<>(Arrays.asList(
        ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".work"
    ));

    public DNSSecurityService() {
        initializeDefaultZones();
    }

    private void initializeDefaultZones() {
        DNSZone minecraftZone = new DNSZone("minecraft");
        minecraftZone.addRecord("auth.mojang.com", "13.107.42.20");
        minecraftZone.addRecord("sessionserver.mojang.com", "13.107.42.20");
        minecraftZone.addRecord("api.mojang.com", "13.107.42.20");
        minecraftZone.addRecord("textures.minecraft.net", "13.107.42.20");
        zones.put("minecraft", minecraftZone);

        DNSZone localZone = new DNSZone("local");
        localZone.addRecord("localhost", "127.0.0.1");
        zones.put("local", localZone);
    }

    public DNSQueryResult processQuery(String clientIP, String domainName, int queryType) {
        DNSQueryResult result = new DNSQueryResult();
        result.setClientIP(clientIP);
        result.setDomainName(domainName);
        result.setQueryType(queryType);
        result.setTimestamp(LocalDateTime.now());

        totalQueries.incrementAndGet();

        if (isRateLimited(clientIP)) {
            result.setBlocked(true);
            result.setReason("Rate limit exceeded");
            blockedQueries.incrementAndGet();
            logEvent(clientIP, domainName, "BLOCKED", "Rate limit exceeded");
            return result;
        }

        if (isDomainBlocked(domainName)) {
            result.setBlocked(true);
            result.setReason("Blocked domain");
            result.setBlocked(true);
            blockedQueries.incrementAndGet();
            logEvent(clientIP, domainName, "BLOCKED", "Blocked domain");
            return result;
        }

        if (isSuspiciousDomain(domainName)) {
            result.setSuspicious(true);
            result.setWarning("Suspicious TLD or pattern");
            suspiciousQueries.incrementAndGet();
            logEvent(clientIP, domainName, "SUSPICIOUS", "Suspicious domain pattern");
        }

        if (isDNSSplitTunneling(clientIP, domainName)) {
            result.setSuspicious(true);
            result.setWarning("Possible DNS tunnel detected");
            suspiciousQueries.incrementAndGet();
            logEvent(clientIP, domainName, "SUSPICIOUS", "Possible DNS tunnel");
        }

        DNSQueryRecord record = new DNSQueryRecord(clientIP, domainName, queryType, LocalDateTime.now());
        queryCache.put(domainName + ":" + clientIP, record);

        List<ClientQueryHistory> history = clientQueryHistory.computeIfAbsent(clientIP, k -> new ArrayList<>());
        history.add(new ClientQueryHistory(domainName, LocalDateTime.now()));

        if (history.size() > 1000) {
            history.subList(0, 500).clear();
        }

        String resolvedIP = resolveDomain(domainName);
        result.setResolvedIP(resolvedIP);
        result.setBlocked(false);

        logEvent(clientIP, domainName, "ALLOWED", "Query allowed");
        return result;
    }

    private boolean isRateLimited(String clientIP) {
        List<ClientQueryHistory> history = clientQueryHistory.get(clientIP);
        if (history == null) return false;

        LocalDateTime oneMinuteAgo = LocalDateTime.now().minusMinutes(1);
        long queriesLastMinute = history.stream()
            .filter(q -> q.getTimestamp().isAfter(oneMinuteAgo))
            .count();

        if (queriesLastMinute > MAX_QUERIES_PER_MINUTE) {
            return true;
        }

        LocalDateTime oneHourAgo = LocalDateTime.now().minusHours(1);
        long queriesLastHour = history.stream()
            .filter(q -> q.getTimestamp().isAfter(oneHourAgo))
            .count();

        return queriesLastHour > MAX_QUERIES_PER_HOUR;
    }

    private boolean isDomainBlocked(String domainName) {
        String lowerDomain = domainName.toLowerCase();
        for (String blocked : blockedDomains) {
            if (lowerDomain.endsWith(blocked) || lowerDomain.equals(blocked)) {
                return true;
            }
        }
        return false;
    }

    private boolean isSuspiciousDomain(String domainName) {
        String lowerDomain = domainName.toLowerCase();

        for (String tld : suspiciousTLDs) {
            if (lowerDomain.endsWith(tld)) {
                return true;
            }
        }

        if (lowerDomain.length() > 50) {
            return true;
        }

        int dots = lowerDomain.split("\\.").length - 1;
        if (dots > 5) {
            return true;
        }

        if (lowerDomain.contains("----") || lowerDomain.contains("----")) {
            return true;
        }

        return false;
    }

    private boolean isDNSSplitTunneling(String clientIP, String domainName) {
        List<ClientQueryHistory> history = clientQueryHistory.get(clientIP);
        if (history == null || history.size() < 10) return false;

        LocalDateTime recent = LocalDateTime.now().minusMinutes(5);
        long recentQueries = history.stream()
            .filter(q -> q.getTimestamp().isAfter(recent))
            .count();

        if (recentQueries < 100) return false;

        Set<String> uniqueDomains = history.stream()
            .filter(q -> q.getTimestamp().isAfter(recent))
            .map(ClientQueryHistory::getDomain)
            .collect(java.util.stream.Collectors.toSet());

        double entropy = calculateEntropy(String.join(".", uniqueDomains));
        return entropy > 4.5;
    }

    private double calculateEntropy(String data) {
        if (data == null || data.isEmpty()) return 0;

        Map<Character, Long> frequency = new HashMap<>();
        for (char c : data.toCharArray()) {
            frequency.merge(c, 1L, Long::sum);
        }

        double entropy = 0;
        int length = data.length();
        for (long count : frequency.values()) {
            double probability = (double) count / length;
            entropy -= probability * (Math.log(probability) / Math.log(2));
        }

        return entropy;
    }

    private String resolveDomain(String domainName) {
        for (DNSZone zone : zones.values()) {
            String ip = zone.resolve(domainName);
            if (ip != null) {
                return ip;
            }
        }

        try {
            InetAddress address = InetAddress.getByName(domainName);
            return address.getHostAddress();
        } catch (Exception e) {
            return null;
        }
    }

    public void addBlockedDomain(String domain) {
        blockedDomains.add(domain.toLowerCase());
        logger.info("Added blocked domain: {}", domain);
    }

    public void removeBlockedDomain(String domain) {
        blockedDomains.remove(domain.toLowerCase());
        logger.info("Removed blocked domain: {}", domain);
    }

    public void addZone(String zoneName, Map<String, String> records) {
        DNSZone zone = new DNSZone(zoneName);
        for (Map.Entry<String, String> entry : records.entrySet()) {
            zone.addRecord(entry.getKey(), entry.getValue());
        }
        zones.put(zoneName, zone);
        logger.info("Added DNS zone: {}", zoneName);
    }

    public Map<String, Object> getStats() {
        Map<String, Object> stats = new HashMap<>();
        stats.put("totalQueries", totalQueries.get());
        stats.put("blockedQueries", blockedQueries.get());
        stats.put("suspiciousQueries", suspiciousQueries.get());
        stats.put("cachedQueries", queryCache.size());
        stats.put("activeClients", clientQueryHistory.size());
        stats.put("zonesConfigured", zones.size());
        stats.put("blockedDomains", blockedDomains.size());

        return stats;
    }

    public Map<String, DNSQueryRecord> getRecentQueries(int limit) {
        Map<String, DNSQueryRecord> recent = new LinkedHashMap<>();
        int count = 0;
        for (Map.Entry<String, DNSQueryRecord> entry : queryCache.entrySet()) {
            if (count++ >= limit) break;
            recent.put(entry.getKey(), entry.getValue());
        }
        return recent;
    }

    public List<String> getTopQueriedDomains(int limit) {
        Map<String, Long> domainCounts = new HashMap<>();
        for (DNSQueryRecord record : queryCache.values()) {
            String domain = record.getDomainName();
            domainCounts.merge(domain, 1L, Long::sum);
        }

        return domainCounts.entrySet().stream()
            .sorted(Map.Entry.<String, Long>comparingByValue().reversed())
            .limit(limit)
            .map(Map.Entry::getKey)
            .collect(java.util.stream.Collectors.toList());
    }

    public Map<String, Long> getClientQueryStats(String clientIP) {
        List<ClientQueryHistory> history = clientQueryHistory.get(clientIP);
        if (history == null) {
            return new HashMap<>();
        }

        Map<String, Long> stats = new HashMap<>();
        stats.put("totalQueries", (long) history.size());

        LocalDateTime oneMinuteAgo = LocalDateTime.now().minusMinutes(1);
        long recentQueries = history.stream()
            .filter(q -> q.getTimestamp().isAfter(oneMinuteAgo))
            .count();
        stats.put("queriesLastMinute", recentQueries);

        return stats;
    }

    private void logEvent(String clientIP, String domain, String eventType, String details) {
        DNSEvent event = new DNSEvent(clientIP, domain, eventType, details, LocalDateTime.now());
        eventLog.offer(event);

        if (eventLog.size() > 5000) {
            eventLog.poll();
        }
    }

    public List<DNSEvent> getRecentEvents(int limit) {
        List<DNSEvent> events = new ArrayList<>();
        int count = 0;
        for (DNSEvent event : eventLog) {
            if (count++ >= limit) break;
            events.add(event);
        }
        return events;
    }

    public static class DNSQueryResult {
        private String clientIP;
        private String domainName;
        private int queryType;
        private String resolvedIP;
        private boolean blocked;
        private boolean suspicious;
        private String reason;
        private String warning;
        private LocalDateTime timestamp;

        public String getClientIP() { return clientIP; }
        public void setClientIP(String clientIP) { this.clientIP = clientIP; }
        public String getDomainName() { return domainName; }
        public void setDomainName(String domainName) { this.domainName = domainName; }
        public int getQueryType() { return queryType; }
        public void setQueryType(int queryType) { this.queryType = queryType; }
        public String getResolvedIP() { return resolvedIP; }
        public void setResolvedIP(String resolvedIP) { this.resolvedIP = resolvedIP; }
        public boolean isBlocked() { return blocked; }
        public void setBlocked(boolean blocked) { this.blocked = blocked; }
        public boolean isSuspicious() { return suspicious; }
        public void setSuspicious(boolean suspicious) { this.suspicious = suspicious; }
        public String getReason() { return reason; }
        public void setReason(String reason) { this.reason = reason; }
        public String getWarning() { return warning; }
        public void setWarning(String warning) { this.warning = warning; }
        public LocalDateTime getTimestamp() { return timestamp; }
        public void setTimestamp(LocalDateTime timestamp) { this.timestamp = timestamp; }
    }

    public static class DNSQueryRecord {
        private final String clientIP;
        private final String domainName;
        private final int queryType;
        private final LocalDateTime timestamp;

        public DNSQueryRecord(String clientIP, String domainName, int queryType, LocalDateTime timestamp) {
            this.clientIP = clientIP;
            this.domainName = domainName;
            this.queryType = queryType;
            this.timestamp = timestamp;
        }

        public String getClientIP() { return clientIP; }
        public String getDomainName() { return domainName; }
        public int getQueryType() { return queryType; }
        public LocalDateTime getTimestamp() { return timestamp; }
    }

    public static class DNSZone {
        private final String name;
        private final Map<String, String> records = new HashMap<>();

        public DNSZone(String name) {
            this.name = name;
        }

        public void addRecord(String domain, String ip) {
            records.put(domain.toLowerCase(), ip);
        }

        public String resolve(String domain) {
            return records.get(domain.toLowerCase());
        }

        public String getName() { return name; }
        public Map<String, String> getRecords() { return records; }
    }

    public static class ClientQueryHistory {
        private final String domain;
        private final LocalDateTime timestamp;

        public ClientQueryHistory(String domain, LocalDateTime timestamp) {
            this.domain = domain;
            this.timestamp = timestamp;
        }

        public String getDomain() { return domain; }
        public LocalDateTime getTimestamp() { return timestamp; }
    }

    public static class DNSEvent {
        private final String clientIP;
        private final String domain;
        private final String eventType;
        private final String details;
        private final LocalDateTime timestamp;

        public DNSEvent(String clientIP, String domain, String eventType, String details, LocalDateTime timestamp) {
            this.clientIP = clientIP;
            this.domain = domain;
            this.eventType = eventType;
            this.details = details;
            this.timestamp = timestamp;
        }

        public String getClientIP() { return clientIP; }
        public String getDomain() { return domain; }
        public String getEventType() { return eventType; }
        public String getDetails() { return details; }
        public LocalDateTime getTimestamp() { return timestamp; }
    }
}
