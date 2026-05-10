package com.aluer.security;

import com.aluer.config.ServerGuardConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.atomic.AtomicLong;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.net.URL;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.UnknownHostException;

@Component
public class ThreatIntelligenceService {
    private static final Logger logger = LoggerFactory.getLogger(ThreatIntelligenceService.class);

    private final ServerGuardConfig config;
    private final Map<String, ThreatIndicator> threatDatabase = new ConcurrentHashMap<>();
    private final Map<String, IPReputation> ipReputations = new ConcurrentHashMap<>();
    private final Queue<ThreatEvent> eventLog = new ConcurrentLinkedQueue<>();
    private final Map<String, List<String>> threatFeeds = new ConcurrentHashMap<>();
    private final Map<String, FeedState> feedStates = new ConcurrentHashMap<>();
    private final Map<String, CachedLookup> lookupCache = new ConcurrentHashMap<>();
    private final AtomicLong totalLookups = new AtomicLong(0);
    private final AtomicLong threatsDetected = new AtomicLong(0);
    private final AtomicLong iocsIdentified = new AtomicLong(0);

    private static final DateTimeFormatter DATE_FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    public ThreatIntelligenceService() {
        this(new ServerGuardConfig());
    }

    @Autowired
    public ThreatIntelligenceService(ServerGuardConfig config) {
        this.config = config;
        initializeDefaultThreatData();
    }

    private void initializeDefaultThreatData() {
        addThreatIndicator("103.21.244.0/24", "NETWORK", "KNOWN_ATTACKER", "Known malicious IP range", 95);
        addThreatIndicator("103.22.200.0/24", "NETWORK", "BOTNET", "Botnet command and control", 90);
        addThreatIndicator("103.31.4.0/24", "NETWORK", "SPAM_SOURCE", "Spam sending infrastructure", 75);
        addThreatIndicator("104.16.0.0/12", "NETWORK", "MALWARE_HOST", "Malware distribution network", 85);
        addThreatIndicator("108.162.192.0/18", "NETWORK", "PHISHING", "Phishing campaign infrastructure", 80);
        addThreatIndicator("141.101.64.0/18", "NETWORK", "ADWARE", "Adware distribution", 60);
        addThreatIndicator("162.158.64.0/18", "NETWORK", "SUSPICIOUS", "Suspicious activity", 50);
        addThreatIndicator("172.64.0.0/13", "NETWORK", "TOR_EXIT", "Tor exit node", 70);
        addThreatIndicator("173.245.48.0/20", "NETWORK", "VPN_PROXY", "VPN/Proxy service", 65);
        addThreatIndicator("188.114.96.0/20", "NETWORK", "MALICIOUS", "Known malicious activity", 85);

        addThreatIndicator("bad-actor.exe", "FILE_HASH", "MALWARE", "Known malware sample", 100);
        addThreatIndicator("eicar_test_file", "FILE_HASH", "TEST", "EICAR test file", 100);
        addThreatIndicator("suspicious-script.js", "FILE_HASH", "MALWARE", "Malicious JavaScript", 95);

        addThreatIndicator("evil-domain.com", "DOMAIN", "MALICIOUS", "Known malicious domain", 90);
        addThreatIndicator("phishing-bank.fake", "DOMAIN", "PHISHING", "Phishing domain", 100);
        addThreatIndicator("ransom-c2.evil", "DOMAIN", "RANSOMWARE", "Ransomware command and control", 100);
        addThreatIndicator("malware-dist.net", "DOMAIN", "MALWARE_HOST", "Malware distribution", 95);
        addThreatIndicator("coin-miner.pool", "DOMAIN", "CRYPTOMINING", "Cryptocurrency mining pool", 80);

        addThreatIndicator("CVE-2024-0001", "CVE", "VULNERABILITY", "Critical vulnerability", 100);
        addThreatIndicator("CVE-2024-0002", "CVE", "VULNERABILITY", "High severity vulnerability", 90);
        addThreatIndicator("CVE-2024-0003", "CVE", "VULNERABILITY", "Medium severity vulnerability", 70);

        logger.info("Initialized threat database with {} indicators", threatDatabase.size());
    }

    public void addThreatIndicator(String indicator, String type, String category, String description, int severity) {
        ThreatIndicator ti = new ThreatIndicator(indicator, type, category, description, severity);
        threatDatabase.put(indicator.toLowerCase(), ti);
        logger.info("Added threat indicator: {} [{}] severity: {}", indicator, type, severity);
    }

    public ThreatLookupResult lookupIP(String ip) {
        CachedLookup cached = lookupCache.get("IP:" + ip);
        if (cached != null && !cached.isExpired(config.getSecurity().getThreatFeeds().getCacheTtlMinutes())) {
            return cached.result.copy();
        }

        ThreatLookupResult result = new ThreatLookupResult();
        result.setIndicator(ip);
        result.setType("IP");
        result.setTimestamp(LocalDateTime.now());

        totalLookups.incrementAndGet();

        IPReputation rep = ipReputations.get(ip);
        if (rep != null) {
            result.setReputationScore(rep.getScore());
            result.setThreatCategories(new ArrayList<>(rep.getThreatCategories()));
            result.setLastSeen(rep.getLastSeen());
            result.setConfidence(rep.getConfidence());
        }

        for (Map.Entry<String, ThreatIndicator> entry : threatDatabase.entrySet()) {
            if (isIPInRange(ip, entry.getKey())) {
                ThreatIndicator ti = entry.getValue();
                result.addMatchedIndicator(ti);
                threatsDetected.incrementAndGet();
                iocsIdentified.incrementAndGet();
            }
        }

        if (result.getMatchedIndicators().isEmpty()) {
            result.setReputationScore(calculateDefaultReputation(ip));
            result.setThreatCategories(new ArrayList<>());
            result.setConfidence(50);
        }

        updateIPReputation(ip, result);
        lookupCache.put("IP:" + ip, new CachedLookup(result.copy()));
        return result;
    }

    public ThreatLookupResult lookupDomain(String domain) {
        CachedLookup cached = lookupCache.get("DOMAIN:" + domain.toLowerCase());
        if (cached != null && !cached.isExpired(config.getSecurity().getThreatFeeds().getCacheTtlMinutes())) {
            return cached.result.copy();
        }

        ThreatLookupResult result = new ThreatLookupResult();
        result.setIndicator(domain);
        result.setType("DOMAIN");
        result.setTimestamp(LocalDateTime.now());

        totalLookups.incrementAndGet();

        ThreatIndicator ti = threatDatabase.get(domain.toLowerCase());
        if (ti != null) {
            result.addMatchedIndicator(ti);
            result.setReputationScore(ti.getSeverity());
            result.setThreatCategories(Collections.singletonList(ti.getCategory()));
            result.setConfidence(ti.getSeverity());
            threatsDetected.incrementAndGet();
            iocsIdentified.incrementAndGet();
        } else {
            result.setReputationScore(calculateDomainReputation(domain));
            result.setThreatCategories(new ArrayList<>());
            result.setConfidence(30);
        }

        lookupCache.put("DOMAIN:" + domain.toLowerCase(), new CachedLookup(result.copy()));
        return result;
    }

    public ThreatLookupResult lookupHash(String hash) {
        CachedLookup cached = lookupCache.get("HASH:" + hash.toLowerCase());
        if (cached != null && !cached.isExpired(config.getSecurity().getThreatFeeds().getCacheTtlMinutes())) {
            return cached.result.copy();
        }

        ThreatLookupResult result = new ThreatLookupResult();
        result.setIndicator(hash);
        result.setType("FILE_HASH");
        result.setTimestamp(LocalDateTime.now());

        totalLookups.incrementAndGet();

        ThreatIndicator ti = threatDatabase.get(hash.toLowerCase());
        if (ti != null) {
            result.addMatchedIndicator(ti);
            result.setReputationScore(ti.getSeverity());
            result.setThreatCategories(Collections.singletonList(ti.getCategory()));
            result.setConfidence(ti.getSeverity());
            threatsDetected.incrementAndGet();
            iocsIdentified.incrementAndGet();
        } else {
            result.setReputationScore(0);
            result.setThreatCategories(new ArrayList<>());
            result.setConfidence(0);
        }

        lookupCache.put("HASH:" + hash.toLowerCase(), new CachedLookup(result.copy()));
        return result;
    }

    private boolean isIPInRange(String ip, String cidr) {
        if (!cidr.contains("/")) {
            return ip.equals(cidr);
        }
        try {
            String[] parts = cidr.split("/");
            byte[] address = InetAddress.getByName(parts[0]).getAddress();
            byte[] target = InetAddress.getByName(ip).getAddress();
            int prefix = Integer.parseInt(parts[1]);
            int fullBytes = prefix / 8;
            int remainingBits = prefix % 8;

            for (int i = 0; i < fullBytes; i++) {
                if (address[i] != target[i]) {
                    return false;
                }
            }

            if (remainingBits == 0) {
                return true;
            }

            int mask = (-1) << (8 - remainingBits);
            return (address[fullBytes] & mask) == (target[fullBytes] & mask);
        } catch (UnknownHostException | NumberFormatException e) {
            return false;
        }
    }

    private int calculateDefaultReputation(String ip) {
        if (ip.startsWith("127.") || ip.startsWith("192.168.") || ip.startsWith("10.")) {
            return 100;
        }
        if (ip.startsWith("172.")) {
            String[] parts = ip.split("\\.");
            if (parts.length >= 1) {
                int second = Integer.parseInt(parts[1]);
                if (second >= 16 && second <= 31) {
                    return 100;
                }
            }
        }
        return 50;
    }

    private int calculateDomainReputation(String domain) {
        String[] parts = domain.split("\\.");
        if (parts.length < 2) return 50;

        String tld = parts[parts.length - 1];
        if (tld.equals("tk") || tld.equals("ml") || tld.equals("ga") || tld.equals("cf") || tld.equals("gq")) {
            return 30;
        }

        if (domain.contains("free") || domain.contains("download") || domain.contains("crack")) {
            return 20;
        }

        return 50;
    }

    private void updateIPReputation(String ip, ThreatLookupResult result) {
        IPReputation rep = ipReputations.computeIfAbsent(ip, k -> new IPReputation(ip));

        if (!result.getMatchedIndicators().isEmpty()) {
            rep.addThreatCategory(result.getMatchedIndicators().get(0).getCategory());
            rep.adjustScore(-10);
        } else {
            rep.adjustScore(5);
        }

        rep.setLastSeen(LocalDateTime.now());
    }

    public void updateIPReputationFromExternal(String ip, int score, List<String> categories) {
        IPReputation rep = ipReputations.computeIfAbsent(ip, k -> new IPReputation(ip));
        rep.setScore(score);
        for (String category : categories) {
            rep.addThreatCategory(category);
        }
        rep.setLastSeen(LocalDateTime.now());
        logger.info("Updated reputation for IP: {} score: {}", ip, score);
    }

    public Map<String, IPReputation> getMaliciousIPs(int limit) {
        Map<String, IPReputation> malicious = new HashMap<>();
        for (Map.Entry<String, IPReputation> entry : ipReputations.entrySet()) {
            if (entry.getValue().getScore() < 30) {
                malicious.put(entry.getKey(), entry.getValue());
            }
        }
        return malicious;
    }

    public void addThreatFeed(String feedName, List<String> indicators) {
        threatFeeds.put(feedName, indicators);
        logger.info("Added threat feed: {} with {} indicators", feedName, indicators.size());
    }

    public Map<String, Object> refreshFeeds() {
        Map<String, Object> result = new LinkedHashMap<>();
        int loaded = 0;
        int failed = 0;

        if (!config.getSecurity().getThreatFeeds().isEnabled()) {
            result.put("enabled", false);
            result.put("loadedFeeds", loaded);
            result.put("failedFeeds", failed);
            return result;
        }

        for (ServerGuardConfig.FeedSourceConfig source : config.getSecurity().getThreatFeeds().getSources()) {
            if (!source.isEnabled() || source.getUrl() == null || source.getUrl().isBlank()) {
                continue;
            }

            try {
                List<String> indicators = downloadIndicators(source);
                if (!indicators.isEmpty()) {
                    addThreatFeed(source.getName(), indicators);
                    for (String indicator : indicators) {
                        addThreatIndicator(indicator, source.getType(), "EXTERNAL_FEED",
                            "Loaded from feed " + source.getName(), Math.min(100, Math.max(10, source.getWeight())));
                    }
                    feedStates.put(source.getName(), new FeedState(source.getName(), true, indicators.size(), LocalDateTime.now(), null));
                    loaded++;
                }
            } catch (IOException e) {
                feedStates.put(source.getName(), new FeedState(source.getName(), false, 0, LocalDateTime.now(), e.getMessage()));
                failed++;
                logger.warn("Threat feed refresh failed for {}: {}", source.getName(), e.getMessage());
            }
        }

        result.put("enabled", true);
        result.put("loadedFeeds", loaded);
        result.put("failedFeeds", failed);
        result.put("feedStates", getFeedStatus());
        return result;
    }

    public Map<String, Object> getFeedStatus() {
        Map<String, Object> status = new LinkedHashMap<>();
        status.put("configuredSources", config.getSecurity().getThreatFeeds().getSources().size());
        status.put("activeFeeds", threatFeeds.size());
        status.put("states", new ArrayList<>(feedStates.values()));
        return status;
    }

    private List<String> downloadIndicators(ServerGuardConfig.FeedSourceConfig source) throws IOException {
        HttpURLConnection connection = (HttpURLConnection) new URL(source.getUrl()).openConnection();
        connection.setConnectTimeout(config.getSecurity().getThreatFeeds().getConnectTimeoutMs());
        connection.setReadTimeout(config.getSecurity().getThreatFeeds().getReadTimeoutMs());
        connection.setRequestMethod("GET");

        List<String> indicators = new ArrayList<>();
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(connection.getInputStream()))) {
            String line;
            while ((line = reader.readLine()) != null) {
                String trimmed = line.trim();
                if (!trimmed.isEmpty() && !trimmed.startsWith("#")) {
                    indicators.add(trimmed);
                }
            }
        }
        return indicators;
    }

    public Map<String, Object> getStats() {
        Map<String, Object> stats = new HashMap<>();
        stats.put("totalLookups", totalLookups.get());
        stats.put("threatsDetected", threatsDetected.get());
        stats.put("iocsIdentified", iocsIdentified.get());
        stats.put("indicatorsInDatabase", threatDatabase.size());
        stats.put("uniqueIPsAnalyzed", ipReputations.size());
        stats.put("threatFeeds", threatFeeds.size());
        stats.put("feedCacheEntries", lookupCache.size());

        long maliciousCount = ipReputations.values().stream()
            .filter(r -> r.getScore() < 30)
            .count();
        stats.put("maliciousIPs", maliciousCount);

        return stats;
    }

    public List<ThreatEvent> getRecentEvents(int limit) {
        List<ThreatEvent> events = new ArrayList<>();
        int count = 0;
        for (ThreatEvent event : eventLog) {
            if (count++ >= limit) break;
            events.add(event);
        }
        return events;
    }

    public void logThreatEvent(String indicator, String type, String details) {
        ThreatEvent event = new ThreatEvent(indicator, type, details, LocalDateTime.now());
        eventLog.offer(event);

        if (eventLog.size() > 5000) {
            eventLog.poll();
        }
    }

    public static class ThreatIndicator {
        private final String indicator;
        private final String type;
        private final String category;
        private final String description;
        private final int severity;

        public ThreatIndicator(String indicator, String type, String category, String description, int severity) {
            this.indicator = indicator;
            this.type = type;
            this.category = category;
            this.description = description;
            this.severity = severity;
        }

        public String getIndicator() { return indicator; }
        public String getType() { return type; }
        public String getCategory() { return category; }
        public String getDescription() { return description; }
        public int getSeverity() { return severity; }
    }

    public static class ThreatLookupResult {
        private String indicator;
        private String type;
        private int reputationScore;
        private List<String> threatCategories;
        private List<ThreatIndicator> matchedIndicators;
        private LocalDateTime lastSeen;
        private int confidence;
        private LocalDateTime timestamp;

        public ThreatLookupResult() {
            this.threatCategories = new ArrayList<>();
            this.matchedIndicators = new ArrayList<>();
        }

        public String getIndicator() { return indicator; }
        public void setIndicator(String indicator) { this.indicator = indicator; }
        public String getType() { return type; }
        public void setType(String type) { this.type = type; }
        public int getReputationScore() { return reputationScore; }
        public void setReputationScore(int reputationScore) { this.reputationScore = reputationScore; }
        public List<String> getThreatCategories() { return threatCategories; }
        public void setThreatCategories(List<String> threatCategories) { this.threatCategories = threatCategories; }
        public List<ThreatIndicator> getMatchedIndicators() { return matchedIndicators; }
        public void addMatchedIndicator(ThreatIndicator indicator) { this.matchedIndicators.add(indicator); }
        public LocalDateTime getLastSeen() { return lastSeen; }
        public void setLastSeen(LocalDateTime lastSeen) { this.lastSeen = lastSeen; }
        public int getConfidence() { return confidence; }
        public void setConfidence(int confidence) { this.confidence = confidence; }
        public LocalDateTime getTimestamp() { return timestamp; }
        public void setTimestamp(LocalDateTime timestamp) { this.timestamp = timestamp; }

        public ThreatLookupResult copy() {
            ThreatLookupResult copy = new ThreatLookupResult();
            copy.setIndicator(indicator);
            copy.setType(type);
            copy.setReputationScore(reputationScore);
            copy.setThreatCategories(new ArrayList<>(threatCategories));
            for (ThreatIndicator matchedIndicator : matchedIndicators) {
                copy.addMatchedIndicator(matchedIndicator);
            }
            copy.setLastSeen(lastSeen);
            copy.setConfidence(confidence);
            copy.setTimestamp(timestamp);
            return copy;
        }
    }

    public static class IPReputation {
        private final String ip;
        private volatile int score;
        private final Set<String> threatCategories;
        private volatile LocalDateTime firstSeen;
        private volatile LocalDateTime lastSeen;

        public IPReputation(String ip) {
            this.ip = ip;
            this.score = 50;
            this.threatCategories = new HashSet<>();
            this.firstSeen = LocalDateTime.now();
            this.lastSeen = LocalDateTime.now();
        }

        public void adjustScore(int delta) {
            this.score = Math.max(-100, Math.min(100, this.score + delta));
        }

        public void addThreatCategory(String category) {
            this.threatCategories.add(category);
        }

        public int getConfidence() {
            return Math.min(100, 50 + threatCategories.size() * 10);
        }

        public String getIp() { return ip; }
        public int getScore() { return score; }
        public void setScore(int score) { this.score = score; }
        public Set<String> getThreatCategories() { return threatCategories; }
        public LocalDateTime getFirstSeen() { return firstSeen; }
        public LocalDateTime getLastSeen() { return lastSeen; }
        public void setLastSeen(LocalDateTime lastSeen) { this.lastSeen = lastSeen; }
    }

    public static class ThreatEvent {
        private final String indicator;
        private final String type;
        private final String details;
        private final LocalDateTime timestamp;

        public ThreatEvent(String indicator, String type, String details, LocalDateTime timestamp) {
            this.indicator = indicator;
            this.type = type;
            this.details = details;
            this.timestamp = timestamp;
        }

        public String getIndicator() { return indicator; }
        public String getType() { return type; }
        public String getDetails() { return details; }
        public LocalDateTime getTimestamp() { return timestamp; }
    }

    public static class FeedState {
        private final String name;
        private final boolean success;
        private final int indicatorsLoaded;
        private final LocalDateTime lastRefresh;
        private final String error;

        public FeedState(String name, boolean success, int indicatorsLoaded, LocalDateTime lastRefresh, String error) {
            this.name = name;
            this.success = success;
            this.indicatorsLoaded = indicatorsLoaded;
            this.lastRefresh = lastRefresh;
            this.error = error;
        }

        public String getName() { return name; }
        public boolean isSuccess() { return success; }
        public int getIndicatorsLoaded() { return indicatorsLoaded; }
        public LocalDateTime getLastRefresh() { return lastRefresh; }
        public String getError() { return error; }
    }

    private static class CachedLookup {
        private final ThreatLookupResult result;
        private final long createdAt;

        private CachedLookup(ThreatLookupResult result) {
            this.result = result;
            this.createdAt = System.currentTimeMillis();
        }

        private boolean isExpired(long ttlMinutes) {
            return System.currentTimeMillis() - createdAt > ttlMinutes * 60_000L;
        }
    }
}
