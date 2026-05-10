package com.aluer.security;

import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

@Service
public class DNSTunnelDetectionService {

    private final Map<String, DNSQueryTracker> queryTrackers = new ConcurrentHashMap<>();
    private final Map<String, Instant> blockedSources = new ConcurrentHashMap<>();
    private final ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor();
    private final AtomicLong totalDetections = new AtomicLong(0);

    // DNS tunneling indicators
    private static final int MAX_QUERY_LENGTH = 52;
    private static final int MAX_SUBDOMAIN_COUNT = 3;
    private static final int MAX_QUERIES_PER_MINUTE = 60;
    private static final int MAX_UNIQUE_SUBDOMAINS = 30;
    private static final double ENTROPY_THRESHOLD = 3.8;
    private static final long BLOCK_SECONDS = 1800;

    private static final Set<String> SUSPICIOUS_DNS_TYPES = Set.of("TXT", "NULL", "CNAME");
    private static final Set<String> SUSPICIOUS_TLDS = Set.of(".xyz", ".top", ".tk", ".ml", ".ga", ".cf", ".gq",
            ".pw", ".club", ".work", ".date", ".bid", ".surf");

    public DNSTunnelDetectionService() {
        scheduler.scheduleAtFixedRate(this::cleanupExpired, 120, 300, TimeUnit.SECONDS);
    }

    public TunnelCheckResult checkDNSQuery(String sourceIP, String domain, String queryType) {
        if (blockedSources.containsKey(sourceIP)) {
            if (Instant.now().isAfter(blockedSources.get(sourceIP))) {
                blockedSources.remove(sourceIP);
            } else {
                return TunnelCheckResult.blocked("Source is blocked for DNS tunneling");
            }
        }

        int score = 0;
        List<String> reasons = new ArrayList<>();

        // Check 1: Long subdomain (data exfiltration via DNS)
        if (domain.length() > MAX_QUERY_LENGTH) {
            score += 25;
            reasons.add("LONG_DOMAIN: " + domain.length() + " chars");
        }

        // Check 2: Too many subdomains
        int subdomainCount = domain.split("\\.").length - 2;
        if (subdomainCount > MAX_SUBDOMAIN_COUNT) {
            score += 15;
            reasons.add("MANY_SUBDOMAINS: " + subdomainCount);
        }

        // Check 3: High entropy subdomain (encoded data)
        String subdomain = domain.contains(".") ? domain.substring(0, domain.indexOf('.')) : domain;
        double entropy = calculateEntropy(subdomain);
        if (entropy > ENTROPY_THRESHOLD) {
            score += 30;
            reasons.add("HIGH_ENTROPY: " + String.format("%.2f", entropy));
        }

        // Check 4: Suspicious TLD
        for (String tld : SUSPICIOUS_TLDS) {
            if (domain.toLowerCase().endsWith(tld)) {
                score += 10;
                reasons.add("SUSPICIOUS_TLD: " + tld);
                break;
            }
        }

        // Check 5: Suspicious DNS record type
        if (SUSPICIOUS_DNS_TYPES.contains(queryType.toUpperCase())) {
            score += 15;
            reasons.add("SUSPICIOUS_TYPE: " + queryType);
        }

        // Check 6: Query frequency
        DNSQueryTracker tracker = queryTrackers.computeIfAbsent(sourceIP, k -> new DNSQueryTracker());
        tracker.recordQuery(domain, queryType);
        if (tracker.queriesPerMinute > MAX_QUERIES_PER_MINUTE) {
            score += 20;
            reasons.add("HIGH_FREQUENCY: " + tracker.queriesPerMinute + "/min");
        }
        if (tracker.uniqueSubdomains.size() > MAX_UNIQUE_SUBDOMAINS) {
            score += 20;
            reasons.add("MANY_UNIQUE: " + tracker.uniqueSubdomains.size());
        }

        // Check 7: Base32/Base64 encoded subdomain
        if (looksEncoded(subdomain)) {
            score += 20;
            reasons.add("ENCODED_SUBDOMAIN");
        }

        if (score >= 60) {
            blockedSources.put(sourceIP, Instant.now().plusSeconds(BLOCK_SECONDS));
            totalDetections.incrementAndGet();
            return TunnelCheckResult.detected(score, reasons, BLOCK_SECONDS);
        } else if (score >= 30) {
            return TunnelCheckResult.suspicious(score, reasons);
        }

        return TunnelCheckResult.clean();
    }

    public Map<String, Object> getStatus() {
        Map<String, Object> status = new LinkedHashMap<>();
        status.put("trackedSources", queryTrackers.size());
        status.put("blockedSources", blockedSources.size());
        status.put("totalDetections", totalDetections.get());
        List<Map<String, Object>> tracked = new ArrayList<>();
        for (Map.Entry<String, DNSQueryTracker> e : queryTrackers.entrySet()) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("ip", e.getKey());
            m.put("queriesPerMinute", e.getValue().queriesPerMinute);
            m.put("uniqueSubdomains", e.getValue().uniqueSubdomains.size());
            tracked.add(m);
        }
        tracked.sort((a, b) -> (int) b.get("queriesPerMinute") - (int) a.get("queriesPerMinute"));
        status.put("topTrackers", tracked.subList(0, Math.min(tracked.size(), 20)));
        return status;
    }

    public long getTotalDetections() { return totalDetections.get(); }

    private double calculateEntropy(String s) {
        if (s.isEmpty()) return 0;
        Map<Character, Integer> freq = new HashMap<>();
        for (char c : s.toCharArray()) freq.merge(c, 1, Integer::sum);
        double entropy = 0;
        int len = s.length();
        for (int count : freq.values()) {
            double p = (double) count / len;
            entropy -= p * (Math.log(p) / Math.log(2));
        }
        return entropy;
    }

    private boolean looksEncoded(String s) {
        int upperCount = 0;
        int digitCount = 0;
        for (char c : s.toCharArray()) {
            if (c >= 'A' && c <= 'Z') upperCount++;
            if (c >= '0' && c <= '9') digitCount++;
        }
        double ratio = (double) (upperCount + digitCount) / s.length();
        return s.length() >= 16 && ratio > 0.9;
    }

    private void cleanupExpired() {
        Instant now = Instant.now();
        blockedSources.entrySet().removeIf(e -> e.getValue().isBefore(now));
        queryTrackers.entrySet().removeIf(e -> e.getValue().lastQuery != null
                && e.getValue().lastQuery.plusSeconds(600).isBefore(now));
    }

    private static class DNSQueryTracker {
        long queriesPerMinute;
        final Set<String> uniqueSubdomains = new HashSet<>();
        Instant lastQuery;
        Instant minuteStart = Instant.now();

        void recordQuery(String domain, String queryType) {
            lastQuery = Instant.now();
            if (Instant.now().isAfter(minuteStart.plusSeconds(60))) {
                queriesPerMinute = 0;
                minuteStart = Instant.now();
            }
            queriesPerMinute++;
            if (domain.contains(".")) {
                uniqueSubdomains.add(domain.substring(0, domain.indexOf('.')));
            }
        }
    }

    public static class TunnelCheckResult {
        private final boolean blocked;
        private final boolean detected;
        private final boolean suspicious;
        private final int score;
        private final List<String> reasons;
        private final String message;
        private final long blockSeconds;

        private TunnelCheckResult(boolean blocked, boolean detected, boolean suspicious, int score,
                                  List<String> reasons, String message, long blockSeconds) {
            this.blocked = blocked;
            this.detected = detected;
            this.suspicious = suspicious;
            this.score = score;
            this.reasons = reasons;
            this.message = message;
            this.blockSeconds = blockSeconds;
        }

        public static TunnelCheckResult clean() {
            return new TunnelCheckResult(false, false, false, 0, List.of(), null, 0);
        }

        public static TunnelCheckResult suspicious(int score, List<String> reasons) {
            return new TunnelCheckResult(false, false, true, score, reasons,
                    "Suspicious DNS: " + String.join("; ", reasons), 0);
        }

        public static TunnelCheckResult detected(int score, List<String> reasons, long blockSeconds) {
            return new TunnelCheckResult(true, true, true, score, reasons,
                    "DNS tunnel detected: " + String.join("; ", reasons), blockSeconds);
        }

        public static TunnelCheckResult blocked(String message) {
            return new TunnelCheckResult(true, false, false, 0, List.of(), message, 0);
        }

        public boolean isBlocked() { return blocked; }
        public boolean isDetected() { return detected; }
        public boolean isSuspicious() { return suspicious; }
        public int getScore() { return score; }
        public List<String> getReasons() { return reasons; }
        public String getMessage() { return message; }
        public long getBlockSeconds() { return blockSeconds; }
    }
}
