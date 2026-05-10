package com.aluer.security;

import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

@Service
public class XXEProtectionService {

    private final Map<String, List<XXEEvent>> detections = new ConcurrentHashMap<>();
    private final AtomicLong totalDetections = new AtomicLong(0);

    private static final List<String> XXE_PATTERNS = List.of(
            "<!ENTITY", "<!DOCTYPE", "SYSTEM \"file://", "SYSTEM 'file://",
            "SYSTEM \"http://", "SYSTEM 'http://", "SYSTEM \"https://", "SYSTEM 'https://",
            "SYSTEM \"ftp://", "SYSTEM 'ftp://", "SYSTEM \"php://", "SYSTEM 'php://",
            "SYSTEM \"expect://", "SYSTEM 'expect://", "SYSTEM \"gopher://", "SYSTEM 'gopher://",
            "xmlns:xsi", "xsi:schemaLocation", "ENTITY %", "parameter-entity",
            "DOCTYPE xxe", "DOCTYPE root", "<?xml", "]>>", "&xxe;", "&lol;",
            "%remote;", "%param1;", "</!ELEMENT", "<!ATTLIST"
    );

    private static final List<String> BILLION_LAUGHS_PATTERNS = List.of(
            "&a1;", "&a2;", "&a3;", "&a4;", "&a5;",
            "&lol1;", "&lol2;", "&lol3;", "&lol4;", "&lol5;",
            "&lol6;", "&lol7;", "&lol8;", "&lol9;"
    );

    public XXECheckResult checkXML(String xmlContent, String sourceIP) {
        if (xmlContent == null || xmlContent.trim().isEmpty()) return XXECheckResult.clean();

        List<String> matched = new ArrayList<>();
        boolean isBillionLaughs = false;

        String lower = xmlContent.toLowerCase().trim();
        if (!lower.startsWith("<?xml") && !lower.contains("<!doctype") && !lower.contains("<!entity")) {
            return XXECheckResult.clean();
        }

        // Check for XXE patterns
        for (String pattern : XXE_PATTERNS) {
            if (lower.contains(pattern.toLowerCase())) {
                matched.add(pattern);
            }
        }

        // Check for Billion Laughs attack
        int blMatches = 0;
        for (String pattern : BILLION_LAUGHS_PATTERNS) {
            if (lower.contains(pattern.toLowerCase())) blMatches++;
        }
        if (blMatches >= 3) {
            isBillionLaughs = true;
            matched.add("BILLION_LAUGHS_ATTACK");
        }

        // Check for external entity reference
        if (lower.contains("system \"") || lower.contains("system '")) {
            matched.add("EXTERNAL_ENTITY");
        }

        // Check for entity expansion bomb
        if (countOccurrences(lower, "<!entity") >= 5) {
            matched.add("ENTITY_EXPANSION_BOMB");
        }

        if (!matched.isEmpty()) {
            XXEEvent event = new XXEEvent(Instant.now(), sourceIP, xmlContent.length() > 200 ? xmlContent.substring(0, 200) : xmlContent,
                    matched, isBillionLaughs);
            detections.computeIfAbsent(sourceIP, k -> new ArrayList<>()).add(event);
            totalDetections.incrementAndGet();
            return XXECheckResult.blocked(matched, isBillionLaughs);
        }

        return XXECheckResult.clean();
    }

    public String sanitizeXML(String xmlContent) {
        if (xmlContent == null) return null;
        return xmlContent
                .replaceAll("(?i)<!DOCTYPE[^>]*>", "<!-- DOCTYPE removed -->")
                .replaceAll("(?i)<!ENTITY[^>]*>", "<!-- ENTITY removed -->")
                .replaceAll("(?i)SYSTEM\\s+[\"'][^\"']*[\"']", "SYSTEM \"blocked\"");
    }

    public Map<String, Object> getStatus() {
        Map<String, Object> status = new LinkedHashMap<>();
        status.put("totalDetections", totalDetections.get());
        status.put("trackedSources", detections.size());
        List<Map<String, Object>> recent = new ArrayList<>();
        for (Map.Entry<String, List<XXEEvent>> e : detections.entrySet()) {
            for (XXEEvent event : e.getValue()) {
                Map<String, Object> m = new LinkedHashMap<>();
                m.put("source", e.getKey());
                m.put("patterns", event.matchedPatterns);
                m.put("billionLaughs", event.isBillionLaughs);
                m.put("time", event.timestamp.toString());
                m.put("snippet", event.snippet);
                recent.add(m);
            }
        }
        recent.sort((a, b) -> b.get("time").toString().compareTo(a.get("time").toString()));
        status.put("recentDetections", recent.subList(0, Math.min(recent.size(), 20)));
        return status;
    }

    public long getTotalDetections() { return totalDetections.get(); }

    private int countOccurrences(String text, String pattern) {
        int count = 0;
        int idx = 0;
        while ((idx = text.indexOf(pattern, idx)) != -1) {
            count++;
            idx += pattern.length();
        }
        return count;
    }

    private static class XXEEvent {
        final Instant timestamp;
        final String sourceIP;
        final String snippet;
        final List<String> matchedPatterns;
        final boolean isBillionLaughs;

        XXEEvent(Instant timestamp, String sourceIP, String snippet, List<String> matchedPatterns, boolean isBillionLaughs) {
            this.timestamp = timestamp;
            this.sourceIP = sourceIP;
            this.snippet = snippet;
            this.matchedPatterns = matchedPatterns;
            this.isBillionLaughs = isBillionLaughs;
        }
    }

    public static class XXECheckResult {
        private final boolean blocked;
        private final boolean isBillionLaughs;
        private final List<String> matchedPatterns;

        private XXECheckResult(boolean blocked, List<String> matchedPatterns, boolean isBillionLaughs) {
            this.blocked = blocked;
            this.matchedPatterns = matchedPatterns;
            this.isBillionLaughs = isBillionLaughs;
        }

        public static XXECheckResult clean() { return new XXECheckResult(false, List.of(), false); }
        public static XXECheckResult blocked(List<String> matchedPatterns, boolean isBillionLaughs) {
            return new XXECheckResult(true, matchedPatterns, isBillionLaughs);
        }

        public boolean isBlocked() { return blocked; }
        public boolean isBillionLaughs() { return isBillionLaughs; }
        public List<String> getMatchedPatterns() { return matchedPatterns; }
    }
}
