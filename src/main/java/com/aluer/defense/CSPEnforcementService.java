package com.aluer.defense;

import com.aluer.config.ServerGuardConfig;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

@Service
public class CSPEnforcementService {

    private final ServerGuardConfig config;
    private final Map<String, List<CSPViolation>> violations = new ConcurrentHashMap<>();
    private final AtomicLong totalViolations = new AtomicLong(0);

    public CSPEnforcementService() {
        this(new ServerGuardConfig());
    }

    public CSPEnforcementService(ServerGuardConfig config) {
        this.config = config;
    }

    private static final String DEFAULT_CSP_HEADER = String.join("; ",
            "default-src 'self'",
            "script-src 'self' 'unsafe-inline' 'unsafe-eval'",
            "style-src 'self' 'unsafe-inline'",
            "img-src 'self' data: https:",
            "font-src 'self'",
            "connect-src 'self' https://api.aluer.com",
            "frame-src 'none'",
            "object-src 'none'",
            "base-uri 'self'",
            "form-action 'self'",
            "frame-ancestors 'none'",
            "upgrade-insecure-requests"
    );

    private static final String STRICT_CSP_HEADER = String.join("; ",
            "default-src 'self'",
            "script-src 'self' 'nonce-{nonce}'",
            "style-src 'self' 'nonce-{nonce}'",
            "img-src 'self' data:",
            "font-src 'self'",
            "connect-src 'self'",
            "frame-src 'none'",
            "object-src 'none'",
            "base-uri 'self'",
            "form-action 'self'",
            "frame-ancestors 'none'",
            "require-trusted-types-for 'script'",
            "report-uri /api/csp-report"
    );

    // XSS attack patterns in CSP reports
    private static final List<String> XSS_PATTERNS = List.of(
            "<script", "javascript:", "onerror=", "onload=", "onclick=",
            "eval(", "document.cookie", "document.write", "innerHTML",
            "<img src=x onerror", "<svg onload", "expression(",
            "String.fromCharCode", "\\x", "\\u00", "fromCodePoint"
    );

    private static final List<String> CLICKJACK_PATTERNS = List.of(
            "opacity:0", "z-index:9999", "position:absolute;top:0;left:0"
    );

    public CSPCheckResult checkRequest(String uri, Map<String, String> headers, String body) {
        if (!config.getSecurity().getSuperEvolution().isCsp()) return CSPCheckResult.clean();
        List<String> matched = new ArrayList<>();
        int score = 0;

        // Check for reflected XSS
        if (body != null) {
            String lower = body.toLowerCase();
            for (String pattern : XSS_PATTERNS) {
                if (lower.contains(pattern.toLowerCase())) {
                    matched.add("XSS: " + pattern);
                    score += 20;
                }
            }
        }

        // Check for clickjacking
        if (body != null && body.toLowerCase().contains("iframe")) {
            for (String pattern : CLICKJACK_PATTERNS) {
                if (body.toLowerCase().contains(pattern.toLowerCase())) {
                    matched.add("CLICKJACK: " + pattern);
                    score += 15;
                }
            }
        }

        // Check for missing security headers
        if (headers != null) {
            if (!headers.containsKey("x-frame-options")) {
                matched.add("MISSING_X_FRAME_OPTIONS");
                score += 5;
            }
            if (!headers.containsKey("x-content-type-options")) {
                matched.add("MISSING_X_CONTENT_TYPE_OPTIONS");
                score += 5;
            }
        }

        if (score >= 30) {
            CSPViolation violation = new CSPViolation(Instant.now(), uri, matched, score);
            violations.computeIfAbsent(uri, k -> new ArrayList<>()).add(violation);
            totalViolations.incrementAndGet();
            return CSPCheckResult.blocked(matched, score);
        }

        return CSPCheckResult.clean();
    }

    public String generateCSPHeader(boolean strict) {
        if (strict) {
            String nonce = generateNonce();
            return STRICT_CSP_HEADER.replace("{nonce}", nonce);
        }
        return DEFAULT_CSP_HEADER;
    }

    public Map<String, String> getSecurityHeaders() {
        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("Content-Security-Policy", DEFAULT_CSP_HEADER);
        headers.put("X-Content-Type-Options", "nosniff");
        headers.put("X-Frame-Options", "DENY");
        headers.put("X-XSS-Protection", "1; mode=block");
        headers.put("Referrer-Policy", "strict-origin-when-cross-origin");
        headers.put("Permissions-Policy", "geolocation=(), microphone=(), camera=(), payment=()");
        headers.put("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
        return headers;
    }

    public Map<String, Object> getStatus() {
        Map<String, Object> status = new LinkedHashMap<>();
        status.put("totalViolations", totalViolations.get());
        status.put("violatedEndpoints", violations.size());
        List<Map<String, Object>> recent = new ArrayList<>();
        for (Map.Entry<String, List<CSPViolation>> e : violations.entrySet()) {
            for (CSPViolation v : e.getValue()) {
                Map<String, Object> m = new LinkedHashMap<>();
                m.put("endpoint", e.getKey());
                m.put("patterns", v.patterns);
                m.put("score", v.score);
                m.put("time", v.timestamp.toString());
                recent.add(m);
            }
        }
        recent.sort((a, b) -> b.get("time").toString().compareTo(a.get("time").toString()));
        status.put("recentViolations", recent.subList(0, Math.min(recent.size(), 20)));
        return status;
    }

    public long getTotalViolations() { return totalViolations.get(); }

    private String generateNonce() {
        byte[] bytes = new byte[24];
        new Random().nextBytes(bytes);
        return Base64.getEncoder().encodeToString(bytes);
    }

    private static class CSPViolation {
        final Instant timestamp;
        final String uri;
        final List<String> patterns;
        final int score;

        CSPViolation(Instant timestamp, String uri, List<String> patterns, int score) {
            this.timestamp = timestamp;
            this.uri = uri;
            this.patterns = patterns;
            this.score = score;
        }
    }

    public static class CSPCheckResult {
        private final boolean blocked;
        private final List<String> matched;
        private final int score;

        private CSPCheckResult(boolean blocked, List<String> matched, int score) {
            this.blocked = blocked;
            this.matched = matched;
            this.score = score;
        }

        public static CSPCheckResult clean() { return new CSPCheckResult(false, List.of(), 0); }
        public static CSPCheckResult blocked(List<String> matched, int score) { return new CSPCheckResult(true, matched, score); }

        public boolean isBlocked() { return blocked; }
        public List<String> getMatched() { return matched; }
        public int getScore() { return score; }
    }
}
