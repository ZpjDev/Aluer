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
import java.util.regex.Pattern;
import java.util.regex.Matcher;

@Component
public class WebApplicationFirewall {
    private static final Logger logger = LoggerFactory.getLogger(WebApplicationFirewall.class);

    private final Map<String, WAFRule> rules = new ConcurrentHashMap<>();
    private final Queue<WAFEvent> eventLog = new ConcurrentLinkedQueue<>();
    private final Map<String, RequestStats> requestStats = new ConcurrentHashMap<>();
    private final Map<String, ClientReputation> clientReputations = new ConcurrentHashMap<>();
    private final AtomicLong totalRequests = new AtomicLong(0);
    private final AtomicLong blockedRequests = new AtomicLong(0);
    private final AtomicLong suspiciousRequests = new AtomicLong(0);

    private static final DateTimeFormatter DATE_FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    public WebApplicationFirewall() {
        initializeDefaultRules();
    }

    private void initializeDefaultRules() {
        addRule("SQL_INJECTION", "HIGH", Pattern.compile(
            ".*(union|select|insert|update|delete|drop|create|alter|exec|execute|script|<script).*",
            Pattern.CASE_INSENSITIVE
        ), "SQL注入攻击");

        addRule("XSS_ATTACK", "HIGH", Pattern.compile(
            ".*(<script|javascript:|onerror=|onload=|alert\\(|eval\\(|document\\.|window\\.).*",
            Pattern.CASE_INSENSITIVE
        ), "跨站脚本攻击(XSS)");

        addRule("PATH_TRAVERSAL", "MEDIUM", Pattern.compile(
            ".*(\\.\\./|\\.\\.\\\\|%2e%2e/|%2e%2e\\\\).*",
            Pattern.CASE_INSENSITIVE
        ), "路径遍历攻击");

        addRule("COMMAND_INJECTION", "HIGH", Pattern.compile(
            ".*(;|\\||`|$|&&|\\|\\||>|<).*(ls|cat|rm|mv|cp|chmod|chown|wget|curl|nc|bash|sh).*",
            Pattern.CASE_INSENSITIVE
        ), "命令注入攻击");

        addRule("LDAP_INJECTION", "MEDIUM", Pattern.compile(
            ".*(\\(|\\)|\\*|\\?|\\?|\\?|\\\\n|\\\\r).*",
            Pattern.CASE_INSENSITIVE
        ), "LDAP注入攻击");

        addRule("XML_INJECTION", "MEDIUM", Pattern.compile(
            ".*(<!DOCTYPE|<!ENTITY|<!ELEMENT|CDATA|\\?xml).*",
            Pattern.CASE_INSENSITIVE
        ), "XML注入攻击");

        addRule("FILE_INCLUDE", "MEDIUM", Pattern.compile(
            ".*(include|require|include_once|require_once|php://|file://).*",
            Pattern.CASE_INSENSITIVE
        ), "文件包含攻击");

        addRule("SSRF_ATTACK", "HIGH", Pattern.compile(
            ".*(https?://(127\\.0\\.0\\.1|localhost|0\\.0\\.0\\.0|169\\.254\\.169\\.254|::1)|gopher://|dict://|ftp://).*",
            Pattern.CASE_INSENSITIVE
        ), "服务端请求伪造(SSRF)");

        addRule("SSTI_ATTACK", "HIGH", Pattern.compile(
            ".*(\\{\\{.*\\}\\}|\\$\\{.*\\}|<%=.*%>|#\\{.*\\}).*",
            Pattern.CASE_INSENSITIVE
        ), "服务端模板注入(SSTI)");

        addRule("JNDI_INJECTION", "HIGH", Pattern.compile(
            ".*\\$\\{jndi:(ldap|ldaps|rmi|dns|iiop):.*",
            Pattern.CASE_INSENSITIVE
        ), "JNDI注入");

        addRule("JAVA_DESERIALIZATION", "HIGH", Pattern.compile(
            ".*(rO0AB|ac ed 00 05|java\\.util\\.PriorityQueue|ysoserial).*",
            Pattern.CASE_INSENSITIVE
        ), "Java反序列化利用");

        addRule("CRLF_INJECTION", "MEDIUM", Pattern.compile(
            ".*(%0d|%0a|\\\\r|\\\\n|\\r|\\n).*",
            Pattern.CASE_INSENSITIVE
        ), "CRLF注入");

        addRule("OPEN_REDIRECT", "MEDIUM", Pattern.compile(
            ".*(redirect=|url=|next=|return=)https?://.*",
            Pattern.CASE_INSENSITIVE
        ), "开放重定向");

        addRule("VALIDATE_EMAIL", "LOW", Pattern.compile(
            "^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$"
        ), "邮箱格式验证");

        addRule("VALIDATE_IP", "LOW", Pattern.compile(
            "^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
        ), "IP地址格式验证");

        addRule("BLOCK_SENSITIVE", "HIGH", Pattern.compile(
            ".*(password|passwd|pwd|secret|token|auth|api_key|apikey|private_key).*",
            Pattern.CASE_INSENSITIVE
        ), "敏感信息访问");

        logger.info("Initialized {} WAF rules", rules.size());
    }

    public void addRule(String name, String severity, Pattern pattern, String description) {
        WAFRule rule = new WAFRule(name, severity, pattern, description);
        rules.put(name, rule);
        logger.info("Added WAF rule: {} [{}]", name, severity);
    }

    public WAFResult checkRequest(String clientIP, String method, String uri, String queryString, Map<String, String> headers, String body) {
        WAFResult result = new WAFResult();
        result.setClientIP(clientIP);
        result.setMethod(method);
        result.setUri(uri);
        result.setTimestamp(LocalDateTime.now());

        totalRequests.incrementAndGet();

        updateClientStats(clientIP);

        if (isClientBlocked(clientIP)) {
            result.setBlocked(true);
            result.setReason("Client is blocked");
            blockedRequests.incrementAndGet();
            logEvent(clientIP, method, uri, "BLOCKED", "Client blocked");
            return result;
        }

        if (isRateLimited(clientIP)) {
            result.setBlocked(true);
            result.setReason("Rate limit exceeded");
            blockedRequests.incrementAndGet();
            updateClientReputation(clientIP, -20);
            logEvent(clientIP, method, uri, "BLOCKED", "Rate limit exceeded");
            return result;
        }

        StringBuilder fullRequestBuilder = new StringBuilder();
        fullRequestBuilder.append(method).append(" ").append(uri);
        if (queryString != null) {
            fullRequestBuilder.append("?").append(queryString);
        }
        for (Map.Entry<String, String> header : headers.entrySet()) {
            if (header.getValue() != null) {
                fullRequestBuilder.append("\n").append(header.getKey()).append(": ").append(header.getValue());
            }
        }
        if (body != null) {
            fullRequestBuilder.append("\n").append(body);
        }
        String fullRequest = fullRequestBuilder.toString();

        for (WAFRule rule : rules.values()) {
            if (!rule.isEnabled()) continue;

            Matcher matcher = rule.getPattern().matcher(fullRequest);
            if (matcher.find()) {
                result.addMatchedRule(rule.getName());

                if ("HIGH".equals(rule.getSeverity())) {
                    result.setBlocked(true);
                    result.setReason("High severity rule matched: " + rule.getDescription());
                    blockedRequests.incrementAndGet();
                    updateClientReputation(clientIP, -15);
                    logEvent(clientIP, method, uri, "BLOCKED", rule.getName() + " - " + rule.getDescription());
                } else if ("MEDIUM".equals(rule.getSeverity())) {
                    result.setSuspicious(true);
                    result.addWarning("Medium severity rule matched: " + rule.getDescription());
                    suspiciousRequests.incrementAndGet();
                    updateClientReputation(clientIP, -5);
                    logEvent(clientIP, method, uri, "SUSPICIOUS", rule.getName());
                } else {
                    result.addWarning("Low severity rule matched: " + rule.getDescription());
                    logEvent(clientIP, method, uri, "WARNING", rule.getName());
                }
            }
        }

        for (Map.Entry<String, String> header : headers.entrySet()) {
            String headerValue = header.getValue();
            if (headerValue != null && headerValue.length() > 1000) {
                result.addWarning("Unusually long header: " + header.getKey());
                suspiciousRequests.incrementAndGet();
            }
            if (headerValue != null && looksLikeHeaderSmuggling(header.getKey(), headerValue)) {
                result.setSuspicious(true);
                result.addWarning("Possible header smuggling: " + header.getKey());
                suspiciousRequests.incrementAndGet();
            }
        }

        if (!result.isBlocked()) {
            logEvent(clientIP, method, uri, "ALLOWED", "Request passed all rules");
        }

        return result;
    }

    private boolean looksLikeHeaderSmuggling(String headerName, String headerValue) {
        String normalizedName = headerName == null ? "" : headerName.toLowerCase(Locale.ROOT);
        String normalizedValue = headerValue == null ? "" : headerValue.toLowerCase(Locale.ROOT);
        if (normalizedValue.contains("\r") || normalizedValue.contains("\n")) {
            return true;
        }
        return normalizedName.equals("host")
            && (normalizedValue.contains("127.0.0.1") || normalizedValue.contains("localhost"));
    }

    private void updateClientStats(String clientIP) {
        RequestStats stats = requestStats.computeIfAbsent(clientIP, k -> new RequestStats(clientIP));
        stats.incrementRequestCount();

        long oneMinuteAgo = System.currentTimeMillis() - 60000;
        if (stats.getWindowStart() < oneMinuteAgo) {
            stats.setRequestCountInLastMinute(stats.getRequestCount() - stats.getRequestCountInLastMinute());
            stats.setWindowStart(System.currentTimeMillis());
        }
        stats.incrementRequestCountInLastMinute();
    }

    private boolean isClientBlocked(String clientIP) {
        ClientReputation rep = clientReputations.get(clientIP);
        return rep != null && rep.getScore() < -100;
    }

    private boolean isRateLimited(String clientIP) {
        RequestStats stats = requestStats.get(clientIP);
        if (stats == null) return false;

        return stats.getRequestCountInLastMinute() > 120;
    }

    private void updateClientReputation(String clientIP, int scoreChange) {
        ClientReputation rep = clientReputations.computeIfAbsent(clientIP, k -> new ClientReputation(clientIP));
        rep.adjustScore(scoreChange);
    }

    public void blockClient(String clientIP, String reason) {
        ClientReputation rep = clientReputations.computeIfAbsent(clientIP, k -> new ClientReputation(clientIP));
        rep.setScore(-200);
        rep.setBlockReason(reason);
        logger.info("Blocked client: {} - {}", clientIP, reason);
    }

    public void unblockClient(String clientIP) {
        ClientReputation rep = clientReputations.get(clientIP);
        if (rep != null) {
            rep.setScore(0);
            rep.setBlockReason(null);
            logger.info("Unblocked client: {}", clientIP);
        }
    }

    public Map<String, Object> getStats() {
        Map<String, Object> stats = new HashMap<>();
        stats.put("totalRequests", totalRequests.get());
        stats.put("blockedRequests", blockedRequests.get());
        stats.put("suspiciousRequests", suspiciousRequests.get());
        stats.put("activeClients", requestStats.size());
        stats.put("blockedClients", clientReputations.values().stream()
            .filter(r -> r.getScore() < -100).count());
        stats.put("rulesLoaded", rules.size());

        return stats;
    }

    public List<WAFEvent> getRecentEvents(int limit) {
        List<WAFEvent> events = new ArrayList<>();
        int count = 0;
        for (WAFEvent event : eventLog) {
            if (count++ >= limit) break;
            events.add(event);
        }
        return events;
    }

    public Map<String, ClientReputation> getBlockedClients() {
        Map<String, ClientReputation> blocked = new HashMap<>();
        for (Map.Entry<String, ClientReputation> entry : clientReputations.entrySet()) {
            if (entry.getValue().getScore() < -100) {
                blocked.put(entry.getKey(), entry.getValue());
            }
        }
        return blocked;
    }

    private void logEvent(String clientIP, String method, String uri, String action, String details) {
        WAFEvent event = new WAFEvent(clientIP, method, uri, action, details, LocalDateTime.now());
        eventLog.offer(event);

        if (eventLog.size() > 10000) {
            eventLog.poll();
        }
    }

    public void enableRule(String ruleName) {
        WAFRule rule = rules.get(ruleName);
        if (rule != null) {
            rule.setEnabled(true);
            logger.info("Enabled WAF rule: {}", ruleName);
        }
    }

    public void disableRule(String ruleName) {
        WAFRule rule = rules.get(ruleName);
        if (rule != null) {
            rule.setEnabled(false);
            logger.info("Disabled WAF rule: {}", ruleName);
        }
    }

    public static class WAFRule {
        private final String name;
        private final String severity;
        private final Pattern pattern;
        private final String description;
        private volatile boolean enabled = true;

        public WAFRule(String name, String severity, Pattern pattern, String description) {
            this.name = name;
            this.severity = severity;
            this.pattern = pattern;
            this.description = description;
        }

        public String getName() { return name; }
        public String getSeverity() { return severity; }
        public Pattern getPattern() { return pattern; }
        public String getDescription() { return description; }
        public boolean isEnabled() { return enabled; }
        public void setEnabled(boolean enabled) { this.enabled = enabled; }
    }

    public static class WAFResult {
        private String clientIP;
        private String method;
        private String uri;
        private boolean blocked;
        private boolean suspicious;
        private String reason;
        private List<String> matchedRules = new ArrayList<>();
        private List<String> warnings = new ArrayList<>();
        private LocalDateTime timestamp;

        public String getClientIP() { return clientIP; }
        public void setClientIP(String clientIP) { this.clientIP = clientIP; }
        public String getMethod() { return method; }
        public void setMethod(String method) { this.method = method; }
        public String getUri() { return uri; }
        public void setUri(String uri) { this.uri = uri; }
        public boolean isBlocked() { return blocked; }
        public void setBlocked(boolean blocked) { this.blocked = blocked; }
        public boolean isSuspicious() { return suspicious; }
        public void setSuspicious(boolean suspicious) { this.suspicious = suspicious; }
        public String getReason() { return reason; }
        public void setReason(String reason) { this.reason = reason; }
        public List<String> getMatchedRules() { return matchedRules; }
        public void addMatchedRule(String rule) { this.matchedRules.add(rule); }
        public List<String> getWarnings() { return warnings; }
        public void addWarning(String warning) { this.warnings.add(warning); }
        public LocalDateTime getTimestamp() { return timestamp; }
        public void setTimestamp(LocalDateTime timestamp) { this.timestamp = timestamp; }
    }

    public static class RequestStats {
        private final String clientIP;
        private volatile long requestCount;
        private volatile long requestCountInLastMinute;
        private volatile long windowStart;

        public RequestStats(String clientIP) {
            this.clientIP = clientIP;
            this.windowStart = System.currentTimeMillis();
        }

        public void incrementRequestCount() { requestCount++; }
        public void incrementRequestCountInLastMinute() { requestCountInLastMinute++; }

        public String getClientIP() { return clientIP; }
        public long getRequestCount() { return requestCount; }
        public long getRequestCountInLastMinute() { return requestCountInLastMinute; }
        public long getWindowStart() { return windowStart; }
        public void setRequestCountInLastMinute(long count) { this.requestCountInLastMinute = count; }
        public void setWindowStart(long windowStart) { this.windowStart = windowStart; }
    }

    public static class ClientReputation {
        private final String clientIP;
        private volatile int score;
        private volatile String blockReason;
        private volatile long lastUpdated;

        public ClientReputation(String clientIP) {
            this.clientIP = clientIP;
            this.score = 0;
            this.lastUpdated = System.currentTimeMillis();
        }

        public void adjustScore(int delta) {
            this.score = Math.max(-200, Math.min(100, this.score + delta));
            this.lastUpdated = System.currentTimeMillis();
        }

        public String getClientIP() { return clientIP; }
        public int getScore() { return score; }
        public void setScore(int score) { this.score = score; }
        public String getBlockReason() { return blockReason; }
        public void setBlockReason(String blockReason) { this.blockReason = blockReason; }
        public long getLastUpdated() { return lastUpdated; }
    }

    public static class WAFEvent {
        private final String clientIP;
        private final String method;
        private final String uri;
        private final String action;
        private final String details;
        private final LocalDateTime timestamp;

        public WAFEvent(String clientIP, String method, String uri, String action, String details, LocalDateTime timestamp) {
            this.clientIP = clientIP;
            this.method = method;
            this.uri = uri;
            this.action = action;
            this.details = details;
            this.timestamp = timestamp;
        }

        public String getClientIP() { return clientIP; }
        public String getMethod() { return method; }
        public String getUri() { return uri; }
        public String getAction() { return action; }
        public String getDetails() { return details; }
        public LocalDateTime getTimestamp() { return timestamp; }
    }
}
