package com.aluer.defense;

import com.aluer.config.ServerGuardConfig;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

@Service
public class DatabaseFirewallService {

    private final ServerGuardConfig config;
    private final Map<String, List<QueryEvent>> queryLog = new ConcurrentHashMap<>();
    private final AtomicLong totalBlocked = new AtomicLong(0);
    private final AtomicLong totalQueries = new AtomicLong(0);

    public DatabaseFirewallService() {
        this(new ServerGuardConfig());
    }

    public DatabaseFirewallService(ServerGuardConfig config) {
        this.config = config;
    }

    private static final List<String> DANGEROUS_KEYWORDS = List.of(
            "DROP TABLE", "DROP DATABASE", "TRUNCATE TABLE", "DELETE FROM",
            "ALTER TABLE", "ALTER DATABASE", "CREATE USER", "GRANT ALL",
            "REVOKE", "SHUTDOWN", "xp_cmdshell", "sp_configure",
            "INTO OUTFILE", "INTO DUMPFILE", "LOAD_FILE", "BENCHMARK(",
            "SLEEP(", "WAITFOR DELAY", "INFORMATION_SCHEMA", "mysql.user",
            "sys.tables", "sqlite_master", "pg_shadow", "pg_database"
    );

    private static final int MAX_QUERY_LENGTH = 4096;
    private static final int MAX_UNION_COUNT = 3;
    private static final int MAX_JOIN_COUNT = 10;

    public QueryCheckResult checkQuery(String sql, String source, String database) {
        if (!config.getSecurity().getSuperEvolution().isDatabaseFirewall()) return QueryCheckResult.clean();
        if (sql == null || sql.trim().isEmpty()) return QueryCheckResult.clean();
        totalQueries.incrementAndGet();

        List<String> reasons = new ArrayList<>();
        String upper = sql.toUpperCase().trim();

        // Length check
        if (sql.length() > MAX_QUERY_LENGTH) {
            reasons.add("OVERSIZED_QUERY: " + sql.length() + " chars");
        }

        // Dangerous keywords
        for (String keyword : DANGEROUS_KEYWORDS) {
            if (upper.contains(keyword.toUpperCase())) {
                reasons.add("DANGEROUS_KEYWORD: " + keyword);
            }
        }

        // UNION-based injection
        int unionCount = countKeyword(upper, "UNION");
        if (unionCount > MAX_UNION_COUNT) {
            reasons.add("EXCESSIVE_UNION: " + unionCount);
        }

        // Comment-based injection
        if (upper.contains("-- ") || upper.contains("/*") || upper.contains("#")) {
            if (upper.contains("' OR ") || upper.contains("' AND ") || upper.contains("1=1") || upper.contains("1=0")) {
                reasons.add("COMMENT_INJECTION");
            }
        }

        // Always-true conditions
        if (upper.contains("OR 1=1") || upper.contains("OR '1'='1'")
                || upper.contains("'a'='a'") || upper.contains("\"=\"") || upper.contains("||1||")) {
            reasons.add("ALWAYS_TRUE_CONDITION");
        }

        // Stacked queries
        int semicolons = countChar(sql, ';');
        if (semicolons > 1) {
            reasons.add("STACKED_QUERIES: " + semicolons);
        }

        // Time-based injection
        if (upper.contains("SLEEP(") || upper.contains("BENCHMARK(") || upper.contains("PG_SLEEP(") || upper.contains("WAITFOR")) {
            reasons.add("TIME_BASED_INJECTION");
        }

        if (!reasons.isEmpty()) {
            QueryEvent event = new QueryEvent(Instant.now(), source, database, sql.length() > 200 ? sql.substring(0, 200) : sql, reasons);
            queryLog.computeIfAbsent(source, k -> new ArrayList<>()).add(event);
            totalBlocked.incrementAndGet();
            return QueryCheckResult.blocked(reasons);
        }

        return QueryCheckResult.clean();
    }

    public Map<String, Object> getStatus() {
        Map<String, Object> status = new LinkedHashMap<>();
        status.put("totalQueries", totalQueries.get());
        status.put("totalBlocked", totalBlocked.get());
        status.put("trackedSources", queryLog.size());
        List<Map<String, Object>> recent = new ArrayList<>();
        for (Map.Entry<String, List<QueryEvent>> e : queryLog.entrySet()) {
            for (QueryEvent event : e.getValue()) {
                Map<String, Object> m = new LinkedHashMap<>();
                m.put("source", e.getKey());
                m.put("database", event.database);
                m.put("snippet", event.snippet);
                m.put("reasons", event.reasons);
                m.put("time", event.timestamp.toString());
                recent.add(m);
            }
        }
        recent.sort((a, b) -> b.get("time").toString().compareTo(a.get("time").toString()));
        status.put("recentBlocked", recent.subList(0, Math.min(recent.size(), 20)));
        return status;
    }

    public long getTotalBlocked() { return totalBlocked.get(); }
    public long getTotalQueries() { return totalQueries.get(); }

    private int countKeyword(String text, String keyword) {
        int count = 0;
        int idx = 0;
        while ((idx = text.indexOf(keyword, idx)) != -1) {
            count++;
            idx += keyword.length();
        }
        return count;
    }

    private int countChar(String text, char c) {
        int count = 0;
        for (char x : text.toCharArray()) {
            if (x == c) count++;
        }
        return count;
    }

    private static class QueryEvent {
        final Instant timestamp;
        final String source;
        final String database;
        final String snippet;
        final List<String> reasons;

        QueryEvent(Instant timestamp, String source, String database, String snippet, List<String> reasons) {
            this.timestamp = timestamp;
            this.source = source;
            this.database = database;
            this.snippet = snippet;
            this.reasons = reasons;
        }
    }

    public static class QueryCheckResult {
        private final boolean blocked;
        private final List<String> reasons;

        private QueryCheckResult(boolean blocked, List<String> reasons) {
            this.blocked = blocked;
            this.reasons = reasons;
        }

        public static QueryCheckResult clean() { return new QueryCheckResult(false, List.of()); }
        public static QueryCheckResult blocked(List<String> reasons) { return new QueryCheckResult(true, reasons); }

        public boolean isBlocked() { return blocked; }
        public List<String> getReasons() { return reasons; }
    }
}
