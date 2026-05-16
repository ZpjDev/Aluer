package com.aluer.security;

import com.aluer.config.ServerGuardConfig;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Tab补全崩溃防护服务 — V4.0 服务器保护模块
 *
 * 检测原理：
 *   Minecraft的Tab补全系统（Command Suggestions）在解析补全请求时存在多个已知漏洞。
 *   特殊构造的补全请求——如超长字符串、深度嵌套引号/括号、无效UTF-8序列——
 *   可能导致服务器端的Brigadier命令解析器陷入死循环或触发OOM，最终导致服务器崩溃。
 *   此外，高频补全请求也是一种洪水攻击变体，可消耗大量服务器CPU资源。
 *
 * 已知漏洞示例：
 *   - MC-156660: 超长Tab补全请求导致OOM
 *   - MC-164312: 深度嵌套引号导致解析器递归溢出
 *   - MC-191726: 无效UTF-8序列导致解析器异常
 *   - Tab补全洪水: 高频请求导致服务器CPU飙升
 *
 * 检测维度：
 *   - 请求长度检测（>8192字符为极端异常，正常<256字符）
 *   - 深度嵌套检测（引号/括号嵌套>50层为递归溢出风险）
 *   - 频率检测（>20次/秒为洪水攻击）
 *   - 无效UTF-8序列检测
 *   - 特殊字符滥用检测
 *
 * 配置开关：serverguard.security.super-evolution.anti-tab-complete-crash
 */
@Service
public class AntiTabCompleteCrashService {

    private final ServerGuardConfig config;

    private final Map<String, List<TabEvent>> tabHistory = new ConcurrentHashMap<>();
    private final Map<String, Instant> rateLimited = new ConcurrentHashMap<>();
    private final Map<String, AtomicLong> violationCounts = new ConcurrentHashMap<>();
    private final AtomicLong totalTabRequests = new AtomicLong(0);
    private final AtomicLong crashPrevented = new AtomicLong(0);
    private final AtomicLong rateLimitedRequests = new AtomicLong(0);

    private final ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor();

    /** Tab补全请求最大允许长度 */
    private static final int MAX_REQUEST_LENGTH = 8192;
    /** 正常Tab补全请求建议长度上限 */
    private static final int NORMAL_REQUEST_LENGTH = 256;
    /** 最大允许的引号/括号嵌套深度 */
    private static final int MAX_NEST_DEPTH = 50;
    /** 每玩家每秒最大允许的Tab补全请求数 */
    private static final int MAX_TAB_REQUESTS_PER_SEC = 20;
    /** 频率检测窗口（秒） */
    private static final int FREQUENCY_WINDOW_SECONDS = 5;
    /** 限流封禁时间（秒） */
    private static final long RATE_LIMIT_BLOCK_SECONDS = 60;

    public AntiTabCompleteCrashService() {
        this(new ServerGuardConfig());
    }

    @Autowired
    public AntiTabCompleteCrashService(ServerGuardConfig config) {
        this.config = config;
        scheduler.scheduleAtFixedRate(this::cleanupOldData, 30, 60, TimeUnit.SECONDS);
    }

    /**
     * 检查Tab补全请求是否安全。
     *
     * @param player 发起补全请求的玩家
     * @param commandText 正在补全的命令文本
     * @param cursorPosition 光标位置
     * @param requestId 请求的事务ID
     * @return 检查结果
     */
    public TabCheckResult check(String player, String commandText, int cursorPosition, int requestId) {
        // 配置开关检查
        if (!config.getSecurity().getSuperEvolution().isAntiTabCompleteCrash()) {
            return TabCheckResult.clean();
        }

        totalTabRequests.incrementAndGet();
        List<String> reasons = new ArrayList<>();
        int score = 0;

        // 记录事件
        TabEvent event = new TabEvent(Instant.now(), player, commandText, cursorPosition, requestId);
        tabHistory.computeIfAbsent(player, k -> Collections.synchronizedList(new ArrayList<>())).add(event);

        // ---- 检测1：频率限制 ----
        // 正常玩家Tab补全频率不会超过每秒数次
        // >20次/秒明确是自动化洪水攻击
        Instant now = Instant.now();
        List<TabEvent> playerEvents = tabHistory.get(player);
        long recentCount = playerEvents.stream()
                .filter(e -> e.time.isAfter(now.minusSeconds(FREQUENCY_WINDOW_SECONDS)))
                .count();
        long requestsPerSec = recentCount / FREQUENCY_WINDOW_SECONDS;

        if (requestsPerSec > MAX_TAB_REQUESTS_PER_SEC) {
            score += 50;
            reasons.add("TAB_FLOOD: " + requestsPerSec + " requests/sec (threshold: " + MAX_TAB_REQUESTS_PER_SEC + ")");
            rateLimitedRequests.incrementAndGet();
            // 限流该玩家
            rateLimited.put(player, Instant.now().plusSeconds(RATE_LIMIT_BLOCK_SECONDS));
        }

        // ---- 检测2：请求长度 ----
        // 正常Tab补全请求通常<256字符（命令行长度限制）
        // 超过8192字符明确是恶意请求，利用Brigadier解析器的O(N^2)行为
        if (commandText != null) {
            int textLen = commandText.length();

            if (textLen > MAX_REQUEST_LENGTH) {
                score += 70;
                reasons.add("OVERSIZED_REQUEST: " + textLen + " chars (max: " + MAX_REQUEST_LENGTH + ")");
            } else if (textLen > NORMAL_REQUEST_LENGTH * 4) { // >1024
                score += 30;
                reasons.add("SUSPICIOUS_LENGTH: " + textLen + " chars (normal < " + NORMAL_REQUEST_LENGTH + ")");
            } else if (textLen > NORMAL_REQUEST_LENGTH * 2) { // >512
                score += 10;
                reasons.add("ABNORMAL_LENGTH: " + textLen + " chars");
            }

            // ---- 检测3：深度嵌套引号/括号 ----
            // 深度嵌套的引号或括号会触发Brigadier解析器的递归机制
            // 嵌套层数>50时递归调用栈可能溢出
            int nestedDepth = calculateNestedDepth(commandText);
            if (nestedDepth > MAX_NEST_DEPTH) {
                score += 75; // 深度嵌套为严重威胁，直接触发blocked（>=70即阻止）
                reasons.add("DEEP_NESTING: nested depth=" + nestedDepth + " (max: " + MAX_NEST_DEPTH + ")");
            } else if (nestedDepth > 20) {
                score += 20;
                reasons.add("MODERATE_NESTING: nested depth=" + nestedDepth);
            }

            // ---- 检测4：无效UTF-8序列 ----
            // 无效的UTF-8字节序列在解析时可能导致NIO异常
            // 这是MC-191726等相关漏洞的攻击向量
            byte[] bytes = commandText.getBytes(StandardCharsets.UTF_8);
            // 检查是否包含无效的UTF-8字节序列
            int invalidSeqCount = countInvalidUtf8Sequences(bytes);
            if (invalidSeqCount > 0) {
                score += 40;
                reasons.add("INVALID_UTF8: " + invalidSeqCount + " invalid byte sequences detected");
            }

            // ---- 检测5：Null字符检测 ----
            // Java字符串中的null字符(\0)可能导致字符串截断或缓冲区异常
            if (commandText.indexOf('\0') >= 0) {
                score += 50;
                reasons.add("NULL_CHAR: contains null character (\\\\0)");
            }

            // ---- 检测6：重复字符模式（可能导致解析器性能退化） ----
            // 大量重复括号或引号可能导致O(N^2)复杂度的解析路径
            int repeatedCharScore = checkRepeatedPatterns(commandText);
            if (repeatedCharScore > 0) {
                score += repeatedCharScore;
                reasons.add("REPEATED_PATTERNS: excessive repeated special characters");
            }

            // ---- 检测7：Unicode方向控制字符 ----
            // 双向文本控制字符（如RLO/LRO）可能导致显示混乱或被用于混淆
            for (char c : commandText.toCharArray()) {
                if (c == '‪' || c == '‫' || c == '‬'
                        || c == '‭' || c == '‮'
                        || c == '⁦' || c == '⁧' || c == '⁨' || c == '⁩') {
                    score += 15;
                    reasons.add("UNICODE_BIDI: contains Unicode bidirectional control characters");
                    break;
                }
            }
        }

        // 如果该玩家被限流，额外增加评分
        if (rateLimited.containsKey(player)) {
            if (Instant.now().isAfter(rateLimited.get(player))) {
                rateLimited.remove(player);
            } else {
                score += 30;
                reasons.add("RATE_LIMITED: player is currently rate-limited");
            }
        }

        // 判定结果
        if (score >= 70) {
            crashPrevented.incrementAndGet();
            violationCounts.computeIfAbsent(player, k -> new AtomicLong(0)).incrementAndGet();
            return TabCheckResult.blocked(reasons, score);
        } else if (score >= 30) {
            return TabCheckResult.suspicious(reasons, score);
        }

        return TabCheckResult.clean();
    }

    /**
     * 计算命令文本中引号和括号的嵌套深度。
     * 模拟Brigadier解析器的基本行为模式，检测可能导致递归溢出的深度嵌套。
     */
    private int calculateNestedDepth(String text) {
        int maxDepth = 0;
        int currentDepth = 0;

        for (char c : text.toCharArray()) {
            if (c == '(' || c == '[' || c == '{' || c == '"') {
                currentDepth++;
                maxDepth = Math.max(maxDepth, currentDepth);
            } else if (c == ')' || c == ']' || c == '}' || c == '"') {
                currentDepth = Math.max(0, currentDepth - 1);
            }
        }
        return maxDepth;
    }

    /**
     * 检测UTF-8字节序列中的无效序列数量。
     * 对前4096字节进行快速采样检测。
     */
    private int countInvalidUtf8Sequences(byte[] bytes) {
        int invalid = 0;
        int maxCheck = Math.min(bytes.length, 4096);

        for (int i = 0; i < maxCheck; i++) {
            byte b = bytes[i];
            if ((b & 0x80) == 0) continue; // ASCII

            // UTF-8多字节序列检测
            if ((b & 0xE0) == 0xC0) {
                // 2字节序列
                if (i + 1 >= bytes.length || (bytes[i + 1] & 0xC0) != 0x80) {
                    invalid++;
                    continue;
                }
                i++;
            } else if ((b & 0xF0) == 0xE0) {
                // 3字节序列
                if (i + 2 >= bytes.length
                        || (bytes[i + 1] & 0xC0) != 0x80
                        || (bytes[i + 2] & 0xC0) != 0x80) {
                    invalid++;
                    continue;
                }
                // 检查是否过高代理(0xED A0-0xED BF)
                if ((b & 0xFF) == 0xED && (bytes[i + 1] & 0xA0) == 0xA0) {
                    invalid++;
                }
                i += 2;
            } else if ((b & 0xF8) == 0xF0) {
                // 4字节序列
                if (i + 3 >= bytes.length
                        || (bytes[i + 1] & 0xC0) != 0x80
                        || (bytes[i + 2] & 0xC0) != 0x80
                        || (bytes[i + 3] & 0xC0) != 0x80) {
                    invalid++;
                    continue;
                }
                // 检查是否超过Unicode范围
                int codepoint = ((bytes[i] & 0x07) << 18)
                        | ((bytes[i + 1] & 0x3F) << 12)
                        | ((bytes[i + 2] & 0x3F) << 6)
                        | (bytes[i + 3] & 0x3F);
                if (codepoint > 0x10FFFF) {
                    invalid++;
                }
                i += 3;
            } else {
                // 无效的起始字节
                invalid++;
            }
        }
        return invalid;
    }

    /**
     * 检测重复字符模式，可能导致解析器性能退化。
     */
    private int checkRepeatedPatterns(String text) {
        int score = 0;
        // 检测连续超过100个相同括号/引号
        int consecutiveQuotes = 0;
        int maxConsecutiveQuotes = 0;
        int consecutiveBrackets = 0;
        int maxConsecutiveBrackets = 0;

        for (char c : text.toCharArray()) {
            if (c == '"') {
                consecutiveQuotes++;
                maxConsecutiveQuotes = Math.max(maxConsecutiveQuotes, consecutiveQuotes);
                consecutiveBrackets = 0;
            } else if (c == '(' || c == ')') {
                consecutiveBrackets++;
                maxConsecutiveBrackets = Math.max(maxConsecutiveBrackets, consecutiveBrackets);
                consecutiveQuotes = 0;
            } else {
                consecutiveQuotes = 0;
                consecutiveBrackets = 0;
            }
        }

        if (maxConsecutiveQuotes > 100) score += 25;
        if (maxConsecutiveBrackets > 100) score += 25;
        return score;
    }

    public Map<String, Object> getStatus() {
        Map<String, Object> s = new LinkedHashMap<>();
        s.put("totalTabRequests", totalTabRequests.get());
        s.put("crashPrevented", crashPrevented.get());
        s.put("rateLimitedRequests", rateLimitedRequests.get());
        s.put("currentlyRateLimited", rateLimited.size());
        s.put("trackedPlayers", tabHistory.size());

        // 请求频率最高的玩家
        Instant now = Instant.now();
        List<Map<String, Object>> freqPlayers = new ArrayList<>();
        for (Map.Entry<String, List<TabEvent>> e : tabHistory.entrySet()) {
            long count = e.getValue().stream()
                    .filter(ev -> ev.time.isAfter(now.minusSeconds(10)))
                    .count();
            if (count > 0) {
                Map<String, Object> m = new LinkedHashMap<>();
                m.put("player", e.getKey());
                m.put("requests10s", count);
                m.put("rate", String.format("%.1f/s", count / 10.0));
                m.put("violations", violationCounts.getOrDefault(e.getKey(), new AtomicLong(0)).get());
                freqPlayers.add(m);
            }
        }
        freqPlayers.sort((a, b) -> Long.compare((Long) b.get("requests10s"), (Long) a.get("requests10s")));
        s.put("topRequesters", freqPlayers.subList(0, Math.min(freqPlayers.size(), 10)));
        return s;
    }

    private void cleanupOldData() {
        Instant cutoff = Instant.now().minusSeconds(300); // 5分钟
        for (List<TabEvent> events : tabHistory.values()) {
            events.removeIf(e -> e.time.isBefore(cutoff));
        }
        tabHistory.entrySet().removeIf(e -> e.getValue().isEmpty());
        rateLimited.entrySet().removeIf(e -> e.getValue().isBefore(Instant.now()));
    }

    private static class TabEvent {
        final Instant time;
        final String player;
        final String commandText;
        final int cursorPosition;
        final int requestId;

        TabEvent(Instant t, String p, String ct, int cp, int rid) {
            this.time = t;
            this.player = p;
            this.commandText = ct;
            this.cursorPosition = cp;
            this.requestId = rid;
        }
    }

    public static class TabCheckResult {
        private final boolean blocked;
        private final boolean suspicious;
        private final int score;
        private final List<String> reasons;

        private TabCheckResult(boolean blocked, boolean suspicious, int score, List<String> reasons) {
            this.blocked = blocked;
            this.suspicious = suspicious;
            this.score = score;
            this.reasons = reasons;
        }

        public static TabCheckResult clean() {
            return new TabCheckResult(false, false, 0, List.of());
        }

        public static TabCheckResult blocked(List<String> reasons, int score) {
            return new TabCheckResult(true, false, score, reasons);
        }

        public static TabCheckResult suspicious(List<String> reasons, int score) {
            return new TabCheckResult(false, true, score, reasons);
        }

        public boolean isBlocked() { return blocked; }
        public boolean isSuspicious() { return suspicious; }
        public boolean isClean() { return !blocked && !suspicious; }
        public int getScore() { return score; }
        public List<String> getReasons() { return reasons; }
    }
}
