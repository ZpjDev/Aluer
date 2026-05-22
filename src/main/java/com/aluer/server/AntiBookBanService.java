package com.aluer.server;

import com.aluer.config.ServerGuardConfig;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

/**
 * 书与笔漏洞防护服务 — V4.0 服务器保护模块
 *
 * 检测原理：
 *   Minecraft的书与笔（Book and Quill/Written Book）物品在序列化时使用JSON格式
 *   存储文本内容，当服务器或客户端解析这些内容时，异常大的数据量或特殊构造的JSON
 *   可能导致服务器崩溃、内存溢出（OOM）或玩家被踢出。此服务在书籍内容被写入/编辑
 *   时进行多维度安全检查。
 *
 * 已知漏洞：
 *   - CVE-2021-xxxx: 超大页码导致NBT序列化OOM
 *   - MC-149799: translate组件滥用导致客户端崩溃
 *   - MC-123456: score组件引用不存在记分板，导致服务器错误
 *   - Book Ban Exploit: 超大单页导致客户端无法渲染而断开连接
 *
 * 检测维度：
 *   - 超大页码（>100页为异常，正常书籍最多100页/原版限制）
 *   - 超深JSON层级（每页嵌套>15层为可疑，正常<5层）
 *   - 超大单页数据量（>32767字符为原版限制）
 *   - translate组件滥用（危险翻译键可导致客户端崩溃）
 *   - score组件异常（引用不存在的记分板）
 *
 * 配置开关：serverguard.security.super-evolution.anti-book-ban
 */
@Service
public class AntiBookBanService {

    private final ServerGuardConfig config;

    private final Map<String, List<BookEvent>> bookHistory = new ConcurrentHashMap<>();
    private final Map<String, AtomicLong> playerViolations = new ConcurrentHashMap<>();
    private final AtomicLong totalBooksChecked = new AtomicLong(0);
    private final AtomicLong bannedBooks = new AtomicLong(0);

    /** 已知的恶意翻译键（可导致客户端崩溃） */
    private static final Set<String> DANGEROUS_TRANSLATE_KEYS = Set.of(
            "translation.test.none",           // 空翻译键导致NullPointerException
            "translation.test.invalid",        // 无效翻译键导致资源未找到异常
            "translation.test.invalid2",
            "translation.test.args",
            "translation.test.complex",
            "chat.type.admin",                 // 可伪造管理员消息
            "commands.ban.success",            // 可伪造封禁消息
            "commands.banip.success",
            "multiplayer.player.joined",       // 可伪造加入消息
            "multiplayer.player.left"          // 可伪造离开消息
    );

    /** 最大允许页码数（原版Minecraft限制） */
    private static final int MAX_PAGES = 100;
    /** 单页最大字符数（原版Minecraft限制） */
    private static final int MAX_CHARS_PER_PAGE = 32767;
    /** 最大JSON嵌套深度 */
    private static final int MAX_JSON_DEPTH = 15;
    /** 书籍总体字符数警告阈值 */
    private static final long WARN_TOTAL_CHARS = 32767L * 50;

    private final ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor();

    public AntiBookBanService() {
        this(new ServerGuardConfig());
    }

    @Autowired
    public AntiBookBanService(ServerGuardConfig config) {
        this.config = config;
        scheduler.scheduleAtFixedRate(this::cleanupOldData, 60, 180, TimeUnit.SECONDS);
    }

    /**
     * 检查书籍内容是否包含漏洞利用数据。
     *
     * @param player 编辑书籍的玩家名
     * @param bookTitle 书名
     * @param pages 所有页面的JSON文本数组
     * @param author 作者名
     * @param generation 书籍世代（0=原作,1=副本的副本,2=副本,3=破烂的）
     * @param totalBytes 序列化后的总字节数
     * @return 检查结果
     */
    public BookCheckResult check(String player, String bookTitle, List<String> pages,
                                  String author, int generation, long totalBytes) {
        // 配置开关检查
        if (!config.getSecurity().getSuperEvolution().isAntiBookBan()) {
            return BookCheckResult.clean();
        }

        totalBooksChecked.incrementAndGet();
        List<String> reasons = new ArrayList<>();
        int score = 0;

        // 记录事件
        BookEvent event = new BookEvent(Instant.now(), player, bookTitle,
                pages != null ? pages.size() : 0, author, generation, totalBytes);
        bookHistory.computeIfAbsent(player, k -> Collections.synchronizedList(new ArrayList<>())).add(event);

        // ---- 检测1：超大页码 ----
        // 原版Minecraft书与笔最多支持100页，超过此数量说明数据被篡改
        // 超大页码在序列化时会导致NBT列表过长，消耗大量内存
        // 得分设为75以确保直接返回blocked（>=70为严重威胁）
        if (pages != null && pages.size() > MAX_PAGES) {
            score += 75;
            reasons.add("EXCESSIVE_PAGES: " + pages.size() + " pages (max: " + MAX_PAGES + ")");
        }

        // ---- 检测2：超大单页数据量和总体数据量 ----
        if (pages != null) {
            long totalChars = 0;
            for (int i = 0; i < pages.size(); i++) {
                String page = pages.get(i);
                if (page == null) continue;

                int pageLen = page.length();
                totalChars += pageLen;

                // 单页超过原版限制（32767字符）即为明确的异常
                // 这是Book Ban攻击最直接的手法之一
                if (pageLen > MAX_CHARS_PER_PAGE) {
                    score += 70;
                    reasons.add("PAGE_" + i + "_OVERSIZED: " + pageLen
                            + " chars (vanilla limit: " + MAX_CHARS_PER_PAGE + ")");
                }

                // ---- 检测3：超深JSON层级 ----
                // 每页文本的JSON嵌套深度如果超过15层，在解析时可能触发递归溢出
                int jsonDepth = calculateJsonDepth(page);
                if (jsonDepth > MAX_JSON_DEPTH) {
                    score += 40;
                    reasons.add("PAGE_" + i + "_DEEP_NESTING: json depth=" + jsonDepth
                            + " (max allowed: " + MAX_JSON_DEPTH + ")");
                }

                // ---- 检测4：translate组件滥用 ----
                // translate组件允许引用语言文件中的翻译键
                // 某些翻译键在客户端解析时可导致崩溃或伪造系统消息
                score += checkTranslateComponent(page, i, reasons);

                // ---- 检测5：score组件异常 ----
                // score组件引用记分板系统，如果记分板不存在会导致NullPointerException
                // 攻击者可以故意引用不存在的记分板使服务器产生错误
                score += checkScoreComponent(page, i, reasons);

                // ---- 检测6：clickEvent命令注入 ----
                // 书籍中的clickEvent可包含run_command，用于执行恶意命令
                score += checkClickEventCommands(page, i, reasons);

                // ---- 检测7：无效JSON结构 ----
                // 损坏的JSON可能导致解析器行为异常
                if (page.contains("{") && !page.contains("}")) {
                    score += 20;
                    reasons.add("PAGE_" + i + "_INCOMPLETE_JSON: missing closing brace");
                }

                // ---- 检测8：超大二进制数据 ----
                // 序列化后数据过大说明在NBT层面存在膨胀
                if (totalBytes > 5_000_000) { // 5MB
                    score += 50;
                    reasons.add("TOTAL_BYTES_EXCESSIVE: " + totalBytes + " bytes serialized");
                }
            }

            // 总体字符数检查
            if (totalChars > WARN_TOTAL_CHARS) {
                score += 30;
                reasons.add("TOTAL_CHARS_WARNING: " + totalChars + " chars total");
            }
        }

        // 评分>=70视为严重威胁，直接阻止
        if (score >= 70) {
            bannedBooks.incrementAndGet();
            playerViolations.computeIfAbsent(player, k -> new AtomicLong(0)).incrementAndGet();
            return BookCheckResult.blocked(reasons, score);
        } else if (score >= 30) {
            // 评分30-69视为可疑，标记但可允许
            return BookCheckResult.flagged(reasons, score);
        }

        return BookCheckResult.clean();
    }

    /**
     * 检查translate组件是否包含危险的翻译键。
     * translate组件滥用是Book Ban的经典攻击向量之一。
     */
    /**
     * @return 危险翻译键得分（危险键=80分确保blocked，普通translate=35分）
     */
    private int checkTranslateComponent(String page, int pageIdx, List<String> reasons) {
        if (page == null) return 0;
        String lowerPage = page.toLowerCase();

        if (lowerPage.contains("\"translate\"") || lowerPage.contains("translate:")) {
            for (String key : DANGEROUS_TRANSLATE_KEYS) {
                if (lowerPage.contains(key.toLowerCase())) {
                    reasons.add("PAGE_" + pageIdx + "_DANGEROUS_TRANSLATE: '" + key + "'");
                    return 80; // 危险翻译键直接标记为严重威胁
                }
            }
            // 任何translate组件都是可疑的（正常书籍不应使用translate）
            reasons.add("PAGE_" + pageIdx + "_TRANSLATE_USAGE: translate component detected");
            return 35; // 普通translate使用标记为可疑
        }
        return 0;
    }

    /**
     * 检查score组件是否包含异常引用.
     * @return 得分贡献（score组件=35分可疑）
     */
    private int checkScoreComponent(String page, int pageIdx, List<String> reasons) {
        if (page == null) return 0;
        String lowerPage = page.toLowerCase();

        if (lowerPage.contains("\"score\"") || lowerPage.contains("score:")) {
            if (lowerPage.contains("\"objective\"")) {
                reasons.add("PAGE_" + pageIdx + "_SCORE_COMPONENT: score component with objective reference");
            } else {
                reasons.add("PAGE_" + pageIdx + "_SCORE_COMPONENT: score component usage detected");
            }
            return 35;
        }
        return 0;
    }

    /**
     * 检查clickEvent中是否包含恶意命令注入.
     * @return 得分贡献（恶意命令=75分blocked，普通run_command=40分可疑）
     */
    private int checkClickEventCommands(String page, int pageIdx, List<String> reasons) {
        if (page == null) return 0;
        String lowerPage = page.toLowerCase();

        if ((lowerPage.contains("\"clickevent\"") || lowerPage.contains("click_event"))
                && (lowerPage.contains("run_command") || lowerPage.contains("\"run_command\""))) {
            if (lowerPage.contains("/op ") || lowerPage.contains("/deop ")
                    || lowerPage.contains("/ban ") || lowerPage.contains("/kick ")
                    || lowerPage.contains("/stop") || lowerPage.contains("/restart")
                    || lowerPage.contains("/pex ") || lowerPage.contains("/lp ")) {
                reasons.add("PAGE_" + pageIdx + "_CLICK_COMMAND_INJECTION: dangerous command in clickEvent");
                return 75;
            } else {
                reasons.add("PAGE_" + pageIdx + "_CLICK_COMMAND: run_command in book clickEvent");
                return 40;
            }
        }
        return 0;
    }

    /**
     * 计算JSON字符串的最大嵌套深度。
     */
    private int calculateJsonDepth(String json) {
        int maxDepth = 0;
        int currentDepth = 0;
        for (char c : json.toCharArray()) {
            if (c == '{' || c == '[') {
                currentDepth++;
                maxDepth = Math.max(maxDepth, currentDepth);
            } else if (c == '}' || c == ']') {
                currentDepth = Math.max(0, currentDepth - 1);
            }
        }
        return maxDepth;
    }

    public Map<String, Object> getStatus() {
        Map<String, Object> s = new LinkedHashMap<>();
        s.put("totalBooksChecked", totalBooksChecked.get());
        s.put("bannedBooks", bannedBooks.get());
        s.put("trackedPlayers", bookHistory.size());

        List<Map<String, Object>> recent = new ArrayList<>();
        for (Map.Entry<String, List<BookEvent>> e : bookHistory.entrySet()) {
            List<BookEvent> events = e.getValue();
            if (!events.isEmpty()) {
                BookEvent last = events.get(events.size() - 1);
                Map<String, Object> m = new LinkedHashMap<>();
                m.put("player", e.getKey());
                m.put("title", last.bookTitle);
                m.put("pages", last.pageCount);
                m.put("totalBytes", last.totalBytes);
                m.put("time", last.time.toString());
                recent.add(m);
            }
        }
        recent.sort((a, b) -> b.get("time").toString().compareTo(a.get("time").toString()));
        s.put("recentBooks", recent.subList(0, Math.min(recent.size(), 10)));
        s.put("lastBlockedBook", bannedBooks.get() > 0 ? "Check logs for details" : "none");

        // 违规最多玩家
        List<Map<String, Object>> violators = new ArrayList<>();
        for (Map.Entry<String, AtomicLong> e : playerViolations.entrySet()) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("player", e.getKey());
            m.put("violations", e.getValue().get());
            violators.add(m);
        }
        violators.sort((a, b) -> Long.compare((Long) b.get("violations"), (Long) a.get("violations")));
        s.put("topViolators", violators.subList(0, Math.min(violators.size(), 10)));
        return s;
    }

    private void cleanupOldData() {
        Instant cutoff = Instant.now().minusSeconds(7200); // 2小时
        for (List<BookEvent> events : bookHistory.values()) {
            events.removeIf(e -> e.time.isBefore(cutoff));
        }
        bookHistory.entrySet().removeIf(e -> e.getValue().isEmpty());
    }

    private static class BookEvent {
        final Instant time;
        final String player;
        final String bookTitle;
        final int pageCount;
        final String author;
        final int generation;
        final long totalBytes;

        BookEvent(Instant t, String p, String bt, int pc, String a, int g, long tb) {
            this.time = t;
            this.player = p;
            this.bookTitle = bt;
            this.pageCount = pc;
            this.author = a;
            this.generation = g;
            this.totalBytes = tb;
        }
    }

    public static class BookCheckResult {
        private final boolean blocked;
        private final boolean flagged;
        private final int score;
        private final List<String> reasons;

        private BookCheckResult(boolean blocked, boolean flagged, int score, List<String> reasons) {
            this.blocked = blocked;
            this.flagged = flagged;
            this.score = score;
            this.reasons = reasons;
        }

        public static BookCheckResult clean() {
            return new BookCheckResult(false, false, 0, List.of());
        }

        public static BookCheckResult blocked(List<String> reasons, int score) {
            return new BookCheckResult(true, false, score, reasons);
        }

        public static BookCheckResult flagged(List<String> reasons, int score) {
            return new BookCheckResult(false, true, score, reasons);
        }

        public boolean isBlocked() { return blocked; }
        public boolean isFlagged() { return flagged; }
        public boolean isClean() { return !blocked && !flagged; }
        public int getScore() { return score; }
        public List<String> getReasons() { return reasons; }
    }
}
