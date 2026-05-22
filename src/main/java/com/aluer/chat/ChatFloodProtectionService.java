package com.aluer.chat;

import com.aluer.config.ServerGuardConfig;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * 聊天洪水/垃圾消息防护服务 — V4.0 聊天社交安全模块
 *
 * 检测原理：
 * 1. 频率追踪：3秒窗口内超过5条消息触发短时静音，10秒窗口内超过10条触发长静音
 * 2. 相似度检测：连续3条消息编辑距离<3视为重复洪水
 * 3. 长度激增检测：突然发送超长消息(>500字符)视为异常，正常聊天<200字符
 * 4. Unicode洪水检测：消息中超过50%为特殊Unicode字符时拦截
 * 5. 递增式静音策略：5秒→30秒→5分钟→永久，防止攻击者反复试探阈值
 *
 * 配置开关：serverguard.security.super-evolution.chat-flood-protection
 */
@Service
public class ChatFloodProtectionService {

    private final ServerGuardConfig config;
    private final Map<String, Deque<ChatEvent>> playerMessageHistory = new ConcurrentHashMap<>();
    private final Map<String, Instant> mutedUntil = new ConcurrentHashMap<>();
    private final Map<String, Integer> muteLevel = new ConcurrentHashMap<>();
    private final AtomicLong totalMessages = new AtomicLong(0);
    private final AtomicLong totalFloodEvents = new AtomicLong(0);

    /** 递增静音时长(秒)：5, 30, 300, 永久(-1) */
    private static final long[] MUTE_ESCALATION_SECONDS = {5L, 30L, 300L, -1L};
    /** 3秒窗口阈值 */
    private static final int SHORT_WINDOW_THRESHOLD = 5;
    /** 10秒窗口阈值 */
    private static final int LONG_WINDOW_THRESHOLD = 10;
    /** 3秒窗口大小(秒) */
    private static final long SHORT_WINDOW_SECONDS = 3L;
    /** 10秒窗口大小(秒) */
    private static final long LONG_WINDOW_SECONDS = 10L;
    /** 超长消息字符数阈值 */
    private static final int LONG_MESSAGE_THRESHOLD = 500;
    /** 正常聊天字符数上限 */
    private static final int NORMAL_MESSAGE_MAX = 200;
    /** 相似度检测的编辑距离阈值 */
    private static final int SIMILARITY_EDIT_DISTANCE = 3;
    /** Unicode洪水检测比例阈值 */
    private static final double UNICODE_FLOOD_RATIO = 0.5;
    /** 历史消息保留条数上限 */
    private static final int MAX_HISTORY_PER_PLAYER = 50;

    public ChatFloodProtectionService() {
        this(new ServerGuardConfig());
    }

    @Autowired
    public ChatFloodProtectionService(ServerGuardConfig config) {
        this.config = config;
    }

    /**
     * 检测玩家聊天消息是否存在洪水/垃圾行为
     *
     * 首先检查玩家是否处于静音期，然后从频率、相似度、长度、Unicode四个维度
     * 逐层检测。每个维度独立判断，命中任一维度即返回blocked。
     *
     * @param player  玩家名
     * @param message 待检测的聊天消息
     * @return 检测结果，包含是否拦截及原因列表
     */
    public CheckResult check(String player, String message) {
        if (!config.getSecurity().getSuperEvolution().isChatFloodProtection()) {
            return CheckResult.clean();
        }

        totalMessages.incrementAndGet();

        // 0. 检查是否处于静音期
        Instant muteEnd = mutedUntil.get(player);
        if (muteEnd != null && Instant.now().isBefore(muteEnd)) {
            totalFloodEvents.incrementAndGet();
            return CheckResult.blocked(List.of("玩家处于静音期至 " + muteEnd));
        }

        // 获取或创建玩家消息历史
        Deque<ChatEvent> history = playerMessageHistory.computeIfAbsent(player,
                k -> new ArrayDeque<>());

        Instant now = Instant.now();
        ChatEvent currentEvent = new ChatEvent(now, message);
        history.addLast(currentEvent);

        // 限制历史记录长度，防止内存膨胀
        while (history.size() > MAX_HISTORY_PER_PLAYER) {
            history.removeFirst();
        }

        List<String> reasons = new ArrayList<>();

        // 1. 短窗口频率检测(3秒窗口内>5条)
        long shortCount = history.stream()
                .filter(e -> e.time.isAfter(now.minusSeconds(SHORT_WINDOW_SECONDS)))
                .count();
        if (shortCount > SHORT_WINDOW_THRESHOLD) {
            reasons.add("3秒内发送" + shortCount + "条消息(阈值" + SHORT_WINDOW_THRESHOLD + ")");
        }

        // 2. 长窗口频率检测(10秒窗口内>10条)
        long longCount = history.stream()
                .filter(e -> e.time.isAfter(now.minusSeconds(LONG_WINDOW_SECONDS)))
                .count();
        if (longCount > LONG_WINDOW_THRESHOLD) {
            reasons.add("10秒内发送" + longCount + "条消息(阈值" + LONG_WINDOW_THRESHOLD + ")");
        }

        // 3. 消息相似度检测(连续3条编辑距离<3)
        if (history.size() >= 3) {
            List<ChatEvent> recent = new ArrayList<>(history);
            int size = recent.size();
            String msg1 = recent.get(size - 3).message;
            String msg2 = recent.get(size - 2).message;
            String msg3 = recent.get(size - 1).message;

            if (editDistance(msg1, msg2) < SIMILARITY_EDIT_DISTANCE
                    && editDistance(msg2, msg3) < SIMILARITY_EDIT_DISTANCE) {
                reasons.add("连续3条消息高度相似(编辑距离<" + SIMILARITY_EDIT_DISTANCE + ")，疑似重复洪水");
            }
        }

        // 4. 消息长度激增检测(>500字符，正常聊天<200字符)
        if (message.length() > LONG_MESSAGE_THRESHOLD) {
            // 检查该玩家历史是否有正常长度的聊天记录
            boolean hasNormalChat = history.stream()
                    .filter(e -> !e.message.equals(message))
                    .anyMatch(e -> e.message.length() < NORMAL_MESSAGE_MAX);
            if (hasNormalChat) {
                reasons.add("突然发送超长消息(" + message.length() + "字符)，正常聊天<" + NORMAL_MESSAGE_MAX + "字符");
            }
        }

        // 5. Unicode洪水检测(消息中>50%为特殊Unicode字符)
        if (isUnicodeFlood(message)) {
            reasons.add("消息中超过50%为特殊Unicode字符，疑似Unicode洪水攻击");
        }

        if (!reasons.isEmpty()) {
            escalateMute(player);
            totalFloodEvents.incrementAndGet();
            return CheckResult.blocked(reasons);
        }

        return CheckResult.clean();
    }

    /**
     * 递增式静音策略
     *
     * 每次洪水事件后递增静音级别，从5秒→30秒→5分钟→永久。
     * 这样可以防止攻击者反复试探阈值，每次违规都会受到更严厉的惩罚。
     *
     * @param player 被静音的玩家名
     */
    private void escalateMute(String player) {
        int level = muteLevel.getOrDefault(player, 0);
        long durationSeconds = MUTE_ESCALATION_SECONDS[Math.min(level, MUTE_ESCALATION_SECONDS.length - 1)];

        if (durationSeconds == -1) {
            // 永久静音：设为遥远的未来时间点
            mutedUntil.put(player, Instant.MAX);
        } else {
            mutedUntil.put(player, Instant.now().plusSeconds(durationSeconds));
        }
        muteLevel.put(player, level + 1);
    }

    /**
     * 计算两个字符串之间的编辑距离(Levenshtein距离)
     *
     * 使用动态规划算法计算将str1转换为str2所需的最少编辑操作次数。
     * 编辑操作包括：插入、删除、替换一个字符。
     * 空间复杂度O(min(m,n))，使用滚动数组优化。
     *
     * @param str1 字符串1
     * @param str2 字符串2
     * @return 编辑距离
     */
    private int editDistance(String str1, String str2) {
        // 确保str1是较短的字符串，节省空间
        if (str1.length() > str2.length()) {
            String temp = str1;
            str1 = str2;
            str2 = temp;
        }

        int m = str1.length();
        int n = str2.length();
        int[] prev = new int[m + 1];
        int[] curr = new int[m + 1];

        for (int i = 0; i <= m; i++) {
            prev[i] = i;
        }

        for (int j = 1; j <= n; j++) {
            curr[0] = j;
            for (int i = 1; i <= m; i++) {
                int cost = str1.charAt(i - 1) == str2.charAt(j - 1) ? 0 : 1;
                curr[i] = Math.min(Math.min(
                        prev[i] + 1,       // 删除
                        curr[i - 1] + 1),   // 插入
                        prev[i - 1] + cost); // 替换
            }
            int[] temp = prev;
            prev = curr;
            curr = temp;
        }

        return prev[m];
    }

    /**
     * 检测消息是否为Unicode洪水
     *
     * 统计消息中Unicode码点位于CJK统一表意文字、特殊符号、数学符号
     * 等范围的字符占比。若超过50%且消息长度>10，视为Unicode洪水。
     * 正常Minecraft聊天以ASCII字符为主。
     *
     * @param message 待检测的消息
     * @return true表示疑似Unicode洪水
     */
    private boolean isUnicodeFlood(String message) {
        if (message.length() < 10) {
            return false; // 短消息不检测，避免误判
        }

        int specialCount = 0;
        for (int i = 0; i < message.length(); i++) {
            int codePoint = message.codePointAt(i);
            // 跳过代理对的高半部分，避免重复计数
            if (Character.isSupplementaryCodePoint(codePoint)) {
                i++;
            }
            // 检测范围：CJK统一表意文字(4E00-9FFF)、CJK扩展A(3400-4DBF)、
            // 全角符号(FF00-FFEF)、数学符号(2200-22FF)、特殊符号(2600-26FF)、
            // 装饰符号(2700-27BF)、零宽字符(200B-200F, 202A-202E, 2060)
            if ((codePoint >= 0x4E00 && codePoint <= 0x9FFF)
                    || (codePoint >= 0x3400 && codePoint <= 0x4DBF)
                    || (codePoint >= 0xFF00 && codePoint <= 0xFFEF)
                    || (codePoint >= 0x2200 && codePoint <= 0x22FF)
                    || (codePoint >= 0x2600 && codePoint <= 0x26FF)
                    || (codePoint >= 0x2700 && codePoint <= 0x27BF)
                    || (codePoint >= 0x200B && codePoint <= 0x200F)
                    || (codePoint >= 0x202A && codePoint <= 0x202E)
                    || codePoint == 0x2060
                    || codePoint == 0xFEFF) { // BOM/零宽不换行空格
                specialCount++;
            }
        }

        return (double) specialCount / message.length() > UNICODE_FLOOD_RATIO;
    }

    /**
     * 获取服务运行状态
     *
     * 返回总处理消息数、当前静音玩家数、洪水事件数、启用的检测维度。
     *
     * @return 包含状态键值对的LinkedHashMap
     */
    public Map<String, Object> getStatus() {
        Map<String, Object> s = new LinkedHashMap<>();
        s.put("enabled", config.getSecurity().getSuperEvolution().isChatFloodProtection());
        s.put("totalMessages", totalMessages.get());
        s.put("mutedPlayers", mutedUntil.size());
        s.put("floodEvents", totalFloodEvents.get());
        s.put("activeTrackers", playerMessageHistory.size());
        s.put("shortWindowThreshold", SHORT_WINDOW_THRESHOLD);
        s.put("longWindowThreshold", LONG_WINDOW_THRESHOLD);
        s.put("unicodeFloodRatio", UNICODE_FLOOD_RATIO);
        return s;
    }

    /**
     * 解除指定玩家的静音状态
     *
     * @param player 玩家名
     */
    public void unmutePlayer(String player) {
        mutedUntil.remove(player);
        muteLevel.remove(player);
    }

    /**
     * 获取当前被静音的玩家列表及其剩余时间
     *
     * @return 玩家名->剩余秒数 的映射
     */
    public Map<String, Long> getMutedPlayers() {
        Map<String, Long> result = new LinkedHashMap<>();
        Instant now = Instant.now();
        for (Map.Entry<String, Instant> entry : mutedUntil.entrySet()) {
            long remaining = entry.getValue().getEpochSecond() - now.getEpochSecond();
            if (remaining > 0 || entry.getValue().equals(Instant.MAX)) {
                result.put(entry.getKey(), entry.getValue().equals(Instant.MAX) ? -1L : remaining);
            }
        }
        return result;
    }

    /**
     * 聊天事件记录，存储时间戳和消息内容
     */
    private static class ChatEvent {
        final Instant time;
        final String message;

        ChatEvent(Instant time, String message) {
            this.time = time;
            this.message = message;
        }
    }

    /**
     * 检测结果类
     */
    public static class CheckResult {
        private final boolean blocked;
        private final List<String> reasons;

        private CheckResult(boolean blocked, List<String> reasons) {
            this.blocked = blocked;
            this.reasons = reasons;
        }

        public static CheckResult clean() {
            return new CheckResult(false, List.of());
        }

        public static CheckResult blocked(List<String> reasons) {
            return new CheckResult(true, reasons);
        }

        public boolean isBlocked() { return blocked; }
        public boolean isClean() { return !blocked; }
        public List<String> getReasons() { return reasons; }
    }
}
