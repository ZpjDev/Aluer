package com.aluer.anticheat.player;

import com.aluer.config.ServerGuardConfig;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.text.Normalizer;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * 玩家名称冒充检测 — V4.0 访问控制模块
 *
 * 检测原理：
 * 1. 检测新加入玩家的名称是否通过Unicode同形字符（homoglyph）冒充现有玩家或管理员
 *    - 例如用 ᴀ (U+1D00) 替换 A, 用 ο (Greek omicron U+03BF) 替换 o
 *    - 用 і (Cyrillic U+0456) 替换 i, 用 а (Cyrillic U+0430) 替换 a
 * 2. 检测包含不可见/零宽字符的玩家名（U+200B零宽空格、U+200C零宽非连接符等）
 *    这些字符在视觉上不可见但会使玩家名在系统中识别为不同名称
 * 3. 大小写欺骗检测：Admin → admin, ADMIN, Admín 等变体
 *    Minecraft用户名不区分大小写，但利用相似Unicode字符可绕过展示层检查
 * 4. 维护已知冒充目标名单（所有在线OP玩家名 + 知名Minecraft人物名 + 服务器自定义名单）
 *    新玩家加入时计算与该名单中每一项的相似度
 * 5. 使用 Levenshtein 编辑距离算法计算名称相似度，并配合 Unicode NFKC 标准化后比对
 *    相似度阈值可配置，超过阈值的名称标记为冒充尝试
 * 6. 检测名称中包含的空格/特殊前缀后缀（如 [Admin] PlayerName 格式混淆）
 *
 * 配置开关：serverguard.security.super-evolution.anti-name-spoof
 */
@Service
public class AntiNameSpoofService {

    private final ServerGuardConfig config;

    /** 需保护的名称集合：OP名、管理员名、知名人物名 */
    private final Set<String> protectedNames = ConcurrentHashMap.newKeySet();
    /** 自定义虚假目标（特殊名单） */
    private final Set<String> customSpoofTargets = ConcurrentHashMap.newKeySet();
    /** 已检测到的冒充尝试 */
    private final Map<String, List<SpoofAttempt>> spoofHistory = new ConcurrentHashMap<>();
    /** 已被阻止的冒充名称集合 */
    private final Set<String> blockedNames = ConcurrentHashMap.newKeySet();

    private final AtomicLong totalNameChecks = new AtomicLong(0);
    private final AtomicLong spoofAttempts = new AtomicLong(0);

    /**
     * Unicode同形字符映射表：视觉相似但Unicode码点不同的字符
     * key = 标准ASCII字母，value = 其Unicode同形字符列表
     */
    private static final Map<Character, List<Character>> HOMOGLYPH_MAP = Map.ofEntries(
            Map.entry('A', List.of('A', 'A', 'Á', 'À', 'Â', 'Ã', 'Ä', 'Å', 'Ā', 'Ă', 'Ą')),
            Map.entry('a', List.of('a', 'á', 'à', 'â', 'ã', 'ä', 'å', 'ā', 'ă', 'ą', '@')),
            Map.entry('B', List.of('B', 'ß', 'Þ')),
            Map.entry('b', List.of('b', 'þ')),
            Map.entry('C', List.of('C', 'Ç', 'Ć', 'Č')),
            Map.entry('c', List.of('c', 'ç', 'ć', 'č')),
            Map.entry('E', List.of('E', 'È', 'É', 'Ê', 'Ë', 'Ē', 'Ĕ', 'Ė', 'Ę', 'Ě')),
            Map.entry('e', List.of('e', 'è', 'é', 'ê', 'ë', 'ē', 'ĕ', 'ė', 'ę', 'ě')),
            Map.entry('H', List.of('H', 'Ĥ', 'Ħ')),
            Map.entry('h', List.of('h', 'ĥ', 'ħ')),
            Map.entry('I', List.of('I', 'Ì', 'Í', 'Î', 'Ï', 'Ĩ', 'Ī', 'Ĭ', 'Į', 'İ')),
            Map.entry('i', List.of('i', 'ì', 'í', 'î', 'ï', 'ĩ', 'ī', 'ĭ', 'į', 'ı', '¡')),
            Map.entry('K', List.of('K', 'Ķ', 'Œ')),
            Map.entry('k', List.of('k', 'ķ', 'ĸ')),
            Map.entry('l', List.of('l', 'ł', 'ŀ', 'ĺ', 'ļ', 'ľ')),
            Map.entry('N', List.of('N', 'Ñ', 'Ń', 'Ņ', 'Ň')),
            Map.entry('n', List.of('n', 'ñ', 'ń', 'ņ', 'ň', 'ŉ')),
            Map.entry('O', List.of('O', 'Ò', 'Ó', 'Ô', 'Õ', 'Ö', 'Ø', 'Ō', 'Ŏ', 'Ő')),
            Map.entry('o', List.of('o', 'ò', 'ó', 'ô', 'õ', 'ö', 'ø', 'ō', 'ŏ', 'ő', 'ο', 'о')),
            Map.entry('P', List.of('P', 'Þ')),
            Map.entry('p', List.of('p', 'þ')),
            Map.entry('S', List.of('S', 'Ś', 'Ŝ', 'Ş', 'Š')),
            Map.entry('s', List.of('s', 'ś', 'ŝ', 'ş', 'š')),
            Map.entry('T', List.of('T', 'Ţ', 'Ť', 'Ŧ')),
            Map.entry('t', List.of('t', 'ţ', 'ť', 'ŧ')),
            Map.entry('U', List.of('U', 'Ù', 'Ú', 'Û', 'Ü', 'Ũ', 'Ū', 'Ŭ', 'Ů', 'Ű', 'Ų')),
            Map.entry('u', List.of('u', 'ù', 'ú', 'û', 'ü', 'ũ', 'ū', 'ŭ', 'ů', 'ű', 'ų', 'µ')),
            Map.entry('Y', List.of('Y', 'Ý', 'Ŷ', 'Ÿ')),
            Map.entry('y', List.of('y', 'ý', 'ÿ', 'ŷ')),
            Map.entry('Z', List.of('Z', 'Ź', 'Ż', 'Ž')),
            Map.entry('z', List.of('z', 'ź', 'ż', 'ž'))
    );

    /** 零宽/不可见Unicode字符 */
    private static final Set<Character> INVISIBLE_CHARACTERS = Set.of(
            '​',  // 零宽空格 Zero Width Space
            '‌',  // 零宽非连接符 Zero Width Non-Joiner
            '‍',  // 零宽连接符 Zero Width Joiner
            '‎',  // 左到右标记 Left-to-Right Mark
            '‏',  // 右到左标记 Right-to-Left Mark
            '⁠',  // 词连接符 Word Joiner
            '⁡',  // 函数应用 Function Application
            '⁢',  // 不可见乘号 Invisible Times
            '⁣',  // 不可见分隔符 Invisible Separator
            '⁤',  // 不可见加号 Invisible Plus
            '﻿',  // 零宽不中断空格 Zero Width No-Break Space / BOM
            '­',  // 软连接符 Soft Hyphen
            '͏',  // 组合用字素连接符 Combining Grapheme Joiner
            '؜',  // 阿拉伯字母格式标记 Arabic Letter Mark
            '᠎',  // 蒙古语元音分隔符（已在Unicode 6.3弃用但仍可能被滥用）
            '⁦',  // 左到右隔离 Left-to-Right Isolate
            '⁧',  // 右到左隔离 Right-to-Left Isolate
            '⁨',  // 第一个强隔离 First Strong Isolate
            '⁩'   // 弹出方向隔离 Pop Directional Isolate
    );

    /** Minecraft知名人物名（常被冒充目标） */
    private static final Set<String> WELL_KNOWN_NAMES = Set.of(
            "Notch", "jeb_", "Dinnerbone", "Grumm",
            "Dream", "Technoblade", "TommyInnit", "Philza",
            "MumboJumbo", "Grian", "Iskall85", "Scar",
            "CaptainSparklez", "DanTDM", "PrestonPlayz",
            "Hypixel", "Spigot", "Paper", "Mojang", "Microsoft",
            "Administrator", "Owner", "Admin"
    );

    /** 相似度阈值（Levenshtein距离占名称长度的比例，0-1，越小越相似） */
    private static final double LEVENSHTEIN_SIMILARITY_THRESHOLD = 0.3;
    /** Minecraft玩家名最大长度 */
    private static final int MAX_PLAYERNAME_LENGTH = 16;

    /** 无参构造函数，使用默认配置 */
    public AntiNameSpoofService() {
        this(new ServerGuardConfig());
    }

    @Autowired
    public AntiNameSpoofService(ServerGuardConfig config) {
        this.config = config;
        // 初始化默认保护名单：知名Minecraft人物名
        protectedNames.addAll(WELL_KNOWN_NAMES);
    }

    /**
     * 检查新加入玩家的名称是否在冒充其他玩家/管理员
     *
     * @param playerName 待检查的玩家名
     * @param ip         玩家IP（用于日志记录）
     * @return 检测结果，包含是否检测到冒充及原因
     */
    public NameSpoofResult checkPlayerName(String playerName, String ip) {
        totalNameChecks.incrementAndGet();

        // 配置开关检查
        if (!config.getSecurity().getSuperEvolution().isAntiNameSpoof()) {
            return NameSpoofResult.clean();
        }

        if (playerName == null || playerName.isBlank()) {
            return NameSpoofResult.clean();
        }

        // Minecraft玩家名不应超过16字符
        if (playerName.length() > MAX_PLAYERNAME_LENGTH) {
            return NameSpoofResult.clean(); // 长度异常在其他模块处理
        }

        List<String> reasons = new ArrayList<>();
        boolean spoofDetected = false;
        Instant now = Instant.now();

        // 检查1：零宽/不可见字符检测
        String visibleName = removeInvisibleCharacters(playerName);
        if (!visibleName.equals(playerName)) {
            spoofDetected = true;
            spoofAttempts.incrementAndGet();
            reasons.add("INVISIBLE_CHARS: Player name \"" + escapeName(playerName)
                    + "\" contains invisible/zero-width Unicode characters ("
                    + countInvisibleChars(playerName) + " chars detected) — "
                    + "can be used to impersonate \"" + visibleName + "\"");

            blockedNames.add(playerName);
            recordSpoofAttempt(playerName, visibleName, "INVISIBLE_CHARS", ip, now);
        }

        // 检查2：Unicode标准化后的差异对比
        String normalized = normalizeForComparison(playerName);
        if (!spoofDetected) {
            for (String protectedName : protectedNames) {
                String normalizedProtected = normalizeForComparison(protectedName);
                if (normalized.equalsIgnoreCase(normalizedProtected)) {
                    spoofDetected = true;
                    spoofAttempts.incrementAndGet();
                    reasons.add("UNICODE_SPOOF: Player name \"" + playerName
                            + "\" uses Unicode characters to visually mimic \"" + protectedName
                            + "\" (normalized: " + normalized + " == " + normalizedProtected + ")");

                    blockedNames.add(playerName);
                    recordSpoofAttempt(playerName, protectedName, "UNICODE_SPOOF", ip, now);
                    break;
                }
            }
        }

        // 检查3：大小写欺骗（不区分大小写比对后，名称匹配但大小写不同）
        if (!spoofDetected) {
            String lowerPlayer = playerName.toLowerCase(Locale.ROOT);
            for (String protectedName : protectedNames) {
                String lowerProtected = protectedName.toLowerCase(Locale.ROOT);
                if (lowerPlayer.equals(lowerProtected) && !playerName.equals(protectedName)) {
                    // 确认不是同一个名字（大小写差异的另一个实现方式）
                    spoofDetected = true;
                    spoofAttempts.incrementAndGet();
                    reasons.add("CASE_SPOOF: Player name \"" + playerName
                            + "\" uses different case to impersonate \"" + protectedName + "\"");

                    blockedNames.add(playerName);
                    recordSpoofAttempt(playerName, protectedName, "CASE_SPOOF", ip, now);
                    break;
                }
            }
        }

        // 检查4：Levenshtein编辑距离相似度检测
        if (!spoofDetected) {
            for (String protectedName : protectedNames) {
                double similarity = levenshteinSimilarity(playerName.toLowerCase(Locale.ROOT),
                        protectedName.toLowerCase(Locale.ROOT));
                if (similarity < LEVENSHTEIN_SIMILARITY_THRESHOLD
                        && playerName.length() >= 3 && protectedName.length() >= 3) {
                    // 排除完全不同的短名称误报
                    if (Math.abs(playerName.length() - protectedName.length()) <= 2) {
                        spoofDetected = true;
                        spoofAttempts.incrementAndGet();
                        reasons.add("SIMILARITY_SPOOF: Player name \"" + playerName
                                + "\" is highly similar to protected name \"" + protectedName
                                + "\" (Levenshtein distance: " + String.format("%.2f", similarity) + ")");

                        blockedNames.add(playerName);
                        recordSpoofAttempt(playerName, protectedName, "SIMILARITY_SPOOF", ip, now);
                        break;
                    }
                }
            }
        }

        if (spoofDetected) {
            return NameSpoofResult.spoofed(reasons);
        }
        return NameSpoofResult.clean();
    }

    /**
     * 添加一个需要保护的名称（OP玩家名、管理员名等）
     *
     * @param name 需保护的名称
     */
    public void addProtectedName(String name) {
        if (name != null && !name.isBlank()) {
            protectedNames.add(name);
        }
    }

    /**
     * 批量添加受保护的名称
     *
     * @param names 需保护的名称列表
     */
    public void addProtectedNames(Collection<String> names) {
        if (names != null) {
            protectedNames.addAll(names);
        }
    }

    /**
     * 从受保护名单中移除名称
     *
     * @param name 名称
     */
    public void removeProtectedName(String name) {
        if (name != null) {
            protectedNames.remove(name);
        }
    }

    /**
     * 获取所有受保护的名称
     *
     * @return 受保护名称集合
     */
    public Set<String> getProtectedNames() {
        return new HashSet<>(protectedNames);
    }

    /**
     * 获取模块运行状态
     *
     * @return 状态Map，包含totalNameChecks/spoofAttempts/blockedNames
     */
    public Map<String, Object> getStatus() {
        Map<String, Object> s = new LinkedHashMap<>();
        s.put("enabled", config.getSecurity().getSuperEvolution().isAntiNameSpoof());
        s.put("totalNameChecks", totalNameChecks.get());
        s.put("spoofAttempts", spoofAttempts.get());
        s.put("blockedNames", blockedNames.size());
        s.put("protectedNames", protectedNames.size());
        s.put("blockedNameList", new ArrayList<>(blockedNames));
        s.put("protectedNameList", new ArrayList<>(protectedNames));

        // 最近10次冒充尝试
        List<Map<String, Object>> recent = new ArrayList<>();
        int total = 0;
        for (List<SpoofAttempt> attempts : spoofHistory.values()) {
            for (SpoofAttempt a : attempts) {
                if (total < 10) {
                    Map<String, Object> m = new LinkedHashMap<>();
                    m.put("time", a.time.toString());
                    m.put("playerName", a.playerName);
                    m.put("target", a.targetName);
                    m.put("type", a.spoofType);
                    m.put("ip", a.ip);
                    recent.add(m);
                }
                total++;
            }
        }
        s.put("recentSpoofAttempts", recent);
        return s;
    }

    // ==================== 内部辅助方法 ====================

    /**
     * 移除字符串中的所有零宽/不可见Unicode字符
     * 用于显示清洗后的可见名称，以及底层对比
     */
    private String removeInvisibleCharacters(String input) {
        if (input == null) return null;
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < input.length(); i++) {
            char c = input.charAt(i);
            if (!INVISIBLE_CHARACTERS.contains(c)) {
                sb.append(c);
            }
        }
        return sb.toString();
    }

    /** 统计不可见字符数量 */
    private int countInvisibleChars(String input) {
        if (input == null) return 0;
        int count = 0;
        for (int i = 0; i < input.length(); i++) {
            if (INVISIBLE_CHARACTERS.contains(input.charAt(i))) {
                count++;
            }
        }
        return count;
    }

    /**
     * Unicode NFKC标准化后转为小写，用于名称的公平比对
     * NFKC会将兼容性字符分解并重新组合（例如将全角字母转为半角）
     */
    private String normalizeForComparison(String input) {
        if (input == null) return "";
        // 先移除不可见字符，再NFKC标准化，再转小写
        String cleaned = removeInvisibleCharacters(input);
        return Normalizer.normalize(cleaned, Normalizer.Form.NFKC).toLowerCase(Locale.ROOT);
    }

    /**
     * 计算两个字符串之间的Levenshtein编辑距离相似度
     * 返回值 = 编辑距离 / 最大字符串长度（结果越小越相似）
     *
     * @param s1 字符串1
     * @param s2 字符串2
     * @return 标准化相似度（0=完全相同，1=完全不同）
     */
    private double levenshteinSimilarity(String s1, String s2) {
        if (s1 == null || s2 == null) return 1.0;
        if (s1.equals(s2)) return 0.0;

        int[][] dp = new int[s1.length() + 1][s2.length() + 1];
        for (int i = 0; i <= s1.length(); i++) dp[i][0] = i;
        for (int j = 0; j <= s2.length(); j++) dp[0][j] = j;

        for (int i = 1; i <= s1.length(); i++) {
            for (int j = 1; j <= s2.length(); j++) {
                int cost = s1.charAt(i - 1) == s2.charAt(j - 1) ? 0 : 1;
                dp[i][j] = Math.min(Math.min(
                        dp[i - 1][j] + 1,      // 删除
                        dp[i][j - 1] + 1),     // 插入
                        dp[i - 1][j - 1] + cost); // 替换
            }
        }

        int maxLen = Math.max(s1.length(), s2.length());
        if (maxLen == 0) return 0.0;
        return (double) dp[s1.length()][s2.length()] / maxLen;
    }

    /** 将名称中的不可见字符转换为Unicode转义序列用于安全日志输出 */
    private String escapeName(String name) {
        if (name == null) return "null";
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < name.length(); i++) {
            char c = name.charAt(i);
            if (INVISIBLE_CHARACTERS.contains(c)) {
                sb.append(String.format("\\u%04X", (int) c));
            } else {
                sb.append(c);
            }
        }
        return sb.toString();
    }

    /** 记录一次冒充尝试 */
    private void recordSpoofAttempt(String playerName, String targetName, String spoofType, String ip, Instant time) {
        SpoofAttempt attempt = new SpoofAttempt(time, playerName, targetName, spoofType, ip);
        spoofHistory.computeIfAbsent(playerName, k -> Collections.synchronizedList(new ArrayList<>())).add(attempt);
    }

    // ==================== 内部数据类 ====================

    /** 冒充尝试记录 */
    private static class SpoofAttempt {
        final Instant time;
        final String playerName;
        final String targetName;
        final String spoofType;
        final String ip;

        SpoofAttempt(Instant time, String playerName, String targetName, String spoofType, String ip) {
            this.time = time;
            this.playerName = playerName;
            this.targetName = targetName;
            this.spoofType = spoofType;
            this.ip = ip;
        }
    }

    /** 名称冒充检测结果 */
    public static class NameSpoofResult {
        private final boolean spoofed;
        private final List<String> reasons;

        private NameSpoofResult(boolean spoofed, List<String> reasons) {
            this.spoofed = spoofed;
            this.reasons = reasons;
        }

        public static NameSpoofResult clean() {
            return new NameSpoofResult(false, List.of());
        }

        public static NameSpoofResult spoofed(List<String> reasons) {
            return new NameSpoofResult(true, reasons);
        }

        public boolean isSpoofed() { return spoofed; }
        public boolean isClean() { return !spoofed; }
        public List<String> getReasons() { return reasons; }
    }
}
