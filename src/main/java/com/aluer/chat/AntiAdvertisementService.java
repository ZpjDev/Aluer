package com.aluer.chat;

import com.aluer.config.ServerGuardConfig;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * 服务器广告/宣传检测服务 — V4.0 聊天社交安全模块
 *
 * 检测原理：
 * 1. IP地址匹配：正则检测包括带端口的IPv4地址
 * 2. 域名匹配：匹配常见顶级域名的服务器宣传域名
 * 3. QQ群号检测：6-12位数字配合"群"关键字
 * 4. Discord邀请检测：discord.gg/xxx 或 discord.com/invite/xxx
 * 5. 绕过技术检测：识别数字间加空格/特殊字符的变体
 * 6. 白名单模式：允许服务器自己的域名/IP通过
 *
 * 配置开关：serverguard.security.super-evolution.anti-advertisement
 */
@Service
public class AntiAdvertisementService {

    private final ServerGuardConfig config;
    private final AtomicLong totalMessages = new AtomicLong(0);
    private final AtomicLong adsDetected = new AtomicLong(0);
    private final AtomicLong blockedMessages = new AtomicLong(0);
    private final Map<String, Long> playerBlockCount = new ConcurrentHashMap<>();

    /** 自身服务器白名单IP/域名 */
    private final Set<String> whitelistIps = ConcurrentHashMap.newKeySet();
    private final Set<String> whitelistDomains = ConcurrentHashMap.newKeySet();

    /** IPv4地址正则：匹配含可选端口的IP地址 */
    private static final Pattern IP_PATTERN = Pattern.compile(
            "\\b\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}(:\\d{1,5})?\\b");

    /** 域名匹配正则：匹配常见顶级域名的域名 */
    private static final Pattern DOMAIN_PATTERN = Pattern.compile(
            "[\\w-]+\\.(com|cn|net|org|cc|xyz|top|tk|ml|ga|cf|fun|online|store|shop)" +
            "(:\\d{1,5})?", Pattern.CASE_INSENSITIVE);

    /** QQ群号正则：6-12位数字，需配合"群"关键字使用 */
    private static final Pattern QQ_GROUP_PATTERN = Pattern.compile(
            "\\b\\d{6,12}\\b");

    /** Discord邀请链接正则 */
    private static final Pattern DISCORD_PATTERN = Pattern.compile(
            "discord\\.gg/\\w+|discord\\.com/invite/\\w+", Pattern.CASE_INSENSITIVE);

    /** 绕过技术正则：数字间插入空格/特殊字符的变体 */
    private static final Pattern OBFUSCATED_IP_PATTERN = Pattern.compile(
            "(\\d{1,3})\\s*[\\.\\s,，、·•]+\\s*(\\d{1,3})\\s*[\\.\\s,，、·•]+\\s*(\\d{1,3})\\s*[\\.\\s,，、·•]+\\s*(\\d{1,3})");

    /** 群聊关键字 */
    private static final String[] GROUP_KEYWORDS = {
            "群", "group", "q群", "qq群", "qqun", "扣扣群", "峮", "裙"
    };

    /** 广告关键字 */
    private static final String[] AD_KEYWORDS = {
            "服务器", "server", "直连", "联机", "开黑", "加入", "join", "ip地址",
            "端口", "port", "基岩", "java版", "mc版本", "minecraft"
    };

    public AntiAdvertisementService() {
        this(new ServerGuardConfig());
    }

    @Autowired
    public AntiAdvertisementService(ServerGuardConfig config) {
        this.config = config;
    }

    /**
     * 检测聊天消息是否包含服务器广告/宣传内容
     *
     * 按以下顺序逐项检测：IP地址、域名、QQ群号、Discord邀请、绕过变体。
     * 命中任一检测项即返回blocked。检测前会与白名单进行比对，
     * 白名单内的IP/域名不会被拦截，防止误拦截自身服务器信息。
     *
     * @param player  玩家名
     * @param message 待检测的聊天消息
     * @return 检测结果
     */
    public CheckResult check(String player, String message) {
        if (!config.getSecurity().getSuperEvolution().isAntiAdvertisement()) {
            return CheckResult.clean();
        }

        totalMessages.incrementAndGet();

        if (message == null || message.isEmpty()) {
            return CheckResult.clean();
        }

        String normalized = normalizeMessage(message);
        List<String> reasons = new ArrayList<>();

        // 1. IP地址检测
        Matcher ipMatcher = IP_PATTERN.matcher(message);
        while (ipMatcher.find()) {
            String found = ipMatcher.group();
            String ipOnly = found.contains(":") ? found.substring(0, found.indexOf(':')) : found;
            if (!isWhitelistedIp(ipOnly)) {
                reasons.add("检测到非白名单IP地址: " + found);
                break;
            }
        }

        // 2. 域名检测
        Matcher domainMatcher = DOMAIN_PATTERN.matcher(message);
        while (domainMatcher.find()) {
            String found = domainMatcher.group().toLowerCase();
            if (!isWhitelistedDomain(found)) {
                reasons.add("检测到非白名单域名: " + found);
                break;
            }
        }

        // 3. QQ群号检测(数字+群关键字)
        Matcher qqMatcher = QQ_GROUP_PATTERN.matcher(normalized);
        boolean hasGroupKeyword = containsGroupKeyword(normalized);
        if (hasGroupKeyword && qqMatcher.find()) {
            reasons.add("检测到QQ群号宣传: " + qqMatcher.group());
        }

        // 4. Discord邀请检测
        Matcher discordMatcher = DISCORD_PATTERN.matcher(normalized);
        if (discordMatcher.find()) {
            reasons.add("检测到Discord邀请链接: " + discordMatcher.group());
        }

        // 5. 绕过技术检测：数字间加空格/特殊字符的变体
        Matcher obfIpMatcher = OBFUSCATED_IP_PATTERN.matcher(message);
        if (obfIpMatcher.find()) {
            // 重建完整IP字符串验证是否为有效IP
            String reconstructed = obfIpMatcher.group(1) + "."
                    + obfIpMatcher.group(2) + "."
                    + obfIpMatcher.group(3) + "."
                    + obfIpMatcher.group(4);
            if (!isWhitelistedIp(reconstructed)) {
                reasons.add("检测到IP地址绕过变体: " + obfIpMatcher.group());
            }
        }

        if (!reasons.isEmpty()) {
            adsDetected.incrementAndGet();
            blockedMessages.incrementAndGet();
            playerBlockCount.merge(player, 1L, Long::sum);
            return CheckResult.blocked(reasons);
        }

        return CheckResult.clean();
    }

    /**
     * 标准化消息文本，用于关键字匹配
     *
     * 将消息转为小写并移除多余空格，便于后续关键字匹配。
     *
     * @param message 原始消息
     * @return 标准化后的消息
     */
    private String normalizeMessage(String message) {
        return message.toLowerCase().replaceAll("\\s+", " ").trim();
    }

    /**
     * 检查IP是否在白名单中
     *
     * @param ip IP地址字符串
     * @return true表示在白名单中
     */
    private boolean isWhitelistedIp(String ip) {
        return whitelistIps.contains(ip);
    }

    /**
     * 检查域名是否在白名单中
     *
     * @param domain 域名字符串
     * @return true表示在白名单中
     */
    private boolean isWhitelistedDomain(String domain) {
        for (String wd : whitelistDomains) {
            if (domain.equalsIgnoreCase(wd) || domain.endsWith("." + wd)) {
                return true;
            }
        }
        return false;
    }

    /**
     * 检查消息是否包含群聊关键字
     *
     * @param message 标准化后的消息
     * @return true表示包含
     */
    private boolean containsGroupKeyword(String message) {
        for (String keyword : GROUP_KEYWORDS) {
            if (message.contains(keyword)) {
                return true;
            }
        }
        return false;
    }

    /**
     * 添加白名单IP
     *
     * @param ip IP地址
     */
    public void addWhitelistedIp(String ip) {
        if (ip != null && !ip.isEmpty()) {
            whitelistIps.add(ip.trim());
        }
    }

    /**
     * 移除白名单IP
     *
     * @param ip IP地址
     */
    public void removeWhitelistedIp(String ip) {
        whitelistIps.remove(ip);
    }

    /**
     * 添加白名单域名
     *
     * @param domain 域名
     */
    public void addWhitelistedDomain(String domain) {
        if (domain != null && !domain.isEmpty()) {
            whitelistDomains.add(domain.trim().toLowerCase());
        }
    }

    /**
     * 移除白名单域名
     *
     * @param domain 域名
     */
    public void removeWhitelistedDomain(String domain) {
        whitelistDomains.remove(domain);
    }

    public Set<String> getWhitelistIps() {
        return new HashSet<>(whitelistIps);
    }

    public Set<String> getWhitelistDomains() {
        return new HashSet<>(whitelistDomains);
    }

    /**
     * 获取玩家被拦截次数
     *
     * @param player 玩家名
     * @return 被拦截次数
     */
    public long getPlayerBlockCount(String player) {
        return playerBlockCount.getOrDefault(player, 0L);
    }

    /**
     * 获取服务运行状态
     *
     * @return 包含状态键值对的LinkedHashMap
     */
    public Map<String, Object> getStatus() {
        Map<String, Object> s = new LinkedHashMap<>();
        s.put("enabled", config.getSecurity().getSuperEvolution().isAntiAdvertisement());
        s.put("totalMessages", totalMessages.get());
        s.put("adsDetected", adsDetected.get());
        s.put("blockedMessages", blockedMessages.get());
        s.put("whitelistIps", new ArrayList<>(whitelistIps));
        s.put("whitelistDomains", new ArrayList<>(whitelistDomains));
        s.put("trackedPlayers", playerBlockCount.size());
        return s;
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
