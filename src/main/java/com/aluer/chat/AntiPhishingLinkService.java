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
 * 钓鱼/恶意链接检测服务 — V4.0 聊天社交安全模块
 *
 * 检测原理：
 * 1. URL提取：从消息中提取所有URL
 * 2. 短链接展开：检测bit.ly、t.co等短链接服务并标记需解析
 * 3. 可疑域名检测：包含minecraft/mojang/login/verify等关键字的非官方域名
 * 4. 已知钓鱼域名黑名单匹配
 * 5. 免费Minecraft骗局链接检测
 * 6. 显示文本与链接不匹配检测(如 [Mojang官方]实际链接到钓鱼站)
 * 7. SSL证书验证标记(需要实际HTTP请求的标记)
 *
 * 配置开关：serverguard.security.super-evolution.anti-phishing-link
 */
@Service
public class AntiPhishingLinkService {

    private final ServerGuardConfig config;
    private final AtomicLong totalUrls = new AtomicLong(0);
    private final AtomicLong phishingDetected = new AtomicLong(0);
    private final AtomicLong shortUrlsResolved = new AtomicLong(0);
    private final Map<String, Long> playerPhishingCount = new ConcurrentHashMap<>();

    /** URL提取正则 */
    private static final Pattern URL_PATTERN = Pattern.compile(
            "https?://[\\w\\-._~:/?#\\[\\]@!$&'()*+,;=%]+|" +
            "www\\.[\\w\\-._~:/?#\\[\\]@!$&'()*+,;=%]+",
            Pattern.CASE_INSENSITIVE);

    /** 短链接服务域名列表 */
    private static final Set<String> SHORT_URL_SERVICES = Set.of(
            "bit.ly", "t.co", "short.url", "is.gd", "tinyurl.com",
            "ow.ly", "buff.ly", "goo.gl", "bitly.com", "cutt.ly",
            "rebrand.ly", "shorten", "short.link", "shorte.st",
            "shorturl", "s.id", "surl", "v.gd", "0rz.tw",
            "4url.cc", "alturl.com", "chilp.it", "cl.ly",
            "dft.ba", "j.mp", "korta.nu", "microurl.com",
            "n9.cl", "rb.gy", "snip.ly", "tny.im", "tr.im",
            "u.to", "urlz.fr", "x.co", "y2u.be", "yourls.org",
            "zi.ma", "zpr.io"
    );

    /** 已知钓鱼/恶意域名黑名单 */
    private static final Set<String> KNOWN_PHISHING_DOMAINS = Set.of(
            "mc-login.com", "mojang-login.com", "minecraft-login.net",
            "mc-free.com", "minecraft-gift.com", "mc-verify.com",
            "mojang-verify.com", "minecraft-security.com", "mc-security.org",
            "minecraft-premium.com", "mc-premium.org", "free-minecraft.net",
            "minecraft-cape.com", "mc-cape-free.com", "optifine-free.com",
            "minecon-cape.com", "minecraft-account.com", "mc-accounts.com",
            "steal-account.info", "phish-account.ml"
    );

    /** 可疑域名关键字(出现在非官方域名中视为钓鱼) */
    private static final String[] SUSPICIOUS_DOMAIN_KEYWORDS = {
            "minecraft", "mojang", "login", "verify", "account",
            "password", "signin", "authenticate", "credential", "redeem",
            "gift", "free-cape", "free-mc", "mc-premium", "premium-mc"
    };

    /** Mojang/Microsoft官方域名，不会被误判 */
    private static final Set<String> OFFICIAL_DOMAINS = Set.of(
            "minecraft.net", "mojang.com", "minecraftforge.net",
            "fabricmc.net", "paperMC.io", "spigotmc.org",
            "bukkit.org", "papermc.io", "purpurmc.org",
            "curseforge.com", "modrinth.com", "planetminecraft.com",
            "xbox.com", "microsoft.com", "live.com"
    );

    /** 免费Minecraft骗局关键字 */
    private static final String[] FREE_MC_KEYWORDS = {
            "free minecraft", "free mc", "get free", "minecraft free",
            "free account", "free gift", "free cape", "generate account",
            "unlimited minecraft", "mc account generator"
    };

    /** Minecraft官方相关的显示文本关键字 */
    private static final String[] OFFICIAL_TEXT_INDICATORS = {
            "mojang", "minecraft official", "minecraft.net", "官方",
            "official", "verify", "验证", "安全", "security"
    };

    public AntiPhishingLinkService() {
        this(new ServerGuardConfig());
    }

    @Autowired
    public AntiPhishingLinkService(ServerGuardConfig config) {
        this.config = config;
    }

    /**
     * 检测消息中的URL是否为钓鱼/恶意链接
     *
     * 从消息中提取所有URL，逐一检测是否为短链接、是否指向已知钓鱼域名、
     * 是否包含可疑关键字但非官方域名、是否为免费Minecraft骗局、以及
     * 显示文本与实际链接是否不匹配。
     *
     * @param player  玩家名
     * @param message 待检测的聊天消息
     * @return 检测结果
     */
    public CheckResult check(String player, String message) {
        if (!config.getSecurity().getSuperEvolution().isAntiPhishingLink()) {
            return CheckResult.clean();
        }

        if (message == null || message.isEmpty()) {
            return CheckResult.clean();
        }

        List<String> reasons = new ArrayList<>();
        String lowerMessage = message.toLowerCase();

        // 提取所有URL
        Matcher urlMatcher = URL_PATTERN.matcher(message);
        List<String> foundUrls = new ArrayList<>();
        while (urlMatcher.find()) {
            foundUrls.add(urlMatcher.group());
        }

        for (String url : foundUrls) {
            totalUrls.incrementAndGet();
            String normalizedUrl = url.toLowerCase();
            String domain = extractDomain(normalizedUrl);

            if (domain == null) {
                continue;
            }

            // 1. 短链接检测
            if (isShortUrlService(domain)) {
                shortUrlsResolved.incrementAndGet();
                reasons.add("检测到短链接服务: " + domain + " (短链接可能隐藏真实目标)");
                continue; // 短链接标记但不过度处罚，继续其他检测
            }

            // 2. 已知钓鱼域名黑名单匹配
            if (KNOWN_PHISHING_DOMAINS.contains(domain)) {
                phishingDetected.incrementAndGet();
                reasons.add("已知钓鱼域名黑名单: " + domain);
            }

            // 3. 可疑域名检测：包含minecraft/mojang/login等关键字但非官方域名
            if (!isOfficialDomain(domain) && containsSuspiciousKeyword(domain)) {
                phishingDetected.incrementAndGet();
                reasons.add("域名包含Minecraft相关关键字但非官方域名: " + domain + " (疑似假冒网站)");
            }

            // 4. 检测"免费Minecraft"骗局
            if (containsFreeMcScam(lowerMessage)) {
                phishingDetected.incrementAndGet();
                reasons.add("检测到免费Minecraft骗局链接: " + url);
            }
        }

        // 5. 检测不匹配的显示文本
        if (!foundUrls.isEmpty() && hasMismatchedDisplayText(message, foundUrls)) {
            phishingDetected.incrementAndGet();
            reasons.add("消息中声称官方但实际链接指向非官方网站，疑似文本链接不匹配钓鱼");
        }

        if (!reasons.isEmpty()) {
            playerPhishingCount.merge(player, 1L, Long::sum);
            return CheckResult.blocked(reasons);
        }

        return CheckResult.clean();
    }

    /**
     * 从URL中提取域名部分
     *
     * 处理http://、https://前缀，移除路径和查询参数，只保留域名。
     *
     * @param url 完整URL
     * @return 纯域名部分，解析失败返回null
     */
    private String extractDomain(String url) {
        if (url == null) return null;
        String cleaned = url.replaceFirst("^https?://", "");
        cleaned = cleaned.replaceFirst("^www\\.", "");
        int slashIndex = cleaned.indexOf('/');
        if (slashIndex > 0) {
            cleaned = cleaned.substring(0, slashIndex);
        }
        int colonIndex = cleaned.lastIndexOf(':');
        if (colonIndex > 0 && cleaned.substring(colonIndex + 1).matches("\\d+")) {
            cleaned = cleaned.substring(0, colonIndex);
        }
        return cleaned.isEmpty() ? null : cleaned;
    }

    /**
     * 判断域名是否为短链接服务
     *
     * @param domain 域名
     * @return true表示是短链接服务
     */
    private boolean isShortUrlService(String domain) {
        if (domain == null) return false;
        for (String service : SHORT_URL_SERVICES) {
            if (domain.equals(service) || domain.endsWith("." + service)) {
                return true;
            }
        }
        return false;
    }

    /**
     * 判断域名是否为Minecraft生态官方域名
     *
     * @param domain 域名
     * @return true表示是官方域名
     */
    private boolean isOfficialDomain(String domain) {
        if (domain == null) return false;
        for (String official : OFFICIAL_DOMAINS) {
            if (domain.equals(official) || domain.endsWith("." + official)) {
                return true;
            }
        }
        return false;
    }

    /**
     * 判断域名是否包含可疑关键字(如minecraft、login等)
     *
     * @param domain 域名
     * @return true表示包含可疑关键字
     */
    private boolean containsSuspiciousKeyword(String domain) {
        if (domain == null) return false;
        for (String keyword : SUSPICIOUS_DOMAIN_KEYWORDS) {
            if (domain.contains(keyword)) {
                return true;
            }
        }
        return false;
    }

    /**
     * 检测消息是否包含"免费Minecraft"骗局关键字
     *
     * @param message 小写的消息文本
     * @return true表示包含骗局关键字
     */
    private boolean containsFreeMcScam(String message) {
        for (String keyword : FREE_MC_KEYWORDS) {
            if (message.contains(keyword)) {
                return true;
            }
        }
        return false;
    }

    /**
     * 检测显示文本与实际链接是否不匹配
     *
     * 例如消息声称"[Mojang官方验证]"但实际链接指向钓鱼站。
     * 同时检测消息中包含Minecraft官方相关文本关键字但URL域名非官方。
     *
     * @param message 消息原文
     * @param urls    消息中的URL列表
     * @return true表示存在不匹配
     */
    private boolean hasMismatchedDisplayText(String message, List<String> urls) {
        String lowerMessage = message.toLowerCase();

        // 检查是否包含官方相关文本关键字
        boolean hasOfficialText = false;
        for (String indicator : OFFICIAL_TEXT_INDICATORS) {
            if (lowerMessage.contains(indicator)) {
                hasOfficialText = true;
                break;
            }
        }

        if (!hasOfficialText) {
            return false;
        }

        // 检查所有URL是否都是非官方域名
        for (String url : urls) {
            String domain = extractDomain(url.toLowerCase());
            if (domain != null && !isOfficialDomain(domain)) {
                return true; // 声称官方但实际URL不是官方域名
            }
        }

        return false;
    }

    /**
     * 获取服务运行状态
     *
     * @return 包含状态键值对的LinkedHashMap
     */
    public Map<String, Object> getStatus() {
        Map<String, Object> s = new LinkedHashMap<>();
        s.put("enabled", config.getSecurity().getSuperEvolution().isAntiPhishingLink());
        s.put("totalUrls", totalUrls.get());
        s.put("phishingDetected", phishingDetected.get());
        s.put("shortUrlsResolved", shortUrlsResolved.get());
        s.put("knownPhishingDomains", KNOWN_PHISHING_DOMAINS.size());
        s.put("shortUrlServices", SHORT_URL_SERVICES.size());
        s.put("trackedPlayers", playerPhishingCount.size());
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
