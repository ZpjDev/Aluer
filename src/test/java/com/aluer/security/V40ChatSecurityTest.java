package com.aluer.security;

import org.junit.jupiter.api.Test;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;

class V40ChatSecurityTest {

    // ================================================================
    // ChatFloodProtectionService Tests
    // ================================================================

    @Test
    void chatFloodDetectsShortWindowFlood() {
        ChatFloodProtectionService cf = new ChatFloodProtectionService();
        // 3秒窗口内快速发送6条消息应触发洪水检测
        for (int i = 0; i < 6; i++) {
            cf.check("Player1", "Test message " + i);
        }
        // 第7条应该被拦截
        ChatFloodProtectionService.CheckResult r = cf.check("Player1", "Another message");
        assertTrue(r.isBlocked(), "6条消息在3秒窗口内应触发洪水检测");
        assertFalse(r.getReasons().isEmpty());
    }

    @Test
    void chatFloodAllowsNormalChatRate() {
        ChatFloodProtectionService cf = new ChatFloodProtectionService();
        // 发送2条消息不应触发洪水
        ChatFloodProtectionService.CheckResult r1 = cf.check("Player2", "Hello");
        assertTrue(r1.isClean());
        ChatFloodProtectionService.CheckResult r2 = cf.check("Player2", "How are you?");
        assertTrue(r2.isClean());
        // 验证计数器运作
        Map<String, Object> status = cf.getStatus();
        assertTrue((Long) status.get("totalMessages") >= 2);
    }

    @Test
    void chatFloodDetectsUnicodeFlood() {
        ChatFloodProtectionService cf = new ChatFloodProtectionService();
        // 构建超过50%为CJK特殊字符的长消息
        StringBuilder unicodeMsg = new StringBuilder();
        for (int i = 0; i < 50; i++) {
            unicodeMsg.append("测试测试测试测试"); // CJK字符
        }
        ChatFloodProtectionService.CheckResult r = cf.check("Player3", unicodeMsg.toString());
        assertTrue(r.isBlocked(), "超过50%CJK字符应触发Unicode洪水检测");
    }

    @Test
    void chatFloodDetectsSimilarMessages() {
        ChatFloodProtectionService cf = new ChatFloodProtectionService();
        // 连续3条高度相似的消息(编辑距离<3)
        cf.check("Player4", "Selling cheap items");
        cf.check("Player4", "Selling cheap items!");  // 只差1个字符
        ChatFloodProtectionService.CheckResult r = cf.check("Player4", "Selling cheap items!!"); // 只差2个字符
        assertTrue(r.isBlocked(), "连续3条高度相似的消息应触发重复洪水检测");
    }

    @Test
    void chatFloodStatusContainsExpectedFields() {
        ChatFloodProtectionService cf = new ChatFloodProtectionService();
        cf.check("Player5", "Message one");
        cf.check("Player5", "Message two");

        Map<String, Object> status = cf.getStatus();
        assertNotNull(status.get("totalMessages"));
        assertNotNull(status.get("mutedPlayers"));
        assertNotNull(status.get("floodEvents"));
        assertNotNull(status.get("activeTrackers"));
        assertTrue(status.get("enabled") instanceof Boolean);
    }

    // ================================================================
    // AntiAdvertisementService Tests
    // ================================================================

    @Test
    void antiAdDetectsIpAddress() {
        AntiAdvertisementService ad = new AntiAdvertisementService();
        AntiAdvertisementService.CheckResult r = ad.check("Player1",
                "Join my server at 123.45.67.89:25565!");
        assertTrue(r.isBlocked(), "消息中包含IP地址应被检测为广告");
    }

    @Test
    void antiAdDetectsDomain() {
        AntiAdvertisementService ad = new AntiAdvertisementService();
        AntiAdvertisementService.CheckResult r = ad.check("Player2",
                "Check out myserver.com for great gameplay!");
        assertTrue(r.isBlocked(), "消息中包含.com域名应被检测为广告");
    }

    @Test
    void antiAdDetectsDiscordInvite() {
        AntiAdvertisementService ad = new AntiAdvertisementService();
        AntiAdvertisementService.CheckResult r = ad.check("Player3",
                "Join our discord.gg/abcdef for giveaways!");
        assertTrue(r.isBlocked(), "消息中包含Discord邀请应被检测为广告");
    }

    @Test
    void antiAdDetectsQQGroup() {
        AntiAdvertisementService ad = new AntiAdvertisementService();
        AntiAdvertisementService.CheckResult r = ad.check("Player4",
                "加群一起玩：12345678");
        assertTrue(r.isBlocked(), "消息中包含QQ群号应被检测为广告");
    }

    @Test
    void antiAdAllowsNormalMessage() {
        AntiAdvertisementService ad = new AntiAdvertisementService();
        AntiAdvertisementService.CheckResult r = ad.check("Player5",
                "Hey guys, how is everyone doing today?");
        assertTrue(r.isClean(), "正常聊天消息不应被拦截");
    }

    @Test
    void antiAdWhitelistIpPasses() {
        AntiAdvertisementService ad = new AntiAdvertisementService();
        ad.addWhitelistedIp("192.168.1.1");
        AntiAdvertisementService.CheckResult r = ad.check("Player6",
                "Server IP is 192.168.1.1:25565");
        assertTrue(r.isClean(), "白名单IP不应被拦截");
    }

    @Test
    void antiAdStatusHasCounters() {
        AntiAdvertisementService ad = new AntiAdvertisementService();
        ad.check("Player7", "Join 10.0.0.1");
        Map<String, Object> status = ad.getStatus();
        assertTrue((Long) status.get("totalMessages") >= 1);
        assertNotNull(status.get("adsDetected"));
        assertNotNull(status.get("blockedMessages"));
    }

    // ================================================================
    // AntiPhishingLinkService Tests
    // ================================================================

    @Test
    void antiPhishDetectsKnownPhishingDomain() {
        AntiPhishingLinkService ap = new AntiPhishingLinkService();
        AntiPhishingLinkService.CheckResult r = ap.check("Player1",
                "Verify your account at http://mc-login.com/verify");
        assertTrue(r.isBlocked(), "已知钓鱼域名应被检测");
    }

    @Test
    void antiPhishDetectsFakeMojangDomain() {
        AntiPhishingLinkService ap = new AntiPhishingLinkService();
        AntiPhishingLinkService.CheckResult r = ap.check("Player2",
                "Free cape at http://minecraft-login.net/free");
        assertTrue(r.isBlocked(), "包含minecraft关键字的非官方域名应被检测");
    }

    @Test
    void antiPhishDetectsShortUrl() {
        AntiPhishingLinkService ap = new AntiPhishingLinkService();
        AntiPhishingLinkService.CheckResult r = ap.check("Player3",
                "Claim your reward: http://bit.ly/freemc123");
        assertTrue(r.isBlocked(), "短链接应被标记");
    }

    @Test
    void antiPhishDetectsFreeMcScam() {
        AntiPhishingLinkService ap = new AntiPhishingLinkService();
        AntiPhishingLinkService.CheckResult r = ap.check("Player4",
                "Get free minecraft account at http://steal-account.info");
        assertTrue(r.isBlocked(), "免费Minecraft骗局应被检测");
    }

    @Test
    void antiPhishDetectsMismatchedText() {
        AntiPhishingLinkService ap = new AntiPhishingLinkService();
        AntiPhishingLinkService.CheckResult r = ap.check("Player5",
                "Mojang官方验证请访问: http://phish-site.com/login");
        assertTrue(r.isBlocked(), "声称官方但链接非官方应被检测为文本链接不匹配");
    }

    @Test
    void antiPhishAllowsNormalMessage() {
        AntiPhishingLinkService ap = new AntiPhishingLinkService();
        AntiPhishingLinkService.CheckResult r = ap.check("Player6",
                "Hey everyone! Let's build something cool today.");
        assertTrue(r.isClean(), "不含URL的正常消息不应被拦截");
    }

    @Test
    void antiPhishStatusHasCounters() {
        AntiPhishingLinkService ap = new AntiPhishingLinkService();
        ap.check("Player7", "Visit http://mc-login.com");
        Map<String, Object> status = ap.getStatus();
        assertNotNull(status.get("totalUrls"));
        assertNotNull(status.get("phishingDetected"));
        assertNotNull(status.get("shortUrlsResolved"));
    }

    // ================================================================
    // AntiCommandAbuseService Tests
    // ================================================================

    @Test
    void antiCmdDetectsCommandFlood() {
        AntiCommandAbuseService ac = new AntiCommandAbuseService();
        // 10秒窗口内快速发送12条命令应触发洪水检测
        for (int i = 0; i < 12; i++) {
            ac.check("Player1", "/tp " + i, "tp");
        }
        // 第13条应被拦截
        AntiCommandAbuseService.CheckResult r = ac.check("Player1", "/tp 13", "tp");
        assertTrue(r.isBlocked(), "10秒内超过10条命令应触发洪水检测");
    }

    @Test
    void antiCmdDetectsShellInjection() {
        AntiCommandAbuseService ac = new AntiCommandAbuseService();
        AntiCommandAbuseService.CheckResult r = ac.check("Player2",
                "/say hello; rm -rf /", "say", "; rm -rf /", true);
        assertTrue(r.isBlocked(), "包含Shell注入字符的命令应被检测");
    }

    @Test
    void antiCmdDetectsPluginScanning() {
        AntiCommandAbuseService ac = new AntiCommandAbuseService();
        // 连续执行不存在的命令(模拟插件扫描)
        for (int i = 0; i < 6; i++) {
            ac.check("Player3", "/nonexistent" + i, "nonexistent" + i, "", false);
        }
        AntiCommandAbuseService.CheckResult r = ac.check("Player3",
                "/nonexistent6", "nonexistent6", "", false);
        assertTrue(r.isBlocked(), "连续执行不存在命令应被检测为插件扫描");
    }

    @Test
    void antiCmdAllowsNormalCommands() {
        AntiCommandAbuseService ac = new AntiCommandAbuseService();
        AntiCommandAbuseService.CheckResult r = ac.check("Player4",
                "/home", "home", null, true);
        assertTrue(r.isClean(), "正常命令不应被拦截");
    }

    @Test
    void antiCmdDetectsDollarSubCommandInjection() {
        AntiCommandAbuseService ac = new AntiCommandAbuseService();
        AntiCommandAbuseService.CheckResult r = ac.check("Player5",
                "/say $(cat /etc/passwd)", "say", "$(cat /etc/passwd)", true);
        assertTrue(r.isBlocked(), "$() Shell注入应被检测");
    }

    @Test
    void antiCmdStatusHasCommandStats() {
        AntiCommandAbuseService ac = new AntiCommandAbuseService();
        ac.check("Player6", "/home", "home");
        ac.check("Player6", "/home", "home");
        ac.check("Player6", "/spawn", "spawn");

        Map<String, Object> status = ac.getStatus();
        assertNotNull(status.get("totalCommands"));
        assertNotNull(status.get("blockedCommands"));
        assertNotNull(status.get("commandStats"));
    }

    // ================================================================
    // PlayerPrivacyService Tests
    // ================================================================

    @Test
    void privacyAnonymizesIpAddress() {
        PlayerPrivacyService pp = new PlayerPrivacyService();
        String result = pp.anonymizeIp("Player connected from 192.168.1.100");
        assertTrue(result.contains("xxx.xxx"), "IP地址应被脱敏为 xxx.xxx");
        assertTrue(result.contains("192.168"), "IP前两位应保留");
        assertFalse(result.contains("1.100"), "IP后两位应被隐藏");
    }

    @Test
    void privacyAnonymizesMultipleIps() {
        PlayerPrivacyService pp = new PlayerPrivacyService();
        String result = pp.anonymizeIp("Connections: 10.0.0.1 and 172.16.5.42");
        assertTrue(result.contains("10.0.xxx.xxx"), "第一个IP应被脱敏");
        assertTrue(result.contains("172.16.xxx.xxx"), "第二个IP应被脱敏");
    }

    @Test
    void privacyRegionLevelRoundsCoordinates() {
        PlayerPrivacyService pp = new PlayerPrivacyService();
        pp.setCoordinateAnonymizationLevel(
                PlayerPrivacyService.CoordinateAnonymizationLevel.REGION);
        String result = pp.anonymizeCoordinates(128.5, 64.1, -256.8);
        // 128.5 -> 130, 64.1 -> 60, -256.8 -> -260
        assertTrue(result.contains("130"), "X坐标应四舍五入到10");
        assertTrue(result.contains("60"), "Y坐标应四舍五入到10");
        assertTrue(result.contains("-260"), "Z坐标应四舍五入到10");
    }

    @Test
    void privacyHiddenLevelHidesCoordinates() {
        PlayerPrivacyService pp = new PlayerPrivacyService();
        pp.setCoordinateAnonymizationLevel(
                PlayerPrivacyService.CoordinateAnonymizationLevel.HIDDEN);
        String result = pp.anonymizeCoordinates(100, 64, 200);
        assertEquals("[***, ***, ***]", result, "HIDDEN级别应完全隐藏坐标");
    }

    @Test
    void privacyDataExportRequest() {
        PlayerPrivacyService pp = new PlayerPrivacyService();
        String requestId = pp.requestDataExport("Player1", "admin");
        assertNotNull(requestId, "导出请求应返回有效ID");

        List<PlayerPrivacyService.DataExportRequest> requests = pp.getPendingRequests();
        assertEquals(1, requests.size());
        assertEquals("Player1", requests.get(0).getPlayerName());
        assertEquals("EXPORT", requests.get(0).getType());
    }

    @Test
    void privacyDataDeletionRequest() {
        PlayerPrivacyService pp = new PlayerPrivacyService();
        String requestId = pp.requestDataDeletion("Player2", "player");
        assertNotNull(requestId, "删除请求应返回有效ID");

        Map<String, Object> status = pp.getStatus();
        assertTrue(((Number) status.get("pendingDataRequests")).intValue() >= 1);
    }

    @Test
    void privacyAuditRecordsAccess() {
        PlayerPrivacyService pp = new PlayerPrivacyService();
        pp.auditAccess("dashboard-api", "Player3", "IP_ADDRESS");
        pp.auditAccess("dashboard-api", "Player3", "COORDINATES");

        List<PlayerPrivacyService.AuditEntry> audits = pp.getAuditForPlayer("Player3");
        assertEquals(2, audits.size(), "应记录2条审计日志");
        assertEquals("IP_ADDRESS", audits.get(0).getDataType());
        assertEquals("COORDINATES", audits.get(1).getDataType());
    }

    @Test
    void privacyPrefersNonNullAudit() {
        PlayerPrivacyService pp = new PlayerPrivacyService();
        List<PlayerPrivacyService.AuditEntry> audits = pp.getAuditForPlayer("NonExistent");
        assertNotNull(audits, "不存在的玩家应返回空列表而非null");
        assertTrue(audits.isEmpty());
    }

    @Test
    void privacyStatusHasExpectedFields() {
        PlayerPrivacyService pp = new PlayerPrivacyService();
        pp.anonymizeIp("Player from 1.2.3.4");

        Map<String, Object> status = pp.getStatus();
        assertNotNull(status.get("anonymizedEntries"));
        assertNotNull(status.get("pendingDataRequests"));
        assertNotNull(status.get("privacyViolations"));
        assertNotNull(status.get("coordinateLevel"));
        assertNotNull(status.get("retentionDays"));
    }
}
