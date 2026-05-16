package com.aluer.security;

import org.junit.jupiter.api.Test;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;

/**
 * V4.0 服务器保护模块测试类
 * 覆盖6个新增安全模块：PacketFloodProtection, AntiSignExploit, AntiBookBan,
 * AntiResourcePackExploit, AntiTabCompleteCrash, AntiOfflineModeSpoof
 */
class V40ServerProtectionTest {

    // ==================== PacketFloodProtectionService ====================

    @Test
    void packetFloodAllowsNormalTraffic() {
        PacketFloodProtectionService svc = new PacketFloodProtectionService();
        // 正常情况下几个数据包不影响
        assertTrue(svc.check("Player1", "ChatMessage", null).isClean());
        assertTrue(svc.check("Player1", "CustomPayload", "minecraft:register").isClean());
    }

    @Test
    void packetFloodDetectsChatMessageFlood() {
        PacketFloodProtectionService svc = new PacketFloodProtectionService();
        // 模拟聊天洪水：5秒内发送远超20/s的数据包
        for (int i = 0; i < 150; i++) {
            svc.check("Flooder1", "ChatMessage", null);
        }
        PacketFloodProtectionService.PacketFloodResult r = svc.check("Flooder1", "ChatMessage", null);
        assertTrue(r.isBlocked());
        assertTrue(r.getReasons().stream().anyMatch(s -> s.contains("ChatMessage")));
    }

    @Test
    void packetFloodDetectsBrandChannelFlood() {
        PacketFloodProtectionService svc = new PacketFloodProtectionService();
        // 品牌包在60秒内超过3次即为异常
        for (int i = 0; i < 5; i++) {
            svc.check("SuspiciousPlayer", "PluginMessage", "minecraft:brand");
        }
        PacketFloodProtectionService.PacketFloodResult r = svc.check(
                "SuspiciousPlayer", "PluginMessage", "minecraft:brand");
        assertTrue(r.isBlocked());
    }

    @Test
    void packetFloodIncrementalPenaltyIncreases() {
        PacketFloodProtectionService svc = new PacketFloodProtectionService();
        // CustomPayload阈值=50/s即250/5s窗口，需发送>250个才触发
        for (int i = 0; i < 300; i++) {
            svc.check("Attacker1", "CustomPayload", "bad:channel");
        }
        PacketFloodProtectionService.PacketFloodResult r1 = svc.check("Attacker1", "CustomPayload", "bad:channel");
        assertTrue(r1.isBlocked());
        // 递增惩罚应该有起步延迟（首次违规100ms）
        assertTrue(r1.getPenaltyMs() >= 100);
    }

    @Test
    void packetFloodStatusHasCounters() {
        PacketFloodProtectionService svc = new PacketFloodProtectionService();
        svc.check("P1", "ChatMessage", null);
        svc.check("P2", "CustomPayload", "test:chan");
        Map<String, Object> s = svc.getStatus();
        assertNotNull(s.get("totalPackets"));
        assertNotNull(s.get("blockedCount"));
        assertNotNull(s.get("packetTypeStats"));
        assertTrue(((Number) s.get("totalPackets")).longValue() >= 2);
    }

    // ==================== AntiSignExploitService ====================

    @Test
    void antiSignExploitAllowsNormalSign() {
        AntiSignExploitService svc = new AntiSignExploitService();
        String[] lines = {"Hello", "World", "", ""};
        AntiSignExploitService.SignCheckResult r = svc.check("Player1", "world", 0, 64, 0, lines, 0);
        assertTrue(r.isClean());
    }

    @Test
    void antiSignExploitDetectsDeepNBTNesting() {
        AntiSignExploitService svc = new AntiSignExploitService();
        String[] lines = {"test", "", "", ""};
        // NBT深度超过8层
        AntiSignExploitService.SignCheckResult r = svc.check("Hacker", "world", 0, 64, 0, lines, 15);
        assertTrue(r.isBlocked());
        assertTrue(r.getReasons().stream().anyMatch(s -> s.contains("NBT_DEEP_NESTING")));
    }

    @Test
    void antiSignExploitDetectsOversizedText() {
        AntiSignExploitService svc = new AntiSignExploitService();
        // 超过10000字符的单行文本
        StringBuilder sb = new StringBuilder();
        sb.append("{\"text\":\"");
        for (int i = 0; i < 11000; i++) sb.append("A");
        sb.append("\"}");
        String[] lines = {sb.toString(), "", "", ""};
        AntiSignExploitService.SignCheckResult r = svc.check("Hacker", "world", 0, 64, 0, lines, 0);
        assertTrue(r.isBlocked());
    }

    @Test
    void antiSignExploitDetectsClickCommandInjection() {
        AntiSignExploitService svc = new AntiSignExploitService();
        String[] lines = {"{\"text\":\"Click me\",\"clickEvent\":{\"action\":\"run_command\",\"value\":\"/op Hacker\"}}",
                "", "", ""};
        AntiSignExploitService.SignCheckResult r = svc.check("Hacker", "world", 0, 64, 0, lines, 0);
        assertTrue(r.isBlocked());
        assertTrue(r.getReasons().stream().anyMatch(s -> s.contains("CLICK_COMMAND")));
    }

    @Test
    void antiSignExploitDetectsDangerousPlaceholder() {
        AntiSignExploitService svc = new AntiSignExploitService();
        String[] lines = {"{\"text\":\"${system:exec:rm -rf /}\"}", "", "", ""};
        AntiSignExploitService.SignCheckResult r = svc.check("Hacker", "world", 0, 64, 0, lines, 0);
        assertTrue(r.isBlocked());
    }

    @Test
    void antiSignExploitStatusHasCounters() {
        AntiSignExploitService svc = new AntiSignExploitService();
        svc.check("P1", "world", 0, 64, 0, new String[]{"Hello"}, 0);
        Map<String, Object> s = svc.getStatus();
        assertNotNull(s.get("totalSignsChecked"));
        assertNotNull(s.get("exploitBlocked"));
        assertNotNull(s.get("lastBlockedDetails"));
    }

    // ==================== AntiBookBanService ====================

    @Test
    void antiBookBanAllowsNormalBook() {
        AntiBookBanService svc = new AntiBookBanService();
        List<String> pages = List.of("{\"text\":\"Hello World\"}", "{\"text\":\"Page 2\"}");
        AntiBookBanService.BookCheckResult r = svc.check("Player1", "My Book", pages, "Player1", 0, 500);
        assertTrue(r.isClean());
    }

    @Test
    void antiBookBanDetectsExcessivePages() {
        AntiBookBanService svc = new AntiBookBanService();
        // 超过100页
        List<String> pages = new ArrayList<>();
        for (int i = 0; i < 150; i++) {
            pages.add("{\"text\":\"Page " + i + "\"}");
        }
        AntiBookBanService.BookCheckResult r = svc.check("Hacker", "Bad Book", pages, "Hacker", 0, 5000);
        assertTrue(r.isBlocked());
        assertTrue(r.getReasons().stream().anyMatch(s -> s.contains("EXCESSIVE_PAGES")));
    }

    @Test
    void antiBookBanDetectsOversizedPage() {
        AntiBookBanService svc = new AntiBookBanService();
        // 单页超过32767字符
        StringBuilder sb = new StringBuilder("{\"text\":\"");
        for (int i = 0; i < 33000; i++) sb.append("B");
        sb.append("\"}");
        List<String> pages = List.of(sb.toString());
        AntiBookBanService.BookCheckResult r = svc.check("Hacker", "Overflow Book", pages, "Hacker", 0, 50000);
        assertTrue(r.isBlocked());
        assertTrue(r.getReasons().stream().anyMatch(s -> s.contains("OVERSIZED")));
    }

    @Test
    void antiBookBanDetectsDangerousTranslate() {
        AntiBookBanService svc = new AntiBookBanService();
        // translate组件引用危险翻译键
        List<String> pages = List.of("{\"translate\":\"translation.test.none\",\"color\":\"red\"}");
        AntiBookBanService.BookCheckResult r = svc.check("Hacker", "Translate Exploit", pages, "Hacker", 0, 200);
        assertTrue(r.isFlagged() || r.isBlocked());
    }

    @Test
    void antiBookBanDetectsDeepJsonNesting() {
        AntiBookBanService svc = new AntiBookBanService();
        // 构造深度超过15层的嵌套JSON
        StringBuilder sb = new StringBuilder("{\"text\":\"x\"");
        for (int i = 0; i < 20; i++) {
            sb = new StringBuilder("{\"extra\":[" + sb + "]}");
        }
        List<String> pages = List.of(sb.toString());
        AntiBookBanService.BookCheckResult r = svc.check("Hacker", "Deep Nest Book", pages, "Hacker", 0, 500);
        assertTrue(r.isFlagged() || r.isBlocked());
    }

    @Test
    void antiBookBanStatusHasCounters() {
        AntiBookBanService svc = new AntiBookBanService();
        svc.check("P1", "Test", List.of("{\"text\":\"Hello\"}"), "P1", 0, 100);
        Map<String, Object> s = svc.getStatus();
        assertNotNull(s.get("totalBooksChecked"));
        assertNotNull(s.get("bannedBooks"));
    }

    // ==================== AntiResourcePackExploitService ====================

    @Test
    void antiResourcePackAllowsNormalPack() {
        AntiResourcePackExploitService svc = new AntiResourcePackExploitService();
        // SHA-1必须是40位十六进制字符，否则格式校验会拒绝
        AntiResourcePackExploitService.PackCheckResult r = svc.check(
                "https://example.com/resourcepack.zip",
                "a1b2c3d4e5f6789012345678901234567890abcd",
                "Admin", 9);
        assertTrue(r.isClean());
    }

    @Test
    void antiResourcePackDetectsFileScheme() {
        AntiResourcePackExploitService svc = new AntiResourcePackExploitService();
        AntiResourcePackExploitService.PackCheckResult r = svc.check(
                "file:///etc/passwd",
                "a1b2c3d4e5f6789012345678901234567890abc",
                "Hacker", 9);
        assertTrue(r.isBlocked());
        assertTrue(r.getReasons().stream().anyMatch(s -> s.contains("SCHEME") || s.contains("BLOCKED")));
    }

    @Test
    void antiResourcePackDetectsInternalNetwork() {
        AntiResourcePackExploitService svc = new AntiResourcePackExploitService();
        AntiResourcePackExploitService.PackCheckResult r = svc.check(
                "http://192.168.1.100/malware.zip",
                "a1b2c3d4e5f6789012345678901234567890abc",
                "Hacker", 9);
        assertTrue(r.isBlocked());
        assertTrue(r.getReasons().stream().anyMatch(s -> s.contains("PRIVATE") || s.contains("SSRF")));
    }

    @Test
    void antiResourcePackDetectsBlacklistedSha1() {
        AntiResourcePackExploitService svc = new AntiResourcePackExploitService();
        String maliciousSha1 = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef";
        svc.addToSha1Blacklist(maliciousSha1);
        AntiResourcePackExploitService.PackCheckResult r = svc.check(
                "https://cdn.example.com/pack.zip", maliciousSha1, "Admin", 9);
        assertTrue(r.isBlocked());
    }

    @Test
    void antiResourcePackDetectsDangerousExtension() {
        AntiResourcePackExploitService svc = new AntiResourcePackExploitService();
        AntiResourcePackExploitService.PackCheckResult r = svc.check(
                "https://evil.com/trojan.jar",
                "a1b2c3d4e5f6789012345678901234567890abc",
                "Hacker", 9);
        assertTrue(r.isBlocked());
        assertTrue(r.getReasons().stream().anyMatch(s -> s.contains("DANGEROUS") || s.contains("EXTENSION")));
    }

    @Test
    void antiResourcePackStatusHasCounters() {
        AntiResourcePackExploitService svc = new AntiResourcePackExploitService();
        svc.check("https://safe.com/pack.zip", "a1b2c3d4e5f6789012345678901234567890abc", "Admin", 9);
        Map<String, Object> s = svc.getStatus();
        assertNotNull(s.get("totalPacksChecked"));
        assertNotNull(s.get("blockedPacks"));
        assertNotNull(s.get("urlBlacklistSize"));
    }

    // ==================== AntiTabCompleteCrashService ====================

    @Test
    void antiTabCompleteAllowsNormalRequest() {
        AntiTabCompleteCrashService svc = new AntiTabCompleteCrashService();
        AntiTabCompleteCrashService.TabCheckResult r = svc.check("Player1", "gamemode c", 8, 1);
        assertTrue(r.isClean());
    }

    @Test
    void antiTabCompleteDetectsOversizedRequest() {
        AntiTabCompleteCrashService svc = new AntiTabCompleteCrashService();
        // 构造超过8192字符的请求
        StringBuilder sb = new StringBuilder("execute as @e[tag=");
        for (int i = 0; i < 10000; i++) sb.append("a");
        AntiTabCompleteCrashService.TabCheckResult r = svc.check("Hacker", sb.toString(), 0, 1);
        assertTrue(r.isBlocked());
        assertTrue(r.getReasons().stream().anyMatch(s -> s.contains("OVERSIZED")));
    }

    @Test
    void antiTabCompleteDetectsDeepNesting() {
        AntiTabCompleteCrashService svc = new AntiTabCompleteCrashService();
        // 构造深度超过50层的嵌套括号
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 60; i++) sb.append("(\"");
        sb.append("test");
        for (int i = 0; i < 60; i++) sb.append("\")");
        AntiTabCompleteCrashService.TabCheckResult r = svc.check("Hacker", sb.toString(), 0, 1);
        assertTrue(r.isBlocked());
        assertTrue(r.getReasons().stream().anyMatch(s -> s.contains("NESTING")));
    }

    @Test
    void antiTabCompleteDetectsTabFlood() {
        AntiTabCompleteCrashService svc = new AntiTabCompleteCrashService();
        // 高频补全请求洪水
        for (int i = 0; i < 150; i++) {
            svc.check("Flooder", "command " + i, 8, i);
        }
        AntiTabCompleteCrashService.TabCheckResult r = svc.check("Flooder", "command x", 8, 999);
        assertTrue(r.isBlocked() || r.isSuspicious());
    }

    @Test
    void antiTabCompleteDetectsInvalidUtf8() {
        AntiTabCompleteCrashService svc = new AntiTabCompleteCrashService();
        // 包含无效UTF-8字节序列的请求
        String badText = "test bad chars";
        // 注意：Java不会阻止 ，但我们应该检测它
        AntiTabCompleteCrashService.TabCheckResult r = svc.check("Hacker", badText, 0, 1);
        // null字符应被检测到
        assertTrue(r.isBlocked() || r.isSuspicious());
    }

    @Test
    void antiTabCompleteStatusHasCounters() {
        AntiTabCompleteCrashService svc = new AntiTabCompleteCrashService();
        svc.check("P1", "help", 4, 1);
        Map<String, Object> s = svc.getStatus();
        assertNotNull(s.get("totalTabRequests"));
        assertNotNull(s.get("crashPrevented"));
    }

    // ==================== AntiOfflineModeSpoofService ====================

    @Test
    void antiOfflineModeAllowsValidLogin() {
        AntiOfflineModeSpoofService svc = new AntiOfflineModeSpoofService();
        AntiOfflineModeSpoofService.SpoofCheckResult r = svc.check(
                "550e8400-e29b-41d4-a716-446655440000",
                "Player1", "192.168.1.1", "session-001");
        assertTrue(r.isClean());
    }

    @Test
    void antiOfflineModeDetectsInvalidUUIDFormat() {
        AntiOfflineModeSpoofService svc = new AntiOfflineModeSpoofService();
        // 完全无效的UUID
        AntiOfflineModeSpoofService.SpoofCheckResult r = svc.check(
                "not-a-valid-uuid-at-all",
                "Hacker", "10.0.0.1", "session-001");
        assertTrue(r.isBlocked());
    }

    @Test
    void antiOfflineModeDetectsRapidUuidSwitch() {
        AntiOfflineModeSpoofService svc = new AntiOfflineModeSpoofService();
        // 同一IP在短时间内使用多个不同UUID
        svc.check("550e8400-e29b-41d4-a716-446655440001", "Alt1", "10.0.0.50", "s1");
        svc.check("550e8400-e29b-41d4-a716-446655440002", "Alt2", "10.0.0.50", "s2");
        svc.check("550e8400-e29b-41d4-a716-446655440003", "Alt3", "10.0.0.50", "s3");
        AntiOfflineModeSpoofService.SpoofCheckResult r = svc.check(
                "550e8400-e29b-41d4-a716-446655440004", "Alt4", "10.0.0.50", "s4");
        assertTrue(r.isBlocked());
        assertTrue(r.getReasons().stream().anyMatch(s -> s.contains("RAPID_UUID_SWITCH")));
    }

    @Test
    void antiOfflineModeDetectsAdminNameSpoof() {
        AntiOfflineModeSpoofService svc = new AntiOfflineModeSpoofService();
        // 用户名是admin但UUID格式异常
        AntiOfflineModeSpoofService.SpoofCheckResult r = svc.check(
                "invalid-uuid-x",
                "Admin", "10.0.0.1", "session-001");
        assertTrue(r.isBlocked());
    }

    @Test
    void antiOfflineModeDetectsProtectedUuid() {
        AntiOfflineModeSpoofService svc = new AntiOfflineModeSpoofService();
        String protectedUuid = "aaaaaaaa-aaaa-4aaa-aaaa-aaaaaaaaaaaa";
        svc.addProtectedUuid(protectedUuid);
        AntiOfflineModeSpoofService.SpoofCheckResult r = svc.check(
                protectedUuid, "Imposter", "192.168.1.1", "session-001");
        assertTrue(r.isBlocked());
        assertTrue(r.getReasons().stream().anyMatch(s -> s.contains("PROTECTED")));
    }

    @Test
    void antiOfflineModeNormalPlayerNotAffected() {
        AntiOfflineModeSpoofService svc = new AntiOfflineModeSpoofService();
        // 多个不同IP的正常UUID加入不应被阻止
        assertTrue(svc.check("550e8400-e29b-41d4-a716-446655440010", "Alice", "1.1.1.1", "s1").isClean());
        assertTrue(svc.check("550e8400-e29b-41d4-a716-446655440020", "Bob", "2.2.2.2", "s2").isClean());
        assertTrue(svc.check("550e8400-e29b-41d4-a716-446655440030", "Carol", "3.3.3.3", "s3").isClean());
    }

    @Test
    void antiOfflineModeStatusHasCounters() {
        AntiOfflineModeSpoofService svc = new AntiOfflineModeSpoofService();
        svc.check("550e8400-e29b-41d4-a716-446655440100", "TestPlayer", "1.1.1.1", "ss");
        Map<String, Object> s = svc.getStatus();
        assertNotNull(s.get("totalJoins"));
        assertNotNull(s.get("spoofBlocked"));
        assertNotNull(s.get("ipUuidMap"));
    }
}
