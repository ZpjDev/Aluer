package com.aluer.security;

import com.aluer.anticheat.player.AntiAltAccountService;
import com.aluer.anticheat.player.AntiNameSpoofService;
import com.aluer.anticheat.player.AntiVPNProxyService;
import com.aluer.defense.BackdoorPluginScannerService;
import com.aluer.defense.ConfigTamperDetectionService;
import com.aluer.defense.OPPrivilegeMonitorService;
import org.junit.jupiter.api.Test;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;

/**
 * V4.0 访问控制模块测试类
 * 覆盖 OPPrivilegeMonitor, ConfigTamperDetection, BackdoorPluginScanner,
 * AntiVPNProxy, AntiAltAccount, AntiNameSpoof 六个安全服务
 */
class V40AccessControlTest {

    // ==================== OPPrivilegeMonitorService Tests ====================

    @Test
    void opMonitorShouldDetectUnauthorizedGrantViaRcon() {
        OPPrivilegeMonitorService service = new OPPrivilegeMonitorService();
        // OP granted via RCON (non-console source) should be flagged suspicious
        OPPrivilegeMonitorService.OPMonitorResult result = service.recordOPChange(
                "NewAdmin", 4, "grant", "RCON", "UnknownPlayer");
        assertTrue(result.isSuspicious());
        assertTrue(result.getReasons().stream().anyMatch(r -> r.contains("UNAUTHORIZED_OP_GRANT")));
    }

    @Test
    void opMonitorShouldAllowConsoleGrant() {
        OPPrivilegeMonitorService service = new OPPrivilegeMonitorService();
        // OP granted via CONSOLE should be considered clean
        OPPrivilegeMonitorService.OPMonitorResult result = service.recordOPChange(
                "LegitAdmin", 4, "grant", "CONSOLE", "Server");
        assertTrue(result.isClean());
    }

    @Test
    void opMonitorShouldDetectOpLevelJump() {
        OPPrivilegeMonitorService service = new OPPrivilegeMonitorService();
        // First grant Level 1 via console (clean)
        service.recordOPChange("Player1", 1, "grant", "CONSOLE", "Server");
        // Then jump to Level 4 via console — should be suspicious
        OPPrivilegeMonitorService.OPMonitorResult result = service.recordOPChange(
                "Player1", 4, "grant", "CONSOLE", "Server");
        assertTrue(result.isSuspicious());
        assertTrue(result.getReasons().stream().anyMatch(r -> r.contains("OP_LEVEL_JUMP")));
    }

    @Test
    void opMonitorShouldDetectCommandStorm() {
        OPPrivilegeMonitorService service = new OPPrivilegeMonitorService();
        // Simulate 6 sensitive commands from same player within 1 minute
        for (int i = 0; i < 6; i++) {
            OPPrivilegeMonitorService.OPMonitorResult result = service.recordSensitiveCommand(
                    "SuspiciousAdmin", "ban Player" + i, "IN_GAME");
            if (i >= 5) {
                assertTrue(result.isSuspicious());
                assertTrue(result.getReasons().stream().anyMatch(r -> r.contains("COMMAND_STORM")));
            }
        }
    }

    @Test
    void opMonitorShouldIdentifySensitiveCommands() {
        OPPrivilegeMonitorService service = new OPPrivilegeMonitorService();
        assertTrue(service.isSensitiveCommand("ban BadPlayer"));
        assertTrue(service.isSensitiveCommand("/stop"));
        assertTrue(service.isSensitiveCommand("/reload"));
        assertTrue(service.isSensitiveCommand("/whitelist add Someone"));
        assertFalse(service.isSensitiveCommand("list"));
        assertFalse(service.isSensitiveCommand("say hello"));
    }

    @Test
    void opMonitorGetStatusReturnsCorrectStructure() {
        OPPrivilegeMonitorService service = new OPPrivilegeMonitorService();
        service.recordOPChange("Admin1", 4, "grant", "CONSOLE", "Server");
        service.recordOPChange("Admin2", 2, "grant", "CONSOLE", "Server");

        var status = service.getStatus();
        assertNotNull(status);
        assertTrue(status.containsKey("totalOps"));
        assertTrue(status.containsKey("opChanges"));
        assertTrue(status.containsKey("sensitiveCommandLog"));
        assertEquals(2L, status.get("totalOps"));
    }

    // ==================== ConfigTamperDetectionService Tests ====================

    @Test
    void configTamperShouldDetectHashMismatch() {
        ConfigTamperDetectionService service = new ConfigTamperDetectionService();
        byte[] original = "online-mode=true\nmax-players=20\n".getBytes();
        byte[] tampered = "online-mode=false\nmax-players=20\n".getBytes();

        service.registerBaseline("server.properties", original);
        ConfigTamperDetectionService.TamperDetectionResult result = service.checkFileIntegrity(
                "server.properties", tampered, "system");

        assertTrue(result.isTampered());
        assertTrue(result.getReasons().stream().anyMatch(r -> r.contains("HASH_MISMATCH")));
    }

    @Test
    void configTamperShouldDetectOnlineModeDisabled() {
        ConfigTamperDetectionService service = new ConfigTamperDetectionService();
        byte[] props = "online-mode=false\nenable-rcon=true\nrcon.password=123\n".getBytes();

        ConfigTamperDetectionService.TamperDetectionResult result = service.checkFileIntegrity(
                "server.properties", props, "system");

        assertTrue(result.isTampered());
        assertTrue(result.getReasons().stream().anyMatch(r -> r.contains("ONLINE_MODE_DISABLED")));
    }

    @Test
    void configTamperShouldDetectWeakRconPassword() {
        ConfigTamperDetectionService service = new ConfigTamperDetectionService();
        byte[] props = "online-mode=true\nenable-rcon=true\nrcon.password=abc\n".getBytes();

        ConfigTamperDetectionService.TamperDetectionResult result = service.checkFileIntegrity(
                "server.properties", props, "system");

        assertTrue(result.isTampered());
        assertTrue(result.getReasons().stream().anyMatch(r -> r.contains("WEAK_RCON_PASSWORD")));
    }

    @Test
    void configTamperShouldDetectSecureProfileDisabled() {
        ConfigTamperDetectionService service = new ConfigTamperDetectionService();
        byte[] props = "online-mode=true\nenforce-secure-profile=false\n".getBytes();

        ConfigTamperDetectionService.TamperDetectionResult result = service.checkFileIntegrity(
                "server.properties", props, "system");

        assertTrue(result.isTampered());
        assertTrue(result.getReasons().stream().anyMatch(r -> r.contains("SECURE_PROFILE_DISABLED")));
    }

    @Test
    void configTamperShouldAllowCleanConfig() {
        ConfigTamperDetectionService service = new ConfigTamperDetectionService();
        byte[] props = "online-mode=true\nmax-players=20\nenforce-secure-profile=true\n".getBytes();

        service.registerBaseline("server.properties", props);
        ConfigTamperDetectionService.TamperDetectionResult result = service.checkFileIntegrity(
                "server.properties", props, "system");

        assertTrue(result.isClean());
    }

    @Test
    void configTamperShouldDetectUnauthorizedOpInOpsJson() {
        ConfigTamperDetectionService service = new ConfigTamperDetectionService();
        service.setLegitimateOps(Set.of("Owner", "Admin1"));

        byte[] opsJson = ("[{\"uuid\":\"aaa-bbb-ccc\",\"name\":\"UnknownHacker\",\"level\":4}]").getBytes();
        ConfigTamperDetectionService.TamperDetectionResult result = service.checkFileIntegrity(
                "ops.json", opsJson, "system");

        assertTrue(result.isTampered());
        assertTrue(result.getReasons().stream().anyMatch(r -> r.contains("UNAUTHORIZED_OP")));
    }

    // ==================== BackdoorPluginScannerService Tests ====================

    @Test
    void backdoorScannerShouldDetectKnownMaliciousPlugin() {
        BackdoorPluginScannerService service = new BackdoorPluginScannerService();
        BackdoorPluginScannerService.PluginScanResult result = service.scanPlugin(
                "ForceOP", "ForceOP.jar", true, "com.force.op.Main",
                List.of("com.force.op.Main"), List.of());

        assertTrue(result.isMalicious());
        assertEquals(BackdoorPluginScannerService.RiskLevel.MALICIOUS, result.getRiskLevel());
    }

    @Test
    void backdoorScannerShouldDetectMissingPluginYml() {
        BackdoorPluginScannerService service = new BackdoorPluginScannerService();
        BackdoorPluginScannerService.PluginScanResult result = service.scanPlugin(
                "MysteryPlugin", "MysteryPlugin.jar", false, "com.test.Main",
                List.of("com.test.Main"), List.of());

        assertTrue(result.isSuspicious());
        assertTrue(result.getReasons().stream().anyMatch(r -> r.contains("MISSING_PLUGIN_YML")));
    }

    @Test
    void backdoorScannerShouldDetectRCECapability() {
        BackdoorPluginScannerService service = new BackdoorPluginScannerService();
        BackdoorPluginScannerService.PluginScanResult result = service.scanPlugin(
                "RemoteTool", "RemoteTool.jar", true, "com.remote.Main",
                List.of("com.remote.Main", "Runtime.exec.Payload", "com.remote.Cleanup"),
                List.of());

        assertTrue(result.isSuspicious());
        assertTrue(result.getReasons().stream().anyMatch(r -> r.contains("RCE_CAPABILITY")));
    }

    @Test
    void backdoorScannerShouldDetectSuspiciousConfigKeys() {
        BackdoorPluginScannerService service = new BackdoorPluginScannerService();
        BackdoorPluginScannerService.PluginScanResult result = service.scanPlugin(
                "NormalPlugin", "NormalPlugin.jar", true, "com.normal.Main",
                List.of("com.normal.Main"),
                List.of("database-url", "backdoor-enabled", "webhook-url"));

        assertTrue(result.isSuspicious());
        assertTrue(result.getReasons().stream().anyMatch(r -> r.contains("SUSPICIOUS_CONFIG_KEY")));
    }

    @Test
    void backdoorScannerShouldAllowSafePlugin() {
        BackdoorPluginScannerService service = new BackdoorPluginScannerService();
        BackdoorPluginScannerService.PluginScanResult result = service.scanPlugin(
                "WorldEdit", "WorldEdit.jar", true, "com.sk89q.worldedit.bukkit.WorldEditPlugin",
                List.of("com.sk89q.worldedit.bukkit.WorldEditPlugin"), List.of("max-blocks", "nav-wand"));

        assertTrue(result.isSafe());
        assertEquals(BackdoorPluginScannerService.RiskLevel.SAFE, result.getRiskLevel());
    }

    @Test
    void backdoorScannerQuickScanShouldDetectMalicious() {
        BackdoorPluginScannerService service = new BackdoorPluginScannerService();
        BackdoorPluginScannerService.PluginScanResult result = service.quickScan("OPMe");

        assertTrue(result.isMalicious());
    }

    // ==================== AntiVPNProxyService Tests ====================

    @Test
    void antiVpnShouldDetectDigitalOceanASN() {
        AntiVPNProxyService service = new AntiVPNProxyService();
        // AS14061 = DigitalOcean
        AntiVPNProxyService.VPNCheckResult result = service.checkIP(
                "159.65.100.50", "14061", "DigitalOcean, LLC", "Player1");

        assertTrue(result.isHosting());
        assertFalse(result.isClean());
    }

    @Test
    void antiVpnShouldDetectDatacenterIPRange() {
        AntiVPNProxyService service = new AntiVPNProxyService();
        // Vultr IP prefix
        AntiVPNProxyService.VPNCheckResult result = service.checkIP(
                "45.76.100.200", null, null, "Player2");

        assertTrue(result.isHosting());
    }

    @Test
    void antiVpnShouldAllowTrustedIP() {
        AntiVPNProxyService service = new AntiVPNProxyService();
        // Add to trusted list first
        service.addTrustedIP("159.65.100.50");

        AntiVPNProxyService.VPNCheckResult result = service.checkIP(
                "159.65.100.50", "14061", "DigitalOcean, LLC", "Player3");

        assertTrue(result.isClean());
    }

    @Test
    void antiVpnShouldDetectHostingISP() {
        AntiVPNProxyService service = new AntiVPNProxyService();
        AntiVPNProxyService.VPNCheckResult result = service.checkIP(
                "198.51.100.50", null, "SomeHosting Cloud LTD", "Player4");

        assertTrue(result.isHosting());
    }

    @Test
    void antiVpnShouldAllowResidentialIP() {
        AntiVPNProxyService service = new AntiVPNProxyService();
        AntiVPNProxyService.VPNCheckResult result = service.checkIP(
                "203.0.113.1", "12345", "Comcast Cable", "LegitPlayer");

        assertTrue(result.isClean());
    }

    // ==================== AntiAltAccountService Tests ====================

    @Test
    void antiAltShouldDetectBanEvasion() {
        AntiAltAccountService service = new AntiAltAccountService();
        // Ban this IP first
        service.recordBannedIP("10.0.0.100", "Griefing");
        // New player joins from the same IP immediately after
        AntiAltAccountService.AltAccountResult result = service.onPlayerLogin(
                "NewAltPlayer", "uuid-new", "10.0.0.100");

        assertTrue(result.isAltDetected());
        assertTrue(result.getReasons().stream().anyMatch(r -> r.contains("BAN_EVASION")));
    }

    @Test
    void antiAltShouldDetectRapidAccountSwitch() {
        AntiAltAccountService service = new AntiAltAccountService();
        // Same IP, multiple accounts within 5 minutes
        service.onPlayerLogin("Alt1", "uuid-1", "10.0.0.200");
        service.onPlayerLogin("Alt2", "uuid-2", "10.0.0.200");
        AntiAltAccountService.AltAccountResult result = service.onPlayerLogin(
                "Alt3", "uuid-3", "10.0.0.200");

        assertTrue(result.isAltDetected());
        assertTrue(result.getReasons().stream().anyMatch(r -> r.contains("RAPID_ACCOUNT_SWITCH")));
    }

    @Test
    void antiAltShouldAllowSingleAccountLogin() {
        AntiAltAccountService service = new AntiAltAccountService();
        AntiAltAccountService.AltAccountResult result = service.onPlayerLogin(
                "LegitPlayer", "uuid-real", "192.168.1.1");

        assertTrue(result.isClean());
    }

    @Test
    void antiAltShouldTrackTroublemakerIPs() {
        AntiAltAccountService service = new AntiAltAccountService();
        // First, login with account and create IP association
        service.onPlayerLogin("Griefer1", "uuid-g1", "10.0.0.50");
        // Ban the IP
        service.recordBannedIP("10.0.0.50", "Griefing");
        // Mark as troublemaker
        service.markAsTroublemaker("Griefer1");

        // New account from same IP should be detected
        AntiAltAccountService.AltAccountResult result = service.onPlayerLogin(
                "GrieferAlt", "uuid-g2", "10.0.0.50");

        assertTrue(result.isAltDetected());
        assertTrue(result.getReasons().stream().anyMatch(r -> r.contains("TROUBLEMAKER_IP")));
    }

    @Test
    void antiAltShouldReturnAssociatedAccounts() {
        AntiAltAccountService service = new AntiAltAccountService();
        service.onPlayerLogin("AccA", "uuid-a", "10.0.0.77");
        service.onPlayerLogin("AccB", "uuid-b", "10.0.0.77");

        Set<String> accounts = service.getAccountsForIP("10.0.0.77");
        assertTrue(accounts.contains("AccA"));
        assertTrue(accounts.contains("AccB"));
    }

    // ==================== AntiNameSpoofService Tests ====================

    @Test
    void antiNameSpoofShouldDetectUnicodeHomoglyph() {
        AntiNameSpoofService service = new AntiNameSpoofService();
        service.addProtectedName("Admin");

        // Use Cyrillic 'a' (U+0430) instead of Latin 'a'
        String spoofedName = "Admin";  // Note: uses Cyrillic 'a' when built with proper Unicode
        // For the test, we check a player name that contains Unicode normalization differences
        AntiNameSpoofService.NameSpoofResult result = service.checkPlayerName(
                "Admın", "10.0.0.1");  // Uses dotless i (U+0131) instead of normal i

        assertTrue(result.isSpoofed());
    }

    @Test
    void antiNameSpoofShouldDetectInvisibleCharacters() {
        AntiNameSpoofService service = new AntiNameSpoofService();
        // Insert zero-width space U+200B into the name
        String spoofedName = "Admin​test";
        AntiNameSpoofService.NameSpoofResult result = service.checkPlayerName(
                spoofedName, "10.0.0.2");

        assertTrue(result.isSpoofed());
        assertTrue(result.getReasons().stream().anyMatch(r -> r.contains("INVISIBLE_CHARS")));
    }

    @Test
    void antiNameSpoofShouldAllowNormalPlayerName() {
        AntiNameSpoofService service = new AntiNameSpoofService();
        service.addProtectedName("Admin");

        AntiNameSpoofService.NameSpoofResult result = service.checkPlayerName(
                "Player123", "10.0.0.3");

        assertTrue(result.isClean());
    }

    @Test
    void antiNameSpoofShouldDetectLevenshteinSimilarity() {
        AntiNameSpoofService service = new AntiNameSpoofService();
        service.addProtectedName("Administrator");

        // "Administrat0r" (using zero instead of 'o') is very similar
        AntiNameSpoofService.NameSpoofResult result = service.checkPlayerName(
                "Administrat0r", "10.0.0.4");

        assertTrue(result.isSpoofed());
        assertTrue(result.getReasons().stream().anyMatch(r -> r.contains("SIMILARITY_SPOOF")));
    }

    @Test
    void antiNameSpoofShouldBlockSpoofedName() {
        AntiNameSpoofService service = new AntiNameSpoofService();
        service.addProtectedName("Notch");

        service.checkPlayerName("N​otch", "10.0.0.5");
        service.checkPlayerName("NOTCH", "10.0.0.6");

        var status = service.getStatus();
        assertTrue((Long) status.get("spoofAttempts") >= 1);
        assertTrue((Integer) status.get("blockedNames") >= 1);
    }
}
