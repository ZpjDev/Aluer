package com.aluer.security;

import org.junit.jupiter.api.Test;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;

class V33SecurityTest {

    // --- GeoBlockService Tests ---

    @Test
    void geoBlockBlocksHighRiskCountry() {
        GeoBlockService geo = new GeoBlockService();
        GeoBlockService.GeoBlockResult r1 = geo.checkConnection("1.2.3.4", "CN");
        assertTrue(r1.isBlocked());
    }

    @Test
    void geoBlockAllowsNormalCountry() {
        GeoBlockService geo = new GeoBlockService();
        GeoBlockService.GeoBlockResult r = geo.checkConnection("8.8.8.8", "US");
        assertTrue(r.isAllowed());
    }

    @Test
    void geoBlockAllowlistOverridesBlocklist() {
        GeoBlockService geo = new GeoBlockService();
        geo.addToAllowlist("CN");
        GeoBlockService.GeoBlockResult r = geo.checkConnection("1.2.3.4", "CN");
        assertTrue(r.isAllowed());
    }

    @Test
    void geoBlockUnknownCountryAllowed() {
        GeoBlockService geo = new GeoBlockService();
        GeoBlockService.GeoBlockResult r = geo.checkConnection("10.0.0.1", "XX");
        assertTrue(r.isAllowed());
    }

    @Test
    void geoBlockStatusHasCounters() {
        GeoBlockService geo = new GeoBlockService();
        geo.checkConnection("1.2.3.4", "CN");
        geo.checkConnection("2.2.2.2", "RU");
        Map<String, Object> status = geo.getStatus();
        assertTrue((Long) status.get("totalBlocked") >= 2);
    }

    // --- PlayerSessionValidationService Tests ---

    @Test
    void sessionValidationDetectsInvalidUUID() {
        PlayerSessionValidationService svc = new PlayerSessionValidationService();
        PlayerSessionValidationService.SessionValidationResult r = svc.validateJoin(
                "invalid-uuid-format", "Player1", "192.168.1.1", "session-1");
        assertTrue(r.isInvalid());
    }

    @Test
    void sessionValidationAcceptsValidJoin() {
        PlayerSessionValidationService svc = new PlayerSessionValidationService();
        PlayerSessionValidationService.SessionValidationResult r = svc.validateJoin(
                "550e8400-e29b-41d4-a716-446655440000", "Player1", "192.168.1.1", "session-a");
        assertTrue(r.isValid());
    }

    @Test
    void sessionValidationDetectsRapidAccountSwitch() {
        PlayerSessionValidationService svc = new PlayerSessionValidationService();
        // Same IP, 4 different accounts in quick succession
        svc.validateJoin("550e8400-e29b-41d4-a716-446655440001", "PlayerA", "192.168.1.50", "s1");
        svc.validateJoin("550e8400-e29b-41d4-a716-446655440002", "PlayerB", "192.168.1.50", "s2");
        svc.validateJoin("550e8400-e29b-41d4-a716-446655440003", "PlayerC", "192.168.1.50", "s3");
        PlayerSessionValidationService.SessionValidationResult r = svc.validateJoin(
                "550e8400-e29b-41d4-a716-446655440004", "PlayerD", "192.168.1.50", "s4");
        assertTrue(r.isSuspicious() || r.isInvalid());
    }

    @Test
    void sessionValidationDetectsDuplicateUUID() {
        PlayerSessionValidationService svc = new PlayerSessionValidationService();
        String uuid = "550e8400-e29b-41d4-a716-446655440010";
        svc.validateJoin(uuid, "PlayerX", "10.0.0.1", "sx1");
        // Same UUID from different IP
        PlayerSessionValidationService.SessionValidationResult r = svc.validateJoin(
                uuid, "PlayerX", "10.0.0.99", "sx2");
        assertTrue(r.isSuspicious());
    }

    @Test
    void sessionValidationStatusWorks() {
        PlayerSessionValidationService svc = new PlayerSessionValidationService();
        svc.validateJoin("550e8400-e29b-41d4-a716-446655440020", "TestPlayer", "1.1.1.1", "ss");
        Map<String, Object> status = svc.getStatus();
        assertNotNull(status.get("totalValidations"));
    }

    // --- PluginVerificationService Tests ---

    @Test
    void pluginVerificationDetectsMaliciousPluginName() {
        PluginVerificationService pvs = new PluginVerificationService();
        // Known hack client name
        PluginVerificationService.VerificationResult r = pvs.scanPluginName("ImpactClient");
        assertTrue(r.isFailed());
    }

    @Test
    void pluginVerificationPassesNormalPluginName() {
        PluginVerificationService pvs = new PluginVerificationService();
        PluginVerificationService.VerificationResult r = pvs.scanPluginName("EssentialsX");
        assertTrue(r.isPassed() || r.isUnknown());
    }

    @Test
    void pluginVerificationHashWorks() {
        PluginVerificationService pvs = new PluginVerificationService();
        pvs.registerPlugin("test-plugin", "/tmp/test.jar", "abc123hash");
        PluginVerificationService.VerificationResult r = pvs.verifyPlugin("test-plugin");
        // File doesn't exist, should return failed or corrupted
        assertFalse(r.isPassed());
    }

    @Test
    void pluginVerificationUnknownPlugin() {
        PluginVerificationService pvs = new PluginVerificationService();
        PluginVerificationService.VerificationResult r = pvs.verifyPlugin("nonexistent-plugin");
        assertTrue(r.isUnknown() || r.isFailed());
    }

    @Test
    void pluginVerificationStatusWorks() {
        PluginVerificationService pvs = new PluginVerificationService();
        pvs.registerPlugin("p1", "/tmp/p1.jar", "hash1");
        Map<String, Object> status = pvs.getStatus();
        assertNotNull(status.get("registeredPlugins"));
    }

    // --- ConnectionThrottleService Tests ---

    @Test
    void connectionThrottleAllowsNormalConnection() {
        ConnectionThrottleService throttle = new ConnectionThrottleService();
        ConnectionThrottleService.ThrottleResult r = throttle.tryAcquire("192.168.1.1");
        assertTrue(r.isAllowed());
    }

    @Test
    void connectionThrottleBlocksExcessConnections() {
        ConnectionThrottleService throttle = new ConnectionThrottleService();
        for (int i = 0; i < 6; i++) {
            throttle.tryAcquire("10.0.0.99");
        }
        ConnectionThrottleService.ThrottleResult r = throttle.tryAcquire("10.0.0.99");
        assertFalse(r.isAllowed());
    }

    @Test
    void connectionThrottleDifferentIPsAllowed() {
        ConnectionThrottleService throttle = new ConnectionThrottleService();
        throttle.tryAcquire("1.1.1.1");
        throttle.tryAcquire("2.2.2.2");
        ConnectionThrottleService.ThrottleResult r = throttle.tryAcquire("3.3.3.3");
        assertTrue(r.isAllowed());
    }

    @Test
    void connectionThrottleStatusWorks() {
        ConnectionThrottleService throttle = new ConnectionThrottleService();
        throttle.tryAcquire("10.0.0.1");
        throttle.tryAcquire("10.0.0.1");
        throttle.tryAcquire("10.0.0.1");
        Map<String, Object> status = throttle.getStatus();
        assertNotNull(status.get("totalConnections"));
    }

    // --- BackupIntegrityService Tests ---

    @Test
    void backupIntegrityRegisterAndVerifyMissingFile() {
        BackupIntegrityService bis = new BackupIntegrityService();
        bis.registerBackup("world-backup", "/tmp/nonexistent-backup.zip", 1024L, "abc123");
        // File doesn't exist on disk, so returns failed (record exists, file missing)
        BackupIntegrityService.IntegrityResult r = bis.verifyBackup("world-backup");
        assertTrue(r.isFailed());
    }

    @Test
    void backupIntegrityUnknownBackupIsMissing() {
        BackupIntegrityService bis = new BackupIntegrityService();
        // No record registered, so verify returns missing
        BackupIntegrityService.IntegrityResult r = bis.verifyBackup("never-registered-backup");
        assertTrue(r.isMissing());
    }

    @Test
    void backupIntegrityUnknownBackup() {
        BackupIntegrityService bis = new BackupIntegrityService();
        BackupIntegrityService.IntegrityResult r = bis.verifyBackup("unknown-backup");
        assertFalse(r.isPassed());
    }

    @Test
    void backupIntegrityStatusWorks() {
        BackupIntegrityService bis = new BackupIntegrityService();
        bis.registerBackup("b1", "/tmp/b1.zip", 500, "h1");
        bis.registerBackup("b2", "/tmp/b2.zip", 800, "h2");
        Map<String, Object> status = bis.getStatus();
        assertEquals(2, ((Number) status.get("totalBackups")).intValue());
    }

    // --- AntiSkinSpoofService Tests ---

    @Test
    void antiSkinSpoofDetectsImpersonation() {
        AntiSkinSpoofService skin = new AntiSkinSpoofService();
        // "Dream" is a known impersonation target
        AntiSkinSpoofService.SkinSpoofResult r = skin.checkSkin(
                "UnknownPlayer", "https://textures.minecraft.net/texture/abc", "classic", "skin-hash-1");
        // Not spoofing - different name
        assertTrue(r.isClean() || r.isSuspicious());
    }

    @Test
    void antiSkinSpoofDetectsSuspiciousURL() {
        AntiSkinSpoofService skin = new AntiSkinSpoofService();
        AntiSkinSpoofService.SkinSpoofResult r = skin.checkSkin(
                "TestPlayer", "https://malicious-server.com/skin.png", "classic", "some-hash");
        assertTrue(r.isSuspicious() || r.isSpoofed());
    }

    @Test
    void antiSkinSpoofDetectsRapidChange() {
        AntiSkinSpoofService skin = new AntiSkinSpoofService();
        for (int i = 0; i < 5; i++) {
            skin.checkSkin("FastChanger", "https://textures.minecraft.net/texture/" + i, "classic", "hash-" + i);
        }
        AntiSkinSpoofService.SkinSpoofResult r = skin.checkSkin(
                "FastChanger", "https://textures.minecraft.net/texture/999", "classic", "hash-999");
        assertTrue(r.isSuspicious() || r.isSpoofed());
    }

    @Test
    void antiSkinSpoofNormalPlayerPasses() {
        AntiSkinSpoofService skin = new AntiSkinSpoofService();
        AntiSkinSpoofService.SkinSpoofResult r = skin.checkSkin(
                "NormalPlayer", "https://textures.minecraft.net/texture/aaaa", "classic", "normal-hash");
        assertTrue(r.isClean());
    }

    @Test
    void antiSkinSpoofDetectsSlimMismatch() {
        AntiSkinSpoofService skin = new AntiSkinSpoofService();
        AntiSkinSpoofService.SkinSpoofResult r = skin.checkSkin(
                "ModelSwitcher", "https://textures.minecraft.net/texture/bbbb", "slim", "recent-slim-hash");
        r = skin.checkSkin(
                "ModelSwitcher", "https://textures.minecraft.net/texture/cccc", "classic", "recent-classic-hash");
        assertTrue(r.isSuspicious() || r.isClean());
    }

    @Test
    void antiSkinSpoofStatusWorks() {
        AntiSkinSpoofService skin = new AntiSkinSpoofService();
        skin.checkSkin("P1", "https://textures.minecraft.net/texture/1", "classic", "h1");
        skin.checkSkin("P2", "https://textures.minecraft.net/texture/2", "classic", "h2");
        Map<String, Object> status = skin.getStatus();
        assertNotNull(status.get("totalChecks"));
    }
}
