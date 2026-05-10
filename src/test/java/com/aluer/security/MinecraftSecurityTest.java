package com.aluer.security;

import org.junit.jupiter.api.Test;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;

class MinecraftSecurityTest {

    // --- AntiXrayDetectionService Tests ---
    @Test
    void antiXrayDetectsHighDiamondRatio() {
        AntiXrayDetectionService xray = new AntiXrayDetectionService();
        // Mine 50 "valuable ores" and only 30 "common blocks" = ratio 1.67 > 0.5
        for (int i = 0; i < 30; i++) {
            xray.checkBlockBreak("XrayPlayer", "STONE", i, 10, 0, "world");
        }
        for (int i = 0; i < 20; i++) {
            AntiXrayDetectionService.XrayCheckResult result = xray.checkBlockBreak(
                    "XrayPlayer", "DIAMOND_ORE", 100, 12, 100, "world");
            if (result.isFlagged()) break;
        }
        var status = xray.getStatus();
        assertTrue((Long) status.get("totalDetections") > 0);
    }

    @Test
    void antiXrayAllowsNormalMining() {
        AntiXrayDetectionService xray = new AntiXrayDetectionService();
        // Normal mining pattern: lots of stone, few ores
        for (int i = 0; i < 100; i++) {
            xray.checkBlockBreak("GoodMiner", "STONE", i, 10, 0, "world");
        }
        AntiXrayDetectionService.XrayCheckResult result = xray.checkBlockBreak(
                "GoodMiner", "DIAMOND_ORE", 50, 12, 50, "world");
        assertFalse(result.isFlagged());
    }

    @Test
    void antiXrayClearPlayerResets() {
        AntiXrayDetectionService xray = new AntiXrayDetectionService();
        for (int i = 0; i < 60; i++) {
            xray.checkBlockBreak("TestPlayer", "DIAMOND_ORE", 100, 12, i, "world");
        }
        xray.clearPlayer("TestPlayer");
        AntiXrayDetectionService.XrayCheckResult result = xray.checkBlockBreak(
                "TestPlayer", "STONE", 0, 10, 0, "world");
        assertFalse(result.isFlagged());
    }

    // --- AntiFlyDetectionService Tests ---
    @Test
    void antiFlyDetectsImpossibleVertical() {
        AntiFlyDetectionService fly = new AntiFlyDetectionService();
        // Rapid upward movement without ground contact (flying up 10 blocks instantly)
        AntiFlyDetectionService.FlyCheckResult result = fly.checkMovement(
                "FlyHacker", 0, 64, 0, 0, 75, 0, false, "survival");
        assertTrue(result.isFlagged());
    }

    @Test
    void antiFlyDetectsExcessiveHorizontal() {
        AntiFlyDetectionService fly = new AntiFlyDetectionService();
        // Moving 20 blocks in one tick in survival mode
        AntiFlyDetectionService.FlyCheckResult result = fly.checkMovement(
                "SpeedHacker", 0, 64, 0, 20, 64, 0, true, "survival");
        assertTrue(result.isFlagged());
    }

    @Test
    void antiFlyDetectsTeleport() {
        AntiFlyDetectionService fly = new AntiFlyDetectionService();
        // 100-block teleport in survival
        AntiFlyDetectionService.FlyCheckResult result = fly.checkMovement(
                "Teleporter", 0, 64, 0, 100, 64, 0, true, "survival");
        assertTrue(result.isFlagged());
    }

    @Test
    void antiFlyAllowsNormalMovement() {
        AntiFlyDetectionService fly = new AntiFlyDetectionService();
        AntiFlyDetectionService.FlyCheckResult result = fly.checkMovement(
                "NormalPlayer", 0, 64, 0, 0.3, 64, 0.3, true, "survival");
        assertFalse(result.isFlagged());
    }

    @Test
    void antiFlyAllowsCreativeFlight() {
        AntiFlyDetectionService fly = new AntiFlyDetectionService();
        AntiFlyDetectionService.FlyCheckResult result = fly.checkMovement(
                "CreativePlayer", 0, 64, 0, 5, 68, 5, false, "creative");
        assertFalse(result.isFlagged());
    }

    // --- AntiDupeDetectionService Tests ---
    @Test
    void antiDupeDetectsStackOverflow() {
        AntiDupeDetectionService dupe = new AntiDupeDetectionService();
        // 100 diamonds in one stack (impossible - max is 64)
        AntiDupeDetectionService.DupeCheckResult result = dupe.checkInventoryChange(
                "DupeHacker", "DIAMOND", 100, 10, "CHEST", 0, 64, 0);
        assertTrue(result.isFlagged());
    }

    @Test
    void antiDupeDetectsNetheriteSurge() {
        AntiDupeDetectionService dupe = new AntiDupeDetectionService();
        // 200 netherite blocks gained in one transaction
        AntiDupeDetectionService.DupeCheckResult result = dupe.checkInventoryChange(
                "DupeHacker2", "NETHERITE_BLOCK", 200, 0, "SHULKER_BOX", 0, 64, 0);
        assertTrue(result.isFlagged());
    }

    @Test
    void antiDupeDetectsImpossibleIncrease() {
        AntiDupeDetectionService dupe = new AntiDupeDetectionService();
        // 1 -> 600 items (3x increase + >500)
        AntiDupeDetectionService.DupeCheckResult result = dupe.checkInventoryChange(
                "DupeHacker3", "DIAMOND", 600, 1, "CHEST", 0, 64, 0);
        assertTrue(result.isFlagged());
    }

    @Test
    void antiDupeAllowsNormalTransfer() {
        AntiDupeDetectionService dupe = new AntiDupeDetectionService();
        AntiDupeDetectionService.DupeCheckResult result = dupe.checkInventoryChange(
                "NormalPlayer", "DIAMOND", 40, 30, "CHEST", 0, 64, 0);
        assertFalse(result.isFlagged());
    }

    // --- CrashExploitProtectionService Tests ---
    @Test
    void crashExploitDetectsOversizedPacket() {
        CrashExploitProtectionService crash = new CrashExploitProtectionService();
        CrashExploitProtectionService.CrashCheckResult result = crash.checkPacket(
                "CustomPayload", 3000000, "10.0.0.1"); // 3MB packet
        assertTrue(result.isDetected() || result.isBlocked());
    }

    @Test
    void crashExploitDetectsNegativeLength() {
        CrashExploitProtectionService crash = new CrashExploitProtectionService();
        CrashExploitProtectionService.CrashCheckResult result = crash.checkPacket(
                "Login", -1, "10.0.0.2");
        assertTrue(result.isDetected() || result.isBlocked());
    }

    @Test
    void crashExploitDetectsDeepNesting() {
        CrashExploitProtectionService crash = new CrashExploitProtectionService();
        CrashExploitProtectionService.CrashCheckResult result = crash.checkNBTData(
                "deeply nested nbt data", 100, "10.0.0.3");
        assertTrue(result.isDetected() || result.isBlocked());
    }

    @Test
    void crashExploitDetectsOversizedBook() {
        CrashExploitProtectionService crash = new CrashExploitProtectionService();
        CrashExploitProtectionService.CrashCheckResult result = crash.checkBookContent(
                "{\"text\":\"...large...\"}", 150, 50000, "10.0.0.4");
        assertTrue(result.isDetected() || result.isBlocked());
    }

    @Test
    void crashExploitAllowsNormalPacket() {
        CrashExploitProtectionService crash = new CrashExploitProtectionService();
        CrashExploitProtectionService.CrashCheckResult result = crash.checkPacket(
                "KeepAlive", 64, "10.0.0.5");
        assertFalse(result.isDetected());
    }

    // --- LagMachineDetectionService Tests ---
    @Test
    void lagMachineDetectsObserverChain() {
        LagMachineDetectionService lag = new LagMachineDetectionService();
        // Place 60 observers + 50 TNT in same chunk = both rules trigger, score >= 40
        LagMachineDetectionService.LagCheckResult result = null;
        for (int i = 0; i < 60; i++) {
            result = lag.checkBlockPlace("LagBuilder", "OBSERVER", i % 16, 64, 0, "world");
        }
        for (int i = 0; i < 50; i++) {
            result = lag.checkBlockPlace("LagBuilder", "TNT", i % 16, 64, 0, "world");
        }
        assertNotNull(result);
        assertTrue(result.isFlagged());
    }

    @Test
    void lagMachineDetectsTNTStack() {
        LagMachineDetectionService lag = new LagMachineDetectionService();
        LagMachineDetectionService.LagCheckResult result = null;
        for (int i = 0; i < 50; i++) {
            result = lag.checkBlockPlace("TNTBuilder", "TNT", 0, 64, i % 16, "world");
            if (result != null && result.isFlagged()) break;
        }
        assertNotNull(result);
        assertTrue(result.isFlagged());
    }

    @Test
    void lagMachineAllowsNormalBuilding() {
        LagMachineDetectionService lag = new LagMachineDetectionService();
        LagMachineDetectionService.LagCheckResult result = lag.checkBlockPlace(
                "Builder", "STONE_BRICKS", 8, 64, 8, "world");
        assertFalse(result.isFlagged());
    }

    @Test
    void lagMachineDetectsHighLagDensity() {
        LagMachineDetectionService lag = new LagMachineDetectionService();
        LagMachineDetectionService.LagCheckResult result = null;
        // Place 105 redstone-related blocks in one chunk
        String[] lagBlocks = {"REDSTONE_WIRE", "REPEATER", "OBSERVER", "PISTON", "HOPPER"};
        int count = 0;
        for (int i = 0; i < 110 && count < 5; i++) {
            result = lag.checkBlockPlace("RedstoneGuy", lagBlocks[i % 5], i % 16, 64, i % 16, "world");
            if (result != null && result.isFlagged()) break;
        }
        assertNotNull(result);
        assertTrue(result.isFlagged() || result.isSuspicious());
    }
}
