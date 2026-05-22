package com.aluer.security;

import com.aluer.config.ServerGuardConfig;
import com.aluer.defense.SecurityBaselineHardeningService;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertTrue;

class SecurityBaselineHardeningServiceTest {

    @Test
    void assessCurrentBaselineFlagsWeakRemoteControlAndUnsafeAutonomyThresholds() {
        ServerGuardConfig config = new ServerGuardConfig();
        config.getMinecraft().getRcon().setEnabled(true);
        config.getMinecraft().getRcon().setPassword("");
        config.getSecurity().getAntiIntrusion().getFileIntegrity().setEnabled(false);
        config.getSecurity().getHostEnforcement().setEnabled(false);
        config.getAi().getDeepseek().getAutoExecute().setEnabled(true);
        config.getAi().getDeepseek().getAutoExecute().setMinConfidence(60);

        SecurityBaselineHardeningService service = new SecurityBaselineHardeningService(config);
        SecurityBaselineHardeningService.HardeningReport report = service.assessCurrentBaseline();

        assertTrue(report.getCriticalCount() >= 1);
        assertTrue(report.getHighCount() >= 1);
        assertTrue(report.getMediumCount() >= 1);
        assertTrue(report.getScore() < 80);
    }
}
