package com.aluer.kernel;

import com.aluer.ai.AIStrategyEngine;
import com.aluer.audit.SecurityAuditService;
import com.aluer.backup.BackupService;
import com.aluer.config.ServerGuardConfig;
import com.aluer.monitor.ProcessMonitor;
import com.aluer.security.CommandExecutionGuardService;
import com.aluer.security.DDoSProtectionService;
import com.aluer.security.FirewallService;
import com.aluer.security.GeoIPService;
import com.aluer.security.IPReputationService;
import com.aluer.security.IntrusionDetectionService;
import com.aluer.security.NetworkMonitorService;
import com.aluer.security.NetworkThreatFusionService;
import com.aluer.security.PacketInspectionService;
import com.aluer.security.PortScanDetectionService;
import com.aluer.security.RateLimitService;
import com.aluer.security.SecurityBaselineHardeningService;
import com.aluer.security.TrafficAnalysisService;
import com.aluer.security.WebApplicationFirewall;
import com.aluer.service.RconClient;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AluerKernelTaskBusTest {

    @Test
    void dispatchesRecoveryAndStabilityTasksThroughPlugins() {
        Fixture fixture = new Fixture();

        fixture.taskBus.submitTask(AluerKernelTaskBus.TaskType.PROCESS_RECOVERY, "test", 95, Map.of("reason", "dead-process"));
        fixture.taskBus.submitTask(AluerKernelTaskBus.TaskType.RELIEVE_PRESSURE, "test", 80, Map.of("reason", "lag-spike"));
        List<AluerKernelTaskBus.KernelTaskResult> results = fixture.taskBus.dispatchQueuedTasks(2);

        assertEquals(2, results.size());
        assertEquals("recovery-plugin", results.get(0).getPluginId());
        assertEquals("stability-plugin", results.get(1).getPluginId());
        assertTrue(fixture.processMonitor.restartAttempts >= 1);
        assertTrue(fixture.rconClient.clearLagCalls >= 1);
        assertFalse(fixture.taskBus.getQueueSnapshot(5).iterator().hasNext());
    }

    private static final class Fixture {
        private final ServerGuardConfig config = new ServerGuardConfig();
        private final FakeProcessMonitor processMonitor;
        private final FakeBackupService backupService;
        private final FakeRconClient rconClient;
        private final AIStrategyEngine strategyEngine = new AIStrategyEngine();
        private final SecurityAuditService auditService;
        private final AluerKernelTaskBus taskBus;

        private Fixture() {
            config.getSecurity().getKernel().setEnabled(false);
            config.getSecurity().getTaskBus().setAutoDispatch(false);
            config.getSecurity().getTaskBus().setEnabled(true);
            config.getMinecraft().getRcon().setPassword("strong-rcon-password");

            processMonitor = new FakeProcessMonitor(config);
            backupService = new FakeBackupService(config);
            rconClient = new FakeRconClient(config);
            auditService = new SecurityAuditService(config, rconClient);

            DDoSProtectionService ddos = new DDoSProtectionService();
            FirewallService firewall = new FirewallService();
            IntrusionDetectionService intrusion = new IntrusionDetectionService();
            NetworkMonitorService networkMonitor = new NetworkMonitorService();
            TrafficAnalysisService traffic = new TrafficAnalysisService();
            PortScanDetectionService portScan = new PortScanDetectionService();
            PacketInspectionService packetInspection = new PacketInspectionService();
            IPReputationService ipReputation = new IPReputationService();
            GeoIPService geoIP = new GeoIPService();
            RateLimitService rateLimit = new RateLimitService();
            NetworkThreatFusionService fusion = new NetworkThreatFusionService(
                ddos, firewall, intrusion, networkMonitor, traffic, portScan, packetInspection, ipReputation, geoIP, rateLimit
            );
            SecurityBaselineHardeningService hardening = new SecurityBaselineHardeningService(config);
            CommandExecutionGuardService commandGuard = new CommandExecutionGuardService(config, intrusion);
            WebApplicationFirewall waf = new WebApplicationFirewall();
            AluerKernelEngine kernel = new AluerKernelEngine(config, fusion, hardening, commandGuard, waf);

            taskBus = new AluerKernelTaskBus(config, processMonitor, backupService, rconClient, strategyEngine, auditService, kernel);
        }
    }

    private static final class FakeProcessMonitor extends ProcessMonitor {
        private boolean running = false;
        private int restartAttempts = 0;

        private FakeProcessMonitor(ServerGuardConfig config) {
            super(config);
        }

        @Override
        public boolean isProcessRunning() {
            return running;
        }

        @Override
        public boolean restartProcess() {
            restartAttempts++;
            running = true;
            return true;
        }
    }

    private static final class FakeBackupService extends BackupService {
        private FakeBackupService(ServerGuardConfig config) {
            super(config);
        }

        @Override
        public BackupResult performScheduledBackup() {
            BackupResult result = new BackupResult();
            result.setName("test-backup");
            result.setSuccess(true);
            result.setBackupPath("/tmp/test-backup");
            result.setStartTime(java.time.LocalDateTime.now());
            return result;
        }
    }

    private static final class FakeRconClient extends RconClient {
        private int clearLagCalls = 0;

        private FakeRconClient(ServerGuardConfig config) {
            super(config);
        }

        @Override
        public boolean clearLag() {
            clearLagCalls++;
            return true;
        }

        @Override
        public boolean setSpawnRate(int rate) {
            return true;
        }

        @Override
        public boolean enableWhitelist() {
            return true;
        }

        @Override
        public String executeCommand(String command) {
            return "ok";
        }

        @Override
        public boolean restartServer() {
            return true;
        }
    }
}
