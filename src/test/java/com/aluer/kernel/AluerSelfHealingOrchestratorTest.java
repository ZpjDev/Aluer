package com.aluer.kernel;

import com.aluer.ai.AIStrategyEngine;
import com.aluer.audit.SecurityAuditService;
import com.aluer.backup.BackupService;
import com.aluer.config.ServerGuardConfig;
import com.aluer.model.MetricsData;
import com.aluer.monitor.ProcessMonitor;
import com.aluer.monitor.ResourceMonitor;
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

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AluerSelfHealingOrchestratorTest {

    @Test
    void healingCyclePlansRecoveryForDeadProcessAndResourceEmergency() {
        Fixture fixture = new Fixture();

        AluerSelfHealingOrchestrator.HealingCycle cycle = fixture.orchestrator.runHealingCycle("test");
        Map<String, Object> cycleMap = cycle.toMap();

        @SuppressWarnings("unchecked")
        List<Map<String, Object>> plan = (List<Map<String, Object>>) cycleMap.get("plan");
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> results = (List<Map<String, Object>>) cycleMap.get("results");

        assertFalse((Boolean) cycleMap.get("processRunning"));
        assertTrue(plan.stream().anyMatch(item -> "PROCESS_RECOVERY".equals(item.get("type"))));
        assertTrue(plan.stream().anyMatch(item -> "RELIEVE_PRESSURE".equals(item.get("type"))));
        assertTrue(results.stream().anyMatch(item -> "PROCESS_RECOVERY".equals(item.get("type"))));
        assertTrue(results.stream().anyMatch(item -> "RELIEVE_PRESSURE".equals(item.get("type"))));
    }

    private static final class Fixture {
        private final ServerGuardConfig config = new ServerGuardConfig();
        private final FakeProcessMonitor processMonitor;
        private final FakeResourceMonitor resourceMonitor;
        private final FakeBackupService backupService;
        private final FakeRconClient rconClient;
        private final AluerSelfHealingOrchestrator orchestrator;

        private Fixture() {
            config.getSecurity().getKernel().setEnabled(false);
            config.getSecurity().getTaskBus().setEnabled(true);
            config.getSecurity().getTaskBus().setAutoDispatch(false);
            config.getSecurity().getSelfHealing().setEnabled(false);
            config.getSecurity().getSelfHealing().setDryRun(false);
            config.getSecurity().getSelfHealing().setAutoBackupBeforeRecovery(true);
            config.getMinecraft().getRcon().setPassword("strong-rcon-password");

            processMonitor = new FakeProcessMonitor(config);
            resourceMonitor = new FakeResourceMonitor(config);
            backupService = new FakeBackupService(config);
            rconClient = new FakeRconClient(config);

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
            AIStrategyEngine strategyEngine = new AIStrategyEngine();
            SecurityAuditService auditService = new SecurityAuditService(config, rconClient);
            AluerKernelTaskBus taskBus = new AluerKernelTaskBus(config, processMonitor, backupService, rconClient, strategyEngine, auditService, kernel);

            orchestrator = new AluerSelfHealingOrchestrator(
                config,
                kernel,
                taskBus,
                resourceMonitor,
                processMonitor,
                hardening,
                auditService
            );
        }
    }

    private static final class FakeProcessMonitor extends ProcessMonitor {
        private FakeProcessMonitor(ServerGuardConfig config) {
            super(config);
        }

        @Override
        public boolean isProcessRunning() {
            return false;
        }

        @Override
        public boolean restartProcess() {
            return true;
        }
    }

    private static final class FakeResourceMonitor extends ResourceMonitor {
        private FakeResourceMonitor(ServerGuardConfig config) {
            super(config);
        }

        @Override
        public MetricsData collectMetrics() {
            MetricsData data = new MetricsData();
            data.setTps(10.5);
            data.setCpuUsage(96.0);
            data.setMemoryUsage(97.0);
            return data;
        }
    }

    private static final class FakeBackupService extends BackupService {
        private FakeBackupService(ServerGuardConfig config) {
            super(config);
        }

        @Override
        public BackupResult performScheduledBackup() {
            BackupResult result = new BackupResult();
            result.setName("heal-backup");
            result.setSuccess(true);
            result.setBackupPath("/tmp/heal-backup");
            result.setStartTime(java.time.LocalDateTime.now());
            return result;
        }
    }

    private static final class FakeRconClient extends RconClient {
        private FakeRconClient(ServerGuardConfig config) {
            super(config);
        }

        @Override
        public boolean clearLag() {
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
