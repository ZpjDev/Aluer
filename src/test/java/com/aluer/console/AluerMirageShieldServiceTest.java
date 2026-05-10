package com.aluer.console;

import com.aluer.ai.AIStrategyEngine;
import com.aluer.audit.SecurityAuditService;
import com.aluer.backup.BackupService;
import com.aluer.config.ServerGuardConfig;
import com.aluer.kernel.AluerKernelEngine;
import com.aluer.kernel.AluerKernelTaskBus;
import com.aluer.kernel.AluerSelfHealingOrchestrator;
import com.aluer.model.MetricsData;
import com.aluer.monitor.ProcessMonitor;
import com.aluer.monitor.ResourceMonitor;
import com.aluer.security.CloudflareIntegrationService;
import com.aluer.security.CommandExecutionGuardService;
import com.aluer.security.DDoSDefenseCoordinator;
import com.aluer.security.DDoSProtectionService;
import com.aluer.security.DistributedAttackMitigationService;
import com.aluer.security.FirewallService;
import com.aluer.security.GeoIPService;
import com.aluer.security.HostEnforcementService;
import com.aluer.security.IPReputationService;
import com.aluer.security.IntrusionDetectionService;
import com.aluer.security.LoadBalancerService;
import com.aluer.security.MinecraftProtocolSecurityService;
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

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AluerMirageShieldServiceTest {

    @Test
    void shelterModeProducesDeterrenceAndQueuesContainment() {
        Fixture fixture = new Fixture();

        Map<String, Object> result = fixture.shieldService.engage("SHELTER", "test-shelter");

        assertEquals("SHELTER", result.get("mode"));
        assertTrue(String.valueOf(result.get("deterrenceMessage")).contains("ALUER NOTICE"));

        @SuppressWarnings("unchecked")
        List<Map<String, Object>> actions = (List<Map<String, Object>>) result.get("actions");
        assertTrue(actions.stream().anyMatch(action -> "under-attack".equals(action.get("type"))));
        assertTrue(actions.stream().anyMatch(action -> "task:WHITELIST_LOCKDOWN".equals(action.get("type"))));
        assertTrue(actions.stream().anyMatch(action -> "self-healing".equals(action.get("type"))));
    }

    private static final class Fixture {
        private final ServerGuardConfig config = new ServerGuardConfig();
        private final AluerMirageShieldService shieldService;

        private Fixture() {
            config.getSecurity().getKernel().setEnabled(false);
            config.getSecurity().getTaskBus().setEnabled(true);
            config.getSecurity().getTaskBus().setAutoDispatch(false);
            config.getSecurity().getSelfHealing().setEnabled(false);
            config.getSecurity().getSelfHealing().setDryRun(true);
            config.getSecurity().getHostEnforcement().setEnabled(false);
            config.getSecurity().getCloudEdge().setEnabled(false);
            config.getSecurity().getCloudEdge().setDryRun(true);
            config.getSecurity().getShield().setEnabled(true);
            config.getSecurity().getShield().setAutoEnableUnderAttack(true);
            config.getMinecraft().getRcon().setPassword("strong-rcon-password");

            FakeProcessMonitor processMonitor = new FakeProcessMonitor(config);
            FakeResourceMonitor resourceMonitor = new FakeResourceMonitor(config);
            FakeBackupService backupService = new FakeBackupService(config);
            FakeRconClient rconClient = new FakeRconClient(config);

            DDoSProtectionService ddosProtectionService = new DDoSProtectionService();
            FirewallService firewallService = new FirewallService();
            IntrusionDetectionService intrusionDetectionService = new IntrusionDetectionService();
            NetworkMonitorService networkMonitorService = new NetworkMonitorService();
            TrafficAnalysisService trafficAnalysisService = new TrafficAnalysisService();
            PortScanDetectionService portScanDetectionService = new PortScanDetectionService();
            PacketInspectionService packetInspectionService = new PacketInspectionService();
            IPReputationService ipReputationService = new IPReputationService();
            GeoIPService geoIPService = new GeoIPService();
            RateLimitService rateLimitService = new RateLimitService();

            NetworkThreatFusionService fusion = new NetworkThreatFusionService(
                ddosProtectionService,
                firewallService,
                intrusionDetectionService,
                networkMonitorService,
                trafficAnalysisService,
                portScanDetectionService,
                packetInspectionService,
                ipReputationService,
                geoIPService,
                rateLimitService
            );
            fusion.quarantineIP("198.51.100.55", "test", "bot swarm");

            SecurityBaselineHardeningService hardening = new SecurityBaselineHardeningService(config);
            CommandExecutionGuardService commandGuard = new CommandExecutionGuardService(config, intrusionDetectionService);
            WebApplicationFirewall waf = new WebApplicationFirewall();
            AluerKernelEngine kernel = new AluerKernelEngine(config, fusion, hardening, commandGuard, waf);
            AIStrategyEngine strategyEngine = new AIStrategyEngine();
            SecurityAuditService auditService = new SecurityAuditService(config, rconClient);
            AluerKernelTaskBus taskBus = new AluerKernelTaskBus(config, processMonitor, backupService, rconClient, strategyEngine, auditService, kernel);
            AluerSelfHealingOrchestrator orchestrator = new AluerSelfHealingOrchestrator(
                config,
                kernel,
                taskBus,
                resourceMonitor,
                processMonitor,
                hardening,
                auditService
            );

            DistributedAttackMitigationService mitigationService = new DistributedAttackMitigationService();
            HostEnforcementService hostEnforcementService = new HostEnforcementService(config);
            CloudflareIntegrationService cloudflareIntegrationService = new CloudflareIntegrationService(config);
            LoadBalancerService loadBalancerService = new LoadBalancerService();
            DDoSDefenseCoordinator ddosDefenseCoordinator = new DDoSDefenseCoordinator(
                config,
                ddosProtectionService,
                mitigationService,
                new MinecraftProtocolSecurityService(),
                hostEnforcementService
            );

            shieldService = new AluerMirageShieldService(
                config,
                fusion,
                ddosDefenseCoordinator,
                mitigationService,
                cloudflareIntegrationService,
                hostEnforcementService,
                loadBalancerService,
                hardening,
                commandGuard,
                kernel,
                taskBus,
                orchestrator,
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
            data.setTps(9.5);
            data.setCpuUsage(97.0);
            data.setMemoryUsage(96.0);
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
            result.setName("shield-backup");
            result.setSuccess(true);
            result.setBackupPath("/tmp/shield-backup");
            result.setStartTime(LocalDateTime.now());
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
