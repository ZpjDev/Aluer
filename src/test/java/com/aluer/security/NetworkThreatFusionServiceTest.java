package com.aluer.security;

import com.aluer.defense.IntrusionDetectionService;
import com.aluer.network.DDoSProtectionService;
import com.aluer.network.FirewallService;
import com.aluer.network.GeoIPService;
import com.aluer.network.IPReputationService;
import com.aluer.network.NetworkMonitorService;
import com.aluer.network.NetworkThreatFusionService;
import com.aluer.network.PacketInspectionService;
import com.aluer.network.PortScanDetectionService;
import com.aluer.network.RateLimitService;
import com.aluer.network.TrafficAnalysisService;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Field;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class NetworkThreatFusionServiceTest {

    @Test
    void inspectIPCombinesSignalsIntoCriticalRisk() throws Exception {
        try (Fixture fixture = new Fixture()) {
            String ip = "203.0.113.10";

            fixture.ddos.blockIP(ip, "SYN_FLOOD", "Traffic burst");
            fixture.firewall.addToBlacklist(ip);
            fixture.firewall.checkConnection(ip, "minecraft", 25565, "tcp");
            fixture.portScan.blockScanner(ip, "PORT_SCAN", "Scanned 25 ports");
            fixture.ipReputation.recordAttack(ip, "PORT_SCAN");
            fixture.ipReputation.addToBlacklist(ip);
            fixture.rateLimit.recordRejection(ip, "api", "Rate limit exceeded");
            fixture.packetInspection.inspectPacket(ip, Map.of("size", 12000));
            fixture.intrusion.triggerAlert("MALICIOUS_IP", "tester", "Known bad host", ip);

            fixture.networkMonitor.recordInboundTraffic(ip, 20_000_000L, 100);
            for (int port = 20000; port < 20045; port++) {
                fixture.networkMonitor.recordConnection(ip, port, "tcp");
            }

            for (int port = 30000; port < 30105; port++) {
                fixture.traffic.analyzePacket(ip, "198.51.100.1", port, 1500, "tcp");
            }

            Map<String, Object> result = fixture.service.inspectIP(ip);

            assertEquals(ip, result.get("ip"));
            assertEquals("critical", result.get("riskLevel"));
            assertTrue(((Integer) result.get("riskScore")) >= 80);
            assertTrue((Boolean) result.get("blocked"));

            @SuppressWarnings("unchecked")
            List<String> reasons = (List<String>) result.get("reasons");
            assertFalse(reasons.isEmpty());
        }
    }

    @Test
    void quarantineIPBlacklistsAcrossServices() throws Exception {
        try (Fixture fixture = new Fixture()) {
            String ip = "198.51.100.22";

            Map<String, Object> result = fixture.service.quarantineIP(ip, "tester", "manual containment");

            assertEquals("quarantined", result.get("status"));
            assertTrue((Boolean) result.get("blocked"));
            assertTrue((Boolean) result.get("quarantined"));
            assertTrue(fixture.ddos.isBlocked(ip));
            assertTrue(fixture.firewall.isBlacklisted(ip));
            assertTrue(fixture.ipReputation.isBlacklisted(ip));
        }
    }

    private static final class Fixture implements AutoCloseable {
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
        private final NetworkThreatFusionService service = new NetworkThreatFusionService(
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
