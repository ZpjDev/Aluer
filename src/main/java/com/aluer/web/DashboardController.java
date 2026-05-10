package com.aluer.web;

import com.aluer.ai.DeepSeekClient;
import com.aluer.audit.SecurityAuditService;
import com.aluer.backup.BackupService;
import com.aluer.config.ServerGuardConfig;
import com.aluer.notification.AttackReportService;
import com.aluer.notification.WebhookService;
import com.aluer.punishment.PunishmentService;
import com.aluer.profiler.PerformanceProfiler;
import com.aluer.security.*;
import com.aluer.service.RconClient;
import com.aluer.world.WorldManagementService;
import org.springframework.web.bind.annotation.*;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api")
public class DashboardController {

    private final RconClient rconClient;
    private final PerformanceProfiler profiler;
    private final BackupService backupService;
    private final PunishmentService punishmentService;
    private final SecurityAuditService auditService;
    private final WorldManagementService worldService;
    private final DeepSeekClient deepSeekClient;
    private final ServerGuardConfig config;
    private final NetworkThreatFusionService networkThreatFusionService;
    private final HealthService healthService;
    private final AttackReportService attackReportService;
    private final WebhookService webhookService;
    // New super-evolution security modules
    private final JwtAuthService jwtAuthService;
    private final BruteForceProtectionService bruteForceProtectionService;
    private final AntiBotDetectionService antiBotDetectionService;
    private final ReverseShellDetectionService reverseShellDetectionService;
    private final ARPSpoofDetectionService arpSpoofDetectionService;
    private final DNSTunnelDetectionService dnsTunnelDetectionService;
    private final ExploitSignatureService exploitSignatureService;
    private final SSRFProtectionService ssrfProtectionService;
    private final XXEProtectionService xxeProtectionService;
    private final CSPEnforcementService cspEnforcementService;
    private final DatabaseFirewallService databaseFirewallService;
    private final DataLossPreventionService dataLossPreventionService;
    private final MemoryProtectionService memoryProtectionService;
    private final ProcessInjectionDetectionService processInjectionDetectionService;
    private final SecureFileDeletionService secureFileDeletionService;
    private final ForensicsCollectorService forensicsCollectorService;
    private final IncidentResponseService incidentResponseService;
    private final ThreatHuntingService threatHuntingService;
    private final ComplianceScannerService complianceScannerService;
    private final AntiGriefDetectionService antiGriefDetectionService;

    @SuppressWarnings("java:S107")
    public DashboardController(
            RconClient rconClient,
            PerformanceProfiler profiler,
            BackupService backupService,
            PunishmentService punishmentService,
            SecurityAuditService auditService,
            WorldManagementService worldService,
            DeepSeekClient deepSeekClient,
            ServerGuardConfig config,
            NetworkThreatFusionService networkThreatFusionService,
            HealthService healthService,
            AttackReportService attackReportService,
            WebhookService webhookService,
            JwtAuthService jwtAuthService,
            BruteForceProtectionService bruteForceProtectionService,
            AntiBotDetectionService antiBotDetectionService,
            ReverseShellDetectionService reverseShellDetectionService,
            ARPSpoofDetectionService arpSpoofDetectionService,
            DNSTunnelDetectionService dnsTunnelDetectionService,
            ExploitSignatureService exploitSignatureService,
            SSRFProtectionService ssrfProtectionService,
            XXEProtectionService xxeProtectionService,
            CSPEnforcementService cspEnforcementService,
            DatabaseFirewallService databaseFirewallService,
            DataLossPreventionService dataLossPreventionService,
            MemoryProtectionService memoryProtectionService,
            ProcessInjectionDetectionService processInjectionDetectionService,
            SecureFileDeletionService secureFileDeletionService,
            ForensicsCollectorService forensicsCollectorService,
            IncidentResponseService incidentResponseService,
            ThreatHuntingService threatHuntingService,
            ComplianceScannerService complianceScannerService,
            AntiGriefDetectionService antiGriefDetectionService) {
        this.rconClient = rconClient;
        this.profiler = profiler;
        this.backupService = backupService;
        this.punishmentService = punishmentService;
        this.auditService = auditService;
        this.worldService = worldService;
        this.deepSeekClient = deepSeekClient;
        this.config = config;
        this.networkThreatFusionService = networkThreatFusionService;
        this.healthService = healthService;
        this.attackReportService = attackReportService;
        this.webhookService = webhookService;
        this.jwtAuthService = jwtAuthService;
        this.bruteForceProtectionService = bruteForceProtectionService;
        this.antiBotDetectionService = antiBotDetectionService;
        this.reverseShellDetectionService = reverseShellDetectionService;
        this.arpSpoofDetectionService = arpSpoofDetectionService;
        this.dnsTunnelDetectionService = dnsTunnelDetectionService;
        this.exploitSignatureService = exploitSignatureService;
        this.ssrfProtectionService = ssrfProtectionService;
        this.xxeProtectionService = xxeProtectionService;
        this.cspEnforcementService = cspEnforcementService;
        this.databaseFirewallService = databaseFirewallService;
        this.dataLossPreventionService = dataLossPreventionService;
        this.memoryProtectionService = memoryProtectionService;
        this.processInjectionDetectionService = processInjectionDetectionService;
        this.secureFileDeletionService = secureFileDeletionService;
        this.forensicsCollectorService = forensicsCollectorService;
        this.incidentResponseService = incidentResponseService;
        this.threatHuntingService = threatHuntingService;
        this.complianceScannerService = complianceScannerService;
        this.antiGriefDetectionService = antiGriefDetectionService;
    }

    @GetMapping("/status")
    public Map<String, Object> getStatus() {
        Map<String, Object> status = new HashMap<>();
        status.put("status", "running");
        status.put("timestamp", System.currentTimeMillis());
        return status;
    }

    @GetMapping("/server/info")
    public Map<String, Object> getServerInfo() {
        Map<String, Object> info = new HashMap<>();
        info.put("name", "Minecraft Server");
        info.put("version", "1.20.4");
        return info;
    }

    @GetMapping("/performance")
    public Map<String, Object> getPerformance() {
        Map<String, Object> data = new HashMap<>();
        data.put("tps", 20.0);
        data.put("cpu", 50);
        data.put("memory", 60);
        return data;
    }

    @PostMapping("/command/execute")
    public Map<String, Object> executeCommand(@RequestParam String command) {
        String result = rconClient.executeCommand(command);
        Map<String, Object> response = new HashMap<>();
        response.put("result", result);
        return response;
    }

    @GetMapping("/backup/list")
    public Map<String, Object> listBackups() {
        Map<String, Object> data = new HashMap<>();
        data.put("backups", new String[]{});
        return data;
    }

    @PostMapping("/backup/create")
    public Map<String, Object> createBackup(@RequestParam String name) {
        Map<String, Object> response = new HashMap<>();
        response.put("backup", name);
        response.put("status", "created");
        return response;
    }

    @GetMapping("/punishment/list")
    public Map<String, Object> listPunishments() {
        Map<String, Object> response = new HashMap<>();
        response.put("bans", 0);
        response.put("mutes", 0);
        return response;
    }

    @GetMapping("/security/stats")
    public Map<String, Object> getSecurityStats() {
        return networkThreatFusionService.getPosture();
    }

    @GetMapping("/security/network/posture")
    public Map<String, Object> getNetworkSecurityPosture() {
        return networkThreatFusionService.getPosture();
    }

    @GetMapping("/security/network/offenders")
    public Map<String, Object> getHighRiskIPs(@RequestParam(defaultValue = "10") int limit) {
        List<Map<String, Object>> offenders = networkThreatFusionService.getTopRiskIPs(limit);
        Map<String, Object> response = new HashMap<>();
        response.put("count", offenders.size());
        response.put("items", offenders);
        return response;
    }

    @GetMapping("/security/network/incidents")
    public Map<String, Object> getNetworkIncidents(@RequestParam(defaultValue = "20") int limit) {
        List<Map<String, Object>> incidents = networkThreatFusionService.getRecentIncidents(limit);
        Map<String, Object> response = new HashMap<>();
        response.put("count", incidents.size());
        response.put("items", incidents);
        return response;
    }

    @GetMapping("/security/network/ip")
    public Map<String, Object> inspectNetworkIP(@RequestParam String ip) {
        return networkThreatFusionService.inspectIP(ip);
    }

    @PostMapping("/security/network/quarantine")
    public Map<String, Object> quarantineIP(@RequestParam String ip,
                                            @RequestParam(defaultValue = "dashboard") String actor,
                                            @RequestParam(defaultValue = "Manual dashboard quarantine") String reason) {
        return networkThreatFusionService.quarantineIP(ip, actor, reason);
    }

    @PostMapping("/security/network/release")
    public Map<String, Object> releaseIP(@RequestParam String ip,
                                         @RequestParam(defaultValue = "dashboard") String actor,
                                         @RequestParam(defaultValue = "Manual dashboard release") String reason) {
        return networkThreatFusionService.releaseIP(ip, actor, reason);
    }

    @GetMapping("/world/list")
    public Map<String, Object> listWorlds() {
        Map<String, Object> data = new HashMap<>();
        data.put("worlds", new String[]{"world", "world_nether", "world_the_end"});
        return data;
    }

    @GetMapping("/ai/status")
    public Map<String, Object> getAIStatus() {
        Map<String, Object> status = new HashMap<>();
        status.put("enabled", true);
        return status;
    }

    @GetMapping("/health")
    public Map<String, Object> getHealth() {
        return healthService.getHealthReport();
    }

    @GetMapping("/health/live")
    public Map<String, Object> getLiveness() {
        return healthService.getLiveness();
    }

    @GetMapping("/health/ready")
    public Map<String, Object> getReadiness() {
        return healthService.getReadiness();
    }

    @GetMapping("/attacks/recent")
    public Map<String, Object> getRecentAttacks(@RequestParam(defaultValue = "20") int limit) {
        Map<String, Object> response = new HashMap<>();
        response.put("count", Math.min(limit, attackReportService.getRecentAttacks(Integer.MAX_VALUE).size()));
        response.put("items", attackReportService.getRecentAttacks(limit));
        return response;
    }

    @PostMapping("/attacks/report")
    public Map<String, Object> generateAttackReport() {
        Map<String, Object> response = new HashMap<>();
        try {
            java.io.File report = attackReportService.saveHtmlReport();
            response.put("status", "generated");
            response.put("path", report.getAbsolutePath());
        } catch (Exception e) {
            response.put("status", "failed");
            response.put("error", e.getMessage());
        }
        return response;
    }

    @PostMapping("/webhook/test")
    public Map<String, Object> testWebhook() {
        Map<String, Object> response = new HashMap<>();
        webhookService.sendCustomMessage("Aluer ServerGuard Test", "Webhook integration test successful.", "info");
        response.put("status", "sent");
        return response;
    }

    // --- Super-Evolution New API Endpoints ---

    @GetMapping("/security/auth/status")
    public Map<String, Object> getAuthStatus() {
        Map<String, Object> response = new HashMap<>();
        response.put("activeTokens", jwtAuthService.getActiveTokenCount());
        response.put("revokedTokens", jwtAuthService.getRevokedTokenCount());
        return response;
    }

    @GetMapping("/security/brute-force/status")
    public Map<String, Object> getBruteForceStatus() {
        return bruteForceProtectionService.getStatus();
    }

    @GetMapping("/security/anti-bot/status")
    public Map<String, Object> getAntiBotStatus() {
        return antiBotDetectionService.getStatus();
    }

    @GetMapping("/security/reverse-shell/status")
    public Map<String, Object> getReverseShellStatus() {
        return reverseShellDetectionService.getStatus();
    }

    @GetMapping("/security/arp-spoof/status")
    public Map<String, Object> getARPSpoofStatus() {
        return arpSpoofDetectionService.getStatus();
    }

    @GetMapping("/security/dns-tunnel/status")
    public Map<String, Object> getDNSTunnelStatus() {
        return dnsTunnelDetectionService.getStatus();
    }

    @GetMapping("/security/exploit-signature/status")
    public Map<String, Object> getExploitSignatureStatus() {
        return exploitSignatureService.getStatus();
    }

    @PostMapping("/security/exploit-signature/scan")
    public Map<String, Object> scanForExploits(@RequestParam String content, @RequestParam(defaultValue = "api") String source) {
        ExploitSignatureService.ExploitCheckResult result = exploitSignatureService.scan(content, source, "api-scan");
        Map<String, Object> response = new HashMap<>();
        response.put("blocked", result.isBlocked());
        response.put("detected", result.isDetected());
        if (result.getMatches() != null) {
            List<Map<String, Object>> matches = new ArrayList<>();
            for (ExploitSignatureService.ExploitMatch m : result.getMatches()) {
                Map<String, Object> mm = new HashMap<>();
                mm.put("name", m.getName());
                mm.put("severity", m.getSeverity().name());
                mm.put("description", m.getDescription());
                matches.add(mm);
            }
            response.put("matches", matches);
        }
        return response;
    }

    @GetMapping("/security/ssrf/status")
    public Map<String, Object> getSSRFStatus() {
        return ssrfProtectionService.getStatus();
    }

    @GetMapping("/security/xxe/status")
    public Map<String, Object> getXXEStatus() {
        return xxeProtectionService.getStatus();
    }

    @GetMapping("/security/csp/status")
    public Map<String, Object> getCSPStatus() {
        return cspEnforcementService.getStatus();
    }

    @GetMapping("/security/csp/headers")
    public Map<String, Object> getCSPHeaders() {
        Map<String, Object> response = new HashMap<>();
        response.put("headers", cspEnforcementService.getSecurityHeaders());
        return response;
    }

    @GetMapping("/security/database-firewall/status")
    public Map<String, Object> getDatabaseFirewallStatus() {
        return databaseFirewallService.getStatus();
    }

    @GetMapping("/security/dlp/status")
    public Map<String, Object> getDLPStatus() {
        return dataLossPreventionService.getStatus();
    }

    @GetMapping("/security/memory/status")
    public Map<String, Object> getMemoryProtectionStatus() {
        Map<String, Object> status = memoryProtectionService.getStatus();
        MemoryProtectionService.MemoryCheckResult check = memoryProtectionService.checkMemory();
        status.put("heapRatio", check.getHeapRatio());
        status.put("heapUsedMB", check.getHeapUsedMB());
        status.put("heapMaxMB", check.getHeapMaxMB());
        status.put("gcTimeMs", check.getGcTimeMs());
        status.put("warnings", check.getWarnings());
        return status;
    }

    @GetMapping("/security/process-injection/status")
    public Map<String, Object> getProcessInjectionStatus() {
        return processInjectionDetectionService.getStatus();
    }

    @GetMapping("/security/secure-delete/status")
    public Map<String, Object> getSecureDeleteStatus() {
        return secureFileDeletionService.getStatus();
    }

    @GetMapping("/security/forensics/status")
    public Map<String, Object> getForensicsStatus() {
        return forensicsCollectorService.getStatus();
    }

    @GetMapping("/security/incident-response/status")
    public Map<String, Object> getIncidentResponseStatus() {
        return incidentResponseService.getStatus();
    }

    @GetMapping("/security/threat-hunting/status")
    public Map<String, Object> getThreatHuntingStatus() {
        return threatHuntingService.getStatus();
    }

    @GetMapping("/security/compliance/status")
    public Map<String, Object> getComplianceStatus() {
        return complianceScannerService.getStatus();
    }

    @GetMapping("/security/anti-grief/status")
    public Map<String, Object> getAntiGriefStatus() {
        return antiGriefDetectionService.getStatus();
    }
}
