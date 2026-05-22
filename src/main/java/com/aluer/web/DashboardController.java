package com.aluer.web;

import com.aluer.ai.DeepSeekClient;
import com.aluer.anticheat.combat.AntiAutoClickerService;
import com.aluer.anticheat.combat.AntiKillAuraService;
import com.aluer.anticheat.combat.AntiReachService;
import com.aluer.anticheat.movement.AntiFlyDetectionService;
import com.aluer.anticheat.movement.AntiJesusService;
import com.aluer.anticheat.movement.AntiNoFallService;
import com.aluer.anticheat.movement.AntiScaffoldService;
import com.aluer.anticheat.movement.AntiSpeedService;
import com.aluer.anticheat.player.AntiAltAccountService;
import com.aluer.anticheat.player.AntiBotDetectionService;
import com.aluer.anticheat.player.AntiInventoryManipulationService;
import com.aluer.anticheat.player.AntiNameSpoofService;
import com.aluer.anticheat.player.AntiOfflineModeSpoofService;
import com.aluer.anticheat.player.AntiSkinSpoofService;
import com.aluer.anticheat.player.AntiVPNProxyService;
import com.aluer.anticheat.world.AntiAutoFishService;
import com.aluer.anticheat.world.AntiBaritoneService;
import com.aluer.anticheat.world.AntiChestStealService;
import com.aluer.anticheat.world.AntiDupeDetectionService;
import com.aluer.anticheat.world.AntiGriefDetectionService;
import com.aluer.anticheat.world.AntiNukerService;
import com.aluer.anticheat.world.AntiXrayDetectionService;
import com.aluer.audit.SecurityAuditService;
import com.aluer.backup.BackupService;
import com.aluer.chat.AntiAdvertisementService;
import com.aluer.chat.AntiCommandAbuseService;
import com.aluer.chat.AntiPhishingLinkService;
import com.aluer.chat.ChatFloodProtectionService;
import com.aluer.chat.PlayerPrivacyService;
import com.aluer.config.ServerGuardConfig;
import com.aluer.defense.BackdoorPluginScannerService;
import com.aluer.defense.BackupIntegrityService;
import com.aluer.defense.ComplianceScannerService;
import com.aluer.defense.ConfigTamperDetectionService;
import com.aluer.defense.CSPEnforcementService;
import com.aluer.defense.DatabaseFirewallService;
import com.aluer.defense.DataLossPreventionService;
import com.aluer.defense.ExploitSignatureService;
import com.aluer.defense.ForensicsCollectorService;
import com.aluer.defense.GeoBlockService;
import com.aluer.defense.IncidentResponseService;
import com.aluer.defense.JwtAuthService;
import com.aluer.defense.MemoryProtectionService;
import com.aluer.defense.OPPrivilegeMonitorService;
import com.aluer.defense.PlayerSessionValidationService;
import com.aluer.defense.PluginVerificationService;
import com.aluer.defense.ProcessInjectionDetectionService;
import com.aluer.defense.SecureFileDeletionService;
import com.aluer.defense.SSRFProtectionService;
import com.aluer.defense.ThreatHuntingService;
import com.aluer.defense.XXEProtectionService;
import com.aluer.network.ARPSpoofDetectionService;
import com.aluer.network.BruteForceProtectionService;
import com.aluer.network.ConnectionThrottleService;
import com.aluer.network.DNSTunnelDetectionService;
import com.aluer.network.NetworkThreatFusionService;
import com.aluer.network.PacketFloodProtectionService;
import com.aluer.network.ReverseShellDetectionService;
import com.aluer.notification.AttackReportService;
import com.aluer.notification.WebhookService;
import com.aluer.punishment.PunishmentService;
import com.aluer.profiler.PerformanceProfiler;
import com.aluer.server.AntiBookBanService;
import com.aluer.server.AntiResourcePackExploitService;
import com.aluer.server.AntiSignExploitService;
import com.aluer.server.AntiTabCompleteCrashService;
import com.aluer.server.CrashExploitProtectionService;
import com.aluer.server.LagMachineDetectionService;
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
    // Minecraft super-evolution services
    private final AntiXrayDetectionService antiXrayDetectionService;
    private final AntiFlyDetectionService antiFlyDetectionService;
    private final AntiDupeDetectionService antiDupeDetectionService;
    private final CrashExploitProtectionService crashExploitProtectionService;
    private final LagMachineDetectionService lagMachineDetectionService;
    // v3.3 new modules
    private final GeoBlockService geoBlockService;
    private final PlayerSessionValidationService playerSessionValidationService;
    private final PluginVerificationService pluginVerificationService;
    private final ConnectionThrottleService connectionThrottleService;
    private final BackupIntegrityService backupIntegrityService;
    private final AntiSkinSpoofService antiSkinSpoofService;
    // V4.0 反作弊扩展模块
    private final AntiKillAuraService antiKillAuraService;
    private final AntiReachService antiReachService;
    private final AntiSpeedService antiSpeedService;
    private final AntiJesusService antiJesusService;
    private final AntiNoFallService antiNoFallService;
    private final AntiScaffoldService antiScaffoldService;
    // V4.0 玩家行为安全模块
    private final AntiNukerService antiNukerService;
    private final AntiAutoClickerService antiAutoClickerService;
    private final AntiChestStealService antiChestStealService;
    private final AntiAutoFishService antiAutoFishService;
    private final AntiInventoryManipulationService antiInventoryManipulationService;
    private final AntiBaritoneService antiBaritoneService;
    // V4.0 服务器保护模块
    private final PacketFloodProtectionService packetFloodProtectionService;
    private final AntiSignExploitService antiSignExploitService;
    private final AntiBookBanService antiBookBanService;
    private final AntiResourcePackExploitService antiResourcePackExploitService;
    private final AntiTabCompleteCrashService antiTabCompleteCrashService;
    private final AntiOfflineModeSpoofService antiOfflineModeSpoofService;
    // V4.0 访问控制模块
    private final OPPrivilegeMonitorService opPrivilegeMonitorService;
    private final ConfigTamperDetectionService configTamperDetectionService;
    private final BackdoorPluginScannerService backdoorPluginScannerService;
    private final AntiVPNProxyService antiVPNProxyService;
    private final AntiAltAccountService antiAltAccountService;
    private final AntiNameSpoofService antiNameSpoofService;
    // V4.0 聊天社交安全模块
    private final ChatFloodProtectionService chatFloodProtectionService;
    private final AntiAdvertisementService antiAdvertisementService;
    private final AntiPhishingLinkService antiPhishingLinkService;
    private final AntiCommandAbuseService antiCommandAbuseService;
    private final PlayerPrivacyService playerPrivacyService;

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
            AntiGriefDetectionService antiGriefDetectionService,
            AntiXrayDetectionService antiXrayDetectionService,
            AntiFlyDetectionService antiFlyDetectionService,
            AntiDupeDetectionService antiDupeDetectionService,
            CrashExploitProtectionService crashExploitProtectionService,
            LagMachineDetectionService lagMachineDetectionService,
            GeoBlockService geoBlockService,
            PlayerSessionValidationService playerSessionValidationService,
            PluginVerificationService pluginVerificationService,
            ConnectionThrottleService connectionThrottleService,
            BackupIntegrityService backupIntegrityService,
            AntiSkinSpoofService antiSkinSpoofService,
            AntiKillAuraService antiKillAuraService,
            AntiReachService antiReachService,
            AntiSpeedService antiSpeedService,
            AntiJesusService antiJesusService,
            AntiNoFallService antiNoFallService,
            AntiScaffoldService antiScaffoldService,
            AntiNukerService antiNukerService,
            AntiAutoClickerService antiAutoClickerService,
            AntiChestStealService antiChestStealService,
            AntiAutoFishService antiAutoFishService,
            AntiInventoryManipulationService antiInventoryManipulationService,
            AntiBaritoneService antiBaritoneService,
            PacketFloodProtectionService packetFloodProtectionService,
            AntiSignExploitService antiSignExploitService,
            AntiBookBanService antiBookBanService,
            AntiResourcePackExploitService antiResourcePackExploitService,
            AntiTabCompleteCrashService antiTabCompleteCrashService,
            AntiOfflineModeSpoofService antiOfflineModeSpoofService,
            OPPrivilegeMonitorService opPrivilegeMonitorService,
            ConfigTamperDetectionService configTamperDetectionService,
            BackdoorPluginScannerService backdoorPluginScannerService,
            AntiVPNProxyService antiVPNProxyService,
            AntiAltAccountService antiAltAccountService,
            AntiNameSpoofService antiNameSpoofService,
            ChatFloodProtectionService chatFloodProtectionService,
            AntiAdvertisementService antiAdvertisementService,
            AntiPhishingLinkService antiPhishingLinkService,
            AntiCommandAbuseService antiCommandAbuseService,
            PlayerPrivacyService playerPrivacyService) {
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
        this.antiXrayDetectionService = antiXrayDetectionService;
        this.antiFlyDetectionService = antiFlyDetectionService;
        this.antiDupeDetectionService = antiDupeDetectionService;
        this.crashExploitProtectionService = crashExploitProtectionService;
        this.lagMachineDetectionService = lagMachineDetectionService;
        this.geoBlockService = geoBlockService;
        this.playerSessionValidationService = playerSessionValidationService;
        this.pluginVerificationService = pluginVerificationService;
        this.connectionThrottleService = connectionThrottleService;
        this.backupIntegrityService = backupIntegrityService;
        this.antiSkinSpoofService = antiSkinSpoofService;
        this.antiKillAuraService = antiKillAuraService;
        this.antiReachService = antiReachService;
        this.antiSpeedService = antiSpeedService;
        this.antiJesusService = antiJesusService;
        this.antiNoFallService = antiNoFallService;
        this.antiScaffoldService = antiScaffoldService;
        this.antiNukerService = antiNukerService;
        this.antiAutoClickerService = antiAutoClickerService;
        this.antiChestStealService = antiChestStealService;
        this.antiAutoFishService = antiAutoFishService;
        this.antiInventoryManipulationService = antiInventoryManipulationService;
        this.antiBaritoneService = antiBaritoneService;
        this.packetFloodProtectionService = packetFloodProtectionService;
        this.antiSignExploitService = antiSignExploitService;
        this.antiBookBanService = antiBookBanService;
        this.antiResourcePackExploitService = antiResourcePackExploitService;
        this.antiTabCompleteCrashService = antiTabCompleteCrashService;
        this.antiOfflineModeSpoofService = antiOfflineModeSpoofService;
        this.opPrivilegeMonitorService = opPrivilegeMonitorService;
        this.configTamperDetectionService = configTamperDetectionService;
        this.backdoorPluginScannerService = backdoorPluginScannerService;
        this.antiVPNProxyService = antiVPNProxyService;
        this.antiAltAccountService = antiAltAccountService;
        this.antiNameSpoofService = antiNameSpoofService;
        this.chatFloodProtectionService = chatFloodProtectionService;
        this.antiAdvertisementService = antiAdvertisementService;
        this.antiPhishingLinkService = antiPhishingLinkService;
        this.antiCommandAbuseService = antiCommandAbuseService;
        this.playerPrivacyService = playerPrivacyService;
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

    // --- Minecraft专项安全 API ---

    @GetMapping("/security/anti-xray/status")
    public Map<String, Object> getAntiXrayStatus() {
        return antiXrayDetectionService.getStatus();
    }

    @GetMapping("/security/anti-fly/status")
    public Map<String, Object> getAntiFlyStatus() {
        return antiFlyDetectionService.getStatus();
    }

    @GetMapping("/security/anti-dupe/status")
    public Map<String, Object> getAntiDupeStatus() {
        return antiDupeDetectionService.getStatus();
    }

    @GetMapping("/security/crash-exploit/status")
    public Map<String, Object> getCrashExploitStatus() {
        return crashExploitProtectionService.getStatus();
    }

    @GetMapping("/security/lag-machine/status")
    public Map<String, Object> getLagMachineStatus() {
        return lagMachineDetectionService.getStatus();
    }

    // --- v3.3 New Module API Endpoints ---

    @GetMapping("/security/geo-block/status")
    public Map<String, Object> getGeoBlockStatus() {
        return geoBlockService.getStatus();
    }

    @GetMapping("/security/session-validation/status")
    public Map<String, Object> getSessionValidationStatus() {
        return playerSessionValidationService.getStatus();
    }

    @GetMapping("/security/plugin-verification/status")
    public Map<String, Object> getPluginVerificationStatus() {
        return pluginVerificationService.getStatus();
    }

    @GetMapping("/security/connection-throttle/status")
    public Map<String, Object> getConnectionThrottleStatus() {
        return connectionThrottleService.getStatus();
    }

    @GetMapping("/security/backup-integrity/status")
    public Map<String, Object> getBackupIntegrityStatus() {
        return backupIntegrityService.getStatus();
    }

    @GetMapping("/security/anti-skin-spoof/status")
    public Map<String, Object> getAntiSkinSpoofStatus() {
        return antiSkinSpoofService.getStatus();
    }

    // --- V4.0 反作弊扩展 API ---

    @GetMapping("/security/anti-kill-aura/status")
    public Map<String, Object> getAntiKillAuraStatus() {
        return antiKillAuraService.getStatus();
    }

    @GetMapping("/security/anti-reach/status")
    public Map<String, Object> getAntiReachStatus() {
        return antiReachService.getStatus();
    }

    @GetMapping("/security/anti-speed/status")
    public Map<String, Object> getAntiSpeedStatus() {
        return antiSpeedService.getStatus();
    }

    @GetMapping("/security/anti-jesus/status")
    public Map<String, Object> getAntiJesusStatus() {
        return antiJesusService.getStatus();
    }

    @GetMapping("/security/anti-no-fall/status")
    public Map<String, Object> getAntiNoFallStatus() {
        return antiNoFallService.getStatus();
    }

    @GetMapping("/security/anti-scaffold/status")
    public Map<String, Object> getAntiScaffoldStatus() {
        return antiScaffoldService.getStatus();
    }

    // --- V4.0 玩家行为安全 API ---

    @GetMapping("/security/anti-nuker/status")
    public Map<String, Object> getAntiNukerStatus() {
        return antiNukerService.getStatus();
    }

    @GetMapping("/security/anti-auto-clicker/status")
    public Map<String, Object> getAntiAutoClickerStatus() {
        return antiAutoClickerService.getStatus();
    }

    @GetMapping("/security/anti-chest-steal/status")
    public Map<String, Object> getAntiChestStealStatus() {
        return antiChestStealService.getStatus();
    }

    @GetMapping("/security/anti-auto-fish/status")
    public Map<String, Object> getAntiAutoFishStatus() {
        return antiAutoFishService.getStatus();
    }

    @GetMapping("/security/anti-inventory-manipulation/status")
    public Map<String, Object> getAntiInventoryManipulationStatus() {
        return antiInventoryManipulationService.getStatus();
    }

    @GetMapping("/security/anti-baritone/status")
    public Map<String, Object> getAntiBaritoneStatus() {
        return antiBaritoneService.getStatus();
    }

    // --- V4.0 服务器保护模块 API ---

    @GetMapping("/security/packet-flood/status")
    public Map<String, Object> getPacketFloodStatus() {
        return packetFloodProtectionService.getStatus();
    }

    @GetMapping("/security/anti-sign-exploit/status")
    public Map<String, Object> getAntiSignExploitStatus() {
        return antiSignExploitService.getStatus();
    }

    @GetMapping("/security/anti-book-ban/status")
    public Map<String, Object> getAntiBookBanStatus() {
        return antiBookBanService.getStatus();
    }

    @GetMapping("/security/anti-resource-pack/status")
    public Map<String, Object> getAntiResourcePackStatus() {
        return antiResourcePackExploitService.getStatus();
    }

    @GetMapping("/security/anti-tab-complete/status")
    public Map<String, Object> getAntiTabCompleteStatus() {
        return antiTabCompleteCrashService.getStatus();
    }

    @GetMapping("/security/anti-offline-spoof/status")
    public Map<String, Object> getAntiOfflineSpoofStatus() {
        return antiOfflineModeSpoofService.getStatus();
    }

    // --- V4.0 访问控制模块 API ---

    @GetMapping("/security/op-monitor/status")
    public Map<String, Object> getOPMonitorStatus() {
        return opPrivilegeMonitorService.getStatus();
    }

    @GetMapping("/security/config-tamper/status")
    public Map<String, Object> getConfigTamperStatus() {
        return configTamperDetectionService.getStatus();
    }

    @GetMapping("/security/backdoor-scanner/status")
    public Map<String, Object> getBackdoorScannerStatus() {
        return backdoorPluginScannerService.getStatus();
    }

    @GetMapping("/security/anti-vpn/status")
    public Map<String, Object> getAntiVPNStatus() {
        return antiVPNProxyService.getStatus();
    }

    @GetMapping("/security/anti-alt/status")
    public Map<String, Object> getAntiAltStatus() {
        return antiAltAccountService.getStatus();
    }

    @GetMapping("/security/anti-name-spoof/status")
    public Map<String, Object> getAntiNameSpoofStatus() {
        return antiNameSpoofService.getStatus();
    }

    // --- V4.0 聊天社交安全模块 API ---

    @GetMapping("/security/chat-flood/status")
    public Map<String, Object> getChatFloodStatus() {
        return chatFloodProtectionService.getStatus();
    }

    @GetMapping("/security/anti-advertisement/status")
    public Map<String, Object> getAntiAdvertisementStatus() {
        return antiAdvertisementService.getStatus();
    }

    @GetMapping("/security/anti-phishing/status")
    public Map<String, Object> getAntiPhishingStatus() {
        return antiPhishingLinkService.getStatus();
    }

    @GetMapping("/security/anti-command-abuse/status")
    public Map<String, Object> getAntiCommandAbuseStatus() {
        return antiCommandAbuseService.getStatus();
    }

    @GetMapping("/security/player-privacy/status")
    public Map<String, Object> getPlayerPrivacyStatus() {
        return playerPrivacyService.getStatus();
    }
}
