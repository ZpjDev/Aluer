package com.aluer.web;

import com.aluer.ai.DeepSeekClient;
import com.aluer.audit.SecurityAuditService;
import com.aluer.backup.BackupService;
import com.aluer.config.ServerGuardConfig;
import com.aluer.punishment.PunishmentService;
import com.aluer.profiler.PerformanceProfiler;
import com.aluer.security.NetworkThreatFusionService;
import com.aluer.service.RconClient;
import com.aluer.world.WorldManagementService;
import org.springframework.web.bind.annotation.*;

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

    public DashboardController(
            RconClient rconClient,
            PerformanceProfiler profiler,
            BackupService backupService,
            PunishmentService punishmentService,
            SecurityAuditService auditService,
            WorldManagementService worldService,
            DeepSeekClient deepSeekClient,
            ServerGuardConfig config,
            NetworkThreatFusionService networkThreatFusionService) {
        this.rconClient = rconClient;
        this.profiler = profiler;
        this.backupService = backupService;
        this.punishmentService = punishmentService;
        this.auditService = auditService;
        this.worldService = worldService;
        this.deepSeekClient = deepSeekClient;
        this.config = config;
        this.networkThreatFusionService = networkThreatFusionService;
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
}
