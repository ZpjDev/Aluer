package com.aluer.console;

import com.aluer.ai.AIAutonomousService;
import com.aluer.ai.AluerSovereignEngine;
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
import com.aluer.security.DistributedAttackMitigationService;
import com.aluer.security.HostEnforcementService;
import com.aluer.security.LoadBalancerService;
import com.aluer.security.NetworkThreatFusionService;
import com.aluer.security.SecurityBaselineHardeningService;
import com.aluer.service.RconClient;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@Service
public class AluerOperationsCenterService {
    private final ServerGuardConfig config;
    private final ResourceMonitor resourceMonitor;
    private final ProcessMonitor processMonitor;
    private final RconClient rconClient;
    private final BackupService backupService;
    private final NetworkThreatFusionService networkThreatFusionService;
    private final DDoSDefenseCoordinator ddosDefenseCoordinator;
    private final DistributedAttackMitigationService distributedAttackMitigationService;
    private final SecurityBaselineHardeningService securityBaselineHardeningService;
    private final SecurityAuditService securityAuditService;
    private final AluerSovereignEngine aluerSovereignEngine;
    private final AIAutonomousService aiAutonomousService;
    private final AluerKernelEngine aluerKernelEngine;
    private final AluerKernelTaskBus aluerKernelTaskBus;
    private final AluerSelfHealingOrchestrator aluerSelfHealingOrchestrator;
    private final HostEnforcementService hostEnforcementService;
    private final CloudflareIntegrationService cloudflareIntegrationService;
    private final LoadBalancerService loadBalancerService;
    private final CommandExecutionGuardService commandExecutionGuardService;
    private final AluerMirageShieldService aluerMirageShieldService;
    private final RemoteSshGatewayService remoteSshGatewayService;

    public AluerOperationsCenterService(ServerGuardConfig config,
                                        ResourceMonitor resourceMonitor,
                                        ProcessMonitor processMonitor,
                                        RconClient rconClient,
                                        BackupService backupService,
                                        NetworkThreatFusionService networkThreatFusionService,
                                        DDoSDefenseCoordinator ddosDefenseCoordinator,
                                        DistributedAttackMitigationService distributedAttackMitigationService,
                                        SecurityBaselineHardeningService securityBaselineHardeningService,
                                        SecurityAuditService securityAuditService,
                                        AluerSovereignEngine aluerSovereignEngine,
                                        AIAutonomousService aiAutonomousService,
                                        AluerKernelEngine aluerKernelEngine,
                                        AluerKernelTaskBus aluerKernelTaskBus,
                                        AluerSelfHealingOrchestrator aluerSelfHealingOrchestrator,
                                        HostEnforcementService hostEnforcementService,
                                        CloudflareIntegrationService cloudflareIntegrationService,
                                        LoadBalancerService loadBalancerService,
                                        CommandExecutionGuardService commandExecutionGuardService,
                                        AluerMirageShieldService aluerMirageShieldService,
                                        RemoteSshGatewayService remoteSshGatewayService) {
        this.config = config;
        this.resourceMonitor = resourceMonitor;
        this.processMonitor = processMonitor;
        this.rconClient = rconClient;
        this.backupService = backupService;
        this.networkThreatFusionService = networkThreatFusionService;
        this.ddosDefenseCoordinator = ddosDefenseCoordinator;
        this.distributedAttackMitigationService = distributedAttackMitigationService;
        this.securityBaselineHardeningService = securityBaselineHardeningService;
        this.securityAuditService = securityAuditService;
        this.aluerSovereignEngine = aluerSovereignEngine;
        this.aiAutonomousService = aiAutonomousService;
        this.aluerKernelEngine = aluerKernelEngine;
        this.aluerKernelTaskBus = aluerKernelTaskBus;
        this.aluerSelfHealingOrchestrator = aluerSelfHealingOrchestrator;
        this.hostEnforcementService = hostEnforcementService;
        this.cloudflareIntegrationService = cloudflareIntegrationService;
        this.loadBalancerService = loadBalancerService;
        this.commandExecutionGuardService = commandExecutionGuardService;
        this.aluerMirageShieldService = aluerMirageShieldService;
        this.remoteSshGatewayService = remoteSshGatewayService;
    }

    public Map<String, Object> buildOverview() {
        MetricsData metrics = resourceMonitor.collectMetrics();
        Map<String, Object> network = networkThreatFusionService.getPosture();
        Map<String, Object> ddos = ddosDefenseCoordinator.getPosture();
        Map<String, Object> sovereign = aluerSovereignEngine.getEngineStatus();
        Map<String, Object> hardening = securityBaselineHardeningService.getSummary();
        Map<String, Object> shield = aluerMirageShieldService.getShieldStatus();
        Map<String, Object> ssh = remoteSshGatewayService.getGatewayStatus();

        Map<String, Object> server = new LinkedHashMap<>();
        server.put("serviceName", config.getMinecraft().getServiceName());
        server.put("workingDir", config.getMinecraft().getWorkingDir());
        server.put("processRunning", processMonitor.isProcessRunning());
        server.put("rconConnected", rconClient.isConnected());
        server.put("metrics", Map.of(
            "tps", metrics.getTps(),
            "cpuUsage", metrics.getCpuUsage(),
            "memoryUsage", metrics.getMemoryUsage(),
            "onlinePlayers", metrics.getOnlinePlayers(),
            "connections", metrics.getConnections(),
            "tickTime", metrics.getTickTime()
        ));

        Map<String, Object> defense = new LinkedHashMap<>();
        defense.put("network", network);
        defense.put("ddos", ddos);
        defense.put("sovereign", sovereign);
        defense.put("shield", shield);
        defense.put("hardening", hardening);
        defense.put("cloudEdge", cloudflareIntegrationService.getStats());
        defense.put("hostEnforcement", hostEnforcementService.getStats());
        defense.put("distributedMitigation", distributedAttackMitigationService.getStats());
        defense.put("loadBalancer", loadBalancerService.getStats());
        defense.put("commandGuard", commandExecutionGuardService.getStats());

        Map<String, Object> kernel = new LinkedHashMap<>();
        kernel.put("engine", aluerKernelEngine.getKernelStatus());
        kernel.put("taskBus", aluerKernelTaskBus.getBusStatus());
        kernel.put("selfHealing", aluerSelfHealingOrchestrator.getStatus());

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("title", config.getDashboard().getTitle());
        result.put("subtitle", config.getDashboard().getSubtitle());
        result.put("refreshIntervalSeconds", config.getDashboard().getRefreshIntervalSeconds());
        result.put("timestamp", Instant.now().toEpochMilli());
        result.put("server", server);
        result.put("defense", defense);
        result.put("ai", aiAutonomousService.getAutonomousStats());
        result.put("kernel", kernel);
        result.put("backups", Map.of("count", backupService.getBackupHistory().size()));
        result.put("ssh", ssh);
        result.put("modules", buildModuleCatalog());
        result.put("audit", buildAuditFeed(12));
        return result;
    }

    public List<Map<String, Object>> buildModuleCatalog() {
        List<Map<String, Object>> modules = new ArrayList<>();
        Map<String, Object> shield = aluerMirageShieldService.getShieldStatus();
        Map<String, Object> sovereign = aluerSovereignEngine.getEngineStatus();
        Map<String, Object> kernel = aluerKernelEngine.getKernelStatus();
        Map<String, Object> taskBus = aluerKernelTaskBus.getBusStatus();
        Map<String, Object> selfHealing = aluerSelfHealingOrchestrator.getStatus();
        Map<String, Object> ssh = remoteSshGatewayService.getGatewayStatus();

        modules.add(module("mirage-shield", "Mirage Shield", String.valueOf(shield.get("currentMode")),
            "偏转护盾 / DDoS 防线 / 攻击者告警", intOf(shield.get("riskScore"))));
        modules.add(module("sovereign-engine", "Sovereign Loop", String.valueOf(sovereign.get("engine")),
            "主控决策环与 DeepSeek 协同", intOf(sovereign.get("kernelHeat"))));
        modules.add(module("kernel-engine", "Aluer Kernel", "ACTIVE",
            "Threat Mesh / Echo Grid / Strain Matrix", lastPulseValue(kernel, "heat")));
        modules.add(module("task-bus", "Kernel Task Bus", "QUEUE=" + taskBus.get("queuedTasks"),
            "插件协议与优先级派发", intOf(taskBus.get("executedTasks"))));
        modules.add(module("self-healing", "Self-Healing", String.valueOf(selfHealing.get("dryRun")),
            "恢复编排与软重启护栏", intOf(selfHealing.get("cycles"))));
        modules.add(module("ssh-gateway", "Remote SSH", String.valueOf(ssh.get("activeSessions")),
            "远程连接、命令执行、审计联动", intOf(ssh.get("activeSessions"))));
        modules.add(module("cloud-edge", "Cloud Edge", String.valueOf(cloudflareIntegrationService.getStats().get("enabled")),
            "边缘挑战、Under Attack、缓存侧协同", intOf(cloudflareIntegrationService.getStats().get("blockedRequests"))));
        modules.add(module("host-enforcement", "Host Enforcement", String.valueOf(hostEnforcementService.getStats().get("backend")),
            "本机封禁与速率限制", intOf(hostEnforcementService.getStats().get("managedRules"))));
        return modules;
    }

    public Map<String, Object> buildAuditFeed(int limit) {
        List<Map<String, Object>> auditEvents = securityAuditService.getRecentEvents(limit).stream()
            .map(event -> Map.<String, Object>of(
                "category", event.getCategory(),
                "player", event.getPlayer(),
                "action", event.getAction(),
                "details", event.getDetails(),
                "timestamp", String.valueOf(event.getTimestamp())
            ))
            .toList();
        List<Map<String, Object>> networkIncidents = networkThreatFusionService.getRecentIncidents(Math.max(4, limit / 2));
        List<Map<String, Object>> shieldTransitions = aluerMirageShieldService.getRecentTransitions(5).stream()
            .map(AluerMirageShieldService.ShieldTransition::toMap)
            .toList();

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("events", auditEvents);
        result.put("networkIncidents", networkIncidents);
        result.put("shieldTransitions", shieldTransitions);
        result.put("activeAlerts", securityAuditService.getActiveAlerts());
        return result;
    }

    private Map<String, Object> module(String id, String name, String status, String summary, int signal) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("id", id);
        result.put("name", name);
        result.put("status", status);
        result.put("summary", summary);
        result.put("signal", signal);
        return result;
    }

    private int lastPulseValue(Map<String, Object> kernelStatus, String field) {
        @SuppressWarnings("unchecked")
        Map<String, Object> lastPulse = (Map<String, Object>) kernelStatus.get("lastPulse");
        return lastPulse == null ? 0 : intOf(lastPulse.get(field));
    }

    private int intOf(Object value) {
        if (value instanceof Number number) {
            return number.intValue();
        }
        try {
            return value == null ? 0 : Integer.parseInt(String.valueOf(value));
        } catch (NumberFormatException ignored) {
            return 0;
        }
    }
}
