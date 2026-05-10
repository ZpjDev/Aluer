package com.aluer.ai;

import com.aluer.audit.SecurityAuditService;
import com.aluer.config.ServerGuardConfig;
import com.aluer.kernel.AluerKernelEngine;
import com.aluer.security.CommandExecutionGuardService;
import com.aluer.security.NetworkThreatFusionService;
import com.aluer.security.SecurityBaselineHardeningService;
import com.aluer.security.SecurityOrchestrationService;
import com.aluer.service.RconClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedDeque;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

@Service
public class AluerSovereignEngine {
    private static final Logger logger = LoggerFactory.getLogger(AluerSovereignEngine.class);
    private static final Set<String> KNOWN_WORKFLOWS = Set.of(
        "MONITOR_ONLY",
        "COMMAND_ABUSE_RESPONSE",
        "HOST_INTRUSION_RESPONSE",
        "RCON_BRUTE_FORCE_RESPONSE",
        "MC_BOT_SWARM_RESPONSE",
        "L34_DDOS_RESPONSE",
        "L7_DDOS_RESPONSE",
        "VULNERABILITY_PATCH"
    );

    private final ServerGuardConfig config;
    private final DeepSeekClient deepSeekClient;
    private final NetworkThreatFusionService networkThreatFusionService;
    private final SecurityOrchestrationService orchestrationService;
    private final AIStrategyEngine aiStrategyEngine;
    private final CommandExecutionGuardService commandExecutionGuardService;
    private final SecurityAuditService securityAuditService;
    private final SecurityBaselineHardeningService hardeningService;
    private final AluerKernelEngine aluerKernelEngine;
    private final RconClient rconClient;

    private final ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor(runnable -> {
        Thread thread = new Thread(runnable, "aluer-sovereign-engine");
        thread.setDaemon(true);
        return thread;
    });
    private final ConcurrentLinkedDeque<RuntimeDecision> decisionLog = new ConcurrentLinkedDeque<>();
    private final ConcurrentLinkedDeque<Long> actionWindow = new ConcurrentLinkedDeque<>();
    private final Map<String, Long> workflowCooldowns = new ConcurrentHashMap<>();
    private final AtomicLong totalCycles = new AtomicLong(0);
    private final AtomicLong deepSeekLedCycles = new AtomicLong(0);
    private final AtomicLong executedActions = new AtomicLong(0);

    private volatile RuntimeDecision lastDecision;

    @Autowired
    public AluerSovereignEngine(ServerGuardConfig config,
                                DeepSeekClient deepSeekClient,
                                NetworkThreatFusionService networkThreatFusionService,
                                SecurityOrchestrationService orchestrationService,
                                AIStrategyEngine aiStrategyEngine,
                                CommandExecutionGuardService commandExecutionGuardService,
                                SecurityAuditService securityAuditService,
                                SecurityBaselineHardeningService hardeningService,
                                AluerKernelEngine aluerKernelEngine,
                                RconClient rconClient) {
        this.config = config;
        this.deepSeekClient = deepSeekClient;
        this.networkThreatFusionService = networkThreatFusionService;
        this.orchestrationService = orchestrationService;
        this.aiStrategyEngine = aiStrategyEngine;
        this.commandExecutionGuardService = commandExecutionGuardService;
        this.securityAuditService = securityAuditService;
        this.hardeningService = hardeningService;
        this.aluerKernelEngine = aluerKernelEngine;
        this.rconClient = rconClient;
        startLoopIfNeeded();
    }

    public RuntimeDecision runSovereignCycle(String trigger) {
        totalCycles.incrementAndGet();
        RuntimeSnapshot snapshot = buildSnapshot(trigger);
        RuntimeDecision decision = decide(snapshot);
        RuntimeDecision applied = apply(snapshot, decision);
        lastDecision = applied;
        rememberDecision(applied);
        return applied;
    }

    public Map<String, Object> getEngineStatus() {
        Map<String, Object> hardening = hardeningService.getSummary();
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("engine", "ALUER_SOVEREIGN_LOOP");
        result.put("enabled", config.getSecurity().getAutonomy().isEnabled());
        result.put("deepseekDominant", config.getSecurity().getAutonomy().isDeepseekDominant());
        result.put("deepseekAvailable", deepSeekClient.isEnabled());
        result.put("quietConsole", config.getSecurity().getAutonomy().isQuietConsole());
        result.put("cycles", totalCycles.get());
        result.put("deepseekLedCycles", deepSeekLedCycles.get());
        result.put("executedActions", executedActions.get());
        result.put("hardeningScore", hardening.getOrDefault("score", 0));
        result.put("hardeningExposureLevel", hardening.getOrDefault("exposureLevel", "unknown"));
        Map<String, Object> kernel = aluerKernelEngine.getKernelStatus();
        result.put("kernelPulseCount", kernel.getOrDefault("pulseCount", 0));
        @SuppressWarnings("unchecked")
        Map<String, Object> lastKernelPulse = (Map<String, Object>) kernel.get("lastPulse");
        if (lastKernelPulse != null) {
            result.put("kernelHeat", lastKernelPulse.getOrDefault("heat", 0));
            result.put("kernelResonance", lastKernelPulse.getOrDefault("resonance", 0));
            result.put("kernelDirective", lastKernelPulse.get("directive"));
        }
        if (lastDecision != null) {
            result.put("lastDecision", lastDecision.toMap());
        }
        return result;
    }

    public List<RuntimeDecision> getRecentDecisions(int limit) {
        List<RuntimeDecision> result = new ArrayList<>();
        int count = 0;
        for (RuntimeDecision decision : decisionLog) {
            if (count++ >= limit) {
                break;
            }
            result.add(decision);
        }
        return result;
    }

    private void startLoopIfNeeded() {
        if (!config.getSecurity().getAutonomy().isEnabled()) {
            return;
        }

        int intervalSeconds = Math.max(15, config.getSecurity().getAutonomy().getLoopIntervalSeconds());
        scheduler.scheduleAtFixedRate(() -> {
            try {
                runSovereignCycle("scheduled");
            } catch (Exception e) {
                logger.warn("Aluer sovereign cycle failed: {}", e.getMessage());
            }
        }, intervalSeconds, intervalSeconds, TimeUnit.SECONDS);
    }

    private RuntimeSnapshot buildSnapshot(String trigger) {
        Map<String, Object> posture = networkThreatFusionService.getPosture();
        List<Map<String, Object>> topRiskIps = networkThreatFusionService.getTopRiskIPs(3);
        List<Map<String, Object>> incidents = networkThreatFusionService.getRecentIncidents(5);
        List<CommandExecutionGuardService.AntiIntrusionIncident> commandIncidents =
            commandExecutionGuardService.getRecentIncidents(5);
        SecurityBaselineHardeningService.HardeningReport hardeningReport = hardeningService.assessCurrentBaseline();
        AluerKernelEngine.KernelPulse kernelPulse = aluerKernelEngine.runKernelPulse("sovereign:" + trigger);

        int postureScore = toInt(posture.get("postureScore"));
        int criticalRiskIps = toInt(posture.get("criticalRiskIPs"));
        int primaryRiskScore = topRiskIps.isEmpty() ? 0 : toInt(topRiskIps.get(0).get("riskScore"));
        String primaryIp = topRiskIps.isEmpty() ? "" : String.valueOf(topRiskIps.get(0).getOrDefault("ip", ""));
        long criticalCommandIncidents = commandIncidents.stream()
            .filter(incident -> incident.getSeverity() >= 90)
            .count();
        boolean secondSignal = criticalRiskIps > 0
            || criticalCommandIncidents > 0
            || hardeningReport.getCriticalCount() > 0
            || hardeningReport.getHighCount() >= 2
            || kernelPulse.getResonance() >= 70;

        return new RuntimeSnapshot(
            trigger,
            posture,
            topRiskIps,
            incidents,
            commandIncidents,
            hardeningReport,
            kernelPulse,
            postureScore,
            criticalRiskIps,
            primaryRiskScore,
            primaryIp,
            secondSignal
        );
    }

    private RuntimeDecision decide(RuntimeSnapshot snapshot) {
        if (config.getSecurity().getAutonomy().isDeepseekDominant() && deepSeekClient.isEnabled()) {
            DeepSeekClient.AutonomyDirective directive = deepSeekClient.planAutonomousDefense(snapshot.toPromptContext());
            if (directive != null) {
                deepSeekLedCycles.incrementAndGet();
                return guard(snapshot, fromDirective(directive));
            }
        }
        return guard(snapshot, buildLocalDecision(snapshot));
    }

    private RuntimeDecision fromDirective(DeepSeekClient.AutonomyDirective directive) {
        return new RuntimeDecision(
            UUID.randomUUID().toString(),
            "DEEPSEEK",
            directive.getWorkflow(),
            directive.getDefenseLevel(),
            directive.getRiskScore(),
            directive.getConfidence(),
            directive.getTargetIp(),
            directive.isShouldQuarantine(),
            directive.isShouldEnableWhitelist(),
            directive.getSummary(),
            directive.getReason(),
            "planned",
            Collections.emptyMap(),
            Instant.now().toEpochMilli()
        );
    }

    private RuntimeDecision buildLocalDecision(RuntimeSnapshot snapshot) {
        AluerKernelEngine.KernelDirective kernelDirective = snapshot.kernelPulse.getDirective();
        if (kernelDirective != null && !"MONITOR_ONLY".equals(kernelDirective.getWorkflow())) {
            return new RuntimeDecision(
                UUID.randomUUID().toString(),
                "ALUER_KERNEL",
                kernelDirective.getWorkflow(),
                kernelDirective.getDefenseLevel(),
                Math.max(snapshot.primaryRiskScore, kernelDirective.getHeat()),
                0.78,
                kernelDirective.getTargetIp().isBlank() ? snapshot.primaryIp : kernelDirective.getTargetIp(),
                kernelDirective.isShouldQuarantine(),
                kernelDirective.isShouldEnableWhitelist(),
                kernelDirective.getSummary(),
                kernelDirective.getReason(),
                "planned",
                Collections.emptyMap(),
                Instant.now().toEpochMilli()
            );
        }

        int effectiveRisk = Math.max(snapshot.primaryRiskScore, 100 - snapshot.postureScore);
        String workflow = "MONITOR_ONLY";
        String defenseLevel = "NORMAL";
        boolean quarantine = false;
        boolean enableWhitelist = false;
        String summary = "态势稳定，继续监控";
        String reason = "当前风险尚未达到主动处置阈值";

        if (!snapshot.commandIncidents.isEmpty() && snapshot.commandIncidents.get(0).getSeverity() >= 90) {
            workflow = "COMMAND_ABUSE_RESPONSE";
            defenseLevel = "LOCKDOWN";
            quarantine = !snapshot.primaryIp.isBlank();
            summary = "检测到高危命令滥用";
            reason = "命令侧出现高危信号，优先执行命令滥用处置工作流。";
        } else if (snapshot.hardeningReport.getCriticalCount() > 0) {
            workflow = "VULNERABILITY_PATCH";
            defenseLevel = "ELEVATED";
            summary = "发现关键安全基线缺口";
            reason = "存在明文凭据或高危配置暴露，需要优先压缩攻击面。";
        } else if (effectiveRisk >= config.getSecurity().getAutonomy().getCriticalRiskScore()) {
            workflow = "L34_DDOS_RESPONSE";
            defenseLevel = "HIGH";
            quarantine = !snapshot.primaryIp.isBlank();
            enableWhitelist = snapshot.criticalRiskIps >= 2;
            summary = "网络风险进入严重区间";
            reason = "威胁融合评分与网络态势均已达到重防御阈值。";
        } else if (effectiveRisk >= config.getSecurity().getAutonomy().getMinRiskScoreForAction()) {
            workflow = "HOST_INTRUSION_RESPONSE";
            defenseLevel = "HIGH";
            quarantine = !snapshot.primaryIp.isBlank();
            summary = "主机与网络侧出现复合异常";
            reason = "命中多维风险阈值，执行主机入侵响应更加稳妥。";
        }

        return new RuntimeDecision(
            UUID.randomUUID().toString(),
            "LOCAL_GUARD",
            workflow,
            defenseLevel,
            effectiveRisk,
            0.68,
            snapshot.primaryIp,
            quarantine,
            enableWhitelist,
            summary,
            reason,
            "planned",
            Collections.emptyMap(),
            Instant.now().toEpochMilli()
        );
    }

    private RuntimeDecision guard(RuntimeSnapshot snapshot, RuntimeDecision decision) {
        String workflow = KNOWN_WORKFLOWS.contains(decision.workflow) ? decision.workflow : "MONITOR_ONLY";
        boolean quarantine = decision.shouldQuarantine;
        String status = decision.status;
        String reason = decision.reason;

        if (!snapshot.secondSignal && config.getSecurity().getAutonomy().isRequireSecondSignalForContainment()) {
            quarantine = false;
            reason = appendReason(reason, "缺少第二信号，跳过自动隔离");
        }

        if ("MONITOR_ONLY".equals(workflow)) {
            quarantine = false;
        }

        String cooldownKey = workflow + ":" + normalize(decision.targetIp);
        if (!"MONITOR_ONLY".equals(workflow) && isWorkflowCoolingDown(cooldownKey)) {
            workflow = "MONITOR_ONLY";
            quarantine = false;
            status = "cooldown";
            reason = appendReason(reason, "命中工作流冷却窗口");
        }

        if (!"MONITOR_ONLY".equals(workflow) && !canExecuteAnotherAction()) {
            workflow = "MONITOR_ONLY";
            quarantine = false;
            status = "rate-limited";
            reason = appendReason(reason, "超过每小时自治动作上限");
        }

        return decision.withGuardedState(workflow, quarantine, reason, status);
    }

    private RuntimeDecision apply(RuntimeSnapshot snapshot, RuntimeDecision decision) {
        Map<String, Object> execution = new LinkedHashMap<>();
        execution.put("trigger", snapshot.trigger);
        execution.put("riskScore", decision.riskScore);
        execution.put("postureScore", snapshot.postureScore);
        execution.put("primaryIp", decision.targetIp);

        aiStrategyEngine.adjustDefenseLevel(decision.defenseLevel);
        execution.put("defenseLevel", decision.defenseLevel);

        if (decision.shouldQuarantine && !decision.targetIp.isBlank()) {
            execution.put("quarantine", networkThreatFusionService.quarantineIP(
                decision.targetIp,
                "aluer-sovereign",
                decision.reason
            ));
        }

        if (!"MONITOR_ONLY".equals(decision.workflow)) {
            Map<String, Object> context = new LinkedHashMap<>();
            context.put("workflow", decision.workflow);
            context.put("riskScore", decision.riskScore);
            context.put("attacker-ip", decision.targetIp);
            context.put("actor", "aluer-sovereign");
            context.put("trigger", snapshot.trigger);
            context.put("reason", decision.reason);
            SecurityOrchestrationService.WorkflowExecutionResult result =
                orchestrationService.executeWorkflowDetailed(decision.workflow, context);
            execution.put("workflow", workflowResultMap(result));

            if (decision.shouldEnableWhitelist) {
                execution.put("whitelistEnabled", rconClient.enableWhitelist());
            }

            executedActions.incrementAndGet();
            markWorkflowExecuted(decision.workflow + ":" + normalize(decision.targetIp));
        }

        securityAuditService.logEvent(
            "ALUER_SOVEREIGN",
            decision.source,
            decision.workflow,
            decision.reason + " | trigger=" + snapshot.trigger
        );

        return decision.withExecution(execution, execution.containsKey("workflow") ? "executed" : decision.status);
    }

    private Map<String, Object> workflowResultMap(SecurityOrchestrationService.WorkflowExecutionResult result) {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("executionId", result.getExecutionId());
        map.put("workflow", result.getWorkflowName());
        map.put("status", result.getStatus());
        map.put("dryRun", result.isDryRun());
        map.put("actions", result.getActions());
        return map;
    }

    private void rememberDecision(RuntimeDecision decision) {
        decisionLog.offerFirst(decision);
        while (decisionLog.size() > 120) {
            decisionLog.pollLast();
        }
    }

    private boolean isWorkflowCoolingDown(String key) {
        Long lastRun = workflowCooldowns.get(key);
        if (lastRun == null) {
            return false;
        }
        long cooldownMillis = Math.max(30, config.getSecurity().getAutonomy().getWorkflowCooldownSeconds()) * 1000L;
        return System.currentTimeMillis() - lastRun < cooldownMillis;
    }

    private void markWorkflowExecuted(String key) {
        workflowCooldowns.put(key, System.currentTimeMillis());
        actionWindow.offerLast(System.currentTimeMillis());
        trimActionWindow();
    }

    private boolean canExecuteAnotherAction() {
        trimActionWindow();
        return actionWindow.size() < Math.max(1, config.getSecurity().getAutonomy().getMaxActionsPerHour());
    }

    private void trimActionWindow() {
        long cutoff = System.currentTimeMillis() - TimeUnit.HOURS.toMillis(1);
        while (!actionWindow.isEmpty() && actionWindow.peekFirst() != null && actionWindow.peekFirst() < cutoff) {
            actionWindow.pollFirst();
        }
    }

    private int toInt(Object value) {
        if (value instanceof Number number) {
            return number.intValue();
        }
        if (value instanceof String string) {
            try {
                return Integer.parseInt(string);
            } catch (NumberFormatException ignored) {
                return 0;
            }
        }
        return 0;
    }

    private String appendReason(String base, String suffix) {
        if (base == null || base.isBlank()) {
            return suffix;
        }
        return base + "；" + suffix;
    }

    private String normalize(String value) {
        return value == null ? "" : value;
    }

    private static final class RuntimeSnapshot {
        private final String trigger;
        private final Map<String, Object> posture;
        private final List<Map<String, Object>> topRiskIps;
        private final List<Map<String, Object>> incidents;
        private final List<CommandExecutionGuardService.AntiIntrusionIncident> commandIncidents;
        private final SecurityBaselineHardeningService.HardeningReport hardeningReport;
        private final AluerKernelEngine.KernelPulse kernelPulse;
        private final int postureScore;
        private final int criticalRiskIps;
        private final int primaryRiskScore;
        private final String primaryIp;
        private final boolean secondSignal;

        private RuntimeSnapshot(String trigger,
                                Map<String, Object> posture,
                                List<Map<String, Object>> topRiskIps,
                                List<Map<String, Object>> incidents,
                                List<CommandExecutionGuardService.AntiIntrusionIncident> commandIncidents,
                                SecurityBaselineHardeningService.HardeningReport hardeningReport,
                                AluerKernelEngine.KernelPulse kernelPulse,
                                int postureScore,
                                int criticalRiskIps,
                                int primaryRiskScore,
                                String primaryIp,
                                boolean secondSignal) {
            this.trigger = trigger;
            this.posture = posture;
            this.topRiskIps = topRiskIps;
            this.incidents = incidents;
            this.commandIncidents = commandIncidents;
            this.hardeningReport = hardeningReport;
            this.kernelPulse = kernelPulse;
            this.postureScore = postureScore;
            this.criticalRiskIps = criticalRiskIps;
            this.primaryRiskScore = primaryRiskScore;
            this.primaryIp = primaryIp == null ? "" : primaryIp;
            this.secondSignal = secondSignal;
        }

        private Map<String, Object> toPromptContext() {
            Map<String, Object> result = new LinkedHashMap<>();
            result.put("trigger", trigger);
            result.put("posture", posture);
            result.put("topRiskIps", topRiskIps);
            result.put("recentIncidents", incidents);
            result.put("kernelPulse", kernelPulse.toMap());
            result.put("commandIncidents", commandIncidents.stream().map(incident -> {
                Map<String, Object> item = new LinkedHashMap<>();
                item.put("type", incident.getType());
                item.put("severity", incident.getSeverity());
                item.put("actor", incident.getActor());
                item.put("source", incident.getSource());
                return item;
            }).toList());
            result.put("hardening", hardeningReport.toMap());
            result.put("policy", Map.of(
                "minRiskScoreForAction", 70,
                "criticalRiskScore", 90,
                "requireSecondSignalForContainment", secondSignal
            ));
            return result;
        }
    }

    public static class RuntimeDecision {
        private final String id;
        private final String source;
        private final String workflow;
        private final String defenseLevel;
        private final int riskScore;
        private final double confidence;
        private final String targetIp;
        private final boolean shouldQuarantine;
        private final boolean shouldEnableWhitelist;
        private final String summary;
        private final String reason;
        private final String status;
        private final Map<String, Object> execution;
        private final long timestamp;

        public RuntimeDecision(String id,
                               String source,
                               String workflow,
                               String defenseLevel,
                               int riskScore,
                               double confidence,
                               String targetIp,
                               boolean shouldQuarantine,
                               boolean shouldEnableWhitelist,
                               String summary,
                               String reason,
                               String status,
                               Map<String, Object> execution,
                               long timestamp) {
            this.id = id;
            this.source = source;
            this.workflow = workflow;
            this.defenseLevel = defenseLevel;
            this.riskScore = riskScore;
            this.confidence = confidence;
            this.targetIp = targetIp == null ? "" : targetIp;
            this.shouldQuarantine = shouldQuarantine;
            this.shouldEnableWhitelist = shouldEnableWhitelist;
            this.summary = summary == null ? "" : summary;
            this.reason = reason == null ? "" : reason;
            this.status = status;
            this.execution = execution;
            this.timestamp = timestamp;
        }

        public Map<String, Object> toMap() {
            Map<String, Object> result = new LinkedHashMap<>();
            result.put("id", id);
            result.put("source", source);
            result.put("workflow", workflow);
            result.put("defenseLevel", defenseLevel);
            result.put("riskScore", riskScore);
            result.put("confidence", confidence);
            result.put("targetIp", targetIp);
            result.put("shouldQuarantine", shouldQuarantine);
            result.put("shouldEnableWhitelist", shouldEnableWhitelist);
            result.put("summary", summary);
            result.put("reason", reason);
            result.put("status", status);
            result.put("execution", execution);
            result.put("timestamp", timestamp);
            return result;
        }

        private RuntimeDecision withGuardedState(String workflow, boolean shouldQuarantine, String reason, String status) {
            return new RuntimeDecision(
                id,
                source,
                workflow,
                defenseLevel,
                riskScore,
                confidence,
                targetIp,
                shouldQuarantine,
                shouldEnableWhitelist,
                summary,
                reason,
                status,
                execution,
                timestamp
            );
        }

        private RuntimeDecision withExecution(Map<String, Object> execution, String status) {
            return new RuntimeDecision(
                id,
                source,
                workflow,
                defenseLevel,
                riskScore,
                confidence,
                targetIp,
                shouldQuarantine,
                shouldEnableWhitelist,
                summary,
                reason,
                status,
                execution,
                timestamp
            );
        }
    }
}
