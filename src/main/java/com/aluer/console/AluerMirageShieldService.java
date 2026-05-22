package com.aluer.console;

import com.aluer.audit.SecurityAuditService;
import com.aluer.config.ServerGuardConfig;
import com.aluer.kernel.AluerKernelEngine;
import com.aluer.kernel.AluerKernelTaskBus;
import com.aluer.kernel.AluerSelfHealingOrchestrator;
import com.aluer.network.CloudflareIntegrationService;
import com.aluer.defense.DDoSDefenseCoordinator;
import com.aluer.network.DistributedAttackMitigationService;
import com.aluer.defense.HostEnforcementService;
import com.aluer.network.LoadBalancerService;
import com.aluer.network.NetworkThreatFusionService;
import com.aluer.defense.SecurityBaselineHardeningService;
import com.aluer.defense.CommandExecutionGuardService;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentLinkedDeque;

@Service
public class AluerMirageShieldService {
    private final ServerGuardConfig config;
    private final NetworkThreatFusionService networkThreatFusionService;
    private final DDoSDefenseCoordinator ddosDefenseCoordinator;
    private final DistributedAttackMitigationService distributedAttackMitigationService;
    private final CloudflareIntegrationService cloudflareIntegrationService;
    private final HostEnforcementService hostEnforcementService;
    private final LoadBalancerService loadBalancerService;
    private final SecurityBaselineHardeningService securityBaselineHardeningService;
    private final CommandExecutionGuardService commandExecutionGuardService;
    private final AluerKernelEngine aluerKernelEngine;
    private final AluerKernelTaskBus aluerKernelTaskBus;
    private final AluerSelfHealingOrchestrator aluerSelfHealingOrchestrator;
    private final SecurityAuditService securityAuditService;
    private final ConcurrentLinkedDeque<ShieldTransition> transitions = new ConcurrentLinkedDeque<>();

    private volatile ShieldMode currentMode = ShieldMode.OBSERVE;

    public AluerMirageShieldService(ServerGuardConfig config,
                                    NetworkThreatFusionService networkThreatFusionService,
                                    DDoSDefenseCoordinator ddosDefenseCoordinator,
                                    DistributedAttackMitigationService distributedAttackMitigationService,
                                    CloudflareIntegrationService cloudflareIntegrationService,
                                    HostEnforcementService hostEnforcementService,
                                    LoadBalancerService loadBalancerService,
                                    SecurityBaselineHardeningService securityBaselineHardeningService,
                                    CommandExecutionGuardService commandExecutionGuardService,
                                    AluerKernelEngine aluerKernelEngine,
                                    AluerKernelTaskBus aluerKernelTaskBus,
                                    AluerSelfHealingOrchestrator aluerSelfHealingOrchestrator,
                                    SecurityAuditService securityAuditService) {
        this.config = config;
        this.networkThreatFusionService = networkThreatFusionService;
        this.ddosDefenseCoordinator = ddosDefenseCoordinator;
        this.distributedAttackMitigationService = distributedAttackMitigationService;
        this.cloudflareIntegrationService = cloudflareIntegrationService;
        this.hostEnforcementService = hostEnforcementService;
        this.loadBalancerService = loadBalancerService;
        this.securityBaselineHardeningService = securityBaselineHardeningService;
        this.commandExecutionGuardService = commandExecutionGuardService;
        this.aluerKernelEngine = aluerKernelEngine;
        this.aluerKernelTaskBus = aluerKernelTaskBus;
        this.aluerSelfHealingOrchestrator = aluerSelfHealingOrchestrator;
        this.securityAuditService = securityAuditService;
    }

    public Map<String, Object> getShieldStatus() {
        ShieldSnapshot snapshot = buildSnapshot("status");
        Map<String, Object> result = snapshot.toMap();
        result.put("enabled", config.getSecurity().getShield().isEnabled());
        result.put("currentMode", currentMode.name());
        result.put("recommendedMode", recommendMode(snapshot).name());
        result.put("deterrenceMessage", composeDeterrenceNotice(snapshot.primaryOffenderIp, "access denied"));
        if (!transitions.isEmpty()) {
            result.put("lastTransition", transitions.peekFirst().toMap());
        }
        return result;
    }

    public Map<String, Object> engage(String requestedMode, String reason) {
        if (!config.getSecurity().getShield().isEnabled()) {
            return Map.of("enabled", false, "status", "disabled");
        }

        ShieldSnapshot snapshot = buildSnapshot("engage");
        ShieldMode targetMode = parseMode(requestedMode, recommendMode(snapshot));
        List<Map<String, Object>> actions = new ArrayList<>();
        String actionReason = reason == null || reason.isBlank() ? "manual-console-engage" : reason.trim();
        List<Map<String, Object>> topOffenders = networkThreatFusionService.getTopRiskIPs(
            Math.max(1, config.getSecurity().getShield().getEdgeChallengeOffenderLimit())
        );
        String notice = composeDeterrenceNotice(snapshot.primaryOffenderIp, actionReason);

        switch (targetMode) {
            case OBSERVE -> {
                distributedAttackMitigationService.setDefenseLevel("LOW");
                loadBalancerService.setAlgorithm("ROUND_ROBIN");
                actions.add(action("defense-level", "LOW", true));
                actions.add(action("load-balancer", "ROUND_ROBIN", true));
            }
            case FORTIFY -> {
                distributedAttackMitigationService.setDefenseLevel("MEDIUM");
                cloudflareIntegrationService.setSecurityLevel(resolveZoneId(), "high");
                actions.add(action("defense-level", "MEDIUM", true));
                actions.add(action("edge-security-level", "high", true));
                submitTask(actions, AluerKernelTaskBus.TaskType.SNAPSHOT_STATE, 74, Map.of("reason", actionReason));
                submitTask(actions, AluerKernelTaskBus.TaskType.SYNC_DEFENSE_LEVEL, 72, Map.of("defenseLevel", "ELEVATED"));
            }
            case MIRAGE -> {
                distributedAttackMitigationService.setDefenseLevel("HIGH");
                loadBalancerService.setAlgorithm("LEAST_CONNECTIONS");
                actions.add(action("defense-level", "HIGH", true));
                actions.add(action("load-balancer", "LEAST_CONNECTIONS", true));
                challengeTopOffenders(actions, topOffenders, notice);
                rateLimitTopOffenders(actions, topOffenders, "mirage-shield");
                submitTask(actions, AluerKernelTaskBus.TaskType.RELIEVE_PRESSURE, 84, Map.of("reason", actionReason));
                submitTask(actions, AluerKernelTaskBus.TaskType.SNAPSHOT_STATE, 76, Map.of("reason", "mirage-forensics"));
            }
            case SHELTER -> {
                distributedAttackMitigationService.setDefenseLevel("HIGH");
                loadBalancerService.setAlgorithm("RESPONSE_TIME");
                actions.add(action("defense-level", "HIGH", true));
                actions.add(action("load-balancer", "RESPONSE_TIME", true));
                if (config.getSecurity().getShield().isAutoEnableUnderAttack()) {
                    CloudflareIntegrationService.EdgeActionResult edgeResult =
                        cloudflareIntegrationService.setUnderAttackMode(true, actionReason);
                    actions.add(edgeAction("under-attack", edgeResult));
                }
                challengeTopOffenders(actions, topOffenders, notice);
                blockTopOffenders(actions, topOffenders, "shelter-mode");
                submitTask(actions, AluerKernelTaskBus.TaskType.WHITELIST_LOCKDOWN, 95, Map.of(
                    "reason", actionReason,
                    "notice", notice
                ));
                submitTask(actions, AluerKernelTaskBus.TaskType.PREPARE_BACKUP, 92, Map.of("reason", "shield-shelter"));
                submitTask(actions, AluerKernelTaskBus.TaskType.SNAPSHOT_STATE, 80, Map.of("reason", "shield-shelter"));
                actions.add(action("self-healing", aluerSelfHealingOrchestrator.runHealingCycle("mirage-shield").getSummary(), true));
            }
            case RECOVERY -> {
                distributedAttackMitigationService.setDefenseLevel("MEDIUM");
                loadBalancerService.setAlgorithm("RESPONSE_TIME");
                actions.add(action("defense-level", "MEDIUM", true));
                actions.add(action("load-balancer", "RESPONSE_TIME", true));
                actions.add(action("self-healing", aluerSelfHealingOrchestrator.runHealingCycle("mirage-recovery").getSummary(), true));
                submitTask(actions, AluerKernelTaskBus.TaskType.SYNC_DEFENSE_LEVEL, 72, Map.of("defenseLevel", "ELEVATED"));
            }
        }

        List<AluerKernelTaskBus.KernelTaskResult> dispatched = aluerKernelTaskBus.dispatchQueuedTasks(4);
        if (!dispatched.isEmpty()) {
            actions.add(action("task-bus-dispatch", dispatched.stream().map(AluerKernelTaskBus.KernelTaskResult::getSummary).toList(), true));
        }

        currentMode = targetMode;
        ShieldTransition transition = new ShieldTransition(targetMode.name(), actionReason, snapshot.riskScore, snapshot.kernelHeat, actions);
        rememberTransition(transition);
        securityAuditService.logEvent("ALUER_MIRAGE_SHIELD", targetMode.name(), "ENGAGE", actionReason);

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("status", "engaged");
        result.put("mode", targetMode.name());
        result.put("reason", actionReason);
        result.put("riskScore", snapshot.riskScore);
        result.put("deterrenceMessage", notice);
        result.put("actions", actions);
        result.put("topOffenders", topOffenders);
        result.put("transition", transition.toMap());
        return result;
    }

    public List<ShieldTransition> getRecentTransitions(int limit) {
        List<ShieldTransition> result = new ArrayList<>();
        int count = 0;
        for (ShieldTransition transition : transitions) {
            if (count++ >= limit) {
                break;
            }
            result.add(transition);
        }
        return result;
    }

    public String composeDeterrenceNotice(String ip, String reason) {
        if (!config.getSecurity().getShield().isAttackerNoticeEnabled()) {
            return "";
        }
        String source = ip == null || ip.isBlank() ? "unknown-source" : ip;
        String details = reason == null || reason.isBlank() ? "policy enforcement" : reason;
        return "ALUER NOTICE: source " + source + " has been identified, recorded, and isolated. " + details + ".";
    }

    private ShieldSnapshot buildSnapshot(String trigger) {
        Map<String, Object> posture = networkThreatFusionService.getPosture();
        Map<String, Object> ddosPosture = ddosDefenseCoordinator.getPosture();
        SecurityBaselineHardeningService.HardeningReport hardening = securityBaselineHardeningService.assessCurrentBaseline();
        Map<String, Object> kernel = aluerKernelEngine.getKernelStatus();
        @SuppressWarnings("unchecked")
        Map<String, Object> lastPulse = (Map<String, Object>) kernel.getOrDefault("lastPulse", Collections.emptyMap());
        int postureScore = asInt(posture.get("postureScore"));
        int kernelHeat = asInt(lastPulse.get("heat"));
        int kernelResonance = asInt(lastPulse.get("resonance"));
        int criticalRiskIps = asInt(posture.get("criticalRiskIPs"));
        int activeIncidents = asInt(ddosPosture.get("activeIncidents"));
        int commandCritical = asInt(commandExecutionGuardService.getStats().get("criticalIncidents"));
        int hardeningCritical = hardening.getCriticalCount();
        int riskScore = Math.min(100,
            Math.max(0, 100 - postureScore)
                + kernelHeat / 2
                + kernelResonance / 3
                + criticalRiskIps * 9
                + activeIncidents * 4
                + commandCritical * 12
                + hardeningCritical * 10
        );
        List<Map<String, Object>> topOffenders = networkThreatFusionService.getTopRiskIPs(5);
        String primaryOffenderIp = topOffenders.isEmpty()
            ? ""
            : String.valueOf(topOffenders.get(0).getOrDefault("ip", ""));
        return new ShieldSnapshot(
            trigger,
            posture,
            ddosPosture,
            hardening,
            kernelHeat,
            kernelResonance,
            riskScore,
            primaryOffenderIp,
            topOffenders
        );
    }

    private ShieldMode recommendMode(ShieldSnapshot snapshot) {
        if (snapshot.riskScore >= config.getSecurity().getShield().getThreatScoreTrigger()
            || snapshot.kernelHeat >= config.getSecurity().getKernel().getLockdownHeatThreshold()) {
            return ShieldMode.SHELTER;
        }
        if (snapshot.kernelHeat >= config.getSecurity().getShield().getHeatTrigger()
            || snapshot.kernelResonance >= config.getSecurity().getShield().getResonanceTrigger()) {
            return ShieldMode.MIRAGE;
        }
        if (snapshot.riskScore >= config.getSecurity().getShield().getThreatScoreTrigger() - 20) {
            return ShieldMode.FORTIFY;
        }
        return ShieldMode.OBSERVE;
    }

    private ShieldMode parseMode(String requestedMode, ShieldMode fallback) {
        if (requestedMode == null || requestedMode.isBlank()) {
            return fallback;
        }
        try {
            return ShieldMode.valueOf(requestedMode.trim().toUpperCase());
        } catch (IllegalArgumentException ignored) {
            return fallback;
        }
    }

    private void submitTask(List<Map<String, Object>> actions,
                            AluerKernelTaskBus.TaskType type,
                            int priority,
                            Map<String, Object> payload) {
        String taskId = aluerKernelTaskBus.submitTask(type, "mirage-shield", priority, payload);
        actions.add(action("task:" + type.name(), taskId, true));
    }

    private void challengeTopOffenders(List<Map<String, Object>> actions,
                                       List<Map<String, Object>> topOffenders,
                                       String notice) {
        for (Map<String, Object> offender : topOffenders) {
            String ip = String.valueOf(offender.getOrDefault("ip", ""));
            if (ip.isBlank() || asInt(offender.get("riskScore")) < 55) {
                continue;
            }
            CloudflareIntegrationService.EdgeActionResult result = cloudflareIntegrationService.applyChallenge(ip, notice);
            actions.add(edgeAction("challenge:" + ip, result));
        }
    }

    private void rateLimitTopOffenders(List<Map<String, Object>> actions,
                                       List<Map<String, Object>> topOffenders,
                                       String reason) {
        for (Map<String, Object> offender : topOffenders) {
            String ip = String.valueOf(offender.getOrDefault("ip", ""));
            if (ip.isBlank() || asInt(offender.get("riskScore")) < 60) {
                continue;
            }
            HostEnforcementService.EnforcementActionResult result = hostEnforcementService.rateLimitIp(
                ip,
                config.getSecurity().getShield().getShelterRateLimitPerMinute(),
                reason
            );
            actions.add(hostAction("rate-limit:" + ip, result));
        }
    }

    private void blockTopOffenders(List<Map<String, Object>> actions,
                                   List<Map<String, Object>> topOffenders,
                                   String reason) {
        for (Map<String, Object> offender : topOffenders) {
            String ip = String.valueOf(offender.getOrDefault("ip", ""));
            if (ip.isBlank() || asInt(offender.get("riskScore")) < 70) {
                continue;
            }
            HostEnforcementService.EnforcementActionResult result = hostEnforcementService.blockIp(
                ip,
                reason,
                config.getSecurity().getHostEnforcement().getDefaultBlockMinutes()
            );
            actions.add(hostAction("block:" + ip, result));
        }
    }

    private Map<String, Object> action(String type, Object details, boolean success) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("type", type);
        result.put("details", details);
        result.put("success", success);
        result.put("timestamp", Instant.now().toEpochMilli());
        return result;
    }

    private Map<String, Object> edgeAction(String type, CloudflareIntegrationService.EdgeActionResult result) {
        return action(type, Map.<String, Object>of(
            "success", result.isSuccess(),
            "dryRun", result.isDryRun(),
            "mode", result.getAction(),
            "ip", result.getIp(),
            "reason", result.getReason()
        ), result.isSuccess());
    }

    private Map<String, Object> hostAction(String type, HostEnforcementService.EnforcementActionResult result) {
        return action(type, Map.of(
            "success", result.isSuccess(),
            "dryRun", result.isDryRun(),
            "backend", result.getBackend(),
            "status", result.getStatus(),
            "ip", result.getIp()
        ), result.isSuccess());
    }

    private void rememberTransition(ShieldTransition transition) {
        transitions.offerFirst(transition);
        while (transitions.size() > 120) {
            transitions.pollLast();
        }
    }

    private String resolveZoneId() {
        Object zoneId = cloudflareIntegrationService.getStats().get("zoneId");
        return zoneId == null ? "" : String.valueOf(zoneId);
    }

    private int asInt(Object value) {
        if (value instanceof Number number) {
            return number.intValue();
        }
        if (value instanceof Collection<?> collection) {
            return collection.size();
        }
        try {
            return value == null ? 0 : Integer.parseInt(String.valueOf(value));
        } catch (NumberFormatException ignored) {
            return 0;
        }
    }

    private enum ShieldMode {
        OBSERVE,
        FORTIFY,
        MIRAGE,
        SHELTER,
        RECOVERY
    }

    private record ShieldSnapshot(
        String trigger,
        Map<String, Object> posture,
        Map<String, Object> ddosPosture,
        SecurityBaselineHardeningService.HardeningReport hardening,
        int kernelHeat,
        int kernelResonance,
        int riskScore,
        String primaryOffenderIp,
        List<Map<String, Object>> topOffenders
    ) {
        private Map<String, Object> toMap() {
            Map<String, Object> result = new LinkedHashMap<>();
            result.put("trigger", trigger);
            result.put("riskScore", riskScore);
            result.put("kernelHeat", kernelHeat);
            result.put("kernelResonance", kernelResonance);
            result.put("primaryOffenderIp", primaryOffenderIp);
            result.put("topOffenders", topOffenders);
            result.put("posture", posture);
            result.put("ddos", ddosPosture);
            result.put("hardening", hardening.toMap());
            return result;
        }
    }

    public static class ShieldTransition {
        private final String mode;
        private final String reason;
        private final int riskScore;
        private final int kernelHeat;
        private final List<Map<String, Object>> actions;
        private final long timestamp;

        public ShieldTransition(String mode,
                                String reason,
                                int riskScore,
                                int kernelHeat,
                                List<Map<String, Object>> actions) {
            this.mode = mode;
            this.reason = reason;
            this.riskScore = riskScore;
            this.kernelHeat = kernelHeat;
            this.actions = actions == null ? List.of() : new ArrayList<>(actions);
            this.timestamp = Instant.now().toEpochMilli();
        }

        public String getMode() { return mode; }
        public String getReason() { return reason; }
        public int getRiskScore() { return riskScore; }
        public int getKernelHeat() { return kernelHeat; }
        public List<Map<String, Object>> getActions() { return actions; }
        public long getTimestamp() { return timestamp; }

        public Map<String, Object> toMap() {
            Map<String, Object> result = new LinkedHashMap<>();
            result.put("mode", mode);
            result.put("reason", reason);
            result.put("riskScore", riskScore);
            result.put("kernelHeat", kernelHeat);
            result.put("actions", actions);
            result.put("timestamp", timestamp);
            return result;
        }
    }
}
