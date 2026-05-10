package com.aluer.kernel;

import com.aluer.audit.SecurityAuditService;
import com.aluer.config.ServerGuardConfig;
import com.aluer.model.MetricsData;
import com.aluer.monitor.ProcessMonitor;
import com.aluer.monitor.ResourceMonitor;
import com.aluer.security.SecurityBaselineHardeningService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentLinkedDeque;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

@Service
public class AluerSelfHealingOrchestrator {
    private final ServerGuardConfig config;
    private final AluerKernelEngine aluerKernelEngine;
    private final AluerKernelTaskBus taskBus;
    private final ResourceMonitor resourceMonitor;
    private final ProcessMonitor processMonitor;
    private final SecurityBaselineHardeningService hardeningService;
    private final SecurityAuditService securityAuditService;

    private final ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor(runnable -> {
        Thread thread = new Thread(runnable, "aluer-self-healing");
        thread.setDaemon(true);
        return thread;
    });
    private final ConcurrentLinkedDeque<HealingCycle> cycleHistory = new ConcurrentLinkedDeque<>();
    private final ConcurrentLinkedDeque<Long> actionWindow = new ConcurrentLinkedDeque<>();
    private final AtomicLong cycleCount = new AtomicLong(0);

    @Autowired
    public AluerSelfHealingOrchestrator(ServerGuardConfig config,
                                        AluerKernelEngine aluerKernelEngine,
                                        AluerKernelTaskBus taskBus,
                                        ResourceMonitor resourceMonitor,
                                        ProcessMonitor processMonitor,
                                        SecurityBaselineHardeningService hardeningService,
                                        SecurityAuditService securityAuditService) {
        this.config = config;
        this.aluerKernelEngine = aluerKernelEngine;
        this.taskBus = taskBus;
        this.resourceMonitor = resourceMonitor;
        this.processMonitor = processMonitor;
        this.hardeningService = hardeningService;
        this.securityAuditService = securityAuditService;
        startLoopIfNeeded();
    }

    public HealingCycle runHealingCycle(String trigger) {
        cycleCount.incrementAndGet();
        AluerKernelEngine.KernelPulse pulse = aluerKernelEngine.runKernelPulse("healing:" + trigger);
        MetricsData metrics = resourceMonitor.collectMetrics();
        boolean processRunning = processMonitor.isProcessRunning();
        SecurityBaselineHardeningService.HardeningReport hardening = hardeningService.assessCurrentBaseline();

        List<PlannedTask> plan = buildPlan(trigger, pulse, metrics, processRunning, hardening);
        List<Map<String, Object>> results = new ArrayList<>();

        for (PlannedTask plannedTask : plan) {
            if (!canRunRecoveryAction() && plannedTask.priority >= 80) {
                results.add(Map.of(
                    "type", plannedTask.type.name(),
                    "status", "skipped-rate-limit",
                    "reason", "自愈动作触达每小时上限"
                ));
                continue;
            }

            if (config.getSecurity().getSelfHealing().isDryRun()) {
                results.add(Map.of(
                    "type", plannedTask.type.name(),
                    "status", "dry-run",
                    "payload", plannedTask.payload
                ));
                continue;
            }

            String taskId = taskBus.submitTask(plannedTask.type, "self-healing", plannedTask.priority, plannedTask.payload);
            List<AluerKernelTaskBus.KernelTaskResult> dispatched = taskBus.dispatchQueuedTasks(1);
            AluerKernelTaskBus.KernelTaskResult result = dispatched.isEmpty()
                ? new AluerKernelTaskBus.KernelTaskResult(taskId, plannedTask.type, "none", false, "No dispatch result", Map.of())
                : dispatched.get(0);
            results.add(result.toMap());
            markRecoveryAction();
        }

        HealingCycle cycle = new HealingCycle(trigger, pulse, metrics, processRunning, hardening, plan, results);
        rememberCycle(cycle);
        securityAuditService.logEvent("ALUER_SELF_HEALING", "orchestrator", trigger, cycle.getSummary());
        return cycle;
    }

    public Map<String, Object> getStatus() {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("enabled", config.getSecurity().getSelfHealing().isEnabled());
        result.put("dryRun", config.getSecurity().getSelfHealing().isDryRun());
        result.put("cycles", cycleCount.get());
        result.put("recentCycles", cycleHistory.size());
        if (!cycleHistory.isEmpty()) {
            result.put("lastCycle", cycleHistory.peekFirst().toMap());
        }
        return result;
    }

    public List<HealingCycle> getRecentCycles(int limit) {
        List<HealingCycle> result = new ArrayList<>();
        int count = 0;
        for (HealingCycle cycle : cycleHistory) {
            if (count++ >= limit) {
                break;
            }
            result.add(cycle);
        }
        return result;
    }

    private void startLoopIfNeeded() {
        if (!config.getSecurity().getSelfHealing().isEnabled()) {
            return;
        }
        int intervalSeconds = Math.max(20, config.getSecurity().getSelfHealing().getLoopIntervalSeconds());
        scheduler.scheduleAtFixedRate(() -> runHealingCycle("scheduled"), intervalSeconds, intervalSeconds, TimeUnit.SECONDS);
    }

    private List<PlannedTask> buildPlan(String trigger,
                                        AluerKernelEngine.KernelPulse pulse,
                                        MetricsData metrics,
                                        boolean processRunning,
                                        SecurityBaselineHardeningService.HardeningReport hardening) {
        List<PlannedTask> plan = new ArrayList<>();
        AluerKernelEngine.KernelDirective directive = pulse.getDirective();

        if (!processRunning) {
            if (config.getSecurity().getSelfHealing().isAutoBackupBeforeRecovery()) {
                plan.add(new PlannedTask(AluerKernelTaskBus.TaskType.PREPARE_BACKUP, 95, Map.of("reason", "pre-recovery", "trigger", trigger)));
            }
            plan.add(new PlannedTask(AluerKernelTaskBus.TaskType.PROCESS_RECOVERY, 100, Map.of("reason", "process-down", "trigger", trigger)));
        }

        if (metrics.getTps() > 0 && metrics.getTps() < config.getSecurity().getSelfHealing().getTpsEmergencyThreshold()) {
            plan.add(new PlannedTask(AluerKernelTaskBus.TaskType.RELIEVE_PRESSURE, 85, Map.of("reason", "low-tps", "tps", metrics.getTps())));
        }

        if (metrics.getCpuUsage() >= config.getSecurity().getSelfHealing().getCpuEmergencyThreshold()
            || metrics.getMemoryUsage() >= config.getSecurity().getSelfHealing().getMemoryEmergencyThreshold()) {
            plan.add(new PlannedTask(AluerKernelTaskBus.TaskType.RELIEVE_PRESSURE, 82, Map.of(
                "reason", "resource-emergency",
                "cpu", metrics.getCpuUsage(),
                "memory", metrics.getMemoryUsage()
            )));

            if (config.getSecurity().getSelfHealing().isAllowSoftRestart()
                && pulse.getHeat() >= config.getSecurity().getKernel().getLockdownHeatThreshold()) {
                plan.add(new PlannedTask(AluerKernelTaskBus.TaskType.SOFT_RESTART, 88, Map.of(
                    "reason", "resource-lockdown",
                    "heat", pulse.getHeat()
                )));
            }
        }

        if (directive.isShouldEnableWhitelist() && config.getSecurity().getSelfHealing().isAutoWhitelistOnSwarm()) {
            plan.add(new PlannedTask(AluerKernelTaskBus.TaskType.WHITELIST_LOCKDOWN, 90, Map.of(
                "reason", directive.getReason(),
                "workflow", directive.getWorkflow()
            )));
        } else if (!"MONITOR_ONLY".equals(directive.getWorkflow())
            && ("L34_DDOS_RESPONSE".equals(directive.getWorkflow())
                || "L7_DDOS_RESPONSE".equals(directive.getWorkflow())
                || "MC_BOT_SWARM_RESPONSE".equals(directive.getWorkflow()))) {
            plan.add(new PlannedTask(AluerKernelTaskBus.TaskType.SEAL_PERIMETER, 84, Map.of(
                "reason", directive.getReason(),
                "workflow", directive.getWorkflow()
            )));
        }

        if (hardening.getCriticalCount() > 0 || pulse.getResonance() >= 72) {
            plan.add(new PlannedTask(AluerKernelTaskBus.TaskType.SNAPSHOT_STATE, 72, Map.of(
                "reason", "forensic-snapshot",
                "heat", pulse.getHeat(),
                "resonance", pulse.getResonance()
            )));
        }

        if (!"NORMAL".equals(directive.getDefenseLevel())) {
            plan.add(new PlannedTask(AluerKernelTaskBus.TaskType.SYNC_DEFENSE_LEVEL, 70, Map.of(
                "defenseLevel", directive.getDefenseLevel()
            )));
        }

        return deduplicate(plan);
    }

    private List<PlannedTask> deduplicate(List<PlannedTask> plan) {
        LinkedHashMap<AluerKernelTaskBus.TaskType, PlannedTask> unique = new LinkedHashMap<>();
        for (PlannedTask task : plan) {
            unique.merge(task.type, task, (left, right) -> left.priority >= right.priority ? left : right);
        }
        return new ArrayList<>(unique.values());
    }

    private boolean canRunRecoveryAction() {
        trimActionWindow();
        return actionWindow.size() < Math.max(1, config.getSecurity().getSelfHealing().getMaxRecoveryActionsPerHour());
    }

    private void markRecoveryAction() {
        actionWindow.offerLast(System.currentTimeMillis());
        trimActionWindow();
    }

    private void trimActionWindow() {
        long cutoff = System.currentTimeMillis() - TimeUnit.HOURS.toMillis(1);
        while (!actionWindow.isEmpty() && actionWindow.peekFirst() != null && actionWindow.peekFirst() < cutoff) {
            actionWindow.pollFirst();
        }
    }

    private void rememberCycle(HealingCycle cycle) {
        cycleHistory.offerFirst(cycle);
        while (cycleHistory.size() > 120) {
            cycleHistory.pollLast();
        }
    }

    private static final class PlannedTask {
        private final AluerKernelTaskBus.TaskType type;
        private final int priority;
        private final Map<String, Object> payload;

        private PlannedTask(AluerKernelTaskBus.TaskType type, int priority, Map<String, Object> payload) {
            this.type = type;
            this.priority = priority;
            this.payload = payload;
        }

        private Map<String, Object> toMap() {
            Map<String, Object> result = new LinkedHashMap<>();
            result.put("type", type.name());
            result.put("priority", priority);
            result.put("payload", payload);
            return result;
        }
    }

    public static class HealingCycle {
        private final String id = java.util.UUID.randomUUID().toString();
        private final String trigger;
        private final AluerKernelEngine.KernelPulse pulse;
        private final MetricsData metrics;
        private final boolean processRunning;
        private final SecurityBaselineHardeningService.HardeningReport hardening;
        private final List<PlannedTask> plan;
        private final List<Map<String, Object>> results;
        private final long timestamp = Instant.now().toEpochMilli();

        public HealingCycle(String trigger,
                            AluerKernelEngine.KernelPulse pulse,
                            MetricsData metrics,
                            boolean processRunning,
                            SecurityBaselineHardeningService.HardeningReport hardening,
                            List<PlannedTask> plan,
                            List<Map<String, Object>> results) {
            this.trigger = trigger;
            this.pulse = pulse;
            this.metrics = metrics;
            this.processRunning = processRunning;
            this.hardening = hardening;
            this.plan = new ArrayList<>(plan);
            this.results = new ArrayList<>(results);
        }

        public String getSummary() {
            return "plan=" + plan.size()
                + ", results=" + results.size()
                + ", heat=" + Math.round(pulse.getHeat())
                + ", processRunning=" + processRunning;
        }

        public Map<String, Object> toMap() {
            Map<String, Object> result = new LinkedHashMap<>();
            result.put("id", id);
            result.put("trigger", trigger);
            result.put("processRunning", processRunning);
            result.put("tps", metrics.getTps());
            result.put("cpu", metrics.getCpuUsage());
            result.put("memory", metrics.getMemoryUsage());
            result.put("kernelHeat", Math.round(pulse.getHeat()));
            result.put("kernelResonance", Math.round(pulse.getResonance()));
            result.put("hardeningScore", hardening.getScore());
            result.put("plan", plan.stream().map(PlannedTask::toMap).toList());
            result.put("results", results);
            result.put("timestamp", timestamp);
            return result;
        }
    }
}
