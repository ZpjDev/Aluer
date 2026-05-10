package com.aluer.kernel;

import com.aluer.config.ServerGuardConfig;
import com.aluer.security.CommandExecutionGuardService;
import com.aluer.security.NetworkThreatFusionService;
import com.aluer.security.SecurityBaselineHardeningService;
import com.aluer.security.WebApplicationFirewall;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedDeque;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

@Service
public class AluerKernelEngine {
    private static final Logger logger = LoggerFactory.getLogger(AluerKernelEngine.class);

    private static final String MODULE_THREAT_MESH = "threat-mesh";
    private static final String MODULE_COMMAND_LATTICE = "command-lattice";
    private static final String MODULE_HARDENING_MATRIX = "hardening-matrix";
    private static final String MODULE_PERIMETER_WARD = "perimeter-ward";
    private static final String MODULE_ECHO_GRID = "echo-grid";

    private final ServerGuardConfig config;
    private final NetworkThreatFusionService networkThreatFusionService;
    private final SecurityBaselineHardeningService hardeningService;
    private final CommandExecutionGuardService commandExecutionGuardService;
    private final WebApplicationFirewall webApplicationFirewall;

    private final ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor(runnable -> {
        Thread thread = new Thread(runnable, "aluer-kernel");
        thread.setDaemon(true);
        return thread;
    });
    private final List<KernelModule> modules = List.of(
        new ThreatMeshModule(),
        new CommandLatticeModule(),
        new HardeningMatrixModule(),
        new PerimeterWardModule(),
        new EchoGridModule()
    );
    private final Map<String, Double> baselineWeights = new LinkedHashMap<>();
    private final Map<String, Double> activeWeights = new ConcurrentHashMap<>();
    private final Map<String, Double> lastModulePressure = new ConcurrentHashMap<>();
    private final Map<String, EchoCell> echoGrid = new ConcurrentHashMap<>();
    private final ConcurrentLinkedDeque<KernelPulse> pulseHistory = new ConcurrentLinkedDeque<>();
    private final ConcurrentLinkedDeque<KernelEvent> journal = new ConcurrentLinkedDeque<>();
    private final AtomicLong pulseCount = new AtomicLong(0);

    private volatile KernelPulse lastPulse;

    @Autowired
    public AluerKernelEngine(ServerGuardConfig config,
                             NetworkThreatFusionService networkThreatFusionService,
                             SecurityBaselineHardeningService hardeningService,
                             CommandExecutionGuardService commandExecutionGuardService,
                             WebApplicationFirewall webApplicationFirewall) {
        this.config = config;
        this.networkThreatFusionService = networkThreatFusionService;
        this.hardeningService = hardeningService;
        this.commandExecutionGuardService = commandExecutionGuardService;
        this.webApplicationFirewall = webApplicationFirewall;
        seedWeights();
        startPulseLoopIfNeeded();
    }

    public KernelPulse runKernelPulse(String trigger) {
        pulseCount.incrementAndGet();
        KernelContext context = buildContext(trigger);
        List<KernelSignal> signals = new ArrayList<>();

        for (KernelModule module : modules) {
            try {
                List<KernelSignal> emitted = module.emit(context);
                if (emitted != null && !emitted.isEmpty()) {
                    signals.addAll(emitted);
                }
            } catch (Exception e) {
                journal("module-error", "system", "模块执行失败: " + module.name(), 35);
                logger.debug("Kernel module {} failed: {}", module.name(), e.getMessage());
            }
        }

        tuneWeights(signals);
        KernelAggregate aggregate = aggregate(signals);
        KernelDirective directive = synthesizeDirective(context, aggregate);
        KernelPulse pulse = new KernelPulse(
            UUID.randomUUID().toString(),
            trigger,
            aggregate.heat,
            aggregate.resonance,
            aggregate.control,
            aggregate.dominantVector,
            aggregate.dominantModule,
            aggregate.vectorScores,
            aggregate.moduleScores,
            signals,
            directive,
            Instant.now().toEpochMilli()
        );

        rememberPulse(pulse);
        updateEchoGrid(pulse);
        journalPulse(pulse);
        lastPulse = pulse;
        return pulse;
    }

    public Map<String, Object> getKernelStatus() {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("engine", "ALUER_KERNEL");
        result.put("enabled", config.getSecurity().getKernel().isEnabled());
        result.put("pulseCount", pulseCount.get());
        result.put("activeEchoCells", echoGrid.size());
        result.put("adaptiveWeights", new LinkedHashMap<>(activeWeights));
        result.put("modulePressure", new LinkedHashMap<>(lastModulePressure));
        result.put("journalSize", journal.size());
        if (lastPulse != null) {
            result.put("lastPulse", lastPulse.toMap());
        }
        return result;
    }

    public List<KernelPulse> getRecentPulses(int limit) {
        List<KernelPulse> result = new ArrayList<>();
        int count = 0;
        for (KernelPulse pulse : pulseHistory) {
            if (count++ >= limit) {
                break;
            }
            result.add(pulse);
        }
        return result;
    }

    public List<Map<String, Object>> getRecentJournal(int limit) {
        List<Map<String, Object>> result = new ArrayList<>();
        int count = 0;
        for (KernelEvent event : journal) {
            if (count++ >= limit) {
                break;
            }
            result.add(event.toMap());
        }
        return result;
    }

    public Map<String, Object> getKernelMatrix() {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("weights", new LinkedHashMap<>(activeWeights));
        result.put("modulePressure", new LinkedHashMap<>(lastModulePressure));
        result.put("echoCells", echoGrid.values().stream()
            .sorted(Comparator.comparingDouble((EchoCell cell) -> cell.pressure).reversed())
            .limit(5)
            .map(EchoCell::toMap)
            .toList());
        if (lastPulse != null) {
            result.put("vectors", lastPulse.getVectorScores());
            result.put("directive", lastPulse.getDirective().toMap());
        }
        return result;
    }

    private void seedWeights() {
        baselineWeights.put(MODULE_THREAT_MESH, 1.12);
        baselineWeights.put(MODULE_COMMAND_LATTICE, 1.18);
        baselineWeights.put(MODULE_HARDENING_MATRIX, 1.05);
        baselineWeights.put(MODULE_PERIMETER_WARD, 0.92);
        baselineWeights.put(MODULE_ECHO_GRID, 0.84);
        activeWeights.putAll(baselineWeights);
    }

    private void startPulseLoopIfNeeded() {
        if (!config.getSecurity().getKernel().isEnabled()) {
            return;
        }

        int intervalSeconds = Math.max(15, config.getSecurity().getKernel().getPulseIntervalSeconds());
        scheduler.scheduleAtFixedRate(() -> {
            try {
                runKernelPulse("kernel-scheduled");
            } catch (Exception e) {
                logger.debug("Kernel pulse failed: {}", e.getMessage());
            }
        }, intervalSeconds, intervalSeconds, TimeUnit.SECONDS);
    }

    private KernelContext buildContext(String trigger) {
        Map<String, Object> posture = networkThreatFusionService.getPosture();
        List<Map<String, Object>> topRiskIps = networkThreatFusionService.getTopRiskIPs(5);
        List<Map<String, Object>> incidents = networkThreatFusionService.getRecentIncidents(8);
        List<CommandExecutionGuardService.AntiIntrusionIncident> commandIncidents =
            commandExecutionGuardService.getRecentIncidents(8);
        SecurityBaselineHardeningService.HardeningReport hardeningReport = hardeningService.assessCurrentBaseline();
        Map<String, Object> wafStats = webApplicationFirewall.getStats();
        return new KernelContext(trigger, posture, topRiskIps, incidents, commandIncidents, hardeningReport, wafStats);
    }

    private KernelAggregate aggregate(List<KernelSignal> signals) {
        Map<String, Double> vectorScores = new LinkedHashMap<>();
        vectorScores.put("network", 0.0);
        vectorScores.put("command", 0.0);
        vectorScores.put("integrity", 0.0);
        vectorScores.put("perimeter", 0.0);
        vectorScores.put("memory", 0.0);

        Map<String, Double> moduleScores = new LinkedHashMap<>();
        for (String module : baselineWeights.keySet()) {
            moduleScores.put(module, 0.0);
        }

        for (KernelSignal signal : signals) {
            double weight = activeWeights.getOrDefault(signal.module, 1.0);
            double weighted = clamp(signal.pressure * weight, 0, 100);
            vectorScores.compute(signal.vector, (key, value) -> clamp((value == null ? 0.0 : value) + weighted, 0, 100));
            moduleScores.compute(signal.module, (key, value) -> clamp((value == null ? 0.0 : value) + weighted, 0, 100));
        }

        lastModulePressure.clear();
        lastModulePressure.putAll(moduleScores);

        List<Double> sortedVectors = vectorScores.values().stream()
            .sorted(Comparator.reverseOrder())
            .toList();
        double averageVector = vectorScores.values().stream().mapToDouble(Double::doubleValue).sum() / vectorScores.size();
        double peakVector = sortedVectors.isEmpty() ? 0.0 : sortedVectors.get(0);
        double secondVector = sortedVectors.size() > 1 ? sortedVectors.get(1) : 0.0;
        double heat = clamp(peakVector * 0.68 + averageVector * 0.32, 0, 100);
        long energizedVectors = vectorScores.values().stream().filter(value -> value >= 35).count();
        double resonance = clamp(
            heat * 0.45
                + secondVector * 0.18
                + energizedVectors * 14.0
                + signals.size() * 2.2,
            0,
            100
        );
        double control = clamp(100 - (heat * 0.62 + resonance * 0.28), 0, 100);

        String dominantVector = vectorScores.entrySet().stream()
            .max(Map.Entry.comparingByValue())
            .map(Map.Entry::getKey)
            .orElse("network");
        String dominantModule = moduleScores.entrySet().stream()
            .max(Map.Entry.comparingByValue())
            .map(Map.Entry::getKey)
            .orElse(MODULE_THREAT_MESH);

        return new KernelAggregate(heat, resonance, control, dominantVector, dominantModule, vectorScores, moduleScores);
    }

    private KernelDirective synthesizeDirective(KernelContext context, KernelAggregate aggregate) {
        String workflow = "MONITOR_ONLY";
        String defenseLevel = "NORMAL";
        String targetIp = primaryTarget(context);
        boolean quarantine = false;
        boolean whitelist = false;
        String summary = "内核认为当前应继续观察";
        String reason = "Aluer Kernel 未发现足够强的复合压力";

        double network = aggregate.vectorScores.getOrDefault("network", 0.0);
        double command = aggregate.vectorScores.getOrDefault("command", 0.0);
        double integrity = aggregate.vectorScores.getOrDefault("integrity", 0.0);
        double perimeter = aggregate.vectorScores.getOrDefault("perimeter", 0.0);
        double memory = aggregate.vectorScores.getOrDefault("memory", 0.0);

        if (command >= 82) {
            workflow = "COMMAND_ABUSE_RESPONSE";
            summary = "内核检测到控制面压力激增";
            reason = "command-lattice 识别到高危命令链或破坏性执行迹象";
            quarantine = !targetIp.isBlank();
        } else if (integrity >= 78) {
            workflow = "VULNERABILITY_PATCH";
            summary = "内核识别到完整性与暴露面失衡";
            reason = "hardening-matrix 判定当前需要优先压缩攻击面";
        } else if (network >= 86 || (network >= 72 && memory >= 45)) {
            workflow = perimeter >= 52 ? "L7_DDOS_RESPONSE" : "L34_DDOS_RESPONSE";
            summary = "内核检测到持续的外部压力";
            reason = "threat-mesh 与 echo-grid 指向重复来源的网络挤压";
            quarantine = !targetIp.isBlank();
            whitelist = network >= 90 || context.topRiskIps.size() >= 3;
        } else if (network >= 68 && context.topRiskIps.size() >= 2) {
            workflow = "MC_BOT_SWARM_RESPONSE";
            summary = "内核识别到多源协同异常";
            reason = "高风险目标分布与事件簇更像机器人群攻";
            quarantine = !targetIp.isBlank();
            whitelist = true;
        } else if (aggregate.heat >= config.getSecurity().getKernel().getDirectiveHeatThreshold()) {
            workflow = "HOST_INTRUSION_RESPONSE";
            summary = "内核发现跨域复合压力";
            reason = "多个模块同时活跃，建议走主机入侵响应路径";
            quarantine = !targetIp.isBlank();
        }

        if (aggregate.heat >= config.getSecurity().getKernel().getLockdownHeatThreshold()) {
            defenseLevel = "LOCKDOWN";
        } else if (aggregate.heat >= 70 || aggregate.resonance >= 80) {
            defenseLevel = "HIGH";
        } else if (aggregate.heat >= 45) {
            defenseLevel = "ELEVATED";
        }

        return new KernelDirective(
            workflow,
            defenseLevel,
            targetIp,
            (int) Math.round(aggregate.heat),
            (int) Math.round(aggregate.resonance),
            aggregate.dominantVector,
            aggregate.dominantModule,
            quarantine,
            whitelist,
            summary,
            reason
        );
    }

    private void updateEchoGrid(KernelPulse pulse) {
        trimEchoGrid();
        String targetIp = pulse.directive.targetIp;
        if (targetIp == null || targetIp.isBlank()) {
            return;
        }

        EchoCell cell = echoGrid.computeIfAbsent(targetIp, EchoCell::new);
        cell.pressure = clamp(cell.pressure * 0.55 + pulse.heat * 0.75, 0, 100);
        cell.hits++;
        cell.lastVector = pulse.dominantVector;
        cell.lastSummary = pulse.directive.summary;
        cell.updatedAt = pulse.timestamp;
    }

    private void trimEchoGrid() {
        long cutoff = System.currentTimeMillis() - TimeUnit.MINUTES.toMillis(
            Math.max(10, config.getSecurity().getKernel().getEchoRetentionMinutes())
        );
        echoGrid.entrySet().removeIf(entry -> entry.getValue().updatedAt < cutoff);
    }

    private void tuneWeights(List<KernelSignal> signals) {
        if (!config.getSecurity().getKernel().isAdaptiveWeights()) {
            return;
        }

        Map<String, Double> modulePressure = new LinkedHashMap<>();
        for (String module : baselineWeights.keySet()) {
            modulePressure.put(module, 0.0);
        }

        for (KernelSignal signal : signals) {
            modulePressure.compute(signal.module, (key, value) -> clamp((value == null ? 0.0 : value) + signal.pressure, 0, 100));
        }

        for (Map.Entry<String, Double> entry : modulePressure.entrySet()) {
            double baseline = baselineWeights.getOrDefault(entry.getKey(), 1.0);
            double target = baseline + (entry.getValue() >= 80 ? 0.18 : entry.getValue() >= 55 ? 0.08 : 0.0);
            double current = activeWeights.getOrDefault(entry.getKey(), baseline);
            activeWeights.put(entry.getKey(), clamp(current * 0.82 + target * 0.18, 0.72, 1.45));
        }
    }

    private void rememberPulse(KernelPulse pulse) {
        pulseHistory.offerFirst(pulse);
        while (pulseHistory.size() > Math.max(50, config.getSecurity().getKernel().getPulseHistorySize())) {
            pulseHistory.pollLast();
        }
    }

    private void journalPulse(KernelPulse pulse) {
        journal("pulse", pulse.directive.targetIp, pulse.directive.summary, pulse.directive.heat);
        if (!"MONITOR_ONLY".equals(pulse.directive.workflow)) {
            journal("directive", pulse.directive.workflow, pulse.directive.reason, pulse.directive.resonance);
        }
    }

    private void journal(String type, String source, String details, int pressure) {
        journal.offerFirst(new KernelEvent(type, source, details, pressure, Instant.now().toEpochMilli()));
        while (journal.size() > Math.max(100, config.getSecurity().getKernel().getJournalSize())) {
            journal.pollLast();
        }
    }

    private String primaryTarget(KernelContext context) {
        if (!context.topRiskIps.isEmpty()) {
            return String.valueOf(context.topRiskIps.get(0).getOrDefault("ip", ""));
        }
        for (CommandExecutionGuardService.AntiIntrusionIncident incident : context.commandIncidents) {
            if (incident.getSource() != null && !incident.getSource().isBlank()) {
                return incident.getSource();
            }
        }
        return "";
    }

    private double clamp(double value, double min, double max) {
        return Math.max(min, Math.min(max, value));
    }

    private int toInt(Object value) {
        if (value instanceof Number number) {
            return number.intValue();
        }
        if (value instanceof String text) {
            try {
                return Integer.parseInt(text);
            } catch (NumberFormatException ignored) {
                return 0;
            }
        }
        return 0;
    }

    private interface KernelModule {
        String name();
        List<KernelSignal> emit(KernelContext context);
    }

    private final class ThreatMeshModule implements KernelModule {
        @Override
        public String name() {
            return MODULE_THREAT_MESH;
        }

        @Override
        public List<KernelSignal> emit(KernelContext context) {
            List<KernelSignal> signals = new ArrayList<>();
            int postureScore = toInt(context.posture.get("postureScore"));
            int critical = toInt(context.posture.get("criticalRiskIPs"));
            int high = toInt(context.posture.get("highRiskIPs"));
            int pressure = (100 - postureScore) + critical * 15 + high * 6;
            if (pressure > 20) {
                signals.add(new KernelSignal(name(), "network", clamp(pressure, 0, 100),
                    primaryTarget(context), "态势压力 " + pressure));
            }

            for (Map<String, Object> incident : context.incidents.stream().limit(3).toList()) {
                int riskScore = toInt(incident.get("riskScore"));
                if (riskScore >= 60) {
                    signals.add(new KernelSignal(name(), "network", clamp(riskScore * 0.85, 0, 100),
                        String.valueOf(incident.getOrDefault("ip", "")),
                        String.valueOf(incident.getOrDefault("details", "network incident"))));
                }
            }
            return signals;
        }
    }

    private final class CommandLatticeModule implements KernelModule {
        @Override
        public String name() {
            return MODULE_COMMAND_LATTICE;
        }

        @Override
        public List<KernelSignal> emit(KernelContext context) {
            List<KernelSignal> signals = new ArrayList<>();
            for (CommandExecutionGuardService.AntiIntrusionIncident incident : context.commandIncidents.stream().limit(4).toList()) {
                if (incident.getSeverity() >= 70) {
                    signals.add(new KernelSignal(name(), "command", incident.getSeverity(),
                        incident.getSource(), incident.getType() + " by " + incident.getActor()));
                }
            }
            return signals;
        }
    }

    private final class HardeningMatrixModule implements KernelModule {
        @Override
        public String name() {
            return MODULE_HARDENING_MATRIX;
        }

        @Override
        public List<KernelSignal> emit(KernelContext context) {
            List<KernelSignal> signals = new ArrayList<>();
            int pressure = context.hardeningReport.getCriticalCount() * 30
                + context.hardeningReport.getHighCount() * 16
                + context.hardeningReport.getMediumCount() * 7;
            if (pressure > 15) {
                signals.add(new KernelSignal(name(), "integrity", clamp(pressure, 0, 100),
                    "", "安全基线得分 " + context.hardeningReport.getScore()));
            }
            return signals;
        }
    }

    private final class PerimeterWardModule implements KernelModule {
        @Override
        public String name() {
            return MODULE_PERIMETER_WARD;
        }

        @Override
        public List<KernelSignal> emit(KernelContext context) {
            List<KernelSignal> signals = new ArrayList<>();
            int blocked = toInt(context.wafStats.get("blockedRequests"));
            int suspicious = toInt(context.wafStats.get("suspiciousRequests"));
            int activeClients = toInt(context.wafStats.get("activeClients"));
            int pressure = blocked * 12 + suspicious * 4 + Math.min(20, activeClients);
            if (pressure > 20) {
                signals.add(new KernelSignal(name(), "perimeter", clamp(pressure, 0, 100),
                    "", "WAF pressure blocked=" + blocked + " suspicious=" + suspicious));
            }
            return signals;
        }
    }

    private final class EchoGridModule implements KernelModule {
        @Override
        public String name() {
            return MODULE_ECHO_GRID;
        }

        @Override
        public List<KernelSignal> emit(KernelContext context) {
            trimEchoGrid();
            EchoCell top = echoGrid.values().stream()
                .sorted(Comparator.comparingDouble((EchoCell cell) -> cell.pressure).reversed())
                .findFirst()
                .orElse(null);
            if (top == null || top.pressure < 25) {
                return Collections.emptyList();
            }
            return List.of(new KernelSignal(name(), "memory", top.pressure, top.target, top.lastSummary));
        }
    }

    private static final class KernelContext {
        private final String trigger;
        private final Map<String, Object> posture;
        private final List<Map<String, Object>> topRiskIps;
        private final List<Map<String, Object>> incidents;
        private final List<CommandExecutionGuardService.AntiIntrusionIncident> commandIncidents;
        private final SecurityBaselineHardeningService.HardeningReport hardeningReport;
        private final Map<String, Object> wafStats;

        private KernelContext(String trigger,
                              Map<String, Object> posture,
                              List<Map<String, Object>> topRiskIps,
                              List<Map<String, Object>> incidents,
                              List<CommandExecutionGuardService.AntiIntrusionIncident> commandIncidents,
                              SecurityBaselineHardeningService.HardeningReport hardeningReport,
                              Map<String, Object> wafStats) {
            this.trigger = trigger;
            this.posture = posture;
            this.topRiskIps = topRiskIps;
            this.incidents = incidents;
            this.commandIncidents = commandIncidents;
            this.hardeningReport = hardeningReport;
            this.wafStats = wafStats;
        }
    }

    private static final class KernelAggregate {
        private final double heat;
        private final double resonance;
        private final double control;
        private final String dominantVector;
        private final String dominantModule;
        private final Map<String, Double> vectorScores;
        private final Map<String, Double> moduleScores;

        private KernelAggregate(double heat,
                                double resonance,
                                double control,
                                String dominantVector,
                                String dominantModule,
                                Map<String, Double> vectorScores,
                                Map<String, Double> moduleScores) {
            this.heat = heat;
            this.resonance = resonance;
            this.control = control;
            this.dominantVector = dominantVector;
            this.dominantModule = dominantModule;
            this.vectorScores = vectorScores;
            this.moduleScores = moduleScores;
        }
    }

    public static class KernelSignal {
        private final String module;
        private final String vector;
        private final double pressure;
        private final String target;
        private final String detail;

        public KernelSignal(String module, String vector, double pressure, String target, String detail) {
            this.module = module;
            this.vector = vector;
            this.pressure = pressure;
            this.target = target == null ? "" : target;
            this.detail = detail == null ? "" : detail;
        }

        public Map<String, Object> toMap() {
            Map<String, Object> result = new LinkedHashMap<>();
            result.put("module", module);
            result.put("vector", vector);
            result.put("pressure", Math.round(pressure));
            result.put("target", target);
            result.put("detail", detail);
            return result;
        }
    }

    public static class KernelDirective {
        private final String workflow;
        private final String defenseLevel;
        private final String targetIp;
        private final int heat;
        private final int resonance;
        private final String dominantVector;
        private final String dominantModule;
        private final boolean shouldQuarantine;
        private final boolean shouldEnableWhitelist;
        private final String summary;
        private final String reason;

        public KernelDirective(String workflow,
                               String defenseLevel,
                               String targetIp,
                               int heat,
                               int resonance,
                               String dominantVector,
                               String dominantModule,
                               boolean shouldQuarantine,
                               boolean shouldEnableWhitelist,
                               String summary,
                               String reason) {
            this.workflow = workflow;
            this.defenseLevel = defenseLevel;
            this.targetIp = targetIp == null ? "" : targetIp;
            this.heat = heat;
            this.resonance = resonance;
            this.dominantVector = dominantVector;
            this.dominantModule = dominantModule;
            this.shouldQuarantine = shouldQuarantine;
            this.shouldEnableWhitelist = shouldEnableWhitelist;
            this.summary = summary;
            this.reason = reason;
        }

        public String getWorkflow() { return workflow; }
        public String getDefenseLevel() { return defenseLevel; }
        public String getTargetIp() { return targetIp; }
        public int getHeat() { return heat; }
        public int getResonance() { return resonance; }
        public boolean isShouldQuarantine() { return shouldQuarantine; }
        public boolean isShouldEnableWhitelist() { return shouldEnableWhitelist; }
        public String getSummary() { return summary; }
        public String getReason() { return reason; }

        public Map<String, Object> toMap() {
            Map<String, Object> result = new LinkedHashMap<>();
            result.put("workflow", workflow);
            result.put("defenseLevel", defenseLevel);
            result.put("targetIp", targetIp);
            result.put("heat", heat);
            result.put("resonance", resonance);
            result.put("dominantVector", dominantVector);
            result.put("dominantModule", dominantModule);
            result.put("shouldQuarantine", shouldQuarantine);
            result.put("shouldEnableWhitelist", shouldEnableWhitelist);
            result.put("summary", summary);
            result.put("reason", reason);
            return result;
        }
    }

    public static class KernelPulse {
        private final String id;
        private final String trigger;
        private final double heat;
        private final double resonance;
        private final double control;
        private final String dominantVector;
        private final String dominantModule;
        private final Map<String, Double> vectorScores;
        private final Map<String, Double> moduleScores;
        private final List<KernelSignal> signals;
        private final KernelDirective directive;
        private final long timestamp;

        public KernelPulse(String id,
                           String trigger,
                           double heat,
                           double resonance,
                           double control,
                           String dominantVector,
                           String dominantModule,
                           Map<String, Double> vectorScores,
                           Map<String, Double> moduleScores,
                           List<KernelSignal> signals,
                           KernelDirective directive,
                           long timestamp) {
            this.id = id;
            this.trigger = trigger;
            this.heat = heat;
            this.resonance = resonance;
            this.control = control;
            this.dominantVector = dominantVector;
            this.dominantModule = dominantModule;
            this.vectorScores = new LinkedHashMap<>(vectorScores);
            this.moduleScores = new LinkedHashMap<>(moduleScores);
            this.signals = new ArrayList<>(signals);
            this.directive = directive;
            this.timestamp = timestamp;
        }

        public double getHeat() { return heat; }
        public double getResonance() { return resonance; }
        public String getDominantVector() { return dominantVector; }
        public KernelDirective getDirective() { return directive; }
        public Map<String, Double> getVectorScores() { return vectorScores; }

        public Map<String, Object> toMap() {
            Map<String, Object> result = new LinkedHashMap<>();
            result.put("id", id);
            result.put("trigger", trigger);
            result.put("heat", Math.round(heat));
            result.put("resonance", Math.round(resonance));
            result.put("control", Math.round(control));
            result.put("dominantVector", dominantVector);
            result.put("dominantModule", dominantModule);
            result.put("vectorScores", vectorScores);
            result.put("moduleScores", moduleScores);
            result.put("signalCount", signals.size());
            result.put("signals", signals.stream().limit(6).map(KernelSignal::toMap).toList());
            result.put("directive", directive.toMap());
            result.put("timestamp", timestamp);
            return result;
        }
    }

    private static final class EchoCell {
        private final String target;
        private double pressure;
        private long hits;
        private String lastVector = "memory";
        private String lastSummary = "";
        private long updatedAt = Instant.now().toEpochMilli();

        private EchoCell(String target) {
            this.target = target;
        }

        private Map<String, Object> toMap() {
            Map<String, Object> result = new LinkedHashMap<>();
            result.put("target", target);
            result.put("pressure", Math.round(pressure));
            result.put("hits", hits);
            result.put("lastVector", lastVector);
            result.put("lastSummary", lastSummary);
            result.put("updatedAt", updatedAt);
            return result;
        }
    }

    private static final class KernelEvent {
        private final String type;
        private final String source;
        private final String details;
        private final int pressure;
        private final long timestamp;

        private KernelEvent(String type, String source, String details, int pressure, long timestamp) {
            this.type = type;
            this.source = source == null ? "" : source;
            this.details = details == null ? "" : details;
            this.pressure = pressure;
            this.timestamp = timestamp;
        }

        private Map<String, Object> toMap() {
            Map<String, Object> result = new LinkedHashMap<>();
            result.put("type", type);
            result.put("source", source);
            result.put("details", details);
            result.put("pressure", pressure);
            result.put("timestamp", timestamp);
            return result;
        }
    }
}
