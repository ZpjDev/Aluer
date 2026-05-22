package com.aluer.defense;

import com.aluer.audit.SecurityAuditService;
import com.aluer.network.CloudflareIntegrationService;
import com.aluer.service.RconClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.atomic.AtomicLong;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

@Component
public class SecurityOrchestrationService {
    private static final Logger logger = LoggerFactory.getLogger(SecurityOrchestrationService.class);

    private final HostEnforcementService hostEnforcementService;
    private final CloudflareIntegrationService cloudflareIntegrationService;
    private final RconClient rconClient;
    private final SecurityAuditService securityAuditService;
    private final Map<String, SecurityWorkflow> workflows = new ConcurrentHashMap<>();
    private final Map<String, OrchestrationTask> activeTasks = new ConcurrentHashMap<>();
    private final Queue<OrchestrationEvent> eventLog = new ConcurrentLinkedQueue<>();
    private final Map<String, List<SecurityAction>> actionHistory = new ConcurrentHashMap<>();
    private final AtomicLong totalWorkflowsExecuted = new AtomicLong(0);
    private final AtomicLong successfulWorkflows = new AtomicLong(0);
    private final AtomicLong failedWorkflows = new AtomicLong(0);

    private volatile boolean enabled = true;
    private static final int MAX_HISTORY = 10000;
    private static final DateTimeFormatter DATE_FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    public SecurityOrchestrationService() {
        this(new HostEnforcementService(), new CloudflareIntegrationService(), null, null);
    }

    @Autowired
    public SecurityOrchestrationService(HostEnforcementService hostEnforcementService,
                                        CloudflareIntegrationService cloudflareIntegrationService,
                                        RconClient rconClient,
                                        SecurityAuditService securityAuditService) {
        this.hostEnforcementService = hostEnforcementService;
        this.cloudflareIntegrationService = cloudflareIntegrationService;
        this.rconClient = rconClient;
        this.securityAuditService = securityAuditService;
        initializeDefaultWorkflows();
        logger.info("Security Orchestration Service initialized");
    }

    private void initializeDefaultWorkflows() {
        addWorkflow("DDOS_MITIGATION", Arrays.asList(
            new SecurityAction("DETECT", "threat-detection", "Analyze attack pattern"),
            new SecurityAction("BLOCK", "firewall", "Block malicious IPs"),
            new SecurityAction("NOTIFY", "alert-system", "Send alert to administrators"),
            new SecurityAction("LOG", "audit-log", "Record incident details")
        ));

        addWorkflow("INTRUSION_RESPONSE", Arrays.asList(
            new SecurityAction("DETECT", "intrusion-detection", "Identify intrusion"),
            new SecurityAction("ISOLATE", "network-isolation", "Isolate affected systems"),
            new SecurityAction("COLLECT", "forensics", "Collect evidence"),
            new SecurityAction("NOTIFY", "alert-system", "Notify security team"),
            new SecurityAction("REMEDIATE", "remediation", "Apply fixes")
        ));

        addWorkflow("DATA_BREACH", Arrays.asList(
            new SecurityAction("DETECT", "data-loss-prevention", "Detect data breach"),
            new SecurityAction("CONTAIN", "access-control", "Restrict access"),
            new SecurityAction("INVESTIGATE", "forensics", "Investigate breach"),
            new SecurityAction("NOTIFY", "compliance", "Notify stakeholders"),
            new SecurityAction("REMEDIATE", "security-patch", "Apply security patches")
        ));

        addWorkflow("MALWARE_DETECTION", Arrays.asList(
            new SecurityAction("SCAN", "antivirus", "Scan for malware"),
            new SecurityAction("QUARANTINE", "isolation", "Quarantine infected files"),
            new SecurityAction("ANALYZE", "sandbox", "Analyze malware"),
            new SecurityAction("REMEDIATE", "clean-tool", "Clean or remove malware")
        ));

        addWorkflow("BRUTE_FORCE_PROTECTION", Arrays.asList(
            new SecurityAction("DETECT", "auth-monitor", "Detect brute force"),
            new SecurityAction("BLOCK", "rate-limiter", "Block attacker IP"),
            new SecurityAction("NOTIFY", "alert-system", "Notify admin"),
            new SecurityAction("AUDIT", "log-analysis", "Audit attack attempts")
        ));

        addWorkflow("MC_STATUS_FLOOD_RESPONSE", Arrays.asList(
            new SecurityAction("DETECT", "minecraft-status", "Detect status ping flood", true),
            new SecurityAction("CORRELATE", "threat-fusion", "Correlate burst sources"),
            new SecurityAction("SCORE", "risk-engine", "Score the incident"),
            new SecurityAction("LOCAL_BLOCK_OR_RATE_LIMIT", "host-firewall", "Rate limit or block source", true),
            new SecurityAction("EDGE_BLOCK_OR_CHALLENGE", "cloud-edge", "Challenge abusive source"),
            new SecurityAction("MINECRAFT_DEFENSE_ACTION", "rcon", "Broadcast degraded state"),
            new SecurityAction("AUDIT", "audit", "Record the incident"),
            new SecurityAction("NOTIFY", "alert-system", "Notify operators")
        ));

        addWorkflow("MC_LOGIN_FLOOD_RESPONSE", Arrays.asList(
            new SecurityAction("DETECT", "minecraft-login", "Detect login burst", true),
            new SecurityAction("CORRELATE", "identity-correlation", "Correlate bot swarm"),
            new SecurityAction("SCORE", "risk-engine", "Score login abuse"),
            new SecurityAction("LOCAL_BLOCK_OR_RATE_LIMIT", "host-firewall", "Block or slow source", true),
            new SecurityAction("EDGE_BLOCK_OR_CHALLENGE", "cloud-edge", "Challenge edge"),
            new SecurityAction("MINECRAFT_DEFENSE_ACTION", "rcon", "Enable temporary whitelist"),
            new SecurityAction("AUDIT", "audit", "Record the incident"),
            new SecurityAction("NOTIFY", "alert-system", "Notify operators")
        ));

        addWorkflow("MC_BOT_SWARM_RESPONSE", Arrays.asList(
            new SecurityAction("DETECT", "bot-swarm", "Detect multi-source swarm", true),
            new SecurityAction("CORRELATE", "cluster-analysis", "Correlate source cohorts"),
            new SecurityAction("SCORE", "risk-engine", "Score swarm severity"),
            new SecurityAction("LOCAL_BLOCK_OR_RATE_LIMIT", "host-firewall", "Block swarm IPs", true),
            new SecurityAction("EDGE_BLOCK_OR_CHALLENGE", "cloud-edge", "Challenge or block edge"),
            new SecurityAction("MINECRAFT_DEFENSE_ACTION", "rcon", "Reduce access surface"),
            new SecurityAction("AUDIT", "audit", "Record bot swarm"),
            new SecurityAction("NOTIFY", "alert-system", "Notify operators")
        ));

        addWorkflow("RCON_BRUTE_FORCE_RESPONSE", Arrays.asList(
            new SecurityAction("DETECT", "rcon-monitor", "Detect RCON brute force", true),
            new SecurityAction("CORRELATE", "credential-abuse", "Correlate repeated failures"),
            new SecurityAction("SCORE", "risk-engine", "Score credential attack"),
            new SecurityAction("LOCAL_BLOCK_OR_RATE_LIMIT", "host-firewall", "Block attacker", true),
            new SecurityAction("EDGE_BLOCK_OR_CHALLENGE", "cloud-edge", "Challenge attacker"),
            new SecurityAction("MINECRAFT_DEFENSE_ACTION", "rcon", "Enable whitelist and notify"),
            new SecurityAction("AUDIT", "audit", "Record RCON abuse"),
            new SecurityAction("NOTIFY", "alert-system", "Notify operators")
        ));

        addWorkflow("L34_DDOS_RESPONSE", Arrays.asList(
            new SecurityAction("DETECT", "l34-ddos", "Detect transport flood", true),
            new SecurityAction("CORRELATE", "ddos-correlation", "Correlate flood vectors"),
            new SecurityAction("SCORE", "risk-engine", "Score ddos"),
            new SecurityAction("LOCAL_BLOCK_OR_RATE_LIMIT", "host-firewall", "Rate limit or block", true),
            new SecurityAction("EDGE_BLOCK_OR_CHALLENGE", "cloud-edge", "Escalate to edge"),
            new SecurityAction("AUDIT", "audit", "Record mitigation"),
            new SecurityAction("NOTIFY", "alert-system", "Notify operators")
        ));

        addWorkflow("L7_DDOS_RESPONSE", Arrays.asList(
            new SecurityAction("DETECT", "l7-ddos", "Detect application flood", true),
            new SecurityAction("CORRELATE", "request-patterns", "Correlate abusive paths"),
            new SecurityAction("SCORE", "risk-engine", "Score app flood"),
            new SecurityAction("LOCAL_BLOCK_OR_RATE_LIMIT", "host-firewall", "Rate limit clients", true),
            new SecurityAction("EDGE_BLOCK_OR_CHALLENGE", "cloud-edge", "Challenge at edge"),
            new SecurityAction("AUDIT", "audit", "Record flood"),
            new SecurityAction("NOTIFY", "alert-system", "Notify operators")
        ));

        addWorkflow("HOST_INTRUSION_RESPONSE", Arrays.asList(
            new SecurityAction("DETECT", "host-edr", "Detect host intrusion", true),
            new SecurityAction("CORRELATE", "host-fusion", "Correlate host evidence"),
            new SecurityAction("SCORE", "risk-engine", "Score host intrusion"),
            new SecurityAction("LOCAL_BLOCK_OR_RATE_LIMIT", "host-firewall", "Block source or isolate host", true),
            new SecurityAction("AUDIT", "audit", "Record host intrusion"),
            new SecurityAction("NOTIFY", "alert-system", "Notify operators")
        ));

        addWorkflow("PLUGIN_TAMPER_RESPONSE", Arrays.asList(
            new SecurityAction("DETECT", "integrity-monitor", "Detect plugin tamper", true),
            new SecurityAction("CORRELATE", "artifact-correlation", "Correlate changed artifacts"),
            new SecurityAction("SCORE", "risk-engine", "Score tamper impact"),
            new SecurityAction("MINECRAFT_DEFENSE_ACTION", "rcon", "Freeze unsafe admin actions"),
            new SecurityAction("AUDIT", "audit", "Record tamper event"),
            new SecurityAction("NOTIFY", "alert-system", "Notify operators")
        ));

        addWorkflow("COMMAND_ABUSE_RESPONSE", Arrays.asList(
            new SecurityAction("DETECT", "command-guard", "Detect dangerous command", true),
            new SecurityAction("CORRELATE", "command-history", "Correlate operator activity"),
            new SecurityAction("SCORE", "risk-engine", "Score abuse"),
            new SecurityAction("LOCAL_BLOCK_OR_RATE_LIMIT", "host-firewall", "Block remote source when applicable"),
            new SecurityAction("AUDIT", "audit", "Record command abuse"),
            new SecurityAction("NOTIFY", "alert-system", "Notify operators")
        ));

        addWorkflow("VULNERABILITY_PATCH", Arrays.asList(
            new SecurityAction("SCAN", "vulnerability-scanner", "Scan for vulnerabilities"),
            new SecurityAction("ASSESS", "risk-assessment", "Assess severity"),
            new SecurityAction("PRIORITIZE", "patch-management", "Prioritize patches"),
            new SecurityAction("APPLY", "patch-manager", "Apply patches"),
            new SecurityAction("VERIFY", "validation", "Verify patch effectiveness")
        ));

        addWorkflow("INSIDER_THREAT", Arrays.asList(
            new SecurityAction("DETECT", "ueba", "Detect anomalous behavior"),
            new SecurityAction("ANALYZE", "behavior-analysis", "Analyze user behavior"),
            new SecurityAction("INVESTIGATE", "forensics", "Investigate threat"),
            new SecurityAction("CONTAIN", "access-control", "Restrict access if needed"),
            new SecurityAction("REPORT", "compliance", "Generate compliance report")
        ));

        logger.info("Initialized {} security workflows", workflows.size());
    }

    public void addWorkflow(String name, List<SecurityAction> actions) {
        SecurityWorkflow workflow = new SecurityWorkflow(name, actions);
        workflows.put(name, workflow);
        logger.info("Added security workflow: {}", name);
    }

    public String executeWorkflow(String workflowName, Map<String, Object> context) {
        return executeWorkflowDetailed(workflowName, context).getExecutionId();
    }

    public WorkflowExecutionResult executeWorkflowDetailed(String workflowName, Map<String, Object> context) {
        if (!enabled) {
            return new WorkflowExecutionResult("", workflowName, "DISABLED", true, new LinkedHashMap<>());
        }

        SecurityWorkflow workflow = workflows.get(workflowName);
        if (workflow == null) {
            return new WorkflowExecutionResult("", workflowName, "NOT_FOUND", true, new LinkedHashMap<>());
        }

        String executionId = UUID.randomUUID().toString();
        totalWorkflowsExecuted.incrementAndGet();

        OrchestrationTask task = new OrchestrationTask(executionId, workflowName, context);
        activeTasks.put(executionId, task);

        logger.info("Executing workflow: {} (ID: {})", workflowName, executionId);

        for (SecurityAction action : workflow.getActions()) {
            try {
                boolean success = executeAction(action, context);
                task.addActionResult(action.getName(), success);

                if (!success && action.isCritical()) {
                    task.setStatus("FAILED");
                    failedWorkflows.incrementAndGet();
                    logEvent(executionId, workflowName, "FAILED", "Critical action failed: " + action.getName());
                    return new WorkflowExecutionResult(executionId, workflowName, "FAILED", false, new LinkedHashMap<>(task.getActionResults()));
                }

                logEvent(executionId, workflowName, "ACTION_COMPLETED", "Action: " + action.getName());

            } catch (Exception e) {
                logger.error("Error executing action {} in workflow {}: {}", action.getName(), workflowName, e.getMessage());
                task.addActionResult(action.getName(), false);

                if (action.isCritical()) {
                    task.setStatus("FAILED");
                    failedWorkflows.incrementAndGet();
                    return new WorkflowExecutionResult(executionId, workflowName, "FAILED", false, new LinkedHashMap<>(task.getActionResults()));
                }
            }
        }

        task.setStatus("COMPLETED");
        successfulWorkflows.incrementAndGet();
        logEvent(executionId, workflowName, "COMPLETED", "Workflow completed successfully");

        return new WorkflowExecutionResult(executionId, workflowName, "COMPLETED", false, new LinkedHashMap<>(task.getActionResults()));
    }

    private boolean executeAction(SecurityAction action, Map<String, Object> context) {
        switch (action.getType()) {
            case "DETECT":
                return executeDetection(action, context);
            case "CORRELATE":
                return executeCorrelation(action, context);
            case "SCORE":
                return executeScore(action, context);
            case "BLOCK":
                return executeBlocking(action, context);
            case "LOCAL_BLOCK_OR_RATE_LIMIT":
                return executeLocalBlockOrRateLimit(action, context);
            case "NOTIFY":
                return executeNotification(action, context);
            case "LOG":
                return executeLogging(action, context);
            case "EDGE_BLOCK_OR_CHALLENGE":
                return executeEdgeBlockOrChallenge(action, context);
            case "ISOLATE":
                return executeIsolation(action, context);
            case "COLLECT":
                return executeCollection(action, context);
            case "INVESTIGATE":
                return executeInvestigation(action, context);
            case "REMEDIATE":
                return executeRemediation(action, context);
            case "SCAN":
                return executeScan(action, context);
            case "QUARANTINE":
                return executeQuarantine(action, context);
            case "ANALYZE":
                return executeAnalysis(action, context);
            case "CONTAIN":
                return executeContainment(action, context);
            case "ASSESS":
                return executeAssessment(action, context);
            case "PRIORITIZE":
                return executePrioritization(action, context);
            case "APPLY":
                return executeApplication(action, context);
            case "VERIFY":
                return executeVerification(action, context);
            case "REPORT":
                return executeReporting(action, context);
            case "MINECRAFT_DEFENSE_ACTION":
                return executeMinecraftDefenseAction(action, context);
            case "AUDIT":
                return executeAuditAction(action, context);
            default:
                logger.warn("Unknown action type: {}", action.getType());
                return true;
        }
    }

    private boolean executeDetection(SecurityAction action, Map<String, Object> context) {
        logger.info("Executing detection action: {}", action.getName());
        context.put("detection-result", "threat-detected");
        context.put("detection-time", System.currentTimeMillis());
        return true;
    }

    private boolean executeCorrelation(SecurityAction action, Map<String, Object> context) {
        logger.info("Executing correlation action: {}", action.getName());
        context.put("correlated", true);
        context.put("correlation-source", action.getName());
        return true;
    }

    private boolean executeScore(SecurityAction action, Map<String, Object> context) {
        logger.info("Executing score action: {}", action.getName());
        int riskScore = ((Number) context.getOrDefault("riskScore", 85)).intValue();
        context.put("riskScore", riskScore);
        context.put("severity", riskScore >= 90 ? "CRITICAL" : riskScore >= 75 ? "HIGH" : "MEDIUM");
        return true;
    }

    private boolean executeBlocking(SecurityAction action, Map<String, Object> context) {
        logger.info("Executing blocking action: {}", action.getName());
        String attackerIP = (String) context.get("attacker-ip");
        if (attackerIP != null) {
            context.put("blocked-ips", attackerIP);
        }
        return true;
    }

    private boolean executeLocalBlockOrRateLimit(SecurityAction action, Map<String, Object> context) {
        logger.info("Executing local block/rate-limit action: {}", action.getName());
        String attackerIP = (String) context.get("attacker-ip");
        if (attackerIP == null || attackerIP.isBlank()) {
            return true;
        }

        int riskScore = ((Number) context.getOrDefault("riskScore", 80)).intValue();
        if (riskScore >= 90) {
            context.put("local-action", hostEnforcementService.blockIp(attackerIP, action.getDescription(), 60));
        } else {
            context.put("local-action", hostEnforcementService.rateLimitIp(attackerIP, 60, action.getDescription()));
        }
        return true;
    }

    private boolean executeNotification(SecurityAction action, Map<String, Object> context) {
        logger.info("Executing notification action: {}", action.getName());
        context.put("notification-sent", true);
        context.put("notification-time", System.currentTimeMillis());
        return true;
    }

    private boolean executeEdgeBlockOrChallenge(SecurityAction action, Map<String, Object> context) {
        logger.info("Executing edge block/challenge action: {}", action.getName());
        String attackerIP = (String) context.get("attacker-ip");
        if (attackerIP == null || attackerIP.isBlank()) {
            return true;
        }

        int riskScore = ((Number) context.getOrDefault("riskScore", 80)).intValue();
        if (riskScore >= 90) {
            context.put("edge-action", cloudflareIntegrationService.applyBlock(attackerIP, action.getDescription()));
        } else {
            context.put("edge-action", cloudflareIntegrationService.applyChallenge(attackerIP, action.getDescription()));
        }
        return true;
    }

    private boolean executeLogging(SecurityAction action, Map<String, Object> context) {
        logger.info("Executing logging action: {}", action.getName());
        context.put("logged", true);
        return true;
    }

    private boolean executeIsolation(SecurityAction action, Map<String, Object> context) {
        logger.info("Executing isolation action: {}", action.getName());
        context.put("isolated", true);
        return true;
    }

    private boolean executeCollection(SecurityAction action, Map<String, Object> context) {
        logger.info("Executing collection action: {}", action.getName());
        context.put("evidence-collected", true);
        return true;
    }

    private boolean executeInvestigation(SecurityAction action, Map<String, Object> context) {
        logger.info("Executing investigation action: {}", action.getName());
        context.put("investigation-complete", true);
        return true;
    }

    private boolean executeRemediation(SecurityAction action, Map<String, Object> context) {
        logger.info("Executing remediation action: {}", action.getName());
        context.put("remediation-complete", true);
        return true;
    }

    private boolean executeScan(SecurityAction action, Map<String, Object> context) {
        logger.info("Executing scan action: {}", action.getName());
        context.put("scan-complete", true);
        return true;
    }

    private boolean executeQuarantine(SecurityAction action, Map<String, Object> context) {
        logger.info("Executing quarantine action: {}", action.getName());
        context.put("quarantined", true);
        return true;
    }

    private boolean executeAnalysis(SecurityAction action, Map<String, Object> context) {
        logger.info("Executing analysis action: {}", action.getName());
        context.put("analysis-complete", true);
        return true;
    }

    private boolean executeContainment(SecurityAction action, Map<String, Object> context) {
        logger.info("Executing containment action: {}", action.getName());
        context.put("contained", true);
        return true;
    }

    private boolean executeAssessment(SecurityAction action, Map<String, Object> context) {
        logger.info("Executing assessment action: {}", action.getName());
        context.put("assessment-complete", true);
        return true;
    }

    private boolean executePrioritization(SecurityAction action, Map<String, Object> context) {
        logger.info("Executing prioritization action: {}", action.getName());
        context.put("prioritized", true);
        return true;
    }

    private boolean executeApplication(SecurityAction action, Map<String, Object> context) {
        logger.info("Executing application action: {}", action.getName());
        context.put("applied", true);
        return true;
    }

    private boolean executeVerification(SecurityAction action, Map<String, Object> context) {
        logger.info("Executing verification action: {}", action.getName());
        context.put("verified", true);
        return true;
    }

    private boolean executeReporting(SecurityAction action, Map<String, Object> context) {
        logger.info("Executing reporting action: {}", action.getName());
        context.put("reported", true);
        return true;
    }

    private boolean executeMinecraftDefenseAction(SecurityAction action, Map<String, Object> context) {
        logger.info("Executing Minecraft defense action: {}", action.getName());
        if (rconClient == null) {
            return true;
        }
        String workflow = (String) context.getOrDefault("workflow", "");
        rconClient.executeCommand("say [Aluer] Security workflow active: " + workflow);
        int riskScore = ((Number) context.getOrDefault("riskScore", 80)).intValue();
        if (workflow.contains("LOGIN") || workflow.contains("RCON") || riskScore >= 95) {
            rconClient.enableWhitelist();
        }
        context.put("minecraft-defense", "applied");
        return true;
    }

    private boolean executeAuditAction(SecurityAction action, Map<String, Object> context) {
        logger.info("Executing audit action: {}", action.getName());
        if (securityAuditService != null) {
            securityAuditService.logEvent(
                "SECURITY_WORKFLOW",
                String.valueOf(context.getOrDefault("actor", "system")),
                String.valueOf(context.getOrDefault("workflow", "unknown")),
                String.valueOf(context.getOrDefault("detection-result", action.getDescription()))
            );
        }
        context.put("audited", true);
        return true;
    }

    public OrchestrationTask getTaskStatus(String taskId) {
        return activeTasks.get(taskId);
    }

    public Map<String, Object> getStats() {
        Map<String, Object> stats = new HashMap<>();
        stats.put("enabled", enabled);
        stats.put("totalWorkflowsExecuted", totalWorkflowsExecuted.get());
        stats.put("successfulWorkflows", successfulWorkflows.get());
        stats.put("failedWorkflows", failedWorkflows.get());
        stats.put("workflowsConfigured", workflows.size());
        stats.put("activeTasks", activeTasks.size());

        double successRate = totalWorkflowsExecuted.get() > 0 ?
            successfulWorkflows.get() * 100.0 / totalWorkflowsExecuted.get() : 0;
        stats.put("successRate", String.format("%.2f%%", successRate));

        return stats;
    }

    public Map<String, SecurityWorkflow> getWorkflows() {
        return new HashMap<>(workflows);
    }

    public List<OrchestrationTask> getActiveTasks() {
        return new ArrayList<>(activeTasks.values());
    }

    public List<OrchestrationEvent> getRecentEvents(int limit) {
        List<OrchestrationEvent> events = new ArrayList<>();
        int count = 0;
        for (OrchestrationEvent event : eventLog) {
            if (count++ >= limit) break;
            events.add(event);
        }
        return events;
    }

    private void logEvent(String taskId, String workflowName, String status, String details) {
        OrchestrationEvent event = new OrchestrationEvent(taskId, workflowName, status, details, LocalDateTime.now());
        eventLog.offer(event);
        if (eventLog.size() > 5000) {
            eventLog.poll();
        }
    }

    public void enable() {
        enabled = true;
        logger.info("Security Orchestration enabled");
    }

    public void disable() {
        enabled = false;
        logger.info("Security Orchestration disabled");
    }

    public static class SecurityWorkflow {
        private final String name;
        private final List<SecurityAction> actions;

        public SecurityWorkflow(String name, List<SecurityAction> actions) {
            this.name = name;
            this.actions = actions;
        }

        public String getName() { return name; }
        public List<SecurityAction> getActions() { return actions; }
    }

    public static class SecurityAction {
        private final String type;
        private final String name;
        private final String description;
        private final boolean critical;

        public SecurityAction(String type, String name, String description) {
            this(type, name, description, false);
        }

        public SecurityAction(String type, String name, String description, boolean critical) {
            this.type = type;
            this.name = name;
            this.description = description;
            this.critical = critical;
        }

        public String getType() { return type; }
        public String getName() { return name; }
        public String getDescription() { return description; }
        public boolean isCritical() { return critical; }
    }

    public static class OrchestrationTask {
        private final String taskId;
        private final String workflowName;
        private final Map<String, Object> context;
        private final Map<String, Boolean> actionResults;
        private volatile String status;
        private final long startTime;

        public OrchestrationTask(String taskId, String workflowName, Map<String, Object> context) {
            this.taskId = taskId;
            this.workflowName = workflowName;
            this.context = context;
            this.actionResults = new HashMap<>();
            this.status = "RUNNING";
            this.startTime = System.currentTimeMillis();
        }

        public void addActionResult(String actionName, boolean success) {
            actionResults.put(actionName, success);
        }

        public String getTaskId() { return taskId; }
        public String getWorkflowName() { return workflowName; }
        public Map<String, Object> getContext() { return context; }
        public Map<String, Boolean> getActionResults() { return actionResults; }
        public String getStatus() { return status; }
        public void setStatus(String status) { this.status = status; }
        public long getStartTime() { return startTime; }
        public long getDuration() { return System.currentTimeMillis() - startTime; }
    }

    public static class OrchestrationEvent {
        private final String taskId;
        private final String workflowName;
        private final String status;
        private final String details;
        private final LocalDateTime timestamp;

        public OrchestrationEvent(String taskId, String workflowName, String status, String details, LocalDateTime timestamp) {
            this.taskId = taskId;
            this.workflowName = workflowName;
            this.status = status;
            this.details = details;
            this.timestamp = timestamp;
        }

        public String getTaskId() { return taskId; }
        public String getWorkflowName() { return workflowName; }
        public String getStatus() { return status; }
        public String getDetails() { return details; }
        public LocalDateTime getTimestamp() { return timestamp; }
    }

    public static class WorkflowExecutionResult {
        private final String executionId;
        private final String workflowName;
        private final String status;
        private final boolean dryRun;
        private final Map<String, Boolean> actions;

        public WorkflowExecutionResult(String executionId, String workflowName, String status, boolean dryRun, Map<String, Boolean> actions) {
            this.executionId = executionId;
            this.workflowName = workflowName;
            this.status = status;
            this.dryRun = dryRun;
            this.actions = actions;
        }

        public String getExecutionId() { return executionId; }
        public String getWorkflowName() { return workflowName; }
        public String getStatus() { return status; }
        public boolean isDryRun() { return dryRun; }
        public Map<String, Boolean> getActions() { return actions; }
    }
}
