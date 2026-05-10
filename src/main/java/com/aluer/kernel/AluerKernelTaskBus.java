package com.aluer.kernel;

import com.aluer.ai.AIStrategyEngine;
import com.aluer.audit.SecurityAuditService;
import com.aluer.backup.BackupService;
import com.aluer.config.ServerGuardConfig;
import com.aluer.monitor.ProcessMonitor;
import com.aluer.service.RconClient;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentLinkedDeque;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

@Service
public class AluerKernelTaskBus {
    private final ServerGuardConfig config;
    private final ProcessMonitor processMonitor;
    private final BackupService backupService;
    private final RconClient rconClient;
    private final AIStrategyEngine aiStrategyEngine;
    private final SecurityAuditService securityAuditService;
    private final AluerKernelEngine aluerKernelEngine;

    private final ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor(runnable -> {
        Thread thread = new Thread(runnable, "aluer-kernel-task-bus");
        thread.setDaemon(true);
        return thread;
    });
    private final ConcurrentLinkedDeque<KernelTask> queue = new ConcurrentLinkedDeque<>();
    private final ConcurrentLinkedDeque<KernelTaskResult> history = new ConcurrentLinkedDeque<>();
    private final List<KernelPlugin> plugins;
    private final AtomicLong submittedTasks = new AtomicLong(0);
    private final AtomicLong executedTasks = new AtomicLong(0);

    @Autowired
    public AluerKernelTaskBus(ServerGuardConfig config,
                              ProcessMonitor processMonitor,
                              BackupService backupService,
                              RconClient rconClient,
                              AIStrategyEngine aiStrategyEngine,
                              SecurityAuditService securityAuditService,
                              AluerKernelEngine aluerKernelEngine) {
        this.config = config;
        this.processMonitor = processMonitor;
        this.backupService = backupService;
        this.rconClient = rconClient;
        this.aiStrategyEngine = aiStrategyEngine;
        this.securityAuditService = securityAuditService;
        this.aluerKernelEngine = aluerKernelEngine;
        this.plugins = List.of(
            new InsightPlugin(),
            new StabilityPlugin(),
            new DefensePlugin(),
            new RecoveryPlugin()
        );
        startDispatcherIfNeeded();
    }

    public String submitTask(TaskType type, String source, int priority, Map<String, Object> payload) {
        KernelTask task = new KernelTask(type, source, priority, payload);
        submitTask(task);
        return task.getId();
    }

    public void submitTask(KernelTask task) {
        if (queue.size() >= Math.max(50, config.getSecurity().getTaskBus().getQueueLimit())) {
            queue.pollLast();
        }
        enqueueByPriority(task);
        submittedTasks.incrementAndGet();

        if (config.getSecurity().getTaskBus().isAutoDispatch()) {
            dispatchQueuedTasks(1);
        }
    }

    public List<KernelTaskResult> dispatchQueuedTasks(int limit) {
        List<KernelTaskResult> results = new ArrayList<>();
        int dispatched = 0;
        while (dispatched < Math.max(1, limit)) {
            KernelTask task = queue.pollFirst();
            if (task == null) {
                break;
            }
            KernelTaskResult result = dispatch(task);
            rememberResult(result);
            results.add(result);
            dispatched++;
        }
        return results;
    }

    public Map<String, Object> getBusStatus() {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("enabled", config.getSecurity().getTaskBus().isEnabled());
        result.put("autoDispatch", config.getSecurity().getTaskBus().isAutoDispatch());
        result.put("queuedTasks", queue.size());
        result.put("submittedTasks", submittedTasks.get());
        result.put("executedTasks", executedTasks.get());
        result.put("registeredPlugins", plugins.stream().map(KernelPlugin::descriptor).toList());
        return result;
    }

    public List<Map<String, Object>> getQueueSnapshot(int limit) {
        List<Map<String, Object>> result = new ArrayList<>();
        int count = 0;
        for (KernelTask task : queue) {
            if (count++ >= limit) {
                break;
            }
            result.add(task.toMap());
        }
        return result;
    }

    public List<KernelTaskResult> getRecentResults(int limit) {
        List<KernelTaskResult> result = new ArrayList<>();
        int count = 0;
        for (KernelTaskResult item : history) {
            if (count++ >= limit) {
                break;
            }
            result.add(item);
        }
        return result;
    }

    private void startDispatcherIfNeeded() {
        if (!config.getSecurity().getTaskBus().isEnabled() || !config.getSecurity().getTaskBus().isAutoDispatch()) {
            return;
        }
        int intervalSeconds = Math.max(3, config.getSecurity().getTaskBus().getDispatchIntervalSeconds());
        scheduler.scheduleAtFixedRate(() -> dispatchQueuedTasks(4), intervalSeconds, intervalSeconds, TimeUnit.SECONDS);
    }

    private KernelTaskResult dispatch(KernelTask task) {
        for (KernelPlugin plugin : plugins) {
            if (plugin.supports(task.getType())) {
                KernelTaskResult result = plugin.handle(task);
                executedTasks.incrementAndGet();
                securityAuditService.logEvent("ALUER_TASK_BUS", plugin.id(), task.getType().name(), result.getSummary());
                return result;
            }
        }
        return new KernelTaskResult(task.getId(), task.getType(), "none", false, "No plugin accepted the task", Collections.emptyMap());
    }

    private void rememberResult(KernelTaskResult result) {
        history.offerFirst(result);
        while (history.size() > Math.max(100, config.getSecurity().getTaskBus().getHistoryLimit())) {
            history.pollLast();
        }
    }

    private void enqueueByPriority(KernelTask task) {
        if (queue.isEmpty()) {
            queue.offer(task);
            return;
        }

        List<KernelTask> reordered = new ArrayList<>();
        boolean inserted = false;
        KernelTask existing;
        while ((existing = queue.pollFirst()) != null) {
            if (!inserted && task.getPriority() > existing.getPriority()) {
                reordered.add(task);
                inserted = true;
            }
            reordered.add(existing);
        }
        if (!inserted) {
            reordered.add(task);
        }
        for (KernelTask item : reordered) {
            queue.offerLast(item);
        }
    }

    private interface KernelPlugin {
        String id();
        String description();
        boolean supports(TaskType type);
        KernelTaskResult handle(KernelTask task);

        default Map<String, Object> descriptor() {
            Map<String, Object> result = new LinkedHashMap<>();
            result.put("id", id());
            result.put("description", description());
            return result;
        }
    }

    private final class InsightPlugin implements KernelPlugin {
        @Override
        public String id() { return "insight-plugin"; }

        @Override
        public String description() { return "Captures kernel and state snapshots."; }

        @Override
        public boolean supports(TaskType type) {
            return type == TaskType.SNAPSHOT_STATE;
        }

        @Override
        public KernelTaskResult handle(KernelTask task) {
            Map<String, Object> data = new LinkedHashMap<>();
            data.put("kernel", aluerKernelEngine.getKernelStatus());
            data.put("queueDepth", queue.size());
            return new KernelTaskResult(task.getId(), task.getType(), id(), true, "State snapshot captured", data);
        }
    }

    private final class StabilityPlugin implements KernelPlugin {
        @Override
        public String id() { return "stability-plugin"; }

        @Override
        public String description() { return "Relieves server pressure and syncs defense level."; }

        @Override
        public boolean supports(TaskType type) {
            return type == TaskType.RELIEVE_PRESSURE || type == TaskType.SYNC_DEFENSE_LEVEL || type == TaskType.SOFT_RESTART;
        }

        @Override
        public KernelTaskResult handle(KernelTask task) {
            Map<String, Object> data = new LinkedHashMap<>();
            boolean success = true;
            String summary;

            switch (task.getType()) {
                case RELIEVE_PRESSURE -> {
                    boolean clearLag = rconClient.clearLag();
                    boolean spawn = rconClient.setSpawnRate(5);
                    data.put("clearLag", clearLag);
                    data.put("spawnRateReduced", spawn);
                    summary = "Pressure relief routine executed";
                    success = clearLag || spawn;
                }
                case SYNC_DEFENSE_LEVEL -> {
                    String defenseLevel = String.valueOf(task.getPayload().getOrDefault("defenseLevel", "ELEVATED"));
                    aiStrategyEngine.adjustDefenseLevel(defenseLevel);
                    data.put("defenseLevel", defenseLevel);
                    summary = "Defense level synchronized";
                }
                case SOFT_RESTART -> {
                    boolean restarted = rconClient.restartServer();
                    data.put("restarted", restarted);
                    summary = "Soft restart attempted";
                    success = restarted;
                }
                default -> {
                    success = false;
                    summary = "Unsupported task for stability plugin";
                }
            }

            return new KernelTaskResult(task.getId(), task.getType(), id(), success, summary, data);
        }
    }

    private final class DefensePlugin implements KernelPlugin {
        @Override
        public String id() { return "defense-plugin"; }

        @Override
        public String description() { return "Seals perimeter and toggles defensive access modes."; }

        @Override
        public boolean supports(TaskType type) {
            return type == TaskType.SEAL_PERIMETER || type == TaskType.WHITELIST_LOCKDOWN;
        }

        @Override
        public KernelTaskResult handle(KernelTask task) {
            Map<String, Object> data = new LinkedHashMap<>();
            boolean whitelist = rconClient.enableWhitelist();
            data.put("whitelistEnabled", whitelist);
            data.put("broadcast", rconClient.executeCommand("say [Aluer] defensive access mode active"));
            String summary = task.getType() == TaskType.WHITELIST_LOCKDOWN
                ? "Whitelist lockdown requested"
                : "Perimeter seal routine executed";
            return new KernelTaskResult(task.getId(), task.getType(), id(), whitelist, summary, data);
        }
    }

    private final class RecoveryPlugin implements KernelPlugin {
        @Override
        public String id() { return "recovery-plugin"; }

        @Override
        public String description() { return "Restarts processes and prepares backups before recovery."; }

        @Override
        public boolean supports(TaskType type) {
            return type == TaskType.PROCESS_RECOVERY || type == TaskType.PREPARE_BACKUP;
        }

        @Override
        public KernelTaskResult handle(KernelTask task) {
            Map<String, Object> data = new LinkedHashMap<>();
            boolean success;
            String summary;

            if (task.getType() == TaskType.PROCESS_RECOVERY) {
                success = processMonitor.restartProcess();
                data.put("processRunning", processMonitor.isProcessRunning());
                data.put("restarted", success);
                summary = "Process recovery attempted";
            } else {
                BackupService.BackupResult backup = backupService.performScheduledBackup();
                success = backup.isSuccess();
                data.put("backupName", backup.getName());
                data.put("backupPath", backup.getBackupPath());
                summary = "Recovery backup prepared";
            }

            return new KernelTaskResult(task.getId(), task.getType(), id(), success, summary, data);
        }
    }

    public enum TaskType {
        SNAPSHOT_STATE,
        RELIEVE_PRESSURE,
        PROCESS_RECOVERY,
        PREPARE_BACKUP,
        SEAL_PERIMETER,
        WHITELIST_LOCKDOWN,
        SYNC_DEFENSE_LEVEL,
        SOFT_RESTART
    }

    public static class KernelTask {
        private final String id;
        private final TaskType type;
        private final String source;
        private final int priority;
        private final Map<String, Object> payload;
        private final long timestamp;

        public KernelTask(TaskType type, String source, int priority, Map<String, Object> payload) {
            this.id = UUID.randomUUID().toString();
            this.type = type;
            this.source = source == null ? "system" : source;
            this.priority = priority;
            this.payload = payload == null ? new LinkedHashMap<>() : new LinkedHashMap<>(payload);
            this.timestamp = Instant.now().toEpochMilli();
        }

        public String getId() { return id; }
        public TaskType getType() { return type; }
        public String getSource() { return source; }
        public int getPriority() { return priority; }
        public Map<String, Object> getPayload() { return payload; }

        public Map<String, Object> toMap() {
            Map<String, Object> result = new LinkedHashMap<>();
            result.put("id", id);
            result.put("type", type.name());
            result.put("source", source);
            result.put("priority", priority);
            result.put("payload", payload);
            result.put("timestamp", timestamp);
            return result;
        }
    }

    public static class KernelTaskResult {
        private final String taskId;
        private final TaskType type;
        private final String pluginId;
        private final boolean success;
        private final String summary;
        private final Map<String, Object> data;
        private final long timestamp;

        public KernelTaskResult(String taskId,
                                TaskType type,
                                String pluginId,
                                boolean success,
                                String summary,
                                Map<String, Object> data) {
            this.taskId = taskId;
            this.type = type;
            this.pluginId = pluginId;
            this.success = success;
            this.summary = summary;
            this.data = data == null ? new LinkedHashMap<>() : new LinkedHashMap<>(data);
            this.timestamp = Instant.now().toEpochMilli();
        }

        public String getTaskId() { return taskId; }
        public TaskType getType() { return type; }
        public String getPluginId() { return pluginId; }
        public boolean isSuccess() { return success; }
        public String getSummary() { return summary; }
        public Map<String, Object> getData() { return data; }

        public Map<String, Object> toMap() {
            Map<String, Object> result = new LinkedHashMap<>();
            result.put("taskId", taskId);
            result.put("type", type.name());
            result.put("pluginId", pluginId);
            result.put("success", success);
            result.put("summary", summary);
            result.put("data", data);
            result.put("timestamp", timestamp);
            return result;
        }
    }
}
