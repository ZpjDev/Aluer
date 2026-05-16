package com.aluer.service;

import com.aluer.ai.DeepSeekClient;
import com.aluer.config.ServerGuardConfig;
import com.aluer.model.AlertEvent;
import com.aluer.model.AlertType;
import com.aluer.plugin.bridge.InternalCommandExecutor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Component
public class AutoExecutor {
    private static final Logger logger = LoggerFactory.getLogger(AutoExecutor.class);

    private final ServerGuardConfig config;
    private final RconClient rconClient;
    private final DeepSeekClient deepSeekClient;
    private final ConcurrentLinkedQueue<ExecuteTask> taskQueue = new ConcurrentLinkedQueue<>();
    private final ConcurrentHashMap<String, Long> recentActions = new ConcurrentHashMap<>();

    private static final Pattern IP_PATTERN = Pattern.compile("\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b");
    private static final long ACTION_COOLDOWN_MS = 60000;

    /** 插件模式下的内部命令执行器（external 模式下为 null） */
    @Autowired(required = false)
    private InternalCommandExecutor internalCommandExecutor;

    public AutoExecutor(ServerGuardConfig config, RconClient rconClient, DeepSeekClient deepSeekClient) {
        this.config = config;
        this.rconClient = rconClient;
        this.deepSeekClient = deepSeekClient;
    }

    public void executeAutoAction(DeepSeekClient.AiAnalysisResult analysis, AlertEvent alert) {
        if (!isAutoExecuteEnabled()) {
            return;
        }
        
        int confidencePercent = (int)(alert.getConfidence() * 100);
        if (confidencePercent < config.getAi().getDeepseek().getAutoExecute().getMinConfidence()) {
            logger.debug("Confidence {}% below threshold, skipping auto-execute", confidencePercent);
            return;
        }
        
        String action = analysis.getAutoAction();
        if (action == null || action.isEmpty() || action.equals("无") || action.equals("none")) {
            return;
        }
        
        logger.info("[AUTO-EXEC] Processing action: {} (confidence: {}%)", action, confidencePercent);
        
        action = action.toLowerCase();
        
        if (action.contains("ban") || action.contains("封禁")) {
            executeBanAction(alert, action);
        }
        
        if (action.contains("kick") || action.contains("踢出")) {
            executeKickAction(alert);
        }
        
        if (action.contains("kill") || action.contains("清除") || action.contains("清理")) {
            executeClearLag();
        }
        
        if (action.contains("spawn") || action.contains("生成")) {
            executeSpawnControl();
        }
        
        if (action.contains("whitelist") || action.contains("白名单")) {
            executeWhitelistAction(action);
        }
        
        if (action.contains("restart") || action.contains("重启")) {
            executeRestart();
        }
        
        if (action.contains("border") || action.contains("边界")) {
            executeWorldBorder();
        }
    }

    private void executeBanAction(AlertEvent alert, String action) {
        if (!config.getAi().getDeepseek().getAutoExecute().isBanIp()) {
            logger.info("[AUTO-EXEC] Ban disabled in config");
            return;
        }

        String ip = extractIpFromAlert(alert);

        if (ip != null) {
            String banKey = "ban-ip:" + ip;
            if (!isActionCooldown(banKey)) {
                boolean success = isPluginMode()
                    ? internalCommandExecutor.banIP(ip, "AI 自动封禁 — " + alert.getType().getTitle())
                    : rconClient.banIp(ip);
                logger.info("[AUTO-EXEC] Ban IP {} - {}", ip, success ? "SUCCESS" : "FAILED");
                recordAction(banKey);
            }
        } else {
            String player = extractPlayerFromAlert(alert);
            if (player != null) {
                String banKey = "ban-player:" + player;
                if (!isActionCooldown(banKey)) {
                    boolean success = isPluginMode()
                        ? internalCommandExecutor.banPlayer(player, "AI 自动封禁 — " + alert.getType().getTitle())
                        : rconClient.banPlayer(player);
                    logger.info("[AUTO-EXEC] Ban player {} - {}", player, success ? "SUCCESS" : "FAILED");
                    recordAction(banKey);
                }
            }
        }
    }

    private void executeKickAction(AlertEvent alert) {
        if (!config.getAi().getDeepseek().getAutoExecute().isKickPlayer()) {
            return;
        }

        String player = extractPlayerFromAlert(alert);
        if (player != null) {
            String kickKey = "kick:" + player;
            if (!isActionCooldown(kickKey)) {
                boolean success = isPluginMode()
                    ? internalCommandExecutor.kickPlayer(player, "AI 安全系统自动踢出")
                    : rconClient.kickPlayer(player, "Auto-kick by AI security system");
                logger.info("[AUTO-EXEC] Kick player {} - {}", player, success ? "SUCCESS" : "FAILED");
                recordAction(kickKey);
            }
        }
    }

    private void executeClearLag() {
        if (!config.getAi().getDeepseek().getAutoExecute().isClearLag()) {
            return;
        }

        String clearKey = "clear-lag";
        if (!isActionCooldown(clearKey)) {
            if (isPluginMode()) {
                int removed = internalCommandExecutor.clearDroppedItems();
                logger.info("[AUTO-EXEC] Clear lag - removed {} dropped items via Bukkit API", removed);
            } else {
                boolean success = rconClient.clearLag();
                logger.info("[AUTO-EXEC] Clear lag - {}", success ? "SUCCESS" : "FAILED");
                rconClient.killAllMobs();
            }
            recordAction(clearKey);
        }
    }

    private void executeSpawnControl() {
        if (!config.getAi().getDeepseek().getAutoExecute().isSetSpawnRate()) {
            return;
        }

        String spawnKey = "spawn-control";
        if (!isActionCooldown(spawnKey)) {
            if (isPluginMode()) {
                internalCommandExecutor.setSpawnRate(5);
            } else {
                rconClient.setSpawnRate(5);
            }
            logger.info("[AUTO-EXEC] Reduced spawn rate to prevent lag");
            recordAction(spawnKey);
        }
    }

    private void executeWhitelistAction(String action) {
        if (!config.getAi().getDeepseek().getAutoExecute().isWhitelist()) {
            return;
        }

        String whitelistKey = "whitelist";
        if (!isActionCooldown(whitelistKey)) {
            if (action.contains("enable") || action.contains("开启") || action.contains("启用")) {
                if (isPluginMode()) {
                    internalCommandExecutor.enableWhitelist();
                } else {
                    rconClient.enableWhitelist();
                }
                logger.info("[AUTO-EXEC] Enabled whitelist");
            } else if (action.contains("disable") || action.contains("关闭")) {
                if (isPluginMode()) {
                    internalCommandExecutor.disableWhitelist();
                } else {
                    rconClient.disableWhitelist();
                }
                logger.info("[AUTO-EXEC] Disabled whitelist");
            }
            recordAction(whitelistKey);
        }
    }

    private void executeRestart() {
        String restartKey = "restart";
        if (!isActionCooldown(restartKey)) {
            logger.warn("[AUTO-EXEC] AI recommended server restart");
            logger.warn("[AUTO-EXEC] Sending alert to admin before restart...");

            if (isPluginMode()) {
                internalCommandExecutor.executeCommand("say §c[Aluer AI] Server restart recommended due to performance issues");
                internalCommandExecutor.saveAllWorlds();
            } else {
                rconClient.executeCommand("say §c[Aluer AI] Server restart recommended due to performance issues");
                rconClient.executeCommand("save-all");
            }

            recordAction(restartKey);
        }
    }

    private void executeWorldBorder() {
        String borderKey = "world-border";
        if (!isActionCooldown(borderKey)) {
            if (isPluginMode()) {
                internalCommandExecutor.executeCommand("worldborder set 1000");
            } else {
                rconClient.setWorldBorder(1000);
            }
            logger.info("[AUTO-EXEC] Set world border to reduce entity spawns");
            recordAction(borderKey);
        }
    }

    private String extractIpFromAlert(AlertEvent alert) {
        String message = alert.getMessage();

        Matcher matcher = IP_PATTERN.matcher(message);
        if (matcher.find()) {
            return matcher.group();
        }

        return isPluginMode() ? null : rconClient.extractIpFromMessage(message);
    }

    /** 当前是否运行在 Paper 插件模式 */
    private boolean isPluginMode() {
        return config.isPluginMode() && internalCommandExecutor != null;
    }

    private String extractPlayerFromAlert(AlertEvent alert) {
        String message = alert.getMessage();
        
        if (message == null) return null;
        
        String[] patterns = {
            "player:\\s*(\\w+)",
            "(\\w+)\\s+logged in",
            "(\\w+)\\s+joined",
            "kick\\s+(\\w+)",
            "ban\\s+(\\w+)"
        };
        
        for (String pattern : patterns) {
            Matcher m = Pattern.compile(pattern, Pattern.CASE_INSENSITIVE).matcher(message);
            if (m.find()) {
                return m.group(1);
            }
        }
        
        return null;
    }

    private boolean isActionCooldown(String actionKey) {
        Long lastTime = recentActions.get(actionKey);
        if (lastTime != null) {
            return (System.currentTimeMillis() - lastTime) < ACTION_COOLDOWN_MS;
        }
        return false;
    }

    private void recordAction(String actionKey) {
        recentActions.put(actionKey, System.currentTimeMillis());
        
        recentActions.entrySet().removeIf(entry -> 
            (System.currentTimeMillis() - entry.getValue()) > 300000);
    }

    public boolean isAutoExecuteEnabled() {
        return config.getAi().getDeepseek().isEnabled() && 
               config.getAi().getDeepseek().getAutoExecute().isEnabled();
    }

    public void addTask(ExecuteTask task) {
        taskQueue.offer(task);
    }

    public void processTasks() {
        ExecuteTask task;
        while ((task = taskQueue.poll()) != null) {
            try {
                if (isPluginMode()) {
                    switch (task.getType()) {
                        case BAN_IP -> internalCommandExecutor.banIP(task.getTarget(), task.getReason());
                        case BAN_PLAYER -> internalCommandExecutor.banPlayer(task.getTarget(), task.getReason());
                        case KICK -> internalCommandExecutor.kickPlayer(task.getTarget(), task.getReason());
                        case CLEAR_LAG -> internalCommandExecutor.clearDroppedItems();
                        case RESTART -> internalCommandExecutor.executeCommand("restart");
                        case WHITELIST -> internalCommandExecutor.enableWhitelist();
                        default -> logger.warn("Unknown task type: {}", task.getType());
                    }
                } else {
                    switch (task.getType()) {
                        case BAN_IP -> rconClient.banIp(task.getTarget());
                        case BAN_PLAYER -> rconClient.banPlayer(task.getTarget());
                        case KICK -> rconClient.kickPlayer(task.getTarget(), task.getReason());
                        case CLEAR_LAG -> rconClient.clearLag();
                        case RESTART -> rconClient.restartServer();
                        default -> logger.warn("Unknown task type: {}", task.getType());
                    }
                }
            } catch (Exception e) {
                logger.error("Failed to execute task: {}", e.getMessage());
            }
        }
    }

    public static class ExecuteTask {
        private TaskType type;
        private String target;
        private String reason;
        private long timestamp;

        public ExecuteTask(TaskType type, String target, String reason) {
            this.type = type;
            this.target = target;
            this.reason = reason;
            this.timestamp = System.currentTimeMillis();
        }

        public TaskType getType() { return type; }
        public String getTarget() { return target; }
        public String getReason() { return reason; }
        public long getTimestamp() { return timestamp; }
    }

    public enum TaskType {
        BAN_IP,
        BAN_PLAYER,
        KICK,
        CLEAR_LAG,
        RESTART,
        WHITELIST
    }
}
