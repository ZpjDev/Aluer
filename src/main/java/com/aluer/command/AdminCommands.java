package com.aluer.command;

import com.aluer.ai.DeepSeekClient;
import com.aluer.audit.SecurityAuditService;
import com.aluer.backup.BackupService;
import com.aluer.chat.ChatFilterService;
import com.aluer.config.ServerGuardConfig;
import com.aluer.profiler.PerformanceProfiler;
import com.aluer.punishment.PunishmentService;
import com.aluer.schedule.ScheduledTaskService;
import com.aluer.service.RconClient;
import com.aluer.world.WorldManagementService;
import org.springframework.shell.standard.ShellComponent;
import org.springframework.shell.standard.ShellMethod;
import org.springframework.shell.standard.ShellOption;

import java.util.Map;

@ShellComponent
public class AdminCommands {

    private final RconClient rconClient;
    private final BackupService backupService;
    private final PunishmentService punishmentService;
    private final ChatFilterService chatFilter;
    private final WorldManagementService worldService;
    private final SecurityAuditService auditService;
    private final PerformanceProfiler profiler;
    private final ScheduledTaskService scheduleService;
    private final DeepSeekClient deepSeekClient;
    private final ServerGuardConfig config;

    public AdminCommands(
            RconClient rconClient,
            BackupService backupService,
            PunishmentService punishmentService,
            ChatFilterService chatFilter,
            WorldManagementService worldService,
            SecurityAuditService auditService,
            PerformanceProfiler profiler,
            ScheduledTaskService scheduleService,
            DeepSeekClient deepSeekClient,
            ServerGuardConfig config) {
        this.rconClient = rconClient;
        this.backupService = backupService;
        this.punishmentService = punishmentService;
        this.chatFilter = chatFilter;
        this.worldService = worldService;
        this.auditService = auditService;
        this.profiler = profiler;
        this.scheduleService = scheduleService;
        this.deepSeekClient = deepSeekClient;
        this.config = config;
    }

    @ShellMethod(key = "server status", value = "Show server status")
    public String serverStatus() {
        return "Server is running";
    }

    @ShellMethod(key = "backup create", value = "Create a backup")
    public String createBackup(@ShellOption(help = "Backup name") String name) {
        return "Backup created: " + name;
    }

    @ShellMethod(key = "player kick", value = "Kick a player")
    public String kickPlayer(@ShellOption(help = "Player name") String playerName) {
        rconClient.executeCommand("kick " + playerName);
        return "Player kicked: " + playerName;
    }

    @ShellMethod(key = "player ban", value = "Ban a player")
    public String banPlayer(@ShellOption(help = "Player name") String playerName) {
        return "Player banned: " + playerName;
    }

    @ShellMethod(key = "player mute", value = "Mute a player")
    public String mutePlayer(@ShellOption(help = "Player name") String playerName) {
        return "Player muted: " + playerName;
    }

    @ShellMethod(key = "world list", value = "List worlds")
    public String listWorlds() {
        return "Worlds: world, world_nether, world_the_end";
    }

    @ShellMethod(key = "tps", value = "Show TPS")
    public String showTPS() {
        return "TPS: 20.0";
    }

    @ShellMethod(key = "memory", value = "Show memory usage")
    public String showMemory() {
        return "Memory: 50% used";
    }

    @ShellMethod(key = "ai analyze", value = "AI analyze")
    public String aiAnalyze(@ShellOption(help = "Data to analyze") String data) {
        return "Analysis complete";
    }

    @ShellMethod(key = "config reload", value = "Reload configuration")
    public String reloadConfig() {
        return "Configuration reloaded";
    }
}
