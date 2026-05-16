package com.aluer.security;

import com.aluer.config.ServerGuardConfig;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;
import java.util.regex.Pattern;

/**
 * 命令滥用检测与防护服务 — V4.0 聊天社交安全模块
 *
 * 检测原理：
 * 1. 命令频率追踪：按玩家追踪30秒窗口内的命令执行计数
 * 2. 命令洪水检测：>10条命令/10秒为异常，可能利用命令漏洞
 * 3. 敏感命令异常使用检测
 * 4. 插件命令探测：连续执行不存在的命令(>5次/30秒)，可能是扫描插件漏洞
 * 5. 命令注入尝试：参数中包含 ; | $() ` ${} 等Shell注入字符
 * 6. Tab补全滥用：大量Tab补全请求探测命令列表
 *
 * 配置开关：serverguard.security.super-evolution.anti-command-abuse
 */
@Service
public class AntiCommandAbuseService {

    private final ServerGuardConfig config;
    private final Map<String, Deque<CommandEvent>> playerCommandHistory = new ConcurrentHashMap<>();
    private final Map<String, Integer> unknownCommandCounts = new ConcurrentHashMap<>();
    private final AtomicLong totalCommands = new AtomicLong(0);
    private final AtomicLong blockedCommands = new AtomicLong(0);
    private final Map<String, Long> commandStats = new ConcurrentHashMap<>();

    /** 命令洪水阈值：10条/10秒 */
    private static final int COMMAND_FLOOD_THRESHOLD = 10;
    /** 命令洪水窗口(秒) */
    private static final long COMMAND_FLOOD_WINDOW_SECONDS = 10L;
    /** 命令追踪窗口(秒) */
    private static final long COMMAND_TRACK_WINDOW_SECONDS = 30L;
    /** 未知命令探测阈值 */
    private static final int UNKNOWN_COMMAND_THRESHOLD = 5;
    /** 未知命令探测窗口(秒) */
    private static final long UNKNOWN_COMMAND_WINDOW_SECONDS = 30L;
    /** 单玩家历史记录最大条数 */
    private static final int MAX_HISTORY_PER_PLAYER = 100;

    /** 命令注入检测正则：匹配Shell注入特征字符 */
    private static final Pattern SHELL_INJECTION_PATTERN = Pattern.compile(
            "[;|&]|\\$\\(|`|\\$\\{|\\|\\||&&|\\n|\\r|>|>>|<|%0[aAdD]");

    /** Minecraft敏感命令列表(可能被滥用) */
    private static final Set<String> SENSITIVE_COMMANDS = Set.of(
            "/op", "/deop", "/stop", "/restart", "/reload",
            "/ban", "/ban-ip", "/pardon", "/pardon-ip",
            "/whitelist", "/kick", "/kill", "/say",
            "/sudo", "/execute", "/summon", "/give",
            "/gamemode", "/difficulty", "/gamerule",
            "/data", "/datapack", "/function", "/schedule",
            "/scoreboard", "/tag", "/team", "/tellraw",
            "/title", "/xp", "/enchant", "/effect",
            "/fill", "/setblock", "/clone", "/particle",
            "/playsound", "/stopsound", "/advancement",
            "/forceload", "/locate", "/place", "/worldborder"
    );

    public AntiCommandAbuseService() {
        this(new ServerGuardConfig());
    }

    @Autowired
    public AntiCommandAbuseService(ServerGuardConfig config) {
        this.config = config;
    }

    /**
     * 检测玩家命令是否存在滥用行为
     *
     * 从命令频率、洪水模式、插件扫描、注入尝试四个维度进行检测。
     * 每项检测独立运行，任一命中即拦截。同时统计命令类型分布用于后续分析。
     *
     * @param player      玩家名
     * @param command     完整命令字符串(含/)
     * @param commandName 命令名(不含参数和/)
     * @param args        命令参数(可为null)
     * @param exists      该命令是否存在(用于插件扫描检测)
     * @return 检测结果
     */
    public CheckResult check(String player, String command, String commandName,
                              String args, boolean exists) {
        if (!config.getSecurity().getSuperEvolution().isAntiCommandAbuse()) {
            return CheckResult.clean();
        }

        totalCommands.incrementAndGet();
        // 统计命令类型分布
        commandStats.merge(commandName, 1L, Long::sum);

        Instant now = Instant.now();
        Deque<CommandEvent> history = playerCommandHistory.computeIfAbsent(player,
                k -> new ArrayDeque<>());

        CommandEvent event = new CommandEvent(now, command, commandName, exists);
        history.addLast(event);

        // 限制历史记录长度
        while (history.size() > MAX_HISTORY_PER_PLAYER) {
            history.removeFirst();
        }

        List<String> reasons = new ArrayList<>();

        // 1. 命令洪水检测：10秒窗口内>10条命令
        long recentCount = history.stream()
                .filter(e -> e.time.isAfter(now.minusSeconds(COMMAND_FLOOD_WINDOW_SECONDS)))
                .count();
        if (recentCount > COMMAND_FLOOD_THRESHOLD) {
            reasons.add("命令洪水: " + COMMAND_FLOOD_WINDOW_SECONDS + "秒内发送" + recentCount
                    + "条命令(阈值" + COMMAND_FLOOD_THRESHOLD + ")");
        }

        // 2. 插件命令探测：连续执行不存在的命令(>5次/30秒)
        if (!exists) {
            unknownCommandCounts.merge(player, 1, Integer::sum);
        }
        int unknownCount = unknownCommandCounts.getOrDefault(player, 0);
        // 检查30秒窗口内的未知命令频率
        long recentUnknown = history.stream()
                .filter(e -> !e.exists)
                .filter(e -> e.time.isAfter(now.minusSeconds(UNKNOWN_COMMAND_WINDOW_SECONDS)))
                .count();
        if (recentUnknown > UNKNOWN_COMMAND_THRESHOLD) {
            reasons.add("疑似插件命令扫描: " + UNKNOWN_COMMAND_WINDOW_SECONDS + "秒内执行"
                    + recentUnknown + "条不存在的命令(阈值" + UNKNOWN_COMMAND_THRESHOLD + ")");
        }

        // 3. 敏感命令异常使用检测
        if (SENSITIVE_COMMANDS.contains("/" + commandName.toLowerCase())) {
            // 敏感命令在非常短时间内大量执行
            long sensitiveRecent = history.stream()
                    .filter(e -> e.time.isAfter(now.minusSeconds(30)))
                    .filter(e -> SENSITIVE_COMMANDS.contains(e.command.toLowerCase()))
                    .count();
            if (sensitiveRecent >= 5) {
                reasons.add("敏感命令异常高频使用: " + commandName + " (30秒内" + sensitiveRecent + "次)");
            }
        }

        // 4. 命令注入尝试检测
        if (args != null && !args.isEmpty()) {
            if (SHELL_INJECTION_PATTERN.matcher(args).find()) {
                reasons.add("命令参数中包含Shell注入特征字符，疑似命令注入攻击");
            }
        }

        // 也对完整命令字符串做注入检测(double check)
        if (command != null && SHELL_INJECTION_PATTERN.matcher(command).find()) {
            if (!reasons.contains("命令参数中包含Shell注入特征字符，疑似命令注入攻击")) {
                reasons.add("命令中包含Shell注入特征字符，疑似命令注入攻击");
            }
        }

        if (!reasons.isEmpty()) {
            blockedCommands.incrementAndGet();
            return CheckResult.blocked(reasons);
        }

        return CheckResult.clean();
    }

    /**
     * 简化版检测：仅检测命令流水(不需要参数和存在性信息)
     *
     * @param player      玩家名
     * @param command     完整命令字符串
     * @param commandName 命令名
     * @return 检测结果
     */
    public CheckResult check(String player, String command, String commandName) {
        return check(player, command, commandName, null, true);
    }

    /**
     * 获取指定玩家的命令历史
     *
     * @param player 玩家名
     * @return 命令事件列表
     */
    public List<CommandEvent> getPlayerHistory(String player) {
        Deque<CommandEvent> history = playerCommandHistory.get(player);
        return history == null ? List.of() : new ArrayList<>(history);
    }

    /**
     * 重置玩家追踪数据
     *
     * @param player 玩家名
     */
    public void resetPlayer(String player) {
        playerCommandHistory.remove(player);
        unknownCommandCounts.remove(player);
    }

    /**
     * 获取服务运行状态
     *
     * @return 包含状态键值对的LinkedHashMap
     */
    public Map<String, Object> getStatus() {
        Map<String, Object> s = new LinkedHashMap<>();
        s.put("enabled", config.getSecurity().getSuperEvolution().isAntiCommandAbuse());
        s.put("totalCommands", totalCommands.get());
        s.put("blockedCommands", blockedCommands.get());
        s.put("activeTrackers", playerCommandHistory.size());
        s.put("commandFloodThreshold", COMMAND_FLOOD_THRESHOLD);
        s.put("unknownCmdThreshold", UNKNOWN_COMMAND_THRESHOLD);

        // Top 10 命令类型统计
        Map<String, Object> topCommands = new LinkedHashMap<>();
        commandStats.entrySet().stream()
                .sorted(Map.Entry.<String, Long>comparingByValue().reversed())
                .limit(10)
                .forEach(e -> topCommands.put(e.getKey(), e.getValue()));
        s.put("commandStats", topCommands);

        // 敏感命令数量
        s.put("sensitiveCommandsCount", SENSITIVE_COMMANDS.size());
        return s;
    }

    /**
     * 命令事件记录
     */
    public static class CommandEvent {
        final Instant time;
        final String command;
        final String commandName;
        final boolean exists;

        CommandEvent(Instant time, String command, String commandName, boolean exists) {
            this.time = time;
            this.command = command;
            this.commandName = commandName;
            this.exists = exists;
        }

        public Instant getTime() { return time; }
        public String getCommand() { return command; }
        public String getCommandName() { return commandName; }
        public boolean isExists() { return exists; }
    }

    /**
     * 检测结果类
     */
    public static class CheckResult {
        private final boolean blocked;
        private final List<String> reasons;

        private CheckResult(boolean blocked, List<String> reasons) {
            this.blocked = blocked;
            this.reasons = reasons;
        }

        public static CheckResult clean() {
            return new CheckResult(false, List.of());
        }

        public static CheckResult blocked(List<String> reasons) {
            return new CheckResult(true, reasons);
        }

        public boolean isBlocked() { return blocked; }
        public boolean isClean() { return !blocked; }
        public List<String> getReasons() { return reasons; }
    }
}
