package com.aluer.defense;

import com.aluer.config.ServerGuardConfig;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;
import java.util.stream.Collectors;

/**
 * OP权限变更监控与审计 — V4.0 访问控制模块
 *
 * 检测原理：
 * 1. 监控服务器OP（管理员）权限的授予和撤销事件，记录操作来源（控制台/命令方块/Rcon/插件）
 * 2. 追踪所有OP玩家的权限级别（Level 1-4），检测异常的权限提升行为
 * 3. 检测非授权OP授予——凡不是通过服务器控制台直接输入的/op命令，均标记为可疑来源
 * 4. 记录OP执行的敏感命令（/ban, /ban-ip, /whitelist, /deop, /stop, /restart, /reload）并审计
 * 5. 检测短时间内的管理命令风暴（>5次/分钟），可能是被入侵账户或恶意OP在批量操作
 * 6. 检测OP权限跳级提升（Level 1 直接跃升至 Level 4），正常流程是逐级提升
 *
 * 配置开关：serverguard.security.super-evolution.op-privilege-monitor
 */
@Service
public class OPPrivilegeMonitorService {

    private final ServerGuardConfig config;

    /** OP玩家名 -> OP权限记录，追踪当前所有在线的OP状态 */
    private final Map<String, OPEvent> currentOps = new ConcurrentHashMap<>();
    /** OP变更历史记录，key为玩家名，value为变更事件列表 */
    private final Map<String, List<OPEvent>> opHistory = new ConcurrentHashMap<>();
    /** 敏感命令日志，key为玩家名，value为该玩家执行的敏感命令列表 */
    private final Map<String, List<SensitiveCommandLog>> sensitiveCommandLogs = new ConcurrentHashMap<>();
    /** 命令频率窗口追踪，key为"玩家名:分钟"用于速率统计 */
    private final Map<String, AtomicLong> commandRateWindow = new ConcurrentHashMap<>();

    private final AtomicLong totalOps = new AtomicLong(0);
    private final AtomicLong totalOpChanges = new AtomicLong(0);
    private final AtomicLong totalSensitiveCommands = new AtomicLong(0);
    private final AtomicLong suspiciousOpGrants = new AtomicLong(0);
    private final AtomicLong anomalousBehaviorCount = new AtomicLong(0);

    /** 已知的合法OP授予来源 */
    private static final String LEGIT_SOURCE_CONSOLE = "CONSOLE";
    /** 敏感命令集合 */
    private static final Set<String> SENSITIVE_COMMANDS = Set.of(
            "ban", "ban-ip", "banlist", "pardon", "pardon-ip",
            "whitelist add", "whitelist remove", "whitelist on", "whitelist off",
            "deop", "op",
            "stop", "restart", "reload",
            "kick", "ban-player", "ban-ip-player"
    );
    /** 命令风暴阈值：同一玩家1分钟内超过5个管理命令 */
    private static final int COMMAND_STORM_THRESHOLD = 5;
    /** 命令风暴窗口大小（毫秒） */
    private static final long COMMAND_STORM_WINDOW_MS = 60_000;
    /** 正常OP权限级别范围 */
    private static final int MAX_OP_LEVEL = 4;

    /** 无参构造函数，使用默认配置 */
    public OPPrivilegeMonitorService() {
        this(new ServerGuardConfig());
    }

    @Autowired
    public OPPrivilegeMonitorService(ServerGuardConfig config) {
        this.config = config;
    }

    /**
     * 记录OP权限变更事件（授予或撤销）
     *
     * @param playerName 被操作的玩家名
     * @param opLevel    OP权限级别 (0=非OP, 1-4=OP级别)
     * @param action     操作类型 ("grant" 授予 / "revoke" 撤销)
     * @param source     操作来源 (CONSOLE, RCON, COMMAND_BLOCK, PLUGIN 等)
     * @param actor      执行操作的实体名（控制台为"Server"，否则为执行OP命令的玩家名）
     * @return 检测结果，包含是否可疑及原因
     */
    public OPMonitorResult recordOPChange(String playerName, int opLevel, String action, String source, String actor) {
        totalOpChanges.incrementAndGet();

        // 配置开关检查：如果模块未启用，直接返回clean
        if (!config.getSecurity().getSuperEvolution().isOpPrivilegeMonitor()) {
            return OPMonitorResult.clean();
        }

        List<String> reasons = new ArrayList<>();
        boolean suspicious = false;
        Instant now = Instant.now();

        OPEvent event = new OPEvent(now, playerName, opLevel, action, source, actor);
        opHistory.computeIfAbsent(playerName, k -> new ArrayList<>()).add(event);

        if ("grant".equalsIgnoreCase(action)) {
            // 检查1：非控制台来源授予OP（可能是插件后门/命令方块绕过）
            if (!LEGIT_SOURCE_CONSOLE.equalsIgnoreCase(source)) {
                suspicious = true;
                suspiciousOpGrants.incrementAndGet();
                reasons.add("UNAUTHORIZED_OP_GRANT: OP granted to " + playerName
                        + " via non-console source [" + source + "] by " + actor);
            }

            // 检查2：检测权限级别异常跳升（Level 1→Level 4）
            OPEvent previous = currentOps.get(playerName);
            if (previous != null && previous.opLevel > 0) {
                int levelJump = opLevel - previous.opLevel;
                if (levelJump >= 3) {
                    suspicious = true;
                    anomalousBehaviorCount.incrementAndGet();
                    reasons.add("OP_LEVEL_JUMP: " + playerName + " jumped from Level "
                            + previous.opLevel + " to Level " + opLevel + " (jump of " + levelJump + ")");
                }
            }

            // 更新当前OP列表
            currentOps.put(playerName, event);
            totalOps.set(currentOps.size());

        } else if ("revoke".equalsIgnoreCase(action)) {
            // 检查3：非控制台来源撤销OP（可能是恶意去OP掩盖行为）
            if (!LEGIT_SOURCE_CONSOLE.equalsIgnoreCase(source)) {
                suspicious = true;
                suspiciousOpGrants.incrementAndGet();
                reasons.add("UNAUTHORIZED_OP_REVOKE: OP revoked from " + playerName
                        + " via non-console source [" + source + "] by " + actor);
            }
            currentOps.remove(playerName);
            totalOps.set(currentOps.size());
        }

        if (suspicious) {
            return OPMonitorResult.suspicious(reasons);
        }
        return OPMonitorResult.clean();
    }

    /**
     * 记录并审计OP执行的敏感命令
     *
     * @param playerName 执行命令的OP玩家名
     * @param command    执行的完整命令字符串
     * @param source     命令来源 (CONSOLE, RCON, IN_GAME 等)
     * @return 检测结果，包含命令风暴警告等
     */
    public OPMonitorResult recordSensitiveCommand(String playerName, String command, String source) {
        totalSensitiveCommands.incrementAndGet();

        if (!config.getSecurity().getSuperEvolution().isOpPrivilegeMonitor()) {
            return OPMonitorResult.clean();
        }

        List<String> reasons = new ArrayList<>();
        boolean suspicious = false;
        Instant now = Instant.now();

        // 记录命令日志
        SensitiveCommandLog log = new SensitiveCommandLog(now, playerName, command, source);
        sensitiveCommandLogs.computeIfAbsent(playerName, k -> new ArrayList<>()).add(log);

        // 检查4：检测管理命令风暴（同一玩家1分钟内超过阈值次数的敏感命令）
        String windowKey = playerName + ":" + (now.toEpochMilli() / COMMAND_STORM_WINDOW_MS);
        AtomicLong counter = commandRateWindow.computeIfAbsent(windowKey, k -> new AtomicLong(0));
        long count = counter.incrementAndGet();

        if (count > COMMAND_STORM_THRESHOLD) {
            suspicious = true;
            anomalousBehaviorCount.incrementAndGet();
            reasons.add("COMMAND_STORM: " + playerName + " executed " + count
                    + " sensitive commands within 1 minute window, may indicate compromised account");
        }

        if (suspicious) {
            return OPMonitorResult.suspicious(reasons);
        }
        return OPMonitorResult.clean();
    }

    /**
     * 验证某命令是否为需要审计的敏感命令
     *
     * @param command 命令字符串
     * @return true 如果该命令是敏感管理命令
     */
    public boolean isSensitiveCommand(String command) {
        if (command == null) return false;
        String lower = command.toLowerCase().trim();
        // 处理带斜杠的命令格式（Minecraft命令可以带或不带/前缀）
        if (lower.startsWith("/")) {
            lower = lower.substring(1);
        }
        for (String sensitive : SENSITIVE_COMMANDS) {
            if (lower.startsWith(sensitive)) {
                return true;
            }
        }
        return false;
    }

    /**
     * 获取指定OP玩家的权限变更历史
     *
     * @param playerName 玩家名
     * @return 该玩家的OP变更事件列表
     */
    public List<Map<String, Object>> getOPHistory(String playerName) {
        List<OPEvent> events = opHistory.getOrDefault(playerName, List.of());
        List<Map<String, Object>> result = new ArrayList<>();
        for (OPEvent e : events) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("time", e.time.toString());
            m.put("player", e.playerName);
            m.put("opLevel", e.opLevel);
            m.put("action", e.action);
            m.put("source", e.source);
            m.put("actor", e.actor);
            result.add(m);
        }
        return result;
    }

    /**
     * 获取当前所有在线OP及其级别
     *
     * @return 当前OP列表
     */
    public Map<String, Integer> getCurrentOps() {
        Map<String, Integer> result = new LinkedHashMap<>();
        currentOps.forEach((name, event) -> result.put(name, event.opLevel));
        return result;
    }

    /**
     * 获取所有敏感命令审计记录
     *
     * @param playerName 玩家名，null则返回所有
     * @return 敏感命令日志列表
     */
    public List<Map<String, Object>> getSensitiveCommandLogs(String playerName) {
        if (playerName != null) {
            List<SensitiveCommandLog> logs = sensitiveCommandLogs.getOrDefault(playerName, List.of());
            return logs.stream().map(l -> {
                Map<String, Object> m = new LinkedHashMap<>();
                m.put("time", l.time.toString());
                m.put("player", l.playerName);
                m.put("command", l.command);
                m.put("source", l.source);
                return m;
            }).collect(Collectors.toList());
        }
        // 返回所有记录
        List<Map<String, Object>> all = new ArrayList<>();
        sensitiveCommandLogs.forEach((name, logs) -> {
            for (SensitiveCommandLog l : logs) {
                Map<String, Object> m = new LinkedHashMap<>();
                m.put("time", l.time.toString());
                m.put("player", l.playerName);
                m.put("command", l.command);
                m.put("source", l.source);
                all.add(m);
            }
        });
        return all;
    }

    /**
     * 获取模块运行状态
     *
     * @return 状态Map，包含totalOps/opChanges/sensitiveCommandLog计数
     */
    public Map<String, Object> getStatus() {
        Map<String, Object> s = new LinkedHashMap<>();
        s.put("enabled", config.getSecurity().getSuperEvolution().isOpPrivilegeMonitor());
        s.put("totalOps", totalOps.get());
        s.put("opChanges", totalOpChanges.get());
        s.put("sensitiveCommandLog", totalSensitiveCommands.get());
        s.put("suspiciousOpGrants", suspiciousOpGrants.get());
        s.put("anomalousBehaviors", anomalousBehaviorCount.get());
        s.put("currentOPs", new ArrayList<>(currentOps.keySet()));
        return s;
    }

    // ==================== 内部数据类 ====================

    /** OP变更事件记录 */
    private static class OPEvent {
        final Instant time;
        final String playerName;
        final int opLevel;
        final String action;
        final String source;
        final String actor;

        OPEvent(Instant time, String playerName, int opLevel, String action, String source, String actor) {
            this.time = time;
            this.playerName = playerName;
            this.opLevel = opLevel;
            this.action = action;
            this.source = source;
            this.actor = actor;
        }
    }

    /** 敏感命令日志记录 */
    private static class SensitiveCommandLog {
        final Instant time;
        final String playerName;
        final String command;
        final String source;

        SensitiveCommandLog(Instant time, String playerName, String command, String source) {
            this.time = time;
            this.playerName = playerName;
            this.command = command;
            this.source = source;
        }
    }

    /** OP监控检测结果 */
    public static class OPMonitorResult {
        private final boolean suspicious;
        private final List<String> reasons;

        private OPMonitorResult(boolean suspicious, List<String> reasons) {
            this.suspicious = suspicious;
            this.reasons = reasons;
        }

        public static OPMonitorResult clean() {
            return new OPMonitorResult(false, List.of());
        }

        public static OPMonitorResult suspicious(List<String> reasons) {
            return new OPMonitorResult(true, reasons);
        }

        public boolean isSuspicious() { return suspicious; }
        public boolean isClean() { return !suspicious; }
        public List<String> getReasons() { return reasons; }
    }
}
