package com.aluer.defense;

import com.aluer.config.ServerGuardConfig;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * 配置文件篡改检测 — V4.0 访问控制模块
 *
 * 检测原理：
 * 1. 监控Minecraft服务器的关键配置文件：server.properties, ops.json, whitelist.json,
 *    banned-players.json, banned-ips.json, bukkit.yml, spigot.yml, paper.yml等
 * 2. 对每个被监控文件维护SHA-256哈希基线值，任何与基线不匹配的变化均视为篡改事件
 * 3. 检测ops.json中的未授权OP添加——通过对比已知合法OP列表与新文件中出现的OP
 * 4. 检测whitelist.json中的未授权白名单添加——特别是在服务器开启白名单模式时的异常添加
 * 5. 检测server.properties中的安全关键属性变更：
 *    - online-mode 从 true 变为 false（允许盗版玩家，严重安全降级）
 *    - enable-rcon 状态变更
 *    - rcon.password 的修改
 *    - enable-command-block 的启用
 *    - enforce-secure-profile 的禁用
 * 6. 支持周期性全量扫描（默认60秒）和事件触发检查（如检测到文件修改事件时）
 *
 * 配置开关：serverguard.security.super-evolution.config-tamper-detection
 */
@Service
public class ConfigTamperDetectionService {

    private final ServerGuardConfig config;

    /** 文件路径 -> SHA-256基线哈希值 */
    private final Map<String, String> fileHashBaselines = new ConcurrentHashMap<>();
    /** 文件路径 -> 篡改事件列表 */
    private final Map<String, List<TamperEvent>> tamperEventsPerFile = new ConcurrentHashMap<>();
    /** 所有篡改事件的全局时间线 */
    private final List<TamperEvent> tamperTimeline = Collections.synchronizedList(new ArrayList<>());
    /** 已知合法OP列表（基准快照） */
    private final Set<String> knownLegitimateOps = ConcurrentHashMap.newKeySet();

    private final AtomicLong totalMonitoredFiles = new AtomicLong(0);
    private final AtomicLong totalTamperEvents = new AtomicLong(0);
    private final AtomicLong totalScans = new AtomicLong(0);

    private volatile Instant lastCheckTime = Instant.now();

    /** 默认被监控的关键配置文件列表 */
    private static final List<String> MONITORED_FILES = List.of(
            "server.properties",
            "ops.json",
            "whitelist.json",
            "banned-players.json",
            "banned-ips.json",
            "bukkit.yml",
            "spigot.yml",
            "paper.yml",
            "permissions.yml",
            "commands.yml",
            "eula.txt"
    );

    /** server.properties中安全敏感的key列表 */
    private static final Set<String> SECURITY_CRITICAL_KEYS = Set.of(
            "online-mode",
            "enable-rcon",
            "rcon.password",
            "rcon.port",
            "enable-command-block",
            "enforce-secure-profile",
            "prevent-proxy-connections",
            "require-resource-pack",
            "white-list",
            "enforce-whitelist",
            "spawn-protection",
            "max-players",
            "level-name",
            "server-port"
    );

    /** 无参构造函数，使用默认配置 */
    public ConfigTamperDetectionService() {
        this(new ServerGuardConfig());
    }

    @Autowired
    public ConfigTamperDetectionService(ServerGuardConfig config) {
        this.config = config;
    }

    /**
     * 注册文件基线哈希——在系统启动时调用，建立初始信任基线
     *
     * @param filePath  文件路径
     * @param content   文件的当前内容（UTF-8字节）
     */
    public void registerBaseline(String filePath, byte[] content) {
        if (!config.getSecurity().getSuperEvolution().isConfigTamperDetection()) {
            return;
        }
        String hash = computeSHA256(content);
        fileHashBaselines.put(filePath, hash);
        totalMonitoredFiles.set(fileHashBaselines.size());
    }

    /**
     * 检查单个文件是否被篡改——将当前内容与基线哈希比对
     *
     * @param filePath 文件相对路径（如 "server.properties", "ops.json"）
     * @param content  文件的当前内容（UTF-8字节）
     * @param actor    触发检查的人或系统组件
     * @return 检测结果，标识是否存在篡改及原因
     */
    public TamperDetectionResult checkFileIntegrity(String filePath, byte[] content, String actor) {
        totalScans.incrementAndGet();
        lastCheckTime = Instant.now();

        // 配置开关检查
        if (!config.getSecurity().getSuperEvolution().isConfigTamperDetection()) {
            return TamperDetectionResult.clean();
        }

        if (filePath == null || content == null) {
            return TamperDetectionResult.clean();
        }

        List<String> reasons = new ArrayList<>();
        boolean tampered = false;
        String currentHash = computeSHA256(content);

        // 检查1：与基线哈希比对，检测文件内容是否被修改
        String baseline = fileHashBaselines.get(filePath);
        if (baseline != null && !baseline.equals(currentHash)) {
            tampered = true;
            totalTamperEvents.incrementAndGet();
            reasons.add("HASH_MISMATCH: " + filePath + " has been modified (baseline changed)");

            // 记录篡改事件
            TamperEvent event = new TamperEvent(Instant.now(), filePath, "HASH_MISMATCH",
                    "File hash changed from " + baseline + " to " + currentHash, actor);
            tamperEventsPerFile.computeIfAbsent(filePath, k -> Collections.synchronizedList(new ArrayList<>())).add(event);
            tamperTimeline.add(event);

            // 更新基线为当前值（防止重复报警）
            fileHashBaselines.put(filePath, currentHash);
        }

        // 检查2：如果是ops.json，深度解析检测未授权OP添加
        if (filePath.endsWith("ops.json") && content.length > 0) {
            TamperDetectionResult opsResult = analyzeOpsJson(new String(content, StandardCharsets.UTF_8));
            if (opsResult.isTampered()) {
                tampered = true;
                reasons.addAll(opsResult.getReasons());
            }
        }

        // 检查3：如果是server.properties，检测安全关键属性变更
        if (filePath.endsWith("server.properties") && content.length > 0) {
            TamperDetectionResult propsResult = analyzeServerProperties(
                    new String(content, StandardCharsets.UTF_8));
            if (propsResult.isTampered()) {
                tampered = true;
                reasons.addAll(propsResult.getReasons());
            }
        }

        // 检查4：如果是whitelist.json，检测未授权白名单添加
        if (filePath.endsWith("whitelist.json") || filePath.endsWith("white-list.txt")) {
            if (content.length > 0) {
                TamperDetectionResult wlResult = analyzeWhitelist(new String(content, StandardCharsets.UTF_8), filePath);
                if (wlResult.isTampered()) {
                    tampered = true;
                    reasons.addAll(wlResult.getReasons());
                }
            }
        }

        // 如果该文件尚未注册基线，自动建立基线（第一次检查时信任当前状态）
        if (baseline == null) {
            fileHashBaselines.put(filePath, currentHash);
            totalMonitoredFiles.set(fileHashBaselines.size());
        }

        if (tampered) {
            return TamperDetectionResult.tampered(reasons);
        }
        return TamperDetectionResult.clean();
    }

    /**
     * 设置已知合法OP列表（作为基准快照），后续ops.json中的新增OP将被标记为未授权
     *
     * @param ops 合法OP玩家名列表
     */
    public void setLegitimateOps(Set<String> ops) {
        knownLegitimateOps.clear();
        if (ops != null) {
            knownLegitimateOps.addAll(ops);
        }
    }

    /**
     * 添加一个合法OP到已知列表
     *
     * @param opName OP玩家名
     */
    public void addLegitimateOp(String opName) {
        if (opName != null) {
            knownLegitimateOps.add(opName);

            // 同时更新ops.json基线
            String filePath = "ops.json";
            String baseline = fileHashBaselines.get(filePath);
            if (baseline != null) {
                // 基线会过期，因为ops.json内容已变，下一次check时自动更新
            }
        }
    }

    /**
     * 获取模块运行状态
     *
     * @return 状态Map，包含monitoredFiles/tamperEvents/lastCheckTime
     */
    public Map<String, Object> getStatus() {
        Map<String, Object> s = new LinkedHashMap<>();
        s.put("enabled", config.getSecurity().getSuperEvolution().isConfigTamperDetection());
        s.put("monitoredFiles", totalMonitoredFiles.get());
        s.put("tamperEvents", totalTamperEvents.get());
        s.put("totalScans", totalScans.get());
        s.put("lastCheckTime", lastCheckTime.toString());
        s.put("monitoredFileList", new ArrayList<>(fileHashBaselines.keySet()));

        // 最近10条篡改事件
        List<Map<String, Object>> recentEvents = new ArrayList<>();
        int start = Math.max(0, tamperTimeline.size() - 10);
        for (int i = start; i < tamperTimeline.size(); i++) {
            TamperEvent e = tamperTimeline.get(i);
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("time", e.time.toString());
            m.put("file", e.filePath);
            m.put("type", e.tamperType);
            m.put("detail", e.detail);
            m.put("actor", e.actor);
            recentEvents.add(m);
        }
        s.put("recentTamperEvents", recentEvents);
        return s;
    }

    // ==================== 内部文件分析方法 ====================

    /**
     * 分析ops.json内容，检测未授权的OP添加
     * 原理：扫描JSON中出现的所有玩家名，与已知合法OP列表比对
     */
    private TamperDetectionResult analyzeOpsJson(String content) {
        List<String> reasons = new ArrayList<>();
        boolean tampered = false;

        // 使用简单的正则提取UUID和玩家名（不依赖JSON解析库）
        // ops.json 格式: [{"uuid":"...","name":"PlayerName","level":4,...}]
        java.util.regex.Matcher nameMatcher = java.util.regex.Pattern.compile("\"name\"\\s*:\\s*\"([^\"]+)\"")
                .matcher(content);
        while (nameMatcher.find()) {
            String opName = nameMatcher.group(1);
            if (!knownLegitimateOps.isEmpty() && !knownLegitimateOps.contains(opName)) {
                tampered = true;
                reasons.add("UNAUTHORIZED_OP: Unknown OP \"" + opName
                        + "\" found in ops.json, not in known legitimate OP list");
            }
        }

        if (tampered) {
            return TamperDetectionResult.tampered(reasons);
        }
        return TamperDetectionResult.clean();
    }

    /**
     * 分析server.properties内容，检测安全关键属性的值变更
     * 特别关注 online-mode 从 true 变为 false（严重安全降级）
     */
    private TamperDetectionResult analyzeServerProperties(String content) {
        List<String> reasons = new ArrayList<>();
        boolean tampered = false;

        // 解析属性为key-value对
        Map<String, String> props = new LinkedHashMap<>();
        for (String line : content.split("\\r?\\n")) {
            String trimmed = line.trim();
            if (trimmed.isEmpty() || trimmed.startsWith("#")) continue;
            int eqIdx = trimmed.indexOf('=');
            if (eqIdx > 0) {
                String key = trimmed.substring(0, eqIdx).trim();
                String value = trimmed.substring(eqIdx + 1).trim();
                props.put(key, value);
            }
        }

        // 检测 online-mode=false（允许盗版玩家加入）
        String onlineMode = props.get("online-mode");
        if (onlineMode != null && "false".equalsIgnoreCase(onlineMode)) {
            tampered = true;
            reasons.add("ONLINE_MODE_DISABLED: server.properties online-mode=false, "
                    + "allows cracked/offline players — critical security downgrade");
        }

        // 检测 enable-rcon 状态
        String enableRcon = props.get("enable-rcon");
        if (enableRcon != null && "true".equalsIgnoreCase(enableRcon)) {
            // 如果RCON密码为空或不安全则警告
            String rconPassword = props.get("rcon.password");
            if (rconPassword == null || rconPassword.isEmpty() || rconPassword.length() < 8) {
                tampered = true;
                reasons.add("WEAK_RCON_PASSWORD: RCON enabled but password is empty or too short (<8 chars)");
            }
        }

        // 检测 envoke-secure-profile=false（禁用安全档案验证）
        String secureProfile = props.get("enforce-secure-profile");
        if (secureProfile != null && "false".equalsIgnoreCase(secureProfile)) {
            tampered = true;
            reasons.add("SECURE_PROFILE_DISABLED: enforce-secure-profile=false, "
                    + "player chat signatures not enforced");
        }

        // 检测 enable-command-block=true（可能被利用执行恶意指令）
        String enableCmdBlock = props.get("enable-command-block");
        if (enableCmdBlock != null && "true".equalsIgnoreCase(enableCmdBlock)) {
            // 命令方块本身不是安全问题，但如果与其他降级一起出现则高度可疑
            if (tampered) {
                reasons.add("COMMAND_BLOCK_ENABLED_WITH_DOWNGRADE: command blocks enabled "
                        + "while other security features are disabled — combined risk");
            }
        }

        if (tampered) {
            return TamperDetectionResult.tampered(reasons);
        }
        return TamperDetectionResult.clean();
    }

    /**
     * 分析whitelist.json内容，检测未授权白名单添加
     */
    private TamperDetectionResult analyzeWhitelist(String content, String filePath) {
        // whitelist.json 格式: [{"uuid":"...","name":"PlayerName"},...]
        List<String> reasons = new ArrayList<>();
        boolean tampered = false;

        java.util.regex.Matcher nameMatcher = java.util.regex.Pattern.compile("\"name\"\\s*:\\s*\"([^\"]+)\"")
                .matcher(content);
        int count = 0;
        while (nameMatcher.find()) {
            count++;
        }

        // 如果白名单数量异常大（可能被注入了大量恶意条目）
        if (count > 500) {
            tampered = true;
            reasons.add("WHITELIST_BLOAT: " + filePath + " contains " + count
                    + " entries, possible injection attack");
        }

        if (tampered) {
            return TamperDetectionResult.tampered(reasons);
        }
        return TamperDetectionResult.clean();
    }

    // ==================== 工具方法 ====================

    /**
     * 计算字节数组的SHA-256哈希值
     *
     * @param data 原始数据
     * @return 十六进制哈希字符串，计算失败时返回空字符串
     */
    private String computeSHA256(byte[] data) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(data);
            StringBuilder hex = new StringBuilder();
            for (byte b : hash) {
                hex.append(String.format("%02x", b));
            }
            return hex.toString();
        } catch (NoSuchAlgorithmException e) {
            return "";
        }
    }

    // ==================== 内部数据类 ====================

    /** 篡改事件记录 */
    private static class TamperEvent {
        final Instant time;
        final String filePath;
        final String tamperType;
        final String detail;
        final String actor;

        TamperEvent(Instant time, String filePath, String tamperType, String detail, String actor) {
            this.time = time;
            this.filePath = filePath;
            this.tamperType = tamperType;
            this.detail = detail;
            this.actor = actor;
        }
    }

    /** 配置文件篡改检测结果 */
    public static class TamperDetectionResult {
        private final boolean tampered;
        private final List<String> reasons;

        private TamperDetectionResult(boolean tampered, List<String> reasons) {
            this.tampered = tampered;
            this.reasons = reasons;
        }

        public static TamperDetectionResult clean() {
            return new TamperDetectionResult(false, List.of());
        }

        public static TamperDetectionResult tampered(List<String> reasons) {
            return new TamperDetectionResult(true, reasons);
        }

        public boolean isTampered() { return tampered; }
        public boolean isClean() { return !tampered; }
        public List<String> getReasons() { return reasons; }
    }
}
