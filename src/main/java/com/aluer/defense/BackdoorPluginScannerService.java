package com.aluer.defense;

import com.aluer.config.ServerGuardConfig;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * 后门插件/恶意JAR扫描 — V4.0 访问控制模块
 *
 * 检测原理：
 * 1. 扫描服务器plugins目录下的所有JAR文件，识别已知恶意后门插件
 * 2. 维护已知恶意插件名称黑名单（PluginHider, SystemX, AntiStalker, OpHider等20+后门变种）
 * 3. 检测可疑插件特征：缺少plugin.yml的JAR、包含不明主类的JAR
 * 4. 检测远程命令执行（RCE）嫌疑：通过分析类名和嵌入的代码字符串查找
 *    org.bukkit.craftbukkit.executor / java.lang.Runtime.exec 等调用
 * 5. 检测JAR中隐藏的可疑配置——通过特征关键词（pass, host, port, shit, backdoor, token等）
 *    推断插件可能包含硬编码后门凭据
 * 6. 检测插件尝试加载字节码操作库（Reflections/ASM/Javassist等）用于隐藏自身或动态注入
 * 7. 对每个已加载插件标记风险等级：SAFE（安全）、SUSPICIOUS（可疑）、MALICIOUS（恶意）
 *
 * 配置开关：serverguard.security.super-evolution.backdoor-plugin-scanner
 */
@Service
public class BackdoorPluginScannerService {

    private final ServerGuardConfig config;

    /** 已扫描插件名 -> 扫描结果 */
    private final Map<String, PluginScanEntry> scannedPlugins = new ConcurrentHashMap<>();
    /** 恶意插件列表 */
    private final Set<String> maliciousPlugins = ConcurrentHashMap.newKeySet();
    /** 可疑插件列表 */
    private final Set<String> suspiciousPlugins = ConcurrentHashMap.newKeySet();

    private final AtomicLong totalPlugins = new AtomicLong(0);
    private final AtomicLong totalScans = new AtomicLong(0);

    /** 已知恶意插件名称（20+后门变种） */
    private static final Set<String> KNOWN_MALICIOUS_PLUGINS = Set.of(
            "PluginHider", "SystemX", "AntiStalker", "OpHider",
            "ConsoleSpamFixer", "BackdoorPlugin", "OpsGuard",
            "HiddenAdmin", "ForceOP", "OPMe",
            "PluginStealer", "ServerCrasher", "JarLoader",
            "RemoteCmd", "SilentOP", "AdminToolz",
            "MineSecure", "CraftHack", "BukkitBackdoor",
            "CommandExploit", "HackLoader", "OPFinder",
            "zPlugin", "xDPlugin", "SystemSpoof",
            "ConfigStealer", "SessionLogger"
    );

    /** 可疑插件名称模式（正则，不区分大小写） */
    private static final List<String> SUSPICIOUS_NAME_PATTERNS = List.of(
            ".*[Bb]ack[Dd]oor.*",
            ".*[Hh]ack.*",
            ".*[Ee]xploit.*",
            ".*[Ss]teal.*",
            ".*[Hh]idden.*",
            ".*[Ff]orce.*",
            ".*[Rr]emote.*",
            ".*[Cc]rack.*",
            ".*[Ii]nject.*",
            ".*[Pp]assword.*"
    );

    /** RCE相关类名关键词 */
    private static final Set<String> RCE_CLASS_KEYWORDS = Set.of(
            "Runtime.exec",
            "ProcessBuilder",
            "org.bukkit.craftbukkit.executor",
            "java.lang.reflect",
            "sun.misc.Unsafe",
            "javax.script.ScriptEngine",
            "org.yaml.snakeyaml.Yaml"
    );

    /** 字节码操作库特征类名 */
    private static final Set<String> BYTECODE_MANIPULATION_CLASSES = Set.of(
            "org.objectweb.asm",
            "org.reflections",
            "javassist",
            "net.bytebuddy",
            "org.ow2.asm",
            "org.apache.bcel",
            "javax.tools.JavaCompiler"
    );

    /** 可疑配置键关键词 */
    private static final Set<String> SUSPICIOUS_CONFIG_KEYS = Set.of(
            "pass", "password", "pwd",
            "host", "ip", "address",
            "port",
            "token", "key", "secret",
            "backdoor", "backdoor-enabled",
            "shit", "fuck",
            "admin-bypass",
            "hide-commands",
            "silent-mode",
            "auto-op",
            "webhook", "discord-webhook",
            "c2-server", "c2",
            "reverse-shell",
            "exec", "execute-on-join"
    );

    /** 无参构造函数，使用默认配置 */
    public BackdoorPluginScannerService() {
        this(new ServerGuardConfig());
    }

    @Autowired
    public BackdoorPluginScannerService(ServerGuardConfig config) {
        this.config = config;
    }

    /**
     * 扫描单个插件JAR（基于元数据进行分析）
     * 在实际部署中，pluginClasses参数应来自JAR文件的实际类名列表
     *
     * @param pluginName     插件名称（来自plugin.yml的name字段）
     * @param jarFileName    JAR文件名
     * @param hasPluginYml   是否包含plugin.yml文件
     * @param mainClass      插件主类（来自plugin.yml的main字段）
     * @param pluginClasses  插件JAR中包含的所有类名列表
     * @param configKeys     插件config.yml中的配置键列表
     * @return 扫描结果，包含风险等级和详细原因
     */
    public PluginScanResult scanPlugin(String pluginName, String jarFileName,
                                        boolean hasPluginYml, String mainClass,
                                        List<String> pluginClasses, List<String> configKeys) {
        totalScans.incrementAndGet();

        // 配置开关检查
        if (!config.getSecurity().getSuperEvolution().isBackdoorPluginScanner()) {
            return PluginScanResult.clean(pluginName);
        }

        List<String> reasons = new ArrayList<>();
        RiskLevel riskLevel = RiskLevel.SAFE;

        if (pluginName == null || pluginName.isBlank()) {
            pluginName = jarFileName != null ? jarFileName.replace(".jar", "") : "unknown";
        }

        // 检查1：已知恶意插件名称匹配
        if (KNOWN_MALICIOUS_PLUGINS.contains(pluginName)) {
            riskLevel = RiskLevel.MALICIOUS;
            reasons.add("KNOWN_MALICIOUS_PLUGIN: Plugin name \"" + pluginName
                    + "\" matches known backdoor/malware plugin");
            maliciousPlugins.add(pluginName);
        }

        // 检查2：可疑插件名称模式匹配
        if (riskLevel == RiskLevel.SAFE) {
            for (String pattern : SUSPICIOUS_NAME_PATTERNS) {
                if (pluginName.toLowerCase().matches(pattern.toLowerCase())) {
                    riskLevel = RiskLevel.SUSPICIOUS;
                    reasons.add("SUSPICIOUS_PLUGIN_NAME: \"" + pluginName
                            + "\" matches suspicious naming pattern \"" + pattern + "\"");
                    suspiciousPlugins.add(pluginName);
                    break;
                }
            }
        }

        // 检查3：缺少plugin.yml的JAR（合法Minecraft插件必须包含plugin.yml）
        if (!hasPluginYml) {
            if (riskLevel.ordinal() < RiskLevel.SUSPICIOUS.ordinal()) {
                riskLevel = RiskLevel.SUSPICIOUS;
            }
            reasons.add("MISSING_PLUGIN_YML: JAR file \"" + jarFileName
                    + "\" does not contain plugin.yml — not a standard Bukkit/Paper plugin");
            suspiciousPlugins.add(pluginName);
        }

        // 检查4：检测RCE相关类名（远程命令执行嫌疑）
        if (pluginClasses != null && !pluginClasses.isEmpty()) {
            for (String className : pluginClasses) {
                for (String rceKeyword : RCE_CLASS_KEYWORDS) {
                    if (className.contains(rceKeyword)) {
                        if (riskLevel.ordinal() < RiskLevel.SUSPICIOUS.ordinal()) {
                            riskLevel = RiskLevel.SUSPICIOUS;
                        }
                        reasons.add("RCE_CAPABILITY: Class \"" + className
                                + "\" indicates remote command execution capability");
                        suspiciousPlugins.add(pluginName);
                        break;
                    }
                }
            }
        }

        // 检查5：检测字节码操作库依赖（用于隐藏自身/动态注入）
        if (pluginClasses != null && !pluginClasses.isEmpty()) {
            for (String className : pluginClasses) {
                for (String bcClass : BYTECODE_MANIPULATION_CLASSES) {
                    if (className.contains(bcClass)) {
                        if (riskLevel.ordinal() < RiskLevel.SUSPICIOUS.ordinal()) {
                            riskLevel = RiskLevel.SUSPICIOUS;
                        }
                        reasons.add("BYTECODE_MANIPULATION: Class \"" + className
                                + "\" bundles bytecode manipulation library, "
                                + "potentially hiding malicious behavior");
                        suspiciousPlugins.add(pluginName);
                        break;
                    }
                }
            }
        }

        // 检查6：检测隐藏的可疑配置键（硬编码后门凭据特征）
        if (configKeys != null && !configKeys.isEmpty()) {
            for (String configKey : configKeys) {
                String lowerKey = configKey.toLowerCase();
                for (String suspiciousKey : SUSPICIOUS_CONFIG_KEYS) {
                    if (lowerKey.contains(suspiciousKey)) {
                        if (riskLevel.ordinal() < RiskLevel.SUSPICIOUS.ordinal()) {
                            riskLevel = RiskLevel.SUSPICIOUS;
                        }
                        reasons.add("SUSPICIOUS_CONFIG_KEY: Config contains suspicious key \""
                                + configKey + "\", possible hardcoded backdoor credential");
                        suspiciousPlugins.add(pluginName);
                        break;
                    }
                }
            }
        }

        // 检查7：主类为奇怪的非标准类名
        if (mainClass != null && !mainClass.isBlank()) {
            // 合法主类通常遵循 com.xxx.plugin.PluginMain 格式
            if (!mainClass.contains(".")) {
                if (riskLevel.ordinal() < RiskLevel.SUSPICIOUS.ordinal()) {
                    riskLevel = RiskLevel.SUSPICIOUS;
                }
                reasons.add("SUSPICIOUS_MAIN_CLASS: Main class \"" + mainClass
                        + "\" has no package — may be obfuscated");
                suspiciousPlugins.add(pluginName);
            }
        }

        // 存储扫描结果
        PluginScanEntry entry = new PluginScanEntry(pluginName, jarFileName, riskLevel,
                reasons, Instant.now());
        scannedPlugins.put(pluginName, entry);

        if (!scannedPlugins.containsKey(pluginName)) {
            totalPlugins.incrementAndGet();
        }

        return new PluginScanResult(pluginName, riskLevel, reasons);
    }

    /**
     * 快速检查：仅通过插件名称判断是否为已知恶意插件
     *
     * @param pluginName 插件名称
     * @return 扫描结果
     */
    public PluginScanResult quickScan(String pluginName) {
        totalScans.incrementAndGet();

        if (!config.getSecurity().getSuperEvolution().isBackdoorPluginScanner()) {
            return PluginScanResult.clean(pluginName);
        }

        if (KNOWN_MALICIOUS_PLUGINS.contains(pluginName)) {
            maliciousPlugins.add(pluginName);
            PluginScanEntry entry = new PluginScanEntry(pluginName, pluginName + ".jar",
                    RiskLevel.MALICIOUS,
                    List.of("KNOWN_MALICIOUS_PLUGIN: " + pluginName),
                    Instant.now());
            scannedPlugins.put(pluginName, entry);
            totalPlugins.incrementAndGet();
            return new PluginScanResult(pluginName, RiskLevel.MALICIOUS,
                    List.of("Known malicious plugin: " + pluginName));
        }

        for (String pattern : SUSPICIOUS_NAME_PATTERNS) {
            if (pluginName.toLowerCase().matches(pattern.toLowerCase())) {
                suspiciousPlugins.add(pluginName);
                PluginScanEntry entry = new PluginScanEntry(pluginName, pluginName + ".jar",
                        RiskLevel.SUSPICIOUS,
                        List.of("SUSPICIOUS_PLUGIN_NAME: " + pluginName),
                        Instant.now());
                scannedPlugins.put(pluginName, entry);
                totalPlugins.incrementAndGet();
                return new PluginScanResult(pluginName, RiskLevel.SUSPICIOUS,
                        List.of("Suspicious plugin name: " + pluginName));
            }
        }

        PluginScanEntry entry = new PluginScanEntry(pluginName, pluginName + ".jar",
                RiskLevel.SAFE, List.of(), Instant.now());
        scannedPlugins.put(pluginName, entry);
        totalPlugins.incrementAndGet();
        return PluginScanResult.clean(pluginName);
    }

    /**
     * 获取指定插件的扫描结果
     *
     * @param pluginName 插件名称
     * @return 扫描结果Map，未扫描过的插件返回null
     */
    public Map<String, Object> getPluginScanInfo(String pluginName) {
        PluginScanEntry entry = scannedPlugins.get(pluginName);
        if (entry == null) return null;

        Map<String, Object> info = new LinkedHashMap<>();
        info.put("pluginName", entry.pluginName);
        info.put("jarFileName", entry.jarFileName);
        info.put("riskLevel", entry.riskLevel.name());
        info.put("reasons", entry.reasons);
        info.put("scanTime", entry.scanTime.toString());
        return info;
    }

    /**
     * 获取所有恶意插件列表
     *
     * @return 恶意插件名称集合
     */
    public Set<String> getMaliciousPlugins() {
        return new HashSet<>(maliciousPlugins);
    }

    /**
     * 获取所有可疑插件列表
     *
     * @return 可疑插件名称集合
     */
    public Set<String> getSuspiciousPlugins() {
        return new HashSet<>(suspiciousPlugins);
    }

    /**
     * 获取模块运行状态
     *
     * @return 状态Map，包含totalPlugins/suspiciousPlugins/maliciousPlugins
     */
    public Map<String, Object> getStatus() {
        Map<String, Object> s = new LinkedHashMap<>();
        s.put("enabled", config.getSecurity().getSuperEvolution().isBackdoorPluginScanner());
        s.put("totalPlugins", totalPlugins.get());
        s.put("totalScans", totalScans.get());
        s.put("suspiciousPlugins", suspiciousPlugins.size());
        s.put("maliciousPlugins", maliciousPlugins.size());
        s.put("suspiciousPluginList", new ArrayList<>(suspiciousPlugins));
        s.put("maliciousPluginList", new ArrayList<>(maliciousPlugins));

        // 所有已扫描插件摘要
        List<Map<String, Object>> scannedList = new ArrayList<>();
        scannedPlugins.forEach((name, entry) -> {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("pluginName", entry.pluginName);
            m.put("riskLevel", entry.riskLevel.name());
            m.put("reasonCount", entry.reasons.size());
            scannedList.add(m);
        });
        s.put("scannedPluginList", scannedList);
        return s;
    }

    // ==================== 内部数据类和枚举 ====================

    /** 插件风险等级 */
    public enum RiskLevel {
        SAFE,       // 安全：未检测到任何可疑特征
        SUSPICIOUS, // 可疑：存在可疑特征，需人工审核
        MALICIOUS   // 恶意：匹配已知恶意插件或包含明确的后门代码特征
    }

    /** 插件扫描结果记录 */
    private static class PluginScanEntry {
        final String pluginName;
        final String jarFileName;
        final RiskLevel riskLevel;
        final List<String> reasons;
        final Instant scanTime;

        PluginScanEntry(String pluginName, String jarFileName, RiskLevel riskLevel,
                        List<String> reasons, Instant scanTime) {
            this.pluginName = pluginName;
            this.jarFileName = jarFileName;
            this.riskLevel = riskLevel;
            this.reasons = reasons;
            this.scanTime = scanTime;
        }
    }

    /** 插件扫描检测结果 */
    public static class PluginScanResult {
        private final String pluginName;
        private final RiskLevel riskLevel;
        private final List<String> reasons;

        private PluginScanResult(String pluginName, RiskLevel riskLevel, List<String> reasons) {
            this.pluginName = pluginName;
            this.riskLevel = riskLevel;
            this.reasons = reasons;
        }

        public static PluginScanResult clean(String pluginName) {
            return new PluginScanResult(pluginName, RiskLevel.SAFE, List.of());
        }

        public static PluginScanResult suspicious(String pluginName, List<String> reasons) {
            return new PluginScanResult(pluginName, RiskLevel.SUSPICIOUS, reasons);
        }

        public static PluginScanResult malicious(String pluginName, List<String> reasons) {
            return new PluginScanResult(pluginName, RiskLevel.MALICIOUS, reasons);
        }

        public boolean isMalicious() { return riskLevel == RiskLevel.MALICIOUS; }
        public boolean isSuspicious() { return riskLevel == RiskLevel.SUSPICIOUS; }
        public boolean isSafe() { return riskLevel == RiskLevel.SAFE; }
        public RiskLevel getRiskLevel() { return riskLevel; }
        public String getPluginName() { return pluginName; }
        public List<String> getReasons() { return reasons; }
    }
}
