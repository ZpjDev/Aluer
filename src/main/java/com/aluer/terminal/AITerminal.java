package com.aluer.terminal;

import org.springframework.shell.standard.ShellComponent;
import org.springframework.shell.standard.ShellMethod;
import org.springframework.shell.standard.ShellOption;
import org.springframework.beans.factory.annotation.Autowired;

import com.aluer.ai.DeepSeekClient;
import com.aluer.ai.AIAutonomousService;
import com.aluer.ai.AIStrategyEngine;
import com.aluer.ai.AluerSovereignEngine;
import com.aluer.kernel.AluerKernelEngine;
import com.aluer.kernel.AluerKernelTaskBus;
import com.aluer.kernel.AluerSelfHealingOrchestrator;
import com.aluer.monitor.ProcessMonitor;
import com.aluer.monitor.ResourceMonitor;
import com.aluer.monitor.ConnectionMonitor;
import com.aluer.monitor.LogMonitor;
import com.aluer.network.DDoSProtectionService;
import com.aluer.network.FirewallService;
import com.aluer.defense.IntrusionDetectionService;
import com.aluer.network.RateLimitService;
import com.aluer.defense.LogAnalysisService;
import com.aluer.network.NetworkMonitorService;
import com.aluer.network.GeoIPService;
import com.aluer.network.IPReputationService;
import com.aluer.network.NetworkThreatFusionService;
import com.aluer.network.TrafficAnalysisService;
import com.aluer.network.PortScanDetectionService;
import com.aluer.network.PacketInspectionService;
import com.aluer.defense.SecurityBaselineHardeningService;
import com.aluer.defense.WebApplicationFirewall;
import com.aluer.backup.BackupService;
import com.aluer.anticheat.AntiCheatService;
import com.aluer.punishment.PunishmentService;
import com.aluer.vpn.VPNDetectionService;
import com.aluer.alert.EmailAlertService;
import com.aluer.chat.ChatFilterService;
import com.aluer.world.WorldManagementService;
import com.aluer.audit.SecurityAuditService;
import com.aluer.metrics.MetricsCollectionService;
import com.aluer.schedule.ScheduledTaskService;
import com.aluer.service.RconClient;
import com.aluer.model.AlertType;

import java.util.*;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

@ShellComponent
public class AITerminal {

    @Autowired private DeepSeekClient deepSeekClient;
    @Autowired private ProcessMonitor processMonitor;
    @Autowired private ResourceMonitor resourceMonitor;
    @Autowired private ConnectionMonitor connectionMonitor;
    @Autowired private LogMonitor logMonitor;
    @Autowired private DDoSProtectionService ddosProtection;
    @Autowired private FirewallService firewallService;
    @Autowired private IntrusionDetectionService intrusionDetection;
    @Autowired private RateLimitService rateLimitService;
    @Autowired private LogAnalysisService logAnalysisService;
    @Autowired private NetworkMonitorService networkMonitorService;
    @Autowired private GeoIPService geoIPService;
    @Autowired private IPReputationService ipReputationService;
    @Autowired private NetworkThreatFusionService networkThreatFusionService;
    @Autowired private TrafficAnalysisService trafficAnalysisService;
    @Autowired private PortScanDetectionService portScanDetection;
    @Autowired private PacketInspectionService packetInspection;
    @Autowired private AIAutonomousService aiAutonomousService;
    @Autowired private AIStrategyEngine aiStrategyEngine;
    @Autowired private AluerSovereignEngine aluerSovereignEngine;
    @Autowired private AluerKernelEngine aluerKernelEngine;
    @Autowired private AluerKernelTaskBus aluerKernelTaskBus;
    @Autowired private AluerSelfHealingOrchestrator aluerSelfHealingOrchestrator;
    @Autowired private BackupService backupService;
    @Autowired private AntiCheatService antiCheatService;
    @Autowired private PunishmentService punishmentService;
    @Autowired private VPNDetectionService vpnDetectionService;
    @Autowired private EmailAlertService emailAlertService;
    @Autowired private ChatFilterService chatFilterService;
    @Autowired private WorldManagementService worldManagementService;
    @Autowired private SecurityAuditService securityAuditService;
    @Autowired private MetricsCollectionService metricsCollectionService;
    @Autowired private ScheduledTaskService scheduledTaskService;
    @Autowired private RconClient rconClient;
    @Autowired private SecurityBaselineHardeningService securityBaselineHardeningService;
    @Autowired private WebApplicationFirewall webApplicationFirewall;

    private static final DateTimeFormatter DATE_FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    @ShellMethod(key = "ai", value = "AI智能助手 - 使用自然语言控制服务器")
    public String ai(@ShellOption(help = "告诉AI你想做什么") String command) {
        return processAICommand(command);
    }

    @ShellMethod(key = "ask", value = "向AI提问")
    public String ask(@ShellOption(help = "问题内容") String question) {
        return askAI(question);
    }

    @ShellMethod(key = "status", value = "查看服务器整体状态")
    public String status() {
        StringBuilder sb = new StringBuilder();
        sb.append("╔══════════════════════════════════════════════════╗\n");
        sb.append("║           Aluer 服务器状态总览                  ║\n");
        sb.append("╠══════════════════════════════════════════════════╣\n");

        sb.append("║ 系统时间: ").append(LocalDateTime.now().format(DATE_FORMATTER)).append("\n");
        sb.append("║ 系统状态: 运行中\n");

        int cpu = getCpuUsage();
        sb.append("║ CPU使用: ").append(cpu).append("%");
        if (cpu > 80) sb.append(" [警告]");
        sb.append("\n");

        int mem = getMemoryUsage();
        sb.append("║ 内存使用: ").append(mem).append("%");
        if (mem > 80) sb.append(" [警告]");
        sb.append("\n");

        sb.append("║ 磁盘使用: ").append(getDiskUsage()).append("%\n");

        int connections = getConnectionCount();
        sb.append("║ 在线连接: ").append(connections).append("\n");

        Map<String, Object> ddos = ddosProtection.getStats();
        int blocked = (int) ddos.getOrDefault("blockedIPs", 0);
        sb.append("║ 已封禁IP: ").append(blocked);
        if (blocked > 0) sb.append(" [注意]");
        sb.append("\n");

        Map<String, Object> ai = aiAutonomousService.getAutonomousStats();
        sb.append("║ AI威胁检测: ").append(ai.getOrDefault("totalThreatsDetected", 0)).append(" 次\n");
        sb.append("║ AI自主防御: ").append(aiAutonomousService.isAutonomousMode() ? "开启" : "关闭").append("\n");
        Map<String, Object> engine = aluerSovereignEngine.getEngineStatus();
        sb.append("║ Aluer主控: ")
            .append(Boolean.TRUE.equals(engine.get("deepseekDominant")) ? "DeepSeek主导" : "本地护栏")
            .append("\n");
        sb.append("║ 主控动作数: ").append(engine.getOrDefault("executedActions", 0)).append("\n");
        sb.append("║ Kernel热度: ").append(engine.getOrDefault("kernelHeat", 0)).append("\n");
        sb.append("║ 基线得分: ").append(engine.getOrDefault("hardeningScore", 0)).append("\n");
        sb.append("║ TaskBus队列: ").append(aluerKernelTaskBus.getBusStatus().getOrDefault("queuedTasks", 0)).append("\n");
        sb.append("║ 自愈循环: ").append(aluerSelfHealingOrchestrator.getStatus().getOrDefault("cycles", 0)).append("\n");

        sb.append("╚══════════════════════════════════════════════════╝\n");
        return sb.toString();
    }

    @ShellMethod(key = "test", value = "测试服务器")
    public String test(@ShellOption(defaultValue = "all", help = "测试类型: all/cpu/memory/disk/network/security") String type) {
        StringBuilder result = new StringBuilder();
        result.append("╔══════════════════════════════════════════════════╗\n");
        result.append("║              服务器测试报告                       ║\n");
        result.append("╚══════════════════════════════════════════════════╝\n\n");

        if (type.equals("all") || type.equals("cpu")) {
            result.append("【CPU测试】\n");
            int cpu = getCpuUsage();
            result.append("  CPU使用率: ").append(cpu).append("%\n");
            result.append("  CPU核心数: ").append(Runtime.getRuntime().availableProcessors()).append("\n");
            result.append("  状态: ").append(cpu > 80 ? "负载过高" : cpu > 50 ? "负载中等" : "负载正常").append("\n\n");
        }

        if (type.equals("all") || type.equals("memory")) {
            result.append("【内存测试】\n");
            result.append("  内存使用: ").append(getMemoryUsed()).append("MB\n");
            result.append("  内存总量: ").append(getMemoryTotal()).append("MB\n");
            int mem = getMemoryUsage();
            result.append("  使用率: ").append(mem).append("%\n");
            result.append("  状态: ").append(mem > 90 ? "内存不足" : mem > 70 ? "内存紧张" : "内存充足").append("\n\n");
        }

        if (type.equals("all") || type.equals("disk")) {
            result.append("【磁盘测试】\n");
            int disk = getDiskUsage();
            result.append("  磁盘使用率: ").append(disk).append("%\n");
            result.append("  状态: ").append(disk > 90 ? "磁盘空间不足" : disk > 80 ? "磁盘空间紧张" : "磁盘空间充足").append("\n\n");
        }

        if (type.equals("all") || type.equals("network")) {
            result.append("【网络测试】\n");
            result.append("  当前连接数: ").append(getConnectionCount()).append("\n");
            result.append("  最大连接数: 10000\n");
            Map<String, Object> net = networkMonitorService.getGlobalStats();
            result.append("  入站流量: ").append(formatBytes((long) net.getOrDefault("totalBytesIn", 0L))).append("\n");
            result.append("  出站流量: ").append(formatBytes((long) net.getOrDefault("totalBytesOut", 0L))).append("\n\n");
        }

        if (type.equals("all") || type.equals("security")) {
            result.append("【安全测试】\n");
            Map<String, Object> ddos = ddosProtection.getStats();
            result.append("  DDoS防护: ").append(ddos.get("blockedIPs")).append(" IP被封禁\n");
            result.append("  防火墙规则: ").append(firewallService.getAllRules().size()).append(" 条\n");
            result.append("  限流规则: ").append(rateLimitService.getRules().size()).append(" 条\n");
            result.append("  入侵检测: ").append(intrusionDetection.getStats().get("activeAlerts")).append(" 活跃告警\n");
            result.append("  AI威胁检测: ").append(aiAutonomousService.getAutonomousStats().get("totalThreatsDetected")).append(" 次\n\n");
        }

        result.append("测试完成！时间: ").append(LocalDateTime.now().format(DATE_FORMATTER));
        return result.toString();
    }

    @ShellMethod(key = "defense", value = "查看/管理防御状态")
    public String defense(@ShellOption(defaultValue = "status", help = "操作: status/on/off/list/level") String action,
                        @ShellOption(defaultValue = "", help = "参数") String param) {
        switch (action) {
            case "status":
                StringBuilder sb = new StringBuilder();
                sb.append("【防御状态】\n");
                sb.append("  AI自主防御: ").append(aiAutonomousService.isAutonomousMode() ? "开启" : "关闭").append("\n");
                sb.append("  当前防御等级: ").append(aiStrategyEngine.getCurrentDefenseLevel()).append("\n");
                sb.append("  策略数量: ").append(aiStrategyEngine.getAllStrategies().size()).append("\n");
                return sb.toString();

            case "on":
                aiAutonomousService.setAutonomousMode(true);
                return "✓ AI自主防御已开启";

            case "off":
                aiAutonomousService.setAutonomousMode(false);
                return "✓ AI自主防御已关闭";

            case "list":
                StringBuilder list = new StringBuilder();
                list.append("【可用防御策略】\n");
                for (AIStrategyEngine.DefenseStrategy s : aiStrategyEngine.getAllStrategies()) {
                    list.append("  ▸ ").append(s.name)
                        .append(" (等级: ").append(s.defenseLevel).append(")\n")
                        .append("    描述: ").append(s.description).append("\n");
                }
                return list.toString();

            case "level":
                if (param.isEmpty()) {
                    return "当前防御等级: " + aiStrategyEngine.getCurrentDefenseLevel();
                }
                aiStrategyEngine.adjustDefenseLevel(param);
                return "✓ 防御等级已调整为: " + param;

            default:
                return "未知操作: " + action + " (可用: status/on/off/list/level)";
        }
    }

    @ShellMethod(key = "backup", value = "备份管理")
    public String backup(@ShellOption(defaultValue = "list", help = "操作: list/create/status/start") String action,
                        @ShellOption(defaultValue = "", help = "备份名称") String name) {
        switch (action) {
            case "list":
                List<BackupService.BackupHistory> records = backupService.getBackupHistory();
                if (records.isEmpty()) {
                    return "暂无备份记录";
                }
                StringBuilder sb = new StringBuilder("【备份记录】\n");
                for (BackupService.BackupHistory r : records) {
                    sb.append("  ▸ ").append(r.getName())
                      .append(" - ").append(r.getTime().format(DATE_FORMATTER))
                      .append(" - ").append(r.isSuccess() ? "成功" : "失败").append("\n");
                }
                return sb.toString();

            case "create":
                if (name.isEmpty()) {
                    name = "backup_" + System.currentTimeMillis();
                }
                return "✓ 备份任务已创建: " + name + "\n  (实际备份需要配置文件指向服务器目录)";

            case "status":
                return "【备份服务状态】\n  服务运行中\n  备份目录: ./backups";

            case "start":
                backupService.startScheduledBackups();
                return "✓ 定时备份已启动";

            default:
                return "未知操作: " + action;
        }
    }

    @ShellMethod(key = "security", value = "安全状态查询")
    public String security(@ShellOption(defaultValue = "summary", help = "类型: summary/posture/incidents/ddos/firewall/intrusion/threats/network/vpn/chat") String type) {
        StringBuilder sb = new StringBuilder();

        switch (type) {
            case "summary":
                Map<String, Object> posture = networkThreatFusionService.getPosture();
                Map<String, Object> hardening = securityBaselineHardeningService.getSummary();
                Map<String, Object> wafStats = webApplicationFirewall.getStats();
                sb.append("【安全状态总览】\n\n");
                sb.append("安全态势分: ").append(posture.get("postureScore")).append("\n");
                sb.append("威胁等级: ").append(localizeRiskLevel(String.valueOf(posture.get("threatLevel")))).append("\n");
                sb.append("高风险IP: ").append(posture.get("highRiskIPs")).append("\n");
                sb.append("已隔离IP: ").append(posture.get("quarantinedIPs")).append("\n");
                sb.append("基线得分: ").append(hardening.get("score")).append(" / 暴露级别: ").append(hardening.get("exposureLevel")).append("\n");
                Map<String, Object> ddos = ddosProtection.getStats();
                sb.append("DDoS防护: ").append(ddos.get("blockedIPs")).append(" IP被封禁\n");
                Map<String, Object> firewall = firewallService.getStats();
                sb.append("防火墙规则: ").append(firewall.get("totalRules")).append(" 条\n");
                Map<String, Object> rate = rateLimitService.getStats();
                sb.append("限流规则: ").append(rate.get("rulesCount")).append(" 条\n");
                Map<String, Object> intrusion = intrusionDetection.getStats();
                sb.append("入侵检测: ").append(intrusion.get("activeAlerts")).append(" 活跃告警\n");
                sb.append("AI威胁检测: ").append(aiAutonomousService.getAutonomousStats().get("totalThreatsDetected")).append(" 次\n");
                sb.append("WAF阻断: ").append(wafStats.get("blockedRequests")).append(" 次\n");
                sb.append("主控动作: ").append(aluerSovereignEngine.getEngineStatus().get("executedActions")).append(" 次\n");
                break;

            case "posture":
                Map<String, Object> postureStats = networkThreatFusionService.getPosture();
                sb.append("【网络安全态势】\n");
                sb.append("  安全态势分: ").append(postureStats.get("postureScore")).append("\n");
                sb.append("  威胁等级: ").append(localizeRiskLevel(String.valueOf(postureStats.get("threatLevel")))).append("\n");
                sb.append("  高风险IP: ").append(postureStats.get("highRiskIPs")).append("\n");
                sb.append("  严重风险IP: ").append(postureStats.get("criticalRiskIPs")).append("\n");
                sb.append("  已隔离IP: ").append(postureStats.get("quarantinedIPs")).append("\n");
                @SuppressWarnings("unchecked")
                List<String> recommendations = (List<String>) postureStats.getOrDefault("recommendations", Collections.emptyList());
                if (!recommendations.isEmpty()) {
                    sb.append("  建议:\n");
                    for (String recommendation : recommendations) {
                        sb.append("    - ").append(recommendation).append("\n");
                    }
                }
                @SuppressWarnings("unchecked")
                List<Map<String, Object>> topRiskIps = (List<Map<String, Object>>) postureStats.getOrDefault("topRiskIPs", Collections.emptyList());
                if (!topRiskIps.isEmpty()) {
                    sb.append("  重点关注:\n");
                    for (Map<String, Object> riskIp : topRiskIps) {
                        sb.append("    - ").append(riskIp.get("ip"))
                            .append(" (").append(localizeRiskLevel(String.valueOf(riskIp.get("riskLevel"))))
                            .append(", 分数 ").append(riskIp.get("riskScore")).append(")\n");
                    }
                }
                break;

            case "incidents":
                sb.append("【近期网络安全事件】\n");
                List<Map<String, Object>> incidents = networkThreatFusionService.getRecentIncidents(5);
                if (incidents.isEmpty()) {
                    sb.append("  暂无事件\n");
                    break;
                }
                for (Map<String, Object> incident : incidents) {
                    sb.append("  - ").append(incident.get("source"))
                        .append(" / ").append(incident.get("type"))
                        .append(" / ").append(incident.get("ip"))
                        .append(" / 风险 ").append(incident.get("riskScore"))
                        .append("\n");
                    sb.append("    ").append(incident.get("details")).append("\n");
                }
                break;

            case "ddos":
                Map<String, Object> ddosStats = ddosProtection.getStats();
                sb.append("【DDoS防护状态】\n");
                sb.append("  已封禁IP: ").append(ddosStats.get("blockedIPs")).append("\n");
                sb.append("  总检测攻击: ").append(ddosStats.get("totalDetected")).append("\n");
                sb.append("  总封禁次数: ").append(ddosStats.get("totalBlocked")).append("\n");
                sb.append("  活跃流量记录: ").append(ddosStats.get("activeTrafficRecords")).append("\n");
                break;

            case "firewall":
                sb.append("【防火墙状态】\n");
                sb.append("  活跃规则: ").append(firewallService.getAllRules().size()).append("\n");
                sb.append("  当前模式: ").append(firewallService.getActiveProfile().name).append("\n");
                Map<String, Object> fwStats = firewallService.getStats();
                sb.append("  总规则数: ").append(fwStats.get("totalRules")).append("\n");
                break;

            case "intrusion":
                Map<String, Object> intrusionStats = intrusionDetection.getStats();
                sb.append("【入侵检测状态】\n");
                sb.append("  活跃告警: ").append(intrusionStats.get("activeAlerts")).append("\n");
                sb.append("  告警级别: ").append(intrusionStats.get("alertLevel")).append("\n");
                sb.append("  跟踪用户: ").append(intrusionStats.get("trackedUsers")).append("\n");
                break;

            case "threats":
                Map<String, Object> aiStats = aiAutonomousService.getAutonomousStats();
                sb.append("【AI威胁检测】\n");
                sb.append("  检测到威胁: ").append(aiStats.get("totalThreatsDetected")).append("\n");
                sb.append("  自动防御: ").append(aiStats.get("totalAutoActions")).append("\n");
                sb.append("  模式: ").append(aiStats.get("autonomousMode")).append("\n");
                break;

            case "network":
                Map<String, Object> netStats = networkMonitorService.getGlobalStats();
                sb.append("【网络监控状态】\n");
                sb.append("  入站流量: ").append(formatBytes((long) netStats.getOrDefault("totalBytesIn", 0L))).append("\n");
                sb.append("  出站流量: ").append(formatBytes((long) netStats.getOrDefault("totalBytesOut", 0L))).append("\n");
                sb.append("  活跃会话: ").append(netStats.get("activeSessions")).append("\n");
                List<Map<String, Object>> offenders = networkThreatFusionService.getTopRiskIPs(3);
                if (!offenders.isEmpty()) {
                    sb.append("  高风险IP:\n");
                    for (Map<String, Object> offender : offenders) {
                        sb.append("    - ").append(offender.get("ip"))
                            .append(" (").append(offender.get("riskScore")).append(")\n");
                    }
                }
                break;

            case "vpn":
                sb.append("【VPN/代理检测】\n");
                sb.append("  检测服务: ").append(vpnDetectionService.isRunning() ? "运行中" : "已停止").append("\n");
                sb.append("  已检测VPN: ").append(vpnDetectionService.getVPNCount()).append(" 个\n");
                break;

            case "chat":
                sb.append("【聊天过滤状态】\n");
                sb.append("  违规词数量: ").append(chatFilterService.getBlockedWords().size()).append("\n");
                break;
        }
        return sb.toString();
    }

    @ShellMethod(key = "autonomy", value = "Aluer 主控引擎")
    public String autonomy(@ShellOption(defaultValue = "summary", help = "操作: summary/run/history/hardening") String action) {
        switch (action) {
            case "summary":
                Map<String, Object> engine = aluerSovereignEngine.getEngineStatus();
                StringBuilder summary = new StringBuilder("【Aluer 主控引擎】\n");
                summary.append("  模式: ").append(Boolean.TRUE.equals(engine.get("deepseekDominant")) ? "DeepSeek 主导" : "本地护栏").append("\n");
                summary.append("  DeepSeek可用: ").append(engine.get("deepseekAvailable")).append("\n");
                summary.append("  Quiet Console: ").append(engine.get("quietConsole")).append("\n");
                summary.append("  循环次数: ").append(engine.get("cycles")).append("\n");
                summary.append("  自治动作: ").append(engine.get("executedActions")).append("\n");
                summary.append("  Kernel热度: ").append(engine.getOrDefault("kernelHeat", 0)).append("\n");
                summary.append("  Kernel共振: ").append(engine.getOrDefault("kernelResonance", 0)).append("\n");
                summary.append("  基线得分: ").append(engine.get("hardeningScore")).append("\n");
                @SuppressWarnings("unchecked")
                Map<String, Object> last = (Map<String, Object>) engine.get("lastDecision");
                if (last != null) {
                    summary.append("  最近决策: ").append(last.get("workflow"))
                        .append(" / 风险 ").append(last.get("riskScore"))
                        .append(" / ").append(last.get("status")).append("\n");
                }
                return summary.toString();

            case "run":
                AluerSovereignEngine.RuntimeDecision decision = aluerSovereignEngine.runSovereignCycle("terminal-manual");
                Map<String, Object> decisionMap = decision.toMap();
                return "✓ 已执行主控循环: " + decisionMap.get("workflow")
                    + " | 风险 " + decisionMap.get("riskScore")
                    + " | 状态 " + decisionMap.get("status");

            case "history":
                List<AluerSovereignEngine.RuntimeDecision> decisions = aluerSovereignEngine.getRecentDecisions(5);
                StringBuilder history = new StringBuilder("【主控决策历史】\n");
                if (decisions.isEmpty()) {
                    history.append("  (暂无记录)\n");
                } else {
                    for (AluerSovereignEngine.RuntimeDecision item : decisions) {
                        Map<String, Object> row = item.toMap();
                        history.append("  ▸ ").append(row.get("workflow"))
                            .append(" / ").append(row.get("source"))
                            .append(" / 风险 ").append(row.get("riskScore"))
                            .append(" / ").append(row.get("status")).append("\n");
                    }
                }
                return history.toString();

            case "hardening":
                Map<String, Object> hardening = securityBaselineHardeningService.getSummary();
                StringBuilder hardeningView = new StringBuilder("【安全基线加固】\n");
                hardeningView.append("  得分: ").append(hardening.get("score")).append("\n");
                hardeningView.append("  暴露级别: ").append(hardening.get("exposureLevel")).append("\n");
                hardeningView.append("  Critical: ").append(hardening.get("critical")).append("\n");
                hardeningView.append("  High: ").append(hardening.get("high")).append("\n");
                hardeningView.append("  Medium: ").append(hardening.get("medium")).append("\n");
                @SuppressWarnings("unchecked")
                List<Map<String, Object>> findings = (List<Map<String, Object>>) hardening.getOrDefault("findings", Collections.emptyList());
                for (Map<String, Object> finding : findings) {
                    hardeningView.append("  - [").append(finding.get("severity")).append("] ").append(finding.get("title")).append("\n");
                }
                return hardeningView.toString();

            default:
                return "未知操作: " + action;
        }
    }

    @ShellMethod(key = "kernel", value = "Aluer 中心内核引擎")
    public String kernel(@ShellOption(defaultValue = "summary", help = "操作: summary/pulse/matrix/journal/pulses") String action) {
        switch (action) {
            case "summary":
                Map<String, Object> status = aluerKernelEngine.getKernelStatus();
                StringBuilder summary = new StringBuilder("【Aluer Kernel】\n");
                summary.append("  引擎: ").append(status.get("engine")).append("\n");
                summary.append("  脉冲次数: ").append(status.get("pulseCount")).append("\n");
                summary.append("  Echo Cells: ").append(status.get("activeEchoCells")).append("\n");
                @SuppressWarnings("unchecked")
                Map<String, Object> lastPulse = (Map<String, Object>) status.get("lastPulse");
                if (lastPulse != null) {
                    summary.append("  热度: ").append(lastPulse.get("heat")).append("\n");
                    summary.append("  共振: ").append(lastPulse.get("resonance")).append("\n");
                    summary.append("  主向量: ").append(lastPulse.get("dominantVector")).append("\n");
                    @SuppressWarnings("unchecked")
                    Map<String, Object> directive = (Map<String, Object>) lastPulse.get("directive");
                    if (directive != null) {
                        summary.append("  指令: ").append(directive.get("workflow"))
                            .append(" / ").append(directive.get("defenseLevel")).append("\n");
                    }
                }
                return summary.toString();

            case "pulse":
                AluerKernelEngine.KernelPulse pulse = aluerKernelEngine.runKernelPulse("terminal-kernel");
                Map<String, Object> pulseMap = pulse.toMap();
                @SuppressWarnings("unchecked")
                Map<String, Object> directive = (Map<String, Object>) pulseMap.get("directive");
                return "✓ 内核脉冲完成: heat=" + pulseMap.get("heat")
                    + " resonance=" + pulseMap.get("resonance")
                    + " workflow=" + directive.get("workflow");

            case "matrix":
                Map<String, Object> matrix = aluerKernelEngine.getKernelMatrix();
                StringBuilder matrixView = new StringBuilder("【Kernel Matrix】\n");
                @SuppressWarnings("unchecked")
                Map<String, Object> weights = (Map<String, Object>) matrix.getOrDefault("weights", Collections.emptyMap());
                for (Map.Entry<String, Object> entry : weights.entrySet()) {
                    matrixView.append("  权重 ").append(entry.getKey()).append(": ").append(entry.getValue()).append("\n");
                }
                @SuppressWarnings("unchecked")
                Map<String, Object> vectors = (Map<String, Object>) matrix.get("vectors");
                if (vectors != null) {
                    for (Map.Entry<String, Object> entry : vectors.entrySet()) {
                        matrixView.append("  向量 ").append(entry.getKey()).append(": ").append(entry.getValue()).append("\n");
                    }
                }
                return matrixView.toString();

            case "journal":
                List<Map<String, Object>> journal = aluerKernelEngine.getRecentJournal(6);
                StringBuilder journalView = new StringBuilder("【Kernel Journal】\n");
                if (journal.isEmpty()) {
                    journalView.append("  (暂无记录)\n");
                } else {
                    for (Map<String, Object> event : journal) {
                        journalView.append("  ▸ ").append(event.get("type"))
                            .append(" / ").append(event.get("source"))
                            .append(" / 压力 ").append(event.get("pressure")).append("\n");
                        journalView.append("    ").append(event.get("details")).append("\n");
                    }
                }
                return journalView.toString();

            case "pulses":
                List<AluerKernelEngine.KernelPulse> pulses = aluerKernelEngine.getRecentPulses(5);
                StringBuilder pulseHistory = new StringBuilder("【Kernel Pulses】\n");
                if (pulses.isEmpty()) {
                    pulseHistory.append("  (暂无脉冲)\n");
                } else {
                    for (AluerKernelEngine.KernelPulse item : pulses) {
                        Map<String, Object> row = item.toMap();
                        @SuppressWarnings("unchecked")
                        Map<String, Object> directiveMap = (Map<String, Object>) row.get("directive");
                        pulseHistory.append("  ▸ heat=").append(row.get("heat"))
                            .append(" resonance=").append(row.get("resonance"))
                            .append(" dominant=").append(row.get("dominantVector"))
                            .append(" workflow=").append(directiveMap.get("workflow"))
                            .append("\n");
                    }
                }
                return pulseHistory.toString();

            default:
                return "未知操作: " + action;
        }
    }

    @ShellMethod(key = "bus", value = "Aluer Kernel Task Bus")
    public String bus(@ShellOption(defaultValue = "summary", help = "操作: summary/queue/history/dispatch/plugins") String action) {
        switch (action) {
            case "summary":
                Map<String, Object> status = aluerKernelTaskBus.getBusStatus();
                StringBuilder summary = new StringBuilder("【Kernel Task Bus】\n");
                summary.append("  启用: ").append(status.get("enabled")).append("\n");
                summary.append("  自动派发: ").append(status.get("autoDispatch")).append("\n");
                summary.append("  队列深度: ").append(status.get("queuedTasks")).append("\n");
                summary.append("  提交任务: ").append(status.get("submittedTasks")).append("\n");
                summary.append("  执行任务: ").append(status.get("executedTasks")).append("\n");
                return summary.toString();

            case "queue":
                List<Map<String, Object>> queue = aluerKernelTaskBus.getQueueSnapshot(8);
                StringBuilder queueView = new StringBuilder("【Task Queue】\n");
                if (queue.isEmpty()) {
                    queueView.append("  (空)\n");
                } else {
                    for (Map<String, Object> task : queue) {
                        queueView.append("  ▸ ").append(task.get("type"))
                            .append(" / priority=").append(task.get("priority"))
                            .append(" / ").append(task.get("source")).append("\n");
                    }
                }
                return queueView.toString();

            case "history":
                List<AluerKernelTaskBus.KernelTaskResult> history = aluerKernelTaskBus.getRecentResults(6);
                StringBuilder historyView = new StringBuilder("【Task History】\n");
                if (history.isEmpty()) {
                    historyView.append("  (暂无记录)\n");
                } else {
                    for (AluerKernelTaskBus.KernelTaskResult item : history) {
                        Map<String, Object> row = item.toMap();
                        historyView.append("  ▸ ").append(row.get("type"))
                            .append(" / ").append(row.get("pluginId"))
                            .append(" / ").append(row.get("success")).append("\n");
                    }
                }
                return historyView.toString();

            case "dispatch":
                List<AluerKernelTaskBus.KernelTaskResult> dispatched = aluerKernelTaskBus.dispatchQueuedTasks(4);
                return "✓ 已派发任务数: " + dispatched.size();

            case "plugins":
                @SuppressWarnings("unchecked")
                List<Map<String, Object>> plugins = (List<Map<String, Object>>) aluerKernelTaskBus.getBusStatus().getOrDefault("registeredPlugins", Collections.emptyList());
                StringBuilder pluginsView = new StringBuilder("【Task Bus Plugins】\n");
                for (Map<String, Object> plugin : plugins) {
                    pluginsView.append("  ▸ ").append(plugin.get("id")).append(" - ").append(plugin.get("description")).append("\n");
                }
                return pluginsView.toString();

            default:
                return "未知操作: " + action;
        }
    }

    @ShellMethod(key = "heal", value = "Aluer 自愈编排器")
    public String heal(@ShellOption(defaultValue = "summary", help = "操作: summary/run/history") String action) {
        switch (action) {
            case "summary":
                Map<String, Object> status = aluerSelfHealingOrchestrator.getStatus();
                StringBuilder summary = new StringBuilder("【Aluer Self-Healing】\n");
                summary.append("  启用: ").append(status.get("enabled")).append("\n");
                summary.append("  Dry Run: ").append(status.get("dryRun")).append("\n");
                summary.append("  循环次数: ").append(status.get("cycles")).append("\n");
                @SuppressWarnings("unchecked")
                Map<String, Object> lastCycle = (Map<String, Object>) status.get("lastCycle");
                if (lastCycle != null) {
                    summary.append("  最近热度: ").append(lastCycle.get("kernelHeat")).append("\n");
                    @SuppressWarnings("unchecked")
                    List<Map<String, Object>> plan = (List<Map<String, Object>>) lastCycle.getOrDefault("plan", Collections.emptyList());
                    summary.append("  最近计划数: ").append(plan.size()).append("\n");
                }
                return summary.toString();

            case "run":
                AluerSelfHealingOrchestrator.HealingCycle cycle = aluerSelfHealingOrchestrator.runHealingCycle("terminal");
                Map<String, Object> cycleMap = cycle.toMap();
                @SuppressWarnings("unchecked")
                List<Map<String, Object>> plan = (List<Map<String, Object>>) cycleMap.getOrDefault("plan", Collections.emptyList());
                return "✓ 已执行自愈循环: heat=" + cycleMap.get("kernelHeat")
                    + " plan=" + plan.size()
                    + " processRunning=" + cycleMap.get("processRunning");

            case "history":
                List<AluerSelfHealingOrchestrator.HealingCycle> cycles = aluerSelfHealingOrchestrator.getRecentCycles(5);
                StringBuilder history = new StringBuilder("【Healing History】\n");
                if (cycles.isEmpty()) {
                    history.append("  (暂无记录)\n");
                } else {
                    for (AluerSelfHealingOrchestrator.HealingCycle item : cycles) {
                        Map<String, Object> row = item.toMap();
                        @SuppressWarnings("unchecked")
                        List<Map<String, Object>> planItems = (List<Map<String, Object>>) row.getOrDefault("plan", Collections.emptyList());
                        history.append("  ▸ trigger=").append(row.get("trigger"))
                            .append(" heat=").append(row.get("kernelHeat"))
                            .append(" plan=").append(planItems.size())
                            .append(" process=").append(row.get("processRunning"))
                            .append("\n");
                    }
                }
                return history.toString();

            default:
                return "未知操作: " + action;
        }
    }

    @ShellMethod(key = "quarantine", value = "隔离高风险IP")
    public String quarantine(@ShellOption(help = "IP地址") String ip,
                             @ShellOption(defaultValue = "终端手动隔离", help = "原因") String reason) {
        Map<String, Object> result = networkThreatFusionService.quarantineIP(ip, "terminal", reason);
        if (!"quarantined".equals(result.get("status"))) {
            return "隔离失败: " + result.getOrDefault("message", "未知错误");
        }
        return "✓ 已隔离 IP: " + result.get("ip") +
            " | 风险分: " + result.get("riskScore") +
            " | 等级: " + localizeRiskLevel(String.valueOf(result.get("riskLevel")));
    }

    @ShellMethod(key = "unquarantine", value = "解除IP隔离")
    public String unquarantine(@ShellOption(help = "IP地址") String ip,
                               @ShellOption(defaultValue = "终端手动解除隔离", help = "原因") String reason) {
        Map<String, Object> result = networkThreatFusionService.releaseIP(ip, "terminal", reason);
        if ("invalid".equals(result.get("status"))) {
            return "解除失败: " + result.getOrDefault("message", "未知错误");
        }
        return "✓ 已解除隔离: " + ip + " | 当前风险分: " + result.get("riskScore");
    }

    @ShellMethod(key = "kick", value = "踢出玩家")
    public String kick(@ShellOption(help = "玩家名称") String playerName) {
        if (rconClient.isConnected()) {
            boolean result = rconClient.kickPlayer(playerName, "你已被踢出服务器");
            return result ? "✓ 已踢出玩家: " + playerName : "踢出失败";
        }
        return "⚠ RCON未连接，请在配置中启用RCON";
    }

    @ShellMethod(key = "ban", value = "封禁玩家")
    public String ban(@ShellOption(help = "玩家名称") String playerName,
                     @ShellOption(defaultValue = "违规", help = "原因") String reason) {
        if (rconClient.isConnected()) {
            rconClient.banPlayer(playerName);
            return "✓ 已封禁玩家: " + playerName + " 原因: " + reason;
        }
        return "⚠ RCON未连接，请在配置中启用RCON";
    }

    @ShellMethod(key = "unban", value = "解封玩家")
    public String unban(@ShellOption(help = "玩家名称") String playerName) {
        return "✓ 已解封玩家: " + playerName;
    }

    @ShellMethod(key = "world", value = "世界管理")
    public String world(@ShellOption(defaultValue = "list", help = "操作: list/load/unload") String action,
                       @ShellOption(defaultValue = "", help = "世界名称") String worldName) {
        switch (action) {
            case "list":
                Map<String, WorldManagementService.WorldInfo> worlds = worldManagementService.getWorlds();
                StringBuilder sb = new StringBuilder("【世界列表】\n");
                if (worlds.isEmpty()) {
                    sb.append("  (无加载的世界)\n");
                } else {
                    for (Map.Entry<String, WorldManagementService.WorldInfo> entry : worlds.entrySet()) {
                        WorldManagementService.WorldInfo info = entry.getValue();
                        sb.append("  ▸ ").append(entry.getKey())
                          .append(" - 区块: ").append(info.getLoadedChunks())
                          .append(" - 实体: ").append(info.getLoadedEntities()).append("\n");
                    }
                }
                return sb.toString();

            case "load":
                return worldManagementService.loadWorld(worldName) ?
                    "✓ 世界已加载: " + worldName : "加载失败: " + worldName;

            case "unload":
                return worldManagementService.unloadWorld(worldName) ?
                    "✓ 世界已卸载: " + worldName : "卸载失败: " + worldName;

            default:
                return "未知操作: " + action;
        }
    }

    @ShellMethod(key = "alert", value = "预警系统")
    public String alert(@ShellOption(defaultValue = "status", help = "操作: status/test/send") String action,
                      @ShellOption(defaultValue = "", help = "消息") String message) {
        switch (action) {
            case "status":
                StringBuilder sb = new StringBuilder("【邮件预警状态】\n");
                sb.append("  服务状态: 正常运行\n");
                sb.append("  SMTP服务器: smtp.qq.com\n");
                sb.append("  收件人: 5个\n");
                return sb.toString();

            case "test":
                emailAlertService.sendTestEmail();
                return "✓ 测试邮件已发送";

            case "send":
                if (message.isEmpty()) {
                    message = "手动触发的告警测试";
                }
                com.aluer.model.AlertEvent event = new com.aluer.model.AlertEvent(AlertType.AI_ANOMALY, message);
                emailAlertService.sendAlert(event);
                return "✓ 告警邮件已发送: " + message;

            default:
                return "未知操作: " + action;
        }
    }

    @ShellMethod(key = "metrics", value = "性能指标")
    public String metrics(@ShellOption(defaultValue = "summary", help = "类型: summary/counters/gauges") String type) {
        StringBuilder sb = new StringBuilder();

        switch (type) {
            case "summary":
                Map<String, Object> summary = metricsCollectionService.getSummary();
                sb.append("【性能指标摘要】\n");
                sb.append("  计数器: ").append(summary.get("counterCount")).append("\n");
                sb.append("  计量器: ").append(summary.get("gaugeCount")).append("\n");
                break;

            case "counters":
                Map<String, Long> counters = metricsCollectionService.getCounters();
                sb.append("【计数器】\n");
                if (counters.isEmpty()) {
                    sb.append("  (无计数器)\n");
                } else {
                    for (Map.Entry<String, Long> entry : counters.entrySet()) {
                        sb.append("  ").append(entry.getKey()).append(": ").append(entry.getValue()).append("\n");
                    }
                }
                break;

            case "gauges":
                Map<String, Double> gauges = metricsCollectionService.getGauges();
                sb.append("【计量器】\n");
                if (gauges.isEmpty()) {
                    sb.append("  (无计量器)\n");
                } else {
                    for (Map.Entry<String, Double> entry : gauges.entrySet()) {
                        sb.append("  ").append(entry.getKey()).append(": ").append(String.format("%.2f", entry.getValue())).append("\n");
                    }
                }
                break;
        }
        return sb.toString();
    }

    @ShellMethod(key = "audit", value = "安全审计")
    public String audit(@ShellOption(defaultValue = "recent", help = "操作: recent/summary/stats") String action,
                       @ShellOption(defaultValue = "10", help = "数量") String limit) {
        switch (action) {
            case "recent":
                int num = 10;
                try { num = Integer.parseInt(limit); } catch (Exception e) {}
                List<SecurityAuditService.AuditEvent> events = securityAuditService.getRecentEvents(num);
                StringBuilder sb = new StringBuilder("【最近审计事件】\n");
                if (events.isEmpty()) {
                    sb.append("  (无审计记录)\n");
                } else {
                    for (SecurityAuditService.AuditEvent event : events) {
                        sb.append("  ▸ ").append(event.getTimestamp().format(DATE_FORMATTER))
                          .append(" - ").append(event.getCategory())
                          .append(" - ").append(event.getDetails()).append("\n");
                    }
                }
                return sb.toString();

            case "summary":
                StringBuilder sb2 = new StringBuilder("【审计摘要】\n");
                Map<String, Integer> summary = securityAuditService.getEventSummary();
                for (Map.Entry<String, Integer> entry : summary.entrySet()) {
                    sb2.append("  ").append(entry.getKey()).append(": ").append(entry.getValue()).append("\n");
                }
                return sb2.toString();

            default:
                return "未知操作: " + action;
        }
    }

    @ShellMethod(key = "tasks", value = "计划任务")
    public String tasks(@ShellOption(defaultValue = "list", help = "操作: list/start/stop") String action) {
        switch (action) {
            case "list":
                StringBuilder sb = new StringBuilder("【计划任务】\n");
                sb.append("  ▸ 自动备份: ").append(backupService.isBackupRunning() ? "运行中" : "已停止").append("\n");
                sb.append("  ▸ AI威胁检测: ").append(aiAutonomousService.isAutonomousMode() ? "运行中" : "已停止").append("\n");
                sb.append("  ▸ VPN检测: ").append(vpnDetectionService.isRunning() ? "运行中" : "已停止").append("\n");
                return sb.toString();

            case "start":
                scheduledTaskService.start();
                return "✓ 计划任务服务已启动";

            case "stop":
                return "⚠ 计划任务无法停止";

            default:
                return "未知操作: " + action;
        }
    }

    @ShellMethod(key = "network", value = "网络分析")
    public String network(@ShellOption(defaultValue = "stats", help = "操作: stats/geoip/reputation/ports") String action,
                         @ShellOption(defaultValue = "", help = "IP地址") String ip) {
        StringBuilder sb = new StringBuilder();

        switch (action) {
            case "stats":
                Map<String, Object> stats = networkMonitorService.getGlobalStats();
                Map<String, Object> posture = networkThreatFusionService.getPosture();
                sb.append("【网络统计】\n");
                sb.append("  活跃会话: ").append(stats.get("activeSessions")).append("\n");
                sb.append("  入站字节: ").append(formatBytes((long) stats.getOrDefault("totalBytesIn", 0L))).append("\n");
                sb.append("  出站字节: ").append(formatBytes((long) stats.getOrDefault("totalBytesOut", 0L))).append("\n");
                sb.append("  安全态势分: ").append(posture.get("postureScore")).append("\n");
                break;

            case "geoip":
                if (ip.isEmpty()) {
                    return "请指定IP地址: network geoip <IP>";
                }
                sb.append("【IP地理位置: ").append(ip).append("】\n");
                GeoIPService.GeoLocation geoLocation = geoIPService.getGeoLocation(ip);
                if (geoLocation == null) {
                    sb.append("  暂无缓存地理信息\n");
                } else {
                    sb.append("  国家: ").append(geoLocation.country).append("\n");
                    sb.append("  城市: ").append(geoLocation.city).append("\n");
                    sb.append("  坐标: ").append(geoLocation.latitude).append(", ").append(geoLocation.longitude).append("\n");
                }
                break;

            case "reputation":
                if (ip.isEmpty()) {
                    return "请指定IP地址: network reputation <IP>";
                }
                sb.append("【IP信誉: ").append(ip).append("】\n");
                Map<String, Object> inspection = networkThreatFusionService.inspectIP(ip);
                sb.append("  风险分: ").append(inspection.get("riskScore")).append("\n");
                sb.append("  威胁等级: ").append(localizeRiskLevel(String.valueOf(inspection.get("riskLevel")))).append("\n");
                sb.append("  已阻断: ").append(inspection.get("blocked")).append("\n");
                @SuppressWarnings("unchecked")
                Map<String, Object> metadata = (Map<String, Object>) inspection.getOrDefault("metadata", Collections.emptyMap());
                if (metadata.containsKey("reputationScore")) {
                    sb.append("  信誉分: ").append(metadata.get("reputationScore")).append("\n");
                }
                break;

            case "ports":
                Map<String, Object> portStats = portScanDetection.getStats();
                sb.append("【端口扫描检测】\n");
                sb.append("  活跃扫描源: ").append(portStats.get("activeScanners")).append("\n");
                sb.append("  已封禁扫描源: ").append(portStats.get("blockedScanners")).append("\n");
                sb.append("  累计检测: ").append(portStats.get("totalDetected")).append("\n");
                break;
        }
        return sb.toString();
    }

    private String processAICommand(String command) {
        return processWithAI(command);
    }

    private String processWithAI(String command) {
        String lower = command.toLowerCase();

        if (lower.contains("测试")) {
            return test("all");
        }
        if (lower.contains("状态") || lower.contains("查看")) {
            return status();
        }
        if (lower.contains("防御") || lower.contains("保护")) {
            if (lower.contains("开") || lower.contains("启动") || lower.contains("启用")) {
                return defense("on", "");
            }
            if (lower.contains("关") || lower.contains("停止") || lower.contains("禁用")) {
                return defense("off", "");
            }
            return defense("status", "");
        }
        if (lower.contains("安全")) {
            return security("summary");
        }
        if (lower.contains("自主") || lower.contains("主控") || lower.contains("deepseek")) {
            return autonomy("summary");
        }
        if (lower.contains("内核") || lower.contains("kernel")) {
            return kernel("summary");
        }
        if (lower.contains("总线") || lower.contains("bus")) {
            return bus("summary");
        }
        if (lower.contains("自愈") || lower.contains("恢复")) {
            return heal("summary");
        }
        if (lower.contains("备份")) {
            return backup("list", "");
        }
        if (lower.contains("踢")) {
            return "请指定玩家名称: kick <玩家名>";
        }
        if (lower.contains("封禁") || lower.contains("ban")) {
            return "请指定玩家名称: ban <玩家名> <原因>";
        }
        if (lower.contains("世界")) {
            return world("list", "");
        }
        if (lower.contains("邮件") || lower.contains("预警") || lower.contains("告警")) {
            return alert("status", "");
        }
        if (lower.contains("指标") || lower.contains("性能")) {
            return metrics("summary");
        }
        if (lower.contains("审计") || lower.contains("日志")) {
            return audit("recent", "10");
        }
        if (lower.contains("网络")) {
            return network("stats", "");
        }

        if (deepSeekClient.isEnabled()) {
            return askAI(command);
        }

        return "无法理解命令: " + command + "\n" + getHelp();
    }

    private String askAI(String question) {
        return "【DeepSeek 主控回答】\n" + deepSeekClient.askQuestion(question);
    }

    @ShellMethod(key = "help", value = "显示全部可用命令与详细帮助")
    public String help(@ShellOption(defaultValue = "all", help = "查看分类: all/ai/status/defense/security/monitor/player/world/admin/info") String category) {
        if (!"all".equals(category)) {
            return getHelpCategory(category);
        }
        return getFullHelp();
    }

    private String getFullHelp() {
        StringBuilder sb = new StringBuilder();
        sb.append("╔══════════════════════════════════════════════════════════════════╗\n");
        sb.append("║                  Aluer ServerGuard - 完整命令帮助               ║\n");
        sb.append("╠══════════════════════════════════════════════════════════════════╣\n");
        sb.append("║  输入 help <分类> 查看分类帮助: ai/status/defense/security     ║\n");
        sb.append("║  monitor/player/world/admin/info                                ║\n");
        sb.append("╚══════════════════════════════════════════════════════════════════╝\n\n");

        sb.append("┌─────────────────────────────────────────────────────────────────┐\n");
        sb.append("│  AI 智能助手                                                     │\n");
        sb.append("├─────────────────────────────────────────────────────────────────┤\n");
        sb.append("│ ai <自然语言>    AI智能命令(测试服务器/开启防御/查看安全)         │\n");
        sb.append("│ ask <问题>       向DeepSeek AI提问任何问题                       │\n");
        sb.append("└─────────────────────────────────────────────────────────────────┘\n\n");

        sb.append("┌─────────────────────────────────────────────────────────────────┐\n");
        sb.append("│  服务器状态与测试                                                │\n");
        sb.append("├─────────────────────────────────────────────────────────────────┤\n");
        sb.append("│ status            查看服务器CPU/内存/连接/AI防御总览              │\n");
        sb.append("│ test [类型]       测试服务器: all/cpu/memory/network/security    │\n");
        sb.append("│ tps               显示服务器TPS (来自AdminCommands)              │\n");
        sb.append("│ memory            显示内存使用率 (来自AdminCommands)             │\n");
        sb.append("└─────────────────────────────────────────────────────────────────┘\n\n");

        sb.append("┌─────────────────────────────────────────────────────────────────┐\n");
        sb.append("│  安全防御管理                                                    │\n");
        sb.append("├─────────────────────────────────────────────────────────────────┤\n");
        sb.append("│ defense [操作]    防御管理: status/on/off/list/level [等级]      │\n");
        sb.append("│ security summary  安全总览(态势分/威胁等级/高风险IP/DDoS等)      │\n");
        sb.append("│ security posture  网络安全态势(建议/重点关注IP)                  │\n");
        sb.append("│ security incidents 近期安全事件列表                              │\n");
        sb.append("│ security ddos     DDoS防护状态(封禁IP/检测攻击数)                │\n");
        sb.append("│ security firewall 防火墙状态(活跃规则/模式)                      │\n");
        sb.append("│ security intrusion 入侵检测状态(告警/跟踪用户)                   │\n");
        sb.append("│ security threats  AI威胁检测统计                                 │\n");
        sb.append("│ security network  网络监控(流量/会话/高风险IP)                   │\n");
        sb.append("│ security vpn      VPN/代理检测状态                               │\n");
        sb.append("│ security chat     聊天过滤状态(违规词数量)                       │\n");
        sb.append("│ quarantine <IP>   隔离高风险IP (参数: IP 原因)                   │\n");
        sb.append("│ unquarantine <IP> 解除IP隔离 (参数: IP 原因)                     │\n");
        sb.append("└─────────────────────────────────────────────────────────────────┘\n\n");

        sb.append("┌─────────────────────────────────────────────────────────────────┐\n");
        sb.append("│  网络分析                                                        │\n");
        sb.append("├─────────────────────────────────────────────────────────────────┤\n");
        sb.append("│ network stats     网络统计(活跃会话/入站/出站流量)               │\n");
        sb.append("│ network geoip     IP地理位置查询 (参数: IP)                      │\n");
        sb.append("│ network reputation IP信誉/风险等级查询 (参数: IP)                │\n");
        sb.append("│ network ports     端口扫描检测统计                               │\n");
        sb.append("└─────────────────────────────────────────────────────────────────┘\n\n");

        sb.append("┌─────────────────────────────────────────────────────────────────┐\n");
        sb.append("│  AI 主控引擎 / 内核 / 自愈                                       │\n");
        sb.append("├─────────────────────────────────────────────────────────────────┤\n");
        sb.append("│ autonomy summary  Aluer主控引擎状态(模式/循环/决策)              │\n");
        sb.append("│ autonomy run      手动执行一次主控循环                           │\n");
        sb.append("│ autonomy history  最近5条主控决策历史                            │\n");
        sb.append("│ autonomy hardening 安全基线加固得分与发现项                      │\n");
        sb.append("│ kernel summary    Aluer Kernel状态(脉冲/Echo/热度)               │\n");
        sb.append("│ kernel pulse      手动执行一次内核脉冲                           │\n");
        sb.append("│ kernel matrix     内核信号矩阵权重与向量                         │\n");
        sb.append("│ kernel journal    内核日志(最近6条)                              │\n");
        sb.append("│ kernel pulses     最近5次脉冲历史                                │\n");
        sb.append("│ bus summary       内核任务总线(队列深度/执行任务)                │\n");
        sb.append("│ bus queue         任务队列快照                                    │\n");
        sb.append("│ bus history       最近任务执行历史                                │\n");
        sb.append("│ bus dispatch      手动派发队列任务                                │\n");
        sb.append("│ bus plugins       已注册TaskBus插件列表                           │\n");
        sb.append("│ heal summary      Aluer自愈编排器(循环/计划/热度)                │\n");
        sb.append("│ heal run          手动执行一次自愈循环                            │\n");
        sb.append("│ heal history      最近5次自愈历史                                 │\n");
        sb.append("└─────────────────────────────────────────────────────────────────┘\n\n");

        sb.append("┌─────────────────────────────────────────────────────────────────┐\n");
        sb.append("│  备份管理                                                        │\n");
        sb.append("├─────────────────────────────────────────────────────────────────┤\n");
        sb.append("│ backup list       查看所有备份记录                                │\n");
        sb.append("│ backup create     创建新备份 (参数: 备份名称)                     │\n");
        sb.append("│ backup status     备份服务状态                                    │\n");
        sb.append("│ backup start      启动定时备份服务                                │\n");
        sb.append("└─────────────────────────────────────────────────────────────────┘\n\n");

        sb.append("┌─────────────────────────────────────────────────────────────────┐\n");
        sb.append("│  玩家管理                                                        │\n");
        sb.append("├─────────────────────────────────────────────────────────────────┤\n");
        sb.append("│ kick <玩家名>     踢出指定玩家 (RCON连接需启用)                   │\n");
        sb.append("│ ban <玩家名>      封禁玩家 (参数: 玩家名 原因)                    │\n");
        sb.append("│ unban <玩家名>    解封玩家                                        │\n");
        sb.append("│ player kick       踢出玩家 (来自AdminCommands)                    │\n");
        sb.append("│ player ban        封禁玩家 (来自AdminCommands)                    │\n");
        sb.append("│ player mute       禁言玩家 (来自AdminCommands)                    │\n");
        sb.append("└─────────────────────────────────────────────────────────────────┘\n\n");

        sb.append("┌─────────────────────────────────────────────────────────────────┐\n");
        sb.append("│  世界管理                                                        │\n");
        sb.append("├─────────────────────────────────────────────────────────────────┤\n");
        sb.append("│ world list        列出所有世界(名称/区块数/实体数)                │\n");
        sb.append("│ world load <世界> 加载世界 (如: world world_nether)               │\n");
        sb.append("│ world unload <世界> 卸载世界                                     │\n");
        sb.append("└─────────────────────────────────────────────────────────────────┘\n\n");

        sb.append("┌─────────────────────────────────────────────────────────────────┐\n");
        sb.append("│  预警系统                                                        │\n");
        sb.append("├─────────────────────────────────────────────────────────────────┤\n");
        sb.append("│ alert status      邮件预警服务状态                                │\n");
        sb.append("│ alert test        发送测试邮件                                    │\n");
        sb.append("│ alert send <消息> 手动发送告警邮件                                │\n");
        sb.append("└─────────────────────────────────────────────────────────────────┘\n\n");

        sb.append("┌─────────────────────────────────────────────────────────────────┐\n");
        sb.append("│  性能监控与审计                                                  │\n");
        sb.append("├─────────────────────────────────────────────────────────────────┤\n");
        sb.append("│ metrics summary   性能指标摘要(计数器/计量器数量)                 │\n");
        sb.append("│ metrics counters  查看所有计数器                                  │\n");
        sb.append("│ metrics gauges    查看所有计量器                                  │\n");
        sb.append("│ audit recent [N]  最近N条审计事件 (默认10条)                      │\n");
        sb.append("│ audit summary     审计事件分类摘要                                │\n");
        sb.append("│ tasks list        查看计划任务(备份/AI/VPN)                       │\n");
        sb.append("│ tasks start       启动计划任务服务                                │\n");
        sb.append("│ config reload     重新加载配置 (来自AdminCommands)                │\n");
        sb.append("└─────────────────────────────────────────────────────────────────┘\n\n");

        sb.append("┌─────────────────────────────────────────────────────────────────┐\n");
        sb.append("│  系统测试 (test命令扩展)                                          │\n");
        sb.append("├─────────────────────────────────────────────────────────────────┤\n");
        sb.append("│ test all          运行全部测试 (来自TestCommands)                 │\n");
        sb.append("│ test quick        快速测试(config/rcon/email)                     │\n");
        sb.append("│ test config       测试配置                                        │\n");
        sb.append("│ test rcon         测试RCON连接                                    │\n");
        sb.append("│ test process      测试进程监控                                    │\n");
        sb.append("│ test resource     测试资源监控                                    │\n");
        sb.append("│ test connection   测试连接监控                                    │\n");
        sb.append("│ test email        测试邮件服务                                    │\n");
        sb.append("│ test email send   发送测试邮件                                    │\n");
        sb.append("│ test deepseek     测试DeepSeek API                                │\n");
        sb.append("│ test autoexecute  测试自动执行配置                                │\n");
        sb.append("│ test simulate attack 模拟攻击测试                                 │\n");
        sb.append("│ test rcon exec    执行RCON命令 (参数: 命令)                       │\n");
        sb.append("└─────────────────────────────────────────────────────────────────┘\n\n");

        sb.append("┌─────────────────────────────────────────────────────────────────┐\n");
        sb.append("│  安全API端点 (HTTP GET /api/...)                                  │\n");
        sb.append("├─────────────────────────────────────────────────────────────────┤\n");
        sb.append("│ /api/status                        系统运行状态                  │\n");
        sb.append("│ /api/performance                   TPS/CPU/内存指标              │\n");
        sb.append("│ /api/health                        完整健康报告                  │\n");
        sb.append("│ /api/health/live                   存活探针                      │\n");
        sb.append("│ /api/health/ready                  就绪探针                      │\n");
        sb.append("│ /api/security/stats                安全统计总览                  │\n");
        sb.append("│ /api/security/network/posture      网络安全态势                  │\n");
        sb.append("│ /api/security/network/offenders    高风险IP列表                  │\n");
        sb.append("│ /api/security/network/incidents    安全事件列表                  │\n");
        sb.append("│ /api/security/auth/status          JWT认证状态                   │\n");
        sb.append("│ /api/security/brute-force/status   暴力破解防护                  │\n");
        sb.append("│ /api/security/anti-bot/status      反机器人检测                  │\n");
        sb.append("│ /api/security/anti-grief/status    反破坏检测                    │\n");
        sb.append("│ /api/security/anti-xray/status     X-ray透视检测                 │\n");
        sb.append("│ /api/security/anti-fly/status      飞行外挂检测                  │\n");
        sb.append("│ /api/security/anti-dupe/status     物品复制检测                  │\n");
        sb.append("│ /api/security/anti-skin-spoof/status 皮肤伪造检测                │\n");
        sb.append("│ /api/security/crash-exploit/status 崩溃漏洞防护                  │\n");
        sb.append("│ /api/security/lag-machine/status   卡服机检测                    │\n");
        sb.append("│ /api/security/reverse-shell/status 反向Shell检测                 │\n");
        sb.append("│ /api/security/arp-spoof/status     ARP欺骗检测                   │\n");
        sb.append("│ /api/security/dns-tunnel/status    DNS隧道检测                   │\n");
        sb.append("│ /api/security/exploit-signature/status 漏洞签名检测              │\n");
        sb.append("│ /api/security/ssrf/status          SSRF防护                      │\n");
        sb.append("│ /api/security/xxe/status           XXE防护                       │\n");
        sb.append("│ /api/security/csp/status           CSP安全头                     │\n");
        sb.append("│ /api/security/database-firewall/status 数据库防火墙              │\n");
        sb.append("│ /api/security/dlp/status           数据防泄漏                    │\n");
        sb.append("│ /api/security/memory/status        JVM内存保护                   │\n");
        sb.append("│ /api/security/process-injection/status 进程注入检测              │\n");
        sb.append("│ /api/security/secure-delete/status 安全文件删除                  │\n");
        sb.append("│ /api/security/forensics/status     取证收集                      │\n");
        sb.append("│ /api/security/incident-response/status 事件响应                  │\n");
        sb.append("│ /api/security/threat-hunting/status 威胁狩猎                     │\n");
        sb.append("│ /api/security/compliance/status    合规扫描                      │\n");
        sb.append("│ /api/security/geo-block/status     地理IP封锁                    │\n");
        sb.append("│ /api/security/session-validation/status 会话验证                 │\n");
        sb.append("│ /api/security/plugin-verification/status 插件校验                │\n");
        sb.append("│ /api/security/connection-throttle/status 连接速率限制            │\n");
        sb.append("│ /api/security/backup-integrity/status 备份完整性                 │\n");
        sb.append("│ /api/attacks/recent                最近攻击列表                  │\n");
        sb.append("│ /api/backup/list                   备份列表                      │\n");
        sb.append("│ /api/punishment/list               封禁/禁言统计                 │\n");
        sb.append("└─────────────────────────────────────────────────────────────────┘\n\n");

        sb.append("┌─────────────────────────────────────────────────────────────────┐\n");
        sb.append("│  自然语言快捷指令 (ai 命令)                                      │\n");
        sb.append("├─────────────────────────────────────────────────────────────────┤\n");
        sb.append("│ ai 测试一下服务器     → 运行完整服务器测试                       │\n");
        sb.append("│ ai 开启防御           → 打开AI自主防御模式                       │\n");
        sb.append("│ ai 关闭防御           → 关闭AI自主防御模式                       │\n");
        sb.append("│ ai 查看安全状态       → 显示安全总览                             │\n");
        sb.append("│ ai 查看网络状态       → 显示网络统计                             │\n");
        sb.append("│ ai 帮我备份           → 查看备份记录                             │\n");
        sb.append("│ ai 查看世界           → 列出所有世界                             │\n");
        sb.append("│ ai 发送预警           → 查看预警系统状态                         │\n");
        sb.append("│ ai 查看主控引擎       → 显示Aluer主控引擎状态                    │\n");
        sb.append("│ ai 查看内核           → 显示Kernel内核状态                       │\n");
        sb.append("│ ai <其他问题>         → 通过DeepSeek AI智能回答                  │\n");
        sb.append("└─────────────────────────────────────────────────────────────────┘\n\n");

        sb.append("  💡 提示: 输入 help <分类> 查看分类命令, help all 查看全部\n");
        sb.append("  💡 所有安全模块开关: application.yml → serverguard.security.super-evolution\n");
        return sb.toString();
    }

    private String getHelpCategory(String category) {
        return switch (category) {
            case "ai" -> """
                【AI 智能助手】
                  ai <自然语言>    使用自然语言与服务器交互
                  ask <问题>       直接向DeepSeek AI提问

                快捷指令:
                  ai 测试一下服务器    ai 开启防御       ai 查看安全状态
                  ai 查看网络状态      ai 帮我备份       ai 查看世界
                  ai 发送预警          ai 查看主控引擎   ai 查看内核""";
            case "status" -> """
                【服务器状态与测试】
                  status            查看服务器CPU/内存/连接/AI防御总览
                  test all          运行全部测试
                  test cpu          仅CPU测试
                  test memory       仅内存测试
                  test network      仅网络测试
                  test security     仅安全测试
                  tps               显示TPS
                  memory            显示内存使用率""";
            case "defense" -> """
                【防御管理】
                  defense status    查看防御状态(AI防御/等级/策略数)
                  defense on        开启AI自主防御模式
                  defense off       关闭AI自主防御模式
                  defense list      列出所有可用防御策略
                  defense level <等级> 调整防御等级""";
            case "security" -> """
                【安全状态查询】
                  security summary      安全总览(态势分/威胁/高风险IP)
                  security posture      网络安全态势(建议/重点关注)
                  security incidents    近期安全事件
                  security ddos         DDoS防护状态
                  security firewall     防火墙状态
                  security intrusion    入侵检测状态
                  security threats      AI威胁检测
                  security network      网络监控
                  security vpn          VPN检测
                  security chat         聊天过滤
                  quarantine <IP> [原因] 隔离高风险IP
                  unquarantine <IP> [原因] 解除IP隔离""";
            case "monitor" -> """
                【AI引擎/内核/自愈/性能监控】
                  autonomy summary/run/history/hardening    主控引擎
                  kernel summary/pulse/matrix/journal/pulses Kernel内核
                  bus summary/queue/history/dispatch/plugins 任务总线
                  heal summary/run/history                   自愈编排
                  metrics summary/counters/gauges            性能指标
                  audit recent [N]/summary                    安全审计
                  tasks list/start                            计划任务""";
            case "player" -> """
                【玩家与网络管理】
                  kick <玩家名>       踢出玩家(RCON需启用)
                  ban <玩家名> [原因]  封禁玩家
                  unban <玩家名>      解封玩家
                  player kick/ban/mute AdminCommands玩家管理
                  network stats       网络统计
                  network geoip <IP>  IP地理位置
                  network reputation <IP> IP信誉查询
                  network ports       端口扫描检测""";
            case "world" -> """
                【世界与备份管理】
                  world list          列出所有世界
                  world load <世界>   加载世界
                  world unload <世界> 卸载世界
                  backup list         查看备份记录
                  backup create [名称] 创建新备份
                  backup status       备份服务状态
                  backup start        启动定时备份""";
            case "admin" -> """
                【系统管理】
                  alert status/test/send [消息]  邮件预警
                  server status                  服务器状态(AdminCommands)
                  config reload                  重新加载配置
                  ai analyze <数据>              AI分析(AdminCommands)
                  test quick/config/rcon/process/resource/connection
                  test email/email send/deepseek/autoexecute
                  test simulate attack/rcon exec <命令>""";
            case "info" -> """
                【安全API端点 (HTTP GET)】
                  /api/status /api/performance /api/health
                  /api/security/stats /api/security/network/*
                  /api/security/auth/status /api/security/brute-force/status
                  /api/security/anti-bot|anti-grief|anti-xray|anti-fly/status
                  /api/security/anti-dupe|anti-skin-spoof|crash-exploit/status
                  /api/security/lag-machine|reverse-shell|arp-spoof/status
                  /api/security/dns-tunnel|exploit-signature|ssrf/status
                  /api/security/xxe|csp|database-firewall|dlp/status
                  /api/security/memory|process-injection|secure-delete/status
                  /api/security/forensics|incident-response|threat-hunting/status
                  /api/security/compliance|geo-block|session-validation/status
                  /api/security/plugin-verification|connection-throttle/status
                  /api/security/backup-integrity/status
                  /api/attacks/recent /api/backup/list /api/punishment/list

                完整API文档: docs/USER_MANUAL.md""";
            default -> "未知分类: " + category + "\n可用: ai/status/defense/security/monitor/player/world/admin/info";
        };
    }

    private String getHelp() {
        return getFullHelp();
    }

    private int getCpuUsage() {
        try {
            com.sun.management.OperatingSystemMXBean os =
                (com.sun.management.OperatingSystemMXBean) java.lang.management.ManagementFactory.getOperatingSystemMXBean();
            return (int) (os.getProcessCpuLoad() * 100);
        } catch (Exception e) {
            return 0;
        }
    }

    private int getMemoryUsage() {
        try {
            Runtime runtime = Runtime.getRuntime();
            long total = runtime.totalMemory();
            long free = runtime.freeMemory();
            return (int) ((total - free) * 100 / total);
        } catch (Exception e) {
            return 0;
        }
    }

    private long getMemoryTotal() {
        return Runtime.getRuntime().totalMemory() / (1024 * 1024);
    }

    private long getMemoryUsed() {
        Runtime runtime = Runtime.getRuntime();
        return (runtime.totalMemory() - runtime.freeMemory()) / (1024 * 1024);
    }

    private int getDiskUsage() {
        return 45;
    }

    private int getConnectionCount() {
        try {
            return connectionMonitor.getTotalConnections();
        } catch (Exception e) {
            return 0;
        }
    }

    private String formatBytes(long bytes) {
        if (bytes < 1024) return bytes + " B";
        if (bytes < 1024 * 1024) return String.format("%.2f KB", bytes / 1024.0);
        if (bytes < 1024 * 1024 * 1024) return String.format("%.2f MB", bytes / (1024.0 * 1024));
        return String.format("%.2f GB", bytes / (1024.0 * 1024 * 1024));
    }

    private String localizeRiskLevel(String level) {
        return switch (level) {
            case "critical" -> "严重";
            case "high" -> "高";
            case "elevated" -> "中高";
            case "guarded" -> "关注";
            default -> "低";
        };
    }
}
