package com.aluer.defense;

import com.aluer.config.ServerGuardConfig;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentLinkedDeque;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Service
public class SecurityBaselineHardeningService {
    private static final Pattern INLINE_SECRET_PATTERN = Pattern.compile(
        "(?im)^\\s*(api-key|password|secret|token|apiKey):\\s*(?!\\$\\{)([^\\s#]+)"
    );

    private final ServerGuardConfig config;
    private final ConcurrentLinkedDeque<HardeningFinding> findingLog = new ConcurrentLinkedDeque<>();
    private final Path applicationConfigPath = Paths.get("src", "main", "resources", "application.yml");

    public SecurityBaselineHardeningService() {
        this(new ServerGuardConfig());
    }

    @Autowired
    public SecurityBaselineHardeningService(ServerGuardConfig config) {
        this.config = config;
    }

    public HardeningReport assessCurrentBaseline() {
        List<HardeningFinding> findings = new ArrayList<>();
        scanRuntimeConfiguration(findings);
        scanConfigFile(findings);
        record(findings);
        return new HardeningReport(findings);
    }

    public List<HardeningFinding> getRecentFindings(int limit) {
        List<HardeningFinding> result = new ArrayList<>();
        int count = 0;
        for (HardeningFinding finding : findingLog) {
            if (count++ >= limit) {
                break;
            }
            result.add(finding);
        }
        result.sort(Comparator.comparingLong(HardeningFinding::getTimestamp).reversed());
        return result;
    }

    public Map<String, Object> getSummary() {
        return assessCurrentBaseline().toMap();
    }

    private void scanRuntimeConfiguration(List<HardeningFinding> findings) {
        ServerGuardConfig.RconConfig rcon = config.getMinecraft().getRcon();
        if (rcon.isEnabled() && isBlank(rcon.getPassword())) {
            findings.add(new HardeningFinding(
                "critical",
                "RCON",
                "RCON 已启用但未配置口令",
                "远程控制接口暴露时，空口令会直接放大入侵面。",
                "为 RCON 设置强随机密码，并限制来源 IP。"
            ));
        } else if (rcon.isEnabled() && rcon.getPassword().length() < 12) {
            findings.add(new HardeningFinding(
                "high",
                "RCON",
                "RCON 口令强度偏弱",
                "当前口令长度过短，容易被暴力猜解或撞库命中。",
                "将 RCON 口令提升到 16 位以上并只通过环境变量注入。"
            ));
        }

        if (!config.getSecurity().getAntiIntrusion().getFileIntegrity().isEnabled()) {
            findings.add(new HardeningFinding(
                "high",
                "INTEGRITY",
                "文件完整性监控已关闭",
                "插件篡改、脚本替换和 systemd 劫持将更难被发现。",
                "启用 file-integrity，并覆盖核心 jar、插件目录和启动脚本。"
            ));
        }

        if (!config.getSecurity().getHostEnforcement().isEnabled()) {
            findings.add(new HardeningFinding(
                "medium",
                "HOST_ENFORCEMENT",
                "主机侧封禁未启用",
                "系统当前只能在应用层做隔离，真正的源地址拦截无法落到主机网络层。",
                "启用 host-enforcement，至少保持 dry-run 观察，再逐步切到真实执行。"
            ));
        } else if (config.getSecurity().getHostEnforcement().isDryRun()) {
            findings.add(new HardeningFinding(
                "low",
                "HOST_ENFORCEMENT",
                "主机侧封禁仍处于 dry-run",
                "当前只生成阻断预览，不会真正下发防火墙规则。",
                "验证命令预览无误后，把 dry-run 切换为 false。"
            ));
        }

        if (config.getAi().getDeepseek().getAutoExecute().isEnabled()
            && config.getAi().getDeepseek().getAutoExecute().getMinConfidence() < 85) {
            findings.add(new HardeningFinding(
                "medium",
                "AUTONOMY",
                "AI 自动执行置信度阈值过低",
                "过低阈值会放大误封禁、误踢人和错误白名单切换的概率。",
                "将 min-confidence 提升到 85 以上，并保留工作流冷却。"
            ));
        }

        if (config.getSecurity().getCloudEdge().isEnabled()
            && (isBlank(config.getSecurity().getCloudEdge().getZoneId())
                || isBlank(config.getSecurity().getCloudEdge().getApiKey()))) {
            findings.add(new HardeningFinding(
                "high",
                "EDGE",
                "云边协同已启用但凭据不完整",
                "边缘拦截配置不完整会导致自治编排在关键阶段失效。",
                "补齐 Cloudflare zone/API 凭据，或显式关闭 cloud-edge。"
            ));
        }
    }

    private void scanConfigFile(List<HardeningFinding> findings) {
        if (!Files.exists(applicationConfigPath)) {
            return;
        }

        try {
            String content = Files.readString(applicationConfigPath, StandardCharsets.UTF_8);
            Matcher matcher = INLINE_SECRET_PATTERN.matcher(content);
            while (matcher.find()) {
                String key = matcher.group(1);
                String value = matcher.group(2);
                if (value != null && !value.isBlank()) {
                    findings.add(new HardeningFinding(
                        "critical",
                        "CONFIG_SECRET",
                        "配置文件中存在明文敏感项: " + key,
                        "明文凭据一旦进仓库、日志或备份，泄露面会持续扩大。",
                        "改为 `${ENV_VAR:}` 形式，并轮换已暴露的真实凭据。"
                    ));
                }
            }
        } catch (IOException ignored) {
        }
    }

    private void record(List<HardeningFinding> findings) {
        for (HardeningFinding finding : findings) {
            findingLog.offer(finding);
        }
        while (findingLog.size() > 500) {
            findingLog.poll();
        }
    }

    private boolean isBlank(String value) {
        return value == null || value.isBlank();
    }

    public static class HardeningReport {
        private final List<HardeningFinding> findings;
        private final int criticalCount;
        private final int highCount;
        private final int mediumCount;
        private final int lowCount;
        private final int score;

        public HardeningReport(List<HardeningFinding> findings) {
            this.findings = findings.stream()
                .sorted(Comparator.comparing((HardeningFinding finding) -> severityWeight(finding.severity)).reversed())
                .toList();
            this.criticalCount = (int) this.findings.stream().filter(finding -> "critical".equals(finding.severity)).count();
            this.highCount = (int) this.findings.stream().filter(finding -> "high".equals(finding.severity)).count();
            this.mediumCount = (int) this.findings.stream().filter(finding -> "medium".equals(finding.severity)).count();
            this.lowCount = (int) this.findings.stream().filter(finding -> "low".equals(finding.severity)).count();
            this.score = Math.max(0, 100 - (criticalCount * 25 + highCount * 15 + mediumCount * 8 + lowCount * 3));
        }

        public List<HardeningFinding> getFindings() { return findings; }
        public int getCriticalCount() { return criticalCount; }
        public int getHighCount() { return highCount; }
        public int getMediumCount() { return mediumCount; }
        public int getLowCount() { return lowCount; }
        public int getScore() { return score; }

        public Map<String, Object> toMap() {
            Map<String, Object> result = new LinkedHashMap<>();
            result.put("score", score);
            result.put("exposureLevel", score >= 85 ? "stable" : score >= 65 ? "guarded" : score >= 45 ? "exposed" : "critical");
            result.put("critical", criticalCount);
            result.put("high", highCount);
            result.put("medium", mediumCount);
            result.put("low", lowCount);
            result.put("findings", findings.stream().limit(6).map(HardeningFinding::toMap).toList());
            result.put("recommendations", findings.stream()
                .map(HardeningFinding::getRecommendation)
                .distinct()
                .limit(5)
                .toList());
            return result;
        }

        private static int severityWeight(String severity) {
            return switch (severity.toLowerCase(Locale.ROOT)) {
                case "critical" -> 4;
                case "high" -> 3;
                case "medium" -> 2;
                default -> 1;
            };
        }
    }

    public static class HardeningFinding {
        private final String severity;
        private final String category;
        private final String title;
        private final String detail;
        private final String recommendation;
        private final long timestamp;

        public HardeningFinding(String severity, String category, String title, String detail, String recommendation) {
            this.severity = severity;
            this.category = category;
            this.title = title;
            this.detail = detail;
            this.recommendation = recommendation;
            this.timestamp = Instant.now().toEpochMilli();
        }

        public String getSeverity() { return severity; }
        public String getCategory() { return category; }
        public String getTitle() { return title; }
        public String getDetail() { return detail; }
        public String getRecommendation() { return recommendation; }
        public long getTimestamp() { return timestamp; }

        public Map<String, Object> toMap() {
            Map<String, Object> result = new LinkedHashMap<>();
            result.put("severity", severity);
            result.put("category", category);
            result.put("title", title);
            result.put("detail", detail);
            result.put("recommendation", recommendation);
            result.put("timestamp", timestamp);
            return result;
        }
    }
}
