package com.aluer.ai;

import com.aluer.config.ServerGuardConfig;
import com.aluer.model.AlertEvent;
import com.aluer.model.MetricsData;
import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentLinkedDeque;

@Component
public class DeepSeekClient {
    private static final Logger logger = LoggerFactory.getLogger(DeepSeekClient.class);

    private final ServerGuardConfig config;
    private final Gson gson = new Gson();
    private final ConcurrentLinkedDeque<MetricsData> recentMetrics = new ConcurrentLinkedDeque<>();
    private final ConcurrentLinkedDeque<AlertEvent> recentAlerts = new ConcurrentLinkedDeque<>();

    public DeepSeekClient(ServerGuardConfig config) {
        this.config = config;
    }

    public void addMetrics(MetricsData data) {
        recentMetrics.add(data);
        int maxSize = config.getAi().getSlidingWindowSize();
        while (recentMetrics.size() > maxSize) {
            recentMetrics.removeFirst();
        }
    }

    public void addAlert(AlertEvent alert) {
        recentAlerts.add(alert);
        while (recentAlerts.size() > 50) {
            recentAlerts.removeFirst();
        }
    }

    public boolean isEnabled() {
        return config.getAi().getDeepseek().isEnabled()
            && !config.getAi().getDeepseek().getApiKey().isEmpty();
    }

    public CompletableFuture<AiAnalysisResult> analyzeAlertAsync(AlertEvent alert) {
        return CompletableFuture.supplyAsync(() -> analyzeAlert(alert));
    }

    public AiAnalysisResult analyzeAlert(AlertEvent alert) {
        if (!isEnabled()) {
            return null;
        }

        try {
            String response = callDeepSeekApi(
                "你是一个专业的 Minecraft 服务器安全专家，擅长分析服务器异常和安全威胁。",
                buildAnalysisPrompt(alert)
            );
            return parseAnalysisResponse(response, alert);
        } catch (Exception e) {
            logger.error("DeepSeek API error: {}", e.getMessage());
            return null;
        }
    }

    public CompletableFuture<AiAnalysisResult> getServerHealthReportAsync() {
        return CompletableFuture.supplyAsync(this::getServerHealthReport);
    }

    public AiAnalysisResult getServerHealthReport() {
        if (!isEnabled()) {
            return null;
        }

        try {
            String response = callDeepSeekApi(
                "你是一个专业的 Minecraft 服务器可靠性与安全专家，需要对服务器健康度做出稳健判断。",
                buildHealthReportPrompt()
            );
            return parseHealthReportResponse(response);
        } catch (Exception e) {
            logger.error("DeepSeek health report error: {}", e.getMessage());
            return null;
        }
    }

    public String askQuestion(String question) {
        if (!isEnabled()) {
            return "DeepSeek 未启用，请先配置 `DEEPSEEK_API_KEY`。";
        }

        try {
            return extractMessageContent(callDeepSeekApi(
                "你是 Aluer 的主控 AI。你的回答要简洁、专业、偏运维与安全决策，不要输出无根据的夸张结论。",
                question
            ));
        } catch (Exception e) {
            logger.error("DeepSeek question error: {}", e.getMessage());
            return "DeepSeek 调用失败: " + e.getMessage();
        }
    }

    public AutonomyDirective planAutonomousDefense(Map<String, Object> postureContext) {
        if (!isEnabled()) {
            return null;
        }

        try {
            StringBuilder userPrompt = new StringBuilder();
            userPrompt.append("请根据以下 Aluer 运行态势给出一条自治防御指令。\n");
            userPrompt.append("只能从以下 workflow 中选择，不能编造新的名字：\n");
            userPrompt.append("MONITOR_ONLY, COMMAND_ABUSE_RESPONSE, HOST_INTRUSION_RESPONSE, ");
            userPrompt.append("RCON_BRUTE_FORCE_RESPONSE, MC_BOT_SWARM_RESPONSE, L34_DDOS_RESPONSE, ");
            userPrompt.append("L7_DDOS_RESPONSE, VULNERABILITY_PATCH\n\n");
            userPrompt.append("上下文(JSON):\n").append(gson.toJson(postureContext)).append("\n\n");
            userPrompt.append("请严格返回 JSON:\n");
            userPrompt.append("{\n");
            userPrompt.append("  \"workflow\": \"MONITOR_ONLY|COMMAND_ABUSE_RESPONSE|HOST_INTRUSION_RESPONSE|RCON_BRUTE_FORCE_RESPONSE|MC_BOT_SWARM_RESPONSE|L34_DDOS_RESPONSE|L7_DDOS_RESPONSE|VULNERABILITY_PATCH\",\n");
            userPrompt.append("  \"defenseLevel\": \"NORMAL|ELEVATED|HIGH|LOCKDOWN\",\n");
            userPrompt.append("  \"riskScore\": 0,\n");
            userPrompt.append("  \"confidence\": 0.0,\n");
            userPrompt.append("  \"targetIp\": \"可为空\",\n");
            userPrompt.append("  \"shouldQuarantine\": false,\n");
            userPrompt.append("  \"shouldEnableWhitelist\": false,\n");
            userPrompt.append("  \"summary\": \"一句话概述\",\n");
            userPrompt.append("  \"reason\": \"为什么要这样做\"\n");
            userPrompt.append("}\n");

            String content = extractMessageContent(callDeepSeekApi(
                "你是 Aluer 的主控防御 AI。你必须在给定工作流内做出保守但果断的决策。",
                userPrompt.toString()
            ));

            JsonObject result = extractEmbeddedJson(content);
            if (result == null) {
                return null;
            }

            AutonomyDirective directive = new AutonomyDirective();
            directive.setWorkflow(getString(result, "workflow", "MONITOR_ONLY"));
            directive.setDefenseLevel(getString(result, "defenseLevel", "NORMAL"));
            directive.setRiskScore(getInt(result, "riskScore", 0));
            directive.setConfidence(getDouble(result, "confidence", 0.0));
            directive.setTargetIp(getString(result, "targetIp", ""));
            directive.setShouldQuarantine(getBoolean(result, "shouldQuarantine", false));
            directive.setShouldEnableWhitelist(getBoolean(result, "shouldEnableWhitelist", false));
            directive.setSummary(getString(result, "summary", ""));
            directive.setReason(getString(result, "reason", ""));
            return directive;
        } catch (Exception e) {
            logger.error("DeepSeek autonomy planning error: {}", e.getMessage());
            return null;
        }
    }

    private String buildAnalysisPrompt(AlertEvent alert) {
        StringBuilder prompt = new StringBuilder();
        prompt.append("你是一个 Minecraft 服务器安全专家 AI 助手。请分析以下服务器告警事件。\n\n");
        prompt.append("## 告警信息\n");
        prompt.append("- 类型: ").append(alert.getType().getTitle()).append("\n");
        prompt.append("- 描述: ").append(alert.getType().getDescription()).append("\n");
        prompt.append("- 消息: ").append(alert.getMessage()).append("\n");
        prompt.append("- 置信度: ").append(String.format("%.1f%%", alert.getConfidence() * 100)).append("\n");
        if (alert.getRootCause() != null) {
            prompt.append("- 初步根因: ").append(alert.getRootCause()).append("\n");
        }

        prompt.append("\n## 最近指标数据\n");
        int count = 0;
        for (MetricsData metric : getRecentMetricsData()) {
            if (count++ >= 10) {
                break;
            }
            prompt.append(String.format("- TPS: %.1f, CPU: %.1f%%, Memory: %.1f%%, Players: %d, Connections: %d\n",
                metric.getTps(), metric.getCpuUsage(), metric.getMemoryUsage(), metric.getOnlinePlayers(), metric.getConnections()));
        }

        prompt.append("\n请以 JSON 格式返回分析结果，包含以下字段：\n");
        prompt.append("{\n");
        prompt.append("  \"severity\": \"critical|high|medium|low\",\n");
        prompt.append("  \"rootCause\": \"详细分析的根本原因\",\n");
        prompt.append("  \"recommendedActions\": [\"建议的操作1\", \"建议的操作2\"],\n");
        prompt.append("  \"autoAction\": \"建议的自动操作 (如封禁IP/限制连接/无)\",\n");
        prompt.append("  \"description\": \"简要描述问题\"\n");
        prompt.append("}\n");
        return prompt.toString();
    }

    private String buildHealthReportPrompt() {
        StringBuilder prompt = new StringBuilder();
        prompt.append("请分析以下 Minecraft 服务器的健康状况，提供综合报告。\n\n");
        prompt.append("## 当前服务器指标\n");
        for (MetricsData metric : recentMetrics) {
            prompt.append(String.format("- TPS: %.1f, CPU: %.1f%%, Memory: %.1f%%, Players: %d, Connections: %d\n",
                metric.getTps(), metric.getCpuUsage(), metric.getMemoryUsage(), metric.getOnlinePlayers(), metric.getConnections()));
        }

        prompt.append("\n## 最近告警\n");
        for (AlertEvent alert : recentAlerts) {
            prompt.append(String.format("- [%s] %s\n", alert.getType().getTitle(), alert.getMessage()));
        }

        prompt.append("\n请以 JSON 格式返回分析结果：\n");
        prompt.append("{\n");
        prompt.append("  \"overallStatus\": \"healthy|warning|critical\",\n");
        prompt.append("  \"summary\": \"总体评估\",\n");
        prompt.append("  \"concerns\": [\"潜在问题1\", \"潜在问题2\"],\n");
        prompt.append("  \"recommendations\": [\"优化建议1\", \"优化建议2\"]\n");
        prompt.append("}\n");
        return prompt.toString();
    }

    private List<MetricsData> getRecentMetricsData() {
        return List.of(recentMetrics.toArray(new MetricsData[0]));
    }

    private String callDeepSeekApi(String systemPrompt, String prompt) throws Exception {
        ServerGuardConfig.DeepSeekConfig deepseek = config.getAi().getDeepseek();

        URL url = new URL(deepseek.getBaseUrl() + "/v1/chat/completions");
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("POST");
        conn.setRequestProperty("Content-Type", "application/json");
        conn.setRequestProperty("Authorization", "Bearer " + deepseek.getApiKey());
        conn.setConnectTimeout(8000);
        conn.setReadTimeout(15000);
        conn.setDoOutput(true);

        JsonObject requestBody = new JsonObject();
        requestBody.addProperty("model", deepseek.getModel());
        requestBody.addProperty("max_tokens", deepseek.getMaxTokens());
        requestBody.addProperty("temperature", deepseek.getTemperature());

        JsonArray messages = new JsonArray();
        JsonObject systemMsg = new JsonObject();
        systemMsg.addProperty("role", "system");
        systemMsg.addProperty("content", systemPrompt);
        messages.add(systemMsg);

        JsonObject userMsg = new JsonObject();
        userMsg.addProperty("role", "user");
        userMsg.addProperty("content", prompt);
        messages.add(userMsg);

        requestBody.add("messages", messages);

        try (OutputStream os = conn.getOutputStream()) {
            byte[] input = gson.toJson(requestBody).getBytes(StandardCharsets.UTF_8);
            os.write(input);
        }

        int statusCode = conn.getResponseCode();
        InputStream stream = statusCode >= 200 && statusCode < 300
            ? conn.getInputStream()
            : conn.getErrorStream();

        if (stream == null) {
            throw new IllegalStateException("DeepSeek 返回空响应流，HTTP " + statusCode);
        }

        StringBuilder response = new StringBuilder();
        try (BufferedReader br = new BufferedReader(new InputStreamReader(stream, StandardCharsets.UTF_8))) {
            String line;
            while ((line = br.readLine()) != null) {
                response.append(line);
            }
        }

        if (statusCode < 200 || statusCode >= 300) {
            throw new IllegalStateException("DeepSeek HTTP " + statusCode + ": " + response);
        }

        return response.toString();
    }

    private AiAnalysisResult parseAnalysisResponse(String response, AlertEvent alert) {
        try {
            JsonObject result = extractEmbeddedJson(extractMessageContent(response));
            if (result == null) {
                return null;
            }

            AiAnalysisResult analysis = new AiAnalysisResult();
            analysis.setSeverity(getString(result, "severity", "medium"));
            analysis.setRootCause(getString(result, "rootCause", alert.getRootCause()));
            analysis.setDescription(getString(result, "description", alert.getMessage()));
            analysis.setAutoAction(getString(result, "autoAction", "无"));

            if (result.get("recommendedActions") != null) {
                JsonArray actions = result.getAsJsonArray("recommendedActions");
                for (int i = 0; i < actions.size(); i++) {
                    analysis.addRecommendedAction(actions.get(i).getAsString());
                }
            }

            return analysis;
        } catch (Exception e) {
            logger.error("Failed to parse DeepSeek response: {}", e.getMessage());
            return null;
        }
    }

    private AiAnalysisResult parseHealthReportResponse(String response) {
        try {
            JsonObject result = extractEmbeddedJson(extractMessageContent(response));
            if (result == null) {
                return null;
            }

            AiAnalysisResult analysis = new AiAnalysisResult();
            analysis.setSeverity(getString(result, "overallStatus", "healthy"));
            analysis.setDescription(getString(result, "summary", ""));

            if (result.get("concerns") != null) {
                JsonArray concerns = result.getAsJsonArray("concerns");
                for (int i = 0; i < concerns.size(); i++) {
                    analysis.addRecommendedAction(concerns.get(i).getAsString());
                }
            }

            return analysis;
        } catch (Exception e) {
            logger.error("Failed to parse health report: {}", e.getMessage());
            return null;
        }
    }

    private String extractMessageContent(String response) {
        JsonObject json = gson.fromJson(response, JsonObject.class);
        JsonArray choices = json.getAsJsonArray("choices");
        if (choices == null || choices.isEmpty()) {
            return "";
        }
        JsonObject message = choices.get(0).getAsJsonObject().getAsJsonObject("message");
        return message != null && message.get("content") != null
            ? message.get("content").getAsString()
            : "";
    }

    private JsonObject extractEmbeddedJson(String content) {
        int jsonStart = content.indexOf("{");
        int jsonEnd = content.lastIndexOf("}");
        if (jsonStart < 0 || jsonEnd < 0 || jsonEnd <= jsonStart) {
            return null;
        }
        return gson.fromJson(content.substring(jsonStart, jsonEnd + 1), JsonObject.class);
    }

    private String getString(JsonObject json, String key, String defaultValue) {
        return json.get(key) != null && !json.get(key).isJsonNull()
            ? json.get(key).getAsString()
            : defaultValue;
    }

    private int getInt(JsonObject json, String key, int defaultValue) {
        return json.get(key) != null && !json.get(key).isJsonNull()
            ? json.get(key).getAsInt()
            : defaultValue;
    }

    private double getDouble(JsonObject json, String key, double defaultValue) {
        return json.get(key) != null && !json.get(key).isJsonNull()
            ? json.get(key).getAsDouble()
            : defaultValue;
    }

    private boolean getBoolean(JsonObject json, String key, boolean defaultValue) {
        return json.get(key) != null && !json.get(key).isJsonNull()
            ? json.get(key).getAsBoolean()
            : defaultValue;
    }

    public static class AiAnalysisResult {
        private String severity;
        private String rootCause;
        private String description;
        private String autoAction;
        private java.util.List<String> recommendedActions = new java.util.ArrayList<>();

        public String getSeverity() { return severity; }
        public void setSeverity(String severity) { this.severity = severity; }
        public String getRootCause() { return rootCause; }
        public void setRootCause(String rootCause) { this.rootCause = rootCause; }
        public String getDescription() { return description; }
        public void setDescription(String description) { this.description = description; }
        public String getAutoAction() { return autoAction; }
        public void setAutoAction(String autoAction) { this.autoAction = autoAction; }
        public java.util.List<String> getRecommendedActions() { return recommendedActions; }
        public void addRecommendedAction(String action) { this.recommendedActions.add(action); }
    }

    public static class AutonomyDirective {
        private String workflow;
        private String defenseLevel;
        private int riskScore;
        private double confidence;
        private String targetIp;
        private boolean shouldQuarantine;
        private boolean shouldEnableWhitelist;
        private String summary;
        private String reason;

        public String getWorkflow() { return workflow; }
        public void setWorkflow(String workflow) { this.workflow = workflow; }
        public String getDefenseLevel() { return defenseLevel; }
        public void setDefenseLevel(String defenseLevel) { this.defenseLevel = defenseLevel; }
        public int getRiskScore() { return riskScore; }
        public void setRiskScore(int riskScore) { this.riskScore = riskScore; }
        public double getConfidence() { return confidence; }
        public void setConfidence(double confidence) { this.confidence = confidence; }
        public String getTargetIp() { return targetIp; }
        public void setTargetIp(String targetIp) { this.targetIp = targetIp; }
        public boolean isShouldQuarantine() { return shouldQuarantine; }
        public void setShouldQuarantine(boolean shouldQuarantine) { this.shouldQuarantine = shouldQuarantine; }
        public boolean isShouldEnableWhitelist() { return shouldEnableWhitelist; }
        public void setShouldEnableWhitelist(boolean shouldEnableWhitelist) { this.shouldEnableWhitelist = shouldEnableWhitelist; }
        public String getSummary() { return summary; }
        public void setSummary(String summary) { this.summary = summary; }
        public String getReason() { return reason; }
        public void setReason(String reason) { this.reason = reason; }
    }
}
