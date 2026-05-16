package com.aluer.service;

import com.aluer.ai.DeepSeekClient;
import com.aluer.model.AlertEvent;
import com.aluer.server.AgentWebSocketServer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

/**
 * Agent 命令调度器 — 将 ServerGuard 的防御决策通过 WebSocket 下发至 Paper 插件 Agent
 *
 * AutoExecutor 生成自动防御动作后，如果存在已连接的 Agent，
 * 优先通过 AgentCommandDispatcher 将命令（ban/kick/whitelist 等）
 * 以 JSON 消息形式发送至 Agent，Agent 端通过 InternalCommandExecutor 执行。
 */
@Component
public class AgentCommandDispatcher {
    private static final Logger logger = LoggerFactory.getLogger(AgentCommandDispatcher.class);

    /**
     * 将 AI 分析结果转换为 Agent 命令并通过 WebSocket 下发
     */
    public void dispatchAutoAction(DeepSeekClient.AiAnalysisResult analysis,
                                   AlertEvent alert,
                                   AgentWebSocketServer agentServer) {
        String action = analysis.getAutoAction();
        if (action == null || action.isEmpty() || "无".equals(action) || "none".equals(action)) {
            return;
        }

        int confidencePercent = (int) (alert.getConfidence() * 100);
        logger.info("[AGENT-DISPATCH] {} (confidence: {}%)", action, confidencePercent);

        action = action.toLowerCase();
        String source = alert.getSource() != null ? alert.getSource() : "";
        String reason = alert.getType().getTitle() + " — " + analysis.getRootCause();

        if (action.contains("ban") || action.contains("封禁")) {
            dispatchBan(alert, agentServer, reason);
        }
        if (action.contains("kick") || action.contains("踢出")) {
            dispatchKick(alert, agentServer, reason);
        }
        if (action.contains("kill") || action.contains("清除") || action.contains("清理")) {
            agentServer.broadcastCommand("CLEAR_LAG", "", reason);
        }
        if (action.contains("whitelist") || action.contains("白名单")) {
            if (action.contains("enable") || action.contains("开启")) {
                agentServer.broadcastCommand("ENABLE_WHITELIST", "", reason);
            }
        }
    }

    private void dispatchBan(AlertEvent alert, AgentWebSocketServer agentServer, String reason) {
        String source = alert.getSource() != null ? alert.getSource() : "";
        // 尝试从 source 中提取 IP
        if (source.matches("\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}")) {
            agentServer.broadcastCommand("BAN_IP", source, reason);
            logger.info("[AGENT-DISPATCH] Ban IP: {}", source);
        } else if (!source.isEmpty()) {
            agentServer.broadcastCommand("BAN_PLAYER", source, reason);
            logger.info("[AGENT-DISPATCH] Ban Player: {}", source);
        }

        // 也尝试从告警消息中提取 IP
        String msg = alert.getMessage();
        if (msg != null) {
            java.util.regex.Matcher m = java.util.regex.Pattern.compile(
                "\\b(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})\\b").matcher(msg);
            if (m.find()) {
                agentServer.broadcastCommand("BAN_IP", m.group(1), reason);
                logger.info("[AGENT-DISPATCH] Ban IP from message: {}", m.group(1));
            }
        }
    }

    private void dispatchKick(AlertEvent alert, AgentWebSocketServer agentServer, String reason) {
        String source = alert.getSource() != null ? alert.getSource() : "";
        if (!source.isEmpty() && !source.matches("\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}")) {
            agentServer.broadcastCommand("KICK", source, reason);
            logger.info("[AGENT-DISPATCH] Kick: {}", source);
        }
    }
}
