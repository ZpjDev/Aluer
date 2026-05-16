package com.aluer.server;

import com.aluer.agent.AgentMessage;
import com.google.gson.JsonObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.socket.*;
import org.springframework.web.socket.handler.TextWebSocketHandler;

import java.io.IOException;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.BiConsumer;

/**
 * Agent WebSocket 服务器 — 运行在 ServerGuard Spring Boot 内部
 *
 * 接收来自 Paper 插件 Agent 的 WebSocket 连接，
 * 将 Agent 上报的事件/指标/告警路由到对应的处理器，
 * 同时提供向已连接 Agent 下发命令的能力。
 *
 * WebSocket 路径：/agent（由 WebSocketConfig 配置）
 */
@Component
public class AgentWebSocketServer extends TextWebSocketHandler {
    private static final Logger logger = LoggerFactory.getLogger(AgentWebSocketServer.class);

    /** 已连接 Agent 的 WebSocket 会话（agentId → session） */
    private final Map<String, WebSocketSession> sessions = new ConcurrentHashMap<>();

    /** Agent 元数据（agentId → 握手信息） */
    private final Map<String, JsonObject> agentMetadata = new ConcurrentHashMap<>();

    /** 事件消息处理器（由 ServerGuardService 注入） */
    private volatile BiConsumer<String, JsonObject> eventHandler;

    /** 指标消息处理器 */
    private volatile BiConsumer<String, JsonObject> metricsHandler;

    /** 告警消息处理器 */
    private volatile BiConsumer<String, JsonObject> alertHandler;

    /** 命令执行结果处理器 */
    private volatile BiConsumer<String, JsonObject> commandResultHandler;

    // ─── Spring WebSocket 回调 ────────────────────────

    @Override
    public void afterConnectionEstablished(WebSocketSession session) {
        String agentId = extractAgentId(session);
        if (agentId == null || agentId.isEmpty()) {
            try {
                session.close(CloseStatus.BAD_DATA);
            } catch (IOException ignored) {}
            logger.warn("Rejected agent connection without agentId");
            return;
        }

        sessions.put(agentId, session);
        logger.info("Agent {} connected from {} (total agents: {})",
            agentId, session.getRemoteAddress(), sessions.size());
    }

    @Override
    protected void handleTextMessage(WebSocketSession session, TextMessage message) {
        String agentId = extractAgentId(session);
        if (agentId == null) return;

        try {
            String payload = message.getPayload();
            String type = AgentMessage.getType(payload);
            JsonObject data = AgentMessage.getPayload(payload);

            if (type == null) return;

            switch (type) {
                case AgentMessage.TYPE_HANDSHAKE:
                    if (data != null) {
                        agentMetadata.put(agentId, data);
                        logger.info("Agent {} handshake: version={}, players={}",
                            agentId,
                            data.get("serverVersion") != null ? data.get("serverVersion").getAsString() : "?",
                            data.get("onlinePlayers") != null ? data.get("onlinePlayers").getAsInt() : 0);
                    }
                    break;

                case AgentMessage.TYPE_EVENT:
                    if (eventHandler != null && data != null) {
                        eventHandler.accept(agentId, data);
                    }
                    break;

                case AgentMessage.TYPE_METRICS:
                    if (metricsHandler != null && data != null) {
                        metricsHandler.accept(agentId, data);
                    }
                    break;

                case AgentMessage.TYPE_ALERT:
                    if (alertHandler != null && data != null) {
                        alertHandler.accept(agentId, data);
                    }
                    break;

                case AgentMessage.TYPE_COMMAND_RESULT:
                    if (commandResultHandler != null && data != null) {
                        commandResultHandler.accept(agentId, data);
                    }
                    break;

                case AgentMessage.TYPE_HEARTBEAT:
                    // 心跳消息仅用于保活，无需额外处理
                    break;

                default:
                    logger.debug("Unknown message type from agent {}: {}", agentId, type);
            }
        } catch (Exception e) {
            logger.error("Failed to handle message from agent {}: {}", agentId, e.getMessage());
        }
    }

    @Override
    public void afterConnectionClosed(WebSocketSession session, CloseStatus status) {
        String agentId = extractAgentId(session);
        if (agentId != null) {
            sessions.remove(agentId);
            agentMetadata.remove(agentId);
            logger.info("Agent {} disconnected (status: {}), remaining: {}",
                agentId, status, sessions.size());
        }
    }

    @Override
    public void handleTransportError(WebSocketSession session, Throwable exception) {
        String agentId = extractAgentId(session);
        logger.error("Transport error for agent {}: {}", agentId, exception.getMessage());
    }

    // ─── 命令下发 ──────────────────────────────────────

    /** 向指定 Agent 发送命令 */
    public boolean sendCommand(String agentId, String commandType, String target, String reason) {
        WebSocketSession session = sessions.get(agentId);
        if (session == null || !session.isOpen()) {
            logger.warn("Cannot send command: agent {} not connected", agentId);
            return false;
        }

        try {
            String message = AgentMessage.buildCommand(commandType, target, reason);
            session.sendMessage(new TextMessage(message));
            return true;
        } catch (IOException e) {
            logger.error("Failed to send command to agent {}: {}", agentId, e.getMessage());
            return false;
        }
    }

    /** 向所有已连接 Agent 广播命令 */
    public void broadcastCommand(String commandType, String target, String reason) {
        for (String agentId : sessions.keySet()) {
            sendCommand(agentId, commandType, target, reason);
        }
    }

    // ─── 处理器注册 ────────────────────────────────────

    public void setEventHandler(BiConsumer<String, JsonObject> handler) {
        this.eventHandler = handler;
    }

    public void setMetricsHandler(BiConsumer<String, JsonObject> handler) {
        this.metricsHandler = handler;
    }

    public void setAlertHandler(BiConsumer<String, JsonObject> handler) {
        this.alertHandler = handler;
    }

    public void setCommandResultHandler(BiConsumer<String, JsonObject> handler) {
        this.commandResultHandler = handler;
    }

    // ─── 状态查询 ──────────────────────────────────────

    public int getConnectedAgentCount() {
        return sessions.size();
    }

    public boolean isAgentConnected(String agentId) {
        return sessions.containsKey(agentId);
    }

    // ─── 内部 ──────────────────────────────────────────

    private String extractAgentId(WebSocketSession session) {
        // 从 URL 查询参数中提取 agentId：/agent?agentId=xxx
        String query = session.getUri() != null ? session.getUri().getQuery() : null;
        if (query != null) {
            for (String param : query.split("&")) {
                String[] kv = param.split("=", 2);
                if (kv.length == 2 && "agentId".equals(kv[0])) {
                    return kv[1];
                }
            }
        }
        // fallback：从 session attributes 获取
        Object attr = session.getAttributes().get("agentId");
        return attr != null ? attr.toString() : null;
    }
}
