package com.aluer.config;

import com.aluer.server.AgentWebSocketServer;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.socket.config.annotation.EnableWebSocket;
import org.springframework.web.socket.config.annotation.WebSocketConfigurer;
import org.springframework.web.socket.config.annotation.WebSocketHandlerRegistry;

/**
 * WebSocket 配置 — 注册 Agent 通信端点
 *
 * Agent（Paper 插件）通过 ws://host:port/agent?agentId=xxx 连接
 */
@Configuration
@EnableWebSocket
public class WebSocketConfig implements WebSocketConfigurer {

    private final AgentWebSocketServer agentWebSocketServer;

    public WebSocketConfig(AgentWebSocketServer agentWebSocketServer) {
        this.agentWebSocketServer = agentWebSocketServer;
    }

    @Override
    public void registerWebSocketHandlers(WebSocketHandlerRegistry registry) {
        registry.addHandler(agentWebSocketServer, "/agent")
            .setAllowedOrigins("*");
    }
}
