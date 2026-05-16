package com.aluer.plugin.bridge;

import com.aluer.agent.AgentMessage;
import com.google.gson.Gson;
import com.google.gson.JsonObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.WebSocket;
import java.time.Duration;
import java.util.UUID;
import java.util.concurrent.*;
import java.util.function.Consumer;

/**
 * Agent WebSocket 客户端 — 运行在 Paper 插件内部
 *
 * 职责：
 * 1. 建立与外部 ServerGuard Server 的 WebSocket 长连接
 * 2. 将 Bukkit 事件序列化为 JSON 并实时推送
 * 3. 接收 Server 下发的命令并交由 InternalCommandExecutor 执行
 * 4. 断线自动重连 + 心跳保活
 *
 * 通信协议见 AgentMessage 类定义
 */
public class AgentWebSocketClient {
    private static final Logger logger = LoggerFactory.getLogger(AgentWebSocketClient.class);

    private final String agentId;
    private final String serverUrl;
    private final InternalCommandExecutor commandExecutor;
    private final HttpClient httpClient;
    private final ScheduledExecutorService scheduler;

    /** 命令结果回调（收到服务端命令后执行） */
    private Consumer<String> commandHandler;

    private volatile WebSocket webSocket;
    private volatile boolean connected = false;
    private volatile boolean running = true;

    /** 重连间隔（秒），指数退避上限 60 秒 */
    private int reconnectDelay = 5;
    private static final int MAX_RECONNECT_DELAY = 60;

    /** 心跳间隔（秒） */
    private static final int HEARTBEAT_INTERVAL = 15;

    /** 待发送消息队列（断线时缓存） */
    private final BlockingQueue<String> pendingMessages = new LinkedBlockingQueue<>(500);

    private static final Gson gson = new Gson();

    public AgentWebSocketClient(String serverUrl, InternalCommandExecutor commandExecutor) {
        this.agentId = UUID.randomUUID().toString();
        this.serverUrl = serverUrl;
        this.commandExecutor = commandExecutor;
        this.httpClient = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(10))
            .build();
        this.scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "aluer-agent-ws");
            t.setDaemon(true);
            return t;
        });
    }

    public void setCommandHandler(Consumer<String> handler) {
        this.commandHandler = handler;
    }

    // ─── 连接管理 ──────────────────────────────────────

    /** 启动连接（异步，不阻塞主线程） */
    public void connect() {
        scheduler.execute(this::doConnect);
    }

    private void doConnect() {
        while (running && !connected) {
            try {
                logger.info("Agent {} connecting to ServerGuard at {}...", agentId, serverUrl);
                URI uri = URI.create(serverUrl + "?agentId=" + agentId);

                CompletableFuture<WebSocket> future = httpClient.newWebSocketBuilder()
                    .connectTimeout(Duration.ofSeconds(10))
                    .buildAsync(uri, new WebSocketListener());

                webSocket = future.get(15, TimeUnit.SECONDS);
                connected = true;
                reconnectDelay = 5; // 重置重连间隔
                logger.info("Agent {} connected to ServerGuard successfully", agentId);

                // 发送握手消息
                sendHandshake();

                // 开始心跳
                startHeartbeat();

                // 发送积压消息
                drainPendingMessages();

            } catch (Exception e) {
                logger.warn("Agent {} connection failed: {}. Retrying in {}s...",
                    agentId, e.getMessage(), reconnectDelay);
                connected = false;

                try {
                    Thread.sleep(reconnectDelay * 1000L);
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                    break;
                }

                reconnectDelay = Math.min(reconnectDelay * 2, MAX_RECONNECT_DELAY);
            }
        }
    }

    /** 断开连接 */
    public void disconnect() {
        running = false;
        scheduler.shutdown();
        if (webSocket != null) {
            webSocket.sendClose(WebSocket.NORMAL_CLOSURE, "Agent shutting down");
        }
        connected = false;
        logger.info("Agent {} disconnected", agentId);
    }

    public boolean isConnected() {
        return connected && webSocket != null && !webSocket.isOutputClosed();
    }

    // ─── 消息发送 ──────────────────────────────────────

    /** 发送事件到 ServerGuard */
    public void sendEvent(String eventType, JsonObject eventData) {
        String msg = AgentMessage.buildMessage(AgentMessage.TYPE_EVENT, agentId, createPayload(eventType, eventData));
        send(msg);
    }

    /** 发送指标数据到 ServerGuard */
    public void sendMetrics(JsonObject metricsData) {
        String msg = AgentMessage.buildMessage(AgentMessage.TYPE_METRICS, agentId, metricsData);
        send(msg);
    }

    /** 发送告警到 ServerGuard */
    public void sendAlert(String alertType, String alertMessage, double confidence, String source) {
        JsonObject alertData = new JsonObject();
        alertData.addProperty("alertType", alertType);
        alertData.addProperty("message", alertMessage);
        alertData.addProperty("confidence", confidence);
        alertData.addProperty("source", source);
        String msg = AgentMessage.buildMessage(AgentMessage.TYPE_ALERT, agentId, alertData);
        send(msg);
    }

    /** 发送命令执行结果回执 */
    public void sendCommandResult(String requestId, boolean success, String details) {
        JsonObject result = new JsonObject();
        result.addProperty("requestId", requestId);
        result.addProperty("success", success);
        result.addProperty("details", details);
        String msg = AgentMessage.buildMessage(AgentMessage.TYPE_COMMAND_RESULT, agentId, result);
        send(msg);
    }

    /** 底层发送方法 */
    private void send(String message) {
        if (isConnected()) {
            try {
                webSocket.sendText(message, true).get(5, TimeUnit.SECONDS);
            } catch (Exception e) {
                logger.debug("WebSocket send failed, queueing message: {}", e.getMessage());
                queuePending(message);
            }
        } else {
            queuePending(message);
        }
    }

    private void queuePending(String message) {
        pendingMessages.offer(message);
        while (pendingMessages.size() > 500) {
            pendingMessages.poll(); // 丢弃最旧消息
        }
    }

    private JsonObject createPayload(String eventType, JsonObject data) {
        JsonObject payload = new JsonObject();
        payload.addProperty("eventType", eventType);
        payload.add("data", data);
        return payload;
    }

    // ─── 内部方法 ──────────────────────────────────────

    private void sendHandshake() {
        JsonObject handshake = new JsonObject();
        handshake.addProperty("serverVersion", getServerVersion());
        handshake.addProperty("onlinePlayers", getOnlinePlayerCount());
        String msg = AgentMessage.buildMessage(AgentMessage.TYPE_HANDSHAKE, agentId, handshake);
        send(msg);
    }

    private void startHeartbeat() {
        scheduler.scheduleAtFixedRate(() -> {
            if (isConnected()) {
                send(AgentMessage.buildHeartbeat(agentId));
            }
        }, HEARTBEAT_INTERVAL, HEARTBEAT_INTERVAL, TimeUnit.SECONDS);
    }

    private void drainPendingMessages() {
        String msg;
        int count = 0;
        while ((msg = pendingMessages.poll()) != null && count < 100) {
            send(msg);
            count++;
        }
        if (count > 0) {
            logger.debug("Drained {} pending messages", count);
        }
    }

    private String getServerVersion() {
        try {
            return org.bukkit.Bukkit.getServer().getVersion();
        } catch (Exception e) {
            return "unknown";
        }
    }

    private int getOnlinePlayerCount() {
        try {
            return org.bukkit.Bukkit.getServer().getOnlinePlayers().size();
        } catch (Exception e) {
            return 0;
        }
    }

    // ─── WebSocket 监听器 ──────────────────────────────

    private class WebSocketListener implements WebSocket.Listener {
        private final StringBuilder buffer = new StringBuilder();

        @Override
        public void onOpen(WebSocket ws) {
            WebSocket.Listener.super.onOpen(ws);
        }

        @Override
        public CompletionStage<?> onText(WebSocket ws, CharSequence data, boolean last) {
            buffer.append(data);
            if (last) {
                String message = buffer.toString();
                buffer.setLength(0);
                handleServerMessage(message);
                ws.request(1);
            }
            return null;
        }

        @Override
        public CompletionStage<?> onClose(WebSocket ws, int statusCode, String reason) {
            logger.warn("Agent {} WebSocket closed: {} — {}", agentId, statusCode, reason);
            connected = false;
            if (running) {
                scheduler.execute(() -> {
                    try {
                        Thread.sleep(reconnectDelay * 1000L);
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                    }
                    doConnect();
                });
            }
            return null;
        }

        @Override
        public void onError(WebSocket ws, Throwable error) {
            logger.error("Agent {} WebSocket error: {}", agentId, error.getMessage());
            connected = false;
        }
    }

    private void handleServerMessage(String message) {
        try {
            String type = AgentMessage.getType(message);
            if (type == null) return;

            switch (type) {
                case AgentMessage.TYPE_COMMAND:
                    // 收到服务端命令，交由 InternalCommandExecutor 执行
                    JsonObject payload = AgentMessage.getPayload(message);
                    if (payload != null && commandExecutor != null) {
                        String cmdType = payload.get("command") != null
                            ? payload.get("command").getAsString()
                            : "";
                        String target = payload.get("target") != null
                            ? payload.get("target").getAsString()
                            : "";
                        String reason = payload.get("reason") != null
                            ? payload.get("reason").getAsString()
                            : "";

                        executeServerCommand(message, cmdType, target, reason);
                    }
                    break;

                case AgentMessage.TYPE_SHUTDOWN:
                    logger.info("Agent {} received shutdown command from ServerGuard", agentId);
                    disconnect();
                    break;

                default:
                    logger.debug("Agent {} received unknown message type: {}", agentId, type);
            }
        } catch (Exception e) {
            logger.error("Failed to handle server message: {}", e.getMessage());
        }
    }

    /** 执行服务端下发的命令 */
    private void executeServerCommand(String rawMessage, String cmdType, String target, String reason) {
        boolean success = false;
        String details = "";

        try {
            switch (cmdType) {
                case AgentMessage.CMD_BAN_IP:
                    success = commandExecutor.banIP(target, reason);
                    details = success ? "IP banned: " + target : "Failed to ban IP";
                    break;
                case AgentMessage.CMD_BAN_PLAYER:
                    success = commandExecutor.banPlayer(target, reason);
                    details = success ? "Player banned: " + target : "Failed to ban player";
                    break;
                case AgentMessage.CMD_KICK:
                    success = commandExecutor.kickPlayer(target, reason);
                    details = success ? "Player kicked: " + target : "Player not online";
                    break;
                case AgentMessage.CMD_CLEAR_LAG:
                    int removed = commandExecutor.clearDroppedItems();
                    success = true;
                    details = "Removed " + removed + " dropped items";
                    break;
                case AgentMessage.CMD_SET_SPAWN_RATE:
                    success = commandExecutor.setSpawnRate(5);
                    details = "Spawn rate reduced";
                    break;
                case AgentMessage.CMD_ENABLE_WHITELIST:
                    success = commandExecutor.enableWhitelist();
                    details = "Whitelist enabled";
                    break;
                case AgentMessage.CMD_DISABLE_WHITELIST:
                    success = commandExecutor.disableWhitelist();
                    details = "Whitelist disabled";
                    break;
                case AgentMessage.CMD_BROADCAST:
                    commandExecutor.broadcast(reason);
                    success = true;
                    details = "Broadcast sent";
                    break;
                case AgentMessage.CMD_SAVE_ALL:
                    success = commandExecutor.saveAllWorlds();
                    details = "Worlds saved";
                    break;
                case AgentMessage.CMD_EXECUTE:
                    success = commandExecutor.executeCommand(target);
                    details = "Command executed: " + target;
                    break;
                default:
                    details = "Unknown command: " + cmdType;
            }
        } catch (Exception e) {
            success = false;
            details = "Error: " + e.getMessage();
            logger.error("Command execution failed: {}", e.getMessage());
        }

        // 发送执行结果回执
        String requestId = null;
        try {
            JsonObject msg = gson.fromJson(rawMessage, JsonObject.class);
            requestId = msg.get("requestId") != null ? msg.get("requestId").getAsString() : null;
        } catch (Exception ignored) {}

        if (requestId != null) {
            sendCommandResult(requestId, success, details);
        }
    }

    public String getAgentId() {
        return agentId;
    }
}
