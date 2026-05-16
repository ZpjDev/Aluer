package com.aluer.agent;

import com.google.gson.Gson;
import com.google.gson.JsonObject;

import java.time.Instant;
import java.util.UUID;

/**
 * Agent 通信协议 — 定义 Agent（Paper 插件）与 ServerGuard（外部 Spring Boot）之间的消息格式
 *
 * 通信方向：
 *   Agent → Server:  EVENT（事件）, METRICS（指标）, ALERT（告警）, HEARTBEAT（心跳）, HANDSHAKE（握手）
 *   Server → Agent:  COMMAND（执行命令）, CONFIG（配置更新）, SHUTDOWN（关闭）
 *
 * 所有消息均为单行 JSON，通过 WebSocket 文本帧传输
 */
public class AgentMessage {

    // ─── 消息类型常量 ──────────────────────────────────

    /** Agent → Server：Bukkit 事件数据 */
    public static final String TYPE_EVENT = "EVENT";
    /** Agent → Server：TPS/CPU/Memory 等服务器指标 */
    public static final String TYPE_METRICS = "METRICS";
    /** Agent → Server：检测到的安全告警 */
    public static final String TYPE_ALERT = "ALERT";
    /** Agent → Server：心跳保活 */
    public static final String TYPE_HEARTBEAT = "HEARTBEAT";
    /** Agent → Server：初次连接握手 */
    public static final String TYPE_HANDSHAKE = "HANDSHAKE";
    /** Agent → Server：命令执行结果回执 */
    public static final String TYPE_COMMAND_RESULT = "COMMAND_RESULT";

    /** Server → Agent：执行命令 */
    public static final String TYPE_COMMAND = "COMMAND";
    /** Server → Agent：配置更新 */
    public static final String TYPE_CONFIG = "CONFIG";
    /** Server → Agent：关闭连接 */
    public static final String TYPE_SHUTDOWN = "SHUTDOWN";

    // ─── 命令类型常量 ──────────────────────────────────

    public static final String CMD_BAN_IP = "BAN_IP";
    public static final String CMD_BAN_PLAYER = "BAN_PLAYER";
    public static final String CMD_KICK = "KICK";
    public static final String CMD_CLEAR_LAG = "CLEAR_LAG";
    public static final String CMD_SET_SPAWN_RATE = "SET_SPAWN_RATE";
    public static final String CMD_ENABLE_WHITELIST = "ENABLE_WHITELIST";
    public static final String CMD_DISABLE_WHITELIST = "DISABLE_WHITELIST";
    public static final String CMD_BROADCAST = "BROADCAST";
    public static final String CMD_SAVE_ALL = "SAVE_ALL";
    public static final String CMD_EXECUTE = "EXECUTE";

    // ─── 事件类型常量 ──────────────────────────────────

    public static final String EVENT_PLAYER_JOIN = "PLAYER_JOIN";
    public static final String EVENT_PLAYER_QUIT = "PLAYER_QUIT";
    public static final String EVENT_PLAYER_MOVE = "PLAYER_MOVE";
    public static final String EVENT_PLAYER_TELEPORT = "PLAYER_TELEPORT";
    public static final String EVENT_PLAYER_CHAT = "PLAYER_CHAT";
    public static final String EVENT_PLAYER_COMMAND = "PLAYER_COMMAND";
    public static final String EVENT_PLAYER_DAMAGE = "PLAYER_DAMAGE";
    public static final String EVENT_COMBAT_ATTACK = "COMBAT_ATTACK";
    public static final String EVENT_COMBAT_DEATH = "COMBAT_DEATH";
    public static final String EVENT_BLOCK_BREAK = "BLOCK_BREAK";
    public static final String EVENT_BLOCK_PLACE = "BLOCK_PLACE";
    public static final String EVENT_INVENTORY_CLICK = "INVENTORY_CLICK";
    public static final String EVENT_ENTITY_SPAWN = "ENTITY_SPAWN";
    public static final String EVENT_CHUNK_LOAD = "CHUNK_LOAD";

    private static final Gson gson = new Gson();

    // ─── 构造方法 ──────────────────────────────────────

    /** 构造一条 Agent → Server 消息 */
    public static String buildMessage(String type, String agentId, JsonObject payload) {
        JsonObject msg = new JsonObject();
        msg.addProperty("type", type);
        msg.addProperty("agentId", agentId);
        msg.addProperty("timestamp", Instant.now().toEpochMilli());
        msg.add("payload", payload);
        return gson.toJson(msg);
    }

    /** 构造一条 Server → Agent 命令消息 */
    public static String buildCommand(String commandType, String target, String reason) {
        JsonObject payload = new JsonObject();
        payload.addProperty("command", commandType);
        payload.addProperty("target", target != null ? target : "");
        payload.addProperty("reason", reason != null ? reason : "");

        JsonObject msg = new JsonObject();
        msg.addProperty("type", TYPE_COMMAND);
        msg.addProperty("requestId", UUID.randomUUID().toString());
        msg.addProperty("timestamp", Instant.now().toEpochMilli());
        msg.add("payload", payload);
        return gson.toJson(msg);
    }

    /** 构造心跳消息 */
    public static String buildHeartbeat(String agentId) {
        JsonObject payload = new JsonObject();
        payload.addProperty("status", "alive");
        return buildMessage(TYPE_HEARTBEAT, agentId, payload);
    }

    /** 解析消息的 type 字段 */
    public static String getType(String message) {
        try {
            JsonObject msg = gson.fromJson(message, JsonObject.class);
            return msg.get("type") != null ? msg.get("type").getAsString() : null;
        } catch (Exception e) {
            return null;
        }
    }

    /** 解析消息的 payload 对象 */
    public static JsonObject getPayload(String message) {
        try {
            JsonObject msg = gson.fromJson(message, JsonObject.class);
            return msg.getAsJsonObject("payload");
        } catch (Exception e) {
            return null;
        }
    }

    /** 解析消息的 agentId */
    public static String getAgentId(String message) {
        try {
            JsonObject msg = gson.fromJson(message, JsonObject.class);
            return msg.get("agentId") != null ? msg.get("agentId").getAsString() : null;
        } catch (Exception e) {
            return null;
        }
    }
}
