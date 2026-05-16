package com.aluer.plugin.listener;

import com.aluer.plugin.AluerPlugin;
import com.aluer.plugin.bridge.AgentWebSocketClient;
import com.google.gson.JsonObject;
import org.bukkit.event.EventHandler;
import org.bukkit.event.EventPriority;
import org.bukkit.event.Listener;
import org.bukkit.event.player.AsyncPlayerChatEvent;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;

/**
 * 聊天事件监听器（Agent 端）
 *
 * Agent 端即时拦截（可取消事件）：IP广告/钓鱼链接/刷屏
 * 同时推送所有聊天数据至 ServerGuard 做深度内容分析和模式学习
 */
public class ChatEventListener implements Listener {
    private static final Logger logger = LoggerFactory.getLogger(ChatEventListener.class);

    private final AluerPlugin plugin;
    private final AgentWebSocketClient wsClient;

    private static final Pattern IP_PATTERN = Pattern.compile(
        "(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})(:\\d{1,5})?");
    private static final Pattern URL_PATTERN = Pattern.compile(
        "https?://[^\\s]+|bit\\.ly/[^\\s]+|discord\\.gg/[^\\s]+",
        Pattern.CASE_INSENSITIVE);

    /** 刷屏检测：最近消息时间戳 */
    private final Map<UUID, Long> lastChatTime = new ConcurrentHashMap<>();
    private final Map<UUID, Integer> chatBurstCount = new ConcurrentHashMap<>();
    private static final long CHAT_BURST_WINDOW_MS = 2000;
    private static final int CHAT_BURST_THRESHOLD = 4;

    public ChatEventListener(AluerPlugin plugin, AgentWebSocketClient wsClient) {
        this.plugin = plugin;
        this.wsClient = wsClient;
    }

    @EventHandler(priority = EventPriority.LOWEST, ignoreCancelled = true)
    public void onAsyncPlayerChat(AsyncPlayerChatEvent event) {
        if (wsClient == null) return;
        String message = event.getMessage();
        String playerName = event.getPlayer().getName();
        UUID uuid = event.getPlayer().getUniqueId();

        // —— Agent 端即时拦截：IP 广告 ——
        if (IP_PATTERN.matcher(message).find()) {
            event.setCancelled(true);
            wsClient.sendAlert("CHAT_ADVERTISEMENT",
                "即时拦截：玩家 " + playerName + " 发送疑似IP地址", 0.9, playerName);
            return;
        }

        // —— Agent 端即时拦截：钓鱼链接 ——
        if (URL_PATTERN.matcher(message).find()) {
            event.setCancelled(true);
            wsClient.sendAlert("CHAT_PHISHING",
                "即时拦截：玩家 " + playerName + " 发送外部链接", 0.85, playerName);
            return;
        }

        // —— Agent 端即时拦截：刷屏 ——
        long now = System.currentTimeMillis();
        Long last = lastChatTime.get(uuid);
        if (last != null && (now - last) < CHAT_BURST_WINDOW_MS) {
            int count = chatBurstCount.merge(uuid, 1, Integer::sum);
            if (count >= CHAT_BURST_THRESHOLD) {
                event.setCancelled(true);
                wsClient.sendAlert("CHAT_FLOOD",
                    "即时拦截：玩家 " + playerName + " 聊天刷屏", 0.8, playerName);
                return;
            }
        } else {
            chatBurstCount.put(uuid, 1);
        }
        lastChatTime.put(uuid, now);

        // 推送聊天数据到 ServerGuard
        JsonObject data = new JsonObject();
        data.addProperty("playerName", playerName);
        data.addProperty("uuid", uuid.toString());
        data.addProperty("message", message);
        wsClient.sendEvent("PLAYER_CHAT", data);
    }
}
