package com.aluer.plugin.listener;

import com.aluer.plugin.AluerPlugin;
import com.aluer.plugin.bridge.AgentWebSocketClient;
import com.google.gson.JsonObject;
import org.bukkit.event.EventHandler;
import org.bukkit.event.EventPriority;
import org.bukkit.event.Listener;
import org.bukkit.event.player.PlayerCommandPreprocessEvent;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 命令事件监听器（Agent 端）
 *
 * Agent 端即时拦截：命令注入、敏感命令
 * 推送所有命令数据至 ServerGuard 做深度行为分析
 */
public class CommandEventListener implements Listener {
    private static final Logger logger = LoggerFactory.getLogger(CommandEventListener.class);

    private final AluerPlugin plugin;
    private final AgentWebSocketClient wsClient;

    private static final String[] BLOCKED_PATTERNS = {
        "${", "`", "&& rm ", "|| rm ", "; rm ", "$((", "eval ", "exec("
    };

    public CommandEventListener(AluerPlugin plugin, AgentWebSocketClient wsClient) {
        this.plugin = plugin;
        this.wsClient = wsClient;
    }

    @EventHandler(priority = EventPriority.LOWEST)
    public void onPlayerCommand(PlayerCommandPreprocessEvent event) {
        if (wsClient == null) return;
        String command = event.getMessage().toLowerCase().trim();
        String playerName = event.getPlayer().getName();

        // —— Agent 端即时拦截：命令注入 ——
        for (String pattern : BLOCKED_PATTERNS) {
            if (command.contains(pattern)) {
                event.setCancelled(true);
                wsClient.sendAlert("COMMAND_ABUSE",
                    "即时拦截：玩家 " + playerName + " 命令注入尝试", 0.95, playerName);
                return;
            }
        }

        // 推送命令数据到 ServerGuard
        JsonObject data = new JsonObject();
        data.addProperty("playerName", playerName);
        data.addProperty("command", event.getMessage());
        data.addProperty("isOp", event.getPlayer().isOp());
        wsClient.sendEvent("PLAYER_COMMAND", data);
    }
}
