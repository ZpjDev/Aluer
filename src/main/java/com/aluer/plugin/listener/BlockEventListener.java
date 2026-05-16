package com.aluer.plugin.listener;

import com.aluer.plugin.AluerPlugin;
import com.aluer.plugin.bridge.AgentWebSocketClient;
import com.google.gson.JsonObject;
import org.bukkit.Material;
import org.bukkit.block.Block;
import org.bukkit.entity.Player;
import org.bukkit.event.EventHandler;
import org.bukkit.event.EventPriority;
import org.bukkit.event.Listener;
import org.bukkit.event.block.BlockBreakEvent;
import org.bukkit.event.block.BlockPlaceEvent;
import org.bukkit.event.block.SignChangeEvent;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 方块事件监听器（Agent 端）
 */
public class BlockEventListener implements Listener {
    private static final Logger logger = LoggerFactory.getLogger(BlockEventListener.class);

    private final AluerPlugin plugin;
    private final AgentWebSocketClient wsClient;

    public BlockEventListener(AluerPlugin plugin, AgentWebSocketClient wsClient) {
        this.plugin = plugin;
        this.wsClient = wsClient;
    }

    @EventHandler(priority = EventPriority.MONITOR, ignoreCancelled = true)
    public void onBlockBreak(BlockBreakEvent event) {
        if (wsClient == null) return;
        Block b = event.getBlock();
        JsonObject data = new JsonObject();
        data.addProperty("playerName", event.getPlayer().getName());
        data.addProperty("material", b.getType().name());
        data.addProperty("x", b.getX()); data.addProperty("y", b.getY()); data.addProperty("z", b.getZ());
        data.addProperty("world", b.getWorld().getName());
        wsClient.sendEvent("BLOCK_BREAK", data);
    }

    @EventHandler(priority = EventPriority.MONITOR, ignoreCancelled = true)
    public void onBlockPlace(BlockPlaceEvent event) {
        if (wsClient == null) return;
        Block b = event.getBlock();
        JsonObject data = new JsonObject();
        data.addProperty("playerName", event.getPlayer().getName());
        data.addProperty("material", b.getType().name());
        data.addProperty("x", b.getX()); data.addProperty("y", b.getY()); data.addProperty("z", b.getZ());
        data.addProperty("world", b.getWorld().getName());
        wsClient.sendEvent("BLOCK_PLACE", data);
    }

    @EventHandler(priority = EventPriority.LOWEST, ignoreCancelled = true)
    public void onSignChange(SignChangeEvent event) {
        if (wsClient == null) return;
        // —— Agent 端即时拦截：SignExploit ——
        for (int i = 0; i < 4; i++) {
            String line = event.getLine(i);
            if (line != null && line.length() > 128) {
                event.setCancelled(true);
                wsClient.sendAlert("SECURITY_SIGN_EXPLOIT",
                    "即时拦截：玩家 " + event.getPlayer().getName() + " 告示牌文本异常长",
                    0.9, event.getPlayer().getName());
                return;
            }
        }
    }
}
