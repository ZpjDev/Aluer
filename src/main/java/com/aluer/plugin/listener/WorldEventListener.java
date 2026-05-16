package com.aluer.plugin.listener;

import com.aluer.plugin.AluerPlugin;
import com.aluer.plugin.bridge.AgentWebSocketClient;
import com.google.gson.JsonObject;
import org.bukkit.event.EventHandler;
import org.bukkit.event.EventPriority;
import org.bukkit.event.Listener;
import org.bukkit.event.world.ChunkLoadEvent;
import org.bukkit.event.world.ChunkUnloadEvent;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class WorldEventListener implements Listener {
    private static final Logger logger = LoggerFactory.getLogger(WorldEventListener.class);

    private final AluerPlugin plugin;
    private final AgentWebSocketClient wsClient;

    public WorldEventListener(AluerPlugin plugin, AgentWebSocketClient wsClient) {
        this.plugin = plugin;
        this.wsClient = wsClient;
    }

    @EventHandler(priority = EventPriority.MONITOR)
    public void onChunkLoad(ChunkLoadEvent event) {
        if (wsClient == null) return;
        JsonObject data = new JsonObject();
        data.addProperty("world", event.getWorld().getName());
        data.addProperty("chunkX", event.getChunk().getX());
        data.addProperty("chunkZ", event.getChunk().getZ());
        data.addProperty("isNew", event.isNewChunk());
        wsClient.sendEvent("CHUNK_LOAD", data);
    }

    @EventHandler(priority = EventPriority.MONITOR)
    public void onChunkUnload(ChunkUnloadEvent event) {
        if (wsClient == null) return;
        JsonObject data = new JsonObject();
        data.addProperty("world", event.getWorld().getName());
        data.addProperty("chunkX", event.getChunk().getX());
        data.addProperty("chunkZ", event.getChunk().getZ());
        wsClient.sendEvent("CHUNK_UNLOAD", data);
    }
}
