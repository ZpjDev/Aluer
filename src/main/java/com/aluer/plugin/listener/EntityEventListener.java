package com.aluer.plugin.listener;

import com.aluer.plugin.AluerPlugin;
import com.aluer.plugin.bridge.AgentWebSocketClient;
import com.google.gson.JsonObject;
import org.bukkit.entity.Player;
import org.bukkit.event.EventHandler;
import org.bukkit.event.EventPriority;
import org.bukkit.event.Listener;
import org.bukkit.event.entity.EntitySpawnEvent;
import org.bukkit.event.entity.EntityPickupItemEvent;
import org.bukkit.event.player.PlayerFishEvent;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class EntityEventListener implements Listener {
    private static final Logger logger = LoggerFactory.getLogger(EntityEventListener.class);

    private final AluerPlugin plugin;
    private final AgentWebSocketClient wsClient;

    public EntityEventListener(AluerPlugin plugin, AgentWebSocketClient wsClient) {
        this.plugin = plugin;
        this.wsClient = wsClient;
    }

    @EventHandler(priority = EventPriority.MONITOR)
    public void onEntitySpawn(EntitySpawnEvent event) {
        if (wsClient == null) return;
        JsonObject data = new JsonObject();
        data.addProperty("entityType", event.getEntity().getType().name());
        data.addProperty("world", event.getLocation().getWorld() != null ? event.getLocation().getWorld().getName() : "");
        wsClient.sendEvent("ENTITY_SPAWN", data);
    }

    @EventHandler(priority = EventPriority.MONITOR, ignoreCancelled = true)
    public void onPlayerFish(PlayerFishEvent event) {
        if (wsClient == null) return;
        if (event.getState() == PlayerFishEvent.State.CAUGHT_FISH || event.getState() == PlayerFishEvent.State.CAUGHT_ENTITY) {
            JsonObject data = new JsonObject();
            data.addProperty("playerName", event.getPlayer().getName());
            data.addProperty("state", event.getState().name());
            wsClient.sendEvent("PLAYER_FISH", data);
        }
    }

    @EventHandler(priority = EventPriority.MONITOR, ignoreCancelled = true)
    public void onEntityPickup(EntityPickupItemEvent event) {
        if (wsClient == null) return;
        if (event.getEntity() instanceof Player p) {
            JsonObject data = new JsonObject();
            data.addProperty("playerName", p.getName());
            data.addProperty("itemType", event.getItem().getItemStack().getType().name());
            wsClient.sendEvent("ENTITY_PICKUP", data);
        }
    }
}
