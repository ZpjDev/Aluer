package com.aluer.plugin.listener;

import com.aluer.plugin.AluerPlugin;
import com.aluer.plugin.bridge.AgentWebSocketClient;
import com.google.gson.JsonObject;
import org.bukkit.entity.Player;
import org.bukkit.event.EventHandler;
import org.bukkit.event.EventPriority;
import org.bukkit.event.Listener;
import org.bukkit.event.inventory.*;
import org.bukkit.inventory.Inventory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class InventoryEventListener implements Listener {
    private static final Logger logger = LoggerFactory.getLogger(InventoryEventListener.class);

    private final AluerPlugin plugin;
    private final AgentWebSocketClient wsClient;

    public InventoryEventListener(AluerPlugin plugin, AgentWebSocketClient wsClient) {
        this.plugin = plugin;
        this.wsClient = wsClient;
    }

    @EventHandler(priority = EventPriority.MONITOR, ignoreCancelled = true)
    public void onInventoryClick(InventoryClickEvent event) {
        if (wsClient == null) return;
        if (!(event.getWhoClicked() instanceof Player p)) return;
        JsonObject data = new JsonObject();
        data.addProperty("playerName", p.getName());
        data.addProperty("inventoryType", event.getInventory().getType().name());
        data.addProperty("action", event.getAction().name());
        data.addProperty("slot", event.getSlot());
        data.addProperty("currentItem", event.getCurrentItem() != null ? event.getCurrentItem().getType().name() : "AIR");
        data.addProperty("cursorItem", event.getCursor() != null ? event.getCursor().getType().name() : "AIR");
        wsClient.sendEvent("INVENTORY_CLICK", data);
    }

    @EventHandler(priority = EventPriority.MONITOR, ignoreCancelled = true)
    public void onInventoryDrag(InventoryDragEvent event) {
        if (wsClient == null) return;
        if (!(event.getWhoClicked() instanceof Player p)) return;
        JsonObject data = new JsonObject();
        data.addProperty("playerName", p.getName());
        data.addProperty("slotsCount", event.getInventorySlots().size());
        wsClient.sendEvent("INVENTORY_DRAG", data);
    }
}
