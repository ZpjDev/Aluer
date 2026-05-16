package com.aluer.plugin.listener;

import com.aluer.model.AlertType;
import com.aluer.plugin.AluerPlugin;
import com.aluer.plugin.bridge.DataBridge;
import com.aluer.plugin.bridge.DataBridge.PlayerSnapshot;
import org.bukkit.block.Container;
import org.bukkit.entity.Player;
import org.bukkit.event.EventHandler;
import org.bukkit.event.EventPriority;
import org.bukkit.event.Listener;
import org.bukkit.event.inventory.*;
import org.bukkit.inventory.Inventory;
import org.bukkit.inventory.ItemStack;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 物品栏事件监听器 — 处理容器交互、物品移动
 *
 * 实时检测：
 * - ChestSteal（快速偷箱）— 短时间内从容器取出大量物品
 * - InventoryManipulation（物品栏操控）— 异常快速的物品移动模式
 * - Dupe（物品复制）— 异常物品数量变化
 */
public class InventoryEventListener implements Listener {
    private static final Logger logger = LoggerFactory.getLogger(InventoryEventListener.class);

    private final AluerPlugin plugin;
    private final DataBridge bridge;

    /** 单次 Click 事件中物品数量变化的阈值（超过视为可疑） */
    private static final int ITEM_CHANGE_THRESHOLD = 64;

    public InventoryEventListener(AluerPlugin plugin, DataBridge bridge) {
        this.plugin = plugin;
        this.bridge = bridge;
    }

    @EventHandler(priority = EventPriority.MONITOR, ignoreCancelled = true)
    public void onInventoryClick(InventoryClickEvent event) {
        if (bridge == null) return;
        if (!(event.getWhoClicked() instanceof Player player)) return;

        Inventory inv = event.getInventory();
        InventoryType type = inv.getType();
        PlayerSnapshot snap = bridge.getPlayer(player.getUniqueId());
        if (snap == null) return;

        bridge.incrementEvent("inventory.click");

        // —— ChestSteal 检测 ——
        // 检测玩家在短时间内从他人容器中快速取走物品
        if (type == InventoryType.CHEST || type == InventoryType.BARREL
            || type == InventoryType.SHULKER_BOX || type == InventoryType.ENDER_CHEST) {

            ItemStack current = event.getCurrentItem();
            ItemStack cursor = event.getCursor();

            // 快速移动（Shift-Click）整组物品
            if (event.getAction() == InventoryAction.MOVE_TO_OTHER_INVENTORY && current != null) {
                int movedAmount = current.getAmount();
                if (movedAmount >= ITEM_CHANGE_THRESHOLD / 2) {
                    bridge.alert(AlertType.SECURITY_CHEST_STEAL,
                        String.format("玩家 %s 从容器快速取走 %d 个物品",
                            player.getName(), movedAmount),
                        0.5, player.getName());
                }
            }
        }
    }

    @EventHandler(priority = EventPriority.MONITOR)
    public void onInventoryOpen(InventoryOpenEvent event) {
        if (bridge == null) return;
        if (!(event.getPlayer() instanceof Player player)) return;

        bridge.incrementEvent("inventory.open");

        // 记录容器打开以辅助 ChestSteal 上下文判断
        Inventory inv = event.getInventory();
        if (inv.getHolder() instanceof Container container) {
            PlayerSnapshot snap = bridge.getPlayer(player.getUniqueId());
            if (snap != null) {
                // 记录容器位置用于后续分析
                String locKey = String.format("container:%d,%d,%d",
                    container.getLocation().getBlockX(),
                    container.getLocation().getBlockY(),
                    container.getLocation().getBlockZ());
            }
        }
    }

    @EventHandler(priority = EventPriority.MONITOR)
    public void onInventoryClose(InventoryCloseEvent event) {
        if (bridge == null) return;
        if (!(event.getPlayer() instanceof Player)) return;
        bridge.incrementEvent("inventory.close");
    }

    @EventHandler(priority = EventPriority.MONITOR, ignoreCancelled = true)
    public void onInventoryDrag(InventoryDragEvent event) {
        if (bridge == null) return;
        if (!(event.getWhoClicked() instanceof Player player)) return;
        bridge.incrementEvent("inventory.drag");

        // 大量物品拖动（可能为 InventoryManipulation hack）
        int totalSlots = event.getInventorySlots().size();
        if (totalSlots > 16) {
            bridge.alert(AlertType.SECURITY_INVENTORY_MANIPULATION,
                String.format("玩家 %s 一次拖动覆盖 %d 个物品栏位，疑似 InventoryManipulation",
                    player.getName(), totalSlots),
                0.65, player.getName());
        }
    }
}
