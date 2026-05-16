package com.aluer.plugin.listener;

import com.aluer.model.AlertType;
import com.aluer.plugin.AluerPlugin;
import com.aluer.plugin.bridge.DataBridge;
import org.bukkit.entity.Player;
import org.bukkit.event.EventHandler;
import org.bukkit.event.EventPriority;
import org.bukkit.event.Listener;
import org.bukkit.event.entity.*;
import org.bukkit.event.player.PlayerFishEvent;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 实体事件监听器 — 处理实体生成、拾取、交互
 *
 * 实时检测：
 * - AutoFish（自动钓鱼）— 异常快速的钓鱼收杆时机
 * - 实体生成速率异常（可能为故意的服务器压力测试）
 */
public class EntityEventListener implements Listener {
    private static final Logger logger = LoggerFactory.getLogger(EntityEventListener.class);

    private final AluerPlugin plugin;
    private final DataBridge bridge;

    public EntityEventListener(AluerPlugin plugin, DataBridge bridge) {
        this.plugin = plugin;
        this.bridge = bridge;
    }

    @EventHandler(priority = EventPriority.MONITOR, ignoreCancelled = true)
    public void onEntitySpawn(EntitySpawnEvent event) {
        if (bridge == null) return;
        bridge.incrementEvent("entity.spawn");
    }

    @EventHandler(priority = EventPriority.MONITOR)
    public void onPlayerFish(PlayerFishEvent event) {
        if (bridge == null) return;
        Player player = event.getPlayer();

        // —— AutoFish 检测 ——
        // 正常钓鱼需要玩家注意力响应，AutoFish hack 会在鱼咬钩瞬间自动收杆
        if (event.getState() == PlayerFishEvent.State.CAUGHT_FISH
            || event.getState() == PlayerFishEvent.State.CAUGHT_ENTITY) {

            bridge.incrementEvent("fish.caught");

            // 记录钓鱼收杆时间，如果连续快速收杆则标记
            var snap = bridge.getPlayer(player.getUniqueId());
            if (snap != null) {
                long now = System.currentTimeMillis();
                long recentCatches = snap.recentTargets.values().stream()
                    .filter(t -> t > now - 30_000) // 30秒内
                    .count();
                if (recentCatches > 5) { // 30秒内收杆超过5次（正常钓鱼约15-60秒一次）
                    bridge.alert(AlertType.SECURITY_AUTO_FISH,
                        String.format("玩家 %s 30秒内钓鱼收杆 %d 次，疑似 AutoFish",
                            player.getName(), recentCatches),
                        0.7, player.getName());
                }
                // 复用 recentTargets 的 key 为 "fish" 来记录钓鱼时间
                snap.recentTargets.put("fish:" + System.nanoTime(), now);
            }
        }
    }

    @EventHandler(priority = EventPriority.MONITOR, ignoreCancelled = true)
    public void onEntityPickupItem(EntityPickupItemEvent event) {
        if (bridge == null) return;
        if (event.getEntity() instanceof Player) {
            bridge.incrementEvent("entity.pickup");
        }
    }

    @EventHandler(priority = EventPriority.MONITOR)
    public void onEntityExplode(EntityExplodeEvent event) {
        if (bridge == null) return;
        bridge.incrementEvent("entity.explode");
    }
}
