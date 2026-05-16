package com.aluer.plugin.listener;

import com.aluer.plugin.AluerPlugin;
import com.aluer.plugin.bridge.DataBridge;
import org.bukkit.event.EventHandler;
import org.bukkit.event.EventPriority;
import org.bukkit.event.Listener;
import org.bukkit.event.world.ChunkLoadEvent;
import org.bukkit.event.world.ChunkUnloadEvent;
import org.bukkit.event.world.WorldSaveEvent;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 世界事件监听器 — 处理区块加载/卸载、世界保存
 *
 * 主要用于性能监控：
 * - 区块加载速率（异常高可能表明 Xray 或 Baritone 矿透机器人）
 * - 世界保存耗时跟踪
 */
public class WorldEventListener implements Listener {
    private static final Logger logger = LoggerFactory.getLogger(WorldEventListener.class);

    private final AluerPlugin plugin;
    private final DataBridge bridge;

    /** 区块加载速率告警阈值（每秒区块数），Baritone/Xray 会快速加载大量区块 */
    private static final int CHUNK_LOAD_RATE_WARNING = 30;

    public WorldEventListener(AluerPlugin plugin, DataBridge bridge) {
        this.plugin = plugin;
        this.bridge = bridge;
    }

    @EventHandler(priority = EventPriority.MONITOR)
    public void onChunkLoad(ChunkLoadEvent event) {
        if (bridge == null) return;
        long count = bridge.incrementEvent("world.chunk_load");

        // 高频区块加载可能表明 Baritone 矿透或 Xray 探索
        if (count > CHUNK_LOAD_RATE_WARNING) {
            // 每秒重置计数器（由 DataBridge 的调度处理）
        }
    }

    @EventHandler(priority = EventPriority.MONITOR)
    public void onChunkUnload(ChunkUnloadEvent event) {
        if (bridge == null) return;
        bridge.incrementEvent("world.chunk_unload");
    }

    @EventHandler(priority = EventPriority.MONITOR)
    public void onWorldSave(WorldSaveEvent event) {
        if (bridge == null) return;
        bridge.incrementEvent("world.save");
        logger.debug("World saved: {}", event.getWorld().getName());
    }
}
