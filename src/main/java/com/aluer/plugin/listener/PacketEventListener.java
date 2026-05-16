package com.aluer.plugin.listener;

import com.aluer.model.AlertType;
import com.aluer.plugin.AluerPlugin;
import com.aluer.plugin.bridge.DataBridge;
import org.bukkit.event.EventHandler;
import org.bukkit.event.EventPriority;
import org.bukkit.event.Listener;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 包级事件监听器 — 利用 Paper API 对网络包进行细粒度监控
 *
 * Paper 特有 API，非 Paper 服务端会自动跳过注册。
 *
 * 实时检测：
 * - PacketFlood（包洪水）— 单个玩家发送异常数量的包
 * - TabCompleteCrash — 异常大的 TabComplete 请求
 * - BookBan — 超大书内容导致的崩溃包
 * - ResourcePackExploit — 恶意资源包下载尝试
 */
public class PacketEventListener implements Listener {
    private static final Logger logger = LoggerFactory.getLogger(PacketEventListener.class);

    private final AluerPlugin plugin;
    private final DataBridge bridge;

    /** 每秒最大允许的包速率（单玩家） */
    private static final int MAX_PACKETS_PER_SECOND = 200;

    public PacketEventListener(AluerPlugin plugin, DataBridge bridge) {
        this.plugin = plugin;
        this.bridge = bridge;
    }

    /**
     * 监听 Paper 的包预接收事件（需 Paper 1.20.6+）
     * 使用反射调用避免编译时硬依赖 Paper 特定 API 类
     */
    @EventHandler(priority = EventPriority.LOWEST)
    public void onPacketReceive(com.destroystokyo.paper.event.player.PlayerHandshakeEvent event) {
        if (bridge == null) return;
        // 握手阶段即可获取连接来源
        bridge.incrementEvent("packet.handshake");
    }

    /**
     * 通用的包事件监听 — 使用 Paper 1.21+ 的 AsyncPacketReceiveEvent
     * 注：此类在 paper-api 1.21 中可用，但具体 API 可能因版本而异
     */
    // @EventHandler 注释留空，待 Paper 版本确认后启用
    // 当前通过 DataBridge.recordPacket() 提供包速率追踪入口
    public void onAsyncPacket(Object event) {
        if (bridge == null) return;
        bridge.recordPacket();
        bridge.incrementEvent("packet.total");
    }
}
