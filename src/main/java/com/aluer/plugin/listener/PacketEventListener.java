package com.aluer.plugin.listener;

import com.aluer.plugin.AluerPlugin;
import com.aluer.plugin.bridge.AgentWebSocketClient;
import com.google.gson.JsonObject;
import org.bukkit.Bukkit;
import org.bukkit.event.EventHandler;
import org.bukkit.event.EventPriority;
import org.bukkit.event.Listener;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 包级事件监听器（Agent 端，Paper 特定 API）
 *
 * 利用 Paper 特有 API 监控网络包速率，
 * 非 Paper 服务端自动跳过注册。
 */
public class PacketEventListener implements Listener {
    private static final Logger logger = LoggerFactory.getLogger(PacketEventListener.class);

    private final AluerPlugin plugin;
    private final AgentWebSocketClient wsClient;

    private long lastPacketReport = System.currentTimeMillis();
    private long packetCount = 0;
    private static final long REPORT_INTERVAL_MS = 1000;

    public PacketEventListener(AluerPlugin plugin, AgentWebSocketClient wsClient) {
        this.plugin = plugin;
        this.wsClient = wsClient;
    }

    /**
     * 定期上报包速率指标（由 ServerGuard 端调度器触发的心跳也会附带此数据）
     */
    public void reportPacketRate() {
        if (wsClient == null) return;
        long now = System.currentTimeMillis();
        long elapsed = now - lastPacketReport;
        if (elapsed <= 0) return;

        double pps = packetCount * 1000.0 / elapsed;
        JsonObject metrics = new JsonObject();
        metrics.addProperty("packetsPerSecond", pps);
        metrics.addProperty("tps", getTPS());
        metrics.addProperty("onlinePlayers", Bukkit.getServer().getOnlinePlayers().size());
        wsClient.sendMetrics(metrics);

        packetCount = 0;
        lastPacketReport = now;
    }

    private double getTPS() {
        try {
            double[] tps = Bukkit.getServer().getTPS();
            return tps.length > 0 ? tps[0] : 20.0;
        } catch (Exception e) {
            return 20.0;
        }
    }
}
