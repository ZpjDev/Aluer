package com.aluer.plugin.listener;

import com.aluer.plugin.AluerPlugin;
import com.aluer.plugin.bridge.AgentWebSocketClient;
import com.google.gson.JsonObject;
import org.bukkit.Location;
import org.bukkit.entity.Player;
import org.bukkit.event.EventHandler;
import org.bukkit.event.EventPriority;
import org.bukkit.event.Listener;
import org.bukkit.event.entity.EntityDamageEvent;
import org.bukkit.event.player.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 玩家事件监听器（Agent 端）
 *
 * 采集：登录/退出/移动/传送/摔伤等原始事件，
 * 序列化为 JSON 后通过 WebSocket 推送至外部 ServerGuard 引擎。
 *
 * Agent 端仅做数据采集和即时拦截（聊天/命令等可取消事件），
 * 深度分析（Speed/Fly/Jesus/NoFall 模式识别）由 ServerGuard 端完成。
 */
public class PlayerEventListener implements Listener {
    private static final Logger logger = LoggerFactory.getLogger(PlayerEventListener.class);

    private final AluerPlugin plugin;
    private final AgentWebSocketClient wsClient;

    /** 用于 Agent 端简单阈值拦截（阻塞即时作弊，深度分析仍由 Server 端处理） */
    private static final double MAX_INSTANT_SPEED = 1.2; // blocks/tick，超高值直接拦截

    /** 玩家上次位置记录（用于计算移动距离） */
    private final Map<UUID, Location> lastLocations = new ConcurrentHashMap<>();

    public PlayerEventListener(AluerPlugin plugin, AgentWebSocketClient wsClient) {
        this.plugin = plugin;
        this.wsClient = wsClient;
    }

    @EventHandler(priority = EventPriority.MONITOR)
    public void onPlayerJoin(PlayerJoinEvent event) {
        if (wsClient == null) return;
        Player p = event.getPlayer();
        JsonObject data = new JsonObject();
        data.addProperty("playerName", p.getName());
        data.addProperty("uuid", p.getUniqueId().toString());
        data.addProperty("ip", p.getAddress() != null && p.getAddress().getAddress() != null
            ? p.getAddress().getAddress().getHostAddress() : "unknown");
        data.addProperty("world", p.getWorld().getName());
        data.addProperty("x", p.getLocation().getX());
        data.addProperty("y", p.getLocation().getY());
        data.addProperty("z", p.getLocation().getZ());
        data.addProperty("isOp", p.isOp());
        data.addProperty("ping", p.getPing());
        wsClient.sendEvent("PLAYER_JOIN", data);
    }

    @EventHandler(priority = EventPriority.MONITOR)
    public void onPlayerQuit(PlayerQuitEvent event) {
        if (wsClient == null) return;
        Player p = event.getPlayer();
        lastLocations.remove(p.getUniqueId());
        JsonObject data = new JsonObject();
        data.addProperty("playerName", p.getName());
        data.addProperty("uuid", p.getUniqueId().toString());
        wsClient.sendEvent("PLAYER_QUIT", data);
    }

    @EventHandler(priority = EventPriority.MONITOR, ignoreCancelled = true)
    public void onPlayerMove(PlayerMoveEvent event) {
        if (wsClient == null) return;
        Player p = event.getPlayer();
        Location from = event.getFrom();
        Location to = event.getTo();
        if (to == null || (from.getX() == to.getX() && from.getY() == to.getY() && from.getZ() == to.getZ())) return;

        double dx = to.getX() - from.getX();
        double dz = to.getZ() - from.getZ();
        double dy = to.getY() - from.getY();
        double horizontal = Math.sqrt(dx * dx + dz * dz);

        // —— Agent 端即时拦截：极高速度直接阻止移动 ——
        if (horizontal > MAX_INSTANT_SPEED && p.getGameMode() == org.bukkit.GameMode.SURVIVAL
            && !p.isGliding() && !p.isInsideVehicle()) {
            event.setCancelled(true);
            wsClient.sendAlert("SECURITY_SPEED",
                "即时拦截：玩家 " + p.getName() + " 水平速度 " + String.format("%.3f", horizontal) + " blocks/tick",
                0.95, p.getName());
            return;
        }

        // 推送移动数据到 ServerGuard 做深度分析
        JsonObject data = new JsonObject();
        data.addProperty("playerName", p.getName());
        data.addProperty("uuid", p.getUniqueId().toString());
        data.addProperty("fromX", from.getX()); data.addProperty("fromY", from.getY()); data.addProperty("fromZ", from.getZ());
        data.addProperty("toX", to.getX()); data.addProperty("toY", to.getY()); data.addProperty("toZ", to.getZ());
        data.addProperty("dx", dx); data.addProperty("dy", dy); data.addProperty("dz", dz);
        data.addProperty("horizontal", horizontal);
        data.addProperty("yaw", to.getYaw()); data.addProperty("pitch", to.getPitch());
        data.addProperty("isFlying", p.isFlying());
        data.addProperty("isGliding", p.isGliding());
        data.addProperty("isSprinting", p.isSprinting());
        data.addProperty("isSneaking", p.isSneaking());
        data.addProperty("isInWater", p.isInWater());
        data.addProperty("isOnGround", ((org.bukkit.entity.LivingEntity) p).isOnGround());
        data.addProperty("gameMode", p.getGameMode().name());
        data.addProperty("inVehicle", p.isInsideVehicle());
        wsClient.sendEvent("PLAYER_MOVE", data);

        lastLocations.put(p.getUniqueId(), to.clone());
    }

    @EventHandler(priority = EventPriority.MONITOR)
    public void onPlayerTeleport(PlayerTeleportEvent event) {
        if (wsClient == null || event.getTo() == null) return;
        JsonObject data = new JsonObject();
        data.addProperty("playerName", event.getPlayer().getName());
        data.addProperty("fromX", event.getFrom().getX()); data.addProperty("fromY", event.getFrom().getY()); data.addProperty("fromZ", event.getFrom().getZ());
        data.addProperty("toX", event.getTo().getX()); data.addProperty("toY", event.getTo().getY()); data.addProperty("toZ", event.getTo().getZ());
        data.addProperty("cause", event.getCause().name());
        wsClient.sendEvent("PLAYER_TELEPORT", data);
    }

    @EventHandler(priority = EventPriority.MONITOR, ignoreCancelled = true)
    public void onPlayerDamage(EntityDamageEvent event) {
        if (wsClient == null) return;
        if (!(event.getEntity() instanceof Player p)) return;

        JsonObject data = new JsonObject();
        data.addProperty("playerName", p.getName());
        data.addProperty("cause", event.getCause().name());
        data.addProperty("damage", event.getDamage());
        data.addProperty("fallDistance", p.getFallDistance());

        if (event.getCause() == EntityDamageEvent.DamageCause.FALL) {
            wsClient.sendEvent("PLAYER_DAMAGE", data);

            // Agent 端即时 NoFall 拦截：高坠落低伤害直接标记
            if (p.getFallDistance() > 4.0 && event.getDamage() < 1.0) {
                wsClient.sendAlert("SECURITY_NOFALL",
                    "玩家 " + p.getName() + " 坠落 " + String.format("%.1f", p.getFallDistance()) + " 方块但伤害仅 " + String.format("%.1f", event.getDamage()),
                    0.85, p.getName());
            }
        }
    }
}
