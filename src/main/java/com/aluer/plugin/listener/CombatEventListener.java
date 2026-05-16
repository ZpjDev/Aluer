package com.aluer.plugin.listener;

import com.aluer.plugin.AluerPlugin;
import com.aluer.plugin.bridge.AgentWebSocketClient;
import com.google.gson.JsonObject;
import org.bukkit.entity.Entity;
import org.bukkit.entity.LivingEntity;
import org.bukkit.entity.Player;
import org.bukkit.event.EventHandler;
import org.bukkit.event.EventPriority;
import org.bukkit.event.Listener;
import org.bukkit.event.entity.EntityDamageByEntityEvent;
import org.bukkit.event.entity.EntityDeathEvent;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 战斗事件监听器（Agent 端）
 *
 * 采集每次 PvP 攻击的原始数据（双方、距离、角度、伤害值、时间戳），
 * 推送至 ServerGuard 做 KillAura/Reach/AutoClicker 模式识别。
 */
public class CombatEventListener implements Listener {
    private static final Logger logger = LoggerFactory.getLogger(CombatEventListener.class);

    private final AluerPlugin plugin;
    private final AgentWebSocketClient wsClient;

    /** Agent 端即时拦截：攻击距离超过此值直接取消（防止极端 Reach hack） */
    private static final double INSTANT_BLOCK_DISTANCE = 5.0;

    /** 记录每个玩家的攻击时间戳（用于 Agent 端简单 CPS 估算） */
    private final Map<UUID, Long> lastAttackTime = new ConcurrentHashMap<>();

    public CombatEventListener(AluerPlugin plugin, AgentWebSocketClient wsClient) {
        this.plugin = plugin;
        this.wsClient = wsClient;
    }

    @EventHandler(priority = EventPriority.MONITOR, ignoreCancelled = true)
    public void onEntityDamageByEntity(EntityDamageByEntityEvent event) {
        if (wsClient == null) return;
        if (!(event.getDamager() instanceof Player attacker)) return;
        Entity victim = event.getEntity();

        double distance = attacker.getLocation().distance(victim.getLocation());
        double attackerAngle = Math.toDegrees(Math.atan2(
            victim.getLocation().getZ() - attacker.getLocation().getZ(),
            victim.getLocation().getX() - attacker.getLocation().getX()
        ));

        // —— Agent 端即时拦截：极端距离直接取消攻击 ——
        if (distance > INSTANT_BLOCK_DISTANCE) {
            event.setCancelled(true);
            wsClient.sendAlert("SECURITY_REACH",
                "即时拦截：玩家 " + attacker.getName() + " 攻击距离 " + String.format("%.2f", distance) + " 方块",
                0.95, attacker.getName());
            return;
        }

        // 计算 CPS（Agent 端简单估算）
        long now = System.currentTimeMillis();
        Long lastTime = lastAttackTime.get(attacker.getUniqueId());
        double estimatedCPS = 0;
        if (lastTime != null && lastTime > 0) {
            long interval = now - lastTime;
            if (interval > 0) estimatedCPS = 1000.0 / interval;
        }
        lastAttackTime.put(attacker.getUniqueId(), now);

        // 推送攻击数据到 ServerGuard
        JsonObject data = new JsonObject();
        data.addProperty("attackerName", attacker.getName());
        data.addProperty("attackerUUID", attacker.getUniqueId().toString());
        data.addProperty("victimName", victim.getName());
        data.addProperty("victimType", victim.getType().name());
        data.addProperty("victimUUID", victim instanceof Player vp ? vp.getUniqueId().toString() : "");
        data.addProperty("distance", distance);
        data.addProperty("angle", attackerAngle);
        data.addProperty("damage", event.getDamage());
        data.addProperty("estimatedCPS", estimatedCPS);
        wsClient.sendEvent("COMBAT_ATTACK", data);

        // Agent 端即时告警（高置信度快速标记，最终决策由 Server 端确认）
        if (estimatedCPS > 25) {
            wsClient.sendAlert("SECURITY_AUTO_CLICKER",
                "Agent 检测：玩家 " + attacker.getName() + " CPS ≈ " + String.format("%.0f", estimatedCPS),
                0.75, attacker.getName());
        }
    }

    @EventHandler(priority = EventPriority.MONITOR)
    public void onEntityDeath(EntityDeathEvent event) {
        if (wsClient == null) return;
        Player killer = event.getEntity().getKiller();
        if (killer == null) return;

        JsonObject data = new JsonObject();
        data.addProperty("killerName", killer.getName());
        data.addProperty("victimName", event.getEntity().getName());
        data.addProperty("victimType", event.getEntity().getType().name());
        wsClient.sendEvent("COMBAT_DEATH", data);
    }
}
