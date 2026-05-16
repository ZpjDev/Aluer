package com.aluer.plugin.listener;

import com.aluer.model.AlertType;
import com.aluer.plugin.AluerPlugin;
import com.aluer.plugin.bridge.DataBridge;
import com.aluer.plugin.bridge.DataBridge.PlayerSnapshot;
import org.bukkit.entity.*;
import org.bukkit.event.EventHandler;
import org.bukkit.event.EventPriority;
import org.bukkit.event.Listener;
import org.bukkit.event.entity.EntityDamageByEntityEvent;
import org.bukkit.event.entity.EntityDeathEvent;
import org.bukkit.event.entity.EntityDamageEvent;
import org.bukkit.util.Vector;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 战斗事件监听器 — 处理玩家攻击、实体伤害、死亡事件
 *
 * 实时检测：
 * - KillAura（杀戮光环）— 多目标快速切换 + 攻击角度一致性
 * - Reach（攻击距离扩展）— 攻击距离超过 3.0 方块
 * - AutoClicker（自动连点）— 异常攻击频率
 * - ChestSteal — 容器交互跟踪由 InventoryEventListener 处理
 */
public class CombatEventListener implements Listener {
    private static final Logger logger = LoggerFactory.getLogger(CombatEventListener.class);

    private final AluerPlugin plugin;
    private final DataBridge bridge;

    /** 正常最大攻击距离（方块） */
    private static final double MAX_ATTACK_DISTANCE = 3.0;

    /** 攻击距离扩展容忍度 */
    private static final double REACH_TOLERANCE = 3.3;

    public CombatEventListener(AluerPlugin plugin, DataBridge bridge) {
        this.plugin = plugin;
        this.bridge = bridge;
    }

    @EventHandler(priority = EventPriority.MONITOR, ignoreCancelled = true)
    public void onEntityDamageByEntity(EntityDamageByEntityEvent event) {
        if (bridge == null) return;

        // 仅处理玩家攻击
        if (!(event.getDamager() instanceof Player attacker)) return;
        Entity victim = event.getEntity();

        PlayerSnapshot attackerSnap = bridge.getPlayer(attacker.getUniqueId());
        if (attackerSnap == null) return;

        // —— 记录攻击目标（KillAura 检测用） ——
        attackerSnap.recordTarget(victim.getName());

        // —— KillAura 检测：多目标快速切换 ——
        int recentTargets = attackerSnap.getRecentTargetCount();
        if (recentTargets > 4) {
            bridge.alert(AlertType.SECURITY_KILL_AURA,
                String.format("玩家 %s 在3秒内攻击了 %d 个不同目标", attacker.getName(), recentTargets),
                Math.min(0.95, recentTargets * 0.2), attacker.getName());
        }

        // —— Reach 检测：攻击距离 ——
        double distance = attacker.getLocation().distance(victim.getLocation());
        attackerSnap.recordAttackDistance(distance);
        if (distance > REACH_TOLERANCE) {
            bridge.alert(AlertType.SECURITY_REACH,
                String.format("玩家 %s 攻击距离异常：%.2f 方块（最大 %.2f）",
                    attacker.getName(), distance, MAX_ATTACK_DISTANCE),
                Math.min(0.95, (distance - MAX_ATTACK_DISTANCE) * 0.5 + 0.5),
                attacker.getName());
        }

        // —— KillAura：攻击角度一致性 ——
        Vector attackerDir = attacker.getLocation().getDirection();
        double angle = Math.atan2(
            victim.getLocation().getZ() - attacker.getLocation().getZ(),
            victim.getLocation().getX() - attacker.getLocation().getX()
        ) * 180.0 / Math.PI;
        attackerSnap.recordAttackAngle(angle);
        if (attackerSnap.hasSuspiciousAngleConsistency()) {
            bridge.alert(AlertType.SECURITY_KILL_AURA,
                String.format("玩家 %s 攻击角度高度一致，疑似 Aimbot", attacker.getName()),
                0.85, attacker.getName());
        }

        // —— AutoClicker 检测：攻击频率异常 ——
        long now = System.currentTimeMillis();
        long recentAttacks = attackerSnap.recentTargets.values().stream()
            .filter(t -> t > now - 1000)
            .count();
        if (recentAttacks > 20) { // 每秒超过20次攻击（正常CPS上限约14）
            bridge.alert(AlertType.SECURITY_AUTO_CLICKER,
                String.format("玩家 %s 攻击频率异常：每秒 %d 次", attacker.getName(), recentAttacks),
                0.8, attacker.getName());
        }
    }

    @EventHandler(priority = EventPriority.MONITOR)
    public void onEntityDeath(EntityDeathEvent event) {
        if (bridge == null) return;
        Entity entity = event.getEntity();
        Player killer = event.getEntity().getKiller();

        if (killer != null && entity instanceof Player victim) {
            bridge.incrementEvent("combat.player_kill");
        }
    }
}
