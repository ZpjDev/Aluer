package com.aluer.plugin.listener;

import com.aluer.model.AlertType;
import com.aluer.plugin.AluerPlugin;
import com.aluer.plugin.bridge.DataBridge;
import com.aluer.plugin.bridge.DataBridge.PlayerSnapshot;
import org.bukkit.Location;
import org.bukkit.entity.Player;
import org.bukkit.event.EventHandler;
import org.bukkit.event.EventPriority;
import org.bukkit.event.Listener;
import org.bukkit.event.entity.EntityDamageEvent;
import org.bukkit.event.player.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 玩家事件监听器 — 处理登录、退出、移动、传送、死亡等核心玩家事件
 *
 * 实时检测：
 * - Speed（移动速度异常）— 水平速度超过 0.65 blocks/tick 则标记
 * - Fly（非法飞行）— 非创造/旁观模式下，垂直位移模式异常
 * - Jesus（水行）— 连续在水中但 y 坐标不下降
 * - NoFall（无摔伤）— 从高处落地无伤害
 */
public class PlayerEventListener implements Listener {
    private static final Logger logger = LoggerFactory.getLogger(PlayerEventListener.class);

    private final AluerPlugin plugin;
    private final DataBridge bridge;

    /** 最大允许水平速度（blocks/tick），超过此值视为 Speed Hack */
    private static final double MAX_HORIZONTAL_SPEED = 0.65;

    /** 可疑移动的告警置信度阈值 */
    private static final double SUSPICIOUS_CONFIDENCE = 0.75;

    public PlayerEventListener(AluerPlugin plugin, DataBridge bridge) {
        this.plugin = plugin;
        this.bridge = bridge;
    }

    // ─── 登录/退出 ──────────────────────────────────────

    @EventHandler(priority = EventPriority.MONITOR)
    public void onPlayerJoin(PlayerJoinEvent event) {
        if (bridge == null) return;
        Player player = event.getPlayer();
        bridge.registerPlayer(player);
        bridge.incrementEvent("player.join");

        // 检查同 IP 多账号
        String ip = player.getAddress() != null && player.getAddress().getAddress() != null
            ? player.getAddress().getAddress().getHostAddress()
            : "unknown";
        var sameIP = bridge.getPlayersByIP(ip);
        if (sameIP.size() > 2) {
            bridge.alert(AlertType.SECURITY_ALT_ACCOUNT,
                String.format("玩家 %s 使用IP %s 登录，该IP已有 %d 个在线账号",
                    player.getName(), ip, sameIP.size()),
                0.7, player.getName());
        }
    }

    @EventHandler(priority = EventPriority.MONITOR)
    public void onPlayerQuit(PlayerQuitEvent event) {
        if (bridge == null) return;
        bridge.removePlayer(event.getPlayer().getUniqueId());
        bridge.incrementEvent("player.quit");
    }

    @EventHandler(priority = EventPriority.MONITOR)
    public void onPlayerKick(PlayerKickEvent event) {
        if (bridge == null) return;
        bridge.removePlayer(event.getPlayer().getUniqueId());
        bridge.incrementEvent("player.kick");
    }

    // ─── 移动检测 ──────────────────────────────────────

    @EventHandler(priority = EventPriority.MONITOR, ignoreCancelled = true)
    public void onPlayerMove(PlayerMoveEvent event) {
        if (bridge == null) return;
        Player player = event.getPlayer();
        PlayerSnapshot snap = bridge.getPlayer(player.getUniqueId());
        if (snap == null) return;

        Location from = event.getFrom();
        Location to = event.getTo();
        if (to == null) return;

        // 仅在位置实际改变时更新
        if (from.getX() == to.getX() && from.getY() == to.getY() && from.getZ() == to.getZ()) return;

        // 更新快照位置
        snap.updatePosition(to.getX(), to.getY(), to.getZ(), to.getYaw(), to.getPitch());

        // 计算水平移动距离
        double dx = to.getX() - from.getX();
        double dz = to.getZ() - from.getZ();
        double horizontalDist = Math.sqrt(dx * dx + dz * dz);
        double dy = to.getY() - from.getY();

        snap.totalDistanceMoved += horizontalDist;

        // —— Speed 检测 ——
        // 排除创造/旁观模式、鞘翅飞行、骑乘状态
        if (player.getGameMode() == org.bukkit.GameMode.SURVIVAL
            && !player.isGliding()
            && !player.isInsideVehicle()
            && !player.isFlying()) {

            if (horizontalDist > MAX_HORIZONTAL_SPEED) {
                bridge.alert(AlertType.SECURITY_SPEED,
                    String.format("玩家 %s 移动速度异常：水平 %.3f blocks/tick（阈值 %.2f）",
                        player.getName(), horizontalDist, MAX_HORIZONTAL_SPEED),
                    Math.min(0.95, horizontalDist / MAX_HORIZONTAL_SPEED * 0.6),
                    player.getName());
            }
        }

        // —— Fly 检测 ——
        // 非飞行玩家在空中时持续 y 坐标下降过慢
        if (player.getGameMode() == org.bukkit.GameMode.SURVIVAL
            && !player.isFlying()
            && !player.isGliding()
            && !player.isInWater()
            && !player.isInsideVehicle()) {

            // 如果玩家在空中（脚下无方块）且 y 不下降反而上升
            boolean onGround = ((org.bukkit.entity.LivingEntity) player).isOnGround();
            if (!onGround && dy > 0.05 && horizontalDist < 0.1) {
                bridge.alert(AlertType.SECURITY_FLY,
                    String.format("玩家 %s 疑似飞行：空中上升 dy=%.3f", player.getName(), dy),
                    SUSPICIOUS_CONFIDENCE, player.getName());
            }
        }

        // —— Jesus（水行）检测 ——
        if (player.isInWater() && player.getGameMode() == org.bukkit.GameMode.SURVIVAL
            && !player.isFlying() && !player.isSwimming()) {
            // 在水中但 y 坐标超过水面特征线
            if (dy > -0.01 && horizontalDist > 0.3) {
                bridge.alert(AlertType.SECURITY_JESUS,
                    String.format("玩家 %s 疑似水行：水中水平移动 %.3f blocks", player.getName(), horizontalDist),
                    0.65, player.getName());
            }
        }
    }

    // ─── 传送跟踪 ──────────────────────────────────────

    @EventHandler(priority = EventPriority.MONITOR)
    public void onPlayerTeleport(PlayerTeleportEvent event) {
        if (bridge == null) return;
        PlayerSnapshot snap = bridge.getPlayer(event.getPlayer().getUniqueId());
        if (snap != null && event.getTo() != null) {
            snap.updatePosition(event.getTo().getX(), event.getTo().getY(), event.getTo().getZ(),
                event.getTo().getYaw(), event.getTo().getPitch());
        }
    }

    // ─── 摔伤检测（NoFall） ─────────────────────────────

    @EventHandler(priority = EventPriority.MONITOR, ignoreCancelled = true)
    public void onPlayerDamage(EntityDamageEvent event) {
        if (bridge == null) return;
        if (!(event.getEntity() instanceof Player player)) return;
        if (event.getCause() != EntityDamageEvent.DamageCause.FALL) return;

        PlayerSnapshot snap = bridge.getPlayer(player.getUniqueId());
        if (snap == null) return;

        double fallDistance = player.getFallDistance();
        // 正常情况：掉落 > 3 方块高度应有伤害
        // NoFall hack 会让服务端认为掉落距离为 0
        if (fallDistance > 3.5 && event.getDamage() < 1.0) {
            bridge.alert(AlertType.SECURITY_NOFALL,
                String.format("玩家 %s 疑似 NoFall：掉落 %.1f 方块但伤害仅 %.1f",
                    player.getName(), fallDistance, event.getDamage()),
                0.8, player.getName());
        }
    }
}
