package com.aluer.plugin.bridge;

import org.bukkit.Bukkit;
import org.bukkit.entity.Player;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 内部命令执行器 — 替代 RCON 协议，直接通过 Bukkit API 执行服务器命令
 *
 * 插件模式下不再需要通过 TCP RCON 连接本地服务器，
 * 直接调用 Bukkit.getServer().dispatchCommand() 即可。
 *
 * 同时封装常见的运维操作：封禁/解封 IP、踢人、白名单管理等。
 */
@Service
public class InternalCommandExecutor {
    private static final Logger logger = LoggerFactory.getLogger(InternalCommandExecutor.class);

    /** 已封禁的 IP 集合（内存缓存，重启后失效，持久化由 Bukkit BanList API 处理） */
    private final Set<String> bannedIPs = ConcurrentHashMap.newKeySet();

    /** 已封禁的玩家名集合 */
    private final Set<String> bannedPlayers = ConcurrentHashMap.newKeySet();

    // ─── 命令执行 ──────────────────────────────────────

    /** 以控制台身份执行任意 Minecraft 命令 */
    public boolean executeCommand(String command) {
        try {
            return Bukkit.getServer().dispatchCommand(
                Bukkit.getServer().getConsoleSender(), command);
        } catch (Exception e) {
            logger.error("Command execution failed: {} — {}", command, e.getMessage());
            return false;
        }
    }

    // ─── 玩家管理 ──────────────────────────────────────

    /** 踢出玩家 */
    public boolean kickPlayer(String playerName, String reason) {
        Player player = Bukkit.getServer().getPlayer(playerName);
        if (player == null) {
            logger.warn("Cannot kick {}: player not online", playerName);
            return false;
        }
        player.kick(net.kyori.adventure.text.Component.text(reason));
        logger.info("Player {} kicked: {}", playerName, reason);
        return true;
    }

    /** 封禁玩家名（通过 /ban 命令持久化封禁） */
    public boolean banPlayer(String playerName, String reason) {
        if (bannedPlayers.contains(playerName)) {
            return true;
        }
        // 使用 dispatchCommand 兼容所有 Paper 版本，避免 BanList API 弃用问题
        boolean ok = executeCommand("ban " + playerName + " " + reason);
        if (ok) {
            bannedPlayers.add(playerName);
            logger.info("Player {} banned: {}", playerName, reason);
        }
        return ok;
    }

    /** 解除玩家封禁 */
    public boolean unbanPlayer(String playerName) {
        boolean ok = executeCommand("pardon " + playerName);
        if (ok) {
            bannedPlayers.remove(playerName);
            logger.info("Player {} unbanned", playerName);
        }
        return ok;
    }

    /** 封禁 IP（通过 /ban-ip 命令持久化封禁） */
    public boolean banIP(String ip, String reason) {
        if (bannedIPs.contains(ip)) {
            return true;
        }
        boolean ok = executeCommand("ban-ip " + ip + " " + reason);
        if (ok) {
            bannedIPs.add(ip);
            // 踢出该 IP 的所有在线玩家
            for (Player player : Bukkit.getServer().getOnlinePlayers()) {
                String playerIP = player.getAddress() != null && player.getAddress().getAddress() != null
                    ? player.getAddress().getAddress().getHostAddress()
                    : "";
                if (ip.equals(playerIP)) {
                    player.kick(net.kyori.adventure.text.Component.text(reason));
                }
            }
            logger.info("IP {} banned: {}", ip, reason);
        }
        return ok;
    }

    /** 解除 IP 封禁 */
    public boolean unbanIP(String ip) {
        boolean ok = executeCommand("pardon-ip " + ip);
        if (ok) {
            bannedIPs.remove(ip);
            logger.info("IP {} unbanned", ip);
        }
        return ok;
    }

    // ─── 白名单管理 ──────────────────────────────────

    /** 启用白名单模式 */
    public boolean enableWhitelist() {
        Bukkit.getServer().setWhitelist(true);
        logger.warn("WHITELIST ENABLED — only whitelisted players can join");
        return true;
    }

    /** 禁用白名单模式 */
    public boolean disableWhitelist() {
        Bukkit.getServer().setWhitelist(false);
        logger.info("Whitelist disabled");
        return true;
    }

    /** 查询白名单状态 */
    public boolean isWhitelistEnabled() {
        return Bukkit.getServer().hasWhitelist();
    }

    // ─── 服务器管理 ─────────────────────────────────────

    /** 保存所有世界 */
    public boolean saveAllWorlds() {
        executeCommand("save-all");
        return true;
    }

    /** 广播消息给全服玩家 */
    public void broadcast(String message) {
        Bukkit.getServer().broadcast(
            net.kyori.adventure.text.Component.text(message));
    }

    /** 清理掉落物 */
    public int clearDroppedItems() {
        int removed = 0;
        for (org.bukkit.World world : Bukkit.getServer().getWorlds()) {
            for (org.bukkit.entity.Entity entity : world.getEntities()) {
                if (entity instanceof org.bukkit.entity.Item) {
                    entity.remove();
                    removed++;
                }
            }
        }
        if (removed > 0) {
            logger.info("Cleared {} dropped items across all worlds", removed);
        }
        return removed;
    }

    /** 设置生物生成速率 */
    @SuppressWarnings("deprecation")
    public boolean setSpawnRate(int rate) {
        for (org.bukkit.World world : Bukkit.getServer().getWorlds()) {
            world.setMonsterSpawnLimit(rate);
            world.setAnimalSpawnLimit(rate);
        }
        return true;
    }

    /** 获取服务器在线玩家对象列表 */
    public Collection<? extends Player> getOnlinePlayers() {
        return Bukkit.getServer().getOnlinePlayers();
    }

    /** 获取已封禁 IP 列表 */
    public Set<String> getBannedIPs() {
        return Collections.unmodifiableSet(bannedIPs);
    }
}
