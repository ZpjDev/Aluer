package com.aluer.plugin.bridge;

import org.bukkit.Bukkit;
import org.bukkit.OfflinePlayer;
import org.bukkit.entity.Player;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.net.InetAddress;
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

    /** 已封禁的 IP 集合（内存缓存，重启后失效，持久化由 BanList API 处理） */
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

    /** 执行命令并返回是否成功（静默模式，不打日志） */
    public boolean executeCommandQuiet(String command) {
        try {
            return Bukkit.getServer().dispatchCommand(
                Bukkit.getServer().getConsoleSender(), command);
        } catch (Exception e) {
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

    /** 封禁玩家名 */
    public boolean banPlayer(String playerName, String reason) {
        if (bannedPlayers.contains(playerName)) {
            return true; // 已封禁
        }
        // 使用 Bukkit BanList API 进行持久化封禁
        OfflinePlayer target = Bukkit.getServer().getOfflinePlayer(playerName);
        if (target != null) {
            Bukkit.getServer().getBanList(org.bukkit.BanList.Type.NAME)
                .addBan(playerName, reason, null, "Aluer ServerGuard");
            bannedPlayers.add(playerName);
            // 如果在线则踢出
            kickPlayer(playerName, reason);
            logger.info("Player {} banned: {}", playerName, reason);
            return true;
        }
        return false;
    }

    /** 解除玩家封禁 */
    public boolean unbanPlayer(String playerName) {
        Bukkit.getServer().getBanList(org.bukkit.BanList.Type.NAME).pardon(playerName);
        bannedPlayers.remove(playerName);
        logger.info("Player {} unbanned", playerName);
        return true;
    }

    /** 封禁 IP */
    public boolean banIP(String ip, String reason) {
        if (bannedIPs.contains(ip)) {
            return true;
        }
        try {
            Bukkit.getServer().getBanList(org.bukkit.BanList.Type.IP)
                .addBan(ip, reason, null, "Aluer ServerGuard");
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
            return true;
        } catch (Exception e) {
            logger.error("Failed to ban IP {}: {}", ip, e.getMessage());
            return false;
        }
    }

    /** 解除 IP 封禁 */
    public boolean unbanIP(String ip) {
        Bukkit.getServer().getBanList(org.bukkit.BanList.Type.IP).pardon(ip);
        bannedIPs.remove(ip);
        logger.info("IP {} unbanned", ip);
        return true;
    }

    /** 将玩家加入白名单 */
    public boolean addToWhitelist(String playerName) {
        OfflinePlayer target = Bukkit.getServer().getOfflinePlayer(playerName);
        if (target != null) {
            target.setWhitelisted(true);
            logger.info("Player {} added to whitelist", playerName);
            return true;
        }
        return false;
    }

    /** 从白名单移除玩家 */
    public boolean removeFromWhitelist(String playerName) {
        OfflinePlayer target = Bukkit.getServer().getOfflinePlayer(playerName);
        if (target != null) {
            target.setWhitelisted(false);
            return true;
        }
        return false;
    }

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

    /** 清理实体（按类型） */
    public int clearEntities(Class<? extends org.bukkit.entity.Entity> entityType) {
        int removed = 0;
        for (org.bukkit.World world : Bukkit.getServer().getWorlds()) {
            for (org.bukkit.entity.Entity entity : world.getEntities()) {
                if (entityType.isInstance(entity) && !(entity instanceof Player)) {
                    entity.remove();
                    removed++;
                }
            }
        }
        return removed;
    }

    /** 设置生物生成速率 */
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

    /** 按 IP 封禁范围（用于隔离攻击源） */
    public boolean quarantineIP(String ip) {
        return banIP(ip, "Aluer Kernel — 安全隔离");
    }

    /** 获取已封禁 IP 列表 */
    public Set<String> getBannedIPs() {
        return Collections.unmodifiableSet(bannedIPs);
    }
}
