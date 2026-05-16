package com.aluer.plugin;

import com.aluer.plugin.bridge.DataBridge;
import com.aluer.plugin.bridge.InternalCommandExecutor;
import org.bukkit.Bukkit;
import org.bukkit.ChatColor;
import org.bukkit.command.Command;
import org.bukkit.command.CommandExecutor;
import org.bukkit.command.CommandSender;
import org.bukkit.command.TabCompleter;
import org.bukkit.entity.Player;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;
import java.util.stream.Collectors;

/**
 * Aluer 插件命令执行器 — 处理 /aluer /aluerstatus /aluerplayers 等管理命令
 *
 * 命令列表：
 *   /aluer status      — 查看防护系统状态
 *   /aluer scan <玩家>  — 手动触发玩家安全扫描
 *   /aluer defense     — 查看当前防御等级
 *   /aluer info        — 查看系统信息
 *   /aluerplayers      — 查看玩家风险列表
 *   /aluerblock <玩家|ip> <目标> [理由] — 手动封禁
 *   /aluerunblock <玩家|ip> <目标> — 手动解封
 *   /aluerwhitelist <on|off|status> — 白名单管理
 */
public class AluerCommandExecutor implements CommandExecutor, TabCompleter {
    private static final Logger logger = LoggerFactory.getLogger(AluerCommandExecutor.class);

    private final AluerPlugin plugin;
    private final DataBridge dataBridge;

    private static final String PREFIX = ChatColor.DARK_GRAY + "[" + ChatColor.GOLD + "Aluer" + ChatColor.DARK_GRAY + "] " + ChatColor.RESET;

    public AluerCommandExecutor(AluerPlugin plugin, DataBridge dataBridge) {
        this.plugin = plugin;
        this.dataBridge = dataBridge;
    }

    @Override
    public boolean onCommand(CommandSender sender, Command command, String label, String[] args) {
        String cmdName = command.getName().toLowerCase();

        switch (cmdName) {
            case "aluer":
                return handleAluerCommand(sender, args);
            case "aluerstatus":
                return handleStatusCommand(sender);
            case "aluerplayers":
                return handlePlayersCommand(sender);
            case "aluerblock":
                return handleBlockCommand(sender, args);
            case "aluerunblock":
                return handleUnblockCommand(sender, args);
            case "aluerscan":
                return handleScanCommand(sender, args);
            case "aluerwhitelist":
                return handleWhitelistCommand(sender, args);
            default:
                return false;
        }
    }

    private boolean handleAluerCommand(CommandSender sender, String[] args) {
        if (args.length == 0) {
            sendHelp(sender);
            return true;
        }

        switch (args[0].toLowerCase()) {
            case "status":
                return handleStatusCommand(sender);
            case "scan":
                return handleScanCommand(sender, Arrays.copyOfRange(args, 1, args.length));
            case "defense":
                return handleDefenseCommand(sender);
            case "info":
                return handleInfoCommand(sender);
            default:
                sendHelp(sender);
                return true;
        }
    }

    private boolean handleStatusCommand(CommandSender sender) {
        sender.sendMessage(PREFIX + ChatColor.YELLOW + "═══ Aluer ServerGuard v4.0.0 ═══");

        if (dataBridge != null) {
            double tps = dataBridge.getCurrentTps();
            int online = dataBridge.getOnlinePlayerCount();
            ChatColor tpsColor = tps >= 18 ? ChatColor.GREEN : tps >= 15 ? ChatColor.YELLOW : ChatColor.RED;

            sender.sendMessage(PREFIX + "TPS: " + tpsColor + String.format("%.1f", tps) +
                ChatColor.RESET + "  |  在线玩家: " + ChatColor.AQUA + online);
            sender.sendMessage(PREFIX + "Spring 上下文: " +
                (plugin.isSpringReady() ? ChatColor.GREEN + "就绪" : ChatColor.RED + "初始化中"));
            sender.sendMessage(PREFIX + "包速率: " + ChatColor.GRAY +
                String.format("%.0f pps", dataBridge.getPacketsPerSecond()));
            sender.sendMessage(PREFIX + "事件处理: " + ChatColor.GRAY +
                dataBridge.getEventCount("player.join") + " 登录, " +
                dataBridge.getEventCount("chat.message") + " 聊天, " +
                dataBridge.getEventCount("block.break") + " 破坏");
        } else {
            sender.sendMessage(PREFIX + ChatColor.RED + "DataBridge 未就绪，请稍候...");
        }

        return true;
    }

    private boolean handlePlayersCommand(CommandSender sender) {
        if (dataBridge == null) {
            sender.sendMessage(PREFIX + ChatColor.RED + "DataBridge 未就绪");
            return true;
        }

        var players = dataBridge.getAllPlayers();
        sender.sendMessage(PREFIX + ChatColor.YELLOW + "在线玩家: " + players.size());

        for (var snap : players) {
            String riskInfo = "";
            if (snap.getRecentTargetCount() > 3) {
                riskInfo = ChatColor.RED + " [多目标]";
            }
            if (snap.hasSuspiciousAngleConsistency()) {
                riskInfo += ChatColor.DARK_RED + " [瞄准可疑]";
            }
            sender.sendMessage(PREFIX + "  " + ChatColor.WHITE + snap.name +
                ChatColor.GRAY + " | IP: " + snap.ip +
                " | Ping: " + snap.ping + "ms" +
                riskInfo);
        }

        return true;
    }

    private boolean handleBlockCommand(CommandSender sender, String[] args) {
        if (args.length < 2) {
            sender.sendMessage(PREFIX + ChatColor.RED + "用法: /aluerblock <player|ip> <目标> [理由]");
            return true;
        }

        String type = args[0].toLowerCase();
        String target = args[1];
        String reason = args.length > 2 ? String.join(" ", Arrays.copyOfRange(args, 2, args.length))
            : "管理员手动封禁";

        InternalCommandExecutor executor = plugin.getSpringContext() != null
            ? plugin.getSpringContext().getBean(InternalCommandExecutor.class)
            : null;

        if (executor == null) {
            sender.sendMessage(PREFIX + ChatColor.RED + "命令执行器未就绪");
            return true;
        }

        boolean success;
        if ("ip".equals(type)) {
            success = executor.banIP(target, reason);
        } else {
            success = executor.banPlayer(target, reason);
        }

        if (success) {
            sender.sendMessage(PREFIX + ChatColor.GREEN + "已封禁 " + type + ": " + target);
            Bukkit.getServer().broadcast(
                net.kyori.adventure.text.Component.text(
                    ChatColor.RED + "[Aluer] " + sender.getName() + " 封禁了 " + target + ": " + reason));
        } else {
            sender.sendMessage(PREFIX + ChatColor.RED + "封禁失败: " + target);
        }

        return true;
    }

    private boolean handleUnblockCommand(CommandSender sender, String[] args) {
        if (args.length < 2) {
            sender.sendMessage(PREFIX + ChatColor.RED + "用法: /aluerunblock <player|ip> <目标>");
            return true;
        }

        String type = args[0].toLowerCase();
        String target = args[1];

        InternalCommandExecutor executor = plugin.getSpringContext() != null
            ? plugin.getSpringContext().getBean(InternalCommandExecutor.class)
            : null;

        if (executor == null) {
            sender.sendMessage(PREFIX + ChatColor.RED + "命令执行器未就绪");
            return true;
        }

        boolean success;
        if ("ip".equals(type)) {
            success = executor.unbanIP(target);
        } else {
            success = executor.unbanPlayer(target);
        }

        if (success) {
            sender.sendMessage(PREFIX + ChatColor.GREEN + "已解封 " + type + ": " + target);
        } else {
            sender.sendMessage(PREFIX + ChatColor.RED + "解封失败: " + target);
        }

        return true;
    }

    private boolean handleScanCommand(CommandSender sender, String[] args) {
        if (args.length < 1) {
            sender.sendMessage(PREFIX + ChatColor.RED + "用法: /aluerscan <玩家名>");
            return true;
        }

        String targetName = args[0];
        Player target = Bukkit.getServer().getPlayer(targetName);

        if (target == null) {
            sender.sendMessage(PREFIX + ChatColor.RED + "玩家不在线: " + targetName);
            return true;
        }

        if (dataBridge == null) {
            sender.sendMessage(PREFIX + ChatColor.RED + "DataBridge 未就绪");
            return true;
        }

        var snap = dataBridge.getPlayer(target.getUniqueId());
        if (snap == null) {
            sender.sendMessage(PREFIX + ChatColor.RED + "未找到玩家数据");
            return true;
        }

        sender.sendMessage(PREFIX + ChatColor.YELLOW + "═══ 安全扫描: " + targetName + " ═══");
        sender.sendMessage(PREFIX + "位置: " + String.format("(%.1f, %.1f, %.1f) [%s]", snap.x, snap.y, snap.z, snap.world));
        sender.sendMessage(PREFIX + "IP: " + snap.ip + " | Ping: " + snap.ping + "ms");
        sender.sendMessage(PREFIX + "飞行: " + snap.isFlying + " | 冲刺: " + snap.isSprinting + " | 潜行: " + snap.isSneaking);
        sender.sendMessage(PREFIX + "最近攻击目标: " + snap.getRecentTargetCount() + " 个");
        sender.sendMessage(PREFIX + "攻击角度一致性: " + (snap.hasSuspiciousAngleConsistency() ? ChatColor.RED + "可疑" : ChatColor.GREEN + "正常"));
        sender.sendMessage(PREFIX + "最近消息: " + snap.recentMessages.size() + " 条");
        sender.sendMessage(PREFIX + "最近命令: " + snap.recentCommands.size() + " 条");
        sender.sendMessage(PREFIX + "在线时长: " + (snap.getOnlineTime() / 60000) + " 分钟");

        return true;
    }

    private boolean handleDefenseCommand(CommandSender sender) {
        sender.sendMessage(PREFIX + ChatColor.YELLOW + "═══ 防御状态 ═══");
        sender.sendMessage(PREFIX + "模式: " + ChatColor.AQUA + "Paper Plugin（嵌入式）");

        if (dataBridge != null) {
            double[] tps = dataBridge.getTpsArray();
            sender.sendMessage(PREFIX + "TPS: " + String.format("1m=%.1f  5m=%.1f  15m=%.1f", tps[0], tps[1], tps[2]));
            sender.sendMessage(PREFIX + "在线: " + dataBridge.getOnlinePlayerCount() + " | 包速率: " +
                String.format("%.0f pps", dataBridge.getPacketsPerSecond()));
        }
        return true;
    }

    private boolean handleInfoCommand(CommandSender sender) {
        sender.sendMessage(PREFIX + ChatColor.GOLD + "Aluer ServerGuard v4.0.0");
        sender.sendMessage(PREFIX + ChatColor.GRAY + "AI-powered Minecraft PaperMC Server Protection");
        sender.sendMessage(PREFIX + "Author: Aluer | Java 17 | Spring Boot 3.2.0");
        sender.sendMessage(PREFIX + "29 反作弊模块 | DDoS 防御 | WAF | Kernel 引擎");
        sender.sendMessage(PREFIX + "模式: " + (plugin.isSpringReady() ? "完全运作" : "初始化中"));
        return true;
    }

    private boolean handleWhitelistCommand(CommandSender sender, String[] args) {
        if (args.length < 1) {
            sender.sendMessage(PREFIX + ChatColor.RED + "用法: /aluerwhitelist <on|off|status>");
            return true;
        }

        InternalCommandExecutor executor = plugin.getSpringContext() != null
            ? plugin.getSpringContext().getBean(InternalCommandExecutor.class)
            : null;

        switch (args[0].toLowerCase()) {
            case "on":
                if (executor != null) {
                    executor.enableWhitelist();
                    sender.sendMessage(PREFIX + ChatColor.RED + "紧急白名单模式已启用！");
                }
                break;
            case "off":
                if (executor != null) {
                    executor.disableWhitelist();
                    sender.sendMessage(PREFIX + ChatColor.GREEN + "白名单模式已关闭");
                }
                break;
            case "status":
                boolean enabled = executor != null && executor.isWhitelistEnabled();
                sender.sendMessage(PREFIX + "白名单: " + (enabled ? ChatColor.RED + "启用中" : ChatColor.GREEN + "关闭"));
                break;
            default:
                sender.sendMessage(PREFIX + ChatColor.RED + "用法: /aluerwhitelist <on|off|status>");
        }
        return true;
    }

    private void sendHelp(CommandSender sender) {
        sender.sendMessage(PREFIX + ChatColor.GOLD + "═══ Aluer ServerGuard 命令 ═══");
        sender.sendMessage(ChatColor.YELLOW + "/aluer status" + ChatColor.GRAY + " — 查看防护状态");
        sender.sendMessage(ChatColor.YELLOW + "/aluer scan <玩家>" + ChatColor.GRAY + " — 安全扫描玩家");
        sender.sendMessage(ChatColor.YELLOW + "/aluer defense" + ChatColor.GRAY + " — 查看防御等级");
        sender.sendMessage(ChatColor.YELLOW + "/aluer info" + ChatColor.GRAY + " — 系统信息");
        sender.sendMessage(ChatColor.YELLOW + "/aluerplayers" + ChatColor.GRAY + " — 玩家风险列表");
        sender.sendMessage(ChatColor.YELLOW + "/aluerblock <player|ip> <目标>" + ChatColor.GRAY + " — 手动封禁");
        sender.sendMessage(ChatColor.YELLOW + "/aluerunblock <player|ip> <目标>" + ChatColor.GRAY + " — 手动解封");
        sender.sendMessage(ChatColor.YELLOW + "/aluerwhitelist <on|off|status>" + ChatColor.GRAY + " — 白名单管理");
    }

    // ─── 命令补全 ──────────────────────────────────────

    @Override
    public List<String> onTabComplete(CommandSender sender, Command command, String alias, String[] args) {
        String cmdName = command.getName().toLowerCase();

        switch (cmdName) {
            case "aluer":
                if (args.length == 1) {
                    return filterStartsWith(Arrays.asList("status", "scan", "defense", "info"), args[0]);
                }
                if (args.length == 2 && "scan".equalsIgnoreCase(args[0])) {
                    return filterStartsWith(
                        Bukkit.getServer().getOnlinePlayers().stream()
                            .map(Player::getName)
                            .collect(Collectors.toList()),
                        args[1]);
                }
                break;
            case "aluerblock":
                if (args.length == 1) {
                    return filterStartsWith(Arrays.asList("player", "ip"), args[0]);
                }
                if (args.length == 2 && "player".equalsIgnoreCase(args[0])) {
                    return filterStartsWith(
                        Bukkit.getServer().getOnlinePlayers().stream()
                            .map(Player::getName)
                            .collect(Collectors.toList()),
                        args[1]);
                }
                break;
            case "aluerunblock":
                if (args.length == 1) {
                    return filterStartsWith(Arrays.asList("player", "ip"), args[0]);
                }
                break;
            case "aluerwhitelist":
                if (args.length == 1) {
                    return filterStartsWith(Arrays.asList("on", "off", "status"), args[0]);
                }
                break;
            case "aluerscan":
                if (args.length == 1) {
                    return filterStartsWith(
                        Bukkit.getServer().getOnlinePlayers().stream()
                            .map(Player::getName)
                            .collect(Collectors.toList()),
                        args[0]);
                }
                break;
        }

        return Collections.emptyList();
    }

    private List<String> filterStartsWith(List<String> options, String prefix) {
        String lower = prefix.toLowerCase();
        return options.stream()
            .filter(s -> s.toLowerCase().startsWith(lower))
            .collect(Collectors.toList());
    }
}
