package com.aluer.plugin;

import com.aluer.plugin.bridge.AgentWebSocketClient;
import com.aluer.plugin.bridge.InternalCommandExecutor;
import org.bukkit.Bukkit;
import org.bukkit.ChatColor;
import org.bukkit.command.Command;
import org.bukkit.command.CommandExecutor;
import org.bukkit.command.CommandSender;
import org.bukkit.command.TabCompleter;
import org.bukkit.entity.Player;

import java.util.*;
import java.util.stream.Collectors;

/**
 * Aluer Agent 命令执行器（精简版）
 *
 * Agent 模式下命令仅作为辅助管理工具，
 * 封禁/踢人等操作仍通过 InternalCommandExecutor 直接执行。
 */
public class AluerCommandExecutor implements CommandExecutor, TabCompleter {

    private final AluerPlugin plugin;
    private final AgentWebSocketClient wsClient;
    private final InternalCommandExecutor executor;

    private static final String P = ChatColor.DARK_GRAY + "[" + ChatColor.GOLD + "Aluer" + ChatColor.DARK_GRAY + "] " + ChatColor.RESET;

    public AluerCommandExecutor(AluerPlugin plugin, AgentWebSocketClient wsClient, InternalCommandExecutor executor) {
        this.plugin = plugin;
        this.wsClient = wsClient;
        this.executor = executor;
    }

    @Override
    public boolean onCommand(CommandSender sender, Command command, String label, String[] args) {
        switch (command.getName().toLowerCase()) {
            case "aluer": return handleAluer(sender, args);
            case "aluerstatus": return handleStatus(sender);
            case "aluerplayers": return handlePlayers(sender);
            case "aluerblock": return handleBlock(sender, args);
            case "aluerunblock": return handleUnblock(sender, args);
            case "aluerscan": return handleScan(sender, args);
            case "aluerwhitelist": return handleWhitelist(sender, args);
            default: return false;
        }
    }

    private boolean handleAluer(CommandSender sender, String[] args) {
        if (args.length == 0) { sendHelp(sender); return true; }
        switch (args[0].toLowerCase()) {
            case "status": return handleStatus(sender);
            case "scan": return handleScan(sender, Arrays.copyOfRange(args, 1, args.length));
            case "info": return handleInfo(sender);
            default: sendHelp(sender); return true;
        }
    }

    private boolean handleStatus(CommandSender sender) {
        sender.sendMessage(P + ChatColor.YELLOW + "═══ Aluer Agent v5.0.0 ═══");
        sender.sendMessage(P + "Server: " + (plugin.isServerConnected() ? ChatColor.GREEN + "已连接" : ChatColor.RED + "未连接"));
        sender.sendMessage(P + "TPS: " + ChatColor.AQUA + String.format("%.1f", getTPS()));
        sender.sendMessage(P + "在线: " + ChatColor.AQUA + Bukkit.getServer().getOnlinePlayers().size());
        return true;
    }

    private boolean handlePlayers(CommandSender sender) {
        sender.sendMessage(P + ChatColor.YELLOW + "在线玩家: " + Bukkit.getServer().getOnlinePlayers().size());
        for (Player p : Bukkit.getServer().getOnlinePlayers()) {
            String ip = p.getAddress() != null && p.getAddress().getAddress() != null
                ? p.getAddress().getAddress().getHostAddress() : "?";
            sender.sendMessage(P + "  " + ChatColor.WHITE + p.getName() +
                ChatColor.GRAY + " | IP: " + ip + " | Ping: " + p.getPing() + "ms");
        }
        return true;
    }

    private boolean handleBlock(CommandSender sender, String[] args) {
        if (args.length < 2) { sender.sendMessage(P + ChatColor.RED + "用法: /aluerblock <player|ip> <目标> [理由]"); return true; }
        String type = args[0].toLowerCase();
        String target = args[1];
        String reason = args.length > 2 ? String.join(" ", Arrays.copyOfRange(args, 2, args.length)) : "管理员手动封禁";

        boolean ok = "ip".equals(type) ? executor.banIP(target, reason) : executor.banPlayer(target, reason);
        sender.sendMessage(P + (ok ? ChatColor.GREEN + "已封禁 " : ChatColor.RED + "封禁失败 ") + type + ": " + target);
        return true;
    }

    private boolean handleUnblock(CommandSender sender, String[] args) {
        if (args.length < 2) { sender.sendMessage(P + ChatColor.RED + "用法: /aluerunblock <player|ip> <目标>"); return true; }
        String type = args[0].toLowerCase();
        String target = args[1];
        boolean ok = "ip".equals(type) ? executor.unbanIP(target) : executor.unbanPlayer(target);
        sender.sendMessage(P + (ok ? ChatColor.GREEN + "已解封 " : ChatColor.RED + "解封失败 ") + type + ": " + target);
        return true;
    }

    private boolean handleScan(CommandSender sender, String[] args) {
        if (args.length < 1) { sender.sendMessage(P + ChatColor.RED + "用法: /aluerscan <玩家名>"); return true; }
        Player target = Bukkit.getServer().getPlayer(args[0]);
        if (target == null) { sender.sendMessage(P + ChatColor.RED + "玩家不在线"); return true; }
        sender.sendMessage(P + ChatColor.YELLOW + "═══ 扫描: " + target.getName() + " ═══");
        sender.sendMessage(P + "位置: " + String.format("(%.1f, %.1f, %.1f)", target.getLocation().getX(), target.getLocation().getY(), target.getLocation().getZ()));
        sender.sendMessage(P + "IP: " + (target.getAddress() != null ? target.getAddress().getAddress().getHostAddress() : "?"));
        sender.sendMessage(P + "Ping: " + target.getPing() + "ms | OP: " + target.isOp());
        sender.sendMessage(P + "飞行: " + target.isFlying() + " | 滑翔: " + target.isGliding());
        return true;
    }

    private boolean handleWhitelist(CommandSender sender, String[] args) {
        if (args.length < 1) { sender.sendMessage(P + ChatColor.RED + "用法: /aluerwhitelist <on|off|status>"); return true; }
        switch (args[0].toLowerCase()) {
            case "on": executor.enableWhitelist(); sender.sendMessage(P + ChatColor.RED + "白名单已启用"); break;
            case "off": executor.disableWhitelist(); sender.sendMessage(P + ChatColor.GREEN + "白名单已关闭"); break;
            case "status": sender.sendMessage(P + "白名单: " + (executor.isWhitelistEnabled() ? ChatColor.RED + "启用" : ChatColor.GREEN + "关闭")); break;
            default: sender.sendMessage(P + ChatColor.RED + "用法: /aluerwhitelist <on|off|status>");
        }
        return true;
    }

    private boolean handleInfo(CommandSender sender) {
        sender.sendMessage(P + ChatColor.GOLD + "Aluer ServerGuard Agent v5.0.0");
        sender.sendMessage(P + ChatColor.GRAY + "轻量数据采集前端 — 连接外部 ServerGuard 引擎");
        sender.sendMessage(P + "Server: " + (plugin.isServerConnected() ? ChatColor.GREEN + "已连接" : ChatColor.RED + "未连接"));
        return true;
    }

    private void sendHelp(CommandSender sender) {
        sender.sendMessage(P + ChatColor.GOLD + "═══ Aluer Agent 命令 ═══");
        sender.sendMessage(ChatColor.YELLOW + "/aluer status" + ChatColor.GRAY + " — 查看Agent状态");
        sender.sendMessage(ChatColor.YELLOW + "/aluer scan <玩家>" + ChatColor.GRAY + " — 玩家信息");
        sender.sendMessage(ChatColor.YELLOW + "/aluer info" + ChatColor.GRAY + " — 系统信息");
        sender.sendMessage(ChatColor.YELLOW + "/aluerplayers" + ChatColor.GRAY + " — 在线玩家列表");
        sender.sendMessage(ChatColor.YELLOW + "/aluerblock <player|ip> <目标>" + ChatColor.GRAY + " — 封禁");
        sender.sendMessage(ChatColor.YELLOW + "/aluerunblock <player|ip> <目标>" + ChatColor.GRAY + " — 解封");
        sender.sendMessage(ChatColor.YELLOW + "/aluerwhitelist <on|off|status>" + ChatColor.GRAY + " — 白名单");
    }

    private double getTPS() {
        try { double[] t = Bukkit.getServer().getTPS(); return t.length > 0 ? t[0] : 20.0; }
        catch (Exception e) { return 20.0; }
    }

    @Override
    public List<String> onTabComplete(CommandSender sender, Command command, String alias, String[] args) {
        String cmd = command.getName().toLowerCase();
        if ("aluer".equals(cmd) && args.length == 1) return filter(Arrays.asList("status", "scan", "info"), args[0]);
        if (("aluerblock".equals(cmd) || "aluerunblock".equals(cmd)) && args.length == 1) return filter(Arrays.asList("player", "ip"), args[0]);
        if ("aluerwhitelist".equals(cmd) && args.length == 1) return filter(Arrays.asList("on", "off", "status"), args[0]);
        if ("aluerscan".equals(cmd) && args.length == 1) return Bukkit.getOnlinePlayers().stream().map(Player::getName).filter(n -> n.toLowerCase().startsWith(args[0].toLowerCase())).collect(Collectors.toList());
        return Collections.emptyList();
    }

    private List<String> filter(List<String> opts, String prefix) {
        return opts.stream().filter(s -> s.toLowerCase().startsWith(prefix.toLowerCase())).collect(Collectors.toList());
    }
}
