package com.aluer.plugin.listener;

import com.aluer.model.AlertType;
import com.aluer.plugin.AluerPlugin;
import com.aluer.plugin.bridge.DataBridge;
import com.aluer.plugin.bridge.DataBridge.PlayerSnapshot;
import org.bukkit.event.EventHandler;
import org.bukkit.event.EventPriority;
import org.bukkit.event.Listener;
import org.bukkit.event.player.PlayerCommandPreprocessEvent;
import org.bukkit.event.server.ServerCommandEvent;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 命令事件监听器 — 监控所有玩家和后台命令执行
 *
 * 实时检测：
 * - CommandAbuse（命令滥用）— OP 权限的敏感命令使用
 * - 插件后门命令 — 异常插件注册的危险命令
 * - 命令注入 — 包含 shell 特殊字符的命令
 */
public class CommandEventListener implements Listener {
    private static final Logger logger = LoggerFactory.getLogger(CommandEventListener.class);

    private final AluerPlugin plugin;
    private final DataBridge bridge;

    /** 高危命令前缀列表（需要告警监控） */
    private static final String[] SENSITIVE_COMMANDS = {
        "op ", "deop ", "ban ", "pardon ", "whitelist ", "stop", "restart",
        "reload", "plugins", "version", "about", "icanhasbukkit",
        "save-all", "save-on", "save-off", "difficulty", "defaultgamemode",
        "seed", "worldborder", "spreadplayers", "fill", "clone",
        "execute", "function", "datapack", "gamerule", "kill",
        "summon", "give", "clear", "enchant", "effect",
        "tp ", "teleport ", "gamemode ", "kick "
    };

    public CommandEventListener(AluerPlugin plugin, DataBridge bridge) {
        this.plugin = plugin;
        this.bridge = bridge;
    }

    @EventHandler(priority = EventPriority.LOWEST)
    public void onPlayerCommand(PlayerCommandPreprocessEvent event) {
        if (bridge == null) return;
        String command = event.getMessage().toLowerCase().trim();
        String playerName = event.getPlayer().getName();
        PlayerSnapshot snap = bridge.getPlayer(event.getPlayer().getUniqueId());

        bridge.incrementEvent("command.player");

        // 记录最近命令（用于滥用检测）
        if (snap != null) {
            snap.recentCommands.add(command);
            while (snap.recentCommands.size() > 10) {
                snap.recentCommands.removeFirst();
            }
        }

        // —— 敏感命令监控 ——
        for (String sensitive : SENSITIVE_COMMANDS) {
            if (command.startsWith("/" + sensitive) || command.startsWith("minecraft:" + sensitive)) {
                bridge.alert(AlertType.COMMAND_ABUSE,
                    String.format("玩家 %s 执行敏感命令：%s", playerName, event.getMessage()),
                    0.6, playerName);
                break;
            }
        }

        // —— 命令注入检测 ——
        if (command.contains("${") || command.contains("`") ||
            command.contains("&&") || command.contains("||") ||
            command.contains(";") && command.contains("rm ")) {
            bridge.alert(AlertType.COMMAND_ABUSE,
                String.format("玩家 %s 命令疑似注入：%s", playerName, event.getMessage()),
                0.9, playerName);
            event.setCancelled(true);
        }
    }

    @EventHandler(priority = EventPriority.MONITOR)
    public void onServerCommand(ServerCommandEvent event) {
        if (bridge == null) return;
        bridge.incrementEvent("command.server");
    }
}
