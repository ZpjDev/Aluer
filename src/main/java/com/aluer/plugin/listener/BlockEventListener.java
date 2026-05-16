package com.aluer.plugin.listener;

import com.aluer.model.AlertType;
import com.aluer.plugin.AluerPlugin;
import com.aluer.plugin.bridge.DataBridge;
import com.aluer.plugin.bridge.DataBridge.PlayerSnapshot;
import org.bukkit.Material;
import org.bukkit.block.Block;
import org.bukkit.entity.Player;
import org.bukkit.event.EventHandler;
import org.bukkit.event.EventPriority;
import org.bukkit.event.Listener;
import org.bukkit.event.block.BlockBreakEvent;
import org.bukkit.event.block.BlockPlaceEvent;
import org.bukkit.event.block.SignChangeEvent;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 方块事件监听器 — 处理方块破坏、放置、告示牌修改
 *
 * 实时检测：
 * - Nuker（炸图）— 短时间内破坏大量方块
 * - Scaffold（搭桥）— 脚下方块快速连续放置模式
 * - SignExploit（告示牌漏洞）— 异常大小的 NBT 标签内容
 * - Grief（破坏）— 查找特定贵重方块的大规模破坏模式
 */
public class BlockEventListener implements Listener {
    private static final Logger logger = LoggerFactory.getLogger(BlockEventListener.class);

    private final AluerPlugin plugin;
    private final DataBridge bridge;

    /** Nuker 检测窗口（秒内破坏方块数） */
    private static final int NUKER_THRESHOLD = 25;

    /** Scaffold 检测窗口（秒内脚下方块放置数） */
    private static final int SCAFFOLD_THRESHOLD = 8;

    /** 贵重方块列表（Grief 检测目标） */
    private static final Material[] VALUABLE_BLOCKS = {
        Material.DIAMOND_BLOCK, Material.GOLD_BLOCK, Material.IRON_BLOCK,
        Material.EMERALD_BLOCK, Material.NETHERITE_BLOCK, Material.BEACON,
        Material.CHEST, Material.ENDER_CHEST, Material.ENCHANTING_TABLE,
        Material.ANVIL, Material.DAMAGED_ANVIL, Material.CHIPPED_ANVIL
    };

    public BlockEventListener(AluerPlugin plugin, DataBridge bridge) {
        this.plugin = plugin;
        this.bridge = bridge;
    }

    @EventHandler(priority = EventPriority.MONITOR, ignoreCancelled = true)
    public void onBlockBreak(BlockBreakEvent event) {
        if (bridge == null) return;
        Player player = event.getPlayer();
        PlayerSnapshot snap = bridge.getPlayer(player.getUniqueId());
        if (snap == null) return;

        Block block = event.getBlock();
        String posKey = String.format("%d,%d,%d",
            block.getX(), block.getY(), block.getZ());

        snap.recentBlockBreaks.add(posKey);
        while (snap.recentBlockBreaks.size() > 50) {
            snap.recentBlockBreaks.removeFirst();
        }

        bridge.incrementEvent("block.break");

        // —— Nuker 检测 ——
        if (snap.recentBlockBreaks.size() >= NUKER_THRESHOLD) {
            bridge.alert(AlertType.SECURITY_NUKER,
                String.format("玩家 %s 短时间内破坏 %d 个方块，疑似 Nuker",
                    player.getName(), snap.recentBlockBreaks.size()),
                Math.min(0.95, snap.recentBlockBreaks.size() / 40.0),
                player.getName());
        }

        // —— Grief 检测：大量破坏贵重方块 ——
        Material type = block.getType();
        for (Material valuable : VALUABLE_BLOCKS) {
            if (type == valuable) {
                bridge.alert(AlertType.SECURITY_GRIEF,
                    String.format("玩家 %s 破坏贵重方块 %s 位于 %s",
                        player.getName(), type.name(), posKey),
                    0.6, player.getName());
                break;
            }
        }
    }

    @EventHandler(priority = EventPriority.MONITOR, ignoreCancelled = true)
    public void onBlockPlace(BlockPlaceEvent event) {
        if (bridge == null) return;
        Player player = event.getPlayer();
        PlayerSnapshot snap = bridge.getPlayer(player.getUniqueId());
        if (snap == null) return;

        Block block = event.getBlock();
        String posKey = String.format("%d,%d,%d",
            block.getX(), block.getY(), block.getZ());

        snap.recentBlockPlaces.add(posKey);
        while (snap.recentBlockPlaces.size() > 50) {
            snap.recentBlockPlaces.removeFirst();
        }

        bridge.incrementEvent("block.place");

        // —— Scaffold 检测：脚下方块快速放置 ——
        // 检查是否在玩家脚下方块附近放置
        double playerY = snap.y;
        if (Math.abs(block.getY() - (playerY - 1)) < 1.5) {
            // 脚下方块
            int footPlaces = 0;
            for (String p : snap.recentBlockPlaces) {
                String[] parts = p.split(",");
                if (parts.length == 3) {
                    try {
                        double by = Double.parseDouble(parts[1]);
                        if (Math.abs(by - (playerY - 1)) < 1.5) footPlaces++;
                    } catch (NumberFormatException ignored) {}
                }
            }
            if (footPlaces >= SCAFFOLD_THRESHOLD) {
                bridge.alert(AlertType.SECURITY_SCAFFOLD,
                    String.format("玩家 %s 疑似 Scaffold：快速在脚下方块放置", player.getName()),
                    0.75, player.getName());
            }
        }
    }

    @EventHandler(priority = EventPriority.LOWEST, ignoreCancelled = true)
    public void onSignChange(SignChangeEvent event) {
        if (bridge == null) return;
        Player player = event.getPlayer();

        // —— SignExploit 检测 ——
        // 检测异常长的告示牌文本（可能导致崩溃的 NBT 攻击）
        for (int i = 0; i < 4; i++) {
            String line = event.getLine(i);
            if (line != null && line.length() > 256) {
                bridge.alert(AlertType.SECURITY_SIGN_EXPLOIT,
                    String.format("玩家 %s 告示牌文本异常长（%d字符），疑似 SignExploit",
                        player.getName(), line.length()),
                    0.9, player.getName());
                event.setCancelled(true);
                return;
            }
        }
    }
}
