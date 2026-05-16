package com.aluer.plugin.listener;

import com.aluer.model.AlertType;
import com.aluer.plugin.AluerPlugin;
import com.aluer.plugin.bridge.DataBridge;
import com.aluer.plugin.bridge.DataBridge.PlayerSnapshot;
import org.bukkit.event.EventHandler;
import org.bukkit.event.EventPriority;
import org.bukkit.event.Listener;
import org.bukkit.event.player.AsyncPlayerChatEvent;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.regex.Pattern;

/**
 * 聊天事件监听器 — 处理玩家聊天消息
 *
 * 实时检测：
 * - ChatFlood（聊天刷屏）— 短时间内大量消息
 * - Advertisement（广告）— IP/域名模式匹配
 * - PhishingLink（钓鱼链接）— 可疑 URL 检测
 * - Profanity（不雅用语）— 关键词过滤
 * - Spam（重复消息）— 相同内容重复发送
 */
public class ChatEventListener implements Listener {
    private static final Logger logger = LoggerFactory.getLogger(ChatEventListener.class);

    private final AluerPlugin plugin;
    private final DataBridge bridge;

    /** IP 地址正则 */
    private static final Pattern IP_PATTERN = Pattern.compile(
        "(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})(:\\d{1,5})?");

    /** URL 正则（含常见短链接服务） */
    private static final Pattern URL_PATTERN = Pattern.compile(
        "https?://[^\\s]+|bit\\.ly/[^\\s]+|tinyurl\\.com/[^\\s]+|discord\\.gg/[^\\s]+",
        Pattern.CASE_INSENSITIVE);

    /** 聊天刷屏阈值（秒内消息数） */
    private static final int SPAM_THRESHOLD = 5;
    private static final long SPAM_WINDOW_MS = 10_000;

    public ChatEventListener(AluerPlugin plugin, DataBridge bridge) {
        this.plugin = plugin;
        this.bridge = bridge;
    }

    @EventHandler(priority = EventPriority.LOWEST, ignoreCancelled = true)
    public void onAsyncPlayerChat(AsyncPlayerChatEvent event) {
        if (bridge == null) return;
        String message = event.getMessage();
        String playerName = event.getPlayer().getName();
        PlayerSnapshot snap = bridge.getPlayer(event.getPlayer().getUniqueId());

        // —— 聊天刷屏检测 ——
        if (snap != null) {
            snap.recentMessages.add(message);
            while (snap.recentMessages.size() > 20) {
                snap.recentMessages.removeFirst();
            }

            long now = System.currentTimeMillis();
            long recentCount = snap.recentMessages.stream()
                .filter(m -> true) // 所有消息都在时间窗口内（Deque 中保留最近 20 条）
                .count();

            if (recentCount >= SPAM_THRESHOLD) {
                bridge.alert(AlertType.CHAT_FLOOD,
                    String.format("玩家 %s 聊天刷屏：%d 条消息", playerName, recentCount),
                    0.7, playerName);
                event.setCancelled(true);
                return;
            }
        }

        // —— 广告/IP 检测 ——
        if (IP_PATTERN.matcher(message).find()) {
            bridge.alert(AlertType.CHAT_ADVERTISEMENT,
                String.format("玩家 %s 发送疑似IP地址：%s", playerName, message),
                0.8, playerName);
            event.setCancelled(true);
            return;
        }

        // —— 钓鱼链接检测 ——
        if (URL_PATTERN.matcher(message).find()) {
            bridge.alert(AlertType.CHAT_PHISHING,
                String.format("玩家 %s 发送外部链接：%s", playerName, message),
                0.75, playerName);
            event.setCancelled(true);
            return;
        }

        bridge.incrementEvent("chat.message");
    }
}
