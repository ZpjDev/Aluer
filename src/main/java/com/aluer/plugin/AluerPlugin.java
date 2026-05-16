package com.aluer.plugin;

import com.aluer.plugin.bridge.AgentWebSocketClient;
import com.aluer.plugin.bridge.InternalCommandExecutor;
import com.aluer.plugin.listener.*;
import org.bukkit.Bukkit;
import org.bukkit.event.HandlerList;
import org.bukkit.plugin.java.JavaPlugin;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Aluer ServerGuard — PaperMC 轻量 Agent 插件
 *
 * 本插件不嵌入 Spring Boot，而是作为数据采集前端：
 * 1. 注册 Bukkit 事件监听器，拦截服务器内部所有关键事件
 * 2. 通过 WebSocket 将事件实时推送至外部 ServerGuard 分析引擎
 * 3. 接收 ServerGuard 下发的防御指令并通过 InternalCommandExecutor 执行
 *
 * 架构：
 *   Bukkit Events → Listeners → AgentWebSocketClient → (WebSocket) → ServerGuard Server
 *   ServerGuard Server → (WebSocket) → AgentWebSocketClient → InternalCommandExecutor → Bukkit API
 *
 * 部署要求：
 *   - 打包为 Paper 插件 JAR，放入 plugins/ 目录
 *   - 外部 ServerGuard 必须先于 Paper 服务器启动
 *   - 默认连接 ws://localhost:8080/agent
 */
public class AluerPlugin extends JavaPlugin {
    private static final Logger logger = LoggerFactory.getLogger(AluerPlugin.class);

    private static AluerPlugin instance;

    /** WebSocket 客户端，负责与服务端通信 */
    private AgentWebSocketClient wsClient;

    /** Bukkit API 命令执行器 */
    private InternalCommandExecutor commandExecutor;

    /** 服务端 URL（可通过 config.yml 覆盖） */
    private String serverUrl = "ws://localhost:8080/agent";

    // ─── 生命周期 ────────────────────────────────────────

    @Override
    public void onLoad() {
        instance = this;
        logger.info("══════════════════════════════════════════════");
        logger.info("  Aluer ServerGuard Agent v5.0.0");
        logger.info("  轻量数据采集前端 — 连接外部 ServerGuard 引擎");
        logger.info("══════════════════════════════════════════════");
    }

    @Override
    public void onEnable() {
        long startMs = System.currentTimeMillis();

        // 读取配置
        saveDefaultConfig();
        serverUrl = getConfig().getString("server-url", "ws://localhost:8080/agent");

        // 初始化内部命令执行器
        commandExecutor = new InternalCommandExecutor();

        // 初始化 WebSocket 客户端
        wsClient = new AgentWebSocketClient(serverUrl, commandExecutor);
        wsClient.connect();

        // 注册 Bukkit 事件监听器（传入 WebSocket 客户端）
        registerEventListeners();

        // 注册插件命令
        registerCommands();

        long elapsed = System.currentTimeMillis() - startMs;
        logger.info("Agent enabled in {}ms", elapsed);
        logger.info("  Server: {}", serverUrl);
        logger.info("  Listeners: 9 event handlers registered");
        logger.info("  Commands: /aluer /aluerstatus /aluerplayers /aluerblock /aluerscan /aluerwhitelist");
    }

    @Override
    public void onDisable() {
        logger.info("Shutting down Aluer Agent...");

        HandlerList.unregisterAll(this);

        if (wsClient != null) {
            wsClient.disconnect();
        }

        instance = null;
        logger.info("Agent disabled");
    }

    // ─── 事件监听器注册 ──────────────────────────────────

    private void registerEventListeners() {
        Bukkit.getPluginManager().registerEvents(new PlayerEventListener(this, wsClient), this);
        Bukkit.getPluginManager().registerEvents(new CombatEventListener(this, wsClient), this);
        Bukkit.getPluginManager().registerEvents(new ChatEventListener(this, wsClient), this);
        Bukkit.getPluginManager().registerEvents(new CommandEventListener(this, wsClient), this);
        Bukkit.getPluginManager().registerEvents(new BlockEventListener(this, wsClient), this);
        Bukkit.getPluginManager().registerEvents(new InventoryEventListener(this, wsClient), this);
        Bukkit.getPluginManager().registerEvents(new EntityEventListener(this, wsClient), this);
        Bukkit.getPluginManager().registerEvents(new WorldEventListener(this, wsClient), this);

        if (Bukkit.getServer().getClass().getPackageName().contains("paper")) {
            Bukkit.getPluginManager().registerEvents(new PacketEventListener(this, wsClient), this);
        }
    }

    // ─── 命令注册 ────────────────────────────────────────

    private void registerCommands() {
        AluerCommandExecutor executor = new AluerCommandExecutor(this, wsClient, commandExecutor);
        var aluerCmd = getCommand("aluer");
        if (aluerCmd != null) {
            aluerCmd.setExecutor(executor);
            aluerCmd.setTabCompleter(executor);
        }
        var statusCmd = getCommand("aluerstatus");
        if (statusCmd != null) statusCmd.setExecutor(executor);
        var playersCmd = getCommand("aluerplayers");
        if (playersCmd != null) playersCmd.setExecutor(executor);
        var blockCmd = getCommand("aluerblock");
        if (blockCmd != null) blockCmd.setExecutor(executor);
        var unblockCmd = getCommand("aluerunblock");
        if (unblockCmd != null) unblockCmd.setExecutor(executor);
        var scanCmd = getCommand("aluerscan");
        if (scanCmd != null) scanCmd.setExecutor(executor);
        var whitelistCmd = getCommand("aluerwhitelist");
        if (whitelistCmd != null) whitelistCmd.setExecutor(executor);
    }

    // ─── 公开访问器 ──────────────────────────────────────

    public static AluerPlugin getInstance() {
        return instance;
    }

    public AgentWebSocketClient getWsClient() {
        return wsClient;
    }

    public InternalCommandExecutor getCommandExecutor() {
        return commandExecutor;
    }

    public boolean isServerConnected() {
        return wsClient != null && wsClient.isConnected();
    }
}
