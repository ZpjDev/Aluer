package com.aluer.plugin;

import com.aluer.ServerGuardApplication;
import com.aluer.plugin.bridge.DataBridge;
import com.aluer.plugin.listener.*;
import org.bukkit.Bukkit;
import org.bukkit.event.HandlerList;
import org.bukkit.plugin.java.JavaPlugin;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ConfigurableApplicationContext;

/**
 * Aluer ServerGuard — PaperMC 插件主入口
 *
 * 插件加载时启动嵌入式 Spring Boot 上下文，
 * 注册所有 Bukkit 事件监听器，通过 DataBridge
 * 将服务器内部实时数据推送至安全分析引擎。
 *
 * 架构：
 *   Bukkit Events → Event Listeners → DataBridge → Security Services → AI → AutoExecutor → Bukkit API
 */
public class AluerPlugin extends JavaPlugin {
    private static final Logger logger = LoggerFactory.getLogger(AluerPlugin.class);

    /** 全局单例引用，供监听器在 Spring 上下文就绪前获取插件实例 */
    private static AluerPlugin instance;

    /** Spring Boot 应用上下文，插件关闭时需 gracefully shutdown */
    private ConfigurableApplicationContext springContext;

    /** 数据桥接中心，连接 Bukkit 事件与安全服务 */
    private DataBridge dataBridge;

    /** Spring 上下文是否已就绪 */
    private volatile boolean springReady = false;

    // ─── 生命周期 ────────────────────────────────────────

    @Override
    public void onLoad() {
        instance = this;
        logger.info("Aluer ServerGuard v4.0.0 — PaperMC Plugin loading (LOAD STARTUP)");
    }

    @Override
    public void onEnable() {
        long startMs = System.currentTimeMillis();

        // 步骤 1：启动嵌入式 Spring Boot（异步，避免阻塞 Paper 主线程）
        logger.info("Starting embedded Spring Boot context...");
        new Thread(() -> {
            try {
                // 设置 Paper 插件模式标志
                System.setProperty("serverguard.mode", "plugin");
                System.setProperty("server.mode", "plugin");

                springContext = ServerGuardApplication.bootstrap();
                dataBridge = springContext.getBean(DataBridge.class);
                springReady = true;
                logger.info("Spring Boot context ready — all security services initialized");
            } catch (Exception e) {
                logger.error("Failed to start Spring Boot context: {}", e.getMessage(), e);
            }
        }, "aluer-spring-boot").start();

        // 步骤 2：等待 Spring 上下文就绪（最长 30 秒）
        int waited = 0;
        while (!springReady && waited < 30) {
            try {
                Thread.sleep(1000);
                waited++;
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
        }

        if (!springReady) {
            logger.error("Spring Boot failed to start within 30s — plugin will operate in degraded mode");
        }

        // 步骤 3：注册 Bukkit 事件监听器
        registerEventListeners();

        // 步骤 4：注册插件命令
        registerCommands();

        long elapsed = System.currentTimeMillis() - startMs;
        logger.info("Aluer ServerGuard enabled in {}ms — real-time protection active", elapsed);
        logger.info("  Listeners: 10 event handlers registered");
        logger.info("  Commands:  /aluer, /aluerstatus, /aluerplayers, /aluerblock, /aluerunblock, /aluerscan, /aluerwhitelist");
        logger.info("  Web Console: http://0.0.0.0:8080/");
    }

    @Override
    public void onDisable() {
        logger.info("Shutting down Aluer ServerGuard...");

        // 注销所有 Bukkit 事件监听器
        HandlerList.unregisterAll(this);

        // 关闭 Spring Boot 上下文
        if (springContext != null) {
            springContext.close();
            springContext = null;
        }

        instance = null;
        logger.info("Aluer ServerGuard disabled — protection stopped");
    }

    // ─── 事件监听器注册 ──────────────────────────────────

    private void registerEventListeners() {
        // 注意：监听器在构造函数中接收 DataBridge 引用
        // 如果 Spring 未就绪则使用 null（监听器内部做空安全处理）
        DataBridge bridge = springReady ? dataBridge : null;

        // 核心监听器：玩家、战斗、聊天、命令
        Bukkit.getPluginManager().registerEvents(new PlayerEventListener(this, bridge), this);
        Bukkit.getPluginManager().registerEvents(new CombatEventListener(this, bridge), this);
        Bukkit.getPluginManager().registerEvents(new ChatEventListener(this, bridge), this);
        Bukkit.getPluginManager().registerEvents(new CommandEventListener(this, bridge), this);

        // 方块与物品监听器
        Bukkit.getPluginManager().registerEvents(new BlockEventListener(this, bridge), this);
        Bukkit.getPluginManager().registerEvents(new InventoryEventListener(this, bridge), this);

        // 实体与世界监听器
        Bukkit.getPluginManager().registerEvents(new EntityEventListener(this, bridge), this);
        Bukkit.getPluginManager().registerEvents(new WorldEventListener(this, bridge), this);

        // 包级监听器（Paper API 特有，用于精确的包速率控制）
        if (Bukkit.getServer().getClass().getPackageName().contains("paper")) {
            Bukkit.getPluginManager().registerEvents(new PacketEventListener(this, bridge), this);
        }
    }

    // ─── 命令注册 ────────────────────────────────────────

    private void registerCommands() {
        AluerCommandExecutor executor = new AluerCommandExecutor(this, dataBridge);
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

    /** 获取插件单例实例 */
    public static AluerPlugin getInstance() {
        return instance;
    }

    /** 获取 Spring 应用上下文（可能为 null，在 Spring 就绪前） */
    public ConfigurableApplicationContext getSpringContext() {
        return springContext;
    }

    /** 获取 DataBridge（可能为 null，在 Spring 就绪前） */
    public DataBridge getDataBridge() {
        return dataBridge;
    }

    /** Spring 上下文是否已完全初始化 */
    public boolean isSpringReady() {
        return springReady;
    }
}
