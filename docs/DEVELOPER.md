# Aluer ServerGuard V5.0 -- 开发者参考手册

## 版本信息

| 项目 | 内容 |
|------|------|
| 版本号 | V5.0 (含 V5.1/V5.2/V5.3 子版本) |
| 更新日期 | 2026-05-16 |
| Java 版本 | 21 |
| Spring Boot | 3.2.0 |
| 构建工具 | Apache Maven 3.9.6 (bundled) |
| PaperMC API | 1.21.1-R0.1-SNAPSHOT |

---

## 目录

1. [系统架构](#系统架构)
2. [项目结构](#项目结构)
3. [核心设计模式](#核心设计模式)
4. [添加新反作弊模块](#添加新反作弊模块)
5. [事件监听器模式](#事件监听器模式)
6. [Agent 通信协议详解](#agent-通信协议详解)
7. [配置系统](#配置系统)
8. [ML/AI 集成](#mlai-集成)
9. [测试规范](#测试规范)
10. [代码风格指南](#代码风格指南)
11. [构建系统](#构建系统)

---

## 系统架构

### 整体架构

```
+------------------------------------------------------------------+
|                     Aluer ServerGuard V5.0                        |
|                                                                   |
|  部署模式一：Plugin 内嵌模式（推荐）                                |
|  ┌─────────────────────────────────────────────────────────────┐  |
|  │  Minecraft PaperMC JVM                                       │  |
|  │  ┌──────────────┐     WebSocket      ┌──────────────────┐   │  |
|  │  │ AluerPlugin   │ ◄═══════════════► │ ServerGuard      │   │  |
|  │  │ (Paper插件)   │  ws://:8080/agent │ Spring Boot App  │   │  |
|  │  │              │                    │                  │   │  |
|  │  │ Bukkit事件 →  │ ──EVENT/METRICS──► │ 安全分析引擎     │   │  |
|  │  │ 监听器       │                    │ ML/AI模块        │   │  |
|  │  │              │ ◄──COMMAND/CONFIG─ │ DeepSeek集成     │   │  |
|  │  │ 命令执行器 ←  │                    │ Web Dashboard    │   │  |
|  │  └──────────────┘                    └──────────────────┘   │  |
|  └─────────────────────────────────────────────────────────────┘  |
|                                                                   |
|  部署模式二：External 外部监控模式                                  |
|  ┌──────────────────┐     RCON + 日志监控    ┌──────────────┐    |
|  │  PaperMC Server  │ ◄═══════════════════► │ ServerGuard  │    |
|  │  (独立JVM)       │                       │ (独立JVM)    │    |
|  └──────────────────┘                       └──────────────┘    |
+------------------------------------------------------------------+
```

### 数据流向

```
Bukkit Events
     │
     ▼
┌─────────────┐    AgentMessage.buildMessage()    ┌──────────────┐
│ Event       │ ─────────────────────────────────► │ Security     │
│ Listeners   │       JSON via WebSocket           │ Modules      │
│ (9个监听器) │                                     │ (123个模块)  │
└─────────────┘                                    │               │
                                                   │ ┌─────────┐  │
                                                   │ │ ML/AI   │  │
                                                   │ │ Engine  │  │
                                                   │ └────┬────┘  │
                                                   │      │       │
                                                   │ ┌────▼────┐  │
                                                   │ │DeepSeek │  │
                                                   │ │Analysis │  │
                                                   │ └────┬────┘  │
                                                   │      │       │
                                                   │ ┌────▼────┐  │
                                                   │ │Autonomy │  │
                                                   │ │/Shield  │  │
                                                   │ └────┬────┘  │
                                                   └──────│───────┘
                                                          │
                                    AgentMessage.buildCommand()
                                                          │
                                                          ▼
                                                   ┌──────────────┐
                                                   │ AluerPlugin   │
                                                   │ Command       │
                                                   │ Executor      │
                                                   │ (Bukkit API)  │
                                                   └──────────────┘
```

---

## 项目结构

```
src/main/java/com/aluer/
│
├── ServerGuardApplication.java       # Spring Boot 主入口
│
├── config/
│   └── ServerGuardConfig.java        # 完整配置类（1273行）
│       ├── MinecraftConfig           # Minecraft 进程配置
│       ├── MonitorConfig             # 监控阈值配置
│       ├── AlertConfig               # 告警（邮件）配置
│       ├── AiConfig                  # AI/ML 配置
│       │   └── DeepSeekConfig        #   DeepSeek 大模型配置
│       │       └── AutoExecuteConfig #   自动执行配置
│       ├── SecurityConfig            # 安全总配置
│       │   ├── MinecraftDefenseConfig    # Minecraft 协议层防御
│       │   ├── DDoSDefenseConfig         # DDoS 防御阈值
│       │   ├── AntiIntrusionConfig       # 入侵检测配置
│       │   ├── HostEnforcementConfig     # 主机层强制
│       │   ├── CloudEdgeConfig           # Cloudflare 边缘
│       │   ├── ThreatFeedsConfig         # 威胁情报源
│       │   ├── OrchestrationConfig       # 多层编排
│       │   ├── AutomationConfig          # 自动化调度
│       │   ├── AutonomyConfig            # 自主决策
│       │   ├── ShieldConfig              # 护盾配置
│       │   ├── KernelConfig              # 内核/脉冲配置
│       │   ├── TaskBusConfig             # 任务总线
│       │   ├── SelfHealingConfig         # 自愈配置
│       │   └── SuperEvolutionConfig      # 全部模块开关（70+开关）
│       ├── DashboardConfig           # Web 控制台
│       ├── AnnouncementConfig        # 公告
│       ├── AfkConfig                 # AFK 管理
│       ├── ChatFilterConfig          # 聊天过滤
│       ├── BackupConfig              # 备份配置
│       └── ScheduleConfig            # 定时任务
│
├── model/
│   └── AlertType.java                # 告警类型枚举（75种）
│
├── agent/
│   └── AgentMessage.java             # Agent 通信协议
│       # 常量：TYPE_EVENT, TYPE_METRICS, TYPE_ALERT,
│       #       TYPE_HEARTBEAT, TYPE_HANDSHAKE, TYPE_COMMAND_RESULT,
│       #       TYPE_COMMAND, TYPE_CONFIG, TYPE_SHUTDOWN
│       # 命令：CMD_BAN_IP, CMD_BAN_PLAYER, CMD_KICK,
│       #       CMD_CLEAR_LAG, CMD_SET_SPAWN_RATE, ...
│       # 事件：EVENT_PLAYER_JOIN, EVENT_PLAYER_MOVE,
│       #       EVENT_COMBAT_ATTACK, EVENT_BLOCK_BREAK, ...
│
├── security/                         # 安全模块（123个Java文件）
│   ├── AntiKillAuraService.java      # 杀戮光环检测
│   ├── AntiReachService.java         # 超距攻击检测
│   ├── AntiSpeedService.java         # 速度异常检测
│   ├── AntiCriticalsService.java     # 暴击检测
│   ├── AntiAutoCrystalService.java   # 水晶自动检测
│   ├── ...                           # 120+ more
│   └── ZeroTrustArchitectureService.java
│
├── ml/                               # ML/AI 模块（4个文件）
│   ├── BehavioralProfilingEngine.java    # 行为画像
│   ├── CombatPatternRecognizer.java      # 战斗模式识别
│   ├── MovementPatternAnalyzer.java      # 移动模式分析
│   └── ThreatScoreAggregator.java        # 威胁评分聚合
│
├── plugin/                           # Paper 插件实现
│   ├── AluerPlugin.java              # 插件主类 (extends JavaPlugin)
│   ├── AluerCommandExecutor.java     # 命令注册器
│   ├── bridge/
│   │   ├── AgentWebSocketClient.java     # WebSocket 客户端
│   │   ├── DataBridge.java              # 数据格式转换
│   │   └── InternalCommandExecutor.java # Bukkit API命令执行
│   └── listener/                     # Bukkit 事件监听器
│       ├── BlockEventListener.java       # 方块事件
│       ├── ChatEventListener.java        # 聊天事件
│       ├── CombatEventListener.java      # 战斗事件
│       ├── CommandEventListener.java     # 命令事件
│       ├── EntityEventListener.java      # 实体事件
│       ├── InventoryEventListener.java   # 背包事件
│       ├── PacketEventListener.java      # 原始包事件
│       ├── PlayerEventListener.java      # 玩家事件
│       └── WorldEventListener.java       # 世界事件
│
├── websocket/                        # WebSocket 服务端
└── controller/
    └── TestController.java           # 测试端点
```

---

## 核心设计模式

### 1. 双构造函数模式

每个安全模块 Service 类同时提供两个构造函数，确保测试友好性和生产注入兼容性：

```java
@Service
public class AntiKillAuraService {

    private final ServerGuardConfig config;

    /** 无参构造函数：用于单元测试，使用默认配置 */
    public AntiKillAuraService() {
        this.config = new ServerGuardConfig();
    }

    /** @Autowired 构造函数：用于生产环境，Spring 自动注入 */
    @Autowired
    public AntiKillAuraService(ServerGuardConfig config) {
        this.config = config;
    }

    // ... 检测逻辑
}
```

### 2. 静态工厂方法模式

检测结果使用内部静态类 + 静态工厂方法构建，避免直接 new：

```java
public static class DetectionResult {
    public enum Status { CLEAN, BLOCKED, FLAGGED }

    private final Status status;
    private final String reason;
    private final double confidence;

    private DetectionResult(Status status, String reason, double confidence) {
        this.status = status;
        this.reason = reason;
        this.confidence = confidence;
    }

    public static DetectionResult clean() {
        return new DetectionResult(Status.CLEAN, null, 0.0);
    }

    public static DetectionResult blocked(String reason, double confidence) {
        return new DetectionResult(Status.BLOCKED, reason, confidence);
    }

    public static DetectionResult flagged(String reason, double confidence) {
        return new DetectionResult(Status.FLAGGED, reason, confidence);
    }

    // getters...
}
```

### 3. ConcurrentHashMap 玩家追踪

所有安全模块使用 `ConcurrentHashMap<String, ...>` 以玩家名称为键追踪行为数据，确保线程安全：

```java
private final Map<String, List<AttackRecord>> playerAttackHistory = new ConcurrentHashMap<>();
private final Map<String, List<Double>> playerAngleHistory = new ConcurrentHashMap<>();
```

### 4. AtomicLong 统计计数

使用 `AtomicLong` 进行线程安全的统计计数：

```java
private final AtomicLong totalChecks = new AtomicLong(0);
private final AtomicLong flaggedCount = new AtomicLong(0);
```

### 5. 配置驱动开关

每个模块通过 `SuperEvolutionConfig` 中的独立开关控制启用/禁用：

```java
if (!config.getSecurity().getSuperEvolution().isAntiKillAura()) {
    return DetectionResult.clean();  // 模块已禁用，跳过检测
}
```

---

## 添加新反作弊模块

### 完整步骤

**第一步：确认反作弊 Hack 类型**

查阅 Meteor Client 的 hack 分类（Combat/Movement/World/Player/Misc/Render），确定你要对抗的 hack 名称和类型。

**第二步：创建 Service 类**

在 `src/main/java/com/aluer/security/` 下创建新类，遵循命名规范 `Anti{Xxx}Service.java`：

```java
package com.aluer.security;

import com.aluer.config.ServerGuardConfig;
import org.springframework.stereotype.Service;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * {Hack名称}检测服务 — V5.X 反作弊模块
 *
 * 检测原理：
 * 1. {原理1的详细说明}
 * 2. {原理2的详细说明}
 *
 * 配置开关：serverguard.security.super-evolution.anti-{xxx}
 */
@Service
public class AntiNewHackService {

    private final ServerGuardConfig config;

    /** 追踪每个玩家的行为数据 */
    private final Map<String, List<BehaviorRecord>> playerHistory = new ConcurrentHashMap<>();

    private final AtomicLong totalChecks = new AtomicLong(0);
    private final AtomicLong flaggedCount = new AtomicLong(0);

    // 常量定义
    private static final int ANALYSIS_WINDOW_MS = 3000;
    private static final double FLAG_THRESHOLD = 0.85;

    /** 无参构造函数（测试用） */
    public AntiNewHackService() {
        this.config = new ServerGuardConfig();
    }

    /** @Autowired 构造函数（生产用） */
    public AntiNewHackService(ServerGuardConfig config) {
        this.config = config;
    }

    /**
     * 分析玩家行为，检测是否存在 {hack名称} 作弊
     *
     * @param playerName 玩家名称
     * @param eventData  事件数据（根据 hack 类型确定参数）
     * @return 检测结果（CLEAN/FLAGGED/BLOCKED）
     */
    public DetectionResult analyze(String playerName, EventData eventData) {
        // 1. 检查模块是否启用
        if (!config.getSecurity().getSuperEvolution().isAntiNewHack()) {
            return DetectionResult.clean();
        }

        totalChecks.incrementAndGet();

        // 2. 更新玩家行为历史
        List<BehaviorRecord> history = playerHistory.computeIfAbsent(
            playerName, k -> Collections.synchronizedList(new ArrayList<>())
        );
        history.add(new BehaviorRecord(eventData, System.currentTimeMillis()));

        // 3. 清理过期记录（超出分析窗口）
        long cutoff = System.currentTimeMillis() - ANALYSIS_WINDOW_MS;
        history.removeIf(r -> r.timestamp < cutoff);

        // 4. 分析行为模式
        double anomalyScore = computeAnomalyScore(history);

        // 5. 返回结果
        if (anomalyScore > FLAG_THRESHOLD) {
            flaggedCount.incrementAndGet();
            return DetectionResult.flagged(
                String.format("NewHack detected: anomaly score %.2f", anomalyScore),
                anomalyScore
            );
        }

        return DetectionResult.clean();
    }

    private double computeAnomalyScore(List<BehaviorRecord> history) {
        // 实现具体的异常检测算法
        // ...
        return 0.0;
    }

    /** 行为记录内部类 */
    private static class BehaviorRecord {
        final EventData data;
        final long timestamp;

        BehaviorRecord(EventData data, long timestamp) {
            this.data = data;
            this.timestamp = timestamp;
        }
    }

    /** 检测结果（静态工厂） */
    public static class DetectionResult {
        public enum Status { CLEAN, BLOCKED, FLAGGED }

        private final Status status;
        private final String reason;
        private final double confidence;

        private DetectionResult(Status status, String reason, double confidence) {
            this.status = status;
            this.reason = reason;
            this.confidence = confidence;
        }

        public static DetectionResult clean() {
            return new DetectionResult(Status.CLEAN, null, 0.0);
        }

        public static DetectionResult blocked(String reason, double confidence) {
            return new DetectionResult(Status.BLOCKED, reason, confidence);
        }

        public static DetectionResult flagged(String reason, double confidence) {
            return new DetectionResult(Status.FLAGGED, reason, confidence);
        }

        public Status getStatus() { return status; }
        public String getReason() { return reason; }
        public double getConfidence() { return confidence; }
        public boolean isClean() { return status == Status.CLEAN; }
        public boolean isBlocked() { return status == Status.BLOCKED; }
        public boolean isFlagged() { return status == Status.FLAGGED; }
    }
}
```

**第三步：添加告警类型**

在 `AlertType.java` 中新增枚举值：

```java
// 在对应分类区域添加
SECURITY_NEW_HACK("NewHack", "Description of this hack detection"),
```

**第四步：添加配置开关**

在 `ServerGuardConfig.SuperEvolutionConfig` 中新增：

```java
// 属性声明
private boolean antiNewHack = true;

// Getter
public boolean isAntiNewHack() { return antiNewHack; }

// Setter
public void setAntiNewHack(boolean antiNewHack) { this.antiNewHack = antiNewHack; }
```

**第五步：添加 application.yml 配置**

```yaml
# 在 super-evolution 节中添加
anti-new-hack: true    # 新Hack检测说明
```

**第六步：编写单元测试**

在 `src/test/java/com/aluer/security/` 下创建测试类：

```java
package com.aluer.security;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class AntiNewHackServiceTest {

    private final AntiNewHackService service = new AntiNewHackService();

    @Test
    void testCleanBehavior() {
        // 正常玩家行为应该返回 CLEAN
        // ...
    }

    @Test
    void testFlaggedBehavior() {
        // 异常行为应该返回 FLAGGED
        // ...
    }

    @Test
    void testModuleDisabled() {
        // 模块关闭时应返回 CLEAN
        // ...
    }
}
```

**第七步：全量测试**

```bash
./apache-maven-3.9.6/bin/mvn test
```

确保所有现有测试和新测试全部通过。

---

## 事件监听器模式

### 监听器基类结构

所有 Bukkit 事件监听器位于 `com.aluer.plugin.listener` 包下，每个监听器负责一类事件：

```java
package com.aluer.plugin.listener;

import com.aluer.plugin.bridge.DataBridge;
import org.bukkit.event.Listener;

/**
 * {事件类别}监听器 — 拦截 Bukkit 事件并转发至 ServerGuard 引擎
 */
public class XxxEventListener implements Listener {

    private final DataBridge dataBridge;

    public XxxEventListener(DataBridge dataBridge) {
        this.dataBridge = dataBridge;
    }

    @EventHandler(priority = EventPriority.MONITOR)
    public void onXxxEvent(XxxEvent event) {
        // 1. 提取事件数据
        // 2. 通过 DataBridge 转换为 AgentMessage
        // 3. 通过 WebSocket 发送至 ServerGuard
        dataBridge.sendEvent("EVENT_TYPE", eventData);
    }
}
```

### 九大监听器及其监听事件

| 监听器 | 主要监听事件 | 数据类型 |
|--------|------------|---------|
| BlockEventListener | BlockBreakEvent, BlockPlaceEvent | 方块坐标、类型、玩家、工具 |
| ChatEventListener | AsyncPlayerChatEvent | 消息内容、发送时间 |
| CombatEventListener | EntityDamageByEntityEvent, PlayerDeathEvent | 攻击者、目标、伤害量、武器 |
| CommandEventListener | PlayerCommandPreprocessEvent | 命令文本、执行时间 |
| EntityEventListener | EntitySpawnEvent, EntityDeathEvent | 实体类型、坐标、原因 |
| InventoryEventListener | InventoryClickEvent, InventoryOpenEvent | 槽位、物品类型、容器位置 |
| PacketEventListener | PacketEvent (ProtocolLib) | 原始数据包内容 |
| PlayerEventListener | PlayerJoinEvent, PlayerQuitEvent, PlayerMoveEvent | 玩家信息、坐标、移动向量 |
| WorldEventListener | ChunkLoadEvent, ChunkUnloadEvent | 区块坐标、加载原因 |

### DataBridge 数据转换

`DataBridge` 负责将 Bukkit 事件数据转换为 AgentMessage JSON 格式：

```java
public class DataBridge {
    private final AgentWebSocketClient wsClient;

    public void sendEvent(String eventType, JsonObject eventData) {
        JsonObject payload = new JsonObject();
        payload.addProperty("eventType", eventType);
        // 添加通用字段
        payload.add("data", eventData);

        String message = AgentMessage.buildMessage(
            AgentMessage.TYPE_EVENT,
            agentId,
            payload
        );
        wsClient.send(message);
    }
}
```

---

## Agent 通信协议详解

### 协议设计

通信基于 WebSocket (RFC 6455)，所有消息为单行 JSON 文本帧。

### 消息类型枚举

定义在 `AgentMessage.java` 中：

**Agent → Server:**
| 常量 | 值 | 说明 |
|------|-----|------|
| TYPE_EVENT | "EVENT" | Bukkit 事件上报 |
| TYPE_METRICS | "METRICS" | 服务器性能指标 |
| TYPE_ALERT | "ALERT" | 安全告警上报 |
| TYPE_HEARTBEAT | "HEARTBEAT" | 心跳保活（间隔由Kernel配置） |
| TYPE_HANDSHAKE | "HANDSHAKE" | 初始连接握手 |
| TYPE_COMMAND_RESULT | "COMMAND_RESULT" | 命令执行结果回执 |

**Server → Agent:**
| 常量 | 值 | 说明 |
|------|-----|------|
| TYPE_COMMAND | "COMMAND" | 防御指令下发 |
| TYPE_CONFIG | "CONFIG" | 动态配置更新 |
| TYPE_SHUTDOWN | "SHUTDOWN" | 连接关闭通知 |

### 命令类型

| 常量 | 值 | 对应 Bukkit 操作 |
|------|-----|-----------------|
| CMD_BAN_IP | "BAN_IP" | Bukkit.banIP() |
| CMD_BAN_PLAYER | "BAN_PLAYER" | Bukkit.getBanList().addBan() |
| CMD_KICK | "KICK" | Player.kickPlayer() |
| CMD_CLEAR_LAG | "CLEAR_LAG" | World.getEntities().clear() |
| CMD_SET_SPAWN_RATE | "SET_SPAWN_RATE" | 调整 spawn-limits |
| CMD_ENABLE_WHITELIST | "ENABLE_WHITELIST" | Bukkit.setWhitelist(true) |
| CMD_DISABLE_WHITELIST | "DISABLE_WHITELIST" | Bukkit.setWhitelist(false) |
| CMD_BROADCAST | "BROADCAST" | Bukkit.broadcastMessage() |
| CMD_SAVE_ALL | "SAVE_ALL" | Bukkit.savePlayers() + World.save() |
| CMD_EXECUTE | "EXECUTE" | Bukkit.dispatchCommand() |

### 事件类型

| 常量 | 值 | 关联 Bukkit 事件 |
|------|-----|-----------------|
| EVENT_PLAYER_JOIN | "PLAYER_JOIN" | PlayerJoinEvent |
| EVENT_PLAYER_QUIT | "PLAYER_QUIT" | PlayerQuitEvent |
| EVENT_PLAYER_MOVE | "PLAYER_MOVE" | PlayerMoveEvent |
| EVENT_PLAYER_TELEPORT | "PLAYER_TELEPORT" | PlayerTeleportEvent |
| EVENT_PLAYER_CHAT | "PLAYER_CHAT" | AsyncPlayerChatEvent |
| EVENT_PLAYER_COMMAND | "PLAYER_COMMAND" | PlayerCommandPreprocessEvent |
| EVENT_PLAYER_DAMAGE | "PLAYER_DAMAGE" | EntityDamageEvent |
| EVENT_COMBAT_ATTACK | "COMBAT_ATTACK" | EntityDamageByEntityEvent |
| EVENT_COMBAT_DEATH | "COMBAT_DEATH" | PlayerDeathEvent |
| EVENT_BLOCK_BREAK | "BLOCK_BREAK" | BlockBreakEvent |
| EVENT_BLOCK_PLACE | "BLOCK_PLACE" | BlockPlaceEvent |
| EVENT_INVENTORY_CLICK | "INVENTORY_CLICK" | InventoryClickEvent |
| EVENT_ENTITY_SPAWN | "ENTITY_SPAWN" | EntitySpawnEvent |
| EVENT_CHUNK_LOAD | "CHUNK_LOAD" | ChunkLoadEvent |

### 消息格式规范

```java
// Agent → Server: 构建消息
public static String buildMessage(String type, String agentId, JsonObject payload) {
    JsonObject msg = new JsonObject();
    msg.addProperty("type", type);
    msg.addProperty("agentId", agentId);
    msg.addProperty("timestamp", Instant.now().toEpochMilli());
    msg.add("payload", payload);
    return gson.toJson(msg);
}

// Server → Agent: 构建命令
public static String buildCommand(String commandType, String target, String reason) {
    JsonObject payload = new JsonObject();
    payload.addProperty("command", commandType);
    payload.addProperty("target", target != null ? target : "");
    payload.addProperty("reason", reason != null ? reason : "");

    JsonObject msg = new JsonObject();
    msg.addProperty("type", TYPE_COMMAND);
    msg.addProperty("requestId", UUID.randomUUID().toString());
    msg.addProperty("timestamp", Instant.now().toEpochMilli());
    msg.add("payload", payload);
    return gson.toJson(msg);
}

// 解析工具方法
public static String getType(String message) { /* 解析 type 字段 */ }
public static JsonObject getPayload(String message) { /* 解析 payload 对象 */ }
public static String getAgentId(String message) { /* 解析 agentId 字段 */ }
```

---

## 配置系统

### 配置层次结构

```
application.yml
  └── serverguard.*                    # 所有配置的前缀
       ├── mode                        # 运行模式：plugin | external
       ├── minecraft.*                 # Minecraft 进程管理
       ├── monitor.*                   # 监控阈值
       ├── alert.*                     # 告警配置
       │    └── email.*                #   邮件配置
       ├── ai.*                        # AI/ML 配置
       │    └── deepseek.*             #   DeepSeek 集成
       │         └── auto-execute.*    #   自动执行
       ├── security.*                  # 安全配置
       │    ├── minecraft-defense.*    #   协议层防御
       │    ├── ddos-defense.*         #   DDoS 防御
       │    ├── anti-intrusion.*       #   入侵检测
       │    │    └── file-integrity.*  #   文件完整性
       │    ├── host-enforcement.*     #   主机强制
       │    ├── cloud-edge.*           #   云端边缘
       │    ├── threat-feeds.*         #   威胁情报
       │    ├── orchestration.*        #   编排
       │    ├── automation.*           #   自动化
       │    ├── autonomy.*             #   自主决策
       │    ├── shield.*               #   护盾
       │    ├── kernel.*               #   内核
       │    ├── task-bus.*             #   任务总线
       │    ├── self-healing.*         #   自愈
       │    └── super-evolution.*      #   模块开关（70+个）
       ├── dashboard.*                 # Web 控制台
       │    └── ssh-gateway.*          #   SSH 网关
       ├── announcement.*              # 公告
       ├── afk.*                       # AFK 管理
       ├── chat-filter.*               # 聊天过滤
       ├── backup.*                    # 备份
       └── schedule.*                  # 定时任务
```

### 配置类映射关系

`ServerGuardConfig` 使用 `@ConfigurationProperties(prefix = "serverguard")` 注解，Spring Boot 自动将 YAML 配置绑定到对应的嵌套静态内部类。

命名转换规则：
- YAML 中 `kebab-case`（如 `tps-threshold`）
- Java 中 `camelCase`（如 `tpsThreshold`）
- Spring Boot 自动完成转换

### 环境变量覆盖

配置值可以使用 `${ENV_VAR:default}` 语法通过环境变量覆盖，示例如下：

```yaml
serverguard:
  mode: ${SERVERGUARD_MODE:external}
  ai:
    deepseek:
      api-key: ${DEEPSEEK_API_KEY:}
      model: ${DEEPSEEK_MODEL:deepseek-chat}
  alert:
    email:
      username: ${ALUER_ALERT_SMTP_USERNAME:}
      password: ${ALUER_ALERT_SMTP_PASSWORD:}
```

---

## ML/AI 集成

### 四大 ML 模块

| 模块 | 功能 | 算法 |
|------|------|------|
| BehavioralProfilingEngine | 基于统计特征建立玩家行为基线，检测偏离 | Isolation Forest, Statistical Profiling |
| CombatPatternRecognizer | 识别异常战斗序列（多目标切换、异常连击模式） | Pattern Matching, Sequence Analysis |
| MovementPatternAnalyzer | 分析移动轨迹异常（路径熵值、加速度模式） | Trajectory Analysis, Entropy Calculation |
| ThreatScoreAggregator | 融合多维度检测结果，生成统一威胁评分 | Weighted Aggregation, Escalation Logic |

### AI 配置参数

```yaml
ai:
  enabled: true
  use-isolation-forest: true       # 启用隔离森林
  use-prediction: true              # 启用时间序列预测
  sliding-window-size: 100          # 滑动窗口数据点数
  anomaly-threshold: 0.7            # 异常判定阈值 (0.0-1.0)
  prediction-horizon-minutes: 60    # 预测未来时间范围
```

### DeepSeek 集成

```yaml
ai:
  deepseek:
    enabled: true
    api-key: ${DEEPSEEK_API_KEY:}
    base-url: https://api.deepseek.com
    model: deepseek-chat
    max-tokens: 1000
    temperature: 0.35               # 低温度获得稳定分析
    auto-analyze-alerts: true       # 自动分析所有告警
    analysis-interval-seconds: 45   # 分析间隔
    auto-execute:
      enabled: true
      ban-ip: true
      kill-entity: true
      clear-lag: true
      set-spawn-rate: true
      kick-player: true
      whitelist: true
      min-confidence: 88            # 低于此置信度不自动执行
```

---

## 测试规范

### 测试原则

1. **打靶试验** — 测试必须模拟真实 Minecraft 服务器环境，不允许使用假数据
2. **生产对齐** — 测试数据和行为必须与实际生产环境对齐
3. **全量验证** — 修改代码前后必须跑全量 278 项测试，一个不能挂
4. **双构造函数模式** — 每个 Service 必须提供无参构造函数用于测试

### 测试类命名规范

```
src/test/java/com/aluer/
├── security/
│   ├── AntiKillAuraServiceTest.java
│   ├── AntiReachServiceTest.java
│   └── ...
├── ml/
│   ├── BehavioralProfilingEngineTest.java
│   └── ...
└── plugin/
    └── ...
```

### 测试方法命名

```java
@Test
void testCleanBehavior() { }          // 正常行为 → CLEAN
@Test
void testFlaggedBehavior() { }        // 可疑行为 → FLAGGED
@Test
void testBlockedBehavior() { }        // 明确作弊 → BLOCKED
@Test
void testModuleDisabled() { }         // 模块关闭 → CLEAN
@Test
void testEdgeCase() { }               // 边界条件
@Test
void testPerformance() { }            // 性能测试
```

### 运行测试

```bash
# 全量测试
./apache-maven-3.9.6/bin/mvn test

# 运行特定测试类
./apache-maven-3.9.6/bin/mvn test -Dtest=AntiKillAuraServiceTest

# 运行特定测试方法
./apache-maven-3.9.6/bin/mvn test -Dtest=AntiKillAuraServiceTest#testFlaggedBehavior
```

---

## 代码风格指南

### 命名规范

| 元素 | 规范 | 示例 |
|------|------|------|
| 包名 | 全小写 | `com.aluer.security` |
| 类名 | PascalCase | `AntiKillAuraService` |
| 方法名 | camelCase | `analyzePlayerBehavior()` |
| 常量 | UPPER_SNAKE_CASE | `MAX_ATTACK_DISTANCE` |
| 配置属性 | camelCase (Java) / kebab-case (YAML) | `tpsThreshold` / `tps-threshold` |
| 枚举值 | UPPER_SNAKE_CASE | `SECURITY_KILL_AURA` |

### 注释规范

- **类级别**：必须有 JavaDoc 注释，说明模块功能、检测原理、配置开关
- **方法级别**：必须有 JavaDoc 注释，说明参数、返回值、算法思路
- **关键逻辑**：行内注释解释 WHY 而非 WHAT
- **语言**：使用中文注释

```java
/**
 * 杀戮光环（KillAura）检测服务 — V4.0 反作弊扩展模块
 *
 * 检测原理：
 * 1. 攻击目标切换频率检测 — 追踪每个玩家的攻击目标列表，如果在3秒窗口内切换超过3个不同目标
 * 2. 攻击角度一致性检测 — 连续攻击的角度偏差小于5度时，表明存在自动瞄准（Aimbot）
 *
 * 配置开关：serverguard.security.super-evolution.anti-kill-aura
 */
@Service
public class AntiKillAuraService {
    // ...
}
```

### 代码组织

```java
// 1. Package 声明
// 2. Import 语句（按字母排序，静态导入在后）
// 3. 类 JavaDoc
// 4. @Service 或其他注解
// 5. 类声明
// 6. 常量字段
// 7. 配置注入字段
// 8. 数据追踪字段（ConcurrentHashMap, AtomicLong）
// 9. 构造函数（无参 + @Autowired）
// 10. 公共分析方法
// 11. 私有辅助方法
// 12. 内部类（BehaviorRecord, DetectionResult）
```

### Git 提交规范

- 使用中文 commit message
- 格式：`{类型}: {简短描述}`
- 类型：新增、修复、重构、文档、测试、优化
- 频繁提交，每个有意义的改动单独提交

示例：
```
新增: AntiAutoCrystal 末影水晶自动化检测模块
修复: Reach 检测误判穿墙攻击时的距离计算错误
重构: 统一所有安全模块的 DetectionResult 返回类型
```

---

## 构建系统

### Maven 配置

项目使用 Apache Maven 3.9.6（bundled），配置文件 `pom.xml`。

### 关键依赖

```xml
<dependencies>
    <!-- Spring Boot 核心 -->
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-web</artifactId>
    </dependency>
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-websocket</artifactId>
    </dependency>
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-mail</artifactId>
    </dependency>

    <!-- Spring Shell CLI -->
    <dependency>
        <groupId>org.springframework.shell</groupId>
        <artifactId>spring-shell-starter</artifactId>
        <version>3.1.3</version>
    </dependency>

    <!-- PaperMC API -->
    <dependency>
        <groupId>io.papermc.paper</groupId>
        <artifactId>paper-api</artifactId>
        <version>1.21.1-R0.1-SNAPSHOT</version>
        <scope>provided</scope>
    </dependency>

    <!-- 机器学习 -->
    <dependency>
        <groupId>com.github.haifengl</groupId>
        <artifactId>smile-core</artifactId>
        <version>2.6.0</version>
    </dependency>
    <dependency>
        <groupId>org.apache.commons</groupId>
        <artifactId>commons-math3</artifactId>
        <version>3.6.1</version>
    </dependency>

    <!-- YAML 配置 -->
    <dependency>
        <groupId>org.yaml</groupId>
        <artifactId>snakeyaml</artifactId>
        <version>2.2</version>
    </dependency>

    <!-- JSON (内嵌) -->
    <dependency>
        <groupId>com.google.code.gson</groupId>
        <artifactId>gson</artifactId>
    </dependency>
</dependencies>
```

### 构建命令速查

```bash
# 编译（不运行测试）
./apache-maven-3.9.6/bin/mvn compile

# 编译 + 运行全量测试
./apache-maven-3.9.6/bin/mvn test

# 打包（跳过测试）
./apache-maven-3.9.6/bin/mvn package -DskipTests

# 打包 + 运行测试
./apache-maven-3.9.6/bin/mvn package

# 清理构建产物
./apache-maven-3.9.6/bin/mvn clean

# 清理 + 完整重新构建
./apache-maven-3.9.6/bin/mvn clean package
```

### 构建产物

```
target/
├── serverguard-4.0.0.jar              # 可执行 JAR（Spring Boot Fat JAR）
├── classes/                            # 编译后的 .class 文件
├── test-classes/                       # 测试编译产物
├── generated-sources/                  # 注解处理器生成
└── surefire-reports/                   # 测试报告
```

### 部署产物说明

- `serverguard-4.0.0.jar` 是 Spring Boot 可执行 JAR，包含所有依赖
- 同时作为 Paper 插件使用（复制到 `plugins/` 目录）
- Plugin 模式下，AluerPlugin 作为 Paper 插件启动，但不启动嵌入的 Spring Boot（由外部引擎独立运行）
