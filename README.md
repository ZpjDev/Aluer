# Aluer ServerGuard V5.0

> AI 驱动的 Minecraft PaperMC 服务器全方位安全防护系统

---

## 项目概述

Aluer ServerGuard 是一款专为 Minecraft PaperMC 服务器打造的新一代智能安全防护系统。系统采用 **Agent 架构**，通过轻量级 Paper 插件作为数据采集前端，配合外部 Spring Boot 分析引擎，实现对服务器的全方位实时防护。

核心特色：
- **AI 行为分析**：基于隔离森林（Isolation Forest）和时间序列预测的异常检测
- **DeepSeek 大模型集成**：自动分析安全告警并生成防御策略
- **全类型反作弊覆盖**：对抗 Meteor Client 等主流外挂客户端的全部 hack 模块
- **服务器自愈能力**：TPS/CPU/内存异常自动恢复，DDoS 自动防御
- **双模式部署**：支持 Plugin 内嵌模式和 External 外部监控模式
- **135+ 安全模块**：覆盖反作弊、网络安全、主机安全、入侵检测、取证分析

---

## 版本历史

| 版本 | 日期 | 核心更新 |
|------|------|----------|
| V5.3 | 2026-05 | Meteor Client 世界/玩家/杂物模块对抗：SpeedMine, FastUse, NoInteract, AutoMine, VeinMiner, AutoTool, FakePlayer, PistonAura, Anchor, StashFinder |
| V5.2 | 2026-05 | Meteor Client 移动类对抗：NoSlow, Spider, Step, PacketFly, AirJump, LongJump, AntiHunger, FastFall, VClip |
| V5.1 | 2026-05 | Meteor Client 战斗类对抗：Criticals, AutoTotem, Surround, AutoTrap, AutoCrystal, AutoArmor, ChestSwap, AutoLog, Hitboxes, BowAimbot |
| V5.0 | 2026-04 | Agent 架构重构，WebSocket 实时通信，Timer/Velocity/Phase/Blink/FastBreak/ElytraFly 反作弊 |
| V4.0 | 2026-03 | KillAura/Reach/Speed/Jesus/NoFall/Scaffold/Nuker/AutoClicker 反作弊，玩家行为安全，服务器保护 |

---

## 架构设计

```
+---------------------------------------------------------------------+
|                     Aluer ServerGuard 系统架构                        |
+---------------------------------------------------------------------+
|                                                                      |
|  +------------------+         WebSocket          +----------------+  |
|  |  PaperMC Server  | <========================> |  ServerGuard   |  |
|  |                  |    ws://host:8080/agent    |  Spring Boot   |  |
|  |  +------------+  |                            |  +----------+  |  |
|  |  | AluerPlugin|  |   EVENT --------------->   |  | Security  |  |  |
|  |  | (Agent)    |  |   METRICS -------------->  |  | Modules   |  |  |
|  |  |            |  |   ALERT -----------------> |  | (135+)    |  |  |
|  |  | Bukkit     |  |   HEARTBEAT -------------> |  +----------+  |  |
|  |  | Events     |  |                            |  +----------+  |  |
|  |  +------------+  |   <-------- COMMAND -----  |  | ML/AI     |  |  |
|  |                  |   <-------- CONFIG ------  |  | Engine    |  |  |
|  |  Event Listeners |                            |  +----------+  |  |
|  |  + Combat       |                            |  +----------+  |  |
|  |  + Block        |                            |  | DeepSeek  |  |  |
|  |  + Movement     |                            |  | Analysis  |  |  |
|  |  + Inventory    |                            |  +----------+  |  |
|  |  + Chat         |                            |  +----------+  |  |
|  |  + Command      |                            |  | Web       |  |  |
|  |  + Entity       |                            |  | Dashboard |  |  |
|  |  + Packet       |                            |  +----------+  |  |
|  |  + World        |                            +----------------+  |
|  +------------------+                                     |         |
|                                                           |         |
|                                              +------------v-------+  |
|                                              |  Self-Healing      |  |
|                                              |  Shield / Kernel   |  |
|                                              |  Autonomy Engine   |  |
|                                              +--------------------+  |
+---------------------------------------------------------------------+
```

**通信协议**：所有消息均为单行 JSON，通过 WebSocket 文本帧双向传输。

Agent 向 Server 发送的消息类型：
- `EVENT` -- Bukkit 事件数据（玩家移动、战斗、方块操作等）
- `METRICS` -- 服务器指标（TPS、CPU、Memory、在线人数）
- `ALERT` -- 安全告警
- `HEARTBEAT` -- 心跳保活
- `HANDSHAKE` -- 初始握手
- `COMMAND_RESULT` -- 命令执行结果

Server 向 Agent 发送的指令类型：
- `COMMAND` -- 执行操作（BAN_IP, BAN_PLAYER, KICK, CLEAR_LAG 等）
- `CONFIG` -- 动态配置更新
- `SHUTDOWN` -- 关闭连接

---

## 技术栈

| 技术 | 版本 | 用途 |
|------|------|------|
| Java | 21 | 核心语言 |
| Spring Boot | 3.2.0 | 应用框架 |
| Maven | 3.9.6 | 构建管理 |
| PaperMC API | 1.21.1-R0.1-SNAPSHOT | Minecraft 服务端 API |
| Spring WebSocket | 3.2.0 | Agent 通信 |
| Spring Mail | 3.2.0 | 邮件告警 |
| Spring Shell | 3.1.3 | 命令行交互 |
| SnakeYAML | 2.2 | YAML 配置解析 |
| Smile | 2.6.0 | 机器学习算法库 |
| Apache Commons Math | 3.6.1 | 数学/统计计算 |
| Gson | (内嵌) | JSON 序列化 |

---

## 完整安全模块清单

### 一、反作弊 -- 战斗类（15 模块）

| 模块名称 | 对应 Hack | 检测原理 |
|---------|----------|---------|
| AntiKillAuraService | KillAura | 多目标切换频率、Aimbot 角度一致性、极限距离攻击模式 |
| AntiReachService | Reach | 攻击距离验证、位置回溯检测 |
| AntiSpeedService | Speed | 水平移动速度异常分析 |
| AntiCriticalsService | Criticals | 零速度暴击、无跳跃暴击、暴击率统计异常 |
| AntiAutoCrystalService | AutoCrystal | 末影水晶放置/引爆速度、最优位置计算检测 |
| AntiAutoTotemService | AutoTotem | 图腾换装速度（毫秒级检测）、连续图腾使用模式 |
| AntiSurroundService | Surround | 四向方块放置速度、防御方块模式识别 |
| AntiAutoTrapService | AutoTrap | 目标玩家围笼构建速度、活塞陷阱自动化 |
| AntiAutoArmor | AutoArmor | 多槽位装甲切换速度、背包扫描模式 |
| AntiChestSwap | ChestSwap | 胸甲/鞘翅互换 tick 级检测 |
| AntiAutoLog | AutoLog | 受伤后立即断线模式、低血量脱战检测 |
| AntiHitboxes | Hitboxes | 边缘命中率、射线追踪距离分布分析 |
| AntiBowAimbot | BowAimbot | 移动目标命中率、弹道一致性、瞬发精准检测 |
| AntiVelocityService | Velocity | 击退幅度异常、抗击退检测 |
| AntiAutoClickerService | AutoClicker | CPS 统计、点击间隔熵值分析 |

### 二、反作弊 -- 移动类（18 模块）

| 模块名称 | 对应 Hack | 检测原理 |
|---------|----------|---------|
| AntiFlyDetectionService | Fly | 垂直/水平速度、悬空时间、移动模式分析 |
| AntiJesusService | Jesus | 水面/岩浆面移动验证 |
| AntiNoFallService | NoFall | 落地检测、摔落伤害验证 |
| AntiSpeedService | Speed | 水平移动速度异常分析 |
| AntiTimerService | Timer | 游戏 tick 间隔异常、移动速度频率分析 |
| AntiPhaseService | Phase | 方块剪切/穿越检测、固体方块穿透验证 |
| AntiBlinkService | Blink | 快速断连躲避伤害检测 |
| AntiSpiderService | Spider | 无攀爬方块贴墙移动、垂直墙面移动检测 |
| AntiStepService | Step | 无跳跃跨越完整方块检测 |
| AntiNoSlowService | NoSlow | 使用物品时移速检测（吃食物/拉弓/举盾） |
| AntiPacketFlyService | PacketFly | 数据包操控飞行、上下震荡模式、永不落地检测 |
| AntiAirJumpService | AirJump | 半空跳跃数据包检测、连续空中跳跃 |
| AntiLongJump | LongJump | 极端水平跳跃距离检测 |
| AntiAntiHunger | AntiHunger | 高活动量零饥饿消耗检测 |
| AntiFastFall | FastFall | 超终端速度下落检测 |
| AntiVClip | VClip | 瞬间垂直穿透方块检测（排除合法传送） |
| AntiElytraFlyService | ElytraFly | 鞘翅速度/高度操控检测 |
| AntiScaffoldService | Scaffold | 方块放置频率/角度/速度模式分析 |

### 三、反作弊 -- 世界/玩家/杂物类（19 模块）

| 模块名称 | 对应 Hack | 检测原理 |
|---------|----------|---------|
| AntiNukerService | Nuker | 挖矿速度/范围/模式识别 |
| AntiAutoMineService | AutoMine | 自动化采矿行为检测 |
| AntiSpeedMineService | SpeedMine | 加速挖掘（InstaMine/PacketMine）检测 |
| AntiFastBreakService | FastBreak | 方块破坏速度异常检测 |
| AntiFastUseService | FastUse | 物品使用加速检测 |
| AntiNoInteractService | NoInteract | 交互绕过检测 |
| AntiVeinMinerService | VeinMiner | 矿脉自动化挖掘模式检测 |
| AntiAutoTool | AutoTool | 即时工具切换检测 |
| AntiAutoFishService | AutoFish | 钓鱼行为时序/反应速度分析 |
| AntiChestStealService | ChestSteal | 开箱/取物速度模式识别 |
| AntiInventoryManipulationService | InventoryManipulation | 背包操作速度、非法槽位操作检测 |
| AntiBaritoneService | Baritone | 路径平滑度/行为重复率分析 |
| AntiXrayDetectionService | Xray | 钻石比率/直线挖掘/暗处精准检测 |
| AntiGriefDetectionService | Grief | 方块破坏率/TNT/纵火/偷箱检测 |
| AntiFakePlayer | FakePlayer | 假人实体检测 |
| AntiPistonAura | PistonAura | 活塞陷阱自动化检测 |
| AntiAnchor | Anchor | 洞穴锚点防御检测 |
| AntiStashFinder | StashFinder | 自动化储藏箱探测检测 |
| AntiDupeDetectionService | AntiDupe | 物品复制检测（堆叠异常/9种复制法） |

### 四、服务器漏洞防护（12 模块）

| 模块名称 | 防护对象 |
|---------|---------|
| AntiSignExploitService | 告示牌 NBT 漏洞（超长 JSON/无效组件/NBT 炸弹） |
| AntiBookBanService | 书与笔封禁漏洞（超大页码/超深 JSON 层级） |
| AntiResourcePackExploitService | 资源包漏洞（恶意 URL/超大文件/格式校验） |
| AntiTabCompleteCrashService | Tab 补全崩溃（长文本/深度嵌套补全限制） |
| AntiOfflineModeSpoofService | 离线 UUID 欺诈（正版 UUID 冲突/IP 关联验证） |
| CrashExploitProtectionService | 崩溃漏洞防护（超大包/NBT 炸弹/书与笔攻击） |
| CrashExploitSignatureDB | 崩溃漏洞签名数据库（12 种已知签名匹配） |
| LagMachineDetectionService | 卡服机检测（Observer 链/TNT 堆/红石密度） |
| ChunkLoadRateLimiter | 区块加载速率限制（WARN/LIMIT/BLOCK 三级响应） |
| EntityCountEnforcer | 实体数量强制执行（按区块/玩家/类型自动清理） |
| RedstoneUpdateLimiter | 红石更新频率限制（降频/冻结/指数退避） |
| PacketFloodProtectionService | 数据包洪水防护 |

### 五、聊天与社交安全（5 模块）

| 模块名称 | 防护对象 |
|---------|---------|
| ChatFloodProtectionService | 聊天洪水（频率/相似度/长度激增） |
| AntiAdvertisementService | 广告检测（IP/域名/群号正则匹配） |
| AntiPhishingLinkService | 钓鱼链接（可疑域名/短链接/SSL 证书校验） |
| AntiCommandAbuseService | 命令滥用（频率限制/敏感命令拦截/权限校验） |
| PlayerPrivacyService | 玩家隐私保护（IP 脱敏/坐标隐藏/日志匿名化） |

### 六、网络安全（13 模块）

| 模块名称 | 防护对象 |
|---------|---------|
| DDoSProtectionService | DDoS 攻击（SYN/UDP/ICMP/HTTP/慢速连接/放大攻击） |
| DDoSDefenseCoordinator | DDoS 多层防御协调 |
| ProtocolStateValidator | 协议状态机验证（HANDSHAKE/STATUS/LOGIN/PLAY） |
| BotFingerprintDetector | 机器人指纹检测（登录时序/命名模式/移动熵值） |
| NBTExploitPrevention | NBT 漏洞防护（深度/尺寸限制） |
| ConnectionHandshakeValidator | 连接握手验证（协议版本/hostname/Ping 洪水/端口扫描） |
| PortScanDetectionService | 端口扫描检测 |
| BruteForceProtectionService | 暴力破解防护（多时间窗口检测） |
| AntiVPNProxyService | VPN/代理检测（已知 VPN IP 库/托管 ASN 匹配） |
| DNSTunnelDetectionService | DNS 隧道检测（熵值/Base32 编码/可疑 TLD） |
| ReverseShellDetectionService | 反向 Shell 检测（50+ shell 模式匹配） |
| ProcessInjectionDetectionService | 进程注入检测 |
| ARPSpoofDetectionService | ARP 欺骗检测（MAC 变更/网关伪造） |

### 七、主机与访问控制安全（6 模块）

| 模块名称 | 防护对象 |
|---------|---------|
| FileIntegrityMonitorService | 文件完整性监控（Hash 基线/实时监控） |
| BackdoorPluginScannerService | 后门插件扫描（已知恶意类名/远程执行/隐藏命令） |
| ConfigTamperDetectionService | 配置文件篡改检测（ops/whitelist 实时监控） |
| OPPrivilegeMonitorService | OP 权限监控（权限变更/敏感命令执行审计） |
| AntiAltAccountService | 小号检测（IP 关联/行为相似度/登录模式） |
| AntiNameSpoofService | 名称冒充检测（管理员/知名玩家昵称伪造） |

### 八、高级安全基础设施（28 模块）

| 模块名称 | 功能描述 |
|---------|---------|
| PlayerSessionValidationService | 玩家会话验证（UUID 伪造/正版/离线检测） |
| PluginVerificationService | 插件完整性校验（Hash 对比/未授权修改） |
| BackupIntegrityService | 备份完整性校验（SHA-256/文件计数/大小对比） |
| ConnectionThrottleService | 连接速率限制（IP/时间窗口/递增延迟） |
| GeoBlockService | 地理 IP 封锁（按国家/地区拦截） |
| AntiSkinSpoofService | 皮肤伪造检测（模型数据异常/皮肤 URL 检测） |
| JwtAuthService | JWT 身份认证与令牌管理 |
| AntiBotDetectionService | 反机器人检测（名称/加入速率/IP 关联） |
| CSPEnforcementService | CSP 安全头强制执行（8 种响应头） |
| SSRFProtectionService | SSRF 防护（内网 IP/云元数据/协议限制） |
| XXEProtectionService | XXE 防护（实体注入/Billion Laughs 检测） |
| DatabaseFirewallService | 数据库防火墙（SQL 注入/联合查询/时间盲注） |
| DataLossPreventionService | 数据防泄漏（12 种敏感信息规则+自动脱敏） |
| MemoryProtectionService | JVM 内存保护（堆/GC/内存泄漏检测） |
| SecureFileDeletionService | 安全文件删除（多道覆写 DoD 标准） |
| ForensicsCollectorService | 取证收集（进程/网络/日志快照） |
| IncidentResponseService | 事件响应（5 种预定义响应剧本） |
| ThreatHuntingService | 威胁狩猎（10 种狩猎定义/5 个类别） |
| ComplianceScannerService | 合规扫描（7 类 20+ 检查项） |
| ExploitSignatureService | 漏洞签名检测（Log4Shell/SQLi/RCE 等 15 种） |
| SecurityOrchestrationService | 多层防御编排（本地封锁/边缘挑战/Minecraft 防御） |
| SecurityAutomationScheduler | 安全自动化调度（情报刷新/态势快照/规则同步） |
| HostEnforcementService | 主机层面强制执行 |
| HostIntrusionCountermeasureService | 主机入侵对抗 |
| IntrusionDetectionService | 网络入侵检测 |
| IntrusionPreventionSystem | 网络入侵防御 |
| WebApplicationFirewall | Web 应用防火墙 |
| ZeroTrustArchitectureService | 零信任架构 |

### 九、网络与流量分析（10 模块）

| 模块名称 | 功能描述 |
|---------|---------|
| NetworkMonitorService | 网络流量监控 |
| NetworkSnifferService | 网络数据包嗅探 |
| NetworkThreatFusionService | 多源威胁情报融合 |
| FlowAnalyzerService | 流量行为分析 |
| TrafficAnalysisService | 流量模式分析 |
| TrafficShapingService | 流量整形与 QoS |
| PacketInspectionService | 深度包检测 |
| ProtocolAnalysisService | 协议异常分析 |
| TokenBucketRateLimiter | 令牌桶速率限制原语 |
| FirewallService | 系统防火墙管理 |

### 十、基础设施与运维安全（8 模块）

| 模块名称 | 功能描述 |
|---------|---------|
| SIEMService | 安全信息与事件管理 |
| LogAnalysisService | 日志模式分析 |
| LogCorrelationService | 跨源日志关联 |
| ThreatIntelligenceService | 威胁情报聚合 |
| IPReputationService | IP 信誉数据库查询 |
| SSLTLSCertificateService | SSL/TLS 证书管理 |
| SecurityBaselineHardeningService | 安全基线加固 |
| ContainerSecurityService | 容器运行时安全 |

### 十一、ML/AI 行为分析（4 模块）

| 模块名称 | 功能描述 |
|---------|---------|
| BehavioralProfilingEngine | 玩家行为画像引擎（基于统计特征的行为基线建模） |
| CombatPatternRecognizer | 战斗模式识别器（异常战斗序列检测） |
| MovementPatternAnalyzer | 移动模式分析器（轨迹异常、路径熵值） |
| ThreatScoreAggregator | 威胁评分聚合器（多维度威胁评分融合与升级） |

---

## 部署指南

### 模式一：Plugin 内嵌模式（推荐）

ServerGuard 以 Paper 插件形式直接运行在 Minecraft 服务器进程内部，零网络延迟，最高实时性能。

**前置条件：**
- Minecraft PaperMC 1.21.1 服务器已安装
- Java 21 运行时
- ServerGuard 引擎 JAR 已编译

**部署步骤：**

1. **编译插件**
   ```bash
   cd /opt/AluerIII
   ./apache-maven-3.9.6/bin/mvn package -DskipTests
   ```

2. **安装插件到 Minecraft**
   ```bash
   cp target/serverguard-4.0.0.jar /opt/minecraft/plugins/AluerServerGuard.jar
   ```

3. **创建插件配置文件** `plugins/AluerServerGuard/config.yml`：
   ```yaml
   server-url: ws://localhost:8080/agent
   ```

4. **启动 ServerGuard 引擎**（必须先于 Minecraft 服务器启动）
   ```bash
   java -jar target/serverguard-4.0.0.jar
   ```

5. **启动 Minecraft 服务器**
   ```bash
   cd /opt/minecraft
   java -Xms4G -Xmx4G -jar paper-1.21.11.jar
   ```

启动后，AluerPlugin 将自动通过 WebSocket 连接到 ServerGuard 引擎并向其推送 Bukkit 事件数据。

### 模式二：External 外部监控模式

ServerGuard 作为独立进程运行，通过 RCON 和日志监控进行外部防护。适用于不想安装插件的场景。

**部署步骤：**

1. **编译**
   ```bash
   ./apache-maven-3.9.6/bin/mvn package -DskipTests
   ```

2. **配置 `application.yml`**
   ```yaml
   serverguard:
     mode: external
     minecraft:
       working-dir: /opt/minecraft
       rcon:
         enabled: true
         host: localhost
         port: 25575
         password: "your_rcon_password_here"
       process-name: paper-1.21.11.jar
   ```

3. **在 Minecraft `server.properties` 中启用 RCON**
   ```properties
   enable-rcon=true
   rcon.port=25575
   rcon.password=your_rcon_password_here
   ```

4. **启动 ServerGuard**
   ```bash
   java -jar target/serverguard-4.0.0.jar
   ```

---

## 配置参考

### 核心配置（serverguard.*）

```yaml
serverguard:
  mode: ${SERVERGUARD_MODE:external}  # plugin 或 external

  minecraft:
    service-name: minecraft
    process-name: paper-1.21.11.jar
    jar-file: paper-1.21.11.jar
    working-dir: /opt/minecraft
    java-opts: -Xms4G -Xmx4G
    check-interval-seconds: 5
    rcon:
      enabled: true
      host: localhost
      port: 25575
      password: ${RCON_PASSWORD:}

  monitor:
    tps-threshold: 15           # TPS 低于此值触发告警
    cpu-threshold: 80.0         # CPU 使用率超过此值触发告警（%）
    memory-threshold: 85.0      # 内存使用率超过此值触发告警（%）
    connection-threshold: 50    # 同时连接数超过此值触发告警
    log-watch-lines: 100        # 日志监控行数
    log-path: /opt/minecraft/logs/latest.log

  alert:
    enabled: true
    email:
      smtp-host: smtp.qq.com
      smtp-port: 587
      username: ${ALUER_ALERT_SMTP_USERNAME:}
      password: ${ALUER_ALERT_SMTP_PASSWORD:}
      to:
        - ${ALUER_ALERT_EMAIL_PRIMARY:}
        - ${ALUER_ALERT_EMAIL_SECONDARY:}
      rate-limit:
        per-type-seconds: 300     # 同类型告警最小间隔（秒）
        max-emails-per-minute: 10 # 每分钟最大邮件数
```

### AI 配置（serverguard.ai.*）

```yaml
  ai:
    enabled: true
    use-isolation-forest: true       # 启用隔离森林异常检测
    use-prediction: true              # 启用时间序列预测
    sliding-window-size: 100          # 分析滑动窗口大小
    anomaly-threshold: 0.7            # 异常判定阈值（0-1）
    prediction-horizon-minutes: 60    # 预测时间范围（分钟）
    deepseek:
      enabled: true
      api-key: ${DEEPSEEK_API_KEY:}
      base-url: ${DEEPSEEK_BASE_URL:https://api.deepseek.com}
      model: ${DEEPSEEK_MODEL:deepseek-chat}
      max-tokens: 1000
      temperature: 0.35               # 分析稳定性（0=精确，1=创造性）
      auto-analyze-alerts: true       # 自动分析告警
      analysis-interval-seconds: 45   # 分析间隔（秒）
      auto-execute:
        enabled: true
        ban-ip: true                  # 允许自动封禁 IP
        kill-entity: true             # 允许自动清除实体
        clear-lag: true               # 允许自动清理延迟
        set-spawn-rate: true          # 允许自动调整生成率
        kick-player: true             # 允许自动踢出玩家
        whitelist: true               # 允许自动启用白名单
        min-confidence: 88            # 自动执行的最低置信度（%）
```

### 安全防御配置（serverguard.security.*）

```yaml
  security:
    enabled: true
    auto-ban-vpn: true
    check-on-login: true
    max-connections-per-ip: 3      # 每 IP 最大连接数
    block-common-exploits: true
    log-all-commands: true

    minecraft-defense:
      enabled: true
      game-tcp-port: 25565
      query-udp-port: 25565
      rcon-tcp-port: 25575
      status-ping-threshold: 25       # Status Ping 洪水阈值
      login-burst-threshold: 12       # 登录突发阈值
      bot-swarm-threshold: 15         # 机器人集群阈值
      query-flood-threshold: 30       # Query 洪水阈值
      rcon-brute-force-threshold: 5   # RCON 暴力破解阈值
      compression-payload-threshold: 8192  # 压缩载荷上限

    ddos-defense:
      enabled: true
      syn-flood-threshold: 100
      udp-flood-threshold: 200
      icmp-flood-threshold: 100
      http-flood-threshold: 150
      slow-connection-threshold: 150
      amplification-threshold: 20
      minecraft-status-threshold: 20
      minecraft-login-threshold: 10
      minecraft-rcon-threshold: 5
      minecraft-query-threshold: 25
      minecraft-bot-swarm-threshold: 12

    anti-intrusion:
      enabled: true
      monitor-commands: true
      monitor-processes: true
      monitor-files: true
      monitor-plugins: true
      monitor-systemd: true
      monitor-rcon: true
      file-integrity:
        enabled: true
        max-depth: 5
        monitored-paths:
          - /opt/minecraft/plugins
          - /opt/minecraft/server.properties
          - /opt/minecraft/paper-1.21.11.jar
          - /opt/minecraft/start.sh
          - /etc/systemd/system/minecraft.service

    host-enforcement:
      enabled: true
      dry-run: true                      # 干燥运行模式（不实际执行封锁）
      preferred-backend: auto            # 后端选择：auto/iptables/nftables/firewalld
      default-block-minutes: 60          # 默认封锁时间（分钟）
      default-rate-limit-per-minute: 120 # 默认每分钟限速
      mirror-to-cloud-edge: true         # 同步到云端边缘

    cloud-edge:
      enabled: false
      dry-run: true
      provider: cloudflare
      zone-id: ${ALUER_CLOUDFLARE_ZONE_ID:}
      api-key: ${ALUER_CLOUDFLARE_API_KEY:}
      api-email: ${ALUER_CLOUDFLARE_EMAIL:}
      default-block-mode: block
      default-challenge-mode: challenge
      enable-under-attack-on-critical: true

    orchestration:
      enabled: true
      allow-local-block: true
      allow-edge-challenge: true
      allow-minecraft-defense: true
      notify-on-critical: true

    automation:
      enabled: true
      feed-refresh-minutes: 15        # 威胁情报刷新间隔
      posture-snapshot-minutes: 5     # 安全态势快照间隔
      integrity-rescan-minutes: 30    # 完整性重新扫描间隔
      rule-sync-minutes: 10           # 规则同步间隔
      incident-retention-minutes: 120 # 事件保留时间

    autonomy:
      enabled: true
      deepseek-dominant: true              # DeepSeek 主导决策
      quiet-console: true                   # 静默控制台
      loop-interval-seconds: 45             # 自主循环间隔
      min-risk-score-for-action: 70         # 最低行动风险分数
      critical-risk-score: 90               # 严重风险分数
      workflow-cooldown-seconds: 180        # 工作流冷却时间
      max-actions-per-hour: 12              # 每小时最大行动次数
      require-second-signal-for-containment: true  # 需要二次信号确认封锁

    shield:
      enabled: true
      auto-mode: true
      auto-enable-under-attack: true
      heat-trigger: 78                      # 热量触发阈值
      resonance-trigger: 72                 # 共振触发阈值
      threat-score-trigger: 85              # 威胁分数触发阈值
      edge-challenge-offender-limit: 6      # 边缘挑战违规者上限
      shelter-rate-limit-per-minute: 45     # 庇护所每分钟限速
      attacker-notice-enabled: true
      deterrence-message: "Your source has been identified, recorded, and isolated by Aluer."

    kernel:
      enabled: true
      pulse-interval-seconds: 30        # 脉冲间隔
      pulse-history-size: 180           # 脉冲历史大小
      journal-size: 300                 # 日志大小
      echo-retention-minutes: 180       # 回响保留时间
      adaptive-weights: true            # 自适应权重
      directive-heat-threshold: 60      # 指令热量阈值
      lockdown-heat-threshold: 82       # 封锁热量阈值

    task-bus:
      enabled: true
      auto-dispatch: true
      dispatch-interval-seconds: 10
      queue-limit: 200
      history-limit: 300

    self-healing:
      enabled: true
      dry-run: true                          # 干燥运行模式
      loop-interval-seconds: 45
      auto-backup-before-recovery: true      # 恢复前自动备份
      auto-whitelist-on-swarm: true          # 集群攻击时自动白名单
      allow-soft-restart: true               # 允许软重启
      tps-emergency-threshold: 12            # TPS 紧急阈值
      cpu-emergency-threshold: 92.0          # CPU 紧急阈值（%）
      memory-emergency-threshold: 95.0       # 内存紧急阈值（%）
      max-recovery-actions-per-hour: 8       # 每小时最大恢复行动
```

### SuperEvolution 模块开关（serverguard.security.super-evolution.*）

```yaml
    super-evolution:
      # === V4.0 高级扩展安全模块 ===
      jwt-auth: true                    # JWT 身份认证与令牌管理
      brute-force: true                 # 暴力破解防护（多时间窗口检测）
      anti-bot: true                    # 反机器人检测
      reverse-shell: true               # 反向 Shell 检测（50+ 模式匹配）
      arp-spoof: true                   # ARP 欺骗检测
      dns-tunnel: true                  # DNS 隧道检测（熵值/Base32编码/可疑TLD）
      exploit-signature: true            # 漏洞签名检测（Log4Shell/SQLi/RCE等15种）
      ssrf: true                        # SSRF 防护
      xxe: true                         # XXE 防护
      csp: true                         # CSP 安全头强制执行
      database-firewall: true           # 数据库防火墙
      dlp: true                         # 数据防泄漏（12种敏感信息规则）
      memory-protection: true           # JVM 内存保护
      process-injection: true           # 进程注入检测
      secure-delete: true               # 安全文件删除
      forensics: true                   # 取证收集
      incident-response: true           # 事件响应（5种预定义剧本）
      threat-hunting: true              # 威胁狩猎（10种狩猎定义）
      compliance: true                  # 合规扫描（7类20+检查项）
      anti-grief: true                  # 反破坏检测
      # === Minecraft 专属防护 ===
      anti-xray: true                   # X-ray 透视检测
      anti-fly: true                    # 飞行外挂检测
      anti-dupe: true                   # 物品复制检测（9种复制法）
      crash-exploit: true               # 崩溃漏洞防护
      lag-machine: true                 # 卡服机检测
      # === V4.0 新增模块 ===
      geo-block: true                   # 地理 IP 封锁
      session-validation: true          # 玩家会话验证
      plugin-verification: true         # 插件完整性校验
      connection-throttle: true         # 连接速率限制
      backup-integrity: true            # 备份完整性校验
      anti-skin-spoof: true             # 皮肤伪造检测
      # === V4.0 反作弊扩展模块 ===
      anti-kill-aura: true              # 杀戮光环检测
      anti-reach: true                  # 超距攻击检测
      anti-speed: true                  # 水平速度检测
      anti-jesus: true                  # 水上行走检测
      anti-no-fall: true                # 无摔落伤害检测
      anti-scaffold: true               # 自动搭路检测
      anti-timer: true                  # 游戏加速检测
      anti-velocity: true               # 击退修改检测
      anti-phase: true                  # 穿墙检测
      anti-blink: true                  # 闪烁检测
      anti-fast-break: true             # 快速破坏检测
      anti-elytra-fly: true             # 鞘翅飞行检测
      # === V4.0 玩家行为安全模块 ===
      anti-nuker: true                  # 快速破坏检测
      anti-auto-clicker: true           # 自动点击检测
      anti-chest-steal: true            # 自动偷箱检测
      anti-auto-fish: true              # 自动钓鱼检测
      anti-inventory-manipulation: true # 背包操作检测
      anti-baritone: true               # AI 寻路机器人检测
      # === V4.0 服务器保护模块 ===
      packet-flood-protection: true     # 数据包洪水防护
      anti-sign-exploit: true           # 告示牌漏洞防护
      anti-book-ban: true               # 书与笔封禁防护
      anti-resource-pack-exploit: true  # 资源包漏洞防护
      anti-tab-complete-crash: true     # Tab 补全崩溃防护
      anti-offline-mode-spoof: true     # 离线 UUID 欺诈防护
      # === V4.0 访问控制模块 ===
      op-privilege-monitor: true        # OP 权限监控
      config-tamper-detection: true     # 配置文件篡改检测
      backdoor-plugin-scanner: true     # 后门插件扫描
      anti-vpn-proxy: true              # VPN 代理检测
      anti-alt-account: true            # 小号检测
      anti-name-spoof: true             # 名称冒充检测
      # === V4.0 聊天社交安全模块 ===
      chat-flood-protection: true       # 聊天洪水防护
      anti-advertisement: true          # 广告检测
      anti-phishing-link: true          # 钓鱼链接检测
      anti-command-abuse: true          # 命令滥用检测
      player-privacy: true              # 玩家隐私保护
      # === V5.0 服务器保护扩展 ===
      chunk-load-rate-limiter: true     # 区块加载速率限制
      entity-count-enforcer: true       # 实体数量强制执行
      redstone-update-limiter: true     # 红石更新频率限制
      crash-exploit-signature-db: true  # 崩溃漏洞签名数据库
      # === V4.0 网络协议安全模块 ===
      protocol-validator: true          # 协议状态机验证
      token-bucket-rate-limiter: true   # 令牌桶速率限制
      bot-fingerprint: true             # 机器人行为指纹检测
      nbt-exploit-prevention: true      # NBT 漏洞防护
      handshake-validator: true         # 连接握手验证
      # === V5.1 反作弊战斗模块（Meteor Client 对抗） ===
      anti-criticals: true              # 自动暴击检测
      anti-auto-totem: true             # 自动不死图腾检测
      anti-surround: true               # 自动包围检测
      anti-auto-trap: true              # 自动困笼检测
      anti-auto-crystal: true           # 自动末影水晶检测
      anti-auto-armor: true             # 自动盔甲检测
      anti-chest-swap: true             # 快速胸甲切换检测
      anti-auto-log: true               # 自动断线检测
      anti-hitboxes: true               # 扩大碰撞箱检测
      anti-bow-aimbot: true             # 弓自瞄检测
      # === V5.2 反作弊移动模块（Meteor Client 移动类对抗） ===
      anti-no-slow: true                # 无减速检测
      anti-spider: true                 # 爬墙检测
      anti-step: true                   # 自动跨步检测
      anti-packet-fly: true             # 数据包飞行检测
      anti-air-jump: true               # 空中跳跃检测
      anti-long-jump: true              # 远跳检测
      anti-anti-hunger: true            # 反饥饿检测
      anti-fast-fall: true              # 快速坠落检测
      anti-vclip: true                  # 垂直穿墙检测
      # === V5.3 反作弊世界/玩家/杂物模块（Meteor Client 对抗） ===
      anti-speed-mine: true             # 加速挖掘检测
      anti-fast-use: true               # 加速物品使用检测
      anti-no-interact: true            # 交互绕过检测
      anti-auto-mine: true              # 自动挖矿检测
      anti-vein-miner: true             # 矿脉自动挖掘检测
      anti-auto-tool: true              # 自动工具切换检测
      anti-fake-player: true            # 假人实体检测
      anti-piston-aura: true            # 活塞陷阱自动化检测
      anti-anchor: true                 # 洞穴锚点检测
      anti-stash-finder: true           # 自动储藏箱探测
```

### 其他配置节

```yaml
  dashboard:
    enabled: true
    title: "Aluer Nebula Console"
    subtitle: "PaperMC defense, recovery, and remote operations fabric"
    refresh-interval-seconds: 6
    compact-terminal: true
    ssh-gateway:
      enabled: true
      session-timeout-minutes: 30
      max-sessions: 6
      command-timeout-seconds: 25
      strict-host-key-checking: false
      allow-private-key-paste: true
      require-engine-handshake: true
      handshake-ttl-seconds: 30

  announcement:
    enabled: false
    interval-seconds: 300
    messages:
      - "Welcome to the server!"

  afk:
    enabled: false
    afk-timeout-minutes: 5
    max-afk-minutes: 30
    teleport-to-afk-zone: false
    afk-zone: "0,100,0"
    auto-logout: false

  chat-filter:
    enabled: false
    block-ip: true
    block-profanity: true
    block-advertising: true
    block-spam: true
    block-illegal: true
    spam-threshold: 5
    spam-window-seconds: 10
    mute-on-violation: true
    mute-duration-minutes: 5
    kick-on-repeat: true
    max-violations-before-kick: 3

  backup:
    enabled: false
    backup-dir: /opt/minecraft/backups
    world-dir: /opt/minecraft/world
    plugin-dir: /opt/minecraft/plugins
    config-dir: /opt/minecraft
    interval-hours: 24
    max-backups: 7
    compress: true
    backup-plugins: true
    backup-config: false
    notify-on-complete: true

  schedule:
    enabled: true
    daily-restart: true
    restart-time: "04:00"
    save-before-restart: true
    announce-restart: true
    announce-message: "Server will restart in {minutes} minutes"
    weekly-backup: true
    backup-day: sunday
    backup-time: "03:00"
    clear-lag-daily: true
    clear-lag-time: "02:00"
```

---

## WebSocket 通信协议

### 消息格式

所有消息均为单行 JSON，通过 WebSocket 文本帧传输。

**Agent → Server 消息示例（事件上报）：**

```json
{
  "type": "EVENT",
  "agentId": "agent-survival-01",
  "timestamp": 1715000000000,
  "payload": {
    "eventType": "PLAYER_MOVE",
    "playerName": "Steve",
    "x": 100.5,
    "y": 64.0,
    "z": 200.3,
    "yaw": 45.0,
    "pitch": 0.0
  }
}
```

**Agent → Server 心跳消息：**

```json
{
  "type": "HEARTBEAT",
  "agentId": "agent-survival-01",
  "timestamp": 1715000005000,
  "payload": {
    "status": "alive"
  }
}
```

**Server → Agent 命令消息：**

```json
{
  "type": "COMMAND",
  "requestId": "550e8400-e29b-41d4-a716-446655440000",
  "timestamp": 1715000001000,
  "payload": {
    "command": "KICK",
    "target": "Hacker123",
    "reason": "KillAura detected - confidence 94%"
  }
}
```

### 事件类型完整列表

| 事件类型常量 | 值 | 说明 |
|-------------|-----|------|
| EVENT_PLAYER_JOIN | PLAYER_JOIN | 玩家加入服务器 |
| EVENT_PLAYER_QUIT | PLAYER_QUIT | 玩家退出服务器 |
| EVENT_PLAYER_MOVE | PLAYER_MOVE | 玩家移动（含坐标 x/y/z 和角度 yaw/pitch） |
| EVENT_PLAYER_TELEPORT | PLAYER_TELEPORT | 玩家传送 |
| EVENT_PLAYER_CHAT | PLAYER_CHAT | 聊天消息 |
| EVENT_PLAYER_COMMAND | PLAYER_COMMAND | 命令执行 |
| EVENT_PLAYER_DAMAGE | PLAYER_DAMAGE | 玩家受伤 |
| EVENT_COMBAT_ATTACK | COMBAT_ATTACK | 攻击事件（含攻击者/目标/伤害量） |
| EVENT_COMBAT_DEATH | COMBAT_DEATH | 死亡事件 |
| EVENT_BLOCK_BREAK | BLOCK_BREAK | 方块破坏（含方块类型/坐标/工具） |
| EVENT_BLOCK_PLACE | BLOCK_PLACE | 方块放置 |
| EVENT_INVENTORY_CLICK | INVENTORY_CLICK | 背包操作（含槽位/物品类型） |
| EVENT_ENTITY_SPAWN | ENTITY_SPAWN | 实体生成 |
| EVENT_CHUNK_LOAD | CHUNK_LOAD | 区块加载 |

### 命令类型完整列表

| 命令常量 | 值 | 说明 |
|---------|-----|------|
| CMD_BAN_IP | BAN_IP | 封禁 IP 地址 |
| CMD_BAN_PLAYER | BAN_PLAYER | 封禁玩家账号 |
| CMD_KICK | KICK | 踢出玩家 |
| CMD_CLEAR_LAG | CLEAR_LAG | 清理所有非玩家实体 |
| CMD_SET_SPAWN_RATE | SET_SPAWN_RATE | 动态调整生物生成率 |
| CMD_ENABLE_WHITELIST | ENABLE_WHITELIST | 启用服务器白名单 |
| CMD_DISABLE_WHITELIST | DISABLE_WHITELIST | 关闭服务器白名单 |
| CMD_BROADCAST | BROADCAST | 向全服广播消息 |
| CMD_SAVE_ALL | SAVE_ALL | 强制保存所有世界 |
| CMD_EXECUTE | EXECUTE | 执行任意控制台命令 |

---

## 告警类型完整列表

系统支持 75 种告警类型，定义在 `AlertType.java` 枚举中：

**系统监控（8）：**
PROCESS_DEAD, TPS_LOW, CPU_HIGH, MEM_HIGH, CONNECTION_FLOOD, LOG_ATTACK, BACKUP_FAILED, AI_ANOMALY

**V4.0 反作弊（10）：**
SECURITY_KILL_AURA, SECURITY_REACH, SECURITY_SPEED, SECURITY_JESUS, SECURITY_NOFALL, SECURITY_SCAFFOLD, SECURITY_NUKER, SECURITY_AUTO_CLICKER, SECURITY_AUTO_FISH, SECURITY_FLY

**V5.0 反作弊（6）：**
SECURITY_TIMER, SECURITY_VELOCITY, SECURITY_PHASE, SECURITY_BLINK, SECURITY_FAST_BREAK, SECURITY_ELYTRA_FLY

**V5.1 战斗（10）：**
SECURITY_CRITICALS, SECURITY_AUTO_TOTEM, SECURITY_SURROUND, SECURITY_AUTO_TRAP, SECURITY_AUTO_CRYSTAL, SECURITY_AUTO_ARMOR, SECURITY_CHEST_SWAP, SECURITY_AUTO_LOG, SECURITY_HITBOXES, SECURITY_BOW_AIMBOT

**V5.2 移动（9）：**
SECURITY_NO_SLOW, SECURITY_SPIDER, SECURITY_STEP, SECURITY_PACKET_FLY, SECURITY_AIR_JUMP, SECURITY_LONG_JUMP, SECURITY_ANTI_HUNGER, SECURITY_FAST_FALL, SECURITY_VCLIP

**V5.3 世界/杂物（10）：**
SECURITY_SPEED_MINE, SECURITY_FAST_USE, SECURITY_NO_INTERACT, SECURITY_AUTO_MINE, SECURITY_VEIN_MINER, SECURITY_AUTO_TOOL, SECURITY_FAKE_PLAYER, SECURITY_PISTON_AURA, SECURITY_ANCHOR, SECURITY_STASH_FINDER

**玩家行为（6）：**
SECURITY_CHEST_STEAL, SECURITY_INVENTORY_MANIPULATION, SECURITY_GRIEF, SECURITY_ALT_ACCOUNT, SECURITY_BARITONE, SECURITY_XRAY

**服务器保护（9）：**
SECURITY_SIGN_EXPLOIT, SECURITY_BOOK_BAN, SECURITY_RESOURCE_PACK_EXPLOIT, SECURITY_TAB_COMPLETE_CRASH, SECURITY_OFFLINE_MODE_SPOOF, SECURITY_CHUNK_RATE, SECURITY_ENTITY_LIMIT, SECURITY_REDSTONE_LAG, SECURITY_CRASH_EXPLOIT

**聊天安全（4）：**
CHAT_FLOOD, CHAT_ADVERTISEMENT, CHAT_PHISHING, COMMAND_ABUSE

**网络安全（9）：**
SECURITY_DDOS, SECURITY_PORT_SCAN, SECURITY_BRUTE_FORCE, SECURITY_VPN_PROXY, SECURITY_DNS_TUNNEL, SECURITY_PROTOCOL_VIOLATION, SECURITY_BOT_FINGERPRINT, SECURITY_NBT_EXPLOIT, SECURITY_HANDSHAKE_ANOMALY

**主机安全（5）：**
SECURITY_REVERSE_SHELL, SECURITY_PROCESS_INJECTION, SECURITY_FILE_TAMPER, SECURITY_BACKDOOR_PLUGIN, SECURITY_CONFIG_TAMPER

**ML 分析（4）：**
ML_BEHAVIOR_ANOMALY, ML_THREAT_ESCALATION, ML_MOVEMENT_PATTERN, ML_COMBAT_PATTERN

**通用（1）：**
SECURITY_OTHER

---

## 测试指南

### 运行全量测试

```bash
cd /opt/AluerIII
./apache-maven-3.9.6/bin/mvn test
```

### 测试规范

本项目遵循严格的测试纪律：
- **打靶试验**：测试必须模拟真实 Minecraft 服务器环境
- **生产对齐**：测试数据和行为必须与实际生产环境对齐
- **双构造函数模式**：每个 Service 类同时提供无参构造函数（用于测试）和 @Autowired 构造函数（用于生产注入）
- **静态工厂方法**：检测结果使用 `clean()`, `blocked()`, `flagged()` 静态工厂方法构建
- **全量验证**：修改前后必须跑全量测试，任何失败必须立即修复

### 构建命令

```bash
# 编译项目
./apache-maven-3.9.6/bin/mvn compile

# 运行全量测试
./apache-maven-3.9.6/bin/mvn test

# 打包（跳过测试，用于快速部署）
./apache-maven-3.9.6/bin/mvn package -DskipTests

# 清理构建产物
./apache-maven-3.9.6/bin/mvn clean
```

---

## 项目结构

```
AluerIII/
├── pom.xml                          # Maven 构建配置
├── application.yml                  # Spring Boot 配置（316 行）
├── CLAUDE.md                        # 开发规范文档
├── README.md                        # 项目说明（中文）
├── README_EN.md                     # 项目说明（English）
├── docs/
│   ├── DEVELOPER.md                 # 开发者参考手册
│   ├── PROJECT_SUMMARY.md           # 项目总览与模块拆解
│   └── USER_MANUAL.md               # 用户手册
├── apache-maven-3.9.6/              # 捆绑的 Maven 3.9.6
├── src/
│   ├── main/java/com/aluer/
│   │   ├── ServerGuardApplication.java    # Spring Boot 主入口
│   │   ├── config/
│   │   │   └── ServerGuardConfig.java     # 完整配置类（1273 行，含 SuperEvolutionConfig）
│   │   ├── model/
│   │   │   └── AlertType.java             # 告警类型枚举（75 种告警类型）
│   │   ├── agent/
│   │   │   └── AgentMessage.java          # Agent 通信协议定义
│   │   ├── security/                      # 安全模块（123 个 Java 文件）
│   │   │   ├── AntiKillAuraService.java
│   │   │   ├── AntiReachService.java
│   │   │   ├── AntiAutoCrystalService.java
│   │   │   ├── ... (120+ 更多)
│   │   │   └── ZeroTrustArchitectureService.java
│   │   ├── ml/                            # ML 模块（4 个文件）
│   │   │   ├── BehavioralProfilingEngine.java
│   │   │   ├── CombatPatternRecognizer.java
│   │   │   ├── MovementPatternAnalyzer.java
│   │   │   └── ThreatScoreAggregator.java
│   │   ├── plugin/                        # Paper 插件实现
│   │   │   ├── AluerPlugin.java           # 插件主入口（JavaPlugin）
│   │   │   ├── AluerCommandExecutor.java  # 命令注册器
│   │   │   ├── bridge/
│   │   │   │   ├── AgentWebSocketClient.java   # WebSocket 客户端
│   │   │   │   ├── DataBridge.java              # 数据格式转换桥接
│   │   │   │   └── InternalCommandExecutor.java # Bukkit API 命令执行器
│   │   │   └── listener/                  # Bukkit 事件监听器（9 个）
│   │   │       ├── BlockEventListener.java     # 方块事件（破坏/放置）
│   │   │       ├── ChatEventListener.java      # 聊天/社交事件
│   │   │       ├── CombatEventListener.java    # 战斗事件（攻击/死亡）
│   │   │       ├── CommandEventListener.java   # 命令执行事件
│   │   │       ├── EntityEventListener.java    # 实体生成/销毁事件
│   │   │       ├── InventoryEventListener.java # 背包/容器事件
│   │   │       ├── PacketEventListener.java    # 原始数据包事件
│   │   │       ├── PlayerEventListener.java    # 玩家加入/退出/移动事件
│   │   │       └── WorldEventListener.java     # 世界/区块事件
│   │   ├── controller/
│   │   │   └── TestController.java        # 测试控制器
│   │   └── websocket/                     # WebSocket 服务端
│   └── main/resources/
│       └── application.yml                # 默认配置文件
└── src/test/                              # 测试代码目录
```

---

## 开发指南

### 快速开始

```bash
# 1. 克隆项目
git clone <repo-url>
cd AluerIII

# 2. 编译项目
./apache-maven-3.9.6/bin/mvn compile

# 3. 运行全量测试
./apache-maven-3.9.6/bin/mvn test

# 4. 打包部署
./apache-maven-3.9.6/bin/mvn package -DskipTests
```

### 环境要求

| 依赖 | 版本 | 说明 |
|------|------|------|
| Java JDK | 21+ | 编译和运行环境 |
| Maven | 3.9.6 | 项目自带捆绑版本 |
| PaperMC | 1.21.1 | Plugin 模式下的 Minecraft 服务端 |

### 开发规范

详见项目根目录 `CLAUDE.md`，核心原则：
- **YOLO 模式**：直接执行，不等确认，不犹豫
- **中文注释**：每个方法和关键逻辑必须有详细中文注释，解释 WHY 而非 WHAT
- **测试纪律**：修改前后必须跑全量测试
- **频繁提交**：每个有意义的改动单独提交 Git，中文 commit message
- **零伪代码**：每一行代码都必须可编译、可运行、可验证

---

## 性能特性

| 指标 | Plugin 模式 | External 模式 |
|------|------------|---------------|
| 通信延迟 | < 1ms（同机 WebSocket） | 取决于 RCON 响应 |
| 事件吞吐 | 50,000+ 事件/秒 | 10,000+ 事件/秒 |
| 在线玩家支持 | 100+ (单 Agent) | 100+ |
| 内存占用 | ~50MB（插件部分） | ~200MB（完整引擎） |
| 模块热开关 | 支持 | 支持 |
| 自动恢复 | 全自动（自愈系统） | 全自动 |
| DDoS 防御 | 多层协同 | 多层协同 |
| AI 决策延迟 | ~45秒（DeepSeek 分析） | ~45秒 |
| 适合场景 | 生产服务器（推荐） | 监控/备份场景 |

---

## 许可证

Proprietary. All rights reserved.
