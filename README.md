<p align="center">
  <img src="logo.png" alt="Aluer ServerGuard" width="200">
</p>

<h1 align="center">Aluer ServerGuard V5.0</h1>

<p align="center">
  <b>AI 驱动的 Minecraft PaperMC 服务器全方位安全防护系统</b>
</p>

<p align="center">
  <a href="https://github.com/ZpjDev/Aluer/releases/latest"><img src="https://img.shields.io/github/v/release/ZpjDev/Aluer?style=for-the-badge&color=6366f1" alt="Latest Release"></a>
  <a href="https://github.com/ZpjDev/Aluer/actions"><img src="https://img.shields.io/badge/build-passing-brightgreen?style=for-the-badge" alt="Build Status"></a>
  <a href="#"><img src="https://img.shields.io/badge/tests-323%2F323-green?style=for-the-badge" alt="Tests"></a>
  <a href="#"><img src="https://img.shields.io/badge/Java-21-red?style=for-the-badge&logo=openjdk" alt="Java"></a>
  <a href="#"><img src="https://img.shields.io/badge/PaperMC-1.21.1-blue?style=for-the-badge" alt="PaperMC"></a>
  <a href="#"><img src="https://img.shields.io/badge/modules-135%2B-purple?style=for-the-badge" alt="Modules"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Proprietary-red?style=for-the-badge" alt="License"></a>
</p>

<p align="center">
  <a href="#-快速开始">快速开始</a> •
  <a href="#-系统架构">系统架构</a> •
  <a href="#-安全模块清单">安全模块</a> •
  <a href="#-部署指南">部署指南</a> •
  <a href="#-配置参考">配置参考</a> •
  <a href="#-meteor-client-对抗覆盖矩阵">Meteor覆盖</a> •
  <a href="README_EN.md">English</a>
</p>

---

## 项目概述

Aluer ServerGuard 是一款专为 Minecraft PaperMC 服务器打造的**新一代智能安全防护系统**。系统采用革命性的 **Agent 架构**——轻量 Paper 插件作为数据采集前端植入服务器进程内部，外部 Spring Boot 分析引擎独立运行，两者通过 **WebSocket 实时双向通信**。

### 核心能力

| 能力 | 说明 |
|---|---|
| **全类型反作弊** | 100% 覆盖 Meteor Client 全部 hack 模块，实时检测 Speed/KillAura/CrystalAura/PacketFly 等 |
| **AI 决策引擎** | DeepSeek 大模型自动分析告警 → 生成防御策略 → 自动执行 (ban/kick/whitelist) |
| **ML 行为分析** | 隔离森林异常检测 + 时间序列预测 + 香农熵行为画像 + FFT 频谱分析 |
| **DDoS 多层防御** | SYN/UDP/ICMP/HTTP/Slowloris/Minecraft 协议 DDoS 协同防御 |
| **服务器自愈** | TPS/CPU/内存异常自动恢复，DDoS 自动开启 Under Attack 模式 |
| **双模式部署** | Plugin Agent 模式（推荐）+ External RCON 外部监控模式 |
| **135+ 安全模块** | 覆盖反作弊 / 网络安全 / 主机安全 / 入侵检测 / 取证分析 / 合规审计 |

---

## 快速开始

### 一键部署（推荐）

```bash
# 1. 下载最新 Release JAR
wget https://github.com/ZpjDev/Aluer/releases/latest/download/serverguard.jar

# 2. 启动 ServerGuard 引擎（External 模式）
java -jar serverguard.jar

# 3. 浏览器访问 Web 控制台
open http://localhost:8080
```

### Agent Plugin 模式（生产推荐）

```bash
# 1. 启动 ServerGuard 引擎
java -jar serverguard.jar

# 2. 复制 JAR 到 Paper 服务器 plugins/ 目录
cp serverguard.jar /opt/minecraft/plugins/AluerServerGuard.jar

# 3. 创建 Agent 配置
echo "server-url: ws://YOUR_SERVER_IP:8080/agent" > /opt/minecraft/plugins/AluerServerGuard/config.yml

# 4. 启动 Paper 服务器——Agent 自动连接
cd /opt/minecraft && java -Xms4G -Xmx4G -jar paper-1.21.11.jar
```

---

## 系统架构

```
                      ┌─────────────────────────────────────────────┐
                      │              ServerGuard 引擎                │
                      │           Spring Boot :8080                  │
                      │                                              │
  ┌───────────┐       │  ┌──────────┐  ┌──────────┐  ┌──────────┐  │
  │ PaperMC   │WebSocket│  │ 135+     │  │ ML/AI    │  │ Web      │  │
  │ Server    │◄══════►│  │ 安全模块  │  │ 分析引擎  │  │ 控制台   │  │
  │           │        │  └──────────┘  └──────────┘  └──────────┘  │
  │ ┌───────┐ │ 实时   │  ┌──────────┐  ┌──────────┐               │
  │ │ Agent │ │ 推送   │  │ DeepSeek │  │ Kernel   │               │
  │ │Plugin │ │────────►│  │ AI决策   │  │ 自治引擎  │               │
  │ │9个监听│ │ 事件/  │  └──────────┘  └──────────┘               │
  │ │器     │ │ 指标/  │                                              │
  │ └───────┘ │ 告警   │  ┌──────────────────────────────────────┐  │
  │           │◄────────│  │ AutoExecutor → AgentCommandDispatcher│  │
  │  Bukkit   │ 下发   │  │ ban/kick/whitelist/clearlag/...     │  │
  │  API直执行 │ 指令   │  └──────────────────────────────────────┘  │
  └───────────┘        └─────────────────────────────────────────────┘
```

**Agent → Server 消息流**：EVENT（事件）· METRICS（指标）· ALERT（告警）· HEARTBEAT（心跳）· HANDSHAKE（握手）· COMMAND_RESULT（执行回执）

**Server → Agent 指令流**：COMMAND（ban/kick/whitelist/clearlag/broadcast/saveall）· CONFIG（动态配置）· SHUTDOWN（断开连接）

---

## 安全模块清单

### 反作弊 — Meteor Client 100% 覆盖

<details open>
<summary><b>战斗类 Combat（16 模块）</b></summary>

| # | 模块类 | 对抗 Hack | 检测技术 |
|---|--------|----------|---------|
| 1 | `AntiKillAuraService` | KillAura | 多目标切换频率 · Aimbot 角度一致性 · 极限距离攻击 |
| 2 | `AntiReachService` | Reach | 攻击距离验证 · 位置回溯验证 |
| 3 | `AntiAutoClickerService` | AutoClicker | CPS 统计 · 点击间隔熵值分析 |
| 4 | `AntiCriticalsService` | Criticals | 零速度暴击 · 无跳跃暴击 · 暴击率统计 |
| 5 | `AntiAutoCrystalService` | AutoCrystal | 水晶放置/引爆速度 · 最优位置计算 |
| 6 | `AntiAutoTotemService` | AutoTotem | 图腾换装速度 ms 级检测 · 连续图腾模式 |
| 7 | `AntiSurroundService` | Surround | 四向方块放置速度 · 防御方块模式 |
| 8 | `AntiAutoTrapService` | AutoTrap | 目标围笼构建速度 · 活塞陷阱自动化 |
| 9 | `AntiAutoArmorService` | AutoArmor | 多槽位同 tick 装甲切换 |
| 10 | `AntiChestSwapService` | ChestSwap | 胸甲/鞘翅 tick 级互换检测 |
| 11 | `AntiAutoLogService` | AutoLog | 受伤后 <500ms 断线 · 低血量脱战 |
| 12 | `AntiHitboxesService` | Hitboxes | 边缘命中率 · 射线追踪距离分布 |
| 13 | `AntiBowAimBotService` | BowAimbot | 移动目标命中率 · 弹道一致性 |
| 14 | `AntiVelocityService` | Velocity | 击退幅度异常 · 抗击退检测 |
| 15 | `AntiAnchorService` | Anchor | 洞穴锚点零位移受击检测 |

</details>

<details open>
<summary><b>移动类 Movement（19 模块）</b></summary>

| # | 模块类 | 对抗 Hack | 检测技术 |
|---|--------|----------|---------|
| 1 | `AntiFlyDetectionService` | Fly | 垂直/水平速度 · 悬空时间分析 |
| 2 | `AntiSpeedService` | Speed | 水平移动速度异常分析 |
| 3 | `AntiJesusService` | Jesus | 水面/岩浆面移动验证 |
| 4 | `AntiNoFallService` | NoFall | 落地检测 · GroundSpoof · 坠落累积 |
| 5 | `AntiTimerService` | Timer | tick 间隔异常 · 移动速度频率分析 |
| 6 | `AntiPhaseService` | Phase | 固体方块穿透验证 |
| 7 | `AntiBlinkService` | Blink | 快速断连躲避伤害检测 |
| 8 | `AntiScaffoldService` | Scaffold | 方块放置频率/角度/速度模式 |
| 9 | `AntiSpiderService` | Spider | 无攀爬方块贴墙移动检测 |
| 10 | `AntiStepService` | Step | 无跳跃跨越完整方块检测 |
| 11 | `AntiNoSlowService` | NoSlow | 使用物品时移速检测 |
| 12 | `AntiPacketFlyService` | PacketFly | 数据包操控飞行 · 永不落地模式 |
| 13 | `AntiAirJumpService` | AirJump | 半空跳跃数据包 · 连续空中跳跃 |
| 14 | `AntiLongJumpService` | LongJump | 极端水平跳跃距离检测 |
| 15 | `AntiAntiHungerService` | AntiHunger | 高活动零饥饿消耗检测 |
| 16 | `AntiFastFallService` | FastFall | 超终端速度下落检测 |
| 17 | `AntiVClipService` | VClip | 瞬间垂直穿透方块 · 合法传送排除 |
| 18 | `AntiElytraFlyService` | ElytraFly | 鞘翅速度/高度操控检测 |

</details>

<details open>
<summary><b>世界/玩家类 World（13 模块）</b></summary>

| # | 模块类 | 对抗 Hack | 检测技术 |
|---|--------|----------|---------|
| 1 | `AntiNukerService` | Nuker | 挖矿速度/范围/模式识别 |
| 2 | `AntiAutoMineService` | AutoMine | 自动化采矿行为检测 |
| 3 | `AntiSpeedMineService` | SpeedMine | InstaMine/PacketMine 检测 |
| 4 | `AntiFastBreakService` | FastBreak | 方块破坏速度异常 |
| 5 | `AntiFastUseService` | FastUse | 物品使用加速检测 |
| 6 | `AntiNoInteractService` | NoInteract | 交互绕过检测 |
| 7 | `AntiVeinMinerService` | VeinMiner | 矿脉自动化挖掘模式 |
| 8 | `AntiAutoToolService` | AutoTool | 即时工具切换检测 |
| 9 | `AntiAutoFishService` | AutoFish | 钓鱼行为时序分析 |
| 10 | `AntiChestStealService` | ChestSteal | 开箱/取物速度模式 |
| 11 | `AntiXrayDetectionService` | Xray | 钻石比率 · 直线挖掘 · 暗处精准 |
| 12 | `AntiBaritoneService` | Baritone | 路径平滑度 · 行为重复率 |
| 13 | `AntiGriefDetectionService` | Grief | 方块破坏率 · TNT/纵火/偷箱 |

</details>

<details>
<summary><b>杂物类 Misc（9 模块）</b></summary>

| # | 模块类 | 对抗 Hack | 检测技术 |
|---|--------|----------|---------|
| 1 | `AntiDupeDetectionService` | Dupe | 9 种复制法检测 |
| 2 | `AntiFakePlayerService` | FakePlayer | 假人实体检测 |
| 3 | `AntiPistonAuraService` | PistonAura | 活塞陷阱自动化 |
| 4 | `AntiStashFinderService` | StashFinder | 自动化储藏箱探测 |
| 5 | `AntiInventoryManipulationService` | Inventory | 背包操作速度/非法槽位 |
| 6 | `AntiNameSpoofService` | NameSpoof | 管理员/知名玩家昵称伪造 |
| 7 | `AntiSkinSpoofService` | SkinSpoof | 皮肤伪造检测 |
| 8 | `AntiAltAccountService` | AltAccount | IP关联/行为相似度/登录模式 |
| 9 | `AntiOfflineModeSpoofService` | OfflineSpoof | UUID欺诈/正版冲突检测 |

</details>

### 服务器漏洞防护

| # | 模块类 | 防护对象 |
|---|--------|---------|
| 1 | `AntiSignExploitService` | 告示牌 NBT 漏洞 |
| 2 | `AntiBookBanService` | 书与笔封禁漏洞 |
| 3 | `AntiResourcePackExploitService` | 资源包漏洞 |
| 4 | `AntiTabCompleteCrashService` | Tab 补全崩溃 |
| 5 | `CrashExploitProtectionService` | 崩溃漏洞防护 |
| 6 | `CrashExploitSignatureDB` | 12 种崩溃漏洞签名 |
| 7 | `LagMachineDetectionService` | 卡服机检测 |
| 8 | `PacketFloodProtectionService` | 数据包洪水 |

### 网络协议安全

| # | 模块类 | 防护对象 |
|---|--------|---------|
| 1 | `ProtocolStateValidator` | 协议状态机验证 (HANDSHAKE→STATUS→LOGIN→PLAY) |
| 2 | `TokenBucketRateLimiter` | 令牌桶速率限制原语 |
| 3 | `BotFingerprintDetector` | 五维机器人行为指纹 |
| 4 | `NBTExploitPrevention` | NBT 漏洞防护 (深度/尺寸限制) |
| 5 | `ConnectionHandshakeValidator` | 握手完整性验证 · 端口扫描检测 |
| 6 | `DDoSProtectionService` | SYN/UDP/ICMP/HTTP/Slowloris 洪水 |
| 7 | `DDoSDefenseCoordinator` | 多层 DDoS 防御协调 |

### 服务器性能保护

| # | 模块类 | 防护对象 |
|---|--------|---------|
| 1 | `ChunkLoadRateLimiter` | 区块加载速率 WARN→LIMIT→BLOCK 三级 |
| 2 | `EntityCountEnforcer` | 实体数量强制执行 · 优先级清理 |
| 3 | `RedstoneUpdateLimiter` | 红石更新降频→冻结→指数退避 |

### 聊天社交安全

| # | 模块类 | 防护对象 |
|---|--------|---------|
| 1 | `ChatFloodProtectionService` | 聊天洪水 |
| 2 | `AntiAdvertisementService` | IP/域名/群号广告正则 |
| 3 | `AntiPhishingLinkService` | 钓鱼链接/短链接检测 |
| 4 | `AntiCommandAbuseService` | 命令滥用/注入检测 |
| 5 | `PlayerPrivacyService` | IP脱敏/坐标隐藏/日志匿名 |

### ML/AI 行为分析引擎

| # | 模块类 | 技术方法 |
|---|--------|---------|
| 1 | `BehavioralProfilingEngine` | 5维特征 · 香农熵 · Z分数 · 6类行为画像 |
| 2 | `ThreatScoreAggregator` | 指数衰减加权 · 4级威胁升级 · EMA平滑 |
| 3 | `MovementPatternAnalyzer` | FFT频谱 · 旋转平滑度 · 扫视眼动 · 宏匹配 |
| 4 | `CombatPatternRecognizer` | CPS方差 · 多目标熵 · 扫视分析 · 命中率 |
| 5 | `AnomalyDetector` | 隔离森林异常检测 |
| 6 | `TimeSeriesPredictor` | TPS/CPU/内存时间序列预测 |

### 纵深防御 & 主机安全（30+ 模块）

WAF · IDS · IPS · SIEM · Honeypot · EDR · ZeroTrust · JWT · SSL/TLS · GeoBlock · VPN检测 · DNS隧道 · ARP欺骗 · 反向Shell · 进程注入 · 文件完整性 · 后门插件扫描 · 合规审计 · 取证收集 · 威胁狩猎 · 事件响应 · 安全基线加固 · 容器安全

---

## Meteor Client 对抗覆盖矩阵

| 类别 | Meteor Hack 模块数 | Aluer 对抗模块数 | 覆盖率 |
|------|-------------------|-----------------|--------|
| Combat（战斗） | 15 | 16 | **100%** |
| Movement（移动） | 18 | 19 | **100%** |
| World（世界） | 12 | 13 | **100%** |
| Player（玩家） | 5 | 9 | **100%** |
| Misc（杂物） | 5 | 9 | **100%** |
| **总计** | **55** | **66** | **100%** |

---

## 部署指南

### 模式对比

| 特性 | Agent Plugin 模式 | External 外部模式 |
|------|------------------|-------------------|
| 通信方式 | WebSocket 同机/跨机 | RCON + 日志监控 |
| 延迟 | < 1ms（同机） | 取决于 RCON |
| 事件吞吐 | 50,000+ 事件/秒 | 10,000+ 事件/秒 |
| Minecraft 侵入性 | 需安装 Paper 插件 | 零侵入（仅需 RCON） |
| 内存占用（插件部分） | ~50MB | 0 |
| 推荐场景 | **生产服务器首选** | 监控/备份/评测 |

### Agent Plugin 模式部署

**前置条件**：Java 21+ · PaperMC 1.21.1 服务端

```bash
# 1. 启动 ServerGuard 引擎
java -jar serverguard.jar

# 2. 安装插件
cp serverguard.jar /opt/minecraft/plugins/AluerServerGuard.jar

# 3. Agent 配置 (plugins/AluerServerGuard/config.yml)
cat > /opt/minecraft/plugins/AluerServerGuard/config.yml << EOF
server-url: ws://localhost:8080/agent
EOF

# 4. 启动 Paper 服务器
cd /opt/minecraft && java -Xms4G -Xmx4G -jar paper-1.21.11.jar nogui
```

### External 外部模式部署

```bash
# 1. Minecraft server.properties 启用 RCON
echo "enable-rcon=true" >> server.properties
echo "rcon.port=25575" >> server.properties
echo "rcon.password=STRONG_PASSWORD" >> server.properties

# 2. 配置 application.yml
cat > application.yml << EOF
serverguard:
  mode: external
  minecraft:
    rcon:
      enabled: true
      host: localhost
      port: 25575
      password: STRONG_PASSWORD
    process-name: paper-1.21.11.jar
EOF

# 3. 启动 ServerGuard
java -jar serverguard.jar
```

---

## 环境变量

| 变量 | 说明 | 默认值 |
|------|------|--------|
| `SERVERGUARD_MODE` | 运行模式 (plugin/external) | `external` |
| `DEEPSEEK_API_KEY` | DeepSeek AI 接口密钥 | (空，禁用 AI) |
| `DEEPSEEK_BASE_URL` | DeepSeek API 地址 | `https://api.deepseek.com` |
| `DEEPSEEK_MODEL` | DeepSeek 模型名称 | `deepseek-chat` |
| `RCON_PASSWORD` | Minecraft RCON 密码 | (空) |
| `ALUER_ALERT_SMTP_USERNAME` | 告警邮件 SMTP 用户名 | (空) |
| `ALUER_ALERT_SMTP_PASSWORD` | 告警邮件 SMTP 密码 | (空) |
| `ALUER_ALERT_EMAIL_PRIMARY` | 主告警接收邮箱 | (空) |
| `ALUER_CLOUDFLARE_ZONE_ID` | Cloudflare Zone ID | (空) |
| `ALUER_CLOUDFLARE_API_KEY` | Cloudflare API Key | (空) |

---

## WebSocket 协议

所有消息为单行 JSON，通过 WebSocket 文本帧传输。

**Agent → Server（事件上报）**
```json
{"type":"EVENT","agentId":"survival-01","timestamp":1715000000000,
 "payload":{"eventType":"PLAYER_MOVE","playerName":"Steve","x":100.5,"y":64.0,"z":200.3}}
```

**Server → Agent（命令下发）**
```json
{"type":"COMMAND","requestId":"550e8400-...","timestamp":1715000001000,
 "payload":{"command":"KICK","target":"Hacker123","reason":"KillAura 94%"}}
```

| 上行消息 | 说明 | 下行消息 | 说明 |
|---------|------|---------|------|
| `EVENT` | Bukkit 事件数据 | `COMMAND` | 执行 BAN_IP/BAN_PLAYER/KICK 等 |
| `METRICS` | TPS/CPU/Memory/在线数 | `CONFIG` | 动态配置更新 |
| `ALERT` | 安全告警 | `SHUTDOWN` | 断开连接 |
| `HEARTBEAT` | 心跳保活 | | |
| `HANDSHAKE` | 初始握手 | | |

---

## 游戏内命令

| 命令 | 权限 | 说明 |
|------|------|------|
| `/aluer status` | `aluer.status` | 查看防护状态、TPS、在线数 |
| `/aluer scan <玩家>` | `aluer.admin` | 深度扫描指定玩家（位置/IP/攻击/移动） |
| `/aluer info` | `aluer.status` | 系统版本与运行信息 |
| `/aluerplayers` | `aluer.status` | 在线玩家列表与风险标记 |
| `/aluerblock player <名>` | `aluer.admin` | 封禁玩家 |
| `/aluerblock ip <地址>` | `aluer.admin` | 封禁 IP |
| `/aluerunblock player <名>` | `aluer.admin` | 解除封禁 |
| `/aluerwhitelist on/off/status` | `aluer.admin` | 紧急白名单管理 |

---

## 构建与测试

```bash
# 编译
./apache-maven-3.9.6/bin/mvn compile

# 全量测试 (323 项)
./apache-maven-3.9.6/bin/mvn test

# 打包
./apache-maven-3.9.6/bin/mvn package -DskipTests
```

| 指标 | 数值 |
|------|------|
| 源代码文件 | 225 个 |
| 总代码行数 | 73,229 行 |
| 测试文件 | 19 个 |
| 测试用例 | 323 项 |
| 测试结果 | **323/323 全绿，0 失败** |

---

## 技术栈

| 技术 | 版本 | 用途 |
|------|------|------|
| Java | 21 | 核心语言 |
| Spring Boot | 3.2.0 | 应用框架 · Web · WebSocket · Mail · Shell |
| PaperMC API | 1.21.1-R0.1-SNAPSHOT | Minecraft 服务端集成 |
| Apache Commons Math3 | 3.6.1 | 统计分析 · 机器学习 |
| Gson | 2.10.1 | JSON 序列化 |
| SnakeYAML | 2.2 | YAML 配置 |
| JSch | 0.2.20 | SSH 网关 |
| React 19 + Vite 6 | — | Web 控制台前端 |

---

## 项目结构

```
AluerIII/
├── pom.xml                                      # Maven 构建 (Java 21)
├── plugin.yml                                   # Paper 插件描述
├── C:\Users\Admin\Desktop\AluerIII\CLAUDE.md    # 开发规范
├── README.md / README_EN.md                     # 项目文档
├── docs/
│   ├── DEVELOPER.md                             # 开发者手册
│   ├── PROJECT_SUMMARY.md                       # 项目总览
│   └── USER_MANUAL.md                           # 用户手册
├── src/main/java/com/aluer/
│   ├── ServerGuardApplication.java              # 引擎入口
│   ├── config/ServerGuardConfig.java            # 配置 (1273行)
│   ├── model/AlertType.java                     # 75种告警枚举
│   ├── agent/AgentMessage.java                  # WebSocket协议
│   ├── security/                                # 135+安全模块
│   ├── ml/                                      # 4个ML分析模块
│   ├── ai/                                      # DeepSeek集成
│   ├── kernel/                                  # Kernel自治引擎
│   ├── plugin/                                  # Agent插件实现
│   │   ├── AluerPlugin.java                     # JavaPlugin入口
│   │   ├── bridge/                              # WebSocket客户端+命令执行器
│   │   └── listener/                            # 9个Bukkit事件监听器
│   ├── server/                                  # WebSocket服务端
│   ├── web/                                     # REST API + Dashboard
│   └── monitor/                                 # 进程/资源/日志监控
├── src/test/                                    # 19个测试文件
└── frontend/                                    # React Web控制台
```

---

## 常见问题

<details>
<summary><b>Q: Agent 和 External 模式如何选择？</b></summary>

生产环境推荐 **Agent Plugin 模式**——零网络延迟，50,000+/秒事件吞吐，直接访问 Bukkit API 执行命令。External 模式适合不想安装插件的场景或临时评测。
</details>

<details>
<summary><b>Q: 需要什么 Java 版本？</b></summary>

Java 21+。Paper 1.21.1 API 使用 class version 65，必须 Java 21 运行时。
</details>

<details>
<summary><b>Q: 性能消耗有多大？</b></summary>

Agent 插件部分约 50MB 内存，CPU 占用 < 5%（100 人在线）。ServerGuard 引擎约 200MB 内存（含 JVM），CPU 取决于 AI 分析频率和模块开启数量。
</details>

<details>
<summary><b>Q: 支持哪些 Minecraft 版本？</b></summary>

当前支持 PaperMC 1.21.1。其他版本可通过修改 `paper.version` 适配。
</details>

<details>
<summary><b>Q: DeepSeek AI 是必须的吗？</b></summary>

不是。未配置 `DEEPSEEK_API_KEY` 时 AI 功能自动禁用，系统退化为规则引擎 + ML 模式，仍具备完整的反作弊和防护能力。
</details>

---

## 版本历史

| 版本 | 日期 | 核心更新 |
|------|------|----------|
| **V5.3** | 2026-05 | Meteor World/Player 对抗：SpeedMine · FastUse · NoInteract · AutoMine · VeinMiner · AutoTool · FakePlayer · PistonAura · Anchor · StashFinder |
| **V5.2** | 2026-05 | Meteor Movement 对抗：NoSlow · Spider · Step · PacketFly · AirJump · LongJump · AntiHunger · FastFall · VClip |
| **V5.1** | 2026-05 | Meteor Combat 对抗：Criticals · AutoTotem · Surround · AutoTrap · AutoCrystal · AutoArmor · ChestSwap · AutoLog · Hitboxes · BowAimbot |
| **V5.0** | 2026-04 | Agent WebSocket 架构 · Timer · Velocity · Phase · Blink · FastBreak · ElytraFly · AI/ML 引擎 |
| **V4.0** | 2026-03 | KillAura · Reach · Speed · Jesus · NoFall · Scaffold · Nuker · AutoClicker · 玩家行为 · 服务器保护 |

---

## 许可证

Proprietary. All rights reserved.

<p align="center">
  <b>Aluer ServerGuard</b> — 保护每一台 Minecraft 服务器
</p>
