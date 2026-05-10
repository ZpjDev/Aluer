# AluerIII 服务器安全防护系统 - 详细项目概括与功能拆解

AluerIII 是一个专为 Minecraft (PaperMC) 服务器设计的高级安全防护与自动化运维系统。它集成了 **AI 驱动威胁感知**、**多层网络安全防御**、**实时监控预警** 与 **自动化管理** 功能。本项目采用 Java 与 Spring Boot 框架构建，具有高度模块化和可扩展的插件式架构。

以下是项目中所有核心模块、包路径及具体类的极其详细的功能拆解：

---

## 1. AI 智能防御与分析模块 (`com.aluer.ai`)
该模块是系统的“大脑”，利用机器学习算法和大型语言模型（如 DeepSeek）进行实时威胁感知、趋势预测与智能决策。

- **`AIAutonomousService`** (自主防御核心)
  - 通过正则匹配和流量模式识别潜在威胁（如 SQL 注入、DDoS 攻击）。
  - 在检测到威胁时，自动执行防御动作（如动态封禁恶意 IP、启用限流）。
- **`AIStrategyEngine`** (智能策略引擎)
  - 根据检测到的威胁严重程度（Severity），动态匹配并下发最佳防御策略（例如：“暴力破解”对应“临时封禁+启用验证码”）。
- **`DeepSeekClient`** (AI 接口集成)
  - 将服务器的异常指标、告警日志发送至 DeepSeek AI 进行深度分析。
  - 自动生成易于理解的健康报告、根本原因分析（RCA）及修复建议。
- **`AnomalyDetector`** (异常检测器)
  - 使用孤立森林（Isolation Forest）等算法检测服务器性能指标（如 CPU、内存突增）中的非典型波动。
- **`AttackDetector`** (协同攻击检测)
  - 关联分析网络连接行为与日志，识别分布式的协同攻击（如慢速连接攻击、僵尸网络扫描）。
- **`TimeSeriesPredictor`** (时间序列预测)
  - 基于历史运行数据预测未来 TPS 走势，提前预警可能的服务器卡顿或内存溢出崩溃。
- **`AdaptiveThreshold`** (自适应阈值控制器)
  - 学习服务器的历史负载模式，动态调整各项监控告警的触发阈值，有效降低误报率。

---

## 2. 核心安全防护系统 (`com.aluer.security`)
系统最庞大的子模块，提供了从网络层（L3/L4）到应用层（L7）的全方位纵深防御体系。

- **`WebApplicationFirewall (WAF)`** (Web 应用防火墙)
  - 针对 Web 控制面板和 API 接口，提供 SQLi、XSS、路径遍历等常见 Web 攻击过滤，并维护客户端请求信誉度。
- **`DDoSProtectionService`** (DDoS 防护引擎)
  - 专防分布式拒绝服务攻击，支持识别 SYN Flood、HTTP Flood、UDP 放大攻击及 ICMP Flood，并执行自动 IP 封禁与流量清洗。
- **`IntrusionDetectionService (IDS)` / `IntrusionPreventionSystem (IPS)`** (入侵检测与防御)
  - 实时扫描服务器内的恶意行为和越权访问，自动阻断非法连接。
- **`SIEMService`** (安全信息与事件管理)
  - 关联不同来源的碎片化事件（如“多次登录失败”+“异常权限变更”），识别出复杂的横向移动或权限提升攻击序列。
- **`IPReputationService` / `GeoIPService`** (IP 信誉与地理位置)
  - 基于全局 IP 黑名单及地理位置库进行流量过滤（如一键屏蔽特定国家或高风险云服务商的流量）。
- **`HoneypotService`** (蜜罐诱捕系统)
  - 通过暴露诱饵端口或伪造的脆弱接口，吸引并捕获扫描者和攻击者，收集威胁情报。
- **`ZeroTrustArchitectureService`** (零信任架构)
  - 实施严格的持续身份验证与最小权限校验，确保内部和外部调用的绝对安全。
- **`AdvancedMalwareDetectionService`** (高级恶意软件扫描)
  - 定期扫描服务器内的可疑文件（如被植入后门的插件）及玩家上传的内容。
- **`FirewallService`** / **`NetworkMonitorService`** (防火墙与网络监控)
  - 管理底层系统防火墙规则（iptables/ufw），监控进出站流量异常。

---

## 3. 监控与指标采集模块 (`com.aluer.monitor` / `com.aluer.metrics`)
负责全天候收集服务器的运行状态，为 AI 决策和控制台提供数据支撑。

- **`ResourceMonitor`** (系统资源监控)
  - 采集底层系统的 CPU 使用率、内存消耗、磁盘 I/O 以及当前 TPS 和在线玩家数。
- **`LogMonitor`** (日志实时分析)
  - 实时追踪 Minecraft 服务端（PaperMC）的 `latest.log`，精准捕获异常崩溃堆栈或安全违规日志。
- **`ProcessMonitor`** (进程守护)
  - 监控 Minecraft 核心进程的存活状态，在检测到异常崩溃时触发自动重启机制。
- **`ConnectionMonitor`** (网络连接监控)
  - 统计并分析入站网络连接的频率，快速检测连接洪水（Connection Flood）或 CC 攻击。
- **`MetricsCollectionService`** (统一指标服务)
  - 将各个 Monitor 采集的数据进行标准化和汇总聚合，供前端 Dashboard 和 AI 模型读取。

---

## 4. 自动化运维与核心调度 (`com.aluer.service` / `com.aluer.schedule`)
统筹全局，确保各模块有序运转，并执行具体的自动化操作。

- **`ServerGuardService`** (系统总控台)
  - 作为 Spring Boot 的启动核心入口，调度所有监控任务，处理告警分发，协调安全模块与 AI 模块的工作流。
- **`AutoExecutor`** (指令自动化执行器)
  - 接收 AI 或安全模块的决策结果，自动将其转化为服务器指令（如踢出玩家、封禁 IP）并执行。
- **`RconClient`** (远程控制台客户端)
  - 通过安全的 RCON 协议与 Minecraft 服务端通信，无缝下发管理指令。
- **`ScheduledTaskService`** (计划任务引擎)
  - 管理所有周期性任务，例如：定时备份世界数据、清理过期日志、定期生成数据统计报表。

---

## 5. Web API 与交互终端 (`com.aluer.web` / `com.aluer.terminal`)
提供用户友好的交互界面与第三方集成接口。

- **`DashboardController`** (Web 面板 API)
  - 提供 RESTful API 接口（如 `/api/status`, `/api/performance`），向前端 Web 界面或 Pterodactyl 等第三方系统暴露实时监控数据、安全日志及配置管理能力。
- **`AITerminal`** (AI 命令行终端)
  - 提供基于 Spring Shell 的交互式控制台。允许管理员通过自然语言（如 `ai 帮我分析一下现在的卡顿原因`）与 AI 助手对话，执行复杂的服务器管理操作。

---

## 6. 辅助管理与合规模块
涵盖服务器日常管理的各类垂直功能。

- **`com.aluer.anticheat.AntiCheatService`** (反作弊联动)
  - 联动服务器内的反作弊插件，汇总玩家违规行为，进行智能封禁判定。
- **`com.aluer.vpn.VPNDetectionService`** (代理与 VPN 检测)
  - 识别并拦截使用代理 IP 或 VPN 的玩家，防止作弊者绕过 IP 封禁。
- **`com.aluer.audit.SecurityAuditService`** (安全审计与日志)
  - 记录所有管理员的敏感操作指令和安全事件变更，确保符合安全合规要求。
- **`com.aluer.backup.BackupService`** (自动容灾备份)
  - 定时或在遭受攻击前，自动对世界地图（World）、插件配置及数据库进行打包和异地备份。
- **`com.aluer.chat.ChatFilterService`** (聊天过滤)
  - 监控游戏内聊天，过滤违规词汇、广告及钓鱼链接。
- **`com.aluer.punishment.PunishmentService`** (惩罚管理)
  - 统一管理玩家的封禁（Ban）、踢出（Kick）及禁言（Mute）记录。

---

## 7. 数据模型与配置管理 (`com.aluer.model` / `com.aluer.config`)
- **`ServerGuardConfig`** (全局参数配置)
  - 映射 `application.yml` 中的参数，包括：各类安全触发阈值、DeepSeek API 密钥、数据库连接及告警邮箱配置等。
- **`AlertEvent`** (告警数据模型)
  - 标准化告警事件结构，包含：告警类型、严重程度、置信度、AI 根因分析及推荐修复动作。
- **`MetricsData`** (性能指标模型)
  - 封装服务器在特定时间点的快照数据，用于历史数据回溯和 AI 时序预测。

---

### 架构总结
AluerIII 采用 **高度解耦的插件式架构**，底层通过 Spring 的依赖注入（DI）机制紧密配合。系统形成了一套 **实时监测 -> AI 深度分析 -> 策略下发 -> 自动防御** 的完整闭环，极大地降低了 Minecraft 服务器运维人员的安全管理成本。