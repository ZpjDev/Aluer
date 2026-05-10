# Aluer ServerGuard V4.0 — 开发参考手册

## 版本信息

| 项目 | 内容 |
|------|------|
| 版本号 | V4.0 |
| 发布日期 | 2026-05-10 |
| 构建工具 | Apache Maven 3.9.6 (bundled) |
| 运行环境 | Java 17+, Spring Boot 3.2.0 |
| 许可证 | Apache 2.0 |

---

## 目录

1. [技术架构](#1-技术架构)
2. [项目结构](#2-项目结构)
3. [模块详解](#3-模块详解)
4. [核心设计模式](#4-核心设计模式)
5. [配置体系](#5-配置体系)
6. [API 参考](#6-api-参考)
7. [CLI 命令系统](#7-cli-命令系统)
8. [测试策略](#8-测试策略)
9. [构建与部署](#9-构建与部署)
10. [安全机制层次](#10-安全机制层次)
11. [扩展开发指南](#11-扩展开发指南)

---

## 1. 技术架构

### 1.1 总体架构

Aluer ServerGuard 采用分层架构设计，自底向上分为基础层、安全层、AI 决策层与交互层：

```
┌──────────────────────────────────────────────────────┐
│                   交互层 (Interaction)                  │
│  AITerminal (Spring Shell)  │  Dashboard (REST API)   │
├──────────────────────────────────────────────────────┤
│                   AI 决策层 (Intelligence)              │
│  DeepSeekClient  │  AnomalyDetector  │  StrategyEngine│
├──────────────────────────────────────────────────────┤
│                   安全层 (Security)                      │
│  ┌──────────┬──────────┬──────────┬──────────┐       │
│  │ 网络防御  │ 主机安全  │ 应用防护  │ 合规审计  │       │
│  │ DDoS/IDS  │ 进程/内存 │ WAF/CSP  │ 取证/报告 │       │
│  └──────────┴──────────┴──────────┴──────────┘       │
├──────────────────────────────────────────────────────┤
│                   基础层 (Foundation)                    │
│  KernelEngine  │  TaskBus  │  SelfHealing  │  Config  │
└──────────────────────────────────────────────────────┘
```

### 1.2 技术栈

| 层次 | 技术 | 用途 |
|------|------|------|
| 运行时 | Java 17 | 核心语言 |
| 框架 | Spring Boot 3.2.0 | 应用容器、依赖注入、配置管理 |
| CLI | Spring Shell 3.1.3 | 交互式命令行终端 |
| Web | Spring Boot Web (Tomcat) | REST API 服务 |
| 构建 | Maven 3.9.6 | 依赖管理、打包 |
| AI | DeepSeek API | 威胁分析、根因诊断 |
| 数学 | Commons Math 3.6.1 | 孤立森林、统计计算 |
| SSH | JSch 0.2.20 | 远程 SSH 连接 |
| 序列化 | Gson 2.10.1 | JSON 处理 |
| 邮件 | javax.mail 1.6.2 | 告警通知 |
| 前端 | React 19.1 + Vite 6.3 | Web 控制台 |

### 1.3 数据流

```
Minecraft Server ──> ProcessMonitor ──> MetricsService ──> AnomalyDetector
       │                    │                   │                │
       │              LogMonitor              │          DeepSeekClient
       │                    │                   │                │
       └── RconClient ──> AutoExecutor <── AIStrategyEngine <──┘
                                │
                          Dashboard API ──> Web Console
```

---

## 2. 项目结构

```
AluerIII/
├── pom.xml                          # Maven 项目配置
├── apache-maven-3.9.6/              # 内置 Maven（无需系统安装）
├── src/
│   ├── main/java/com/aluer/
│   │   ├── ServerGuardApplication.java    # Spring Boot 启动入口
│   │   ├── ai/                            # AI 智能分析模块 (7 files)
│   │   ├── alert/                         # 邮件告警 (1 file)
│   │   ├── anticheat/                     # 反作弊集成 (1 file)
│   │   ├── audit/                         # 安全审计 (1 file)
│   │   ├── backup/                        # 自动备份 (1 file)
│   │   ├── chat/                          # 聊天过滤 (1 file)
│   │   ├── command/                       # Shell 命令 (2 files)
│   │   ├── config/                        # 配置管理 (2 files)
│   │   ├── console/                       # 运维控制台 (4 files)
│   │   ├── controller/                    # 测试端点 (1 file)
│   │   ├── export/                        # 数据导出 (1 file)
│   │   ├── kernel/                        # 内核引擎 (3 files)
│   │   ├── metrics/                       # 指标采集 (1 file)
│   │   ├── model/                         # 数据模型 (3 files)
│   │   ├── monitor/                       # 系统监控 (4 files)
│   │   ├── notification/                  # Webhook/报告 (2 files)
│   │   ├── profiler/                      # 性能分析 (1 file)
│   │   ├── punishment/                    # 玩家处罚 (1 file)
│   │   ├── schedule/                      # 定时任务 (1 file)
│   │   ├── security/                      # 安全引擎 (85 files)
│   │   ├── service/                       # 核心服务 (4 files)
│   │   ├── terminal/                      # AI 终端 (1 file)
│   │   ├── vpn/                           # VPN 检测 (1 file)
│   │   ├── web/                           # Web 控制台 (5 files)
│   │   └── world/                         # 世界管理 (1 file)
│   ├── main/resources/
│   │   └── application.yml               # 全局配置
│   └── test/java/com/aluer/              # 测试 (12 files, 114 cases)
├── docs/
│   ├── DEVELOPER.md                      # 本文档
│   ├── USER_MANUAL.md                    # 用户手册
│   └── PROJECT_SUMMARY.md               # 功能拆解
├── frontend/                             # React Web 控制台源码
├── forensics/                            # 取证输出目录
├── release/                              # 发布产物
└── README.md                             # 项目概览
```

---

## 3. 模块详解

### 3.1 AI 智能分析模块 (`com.aluer.ai`)

负责威胁感知、异常检测、趋势预测与智能决策。

| 类名 | 功能 | 核心算法 |
|------|------|----------|
| `AIAutonomousService` | 自主威胁感知与自动防御触发 | 正则模式匹配、流量时序分析 |
| `AIStrategyEngine` | 根据威胁严重程度匹配防御策略 | 规则引擎 |
| `DeepSeekClient` | DeepSeek API 集成，深度威胁分析 | LLM 推理 |
| `AnomalyDetector` | 多指标异常检测 | 孤立森林 (Isolation Forest) |
| `AttackDetector` | 协同攻击检测 | 关联分析 |
| `TimeSeriesPredictor` | TPS/内存趋势预测 | 滑动窗口 + 线性回归 |
| `AdaptiveThreshold` | 动态告警阈值调整 | 历史基线学习 |
| `AluerSovereignEngine` | 自主决策总控引擎 | 多信号融合 |

### 3.2 Kernel 内核模块 (`com.aluer.kernel`)

系统级信号处理与任务调度核心。

| 类名 | 功能 |
|------|------|
| `AluerKernelEngine` | 内核脉冲引擎，周期性采集系统信号，维护信号日志与回响队列 |
| `AluerKernelTaskBus` | 异步任务总线，支持任务排队、分发与历史记录 |
| `AluerSelfHealingOrchestrator` | 自愈编排器，检测异常后自动执行恢复剧本（重启/备份/白名单） |

### 3.3 安全引擎 (`com.aluer.security`)

85 个安全服务类，分为以下子类：

#### 3.3.1 网络安全防御

| 服务类 | 防护目标 | 关键技术 |
|--------|----------|----------|
| `DDoSProtectionService` | DDoS 攻击 | SYN/HTTP/UDP/ICMP Flood 检测 |
| `DDoSDefenseCoordinator` | 多层 DDoS 协同防御 | 流量清洗调度 |
| `IntrusionDetectionService` | 入侵检测 | 行为基线偏离 |
| `IntrusionPreventionSystem` | 入侵阻断 | 实时封禁 |
| `FirewallService` | 主机防火墙 | iptables/ufw 规则管理 |
| `NetworkMonitorService` | 网络流量监控 | 带宽统计、连接追踪 |
| `PortScanDetectionService` | 端口扫描检测 | 连接频率 + 端口序列分析 |
| `IPReputationService` | IP 信誉评估 | 黑名单 + 行为评分 |
| `GeoIPService` | IP 地理定位 | GeoIP 数据库查询 |
| `GeoBlockService` | 地理区域封锁 | 国家/地区级拦截 (v3.3) |
| `ConnectionThrottleService` | 连接速率限制 | 多时间窗口 + 递增延迟 (v3.3) |
| `TrafficAnalysisService` | 流量深度分析 | 协议识别、异常流量模式 |
| `TrafficShapingService` | 流量整形 | 带宽限制、优先级队列 |
| `LoadBalancerService` | 负载均衡 | 连接分发 |
| `NetworkThreatFusionService` | 威胁信号融合 | 多源威胁情报合并 |
| `NetworkSegmentationService` | 网络隔离 | 微隔离策略 |
| `NetworkSnifferService` | 网络嗅探 | 原始数据包捕获 |
| `PacketInspectionService` | 深度包检测 | 载荷特征匹配 |
| `ProtocolAnalysisService` | 协议分析 | Minecraft 协议异常 |
| `FlowAnalyzerService` | 流量分析器 | NetFlow/sFlow 分析 |
| `DistributedAttackMitigationService` | 分布式攻击缓解 | 多节点协同防御 |
| `ContainerSecurityService` | 容器安全 | Docker/K8s 安全策略 |

#### 3.3.2 应用层安全

| 服务类 | 防护目标 | 关键技术 |
|--------|----------|----------|
| `WebApplicationFirewall` | Web 应用攻击 | SQLi/XSS/路径遍历过滤 |
| `WafRequestFilter` | HTTP 请求过滤 | Servlet Filter 拦截 |
| `JwtAuthService` | API 身份认证 | JWT 令牌签发/验证 |
| `BruteForceProtectionService` | 暴力破解防护 | 多时间窗口登录失败计数 |
| `AntiBotDetectionService` | 机器人检测 | 名称模式/加入速率/IP 关联 |
| `CSPEnforcementService` | 内容安全策略 | 8 种 HTTP 安全响应头 |
| `XXEProtectionService` | XML 外部实体防护 | Entity 注入检测 |
| `SSRFProtectionService` | 服务端请求伪造防护 | 内网 IP/云元数据/编码绕过 |
| `SessionManagementService` | 会话管理 | 超时/并发/固定 |
| `APIRateLimitService` | API 速率限制 | 令牌桶算法 |
| `RateLimitService` | 通用速率限制 | 滑动窗口 |
| `CommandExecutionGuardService` | 命令执行防护 | 注入检测 |

#### 3.3.3 主机与端点安全

| 服务类 | 防护目标 | 关键技术 |
|--------|----------|----------|
| `ReverseShellDetectionService` | 反向 Shell 检测 | 50+ Shell 模式匹配 |
| `ARPSpoofDetectionService` | ARP 欺骗检测 | MAC 变更/网关伪造监测 |
| `DNSTunnelDetectionService` | DNS 隧道检测 | 香农熵/Base32 编码/可疑 TLD |
| `ExploitSignatureService` | 漏洞特征检测 | 15 种已知漏洞模式匹配 |
| `DatabaseFirewallService` | 数据库防火墙 | SQL 注入/联合查询/时间盲注 |
| `DataLossPreventionService` | 数据防泄漏 | 12 种敏感信息规则/自动脱敏 |
| `MemoryProtectionService` | JVM 内存保护 | 堆/GC/内存泄漏监控 |
| `ProcessInjectionDetectionService` | 进程注入检测 | /proc 扫描/线程异常检测 |
| `SecureFileDeletionService` | 安全文件删除 | 多道覆写 (DoD 5220.22-M) |
| `ForensicsCollectorService` | 取证数据收集 | 进程/网络/日志快照 |
| `IncidentResponseService` | 事件响应自动化 | 5 种预定义响应剧本 |
| `ThreatHuntingService` | 威胁狩猎 | 10 种狩猎定义/5 个 IOC 类别 |
| `ComplianceScannerService` | 合规扫描 | 7 类 20+ 检查项 |
| `SecurityBaselineHardeningService` | 安全基线硬化 | 系统配置加固 |
| `SecurityAutomationScheduler` | 安全自动化调度 | 定时安全任务 |
| `SecurityOrchestrationService` | 安全编排 | 多模块协同 |
| `FileIntegrityMonitorService` | 文件完整性监控 | 哈希比对 |
| `EndpointDetectionResponseService` | 端点检测响应 | 行为监控 |
| `HostEnforcementService` | 主机强制策略 | 内核级防火墙 |
| `HostIntrusionCountermeasureService` | 主机入侵对策 | 自动隔离 |
| `LogAnalysisService` | 日志分析 | 模式匹配与异常检测 |
| `LogCorrelationService` | 日志关联 | 多源日志关联分析 |
| `SIEMService` | 安全信息事件管理 | 事件关联引擎 |
| `EncryptionService` | 加密服务 | AES/RSA 操作 |
| `SSLMonitorService` | SSL 证书监控 | 到期检测 |
| `SSLTLSCertificateService` | SSL/TLS 管理 | 证书生命周期 |

#### 3.3.4 Minecraft 专属安全

| 服务类 | 防护目标 | 关键技术 |
|--------|----------|----------|
| `MinecraftProtocolSecurityService` | 协议层安全 | NBT/数据包校验 |
| `AntiGriefDetectionService` | 反破坏检测 | 方块破坏率/TNT/纵火/偷箱 |
| `AntiXrayDetectionService` | X-ray 透视检测 | 钻石矿比例/直线挖掘/暗处精准 |
| `AntiFlyDetectionService` | 飞行外挂检测 | 垂直/水平速度阈值/悬空时间 |
| `AntiDupeDetectionService` | 物品复制检测 | 堆叠异常/高价值暴涨/9 种复制模式 |
| `CrashExploitProtectionService` | 崩溃漏洞防护 | 超大包/NBT 炸弹/书与笔攻击 |
| `LagMachineDetectionService` | 卡服机检测 | Observer 链/TNT 堆/红石密度 |
| `PlayerSessionValidationService` | 玩家会话验证 | UUID 格式/离线模式/快速切换 (v3.3) |
| `PluginVerificationService` | 插件完整性校验 | SHA-256/文件大小/恶意名称 (v3.3) |
| `AntiSkinSpoofService` | 皮肤伪造检测 | 模型异常/URL 检测/变更频率 (v3.3) |

#### 3.3.5 运维安全

| 服务类 | 功能 |
|--------|------|
| `BackupSecurityService` | 备份安全策略管理 |
| `BackupIntegrityService` | 备份完整性校验 SHA-256 (v3.3) |
| `HoneypotService` | 蜜罐诱捕系统 |
| `ZeroTrustArchitectureService` | 零信任架构 |
| `CloudflareIntegrationService` | Cloudflare CDN 联动 |
| `ThreatIntelligenceService` | 威胁情报中心 |
| `AdvancedMalwareDetectionService` | 恶意软件扫描 |
| `DNSSecurityService` | DNS 安全 |

### 3.4 监控模块 (`com.aluer.monitor`)

| 类名 | 监控目标 | 采集指标 |
|------|----------|----------|
| `ResourceMonitor` | 系统资源 | CPU/内存/磁盘/TPS |
| `LogMonitor` | 服务端日志 | 异常堆栈/安全事件 |
| `ProcessMonitor` | Minecraft 进程 | 存活状态/重启触发 |
| `ConnectionMonitor` | 网络连接 | 连接数/连接频率 |

### 3.5 核心服务 (`com.aluer.service`)

| 类名 | 功能 |
|------|------|
| `ServerGuardService` | 系统总控，协调所有模块启动与调度 |
| `AutoExecutor` | 自动化指令执行，将 AI 决策转为服务器操作 |
| `RconClient` | RCON 协议客户端，安全下发 Minecraft 指令 |

### 3.6 Web 控制台 (`com.aluer.web`)

| 类名 | 功能 |
|------|------|
| `DashboardController` | 主 API 控制器，48 个 REST 端点 |
| `ConsoleStreamController` | 控制台实时流 |
| `OperationsConsoleController` | 运维操作 API |
| `HealthService` | 健康检查服务 |
| `RequestLoggingFilter` | HTTP 请求日志过滤器 |

---

## 4. 核心设计模式

### 4.1 结果封装模式

所有安全服务采用**内部静态结果类 + 静态工厂方法**模式：

```java
public class SomeSecurityService {
    public static class DetectionResult {
        private final boolean blocked;
        private final List<String> reasons;

        private DetectionResult(boolean blocked, List<String> reasons) { ... }

        public static DetectionResult clean() { return new DetectionResult(false, List.of()); }
        public static DetectionResult blocked(List<String> reasons) { return new DetectionResult(true, reasons); }

        public boolean isBlocked() { return blocked; }
        public List<String> getReasons() { return reasons; }
    }
}
```

优势：不可变、类型安全、语义明确、易于测试断言。

### 4.2 双构造函数模式

所有安全服务实现双构造函数以支持 Spring 注入和单元测试：

```java
public class SomeSecurityService {
    private final ServerGuardConfig config;

    // 无参构造函数 — 测试用
    public SomeSecurityService() {
        this(new ServerGuardConfig());
    }

    // 参数化构造函数 — Spring 注入
    @Autowired
    public SomeSecurityService(ServerGuardConfig config) {
        this.config = config;
    }
}
```

### 4.3 开关控制模式

所有 31 个扩展安全模块通过 `ServerGuardConfig` 统一控制，方法入口处检查：

```java
public DetectionResult detect(String input) {
    if (!config.getSecurity().getSuperEvolution().isXxx()) {
        return DetectionResult.clean();  // 模块关闭，返回安全结果
    }
    // ... 实际检测逻辑
}
```

### 4.4 配置层次绑定

使用 `@ConfigurationProperties(prefix = "serverguard")` 实现类型安全的 YAML 到 Java 映射，支持嵌套静态内部类，每个层级对应 YAML 的一级缩进。

---

## 5. 配置体系

### 5.1 配置层级

```
serverguard
├── minecraft        # Minecraft 服务端连接
│   └── rcon         # RCON 协议配置
├── monitor          # 监控阈值
├── alert            # 告警配置
│   └── email        # 邮件服务
│       └── rate-limit
├── ai               # AI 模块配置
│   └── deepseek     # DeepSeek API
│       └── auto-execute
├── security         # 安全模块配置
│   ├── anti-intrusion
│   │   └── file-integrity
│   ├── host-enforcement
│   ├── cloud-edge
│   ├── orchestration
│   ├── autonomy
│   ├── shield
│   ├── kernel
│   ├── task-bus
│   ├── self-healing
│   └── super-evolution    # 31 个扩展模块独立开关
├── dashboard        # Web 控制台
│   └── ssh-gateway
├── webhook          # 通知集成
└── report           # 报告输出
```

### 5.2 Super Evolution 模块开关 (V4.0 全部 31 个)

所有开关均为 `boolean` 类型，默认值 `true`，位于 `serverguard.security.super-evolution` 路径下：

| 配置键 | 模块名称 | 版本 |
|--------|----------|------|
| `jwt-auth` | JWT 身份认证 | v3.1 |
| `brute-force` | 暴力破解防护 | v3.1 |
| `anti-bot` | 反机器人检测 | v3.1 |
| `reverse-shell` | 反向 Shell 检测 | v3.1 |
| `arp-spoof` | ARP 欺骗检测 | v3.1 |
| `dns-tunnel` | DNS 隧道检测 | v3.1 |
| `exploit-signature` | 漏洞签名检测 | v3.1 |
| `ssrf` | SSRF 防护 | v3.1 |
| `xxe` | XXE 防护 | v3.1 |
| `csp` | CSP 安全头 | v3.1 |
| `database-firewall` | 数据库防火墙 | v3.1 |
| `dlp` | 数据防泄漏 | v3.1 |
| `memory-protection` | 内存保护 | v3.1 |
| `process-injection` | 进程注入检测 | v3.1 |
| `secure-delete` | 安全文件删除 | v3.1 |
| `forensics` | 取证收集 | v3.1 |
| `incident-response` | 事件响应 | v3.1 |
| `threat-hunting` | 威胁狩猎 | v3.1 |
| `compliance` | 合规扫描 | v3.1 |
| `anti-grief` | 反破坏检测 | v3.1 |
| `anti-xray` | X-ray 检测 | v3.2 |
| `anti-fly` | 飞行外挂检测 | v3.2 |
| `anti-dupe` | 物品复制检测 | v3.2 |
| `crash-exploit` | 崩溃漏洞防护 | v3.2 |
| `lag-machine` | 卡服机检测 | v3.2 |
| `geo-block` | 地理 IP 封锁 | v3.3 |
| `session-validation` | 会话验证 | v3.3 |
| `plugin-verification` | 插件校验 | v3.3 |
| `connection-throttle` | 连接速率限制 | v3.3 |
| `backup-integrity` | 备份完整性 | v3.3 |
| `anti-skin-spoof` | 皮肤伪造检测 | v3.3 |

---

## 6. API 参考

所有 API 基于 Spring Boot REST，前缀 `/api`。以下按功能域分组：

### 6.1 系统状态

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/health` | 系统健康检查 |
| GET | `/api/status` | 综合状态概览 |
| GET | `/api/status/ai` | AI 模块状态 |
| GET | `/api/status/monitor` | 监控模块状态 |

### 6.2 安全防御

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/security/ddos/status` | DDoS 防御状态 |
| GET | `/api/security/firewall/status` | 防火墙状态 |
| GET | `/api/security/ids/status` | 入侵检测状态 |
| GET | `/api/security/ips/status` | 入侵防御状态 |
| GET | `/api/security/waf/status` | WAF 状态 |
| GET | `/api/security/ip-reputation/status` | IP 信誉状态 |
| GET | `/api/security/geo-block/status` | 地理封锁状态 (v3.3) |
| GET | `/api/security/session-validation/status` | 会话验证状态 (v3.3) |
| GET | `/api/security/plugin-verification/status` | 插件校验状态 (v3.3) |
| GET | `/api/security/connection-throttle/status` | 连接限制状态 (v3.3) |
| GET | `/api/security/backup-integrity/status` | 备份完整性状态 (v3.3) |
| GET | `/api/security/anti-skin-spoof/status` | 反皮肤伪造状态 (v3.3) |

### 6.3 安全检测（应用层）

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/security/jwt/status` | JWT 认证状态 |
| GET | `/api/security/brute-force/status` | 暴力破解防御状态 |
| GET | `/api/security/anti-bot/status` | 反机器人状态 |
| GET | `/api/security/reverse-shell/status` | 反向 Shell 检测状态 |
| GET | `/api/security/arp-spoof/status` | ARP 欺骗检测状态 |
| GET | `/api/security/dns-tunnel/status` | DNS 隧道状态 |
| GET | `/api/security/exploit-signature/status` | 漏洞签名状态 |
| GET | `/api/security/ssrf/status` | SSRF 防护状态 |
| GET | `/api/security/xxe/status` | XXE 防护状态 |
| GET | `/api/security/csp/status` | CSP 状态 |
| GET | `/api/security/database-firewall/status` | 数据库防火墙状态 |
| GET | `/api/security/dlp/status` | 数据防泄漏状态 |
| GET | `/api/security/memory-protection/status` | 内存保护状态 |
| GET | `/api/security/process-injection/status` | 进程注入检测状态 |
| GET | `/api/security/secure-delete/status` | 安全删除状态 |
| GET | `/api/security/forensics/status` | 取证状态 |
| GET | `/api/security/incident-response/status` | 事件响应状态 |
| GET | `/api/security/threat-hunting/status` | 威胁狩猎状态 |
| GET | `/api/security/compliance/status` | 合规扫描状态 |

### 6.4 Minecraft 专属防御

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/security/anti-grief/status` | 反破坏检测状态 |
| GET | `/api/security/anti-xray/status` | 反 X-ray 状态 |
| GET | `/api/security/anti-fly/status` | 反飞行外挂状态 |
| GET | `/api/security/anti-dupe/status` | 反物品复制状态 |
| GET | `/api/security/crash-exploit/status` | 崩溃漏洞防护状态 |
| GET | `/api/security/lag-machine/status` | 反卡服机状态 |

### 6.5 运维操作

| 方法 | 路径 | 说明 |
|------|------|------|
| POST | `/api/player/kick` | 踢出玩家 |
| POST | `/api/player/ban` | 封禁玩家 |
| POST | `/api/player/unban` | 解封玩家 |
| GET | `/api/player/list` | 在线玩家列表 |
| POST | `/api/world/backup` | 触发世界备份 |
| GET | `/api/world/backup/list` | 备份列表 |
| POST | `/api/world/restore` | 恢复世界备份 |
| GET | `/api/profile` | 性能分析数据 |
| POST | `/api/security/report/generate` | 生成安全报告 |

### 6.6 返回格式

```json
{
  "success": true,
  "data": { ... },
  "timestamp": "2026-05-10T22:00:00+08:00"
}
```

---

## 7. CLI 命令系统

### 7.1 架构

基于 Spring Shell 3.1.3，入口类 `AITerminal` (`@ShellComponent`)。支持 `@ShellMethod` 注解自动注册。

### 7.2 命令分类

| 类别 | 命令数 | 说明 |
|------|--------|------|
| `all` | ~35 | 全部命令列表（默认） |
| `ai` | 6 | AI 分析与策略指令 |
| `status` | 5 | 系统状态查询 |
| `defense` | 8 | 防御模式控制 |
| `security` | 6 | 安全模块管理 |
| `monitor` | 4 | 监控数据查询 |
| `player` | 5 | 玩家管理 |
| `world` | 3 | 世界/备份管理 |
| `admin` | 6 | 管理员运维操作 |

### 7.3 使用示例

```bash
# 启动终端
java -jar AluerServerGuard-V4.0.jar

# 在终端内
help                    # 显示完整命令参考
help ai                 # AI 相关命令
help security           # 安全相关命令
help all                # 全部命令（含 API 端点列表）

# 自然语言交互
分析当前服务器安全状态
查看最近攻击报告
```

---

## 8. 测试策略

### 8.1 测试框架

- JUnit 5 (Jupiter)
- Plain POJO 测试（不加载 Spring 上下文）
- 不依赖 Mockito

### 8.2 测试文件清单

| 测试类 | 用例数 | 覆盖范围 |
|--------|--------|----------|
| `MinecraftSecurityTest` | 21 | 核心安全模块 |
| `SuperEvolutionSecurityTest` | 52 | v3.1/v3.2 扩展模块 |
| `V33SecurityTest` | 29 | v3.3 新模块 (6 个服务) |
| `WebApplicationFirewallTest` | 2 | WAF 引擎 |
| `NetworkThreatFusionServiceTest` | 2 | 威胁融合 |
| `SecurityBaselineHardeningServiceTest` | 1 | 安全基线 |
| `AluerKernelEngineTest` | 2 | 内核引擎 |
| `AluerKernelTaskBusTest` | 1 | 任务总线 |
| `AluerSelfHealingOrchestratorTest` | 1 | 自愈编排 |
| `AluerEngineHandshakeServiceTest` | 1 | 引擎握手 |
| `AluerMirageShieldServiceTest` | 1 | Mirage 盾 |
| `RemoteSshGatewayServiceTest` | 1 | SSH 网关 |
| **总计** | **114** | |

### 8.3 运行测试

```bash
./apache-maven-3.9.6/bin/mvn test
```

### 8.4 测试模式

所有安全服务使用双构造函数，测试中直接 `new ServiceName()` 实例化，无需 Spring 容器。涉及文件 I/O 的测试使用 `/tmp/` 路径配合不存在的文件，避免磁盘污染。

---

## 9. 构建与部署

### 9.1 环境要求

| 项目 | 最低要求 |
|------|----------|
| JDK | 17+ |
| 构建工具 | 内置 Maven 3.9.6 (无需系统安装) |
| 操作系统 | Linux (推荐 Ubuntu 22.04+) |
| 内存 | 建议 2GB+ 可用 |
| 磁盘 | 建议 10GB+ 可用 |

### 9.2 构建命令

```bash
# 编译 + 运行全部测试
./apache-maven-3.9.6/bin/mvn test

# 构建 fat JAR（跳过测试）
./apache-maven-3.9.6/bin/mvn package -DskipTests

# 产物位置
# target/serverguard.jar  (Spring Boot 可执行 fat JAR)
```

### 9.3 部署

```bash
# 复制到目标服务器
scp release/V4.0/AluerServerGuard-V4.0.jar user@server:/opt/aluer/

# 启动（前台测试）
java -jar /opt/aluer/AluerServerGuard-V4.0.jar

# 启动（后台生产）
nohup java -jar /opt/aluer/AluerServerGuard-V4.0.jar > /var/log/aluer.log 2>&1 &

# 或使用 systemd（配置见 systemd/ 目录）
sudo systemctl enable aluer
sudo systemctl start aluer
```

### 9.4 版本发布

发布产物存放于 `release/V4.0/` 目录：

| 文件 | 说明 |
|------|------|
| `AluerServerGuard-V4.0.jar` | Spring Boot fat JAR (~29MB) |

---

## 10. 安全机制层次

系统实现四层纵深防御体系：

```
第一层 — 边界防御
  GeoBlock, ConnectionThrottle, IPReputation, DDoS Protection
  Cloudflare Integration, Port Scan Detection

第二层 — 网络与协议
  Firewall, IDS/IPS, Deep Packet Inspection, Protocol Analysis
  DNS Tunnel Detection, ARP Spoof Detection, Reverse Shell Detection
  DNSSEC, SSL/TLS Monitoring

第三层 — 应用与数据
  WAF, JWT Auth, Brute Force Protection, Anti-Bot
  CSP, XXE Protection, SSRF Protection
  SQL Firewall, DLP, Encryption Service
  Session Management, API Rate Limit

第四层 — 主机与运营
  Memory Protection, Process Injection Detection
  File Integrity Monitoring, Secure Delete, Forensics
  Anti-Cheat (Xray/Fly/Dupe/Grief)
  Crash Exploit, Lag Machine, Skin Spoof
  Plugin Verification, Backup Integrity
  Compliance Scanner, Threat Hunting, Incident Response
```

---

## 11. 扩展开发指南

### 11.1 新增安全模块流程

**步骤 1** — 创建服务类 (`src/main/java/com/aluer/security/NewDetectionService.java`)

```java
package com.aluer.security;

import com.aluer.config.ServerGuardConfig;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

@Service
public class NewDetectionService {

    private final ServerGuardConfig config;
    private final AtomicLong detectionCount = new AtomicLong(0);
    private final Map<String, List<DetectionEvent>> history = new ConcurrentHashMap<>();

    public NewDetectionService() { this(new ServerGuardConfig()); }

    @Autowired
    public NewDetectionService(ServerGuardConfig config) { this.config = config; }

    public DetectionResult detect(String input, String source) {
        if (!config.getSecurity().getSuperEvolution().isNewDetection()) {
            return DetectionResult.clean();
        }
        // 检测逻辑...
        return DetectionResult.clean();
    }

    public Map<String, Object> getStatus() {
        Map<String, Object> s = new LinkedHashMap<>();
        s.put("totalDetections", detectionCount.get());
        return s;
    }

    public static class DetectionResult {
        private final boolean flagged;
        private final List<String> reasons;
        private DetectionResult(boolean f, List<String> r) { this.flagged = f; this.reasons = r; }
        public static DetectionResult clean() { return new DetectionResult(false, List.of()); }
        public static DetectionResult flagged(List<String> r) { return new DetectionResult(true, r); }
        public boolean isFlagged() { return flagged; }
        public List<String> getReasons() { return reasons; }
    }

    private static class DetectionEvent {
        final long timestamp;
        final String source;
        final String input;
        DetectionEvent(long t, String s, String i) {}
    }
}
```

**步骤 2** — 添加配置开关 (`ServerGuardConfig.SuperEvolutionConfig` 中添加 `boolean` 字段)

**步骤 3** — 添加 YAML 配置 (`application.yml` 中添加带中文注释的开关行)

**步骤 4** — 注册 API 端点 (`DashboardController` 中添加 `@GetMapping` 方法)

**步骤 5** — 编写测试 (至少 3 个用例：正常/异常/状态)

**步骤 6** — 更新文档

### 11.2 代码规范

- 使用 `LinkedHashMap` 保持状态 Map 的插入顺序
- 并发场景使用 `ConcurrentHashMap` + `AtomicLong`
- 结果类使用内部静态类，构造函数私有，提供静态工厂方法
- 不引入 Lombok 以外的额外依赖
- 日志使用 Slf4j，级别：WARN（关键事件）、INFO（状态变更）、DEBUG（详细追踪）
- 禁止在安全服务中执行阻塞 I/O 操作；所有文件操作使用异步调度器

---

<div align="center">
  <p><strong>Aluer ServerGuard V4.0</strong></p>
  <p>为 Minecraft 服务器安全构建的专业防护系统</p>
  <p>Apache 2.0 License © 2026</p>
</div>
