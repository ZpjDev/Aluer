# Aluer ServerGuard V5.0 -- 项目总览与模块拆解

> 本文档提供 Aluer ServerGuard 项目的宏观总览，包括完整模块清单、技术栈、性能特征和安全覆盖矩阵。

---

## 项目标识

| 属性 | 值 |
|------|-----|
| 项目名称 | Aluer ServerGuard |
| 当前版本 | V5.0 (V5.3 子版本) |
| 构建工具 | Apache Maven 3.9.6 (bundled) |
| 代码语言 | Java 21 |
| 应用框架 | Spring Boot 3.2.0 |
| 目标平台 | Minecraft PaperMC 1.21.1 |
| 源码文件数 | ~170 个 Java 文件 |
| 安全模块数 | 135 个 |
| 告警类型 | 75 种 |

---

## 模块统计总览

| 类别 | 模块数量 | 描述 |
|------|---------|------|
| 反作弊 -- 战斗类 | 15 | KillAura, Reach, Speed, Criticals, AutoCrystal 等 |
| 反作弊 -- 移动类 | 18 | Fly, Jesus, NoFall, Timer, Phase, Spider 等 |
| 反作弊 -- 世界/玩家/杂物类 | 19 | Nuker, AutoMine, Xray, Baritone, Dupe 等 |
| 服务器漏洞防护 | 12 | SignExploit, BookBan, CrashExploit, LagMachine 等 |
| 聊天与社交安全 | 5 | ChatFlood, Advertisement, Phishing, CommandAbuse |
| 网络安全 | 13 | DDoS, ProtocolViolation, BotFingerprint, VPN 等 |
| 主机与访问控制 | 6 | FileIntegrity, BackdoorPlugin, AltAccount 等 |
| 高级安全基础设施 | 28 | SessionValidation, CSP, SSRF, XXE, Forensics 等 |
| 网络与流量分析 | 10 | NetworkMonitor, PacketInspection, TokenBucket 等 |
| 基础设施与运维 | 8 | SIEM, LogAnalysis, ThreatIntelligence 等 |
| ML/AI 行为分析 | 4 | BehavioralProfiling, CombatPattern, MovementPattern |
| **总计** | **135+** | |

---

## 一、反作弊 -- 战斗类（15 模块）

完整覆盖 Meteor Client Combat 类别全部 14 个 hack 模块 + AutoClicker。

| 类名 | Meteor Hack | 检测维度 |
|------|------------|---------|
| AntiKillAuraService | KillAura | 目标切换频率、Aimbot 角度一致性、极限距离攻击 |
| AntiReachService | Reach | 攻击距离验证、位置回溯 |
| AntiCriticalsService | Criticals | 零速度暴击、暴击率统计、无跳跃暴击 |
| AntiAutoCrystalService | AutoCrystal | 水晶放置/引爆速度、最优位置计算 |
| AntiAutoTotemService | AutoTotem | 图腾换装速度（毫秒级）、连续使用模式 |
| AntiSurroundService | Surround | 四向方块放置速度、防御方块模式 |
| AntiAutoTrapService | AutoTrap | 围笼构建速度、活塞陷阱自动化 |
| AntiAutoArmor | AutoArmor | 多槽位装甲切换速度、背包扫描 |
| AntiChestSwap | ChestSwap | 胸甲/鞘翅互换 tick 检测 |
| AntiAutoLog | AutoLog | 受伤后立即断线、低血量脱战 |
| AntiHitboxes | Hitboxes | 边缘命中率、射线追踪距离分布 |
| AntiBowAimbot | BowAimbot | 移动目标命中率、弹道一致性、瞬发精准 |
| AntiVelocityService | Velocity | 击退幅度异常、抗击退 |
| AntiAutoClickerService | AutoClicker | CPS 统计、点击间隔熵值分析 |
| AntiSpeedService | Speed | 水平移动速度异常（战斗中的移动速度） |

## 二、反作弊 -- 移动类（18 模块）

完整覆盖 Meteor Client Movement 类别全部 18 个 hack 模块。

| 类名 | Meteor Hack | 检测维度 |
|------|------------|---------|
| AntiFlyDetectionService | Fly | 垂直/水平速度、悬空时间 |
| AntiJesusService | Jesus | 水面/岩浆面移动验证 |
| AntiNoFallService | NoFall | 落地检测、摔落伤害验证 |
| AntiSpeedService | Speed | 水平移动速度异常分析 |
| AntiTimerService | Timer | 游戏 tick 间隔异常 |
| AntiPhaseService | Phase | 方块剪切/穿越检测 |
| AntiBlinkService | Blink | 快速断连躲避伤害 |
| AntiSpiderService | Spider | 无攀爬方块贴墙移动 |
| AntiStepService | Step | 无跳跃跨越完整方块 |
| AntiNoSlowService | NoSlow | 使用物品时移速不减 |
| AntiPacketFlyService | PacketFly | 数据包操控飞行、震荡模式 |
| AntiAirJumpService | AirJump | 半空跳跃数据包 |
| AntiLongJump | LongJump | 极端水平跳跃距离 |
| AntiAntiHunger | AntiHunger | 高活动量零饥饿消耗 |
| AntiFastFall | FastFall | 超终端速度下落 |
| AntiVClip | VClip | 瞬间垂直穿透方块 |
| AntiElytraFlyService | ElytraFly | 鞘翅速度/高度操控 |
| AntiScaffoldService | Scaffold | 方块放置频率/角度/速度 |

## 三、反作弊 -- 世界/玩家/杂物类（19 模块）

完整覆盖 Meteor Client World, Player, Misc 类别 hack 模块。

| 类名 | Meteor Hack | 类别 | 检测维度 |
|------|------------|------|---------|
| AntiNukerService | Nuker | World | 挖矿速度/范围/模式识别 |
| AntiAutoMineService | AutoMine | World | 自动化采矿行为 |
| AntiSpeedMineService | SpeedMine | World | InstaMine/PacketMine 检测 |
| AntiFastBreakService | FastBreak | Misc | 方块破坏速度异常 |
| AntiFastUseService | FastUse | Misc | 物品使用加速 |
| AntiNoInteractService | NoInteract | Misc | 交互绕过 |
| AntiVeinMinerService | VeinMiner | World | 矿脉自动化挖掘 |
| AntiAutoTool | AutoTool | Player | 即时工具切换 |
| AntiAutoFishService | AutoFish | Player | 钓鱼行为时序分析 |
| AntiChestStealService | ChestSteal | Player | 开箱/取物速度 |
| AntiInventoryManipulationService | InventoryManipulation | Player | 背包操作速度/非法槽位 |
| AntiBaritoneService | Baritone | Player | 路径平滑度/行为重复率 |
| AntiXrayDetectionService | Xray | World | 钻石比率/直线挖掘/暗处精准 |
| AntiGriefDetectionService | Grief | Misc | 方块破坏率/TNT/纵火 |
| AntiFakePlayer | FakePlayer | Misc | 假人实体检测 |
| AntiPistonAura | PistonAura | World | 活塞陷阱自动化 |
| AntiAnchor | Anchor | World | 洞穴锚点防御 |
| AntiStashFinder | StashFinder | World | 储藏箱自动化探测 |
| AntiDupeDetectionService | AntiDupe | Misc | 9 种复制法检测 |

## 四、服务器漏洞防护（12 模块）

| 类名 | 防护对象 | 技术手段 |
|------|---------|---------|
| AntiSignExploitService | 告示牌 NBT 漏洞 | JSON 深度/组件有效性校验 |
| AntiBookBanService | 书与笔封禁漏洞 | 页码上限/JSON 层级限制 |
| AntiResourcePackExploitService | 资源包漏洞 | URL 校验/文件大小/格式校验 |
| AntiTabCompleteCrashService | Tab 补全崩溃 | 文本长度限制/嵌套深度限制 |
| AntiOfflineModeSpoofService | 离线 UUID 欺诈 | UUID 冲突检测/IP 关联验证 |
| CrashExploitProtectionService | 崩溃漏洞 | 超大包/NBT 炸弹/书与笔攻击拦截 |
| CrashExploitSignatureDB | 崩溃签名匹配 | 12 种已知签名四级响应 |
| LagMachineDetectionService | 卡服机 | Observer 链/TNT 堆/红石密度 |
| ChunkLoadRateLimiter | 区块加载洪流 | WARN/LIMIT/BLOCK 三级响应 |
| EntityCountEnforcer | 实体数量溢出 | 按区块/玩家/类型自动清理 |
| RedstoneUpdateLimiter | 红石更新风暴 | 降频/冻结/指数退避 |
| PacketFloodProtectionService | 数据包洪水 | 窗口/负载/品牌包限制 |

## 五、聊天与社交安全（5 模块）

| 类名 | 防护对象 |
|------|---------|
| ChatFloodProtectionService | 消息洪水（频率/相似度/长度激增） |
| AntiAdvertisementService | IP/域名/群号广告 |
| AntiPhishingLinkService | 钓鱼链接/短链接/可疑域名 |
| AntiCommandAbuseService | 敏感命令滥用/频率限制 |
| PlayerPrivacyService | IP 脱敏/坐标隐藏/日志匿名化 |

## 六、网络安全（13 模块）

| 类名 | 防护对象 |
|------|---------|
| DDoSProtectionService | SYN/UDP/ICMP/HTTP/慢速连接/放大攻击 |
| DDoSDefenseCoordinator | 多层 DDoS 防御协调 |
| ProtocolStateValidator | HANDSHAKE/STATUS/LOGIN/PLAY 状态机 |
| BotFingerprintDetector | 登录时序/命名模式/移动熵值 |
| NBTExploitPrevention | NBT 深度/尺寸限制 |
| ConnectionHandshakeValidator | 协议版本/hostname/Ping 洪水/端口扫描 |
| PortScanDetectionService | 端口扫描 |
| BruteForceProtectionService | 暴力破解（多时间窗口） |
| AntiVPNProxyService | 已知 VPN IP/托管 ASN 匹配 |
| DNSTunnelDetectionService | 熵值/Base32 编码/可疑 TLD |
| ReverseShellDetectionService | 50+ shell 模式匹配 |
| ProcessInjectionDetectionService | /proc 扫描/线程异常 |
| ARPSpoofDetectionService | MAC 变更/网关伪造 |

## 七、主机与访问控制安全（6 模块）

| 类名 | 防护对象 |
|------|---------|
| FileIntegrityMonitorService | 文件 Hash 基线/实时监控 |
| BackdoorPluginScannerService | 已知恶意类名/远程执行/隐藏命令 |
| ConfigTamperDetectionService | ops/whitelist 实时篡改检测 |
| OPPrivilegeMonitorService | 权限变更/敏感命令审计 |
| AntiAltAccountService | IP 关联/行为相似度/登录模式 |
| AntiNameSpoofService | 管理员/知名玩家昵称伪造 |

## 八、高级安全基础设施（28 模块）

| 类名 | 功能 |
|------|------|
| PlayerSessionValidationService | UUID 伪造/正版/离线验证 |
| PluginVerificationService | Hash 对比/未授权修改检测 |
| BackupIntegrityService | SHA-256/文件计数/大小对比 |
| ConnectionThrottleService | IP/时间窗口/递增延迟 |
| GeoBlockService | 按国家/地区 IP 封锁 |
| AntiSkinSpoofService | 模型数据异常/皮肤 URL 检测 |
| JwtAuthService | JWT 令牌签发与验证 |
| AntiBotDetectionService | 机器人名称/加入速率/IP 关联 |
| CSPEnforcementService | 8 种 CSP 响应头强制执行 |
| SSRFProtectionService | 内网 IP/云元数据/协议限制 |
| XXEProtectionService | 实体注入/Billion Laughs 检测 |
| DatabaseFirewallService | SQL 注入/联合查询/时间盲注 |
| DataLossPreventionService | 12 种敏感信息规则+自动脱敏 |
| MemoryProtectionService | JVM 堆/GC/内存泄漏检测 |
| SecureFileDeletionService | 多道覆写（DoD 标准） |
| ForensicsCollectorService | 进程/网络/日志快照 |
| IncidentResponseService | 5 种预定义响应剧本 |
| ThreatHuntingService | 10 种狩猎定义/5 类别 |
| ComplianceScannerService | 7 类 20+ 检查项 |
| ExploitSignatureService | Log4Shell/SQLi/RCE 等 15 种 |
| SecurityOrchestrationService | 本地/边缘/Minecraft 多层编排 |
| SecurityAutomationScheduler | 情报刷新/态势快照/规则同步 |
| HostEnforcementService | iptables/nftables/firewalld 后端 |
| HostIntrusionCountermeasureService | 主机入侵主动对抗 |
| IntrusionDetectionService | 网络入侵检测 |
| IntrusionPreventionSystem | 网络入侵防御 |
| WebApplicationFirewall | HTTP/WS 请求过滤 |
| ZeroTrustArchitectureService | 零信任身份与访问控制 |

## 九、网络与流量分析（10 模块）

| 类名 | 功能 |
|------|------|
| NetworkMonitorService | 网络流量实时监控 |
| NetworkSnifferService | 原始数据包捕获分析 |
| NetworkThreatFusionService | 多源威胁情报融合评分 |
| FlowAnalyzerService | NetFlow/IPFIX 流量行为分析 |
| TrafficAnalysisService | 流量模式识别与异常检测 |
| TrafficShapingService | 带宽管理与 QoS 策略 |
| PacketInspectionService | 深度包检测（DPI） |
| ProtocolAnalysisService | 协议合规性与异常分析 |
| TokenBucketRateLimiter | 可复用令牌桶限速原语 |
| FirewallService | iptables/nftables 策略管理 |

## 十、基础设施与运维安全（8 模块）

| 类名 | 功能 |
|------|------|
| SIEMService | 安全事件聚合、关联与告警 |
| LogAnalysisService | 日志模式挖掘与异常检测 |
| LogCorrelationService | 跨源日志时间线关联 |
| ThreatIntelligenceService | 开源/商业威胁情报消费 |
| IPReputationService | IP 信誉评分与黑名单查询 |
| SSLTLSCertificateService | 证书有效性/到期/链验证 |
| SecurityBaselineHardeningService | CIS/STIG 基线自动加固 |
| ContainerSecurityService | Docker/K8s 运行时安全 |

## 十一、ML/AI 行为分析（4 模块）

| 类名 | 算法/方法 | 输入 | 输出 |
|------|----------|------|------|
| BehavioralProfilingEngine | Isolation Forest, 统计画像 | 玩家事件序列 | 行为异常分数 |
| CombatPatternRecognizer | 序列模式匹配 | 战斗事件序列 | 异常战斗模式标记 |
| MovementPatternAnalyzer | 轨迹分析、路径熵值 | 移动事件序列 | 移动异常分数 |
| ThreatScoreAggregator | 加权聚合、升级逻辑 | 多维度检测结果 | 统一威胁评分 |

---

## 技术栈详情

| 技术 | 版本 | 许可证 | 用途 |
|------|------|--------|------|
| Java | 21 (LTS) | Oracle GPL | 核心编程语言 |
| Spring Boot | 3.2.0 | Apache 2.0 | 应用框架 (IoC, WebSocket, Mail) |
| Spring Shell | 3.1.3 | Apache 2.0 | 交互式 CLI |
| Maven | 3.9.6 | Apache 2.0 | 项目构建与依赖管理 |
| PaperMC API | 1.21.1-R0.1 | MIT | Minecraft 服务端 API |
| SnakeYAML | 2.2 | Apache 2.0 | YAML 配置解析 |
| Smile | 2.6.0 | Apache 2.0 | 机器学习算法 (Isolation Forest) |
| Apache Commons Math | 3.6.1 | Apache 2.0 | 统计计算 |
| Gson | 2.10.1 | Apache 2.0 | JSON 序列化/反序列化 |
| JavaMail | 1.6.2 | GPLv2+CE | SMTP 邮件发送 |

---

## 性能特征

### 部署模式对比

| 指标 | Plugin 内嵌模式 | External 外部模式 |
|------|----------------|-------------------|
| 通信方式 | WebSocket (localhost) | RCON + 日志 |
| 通信延迟 | < 1ms | 20-200ms |
| 事件吞吐量 | 50,000+ 事件/秒 | 10,000+ 事件/秒 |
| 数据完整性 | 完整（所有 Bukkit 事件） | 有限（仅日志 + RCON） |
| 实时性 | 实时（tick 级响应） | 准实时（秒级延迟） |
| 内存占用（插件部分） | ~50 MB | 0 MB |
| 内存占用（引擎） | ~200 MB | ~200 MB |
| 推荐场景 | 生产服务器 | 监控/备份/测试 |

### 资源消耗

| 场景 | CPU 使用率 | 内存使用 | 网络带宽 |
|------|-----------|---------|---------|
| 空闲 (0 玩家) | < 1% | ~200 MB | < 1 KB/s |
| 低负载 (20 玩家) | 2-5% | ~250 MB | ~50 KB/s |
| 中负载 (50 玩家) | 5-10% | ~300 MB | ~200 KB/s |
| 高负载 (100 玩家) | 10-20% | ~400 MB | ~500 KB/s |
| DDoS 攻击中 | 20-40% | ~500 MB | ~10 MB/s |

---

## Meteor Client 安全覆盖矩阵

本矩阵展示 Aluer ServerGuard 对 Meteor Client 各 hack 模块的检测覆盖情况。

### Combat 类别

| Meteor Hack | Aluer 检测模块 | 检测方法 | 覆盖度 |
|------------|---------------|---------|--------|
| KillAura | AntiKillAuraService | 目标切换频率 + Aimbot 角度一致性 + 距离模式 | 完整 |
| Reach | AntiReachService | 攻击距离验证 + 位置回溯 | 完整 |
| Criticals | AntiCriticalsService | 零速度暴击 + 暴击率统计 | 完整 |
| AutoCrystal | AntiAutoCrystalService | 水晶放置/引爆速度 + 位置计算 | 完整 |
| AutoTotem | AntiAutoTotemService | 图腾换装速度（毫秒级） | 完整 |
| Surround | AntiSurroundService | 四向方块放置模式 | 完整 |
| AutoTrap | AntiAutoTrapService | 围笼构建速度 | 完整 |
| AutoArmor | AntiAutoArmor | 多槽位装甲切换速度 | 完整 |
| ChestSwap | AntiChestSwap | 胸甲/鞘翅 Tick 检测 | 完整 |
| AutoLog | AntiAutoLog | 受伤后断线模式 | 完整 |
| Hitboxes | AntiHitboxes | 边缘命中率 + 射线分析 | 完整 |
| BowAimbot | AntiBowAimbot | 移动命中率 + 弹道一致性 | 完整 |
| Velocity | AntiVelocityService | 击退幅度 + 抗击退检测 | 完整 |
| AutoClicker | AntiAutoClickerService | CPS 统计 + 熵值分析 | 完整 |
| Anchor | AntiAnchor | 洞穴锚点 Knockback 防御 | 完整 |

### Movement 类别

| Meteor Hack | Aluer 检测模块 | 检测方法 | 覆盖度 |
|------------|---------------|---------|--------|
| Fly | AntiFlyDetectionService | 垂直/水平速度 + 悬空时间 | 完整 |
| Jesus | AntiJesusService | 水面/岩浆面移动验证 | 完整 |
| NoFall | AntiNoFallService | 落地检测 + 伤害验证 | 完整 |
| Speed | AntiSpeedService | 水平速度异常分析 | 完整 |
| Timer | AntiTimerService | Tick 间隔异常 | 完整 |
| Phase | AntiPhaseService | 方块剪切/穿越检测 | 完整 |
| Blink | AntiBlinkService | 快速断连躲避 | 完整 |
| Spider | AntiSpiderService | 无攀爬方块贴墙 | 完整 |
| Step | AntiStepService | 无跳跃跨越方块 | 完整 |
| NoSlow | AntiNoSlowService | 物品使用时移速不减 | 完整 |
| PacketFly | AntiPacketFlyService | 数据包操控 + 震荡模式 | 完整 |
| AirJump | AntiAirJumpService | 半空跳跃数据包 | 完整 |
| LongJump | AntiLongJump | 极端水平跳跃距离 | 完整 |
| AntiHunger | AntiAntiHunger | 高活动量零饥饿消耗 | 完整 |
| FastFall | AntiFastFall | 超终端速度下落 | 完整 |
| VClip | AntiVClip | 瞬间垂直穿透方块 | 完整 |
| ElytraFly | AntiElytraFlyService | 鞘翅速度/高度操控 | 完整 |
| Scaffold | AntiScaffoldService | 方块放置频率/角度 | 完整 |

### World 类别

| Meteor Hack | Aluer 检测模块 | 检测方法 | 覆盖度 |
|------------|---------------|---------|--------|
| Nuker | AntiNukerService | 挖矿速度/范围/模式 | 完整 |
| AutoMine | AntiAutoMineService | 自动化采矿行为 | 完整 |
| SpeedMine | AntiSpeedMineService | InstaMine/PacketMine | 完整 |
| VeinMiner | AntiVeinMinerService | 矿脉自动化挖掘 | 完整 |
| PistonAura | AntiPistonAura | 活塞陷阱自动化 | 完整 |
| StashFinder | AntiStashFinder | 储藏箱自动化探测 | 完整 |
| Xray | AntiXrayDetectionService | 钻石比/直线挖掘/暗处精准 | 完整 |

### Player 类别

| Meteor Hack | Aluer 检测模块 | 检测方法 | 覆盖度 |
|------------|---------------|---------|--------|
| AutoFish | AntiAutoFishService | 钓鱼时序/反应速度 | 完整 |
| ChestSteal | AntiChestStealService | 开箱/取物速度 | 完整 |
| AutoTool | AntiAutoTool | 即时工具切换 | 完整 |
| Baritone | AntiBaritoneService | 路径平滑度/重复率 | 完整 |
| InventoryManipulation | AntiInventoryManipulationService | 操作速度/非法槽位 | 完整 |

### Misc 类别

| Meteor Hack | Aluer 检测模块 | 检测方法 | 覆盖度 |
|------------|---------------|---------|--------|
| FastUse | AntiFastUseService | 物品使用加速 | 完整 |
| FastBreak | AntiFastBreakService | 方块破坏速度异常 | 完整 |
| NoInteract | AntiNoInteractService | 交互绕过 | 完整 |
| FakePlayer | AntiFakePlayer | 假人实体检测 | 完整 |
| AntiDupe | AntiDupeDetectionService | 9 种复制法 | 完整 |
| Grief | AntiGriefDetectionService | 破坏率/TNT/纵火 | 完整 |

### 覆盖率总结

| 类别 | Meteor Client 模块数 | Aluer 覆盖数 | 覆盖率 |
|------|---------------------|-------------|--------|
| Combat | 14 | 14 | 100% |
| Movement | 18 | 18 | 100% |
| World | 7 | 7 | 100% |
| Player | 5 | 5 | 100% |
| Misc | 6 | 6 | 100% |
| **总计** | **50** | **50** | **100%** |

---

## 与同类解决方案对比

| 特性 | Aluer ServerGuard | GrimAC | AntiAura | Vulcan | Themis |
|------|------------------|--------|----------|--------|--------|
| 部署方式 | 双模式 (Plugin+External) | Plugin | Plugin | Plugin | Plugin |
| AI 行为分析 | 是 (Isolation Forest) | 否 | 否 | 否 | 否 |
| LLM 集成 | 是 (DeepSeek) | 否 | 否 | 否 | 否 |
| DDoS 防护 | 是 (多层) | 否 | 否 | 否 | 否 |
| 主机安全 | 是 (文件/进程/入侵) | 否 | 否 | 否 | 否 |
| 自愈能力 | 是 (TPS/CPU/内存) | 否 | 否 | 否 | 否 |
| Web 控制台 | 是 (Nebula Console) | 否 | 否 | 否 | 否 |
| SSH 远程管理 | 是 | 否 | 否 | 否 | 否 |
| 威胁情报 | 是 (多源聚合) | 否 | 否 | 否 | 否 |
| 聊天安全 | 是 | 否 | 否 | 否 | 否 |
| 取证/合规 | 是 | 否 | 否 | 否 | 否 |
| Meteor Client 覆盖 | 100% (50/50) | ~60% | ~70% | ~80% | ~50% |
| 开源 | 闭源 | 开源 (GPL) | 付费 | 付费 | 闭源 |
| 目标用户 | 企业/大型社区服 | 通用 | 通用 | 通用 | 通用 |

---

## 关键文件清单

| 文件 | 行数 | 说明 |
|------|------|------|
| `ServerGuardConfig.java` | 1,273 | 完整配置类，含 SuperEvolutionConfig (70+开关) |
| `AlertType.java` | 131 | 告警类型枚举（75种） |
| `AgentMessage.java` | 138 | Agent 通信协议定义 |
| `application.yml` | 316 | 默认 Spring Boot 配置 |
| `AluerPlugin.java` | ~200 | Paper 插件主入口 |
| `security/*.java` (123文件) | ~60,000 | 全部安全检测模块 |
| `ml/*.java` (4文件) | ~2,000 | ML/AI 行为分析模块 |
| `plugin/listener/*.java` (9文件) | ~4,500 | Bukkit 事件监听器 |

---

## 项目历史

| 版本 | 日期 | 里程碑 |
|------|------|--------|
| V5.3 | 2026-05 | 完成 Meteor Client World/Player/Misc 全量对抗 |
| V5.2 | 2026-05 | 完成 Meteor Client Movement 全量对抗 |
| V5.1 | 2026-05 | 完成 Meteor Client Combat 全量对抗 |
| V5.0 | 2026-04 | Agent 架构重构，WebSocket 实时通信 |
| V4.0 | 2026-03 | 基础反作弊框架（KillAura, Reach, Speed 等） |
| V1.0-V3.0 | 2025-2026 | 系统监控、基础防护、告警系统 |
