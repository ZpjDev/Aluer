# Aluer ServerGuard V5.0 -- 用户手册

## 目录

1. [系统简介](#系统简介)
2. [功能特性概览](#功能特性概览)
3. [安装部署](#安装部署)
4. [配置说明](#配置说明)
5. [命令参考](#命令参考)
6. [Web 控制台使用](#web-控制台使用)
7. [告警与通知](#告警与通知)
8. [故障排查](#故障排查)
9. [性能调优](#性能调优)
10. [常见问题](#常见问题)

---

## 系统简介

Aluer ServerGuard 是一款 AI 驱动的 Minecraft PaperMC 服务器全方位安全防护系统。它提供两种运行模式：

- **Plugin 内嵌模式（推荐）**：以 Paper 插件形式直接在 Minecraft 进程内运行，通过 WebSocket 与外部分析引擎通信。延迟 < 1ms，性能最高。
- **External 外部监控模式**：以独立进程运行，通过 RCON 和日志监控进行外部防护。

本系统包含 135+ 安全模块，覆盖反作弊、DDoS 防御、入侵检测、漏洞防护、聊天安全、主机安全、ML/AI 行为分析等领域。

---

## 功能特性概览

### 核心功能

| 功能 | 说明 |
|------|------|
| AI 行为分析 | 基于 Isolation Forest 的异常检测，自动识别异常玩家行为 |
| DeepSeek 集成 | 大模型自动分析安全告警，生成防御策略并自主执行 |
| 全量反作弊 | 100% 覆盖 Meteor Client 全部 50 个 hack 模块 |
| DDoS 防御 | 多层协同防御（SYN/UDP/ICMP/HTTP/Minecraft 专属） |
| 自愈系统 | TPS/CPU/内存异常自动恢复，自动白名单、自动备份 |
| Web 控制台 | Nebula Console 实时仪表盘，SSH 远程管理 |
| 邮件告警 | SMTP 邮件通知，支持速率限制和多收件人 |
| 备份管理 | 定时全量/增量备份，完整性校验（SHA-256） |
| 定时任务 | 每日重启/清 lag/周备份，全自动调度 |
| 聊天过滤 | 广告/钓鱼/洪水/敏感词检测，自动禁言/踢出 |

---

## 安装部署

### 环境要求

| 依赖 | 最低版本 | 说明 |
|------|---------|------|
| Java JDK | 21 | 编译和运行 |
| PaperMC | 1.21.1 | Minecraft 服务端（Plugin 模式） |
| 操作系统 | Linux (推荐) / Windows | 64 位 |
| 内存 | 512 MB 可用 | 引擎占用 ~200MB |
| 磁盘 | 100 MB | 不含日志和备份 |

### 方式一：Plugin 内嵌模式（推荐）

**步骤 1：编译项目**

```bash
cd /opt/AluerIII
./apache-maven-3.9.6/bin/mvn package -DskipTests
```

**步骤 2：安装插件**

```bash
cp target/serverguard-4.0.0.jar /opt/minecraft/plugins/AluerServerGuard.jar
```

**步骤 3：创建插件配置** `/opt/minecraft/plugins/AluerServerGuard/config.yml`：

```yaml
server-url: ws://localhost:8080/agent
```

**步骤 4：配置环境变量（可选但推荐）**

```bash
export DEEPSEEK_API_KEY="sk-your-api-key"
export ALUER_ALERT_SMTP_USERNAME="your-email@qq.com"
export ALUER_ALERT_SMTP_PASSWORD="your-smtp-password"
export ALUER_ALERT_EMAIL_PRIMARY="admin@example.com"
export RCON_PASSWORD="your-rcon-password"
```

**步骤 5：启动 ServerGuard 引擎**

```bash
java -jar target/serverguard-4.0.0.jar
```

**步骤 6：启动 Minecraft 服务器**

```bash
cd /opt/minecraft
java -Xms4G -Xmx4G -jar paper-1.21.11.jar
```

**验证安装成功：**

查看 Minecraft 控制台输出，应该看到：
```
[AluerServerGuard] Aluer ServerGuard Agent v5.0.0
[AluerServerGuard] 轻量数据采集前端 - 连接外部 ServerGuard 引擎
[AluerServerGuard] WebSocket connected to ws://localhost:8080/agent
```

查看 ServerGuard 控制台输出，应该看到：
```
Agent connected: agent-xxxx
Agent handshake completed: agent-xxxx
```

### 方式二：External 外部监控模式

**步骤 1：编译**

```bash
./apache-maven-3.9.6/bin/mvn package -DskipTests
```

**步骤 2：配置 `application.yml`**

```yaml
serverguard:
  mode: external
  minecraft:
    working-dir: /opt/minecraft
    rcon:
      enabled: true
      host: localhost
      port: 25575
      password: "${RCON_PASSWORD}"
    process-name: paper-1.21.11.jar
```

**步骤 3：在 Minecraft `server.properties` 中启用 RCON**

```properties
enable-rcon=true
rcon.port=25575
rcon.password=your-rcon-password-here
```

**步骤 4：启动 ServerGuard**

```bash
java -jar target/serverguard-4.0.0.jar
```

---

## 配置说明

### 配置文件位置

- **ServerGuard 引擎配置**：`application.yml`（与 JAR 同目录或 classpath）
- **Plugin 插件配置**：`plugins/AluerServerGuard/config.yml`
- **环境变量**：通过 `${ENV_VAR:default}` 语法覆盖

### 配置节导航

`application.yml` 包含以下顶配配置节：

| 配置节 | 说明 | 关键参数 |
|--------|------|---------|
| `serverguard.mode` | 运行模式 | `plugin` / `external` |
| `serverguard.minecraft` | Minecraft 进程管理 | working-dir, process-name, rcon |
| `serverguard.monitor` | 监控阈值 | tps-threshold, cpu-threshold, memory-threshold |
| `serverguard.alert` | 邮件告警 | smtp 配置, 收件人, 速率限制 |
| `serverguard.ai` | AI/ML + DeepSeek | 隔离森林, 预测, 自动执行 |
| `serverguard.security` | 安全防御总配置 | 含 15 个子配置节 |
| `serverguard.dashboard` | Web 控制台 | SSH 网关, 刷新间隔 |
| `serverguard.backup` | 自动备份 | 备份目录, 压缩, 保留数量 |
| `serverguard.schedule` | 定时任务 | 每日重启, 周备份, 清 lag |
| `serverguard.chat-filter` | 聊天过滤 | 广告/钓鱼/洪水/禁言 |
| `serverguard.afk` | AFK 管理 | 超时时间, AFK 区域, 自动踢出 |

### 快速配置示例

**最小化生产配置：**

```yaml
serverguard:
  mode: plugin
  minecraft:
    working-dir: /opt/minecraft
    rcon:
      password: "${RCON_PASSWORD}"
  monitor:
    tps-threshold: 15
    cpu-threshold: 80.0
    memory-threshold: 85.0
  security:
    enabled: true
    super-evolution:
      anti-kill-aura: true
      anti-reach: true
      anti-speed: true
      anti-fly: true
      anti-xray: true
      anti-dupe: true
      # ... 按需启用其他模块
```

**启用全部反作弊模块：**

在 `super-evolution` 节中将所有 `anti-*` 开关设置为 `true`。默认配置中全部模块已默认启用。

### 环境变量参考

| 变量名 | 说明 | 必需 |
|--------|------|------|
| `SERVERGUARD_MODE` | 运行模式（覆盖 mode 配置） | 否 |
| `DEEPSEEK_API_KEY` | DeepSeek API 密钥 | 建议（AI 功能） |
| `DEEPSEEK_BASE_URL` | DeepSeek API 地址 | 否 |
| `DEEPSEEK_MODEL` | 模型名称 | 否 |
| `RCON_PASSWORD` | Minecraft RCON 密码 | 是（External 模式） |
| `ALUER_ALERT_SMTP_USERNAME` | SMTP 发件邮箱 | 建议（告警功能） |
| `ALUER_ALERT_SMTP_PASSWORD` | SMTP 密码/授权码 | 建议（告警功能） |
| `ALUER_ALERT_EMAIL_PRIMARY` | 主告警接收邮箱 | 建议（告警功能） |
| `ALUER_ALERT_EMAIL_SECONDARY` | 备用告警接收邮箱 | 否 |
| `ALUER_CLOUDFLARE_ZONE_ID` | Cloudflare Zone ID | 否 |
| `ALUER_CLOUDFLARE_API_KEY` | Cloudflare API Key | 否 |
| `ALUER_CLOUDFLARE_EMAIL` | Cloudflare 账号邮箱 | 否 |
| `ALUER_WEBHOOK_DISCORD` | Discord Webhook URL | 否 |
| `ALUER_WEBHOOK_SLACK` | Slack Webhook URL | 否 |

---

## 命令参考

### Spring Shell CLI 命令

ServerGuard 引擎启动后提供交互式命令行（Spring Shell），支持以下命令：

#### 系统状态

| 命令 | 说明 |
|------|------|
| `status` | 显示系统运行状态（运行时间、内存、活跃线程） |
| `tps` | 显示当前 TPS 和 MSPT |
| `players` | 列出在线玩家 |
| `metrics` | 显示完整性能指标 |

#### 安全管理

| 命令 | 说明 |
|------|------|
| `ban <player>` | 封禁玩家 |
| `ban-ip <ip>` | 封禁 IP |
| `kick <player> [reason]` | 踢出玩家 |
| `unban <player>` | 解封玩家 |
| `whitelist on\|off` | 启用/关闭白名单 |
| `whitelist add <player>` | 添加白名单 |
| `whitelist remove <player>` | 移除白名单 |

#### 模块管理

| 命令 | 说明 |
|------|------|
| `modules list` | 列出所有安全模块及状态 |
| `modules enable <name>` | 启用指定模块 |
| `modules disable <name>` | 禁用指定模块 |
| `modules status <name>` | 查看模块详细状态 |

#### AI 控制

| 命令 | 说明 |
|------|------|
| `ai status` | 查看 AI 引擎状态 |
| `ai analyze <player>` | 对指定玩家进行 AI 行为分析 |
| `ai report` | 生成当前安全态势报告 |

#### 系统控制

| 命令 | 说明 |
|------|------|
| `save-all` | 强制保存所有世界 |
| `clear-lag` | 清理所有非玩家实体 |
| `backup now` | 立即执行一次备份 |
| `restart [delay]` | 计划重启服务器 |
| `reload-config` | 重新加载配置文件 |

### Minecraft 游戏内命令（Plugin 模式）

当使用 Plugin 模式时，具有 OP 权限的玩家可以在游戏内使用以下命令：

| 命令 | 权限 | 说明 |
|------|------|------|
| `/aluer status` | aluer.status | 显示防护状态 |
| `/aluer tps` | aluer.status | 显示 TPS 信息 |
| `/aluer alerts` | aluer.alerts | 查看最近告警 |
| `/aluer check <player>` | aluer.check | 对玩家执行安全检查 |
| `/aluer report <player>` | aluer.report | 举报可疑玩家 |
| `/aluer reload` | aluer.admin | 重新加载配置 |

---

## Web 控制台使用

### Nebula Console

ServerGuard 内置 Web 控制台（Nebula Console），提供实时仪表盘和远程管理功能。

**访问地址**：`http://<host>:8080`

**主要功能：**

1. **实时仪表盘** — TPS、CPU、内存、在线玩家、告警数实时图表
2. **玩家列表** — 在线玩家详情、威胁评分、行为日志
3. **告警中心** — 历史告警查询、筛选、DeepSeek 分析结果
4. **模块管理** — 查看/启用/禁用各安全模块
5. **SSH 网关** — 通过 Web 终端直接操作服务器
6. **配置管理** — 在线修改配置（需重启生效）

### SSH 网关配置

```yaml
serverguard:
  dashboard:
    ssh-gateway:
      enabled: true
      session-timeout-minutes: 30
      max-sessions: 6
      command-timeout-seconds: 25
      strict-host-key-checking: false
      allow-private-key-paste: true
      require-engine-handshake: true
      handshake-ttl-seconds: 30
```

**使用 SSH 网关：**

1. 打开 Nebula Console
2. 点击 "SSH Terminal"
3. 输入目标主机、端口、用户名
4. 粘贴 SSH 私钥或输入密码
5. 执行引擎握手验证
6. 获得交互式 Shell

---

## 告警与通知

### 告警渠道

| 渠道 | 配置 | 说明 |
|------|------|------|
| 邮件 | `serverguard.alert.email.*` | SMTP 邮件通知 |
| Discord | `serverguard.webhook.discord-url` | Discord Webhook |
| Slack | `serverguard.webhook.slack-url` | Slack Webhook |
| 控制台 | 默认启用 | Spring Shell/日志输出 |
| Web 控制台 | `serverguard.dashboard.enabled` | Nebula Console 实时推送 |

### 告警级别

| 级别 | 说明 | 自动响应 |
|------|------|---------|
| INFO | 信息性通知 | 无 |
| WARNING | 潜在威胁 | 记录日志 |
| CRITICAL | 严重威胁 | 自动防御（如配置） |
| EMERGENCY | 紧急情况 | 全自动响应 + 通知 |

### 邮件告警配置

```yaml
serverguard:
  alert:
    enabled: true
    email:
      smtp-host: smtp.qq.com        # QQ邮箱
      smtp-port: 587
      username: "your-email@qq.com"
      password: "授权码（非密码）"
      to:
        - "admin@example.com"
        - "backup-admin@example.com"
      rate-limit:
        per-type-seconds: 300       # 同类型告警 5 分钟内只发一次
        max-emails-per-minute: 10   # 每分钟最多 10 封
```

**QQ 邮箱 SMTP 配置步骤：**
1. 登录 QQ 邮箱
2. 设置 -> 账户 -> POP3/IMAP/SMTP 服务
3. 开启 SMTP 服务
4. 获取授权码（不是 QQ 密码）
5. 将授权码填入 `password` 字段

---

## 故障排查

### 常见问题与解决方案

#### 1. Plugin 无法连接到 ServerGuard

**症状**：Minecraft 控制台显示 "Failed to connect to ServerGuard"

**排查步骤**：
1. 确认 ServerGuard 引擎已启动：`ps aux | grep serverguard`
2. 确认端口 8080 未被占用：`netstat -tlnp | grep 8080`
3. 检查 `config.yml` 中的 `server-url` 是否正确
4. 检查防火墙是否阻止了 localhost 连接
5. 查看 ServerGuard 日志：`tail -f /var/log/serverguard.log`

#### 2. DeepSeek API 连接失败

**症状**：日志显示 "DeepSeek API error"

**排查步骤**：
1. 确认 API Key 正确设置：`echo $DEEPSEEK_API_KEY`
2. 测试 API 连通性：`curl -H "Authorization: Bearer $DEEPSEEK_API_KEY" https://api.deepseek.com/v1/models`
3. 检查 API 额度是否用尽
4. 检查网络是否需要代理

#### 3. TPS 持续偏低

**症状**：告警 "Low TPS" 频繁触发

**排查步骤**：
1. 使用 `/aluer tps` 查看实时 TPS
2. 检查实体数量：`/aluer status` 中的 Entity Count
3. 手动清理实体：`clear-lag` 命令
4. 调整 `entity-count-enforcer` 阈值
5. 检查 `redstone-update-limiter` 是否启用

#### 4. 误判/误封

**症状**：正常玩家被标记为作弊

**排查步骤**：
1. 使用 `ai analyze <player>` 查看 AI 分析结果
2. 检查该玩家触发了哪些检测模块
3. 调整对应模块的检测阈值
4. 将玩家加入白名单（临时方案）
5. 查看 DeepSeek 告警分析以了解误判原因

#### 5. 构建失败

**症状**：`mvn compile` 或 `mvn test` 失败

**排查步骤**：
1. 确认 Java 版本：`java -version`（需要 Java 21）
2. 清理构建缓存：`./apache-maven-3.9.6/bin/mvn clean`
3. 检查 PaperMC API 仓库是否可访问
4. 查看完整错误日志：`./apache-maven-3.9.6/bin/mvn compile -e`

---

## 性能调优

### TPS 优化

```yaml
serverguard:
  monitor:
    tps-threshold: 15          # 根据服务器性能调整

  security:
    super-evolution:
      # 在低性能服务器上可选择性禁用高开销模块
      entity-count-enforcer: true     # 自动清理过多实体
      redstone-update-limiter: true   # 限制红石更新
      chunk-load-rate-limiter: true   # 限制区块加载
```

### 内存优化

```yaml
serverguard:
  minecraft:
    java-opts: -Xms4G -Xmx4G  # 根据实际内存调整

  monitor:
    memory-threshold: 85.0     # 内存告警阈值

  ai:
    sliding-window-size: 100   # 减小窗口降低内存占用
```

### AI 性能调优

```yaml
serverguard:
  ai:
    use-isolation-forest: true   # 隔离森林（轻量）
    use-prediction: false         # 在低配服务器上关闭预测
    sliding-window-size: 50       # 减小窗口提高响应速度
    anomaly-threshold: 0.8        # 提高阈值减少误报

  security:
    autonomy:
      loop-interval-seconds: 60   # 增大间隔降低 CPU 占用
      max-actions-per-hour: 5     # 限制自动操作频率
```

### 大型服务器推荐配置（100+ 玩家）

```yaml
serverguard:
  monitor:
    tps-threshold: 18            # 更严格的 TPS 阈值
    connection-threshold: 200    # 更高的连接阈值

  security:
    minecraft-defense:
      login-burst-threshold: 30   # 允许更高的登录突发
      bot-swarm-threshold: 30
    ddos-defense:
      syn-flood-threshold: 300
      minecraft-status-threshold: 50

  ai:
    sliding-window-size: 200     # 更大的分析窗口
    deepseek:
      analysis-interval-seconds: 120  # 降低分析频率

  self-healing:
    tps-emergency-threshold: 15  # 更早触发自动恢复
```

### 小型服务器推荐配置（< 20 玩家）

```yaml
serverguard:
  monitor:
    tps-threshold: 12
    cpu-threshold: 90.0

  ai:
    use-prediction: false        # 关闭预测功能节省资源
    sliding-window-size: 50

  security:
    super-evolution:
      # 低资源消耗模块全部启用
      anti-kill-aura: true
      anti-reach: true
      anti-speed: true
      anti-fly: true
      anti-xray: true
      # ... 按需开启
```

---

## 常见问题

### Q1: Plugin 模式和 External 模式如何选择？

**A**: 如果服务器的 PaperMC 版本 >= 1.21.1 且你可以安装插件，强烈推荐 Plugin 模式。Plugin 模式延迟 < 1ms，能够获取完整的 Bukkit 事件数据，检测精度和实时性远超 External 模式。External 模式适用于你无法安装插件或仅需要基础监控的场景。

### Q2: DeepSeek API 是必需的吗？

**A**: 不是必需的，但强烈推荐。没有 DeepSeek，AI 自主分析和自动防御功能将不可用，但所有 135+ 安全模块仍然正常工作。你可以在 `ai.deepseek.enabled: false` 关闭。

### Q3: 如何只启用反作弊功能？

**A**: 在 `application.yml` 的 `super-evolution` 节中，将不需要的模块开关设置为 `false`，仅保留 `anti-*` 相关的反作弊开关。

### Q4: 误封了玩家怎么办？

**A**: 
1. 使用 `unban <player>` 命令立即解封
2. 使用 `ai analyze <player>` 查看 AI 分析结果
3. 调整对应模块的检测阈值或暂时禁用
4. 确保 `self-healing.dry-run: true` 在测试阶段启用（干燥运行不会实际执行封锁）

### Q5: 系统对服务器性能影响有多大？

**A**: 在 Plugin 模式下，插件部分内存占用约 50MB，外部引擎约 200MB。在 50 人服务器上，CPU 额外开销约 5-10%。External 模式下对 Minecraft 进程零影响，但检测能力有限。

### Q6: 如何更新到最新版本？

**A**:
1. 备份当前配置 `cp application.yml application.yml.bak`
2. 拉取最新代码 `git pull`
3. 重新编译 `./apache-maven-3.9.6/bin/mvn package -DskipTests`
4. 重新部署 JAR
5. 对比新旧 `application.yml` 合并新增配置项

### Q7: 日志文件在哪里？

**A**:
- ServerGuard 引擎日志：`/var/log/serverguard.log`（可在 `logging.file.name` 配置）
- Minecraft 服务器日志：`/opt/minecraft/logs/latest.log`
- 告警报告：`./reports/`（可在 `serverguard.report.dir` 配置）

### Q8: 支持哪些 Minecraft 版本？

**A**: 当前基于 PaperMC API 1.21.1-R0.1-SNAPSHOT，理论上兼容 PaperMC 1.21.x 全系列。其他版本需要调整 API 依赖。

---

## 技术支持

- 项目文档：`docs/` 目录
- 开发规范：`CLAUDE.md`
- 项目结构：`README.md`
- API 协议：见 `AgentMessage.java` 源码注释
