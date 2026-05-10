# Aluer 服务器安全防护系统 - 用户手册

## 目录
1. [系统简介](#系统简介)
2. [功能特性](#功能特性)
3. [安装部署](#安装部署)
4. [快速开始](#快速开始)
5. [AI协作终端](#ai协作终端)
6. [命令参考](#命令参考)
7. [配置说明](#配置说明)
8. [预警系统](#预警系统)
9. [常见问题](#常见问题)

---

## 系统简介

Aluer 是一款专为 Minecraft PaperMC 服务器设计的安全防护系统，集成了 AI 智能决策、DDoS 防护、入侵检测等多种安全功能。系统采用 Java + Spring Boot 开发，支持通过终端命令行或自然语言与系统交互。

### 核心特性
- 🤖 **AI 智能决策** - 基于 DeepSeek API 的智能威胁分析
- 🛡️ **多层防御** - DDoS防护、防火墙、入侵检测、VPN检测
- 📧 **邮件预警** - 实时告警通知管理员
- 🔄 **自动备份** - 定时自动备份服务器数据
- 💬 **聊天过滤** - 智能过滤违规内容和广告

---

## 功能特性

### 安全防护模块
| 模块 | 功能说明 |
|------|----------|
| DDoS防护 | 流量清洗、IP封禁、连接限制 |
| 防火墙 | 灵活规则配置、黑白名单 |
| 入侵检测 (IDS/IPS) | 异常行为识别、自动防御拦截 |
| 端口扫描检测 | 防护恶意扫描 |
| IP信誉查询 | 评估IP风险等级 |
| VPN/代理检测 | 识别并封禁VPN用户 |
| 流量分析 | 实时监控网络流量 |
| 数据包检查 (DPI) | 深度包检测与特征匹配 |

### 高级进阶防护
| 模块 | 功能说明 |
|------|----------|
| WAF防火墙 | 针对Web面板和API的恶意请求防护 |
| 蜜罐系统 (Honeypot) | 诱导并捕获恶意攻击者 |
| 零信任架构 (ZTA) | 强制身份验证、严格的权限控制 |
| Cloudflare 集成 | 自动同步真实玩家IP，联动CDN防御 |
| 反作弊集成 | 自动联动服务端反作弊插件，智能判定 |
| 威胁情报中心 | 全局恶意IP库共享与实时更新 |

### AI 自主防御
- 自动威胁检测与分类
- 智能防御策略选择
- 预测性维护建议
- 自动执行防御动作

### 服务器管理
- 定时自动备份（世界、插件、配置）
- 玩家管理（踢出、封禁、解封）
- 世界管理（动态加载、卸载）
- 高级性能监控与分析 (Profiler)
- 安全审计与数据导出 (Data Export)

---

## 安装部署

### 环境要求
- Java 17 或更高版本
- Ubuntu/Debian 服务器
- 2GB+ 可用内存
- 10GB+ 可用磁盘空间

### 安装步骤

#### 1. 上传文件到服务器
```bash
# 在本地打包
cd /path/to/AluerIII
./apache-maven-3.9.6/bin/mvn package -DskipTests

# 上传 jar 包和配置到服务器
scp target/serverguard-1.0.0.jar user@your-server:/opt/aluer/
scp start.sh user@your-server:/opt/aluer/
```

#### 2. 配置系统服务
```bash
# 创建 systemd 服务文件
sudo nano /etc/systemd/system/aluer.service
```

写入以下内容：
```ini
[Unit]
Description=Aluer ServerGuard
After=network.target

[Service]
Type=simple
User=minecraft
WorkingDirectory=/opt/aluer
ExecStart=/usr/bin/java -jar /opt/aluer/serverguard-1.0.0.jar
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
```

#### 3. 启动服务
```bash
sudo systemctl daemon-reload
sudo systemctl enable aluer
sudo systemctl start aluer

# 查看状态
sudo systemctl status aluer
```

---

## 快速开始

### 启动系统
```bash
# 方式1: 直接运行
java -jar serverguard-1.0.0.jar

# 方式2: 使用启动脚本
./start.sh

# 方式3: 使用系统服务
sudo systemctl start aluer
```

### 首次使用
系统启动后会进入交互式终端：

```
╔══════════════════════════════════════════════════╗
║       欢迎使用 Aluer 服务器安全防护系统          ║
╠══════════════════════════════════════════════════╣
║  输入 help 查看可用命令                          ║
║  输入 ai <命令> 使用AI智能助手                   ║
╚══════════════════════════════════════════════════╝
aluer>
```

---

## AI协作终端

Aluer 的核心特性是可以用自然语言与系统对话。

### 使用方式
在终端输入 `ai` 后跟你的需求：

```
aluer> ai 测试一下服务器
```
系统会自动执行完整服务器测试。

```
aluer> ai 开启防御
```
系统会开启AI自主防御模式。

### 常用对话示例
| 你说 | 系统执行 |
|------|----------|
| 测试一下服务器 | 执行完整测试 |
| 开启防御 | 开启AI防御 |
| 查看安全状态 | 显示安全概览 |
| 帮我备份 | 查看备份记录 |
| 查看世界 | 列出所有世界 |
| 发送预警邮件 | 手动触发预警 |

---

## 命令参考

### 基础命令

#### help - 帮助
```
aluer> help
```
显示所有可用命令。

#### status - 服务器状态
```
aluer> status
```
显示服务器整体状态，包括CPU、内存、连接数等。

#### test - 测试服务器
```
aluer> test                    # 完整测试
aluer> test cpu               # 仅CPU测试
aluer> test memory            # 仅内存测试
aluer> test network           # 仅网络测试
aluer> test security          # 仅安全测试
```

### 安全命令

#### security - 安全状态
```
aluer> security               # 安全总览
aluer> security ddos         # DDoS防护状态
aluer> security firewall      # 防火墙状态
aluer> security intrusion    # 入侵检测状态
aluer> security threats      # AI威胁检测
aluer> security vpn          # VPN检测状态
aluer> security chat         # 聊天过滤状态
```

#### defense - 防御管理
```
aluer> defense                # 查看防御状态
aluer> defense on            # 开启AI防御
aluer> defense off           # 关闭AI防御
aluer> defense list          # 查看防御策略
aluer> defense level high     # 设置防御等级
```

### 管理命令

#### backup - 备份管理
```
aluer> backup                 # 查看备份记录
aluer> backup create         # 创建新备份
aluer> backup status         # 备份服务状态
aluer> backup start          # 启动定时备份
```

#### kick - 踢出玩家
```
aluer> kick PlayerName
```

#### ban - 封禁玩家
```
aluer> ban PlayerName        # 封禁玩家
aluer> ban PlayerName 作弊原因  # 带原因封禁
```

#### unban - 解封玩家
```
aluer> unban PlayerName
```

### 世界管理

#### world - 世界管理
```
aluer> world                 # 查看世界列表
aluer> world load world_nether  # 加载世界
aluer> world unload world_nether # 卸载世界
```

### 网络分析

#### network - 网络分析
```
aluer> network               # 网络统计
aluer> network geoip 1.2.3.4  # IP地理位置
aluer> network reputation 1.2.3.4  # IP信誉查询
aluer> network ports         # 端口扫描检测
```

### 预警系统

#### alert - 邮件预警
```
aluer> alert                 # 查看预警状态
aluer> alert test            # 发送测试邮件
aluer> alert send 服务器异常   # 手动发送告警
```

### 监控命令

#### metrics - 性能指标
```
aluer> metrics               # 指标摘要
aluer> metrics counters      # 查看计数器
aluer> metrics gauges       # 查看计量器
```

#### audit - 安全审计
```
aluer> audit                 # 最近审计事件
aluer> audit recent 20       # 查看最近20条
aluer> audit summary         # 审计摘要
```

#### tasks - 计划任务
```
aluer> tasks                 # 查看任务列表
aluer> tasks start           # 启动任务服务
```

### AI 命令

#### ask - 向AI提问
```
aluer> ask 如何提高服务器安全性?
```

---

## Web 控制面板与 API

Aluer 内置了轻量级的 Web Dashboard 和 RESTful API，方便与 Pterodactyl 等第三方服务器面板集成，或通过网页端实时查看状态。

### 访问方式
启动系统后，可通过 HTTP 协议访问系统 API 服务。

### 常用 API 接口
| 接口路径 | 方法 | 说明 |
|----------|------|------|
| `/api/status` | GET | 获取系统运行状态及时间戳 |
| `/api/server/info` | GET | 获取 Minecraft 服务器名称与版本信息 |
| `/api/performance` | GET | 获取性能指标（TPS, CPU, 内存） |
| `/api/command/execute` | POST | 远程执行 RCON 命令 (参数: `command`) |
| `/api/backup/list` | GET | 获取所有服务器备份列表 |
| `/api/backup/create` | POST | 触发创建新备份 (参数: `name`) |
| `/api/punishment/list` | GET | 获取封禁与禁言记录统计 |

*(提示：在生产环境中，请务必通过反向代理并配置鉴权，以保护 API 接口安全)*

---

## 配置说明

### 配置文件位置
主配置文件: `src/main/resources/application.yml`

### 核心配置项

#### DeepSeek AI 配置
```yaml
deepseek:
  api-key: sk-your-api-key    # API密钥
  enabled: true               # 是否启用
  model: deepseek-chat        # 模型名称
```

#### RCON 配置（用于连接Minecraft服务器）
```yaml
rcon:
  enabled: true
  host: localhost
  port: 25575
  password: your-password
```

#### 邮件预警配置
```yaml
alert:
  email:
    enabled: true
    smtp-host: smtp.qq.com
    smtp-port: 587
    username: your-email@qq.com
    password: your-auth-code
    from: your-email@qq.com
    to:
      - admin@example.com
      - backup@example.com
```

#### 安全模块配置
```yaml
security:
  ddos:
    enabled: true
    threshold: 1000      # 连接数阈值
  firewall:
    enabled: true
  intrusion:
    enabled: true
    alert-level: MEDIUM
```

#### 备份配置
```yaml
backup:
  enabled: true
  interval-hours: 6      # 备份间隔（小时）
  backup-dir: ./backups
  world-dir: /path/to/server/world
  backup-plugins: true
  backup-config: true
```

---

## 预警系统

### 预警类型
系统会自动检测并发送预警：
- ⚠️ 服务器进程停止
- ⚠️ TPS过低
- ⚠️ CPU使用率过高
- ⚠️ 内存使用率过高
- ⚠️ 连接数异常（DDoS攻击）
- ⚠️ 日志中发现攻击行为
- ⚠️ 备份失败

### 手动触发预警
```bash
aluer> alert send 服务器可能遭受攻击
```

### 测试邮件系统
```bash
aluer> alert test
```

---

## 常见问题

### Q: 如何查看AI是否正常工作？
```bash
aluer> ask 你好
```
如果返回AI回答，说明配置正确。

### Q: 收不到邮件预警怎么办？
1. 检查 `application.yml` 中的邮箱配置
2. 确保使用的是授权码而非登录密码
3. 检查垃圾邮件文件夹

### Q: 如何完全停止系统？
```bash
sudo systemctl stop aluer
```

### Q: 如何查看运行日志？
```bash
# Systemd 日志
sudo journalctl -u aluer -f

# 应用日志
tail -f logs/aluer.log
```

### Q: AI防御模式有什么用？
AI防御模式开启后，系统会自动：
- 分析日志中的威胁
- 检测异常流量
- 预测服务器问题
- 自动执行防御动作

### Q: 如何更新系统？
```bash
# 停止服务
sudo systemctl stop aluer

# 备份数据
cp -r /opt/aluer/backups /backup/

# 替换jar包
cp target/serverguard-1.0.0.jar /opt/aluer/

# 重启服务
sudo systemctl start aluer
```

---

## 技术支持

- 问题反馈: https://github.com/aluer/serverguard/issues
- 文档更新: https://docs.aluer.com

---

*Aluer v1.0.0 - 保护您的 Minecraft 服务器*
