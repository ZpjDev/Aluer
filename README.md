<div align="right">

[**English**](README_EN.md) · **简体中文**

</div>

<br>
<p align="center">
  <img src="logo.png" width="200" alt="Aluer ServerGuard 徽标" />
</p>
<br>

<p align="center">
  <img src="https://img.shields.io/badge/Java-17%2B-orange?logo=openjdk&logoColor=white&style=for-the-badge" alt="Java">
  <img src="https://img.shields.io/badge/Spring_Boot-3.2.0-6DB33F?logo=springboot&logoColor=white&style=for-the-badge" alt="Spring Boot">
  <img src="https://img.shields.io/badge/React-19.1-61DAFB?logo=react&logoColor=black&style=for-the-badge" alt="React">
  <img src="https://img.shields.io/badge/Vite-6.3-646CFF?logo=vite&logoColor=white&style=for-the-badge" alt="Vite">
  <img src="https://img.shields.io/badge/DeepSeek-AI-536DFE?logo=openai&logoColor=white&style=for-the-badge" alt="DeepSeek AI">
  <img src="https://img.shields.io/badge/许可证-Apache_2.0-blue?logo=apache&logoColor=white&style=for-the-badge" alt="许可证">
</p>

<p align="center">
  <a href="https://github.com/ZpjDev/Aluer/stargazers"><img src="https://img.shields.io/github/stars/ZpjDev/Aluer?style=for-the-badge&logo=github&color=f1c40f&labelColor=1a1a2e" alt="收藏"></a>
  <a href="https://github.com/ZpjDev/Aluer/network/members"><img src="https://img.shields.io/github/forks/ZpjDev/Aluer?style=for-the-badge&logo=github&color=3498db&labelColor=1a1a2e" alt="复刻"></a>
  <a href="https://github.com/ZpjDev/Aluer/issues"><img src="https://img.shields.io/github/issues/ZpjDev/Aluer?style=for-the-badge&logo=github&color=e74c3c&labelColor=1a1a2e" alt="问题"></a>
  <a href="https://github.com/ZpjDev/Aluer/pulls"><img src="https://img.shields.io/github/issues-pr/ZpjDev/Aluer?style=for-the-badge&logo=github&color=2ecc71&labelColor=1a1a2e" alt="合并请求"></a>
  <a href="https://github.com/ZpjDev/Aluer/commits/main"><img src="https://img.shields.io/github/last-commit/ZpjDev/Aluer?style=for-the-badge&logo=git&color=9b59b6&labelColor=1a1a2e" alt="最后提交"></a>
</p>

---

<h1 align="center">Aluer ServerGuard</h1>

<p align="center">
  <strong>🛡️ AI 驱动的 Minecraft PaperMC 服务器安全防护与自动化运维系统</strong>
</p>

<p align="center">
  <sub>为不愿在安全上妥协的 Minecraft 服主用心构建</sub>
</p>

<blockquote align="center">
  <p>
    <i>"当 DDoS 攻击、机器人潮和零日漏洞威胁着你的 Minecraft 社区，<br>Aluer 以自主守护者的姿态屹立——由 DeepSeek AI 与多层内核融合引擎驱动。"</i>
  </p>
</blockquote>

<p align="center">
  <a href="#-系统架构">🏗 系统架构</a> &nbsp;·&nbsp;
  <a href="#-快速开始">🚀 快速开始</a> &nbsp;·&nbsp;
  <a href="#️-配置参考">⚙️ 配置参考</a> &nbsp;·&nbsp;
  <a href="#-模块清单">📦 模块清单</a> &nbsp;·&nbsp;
  <a href="#-api-参考">🌐 API 参考</a> &nbsp;·&nbsp;
  <a href="#-web-控制台">🖥 Web 控制台</a> &nbsp;·&nbsp;
  <a href="#-shell-命令参考">💻 命令参考</a> &nbsp;·&nbsp;
  <a href="#-faq">❓ 常见问题</a>
</p>

<hr>

<table align="center">
  <tr>
    <td align="center" width="140">
      <img src="https://raw.githubusercontent.com/Tarikul-Islam-Anik/Animated-Fluent-Emojis/master/Emojis/Travel%20and%20places/Rocket.png" width="32" height="32" /><br>
      <strong>2-5秒</strong><br>
      <sub>大模型响应</sub>
    </td>
    <td align="center" width="140">
      <img src="https://raw.githubusercontent.com/Tarikul-Islam-Anik/Animated-Fluent-Emojis/master/Emojis/Objects/Electric%20Plug.png" width="32" height="32" /><br>
      <strong>&lt;1毫秒</strong><br>
      <sub>内核延迟</sub>
    </td>
    <td align="center" width="140">
      <img src="https://raw.githubusercontent.com/Tarikul-Islam-Anik/Animated-Fluent-Emojis/master/Emojis/Objects/Locked%20with%20Key.png" width="32" height="32" /><br>
      <strong>四级</strong><br>
      <sub>防御体系</sub>
    </td>
    <td align="center" width="140">
      <img src="https://raw.githubusercontent.com/Tarikul-Islam-Anik/Animated-Fluent-Emojis/master/Emojis/Smilies/Alien%20Monster.png" width="32" height="32" /><br>
      <strong>30+</strong><br>
      <sub>安全模块</sub>
    </td>
    <td align="center" width="140">
      <img src="https://raw.githubusercontent.com/Tarikul-Islam-Anik/Animated-Fluent-Emojis/master/Emojis/Objects/Bar%20Chart.png" width="32" height="32" /><br>
      <strong>约200MB</strong><br>
      <sub>内存占用</sub>
    </td>
  </tr>
</table>

<hr>

## 目录

- [系统架构](#-系统架构)
  - [三层决策引擎](#1-三层决策引擎)
  - [Kernel 信号融合模型](#2-kernel-信号融合模型)
  - [数据流全景](#3-数据流全景)
- [快速开始](#-快速开始)
  - [环境要求](#环境要求)
  - [本地构建](#本地构建)
  - [环境变量配置](#环境变量配置)
  - [首次启动](#首次启动)
  - [一键安装脚本](#一键安装脚本)
- [部署指南](#-部署指南)
  - [Systemd 服务](#systemd-服务)
  - [sudo 权限配置](#sudo-权限配置)
  - [反向代理（可选）](#反向代理可选)
- [配置参考](#️-配置参考)
  - [完整配置树](#完整配置树)
  - [环境变量注入表](#环境变量注入表)
- [模块清单](#-模块清单)
  - [AI 决策层](#ai-决策层-comaluerai)
  - [Kernel 内核层](#kernel-内核层-comaluerkernel)
  - [安全防护层](#安全防护层-comaluersecurity)
  - [运营控制层](#运营控制层-comaluerconsole)
  - [监控采集层](#监控采集层-comaluermonitor)
  - [核心服务层](#核心服务层-comaluerservice)
  - [Web 交互层](#web-交互层-comaluerweb)
  - [通知与报告层](#通知与报告层-comaluernotification)
  - [辅助功能模块](#辅助功能模块)
  - [数据模型](#数据模型-comaluermodel)
- [防御等级与自动响应](#️-防御等级与自动响应)
- [API 参考](#-api-参考)
  - [系统状态 API](#系统状态-api)
  - [安全态势 API](#安全态势-api)
  - [健康检查 API](#健康检查-api)
  - [通知与报告 API](#通知与报告-api)
  - [控制台操作 API](#控制台操作-api)
  - [SSH 网关 API](#ssh-网关-api)
  - [备份管理 API](#备份管理-api)
- [Web 控制台](#-web-控制台)
- [Shell 命令参考](#-shell-命令参考)
- [开发指南](#-开发指南)
- [常见问题](#-常见问题)
- [许可证](#-许可证)
- [支持项目](#-支持项目)

---

## ✨ 为什么选择 Aluer

<table>
  <tr>
    <td width="50%">
      <h3>🧠 双引擎智能决策</h3>
      <p>大模型（DeepSeek）+ 内核规则引擎协同工作。Sovereign 处理未知威胁，Kernel 在 1 毫秒内响应已知模式。<b>杜绝单点决策失效。</b></p>
    </td>
    <td width="50%">
      <h3>🛡️ 全栈纵深防御</h3>
      <p>从 MC 协议层 → 应用 WAF → 系统防火墙 → Cloudflare 边缘节点。<b>30+ 安全模块</b>覆盖 L3-L7，零信任架构、蜜罐诱捕一应俱全。</p>
    </td>
  </tr>
  <tr>
    <td>
      <h3>📊 实时可视化控制台</h3>
      <p>React 19 星云控制台，SSE 实时流、性能走势条、健康探针、自动刷新——专为<b>应急指挥官</b>设计，一眼看清全局。</p>
    </td>
    <td>
      <h3>🔧 全自动运维</h3>
      <p>自愈编排、恢复前自动备份、定时任务、Discord/Slack 通知、HTML 攻击报告。<b>你睡觉时，服务器自己守着自己。</b></p>
    </td>
  </tr>
</table>

---

## 🧬 系统架构

Aluer ServerGuard 部署在 Minecraft 服务器同一台主机上，通过 **RCON 协议** 与 PaperMC 服务端通信，同时管理操作系统级防火墙（iptables/ufw）和 Cloudflare 边缘防护。

### 1. 三层决策引擎

这是整个系统的核心设计——L1 负责宏观战略决策，L2 负责信号级战术判断，L3 负责执行落地。

```
┌──────────────────────────────────────────────────────────────┐
│                    L1: AluerSovereignEngine                  │
│  输入: 全网态势 JSON（数百个字段的压缩上下文）               │
│  处理: 发送给 DeepSeek LLM，要求返回结构化指令               │
│  输出: workflow（8 种工作流之一）+ defenseLevel + reason     │
│  周期: 每 45 秒执行一次                                      │
│  特征: LLM 主导，具备自然语言推理能力，处理模糊/新类型威胁   │
├──────────────────────────────────────────────────────────────┤
│                    L2: AluerKernelEngine                      │
│  输入: 5 个虚拟模块从 10+ 安全子系统采集的实时信号           │
│  处理: 加权汇聚 → 三维压力计算 → 指令合成                    │
│  输出: heat / resonance / control + KernelDirective          │
│  周期: 每 30 秒一次 Pulse                                    │
│  特征: 确定性规则引擎，可解释，不受 LLM 延迟/幻觉影响        │
├──────────────────────────────────────────────────────────────┤
│                    L3: AIAutonomousService                    │
│  输入: L1 宏观指令 + L2 Kernel 指令                          │
│  处理: 冲突仲裁 → 冷却检查 → 操作限流 → RCON 命令构造       │
│  输出: ban-ip / kick / whitelist / clear-lag / set-spawn-rate │
│  护栏: 每小时最多 12 次操作，高风险操作需双信号确认          │
└──────────────────────────────────────────────────────────────┘
```

**为什么需要两层决策？** Sovereign（DeepSeek）擅长理解新威胁模式，但存在 API 延迟（~2-5 秒）和偶发的非结构化输出。Kernel 是纯规则引擎，延迟 < 1ms，可以在 Sovereign 响应之前对已知威胁模式做出即时反应。两者取交集，互相兜底。

### 2. Kernel 信号融合模型

Kernel 内部运行 5 个虚拟模块（`KernelModule` 接口），每个模块从特定安全子系统采集压力信号：

| 模块 | 名称 | 数据源 | 映射向量 | 基准权重 |
|------|------|--------|----------|----------|
| `ThreatMeshModule` | 威胁网格 | DDoS / 防火墙 / IDS / 端口扫描 / 深度包检测 | `network` | 1.12 |
| `CommandLatticeModule` | 指令晶格 | 命令守卫（危险指令拦截 + RCON 爆破） | `command` | 1.18 |
| `HardeningMatrixModule` | 加固矩阵 | 安全基线审计（漏洞数 × 严重性） | `integrity` | 1.05 |
| `PerimeterWardModule` | 边界护盾 | WAF（被拦截/可疑请求 + 活跃客户端数） | `perimeter` | 0.92 |
| `EchoGridModule` | 回波网格 | 历史 IP 的压力记忆衰减 | `memory` | 0.84 |

每个 Pulse 周期（默认 30s），5 个模块各自产生 0~N 个 `KernelSignal`（module + vector + pressure）。汇聚算法：

```
对于每个信号 signal:
  weighted = clamp(signal.pressure × adaptiveWeight[module], 0, 100)
  vectorScores[signal.vector] += weighted
  moduleScores[signal.module] += weighted

heat     = clamp(peak_vector × 0.68 + average_vector × 0.32, 0, 100)
resonance = clamp(heat × 0.45 + second_vector × 0.18 + energized_count × 14 + signal_count × 2.2, 0, 100)
control  = clamp(100 - heat × 0.62 - resonance × 0.28, 0, 100)
```

自适应权重通过指数移动平均动态调整：

```
target_weight = baseline_weight + (module_pressure ≥ 80 ? 0.18 : module_pressure ≥ 55 ? 0.08 : 0)
active_weight = current × 0.82 + target × 0.18
active_weight = clamp(active_weight, 0.72, 1.45)
```

EchoGrid （攻击者记忆）衰减公式：

```
cell.pressure = cell.pressure × 0.55 + pulse.heat × 0.75
// 超过 retention 时间未更新的 cell 自动清除
```

### 3. 数据流全景

```
                      ┌──────────────┐
                      │  Minecraft    │
                      │  PaperMC      │
                      │  (RCON 25575) │
                      └──┬───────┬──┘
                         │       │
              RCON 指令   │       │ latest.log
              (ban-ip /   │       │ /proc 指标
               kick /     │       │ netstat
               whitelist) │       │
                         │       │
    ┌────────────────────┴───────┴──────────────────────┐
    │                 Aluer ServerGuard                  │
    │                                                    │
    │  ┌──────────┐  ┌──────────┐  ┌──────────┐         │
    │  │ Monitor  │  │ Security │  │   AI     │         │
    │  │ Process  │  │ DDoS/IDS │  │ DeepSeek │         │
    │  │ Resource │  │ WAF/Honey│  │ Anomaly  │         │
    │  │ Connect  │  │ ZeroTrust│  │ Predict  │         │
    │  │ Log      │  │ 30+ svc  │  │ Adaptive │         │
    │  └────┬─────┘  └────┬─────┘  └────┬─────┘         │
    │       │             │             │                │
    │       └─────────┬───┴─────────────┘                │
    │                 │                                  │
    │    ┌────────────┴────────────┐                     │
    │    │  Kernel + Sovereign     │                     │
    │    │  信号融合 + 指令产出    │                     │
    │    └────────────┬────────────┘                     │
    │                 │                                  │
    │    ┌────────────┴────────────┐                     │
    │    │  AutoExecutor / RCON   │                      │
    │    │  指令执行 + 操作记录    │                      │
    │    └────────────────────────┘                      │
    │                                                    │
    │    ┌────────────────────────┐                      │
    │    │  Web Dashboard :8080   │  ← 管理员浏览器       │
    │    │  Spring Shell Terminal │  ← 管理员终端         │
    │    └────────────────────────┘                      │
    └────────────────────────────────────────────────────┘
                         │
                  Cloudflare API
                  (边缘挑战 / 封禁 / Under Attack)
```

---

## 🚀 快速开始

### 环境要求

| 依赖 | 版本 | 说明 |
|------|------|------|
| JDK | 17+ | 编译和运行 |
| Maven | 3.9+（内置） | `apache-maven-3.9.6/` 已打包在仓库中 |
| OS | Ubuntu / Debian | 生产环境推荐，其他 Linux 也可运行但部分安全模块依赖 iptables/ufw |
| Memory | 2 GB+ 可用 | JVM 堆 + Minecraft 服务端本身的内存占用之外 |
| Disk | 10 GB+ | 日志 + 备份 + jar 包 |
| Minecraft | PaperMC 1.21+ | 需开启 RCON（`server.properties` 中 `enable-rcon=true`） |
| DeepSeek | API Key | AI 决策和自然语言问答必需 |
| Node.js | 18+（仅开发前端时需要） | 生产部署使用预构建的静态资源 |

### 本地构建

```bash
# 1. 克隆仓库
git clone https://github.com/ZpjDev/Aluer.git
cd serverguard

# 2. 使用项目内置的 Maven 构建
./apache-maven-3.9.6/bin/mvn clean package -DskipTests

# 3. 产物位置
ls -lh target/serverguard.jar
```

构建过程同时会通过 Vite 编译前端 React 应用，将产物输出到 `src/main/resources/static/`，最终嵌入 jar 包。

### 环境变量配置

**最小可运行配置**（仅需 3 个环境变量）：

```bash
# 必须：DeepSeek API Key（从 https://platform.deepseek.com 获取）
export DEEPSEEK_API_KEY=sk-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx

# 必须：RCON 密码（与 Minecraft server.properties 中 rcon.password 一致）
export RCON_PASSWORD=your-strong-rcon-password
```

**完整生产环境配置**：

```bash
# ──── 核心凭证 ────
export DEEPSEEK_API_KEY=sk-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
export DEEPSEEK_BASE_URL=https://api.deepseek.com          # 可选，默认值
export DEEPSEEK_MODEL=deepseek-chat                         # 可选
export RCON_PASSWORD=your-strong-rcon-password

# ──── 邮件告警（QQ 邮箱示例） ────
export ALUER_ALERT_SMTP_USERNAME=your-email@qq.com
export ALUER_ALERT_SMTP_PASSWORD=your-smtp-auth-code       # QQ 邮箱需使用授权码
export ALUER_ALERT_EMAIL_PRIMARY=admin@example.com
export ALUER_ALERT_EMAIL_SECONDARY=backup@example.com      # 可选

# ──── Cloudflare 边缘防护（可选） ────
export ALUER_CLOUDFLARE_ZONE_ID=your-zone-id
export ALUER_CLOUDFLARE_API_KEY=your-api-key
export ALUER_CLOUDFLARE_EMAIL=your-cloudflare-email
```

> **安全提示**：不要将 API Key 和密码硬编码在 `application.yml` 中。所有敏感配置项都使用 `${VAR_NAME:}` 占位符语法引用环境变量，未设置时使用空字符串作为默认值。

### 首次启动

```bash
# 前台启动（可看到 Spring Shell 交互终端）
java -jar target/serverguard.jar

# 后台启动（使用提供的脚本）
./start.sh

# 使用 systemd（推荐生产环境）
sudo systemctl start serverguard
```

启动成功后会显示 Spring Shell 终端：

```
╔══════════════════════════════════════════════════╗
║       欢迎使用 Aluer 服务器安全防护系统           ║
╠══════════════════════════════════════════════════╣
║  输入 help 查看可用命令                          ║
║  输入 ai <问题> 使用 AI 智能助手                 ║
╚══════════════════════════════════════════════════╝
aluer>
```

验证一切正常：

```bash
# 测试 API
curl http://localhost:8080/api/status

# 预期响应
{"status":"running","timestamp":1746883200000}

# 访问 Web 控制台
curl http://localhost:8080/
```

### 一键安装脚本

```bash
# 使用 sudo 权限执行
sudo bash install.sh
```

该脚本会：
1. 检测/安装 Java 17
2. 创建 `/opt/serverguard/` 工作目录
3. 等待你上传 jar 包（通过 `scp` 或其他方式）
4. 自动创建并启用 systemd 服务
5. 启动服务并验证状态

---

## 📦 部署指南

### Systemd 服务

仓库提供了两个 systemd unit 文件：

**`systemd/minecraft.service`** — Minecraft 服务端（Aluer 的前提依赖）：

```ini
[Unit]
Description=Minecraft PaperMC Server
After=network.target

[Service]
Type=simple
User=minecraft
WorkingDirectory=/opt/minecraft
ExecStart=/usr/bin/java -Xms4G -Xmx4G -jar paper-1.21.11.jar nogui
Restart=on-failure
RestartSec=10
StartLimitBurst=3

[Install]
WantedBy=multi-user.target
```

**`systemd/serverguard.service`** — Aluer 防护系统：

```ini
[Unit]
Description=Aluer ServerGuard Protection System
After=network.target minecraft.service
Requires=minecraft.service

[Service]
Type=simple
User=root
WorkingDirectory=/opt/serverguard
ExecStart=/usr/bin/java -jar serverguard.jar
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

部署步骤：

```bash
# 1. 复制服务文件
sudo cp systemd/minecraft.service /etc/systemd/system/
sudo cp systemd/serverguard.service /etc/systemd/system/

# 2. 创建 minecraft 用户
sudo useradd -r -m -d /opt/minecraft minecraft

# 3. 重新加载 systemd
sudo systemctl daemon-reload

# 4. 先启动 Minecraft，再启动 Aluer
sudo systemctl enable --now minecraft
sudo systemctl enable --now serverguard

# 5. 查看运行状态
sudo systemctl status minecraft serverguard

# 6. 查看 Aluer 日志
sudo journalctl -u serverguard -f
```

### sudo 权限配置

Aluer 需要能执行 `systemctl restart minecraft` 来重启 Minecraft 服务端。将 `systemd/sudoers.serverguard` 复制到 `/etc/sudoers.d/`：

```bash
sudo cp systemd/sudoers.serverguard /etc/sudoers.d/serverguard
sudo chmod 440 /etc/sudoers.d/serverguard
```

该文件内容：

```
%sudo   ALL=(ALL) NOPASSWD: /bin/systemctl restart minecraft
%sudo   ALL=(ALL) NOPASSWD: /bin/systemctl stop minecraft
%sudo   ALL=(ALL) NOPASSWD: /bin/systemctl start minecraft
%sudo   ALL=(ALL) NOPASSWD: /bin/systemctl status minecraft
%sudo   ALL=(minecraft) NOPASSWD: /usr/bin/rcon-cli *
```

### 反向代理（可选）

如果要将 Web 控制台暴露到公网，建议在前面放置 Nginx：

```nginx
server {
    listen 443 ssl;
    server_name console.your-server.com;

    # 基础鉴权
    auth_basic "Aluer Console";
    auth_basic_user_file /etc/nginx/.htpasswd;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}
```

> **警告**：绝对不要将 Aluer 的 8080 端口直接暴露到公网，WAF 模块仅提供基础 Web 防护，不足以替代专业反向代理的安全加固。

---

## ⚙️ 配置参考

### 完整配置树

以下是 `application.yml` 中的所有顶级配置节点及其用途。每个节点都可以通过 YAML 文件或环境变量覆盖。

```
serverguard
├── minecraft                     # Minecraft 服务端连接配置
│   ├── service-name              # systemd 服务名（默认: minecraft）
│   ├── process-name              # 进程匹配名（用于进程存活检测）
│   ├── jar-file                  # PaperMC jar 文件名
│   ├── working-dir               # Minecraft 服务端工作目录
│   ├── java-opts                 # JVM 启动参数
│   ├── check-interval-seconds    # 监控检查间隔（默认: 5s）
│   └── rcon
│       ├── enabled               # 是否启用 RCON 连接
│       ├── host                  # RCON 主机（默认: localhost）
│       ├── port                  # RCON 端口（默认: 25575）
│       └── password              # RCON 密码（${RCON_PASSWORD}）
│
├── monitor                       # 监控阈值配置
│   ├── tps-threshold             # TPS 告警阈值（默认: 15）
│   ├── cpu-threshold             # CPU 使用率告警阈值 %（默认: 80）
│   ├── memory-threshold          # 内存使用率告警阈值 %（默认: 85）
│   ├── connection-threshold      # 连接数异常阈值
│   ├── log-watch-lines           # 日志尾部跟踪行数
│   └── log-path                  # Minecraft 日志文件路径
│
├── alert                         # 告警通知配置
│   ├── enabled                   # 是否启用告警
│   └── email
│       ├── smtp-host             # SMTP 服务器
│       ├── smtp-port             # SMTP 端口（默认: 587）
│       ├── username              # 发件邮箱（${ALUER_ALERT_SMTP_USERNAME}）
│       ├── password              # SMTP 授权码（${ALUER_ALERT_SMTP_PASSWORD}）
│       ├── to                    # 收件人列表（环境变量注入）
│       └── rate-limit
│           ├── per-type-seconds  # 同类型告警冷却时间（默认: 300s）
│           └── max-emails-per-minute  # 每分钟最大邮件数
│
├── ai                            # AI 引擎配置
│   ├── enabled                   # 是否启用 AI 分析
│   ├── use-isolation-forest      # 是否使用孤立森林异常检测
│   ├── use-prediction            # 是否使用时序预测
│   ├── sliding-window-size       # 滑动窗口大小（指标数据点数）
│   ├── anomaly-threshold         # 异常检测阈值（0-1）
│   ├── prediction-horizon-minutes # 预测时间范围（分钟）
│   └── deepseek
│       ├── enabled               # 是否启用 DeepSeek
│       ├── api-key               # API Key（${DEEPSEEK_API_KEY}）
│       ├── base-url              # API 地址（默认: https://api.deepseek.com）
│       ├── model                 # 模型名（默认: deepseek-chat）
│       ├── max-tokens            # 最大输出 token 数
│       ├── temperature           # 生成温度（0-1，建议 0.35）
│       ├── auto-analyze-alerts   # 是否自动分析告警
│       ├── analysis-interval-seconds  # AI 分析间隔
│       └── auto-execute
│           ├── enabled           # 是否启用 AI 自动执行防御操作
│           ├── ban-ip            # 允许自动封禁 IP
│           ├── kill-entity       # 允许自动清除实体
│           ├── clear-lag         # 允许自动清理延迟
│           ├── set-spawn-rate    # 允许自动调节生物生成率
│           ├── kick-player       # 允许自动踢出玩家
│           ├── whitelist         # 允许自动开启白名单
│           └── min-confidence    # 自动执行的最低置信度（默认: 88）
│
├── security                      # 安全模块总配置（见下面子节点）
│   ├── enabled                   # 主开关
│   ├── auto-ban-vpn              # 自动封禁 VPN/代理用户
│   ├── check-on-login            # 玩家登录时执行安全检查
│   ├── max-connections-per-ip    # 单 IP 最大连接数
│   ├── block-common-exploits     # 拦截常见漏洞利用
│   ├── log-all-commands          # 记录所有命令
│   │
│   ├── minecraft-defense         # Minecraft 协议层防御
│   │   ├── game-tcp-port=25565
│   │   ├── query-udp-port=25565
│   │   ├── rcon-tcp-port=25575
│   │   ├── status-ping-threshold=25
│   │   ├── login-burst-threshold=12
│   │   ├── bot-swarm-threshold=15
│   │   ├── query-flood-threshold=30
│   │   ├── rcon-brute-force-threshold=5
│   │   └── compression-payload-threshold=8192
│   │
│   ├── ddos-defense              # DDoS 多层检测阈值
│   │   ├── syn-flood-threshold=100
│   │   ├── udp-flood-threshold=200
│   │   ├── icmp-flood-threshold=100
│   │   ├── http-flood-threshold=150
│   │   ├── slow-connection-threshold=150
│   │   ├── amplification-threshold=20
│   │   └── minecraft-*          # Minecraft 专属 DDoS 阈值
│   │
│   ├── anti-intrusion            # 入侵检测配置
│   │   ├── monitor-commands      # 监控可疑命令
│   │   ├── monitor-processes     # 监控进程变更
│   │   ├── monitor-files         # 监控文件变更
│   │   ├── monitor-plugins       # 监控插件目录
│   │   ├── monitor-systemd       # 监控服务状态
│   │   ├── monitor-rcon          # 监控 RCON 爆破
│   │   └── file-integrity        # 文件完整性监控
│   │       ├── enabled
│   │       ├── max-depth=5       # 扫描深度
│   │       └── monitored-paths   # 监控路径列表
│   │
│   ├── host-enforcement          # 本机防火墙强制
│   │   ├── enabled
│   │   ├── dry-run=true          # 首次部署建议开启
│   │   ├── preferred-backend=auto # iptables / ufw / nftables
│   │   ├── default-block-minutes=60
│   │   ├── default-rate-limit-per-minute=120
│   │   └── mirror-to-cloud-edge=true # 同步到 Cloudflare
│   │
│   ├── cloud-edge                # Cloudflare 边缘防护
│   │   ├── enabled
│   │   ├── dry-run=true
│   │   ├── provider=cloudflare
│   │   ├── zone-id / api-key / api-email
│   │   ├── default-block-mode=block
│   │   ├── default-challenge-mode=challenge
│   │   └── enable-under-attack-on-critical=true
│   │
│   ├── orchestration             # 编排策略
│   │   ├── enabled
│   │   ├── allow-local-block=true
│   │   ├── allow-edge-challenge=true
│   │   ├── allow-minecraft-defense=true
│   │   └── notify-on-critical=true
│   │
│   ├── autonomy                  # 自主防御策略
│   │   ├── enabled
│   │   ├── deepseek-dominant=true # L1 是否优先于 L2
│   │   ├── quiet-console=true     # 减少终端输出
│   │   ├── loop-interval-seconds=45
│   │   ├── min-risk-score-for-action=70
│   │   ├── critical-risk-score=90
│   │   ├── workflow-cooldown-seconds=180
│   │   ├── max-actions-per-hour=12
│   │   └── require-second-signal-for-containment=true
│   │
│   ├── shield                    # Mirage Shield 配置
│   │   ├── enabled
│   │   ├── auto-mode=true
│   │   ├── auto-enable-under-attack=true
│   │   ├── heat-trigger=78
│   │   ├── resonance-trigger=72
│   │   ├── threat-score-trigger=85
│   │   ├── edge-challenge-offender-limit=6
│   │   ├── shelter-rate-limit-per-minute=45
│   │   ├── attacker-notice-enabled=true
│   │   └── deterrence-message="..."
│   │
│   ├── kernel                    # Kernel 引擎配置
│   │   ├── enabled
│   │   ├── pulse-interval-seconds=30
│   │   ├── pulse-history-size=180
│   │   ├── journal-size=300
│   │   ├── echo-retention-minutes=180
│   │   ├── adaptive-weights=true
│   │   ├── directive-heat-threshold=60
│   │   └── lockdown-heat-threshold=82
│   │
│   ├── task-bus                  # 任务总线配置
│   │   ├── enabled
│   │   ├── auto-dispatch=true
│   │   ├── dispatch-interval-seconds=10
│   │   ├── queue-limit=200
│   │   └── history-limit=300
│   │
│   └── self-healing              # 自愈编排配置
│       ├── enabled
│       ├── dry-run=true          # 首次部署建议开启
│       ├── loop-interval-seconds=45
│       ├── auto-backup-before-recovery=true
│       ├── auto-whitelist-on-swarm=true
│       ├── allow-soft-restart=true
│       ├── tps-emergency-threshold=12
│       ├── cpu-emergency-threshold=92.0
│       ├── memory-emergency-threshold=95.0
│       └── max-recovery-actions-per-hour=8
│
├── dashboard                     # Web 控制台配置
│   ├── enabled
│   ├── title="Aluer Nebula Console"
│   ├── subtitle="PaperMC defense, recovery, and remote operations fabric"
│   ├── refresh-interval-seconds=6
│   ├── compact-terminal=true
│   └── ssh-gateway
│       ├── enabled
│       ├── session-timeout-minutes=30
│       ├── max-sessions=6
│       ├── command-timeout-seconds=25
│       ├── strict-host-key-checking=false
│       ├── allow-private-key-paste=true
│       ├── require-engine-handshake=true
│       └── handshake-ttl-seconds=30
│
├── backup                        # 备份配置
│   ├── enabled
│   ├── backup-dir=/opt/minecraft/backups
│   ├── world-dir=/opt/minecraft/world
│   ├── plugin-dir=/opt/minecraft/plugins
│   ├── interval-hours=24
│   ├── max-backups=7
│   ├── compress=true
│   ├── backup-plugins=true
│   └── notify-on-complete=true
│
├── schedule                      # 计划任务
│   ├── enabled
│   ├── daily-restart / restart-time="04:00"
│   ├── save-before-restart / announce-restart
│   ├── weekly-backup / backup-day="sunday"
│   └── clear-lag-daily / clear-lag-time="02:00"
│
├── chat-filter                   # 聊天过滤
│   ├── enabled
│   ├── block-ip / block-profanity / block-advertising
│   ├── block-spam / block-illegal
│   ├── spam-threshold=5
│   ├── spam-window-seconds=10
│   ├── mute-on-violation / mute-duration-minutes=5
│   ├── kick-on-repeat / max-violations-before-kick=3
│   └── custom-words[]
│
├── announcement                  # 定时公告
│   ├── interval-seconds=300
│   └── messages[]
│
└── afk                           # AFK 管理
    ├── enabled
    ├── afk-timeout-minutes=5
    ├── max-afk-minutes=30
    ├── teleport-to-afk-zone
    ├── afk-zone="0,100,0"
    └── auto-logout
```

### 环境变量注入表

配置文件中所有 `${VAR_NAME:default}` 形式的值都可以通过环境变量覆盖：

| 环境变量 | 对应配置路径 | 默认值 |
|----------|-------------|--------|
| `RCON_PASSWORD` | `serverguard.minecraft.rcon.password` | (空) |
| `DEEPSEEK_API_KEY` | `serverguard.ai.deepseek.api-key` | (空) |
| `DEEPSEEK_BASE_URL` | `serverguard.ai.deepseek.base-url` | `https://api.deepseek.com` |
| `DEEPSEEK_MODEL` | `serverguard.ai.deepseek.model` | `deepseek-chat` |
| `ALUER_ALERT_SMTP_USERNAME` | `serverguard.alert.email.username` | (空) |
| `ALUER_ALERT_SMTP_PASSWORD` | `serverguard.alert.email.password` | (空) |
| `ALUER_ALERT_EMAIL_PRIMARY` | `serverguard.alert.email.to[0]` | (空) |
| `ALUER_ALERT_EMAIL_SECONDARY` | `serverguard.alert.email.to[1]` | (空) |
| `ALUER_CLOUDFLARE_ZONE_ID` | `serverguard.security.cloud-edge.zone-id` | (空) |
| `ALUER_CLOUDFLARE_API_KEY` | `serverguard.security.cloud-edge.api-key` | (空) |
| `ALUER_CLOUDFLARE_EMAIL` | `serverguard.security.cloud-edge.api-email` | (空) |

---

## 📋 模块清单

### AI 决策层 (`com.aluer.ai`)

| 类 | 文件 | 功能 |
|----|------|------|
| `AluerSovereignEngine` | `ai/AluerSovereignEngine.java` | **L1 主控引擎**。每 45 秒收集全网态势 JSON → DeepSeek 生成 `AutonomyDirective`（workflow + defenseLevel + riskScore）。内置工作流名称校验白名单，防止 LLM 幻觉产生无效指令。 |
| `DeepSeekClient` | `ai/DeepSeekClient.java` | **DeepSeek API 客户端**。原生 `HttpURLConnection` 实现。支持 3 种调用模式：告警分析（`analyzeAlert`）、健康报告（`getServerHealthReport`）、自由问答（`askQuestion`）和自治指令规划（`planAutonomousDefense`）。内置从 Markdown/文本中提取 JSON 的容错解析。 |
| `AIAutonomousService` | `ai/AIAutonomousService.java` | **L3 执行落地层**。读取 L1 Sovereign 指令 + L2 Kernel 指令，执行冲突仲裁、操作冷却检查、每小时操作次数限制、双信号确认，最终将决策转化为 RCON 命令。 |
| `AIStrategyEngine` | `ai/AIStrategyEngine.java` | **策略匹配引擎**。根据威胁类型和严重程度映射最佳防御策略（暴力破解 → 临时封禁+验证码，DDoS → 流量清洗+限流）。 |
| `AnomalyDetector` | `ai/AnomalyDetector.java` | **孤立森林异常检测**。基于 Apache Commons Math3 实现，对 CPU/内存/TPS/连接数等多维指标进行无监督异常检测。 |
| `TimeSeriesPredictor` | `ai/TimeSeriesPredictor.java` | **时序预测器**。基于滑动窗口的历史指标数据，预测未来 60 分钟内的 TPS 走势，提前预警性能瓶颈。 |
| `AdaptiveThreshold` | `ai/AdaptiveThreshold.java` | **自适应阈值**。学习服务器历史负载模式，动态调整各项监控告警的触发阈值，降低凌晨低负载时段的误报率。 |

### Kernel 内核层 (`com.aluer.kernel`)

| 类 | 文件 | 功能 |
|----|------|------|
| `AluerKernelEngine` | `kernel/AluerKernelEngine.java` | **L2 内核引擎**。每 30 秒执行一次 Pulse 循环。内部运行 5 个虚拟模块（ThreatMesh / CommandLattice / HardeningMatrix / PerimeterWard / EchoGrid），加权汇聚信号，计算 heat/resonance/control 三维压力，产出 `KernelDirective`。支持自适应权重调整和 EchoGrid 攻击者记忆衰减。 |
| `AluerKernelTaskBus` | `kernel/AluerKernelTaskBus.java` | **任务总线**。插件化的任务执行框架。4 个内置 Plugin（Insight / Stability / Defense / Recovery）按优先级派发任务。支持任务队列限长、执行历史追踪。 |
| `AluerSelfHealingOrchestrator` | `kernel/AluerSelfHealingOrchestrator.java` | **自愈编排器**。每 45 秒运行一次恢复检查。检测 TPS/CPU/内存是否触发紧急阈值。恢复动作包括：软重启、清实体、调节生物生成率、开启白名单（bot swarm 场景）、恢复前自动备份。每小时最多 8 次恢复操作。 |

### 安全防护层 (`com.aluer.security`)

这是系统中规模最大的包，包含 30+ 个安全服务：

| 类别 | 类 | 功能 |
|------|-----|------|
| **DDoS 防御** | `DDoSProtectionService` | SYN/HTTP/UDP/ICMP Flood 检测，Minecraft 专属 Status/Login/Rcon/Query Flood 识别 |
| | `DDoSDefenseCoordinator` | 统一协调多个 DDoS 检测源，防重复封禁 |
| | `DistributedAttackMitigationService` | 分布式攻击缓解，跨节点协同 |
| | `MinecraftProtocolSecurityService` | Minecraft 协议层深度防御（Status Ping / Login Burst / Bot Swarm / Compression Bomb） |
| **防火墙** | `FirewallService` | iptables/ufw 规则管理，黑白名单维护 |
| | `HostEnforcementService` | 本机防火墙强制，支持 auto/iptables/ufw/nftables 后端 |
| | `NetworkMonitorService` | 进出站流量统计与异常检测 |
| | `NetworkSegmentationService` | 网络分段隔离 |
| **入侵检测** | `IntrusionDetectionService` | 基于签名的入侵检测 |
| | `IntrusionPreventionSystem` | 自动阻断入侵行为 |
| | `HostIntrusionCountermeasureService` | 主机层面入侵反制 |
| | `LogAnalysisService` | 日志异常模式匹配 |
| | `LogCorrelationService` | 多源日志关联分析 |
| **应用安全** | `WebApplicationFirewall` (WAF) | SQLi / XSS / 路径遍历 / Header 注入防护，客户端信誉评分 |
| | `WafRequestFilter` | WAF 的 HTTP 请求过滤拦截器 |
| | `APIRateLimitService` | API 接口速率限制 |
| | `RateLimitService` | 通用速率限制引擎 |
| **高级防御** | `HoneypotService` | 蜜罐诱饵端口，捕获扫描者，收集攻击指纹 |
| | `ZeroTrustArchitectureService` | 持续身份验证，最小权限校验 |
| | `AdvancedMalwareDetectionService` | 恶意文件扫描（插件后门、可疑 jar） |
| | `EndpointDetectionResponseService` | EDR 端点检测与响应 |
| | `ContainerSecurityService` | 容器安全检查 |
| **网络分析** | `TrafficAnalysisService` | 流量模式分析 |
| | `PacketInspectionService` | 深度包检测（DPI） |
| | `FlowAnalyzerService` | NetFlow/sFlow 流分析 |
| | `PortScanDetectionService` | 端口扫描检测与扫描者封禁 |
| | `ProtocolAnalysisService` | 协议异常检测 |
| **IP 情报** | `IPReputationService` | IP 信誉评分，全局黑名单查询 |
| | `GeoIPService` | IP 地理位置查询，按国家/地区过滤 |
| | `ThreatIntelligenceService` | 威胁情报源集成（可配置多个 Feed） |
| | `VPNDetectionService` | VPN/代理/托管服务商 IP 检测 |
| **SSL/TLS** | `SSLMonitorService` | SSL/TLS 证书过期监控 |
| | `SSLTLSCertificateService` | 证书管理 |
| **安全运维** | `SIEMService` | 安全信息与事件管理，关联碎片化事件识别攻击链 |
| | `SecurityOrchestrationService` | 安全编排，协调 L1/L2 决策与具体防御模块 |
| | `SecurityAutomationScheduler` | 自动化安全任务调度 |
| | `SecurityBaselineHardeningService` | 安全基线审计与加固（系统配置、文件权限、服务状态） |
| | `BackupSecurityService` | 备份文件安全保护 |
| **命令安全** | `CommandExecutionGuardService` | 危险命令拦截（rm -rf / wget | sh / 权限提升等） |
| **执行层** | `HostEnforcementService` | 本机防火墙强制 |
| | `CloudflareIntegrationService` | Cloudflare API 集成（IP 封禁/挑战/Under Attack 模式） |
| | `DNSSecurityService` | DNS 安全防护 |
| | `SessionManagementService` | 会话管理与异常检测 |
| | `LoadBalancerService` | 简易负载均衡 |
| | `TrafficShapingService` | 流量整形/QoS |
| | `EncryptionService` | 数据加密工具 |

### 运营控制层 (`com.aluer.console`)

| 类 | 功能 |
|----|------|
| `AluerOperationsCenterService` | **运营总控台**，聚合全部子系统状态，输出给 Web 控制台的 `/api/console/overview` 接口 |
| `AluerMirageShieldService` | **幻影护盾**，四级模式（OBSERVE → FORTIFY → MIRAGE → SHELTER），攻击者威慑通知，自动模式切换 |
| `RemoteSshGatewayService` | **远程 SSH 网关**，内置终端，支持 Sovereign Handshake 连接审批 + 命令守卫联动 |
| `ConsoleStreamController` | **SSE 实时流**，通过 Server-Sent Events 推送实时总览数据到 Web 前端 |

### 监控采集层 (`com.aluer.monitor`)

| 类 | 功能 |
|----|------|
| `ProcessMonitor` | 进程存活检测，崩溃自动重启 Minecraft 服务端 |
| `ResourceMonitor` | 系统资源采集（CPU/内存/磁盘 I/O），通过 `/proc` 和 JMX 获取 |
| `ConnectionMonitor` | 网络连接统计，检测 Connection Flood 攻击模式 |
| `LogMonitor` | Minecraft `latest.log` 实时追踪，捕获崩溃堆栈和异常登录模式 |

### 核心服务层 (`com.aluer.service`)

| 类 | 功能 |
|----|------|
| `ServerGuardService` | **系统总控**，`CommandLineRunner` 入口，调度全部监控循环和 AI 分析循环 |
| `RconClient` | Minecraft RCON 协议客户端，所有游戏内命令的通道 |
| `AutoExecutor` | AI 决策到 RCON 命令的翻译器，将抽象的防御动作（"封禁IP"）转为具体指令（`/ban-ip 1.2.3.4`） |

### Web 交互层 (`com.aluer.web`)

| 类 | 功能 |
|----|------|
| `DashboardController` | REST API（`/api/*`），提供状态查询、命令执行、备份管理、健康检查、攻击报告等接口 |
| `OperationsConsoleController` | 运营控制台 API（`/api/console/*`），总览数据、Shield 控制、快捷操作 |
| `ConsoleStreamController` | SSE 流推送（`/api/console/stream/overview`） |
| `HealthService` | 组件级健康检查（RCON/AI/邮件/安全/自愈），系统资源信息汇总 |
| `RequestLoggingFilter` | HTTP 请求日志过滤器，慢请求和 500 错误自动告警 |

### 辅助功能模块

| 包 | 类 | 功能 |
|----|-----|------|
| `com.aluer.alert` | `EmailAlertService` | 邮件告警，支持 QQ/Gmail/自定义 SMTP，内置发送频率限制 |
| `com.aluer.backup` | `BackupService` | 世界/插件/配置定时打包备份，支持压缩和自动清理旧备份 |
| `com.aluer.anticheat` | `AntiCheatService` | 反作弊联动，汇总反作弊插件数据，智能判罚 |
| `com.aluer.vpn` | `VPNDetectionService` | VPN/代理 IP 检测，防止作弊者绕过 IP 封禁 |
| `com.aluer.chat` | `ChatFilterService` | 游戏内聊天过滤（脏话/广告/钓鱼链接/刷屏） |
| `com.aluer.punishment` | `PunishmentService` | 统一处罚管理（封禁/踢出/禁言），记录历史 |
| `com.aluer.audit` | `SecurityAuditService` | 安全审计日志，记录所有管理员操作和安全事件 |
| `com.aluer.world` | `WorldManagementService` | Minecraft 世界管理（动态加载/卸载/列表） |
| `com.aluer.metrics` | `MetricsCollectionService` | 指标统一汇总，标准化各 Monitor 的采集数据 |
| `com.aluer.profiler` | `PerformanceProfiler` | 性能分析器，CPU/内存/Tick 耗时深度剖析 |
| `com.aluer.schedule` | `ScheduledTaskService` | 计划任务引擎（定时重启/备份/清 lag/公告） |
| `com.aluer.export` | `DataExportService` | 安全数据导出（审计日志/攻击记录/性能报告） |
| `com.aluer.command` | `AdminCommands` / `TestCommands` | Spring Shell 管理命令和测试命令 |
| `com.aluer.notification` | `WebhookService` / `AttackReportService` | Discord/Slack Webhook 告警通知；HTML 攻击报告自动生成与导出 |

### 数据模型 (`com.aluer.model`)

| 类 | 字段 | 说明 |
|----|------|------|
| `AlertEvent` | type, message, rootCause, timestamp, confidence, suggestedAction | 标准化告警事件 |
| `AlertType` | PROCESS_DEAD / TPS_LOW / CPU_HIGH / MEM_HIGH / CONNECTION_FLOOD / LOG_ATTACK / BACKUP_FAILED / AI_ANOMALY | 告警类型枚举 |
| `MetricsData` | tps, cpuUsage, memoryUsage, onlinePlayers, connections, tickTime | 服务器性能快照 |

---

## 🛡️ 防御等级与自动响应

### 四级防御体系

系统根据 Kernel heat 和 Sovereign 综合判定自动切换防御等级：

| 等级 | heat 范围 | 触发条件 | 自动行为 |
|------|-----------|----------|----------|
| `NORMAL` | < 45 | 正常运行 | 常规监控，异常记录到日志，不执行主动防御 |
| `ELEVATED` | 45–69 | 单个模块压力上升 | 加强检测频率，IP 信誉查询启用，高风险 IP 标记 |
| `HIGH` | 70–81 | 多模块同时报警 | 自动封禁高风险 IP，速率限制启用，边缘挑战开启 |
| `LOCKDOWN` | ≥ 82 | 严重复合攻击 | 白名单模式，Cloudflare Under Attack，拒绝新连接，邮件紧急通知 |

### Mirage Shield 模式切换

Mirage Shield 是面向攻击者的偏转护盾，有 4 种运行模式：

| 模式 | 含义 | 自动触发条件 |
|------|------|-------------|
| `OBSERVE` | 仅观察，不干预 | 默认模式 |
| `FORTIFY` | 加固防御 | heat ≥ 78 或 threat_score ≥ 85 |
| `MIRAGE` | 镜像偏转 | resonance ≥ 72 且有高置信度攻击者 |
| `SHELTER` | 避难所模式 | heat ≥ 82 且 resonance ≥ 80，进入严格限流 |

Mirage Shield 在 `MIRAGE` 和 `SHELTER` 模式下，会向检测到的攻击 IP 返回威慑消息（`deterrence-message` 配置项）。

### 自愈编排触发条件

`AluerSelfHealingOrchestrator` 在满足以下任一条件时触发恢复流程：

| 条件 | 阈值 | 恢复动作 |
|------|------|----------|
| TPS 低于紧急线 | < 12 TPS | `clear-lag` + `kill-entity` + `set-spawn-rate 低` |
| CPU 高于紧急线 | > 92% | 优先 `clear-lag`，若无效则考虑软重启 |
| 内存高于紧急线 | > 95% | `save-all` → 通知玩家 → 软重启 |
| Bot Swarm 检测 | ≥ 15 个并发假玩家 | `whitelist on` + 封禁来源 IP |

所有恢复动作在 `dry-run=true` 时仅记录日志而不实际执行。

---

## 🌐 API 参考

### 系统状态 API

| 方法 | 路径 | 说明 |
|------|------|------|
| `GET` | `/api/status` | 系统运行状态 |
| `GET` | `/api/server/info` | Minecraft 服务器信息 |
| `GET` | `/api/performance` | TPS / CPU / 内存指标 |
| `POST` | `/api/command/execute` | 执行 RCON 命令（参数 `command`） |

**示例**：

```bash
# 执行 RCON 命令
curl -X POST http://localhost:8080/api/command/execute \
  -d "command=list"

# 获取性能指标
curl http://localhost:8080/api/performance
```

### 安全态势 API

| 方法 | 路径 | 说明 |
|------|------|------|
| `GET` | `/api/security/stats` | 安全总览 |
| `GET` | `/api/security/network/posture` | 网络态势详情 |
| `GET` | `/api/security/network/offenders?limit=10` | 高风险 IP 列表 |
| `GET` | `/api/security/network/incidents?limit=20` | 安全事件列表 |
| `GET` | `/api/security/network/ip?ip=1.2.3.4` | 单 IP 深度检查 |
| `POST` | `/api/security/network/quarantine` | 隔离 IP（参数 `ip`, `actor`, `reason`） |
| `POST` | `/api/security/network/release` | 释放 IP（参数同上） |

**示例**：

```bash
# 查询 IP 信誉
curl "http://localhost:8080/api/security/network/ip?ip=45.33.32.156"

# 手动隔离 IP
curl -X POST "http://localhost:8080/api/security/network/quarantine" \
  -d "ip=45.33.32.156&actor=admin&reason=syn flood detected"
```

### 控制台操作 API

| 方法 | 路径 | 说明 |
|------|------|------|
| `GET` | `/api/console/overview` | 完整运营总览（所有子系统状态聚合） |
| `GET` | `/api/console/stream/overview` | SSE 实时流推送 |
| `POST` | `/api/console/shield/engage` | 手动切换 Shield 模式（参数 `mode`, `reason`） |
| `POST` | `/api/console/quick-action` | 快捷操作（参数 `action`：`backup-now` / `shield-mirage` / `shield-shelter`） |

### SSH 网关 API

| 方法 | 路径 | 说明 |
|------|------|------|
| `POST` | `/api/console/ssh/handshake` | Sovereign 握手审批（参数 `host`, `port`, `username`, `purpose`） |
| `POST` | `/api/console/ssh/connect` | 建立 SSH 连接（参数 `alias`, `host`, `port`, `username`, `password`, `privateKeyPath`, `handshakeToken`） |
| `POST` | `/api/console/ssh/execute` | 执行远程命令（参数 `sessionId`, `command`） |
| `DELETE` | `/api/console/ssh/{sessionId}` | 断开 SSH 会话 |

**SSH 网关的安全设计**：

1. **Sovereign Handshake 前置**：连接前必须先通过握手审批，Kernel 根据当前 heat 和风险评分决定是否批准
2. **命令守卫联动**：执行的每条命令都经过 `CommandExecutionGuardService` 审查，危险命令被标记和阻断
3. **会话超时**：默认 30 分钟无活动自动断开
4. **审计同步**：所有 SSH 操作自动记录到 `SecurityAuditService`

### 健康检查 API

| 方法 | 路径 | 说明 |
|------|------|------|
| `GET` | `/api/health` | 完整健康报告（组件状态 + 系统资源） |
| `GET` | `/api/health/live` | 存活探针（K8s liveness probe） |
| `GET` | `/api/health/ready` | 就绪探针（K8s readiness probe） |

**示例响应 (`/api/health`)**：

```json
{
  "status": "HEALTHY",
  "uptimeSeconds": 86400,
  "components": {
    "rcon": {"status": "UP", "host": "localhost:25575"},
    "deepseek-ai": {"status": "UP", "model": "deepseek-chat"},
    "email-alert": {"status": "UP"},
    "security": {"status": "UP", "kernelEnabled": true},
    "self-healing": {"status": "UP", "dryRun": true}
  },
  "system": {
    "memory": {"usedMB": 320, "maxMB": 4096, "usagePercent": 7.8},
    "heapUsedMB": 180,
    "systemCpuLoad": 12.5
  }
}
```

### 通知与报告 API

| 方法 | 路径 | 说明 |
|------|------|------|
| `GET` | `/api/attacks/recent?limit=20` | 最近攻击记录 |
| `POST` | `/api/attacks/report` | 生成 HTML 攻击报告 |
| `POST` | `/api/webhook/test` | 测试 Discord/Slack Webhook |

**Webhook 配置**（`application.yml`）：

```yaml
serverguard:
  webhook:
    enabled: false
    discord-url: ${ALUER_WEBHOOK_DISCORD:}
    slack-url: ${ALUER_WEBHOOK_SLACK:}
```

### 备份管理 API

| 方法 | 路径 | 说明 |
|------|------|------|
| `GET` | `/api/backup/list` | 备份列表 |
| `POST` | `/api/backup/create` | 创建新备份（参数 `name`） |

---

## 🖥️ Web 控制台

Aluer 内置 React 19 + Vite 6 构建的单页应用控制台（Nebula Console）。

### 页面布局

```
┌────────────┬───────────────────────────────────────────────┐
│  Command   │  Hero Panel（Mirage Shield 当前模式）         │
│  Rail      │  ┌─────────────┐  ┌──────────────┐            │
│  ────────  │  │ Risk Score  │  │  Shield 操作 │            │
│  System    │  │ Kernel Heat │  │  FORTIFY     │            │
│  Title     │  │ Resonance   │  │  MIRAGE      │            │
│  ────────  │  └─────────────┘  │  SHELTER     │            │
│  Stream    │                    │  RECOVERY    │            │
│  Status    │                    └──────────────┘            │
│  ────────  ├───────────────────────────────────────────────┤
│  Quick     │  Module Constellation（互联能力矩阵）         │
│  Actions   │  ┌──────────┐ ┌──────────┐ ┌──────────┐      │
│  ────────  │  │ Mirage   │ │ Kernel   │ │ Task Bus │      │
│  Metric    │  │ Shield   │ │ Engine   │ │          │      │
│  Cards     │  └──────────┘ └──────────┘ └──────────┘      │
│  TPS/CPU   │  ...                                          │
│  Memory/   ├───────────────────────────────────────────────┤
│  Threat    │  Node Fabric（本地核心 + 远程 SSH 节点）      │
│            ├───────────────────────────────────────────────┤
│            │  Remote SSH Workbench + Terminal               │
│            │  ┌─────────────────────────────────────────┐  │
│            │  │ [终端输出区域，最多 120 行]               │  │
│            │  └─────────────────────────────────────────┘  │
│            ├───────────────────────────────────────────────┤
│            │  Threat Trace（高风险来源列表）                │
│            ├───────────────────────────────────────────────┤
│            │  Audit Stream（审计事件流，支持筛选）          │
└────────────┴───────────────────────────────────────────────┘
```

### 实时数据流

前端通过 **SSE（Server-Sent Events）** 接收实时数据推送：

```
浏览器 ──EventSource──→ /api/console/stream/overview
                            │
                  每 6 秒推送一次全量总览 JSON
                  （由 AluerOperationsCenterService 聚合）
                            │
                  降级机制：SSE 连接失败时自动切换为
                  setInterval 轮询 /api/console/overview
```

### 功能清单

| 功能 | 说明 |
|------|------|
| Shield 控制 | 一键切换 FORTIFY / MIRAGE / SHELTER / RECOVERY 模式 |
| 性能走势 | TPS / CPU / Memory / 在线玩家 SparkBar 实时可视化 |
| 自动刷新 | 可切换开关 + 可选间隔（3s / 6s / 10s / 30s） |
| 健康检查面板 | 可折叠，显示 RCON/AI/邮件/安全/自愈 组件 UP/DOWN 状态 |
| SSH 远程终端 | 连接远程节点，执行命令，带命令守卫审查 |
| 模块监控 | 9 个模块的状态、信号值实时显示 |
| 威胁视图 | 高风险 IP 列表，score + riskLevel + 详情（最多 10 条） |
| 审计筛选 | 实时筛选审计事件、网络事件、Shield 状态变迁（最多 24 条） |

---

## 🖧 Shell 命令参考

Aluer 启动后提供 Spring Shell 交互终端，支持自然语言和结构化命令。

### AI 对话

```bash
aluer> ai 测试一下服务器                      # 执行完整服务器测试
aluer> ai 开启防御                            # 开启 AI 自主防御
aluer> ai 查看安全状态                        # 获取安全态势概览
aluer> ai 帮我分析一下当前的卡顿原因          # DeepSeek 深度分析
aluer> ai 查看世界                            # 列出所有世界
aluer> ask 如何提高服务器安全性              # 自由问答
```

### 基础命令

| 命令 | 示例 | 说明 |
|------|------|------|
| `help` | `help` | 显示所有可用命令 |
| `status` | `status` | 服务器运行状态（进程/CPU/内存/连接数） |
| `test` | `test` / `test cpu` / `test memory` / `test network` / `test security` | 运行测试 |
| `metrics` | `metrics` / `metrics counters` / `metrics gauges` | 性能指标查询 |

### 安全管理

| 命令 | 示例 | 说明 |
|------|------|------|
| `security` | `security` / `security ddos` / `security firewall` / `security intrusion` / `security threats` / `security vpn` / `security chat` | 各安全模块状态 |
| `defense` | `defense` / `defense on` / `defense off` / `defense list` / `defense level high` | AI 防御管控 |
| `network` | `network` / `network geoip 1.2.3.4` / `network reputation 1.2.3.4` / `network ports` | 网络分析 |

### 玩家管理

| 命令 | 示例 | 说明 |
|------|------|------|
| `kick` | `kick PlayerName` | 踢出玩家 |
| `ban` | `ban PlayerName` / `ban PlayerName 作弊` | 封禁玩家 |
| `unban` | `unban PlayerName` | 解封玩家 |

### 运维管理

| 命令 | 示例 | 说明 |
|------|------|------|
| `backup` | `backup` / `backup create` / `backup status` / `backup start` | 备份管理 |
| `world` | `world` / `world load world_nether` / `world unload world_nether` | 世界管理 |
| `alert` | `alert` / `alert test` / `alert send 服务器异常` | 邮件告警 |
| `audit` | `audit` / `audit recent 20` / `audit summary` | 安全审计 |
| `tasks` | `tasks` / `tasks start` | 计划任务管理 |

---

## 🔧 开发指南

### 项目结构

```
AluerIII/
├── src/main/java/com/aluer/
│   ├── ai/                    # AI 决策引擎（7 个类）
│   │   ├── AdaptiveThreshold.java
│   │   ├── AIAutonomousService.java
│   │   ├── AIStrategyEngine.java
│   │   ├── AluerSovereignEngine.java
│   │   ├── AnomalyDetector.java
│   │   ├── AttackDetector.java
│   │   ├── DeepSeekClient.java
│   │   └── TimeSeriesPredictor.java
│   ├── kernel/                # 内核引擎（3 个类）
│   │   ├── AluerKernelEngine.java
│   │   ├── AluerKernelTaskBus.java
│   │   └── AluerSelfHealingOrchestrator.java
│   ├── security/              # 安全模块（33 个类）
│   │   ├── DDoSProtectionService.java
│   │   ├── DDoSDefenseCoordinator.java
│   │   ├── FirewallService.java
│   │   ├── WebApplicationFirewall.java
│   │   ├── IntrusionDetectionService.java
│   │   ├── IntrusionPreventionSystem.java
│   │   ├── HoneypotService.java
│   │   ├── ZeroTrustArchitectureService.java
│   │   ├── CloudflareIntegrationService.java
│   │   ├── ...（见模块清单）
│   │   └── NetworkThreatFusionService.java
│   ├── console/               # 运营控制（4 个类）
│   │   ├── AluerOperationsCenterService.java
│   │   ├── AluerMirageShieldService.java
│   │   ├── RemoteSshGatewayService.java
│   │   └── ConsoleStreamController.java
│   ├── monitor/               # 监控采集（4 个类）
│   │   ├── ProcessMonitor.java
│   │   ├── ResourceMonitor.java
│   │   ├── ConnectionMonitor.java
│   │   └── LogMonitor.java
│   ├── service/               # 核心服务（4 个类）
│   │   ├── ServerGuardService.java
│   │   ├── RconClient.java
│   │   ├── AutoExecutor.java
│   │   └── TestService.java
│   ├── web/                   # Web 层（3 个类）
│   │   ├── DashboardController.java
│   │   ├── OperationsConsoleController.java
│   │   └── ConsoleStreamController.java
│   ├── config/                # 配置
│   │   └── ServerGuardConfig.java
│   ├── model/                 # 数据模型
│   │   ├── AlertEvent.java
│   │   ├── AlertType.java
│   │   └── MetricsData.java
│   ├── terminal/              # Shell 终端
│   │   └── AITerminal.java
│   ├── command/               # Shell 命令
│   │   ├── AdminCommands.java
│   │   └── TestCommands.java
│   ├── alert/                 # 告警
│   │   └── EmailAlertService.java
│   ├── backup/                # 备份
│   │   └── BackupService.java
│   ├── anticheat/             # 反作弊
│   │   └── AntiCheatService.java
│   ├── vpn/                   # VPN 检测
│   │   └── VPNDetectionService.java
│   ├── chat/                  # 聊天过滤
│   │   └── ChatFilterService.java
│   ├── punishment/            # 处罚管理
│   │   └── PunishmentService.java
│   ├── audit/                 # 安全审计
│   │   └── SecurityAuditService.java
│   ├── world/                 # 世界管理
│   │   └── WorldManagementService.java
│   ├── metrics/               # 指标汇聚
│   │   └── MetricsCollectionService.java
│   ├── profiler/              # 性能分析
│   │   └── PerformanceProfiler.java
│   ├── schedule/              # 计划任务
│   │   └── ScheduledTaskService.java
│   ├── export/                # 数据导出
│   │   └── DataExportService.java
│   └── ServerGuardApplication.java   # Spring Boot 入口
│
├── src/main/resources/
│   ├── application.yml        # 主配置文件
│   ├── logback.xml            # 日志配置
│   └── static/                # 前端构建产物
│       ├── index.html
│       └── nebula-assets/
│
├── src/test/java/com/aluer/   # 测试（9 个文件）
│   ├── kernel/
│   │   ├── AluerKernelEngineTest.java
│   │   ├── AluerKernelTaskBusTest.java
│   │   └── AluerSelfHealingOrchestratorTest.java
│   ├── security/
│   │   ├── NetworkThreatFusionServiceTest.java
│   │   ├── SecurityBaselineHardeningServiceTest.java
│   │   └── WebApplicationFirewallTest.java
│   └── console/
│       ├── AluerMirageShieldServiceTest.java
│       ├── AluerEngineHandshakeServiceTest.java
│       └── RemoteSshGatewayServiceTest.java
│
├── frontend/                  # React 前端
│   ├── package.json
│   ├── vite.config.js
│   └── src/
│       ├── main.jsx           # 入口 + ErrorBoundary
│       ├── App.jsx            # 主应用（Nebula Console）
│       └── styles.css         # 样式
│
├── systemd/                   # Systemd 服务文件
│   ├── minecraft.service
│   ├── serverguard.service
│   └── sudoers.serverguard
│
├── docs/                      # 文档
│   ├── PROJECT_SUMMARY.md
│   └── USER_MANUAL.md
│
├── apache-maven-3.9.6/        # 内置 Maven
├── pom.xml
├── install.sh                 # 一键安装脚本
├── start.sh                   # 启动脚本
└── README.md
```

### 构建与运行

```bash
# 完整构建（含前端编译）
./apache-maven-3.9.6/bin/mvn clean package -DskipTests

# 仅编译后端（跳过前端）
./apache-maven-3.9.6/bin/mvn compile

# 运行 jar
java -jar target/serverguard.jar

# 带自定义配置运行
java -jar target/serverguard.jar --spring.config.location=/path/to/application.yml
```

### 前端开发

```bash
cd frontend

# 安装依赖
npm install

# 启动开发服务器（http://localhost:4173）
npm run dev

# dev server 自动将 /api 请求代理到 localhost:8080
# 需要后端已在本地运行

# 构建生产版本（输出到 ../src/main/resources/static/）
npm run build
```

Vite 配置要点：

```javascript
// frontend/vite.config.js
export default defineConfig({
  plugins: [react()],
  server: {
    host: "0.0.0.0",
    port: 4173,
    proxy: { "/api": "http://localhost:8080" }   // 开发时代理到后端
  },
  build: {
    outDir: "../src/main/resources/static",       // 构建产物直接嵌入后端
    emptyOutDir: false,
    assetsDir: "nebula-assets"
  }
});
```

### 运行测试

```bash
# 运行全部测试
./apache-maven-3.9.6/bin/mvn test

# 运行指定测试类
./apache-maven-3.9.6/bin/mvn test -Dtest=AluerKernelEngineTest

# 运行指定测试方法
./apache-maven-3.9.6/bin/mvn test -Dtest=AluerKernelEngineTest#kernelPulseGeneratesCommandAbuseDirectiveAndEchoMemory

# 查看测试报告
cat target/surefire-reports/*.txt
```

### 添加新安全模块

每个安全模块遵循统一的约定：

1. 在 `com.aluer.security` 包下创建新类
2. 通过构造器注入 `ServerGuardConfig` 获取配置
3. 实现 `getPosture()` 方法返回态势数据（供 Kernel 消费）
4. 在 `NetworkThreatFusionService` 中注册（如果模块涉及网络安全）
5. 在 `AluerOperationsCenterService` 的 `buildOverview()` 中聚合（如果需要展示到控制台）
6. 在 `application.yml` 中添加对应的配置节点

---

## ❓ 常见问题

<details>
<summary><strong>如何验证 AI 是否正常工作？</strong></summary>

```bash
# 在终端执行
aluer> ask 你好
```

如果有 AI 回复，说明 DeepSeek 配置正确。也可以查看日志：

```bash
tail -f /var/log/serverguard.log | grep DeepSeek
```
</details>

<details>
<summary><strong>收不到邮件告警？</strong></summary>

1. 确认 `application.yml` 中邮箱配置的 `username`/`password` 正确
2. QQ 邮箱必须使用**授权码**而非登录密码
3. 检查垃圾邮件文件夹
4. 执行 `alert test` 发送测试邮件确认

```bash
aluer> alert test
```
</details>

<details>
<summary><strong>首次部署应该注意什么？</strong></summary>

建议先开启 **dry-run 模式**：

```yaml
serverguard:
  security:
    host-enforcement:
      dry-run: true        # 本机防火墙仅记录不执行
    cloud-edge:
      dry-run: true        # Cloudflare 仅记录不执行
    self-healing:
      dry-run: true        # 自愈仅记录不执行
```

观察 1-2 天确认无误报后，再逐步关闭 dry-run。
</details>

<details>
<summary><strong>如何查看运行日志？</strong></summary>

```bash
# systemd 管理时
sudo journalctl -u serverguard -f

# 直接运行时查看应用日志
tail -f /var/log/serverguard.log

# 查看 Minecraft 日志
tail -f /opt/minecraft/logs/latest.log
```
</details>

<details>
<summary><strong>如何升级到新版本？</strong></summary>

```bash
# 1. 停止服务
sudo systemctl stop serverguard

# 2. 备份当前版本和数据
cp /opt/serverguard/serverguard.jar /opt/serverguard/serverguard.jar.bak
cp -r /opt/serverguard/backups /backup/

# 3. 替换 jar 包
cp target/serverguard.jar /opt/serverguard/

# 4. 重启服务
sudo systemctl start serverguard

# 5. 验证
sudo systemctl status serverguard
curl http://localhost:8080/api/status
```
</details>

<details>
<summary><strong>如何安全地修改配置？</strong></summary>

1. 不要直接编辑 jar 包内的 `application.yml`
2. 在 jar 包同目录创建外部 `application.yml`（Spring Boot 自动优先读取外部文件）
3. 或者通过环境变量覆盖（推荐生产环境）
4. 修改后重启服务

```bash
# 方法 1：外部配置文件
sudo nano /opt/serverguard/application.yml
sudo systemctl restart serverguard

# 方法 2：环境变量（在 systemd unit 中设置）
sudo systemctl edit serverguard
# 添加：
# [Service]
# Environment="DEEPSEEK_API_KEY=sk-xxx"
sudo systemctl restart serverguard
```
</details>

<details>
<summary><strong>为什么有两个决策引擎（Sovereign + Kernel）？不会冲突吗？</strong></summary>

不会。它们是互补关系：

- **Sovereign（DeepSeek）** 擅长理解复杂的、从未见过的攻击模式，但延迟 2-5 秒且偶有非结构化输出
- **Kernel（规则引擎）** 响应时间 < 1ms，100% 可预测，但无法应对未知攻击模式

当两者输出不一致时，`AIAutonomousService`（L3）按照 `autonomy.deepseek-dominant` 配置决定谁来拍板。同时 `SecurityOrchestrationService` 做最终的安全兜底——任何操作都不会超过 `max-actions-per-hour` 的限制。
</details>

<details>
<summary><strong>性能开销有多大？</strong></summary>

在 2 核 4GB 的 VPS 上实测：

- JVM 常驻内存：约 180-250 MB（含 Spring Boot + 所有服务）
- CPU 空闲占用：< 2%（监控和 Pulse 循环）
- DeepSeek API 调用时 CPU 开销：约 5%（网络 I/O 等待为主）
- 不影响 Minecraft 服务端性能（通过 RCON 异步通信）
</details>

---

## 📄 许可证

本项目基于 **Apache License 2.0** 开源。完整许可证文本见 [LICENSE](LICENSE) 文件。

| 条款 | 说明 |
|:-----|:-----|
| ✅ **允许** | 商业使用、修改、分发、专利授权、私人使用 |
| ⚠️ **条件** | 分发时需包含许可证声明和版权声明，修改文件需标注变更 |
| ❌ **限制** | 不提供任何担保，作者不对使用本软件造成的损失承担责任 |

---

## 🌟 支持项目

如果 Aluer ServerGuard 帮助了你，请考虑：

<p align="center">
  <a href="https://github.com/ZpjDev/Aluer"><img src="https://img.shields.io/badge/⭐_收藏仓库-f1c40f?style=for-the-badge&logo=github" alt="收藏"></a>
  &nbsp;
  <a href="https://github.com/ZpjDev/Aluer/fork"><img src="https://img.shields.io/badge/🍴_复刻-3498db?style=for-the-badge&logo=github" alt="复刻"></a>
  &nbsp;
  <a href="https://github.com/ZpjDev/Aluer/issues"><img src="https://img.shields.io/badge/🐛_报告问题-e74c3c?style=for-the-badge&logo=github" alt="报告问题"></a>
  &nbsp;
  <a href="https://github.com/ZpjDev/Aluer/discussions"><img src="https://img.shields.io/badge/💬_讨论-2ecc71?style=for-the-badge&logo=github" alt="讨论"></a>
</p>

---

<h2 align="center">🏆 贡献者</h2>

<p align="center">
  <a href="https://github.com/ZpjDev/Aluer/graphs/contributors">
    <img src="https://contrib.rocks/image?repo=ZpjDev/Aluer&max=12" />
  </a>
</p>

<p align="center">
  <sub>由 Aluer 社区用 ❤️ 构建 — 守护世界各地的 Minecraft 服务器</sub>
</p>

---

<p align="center">
  <a href="https://github.com/ZpjDev/Aluer">
    <img src="https://img.shields.io/github/repo-size/ZpjDev/Aluer?style=flat-square&label=仓库大小&color=3498db" alt="仓库大小">
  </a>
  <a href="https://github.com/ZpjDev/Aluer/blob/main/LICENSE">
    <img src="https://img.shields.io/github/license/ZpjDev/Aluer?style=flat-square&label=许可证&color=2ecc71" alt="许可证">
  </a>
  <img src="https://img.shields.io/badge/技术栈-Java%2017%20%7C%20Spring%20Boot%203.2%20%7C%20React%2019%20%7C%20DeepSeek%20AI-536DFE?style=flat-square" alt="技术栈">
  <br>
  <sub>Aluer ServerGuard v3.0 — 为你的 Minecraft 社区提供自主防护</sub>
</p>
