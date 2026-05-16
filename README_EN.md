<p align="center">
  <img src="logo.png" alt="Aluer ServerGuard" width="180">
</p>

<h1 align="center">Aluer ServerGuard V5.0</h1>

<p align="center">
  <b>AI-Powered Minecraft PaperMC Server Protection System</b><br>
  <sub>135+ Security Modules · 100% Meteor Client Coverage · Agent Architecture · DeepSeek AI</sub>
</p>

<p align="center">
  <a href="https://github.com/ZpjDev/Aluer/releases/latest"><img src="https://img.shields.io/github/v/release/ZpjDev/Aluer?style=for-the-badge&color=6366f1" alt="Latest Release"></a>
  <a href="#"><img src="https://img.shields.io/badge/build-passing-brightgreen?style=for-the-badge" alt="Build"></a>
  <a href="#"><img src="https://img.shields.io/badge/tests-323%2F323-green?style=for-the-badge" alt="Tests"></a>
  <a href="#"><img src="https://img.shields.io/badge/Java-21-red?style=for-the-badge&logo=openjdk" alt="Java 21"></a>
  <a href="#"><img src="https://img.shields.io/badge/PaperMC-1.21.1-blue?style=for-the-badge" alt="PaperMC"></a>
  <a href="#"><img src="https://img.shields.io/badge/modules-135%2B-purple?style=for-the-badge" alt="Modules"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache%202.0-orange?style=for-the-badge" alt="Apache 2.0 License"></a>
</p>

<p align="center">
  <a href="#quick-start">Quick Start</a> ·
  <a href="#architecture">Architecture</a> ·
  <a href="#security-modules">Modules</a> ·
  <a href="#meteor-client-coverage-matrix">Meteor Coverage</a> ·
  <a href="#deployment">Deployment</a> ·
  <a href="#faq">FAQ</a> ·
  <a href="README.md">中文</a>
</p>

---

## Overview

Aluer ServerGuard is a **next-generation intelligent security system** for Minecraft PaperMC servers. It employs a revolutionary **Agent Architecture** — a lightweight Paper plugin collects real-time data from inside the server process, while an external Spring Boot analysis engine runs independently. The two communicate via **real-time bidirectional WebSocket**.

### Why Aluer ServerGuard?

| Problem | Aluer Solution |
|---------|---------------|
| Cheat clients rampant (Meteor Client etc.) | 100% coverage of all 55 Meteor Client hack modules with millisecond-level detection |
| Traditional anti-cheats rely on rigid rules | AI + ML dual-layer: DeepSeek LLM semantic analysis + Isolation Forest/Shannon Entropy/FFT statistical detection |
| DDoS attacks crash servers | 7-layer coordinated DDoS defense (SYN/UDP/ICMP/HTTP/Slowloris/MC protocol/amplification) |
| Server crashes when admin is offline | Kernel autonomy engine + SelfHealing orchestrator: auto-detect → analyze → execute → recover |
| Multiple security tools complex to manage | Single JAR deployment, Web console for all 135+ modules, in-game /aluer commands |
| Plugin mode invasive, impacts TPS | Agent architecture: plugin uses only ~50MB RAM, analysis engine runs separately |

### Core Capabilities

| Capability | Description |
|---|---|
| **Full Anti-Cheat** | 100% Meteor Client coverage — Combat/Movement/World/Player/Misc 55 modules |
| **AI Decision Engine** | DeepSeek LLM auto-analysis → defense strategy → auto-execution (ban/kick/whitelist/clearlag) |
| **ML Behavioral Analysis** | Isolation Forest anomaly detection + Time series prediction + Shannon Entropy profiling + FFT spectrum analysis |
| **DDoS Multi-Layer Defense** | SYN/UDP/ICMP/HTTP/Slowloris/MC Status/Login/Rcon/Query coordinated defense |
| **Server Self-Healing** | TPS < 12 or CPU > 92% or Memory > 95% auto-triggers recovery (backup → clear entities → throttle → whitelist → soft restart) |
| **Dual-Mode** | Agent Plugin mode (recommended, <1ms latency, 50K+/s) + External RCON mode (zero invasion) |

---

## Quick Start

```bash
# Download latest release
wget https://github.com/ZpjDev/Aluer/releases/latest/download/serverguard.jar

# Start (External mode, ready out of the box)
java -jar serverguard.jar
# Web Console: http://localhost:8080
```

### Agent Plugin Mode (Production)

```bash
# 1. Start ServerGuard engine
java -jar serverguard.jar

# 2. Copy JAR to Paper plugins/
cp serverguard.jar /opt/minecraft/plugins/AluerServerGuard.jar

# 3. Agent config
mkdir -p /opt/minecraft/plugins/AluerServerGuard
echo 'server-url: ws://localhost:8080/agent' > /opt/minecraft/plugins/AluerServerGuard/config.yml

# 4. Start Paper — Agent auto-connects
cd /opt/minecraft && java -Xms4G -Xmx4G -jar paper-1.21.11.jar nogui
```

### Build from Source

```bash
git clone https://github.com/ZpjDev/Aluer.git && cd Aluer
./apache-maven-3.9.6/bin/mvn compile      # Compile 225 source files
./apache-maven-3.9.6/bin/mvn test          # Run 323 tests
./apache-maven-3.9.6/bin/mvn package -DskipTests  # Build JAR (~63MB)
```

---

## Architecture

```
  ┌─────────────────────────┐          WebSocket          ┌──────────────────────────┐
  │     PaperMC Server       │ <=========================> │   ServerGuard Engine     │
  │                          │   ws://host:8080/agent       │   Spring Boot :8080      │
  │  ┌────────────────────┐  │                              │                          │
  │  │ AluerPlugin (Agent) │  │  Agent → Server              │  ┌────────────────────┐  │
  │  │                    │  │  EVENT/METRICS/ALERT         │  │ 135+ Security      │  │
  │  │ 9 Event Listeners  │  │  HEARTBEAT/HANDSHAKE         │  │ Modules            │  │
  │  │ + WebSocket Client │  │                              │  ├────────────────────┤  │
  │  │ + Command Executor │  │  Server → Agent              │  │ ML/AI Engine       │  │
  │  └────────────────────┘  │  COMMAND/CONFIG/SHUTDOWN     │  │ + DeepSeek Client  │  │
  │                          │                              │  │ + Kernel Autonomy  │  │
  │  Immediate interception  │                              │  │ + Web Console      │  │
  │  event.setCancelled()    │                              │  └────────────────────┘  │
  └─────────────────────────┘                              └──────────────────────────┘
```

**Message Types (Agent → Server):** `EVENT` · `METRICS` · `ALERT` · `HEARTBEAT` · `HANDSHAKE` · `COMMAND_RESULT`

**Commands (Server → Agent):** `BAN_IP` · `BAN_PLAYER` · `KICK` · `CLEAR_LAG` · `SET_SPAWN_RATE` · `ENABLE_WHITELIST` · `BROADCAST` · `SAVE_ALL` · `EXECUTE`

---

## Security Modules

### Anti-Cheat — 100% Meteor Client Coverage

**Combat (16 modules):** `AntiKillAura` · `AntiReach` · `AntiAutoClicker` · `AntiCriticals` · `AntiAutoCrystal` · `AntiAutoTotem` · `AntiSurround` · `AntiAutoTrap` · `AntiAutoArmor` · `AntiChestSwap` · `AntiAutoLog` · `AntiHitboxes` · `AntiBowAimBot` · `AntiVelocity` · `AntiAnchor`

**Movement (19 modules):** `AntiFly` · `AntiSpeed` · `AntiJesus` · `AntiNoFall` · `AntiTimer` · `AntiPhase` · `AntiBlink` · `AntiScaffold` · `AntiSpider` · `AntiStep` · `AntiNoSlow` · `AntiPacketFly` · `AntiAirJump` · `AntiLongJump` · `AntiAntiHunger` · `AntiFastFall` · `AntiVClip` · `AntiElytraFly`

**World (13 modules):** `AntiNuker` · `AntiAutoMine` · `AntiSpeedMine` · `AntiFastBreak` · `AntiFastUse` · `AntiNoInteract` · `AntiVeinMiner` · `AntiAutoTool` · `AntiAutoFish` · `AntiChestSteal` · `AntiXray` · `AntiBaritone` · `AntiGrief`

**Misc (9 modules):** `AntiDupe` · `AntiFakePlayer` · `AntiPistonAura` · `AntiStashFinder` · `AntiInventoryManipulation` · `AntiNameSpoof` · `AntiSkinSpoof` · `AntiAltAccount` · `AntiOfflineModeSpoof`

**Network Protocol (7):** `ProtocolStateValidator` · `TokenBucketRateLimiter` · `BotFingerprintDetector` · `NBTExploitPrevention` · `ConnectionHandshakeValidator` · `DDoSProtection` · `DDoSDefenseCoordinator`

**Server Protection (11):** `AntiSignExploit` · `AntiBookBan` · `AntiResourcePackExploit` · `AntiTabCompleteCrash` · `CrashExploitProtection` · `CrashExploitSignatureDB` · `LagMachineDetection` · `PacketFloodProtection` · `ChunkLoadRateLimiter` · `EntityCountEnforcer` · `RedstoneUpdateLimiter`

**Chat Security (5):** `ChatFloodProtection` · `AntiAdvertisement` · `AntiPhishingLink` · `AntiCommandAbuse` · `PlayerPrivacy`

**ML/AI Engine (6):** `BehavioralProfilingEngine` · `ThreatScoreAggregator` · `MovementPatternAnalyzer` · `CombatPatternRecognizer` · `AnomalyDetector` · `TimeSeriesPredictor`

**Defense-in-Depth (30+):** WAF · IDS · IPS · SIEM · Honeypot · EDR · ZeroTrust · JWT · SSL/TLS · GeoBlock · VPN · DNS Tunnel · ARP Spoof · ReverseShell · Process Injection · File Integrity · Backdoor Plugin · Compliance · Forensics · Threat Hunting · Incident Response · Security Baseline · Container Security

---

## Meteor Client Coverage Matrix

| Category | Meteor Hacks | Aluer Counter-Modules | Coverage |
|----------|-------------|----------------------|----------|
| Combat | 15 | 16 | **100%** |
| Movement | 18 | 19 | **100%** |
| World | 12 | 13 | **100%** |
| Player | 5 | 10 | **100%** |
| Misc | 5 | 9 | **100%** |
| **Total** | **55** | **66** | **100%** |

[Meteor Client](https://github.com/MeteorDevelopment/meteor-client) is the largest Minecraft cheat client. Every single hack module has a corresponding detection service in Aluer ServerGuard.

---

## Deployment

### Mode Comparison

| Feature | Agent Plugin | External |
|---------|-------------|----------|
| Communication | WebSocket bidirectional real-time | RCON + log parsing |
| Latency | < 1ms (local) | 50-200ms (RCON) |
| Event Throughput | 50,000+ events/s | Log-dependent |
| Data Precision | Bukkit Event level (per tick) | Log text level (seconds delay) |
| MC Invasiveness | Paper plugin (~50MB) | Zero (RCON port only) |
| Instant Interception | Yes (event.setCancelled) | No (post-alert only) |
| Module Coverage | Full 135+ modules | ~40 external monitor modules |
| Recommended | **Production** | Evaluation / Testing |

---

## In-Game Commands

| Command | Permission | Description |
|---------|-----------|-------------|
| `/aluer status` | `aluer.status` | Protection status, TPS, online players, packet rate |
| `/aluer scan <player>` | `aluer.admin` | Deep scan: position/IP/ping/fly/attack history/messages/commands |
| `/aluer info` | `aluer.status` | Version, tech stack, module count, mode |
| `/aluerplayers` | `aluer.status` | Online player list with risk flags |
| `/aluerblock player <name>` | `aluer.admin` | Ban player + broadcast |
| `/aluerblock ip <addr>` | `aluer.admin` | Ban IP + kick all from that IP |
| `/aluerwhitelist on/off/status` | `aluer.admin` | Emergency whitelist management |

---

## Build & Test

| Metric | Value |
|--------|-------|
| Source Files | 225 |
| Code Lines | 73,229 |
| Security Modules | 151 files, 53,763 lines |
| Test Files | 19 |
| Test Cases | 323 |
| Test Result | **323/323 PASS, 0 failures** |

```bash
./apache-maven-3.9.6/bin/mvn compile          # Compile
./apache-maven-3.9.6/bin/mvn test             # 323 tests
./apache-maven-3.9.6/bin/mvn package -DskipTests  # Build JAR
```

---

## Tech Stack

| Technology | Version | Purpose |
|-----------|---------|---------|
| Java | 21 | Core language |
| Spring Boot | 3.2.0 | Framework (Web · WebSocket · Mail · Shell) |
| PaperMC API | 1.21.1-R0.1-SNAPSHOT | Minecraft integration |
| Apache Commons Math3 | 3.6.1 | Statistics · ML (DescriptiveStatistics/TTest/FFT) |
| Gson | 2.10.1 | JSON serialization |
| DeepSeek API | /v1/chat/completions | AI decision engine |
| React 19 + Vite 6 | — | Web console frontend |

---

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `SERVERGUARD_MODE` | Run mode: `plugin` or `external` | `external` |
| `DEEPSEEK_API_KEY` | DeepSeek AI API key | (empty = AI disabled) |
| `RCON_PASSWORD` | Minecraft RCON password | (empty) |
| `SERVER_PORT` | Web server port | `8080` |
| `ALUER_ALERT_SMTP_USERNAME` | Alert email SMTP username | (empty) |
| `ALUER_ALERT_EMAIL_PRIMARY` | Alert email recipient | (empty) |
| `ALUER_CLOUDFLARE_ZONE_ID` | Cloudflare Zone ID | (empty) |

---

## FAQ

<details>
<summary><b>Agent vs External mode?</b></summary>

Agent Plugin mode is strongly recommended for production — sub-millisecond latency, 50K+ events/s, per-tick data precision, instant event cancellation, full 135+ module coverage. External mode for evaluation or plugin-free setups.
</details>

<details>
<summary><b>Is DeepSeek AI required?</b></summary>

No. Without `DEEPSEEK_API_KEY`, AI auto-disables and the system operates as rule engine + ML mode with full anti-cheat capability. AI adds intelligent root cause analysis, health reports, and autonomous defense generation.
</details>

<details>
<summary><b>Java version required?</b></summary>

Java 21+. Paper 1.21.1 API (class version 65) requires Java 21 runtime.
</details>

<details>
<summary><b>Supported Minecraft versions?</b></summary>

PaperMC 1.21.1. Can be adapted to Paper 1.20.5+ (needs Java 21). Paper 1.20.4 and below require Java 17 downgrade.
</details>

<details>
<summary><b>Will it false-ban legit players?</b></summary>

Layered design minimizes false bans: immediate interception only at physically impossible values, server-side multi-dimensional cross-validation, AI auto-execute requires ≥88% confidence, and SelfHealing/HostEnforcement default to dry-run mode.
</details>

---

## Contributors

| Contributor | GitHub | Role |
|------------|--------|------|
| Peijun Zhao | [@ZpjDev](https://github.com/ZpjDev) | Architecture Design & Core Development |

---

## License

**Apache License 2.0** — see [LICENSE](LICENSE) for full text.

<p align="center">
  <br>
  <b>Aluer ServerGuard V5.0</b><br>
  <sub>Protecting Every Minecraft Server</sub>
</p>
