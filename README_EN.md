# Aluer ServerGuard V5.0

> AI-Powered Comprehensive Protection System for Minecraft PaperMC Servers

---

## Project Overview

Aluer ServerGuard is a next-generation intelligent security protection system designed for Minecraft PaperMC servers. The system features an **Agent architecture** with a lightweight Paper plugin serving as the data collection frontend, paired with an external Spring Boot analysis engine, delivering comprehensive real-time server protection.

Key Features:
- **AI Behavioral Analysis**: Anomaly detection based on Isolation Forest and time series prediction
- **DeepSeek LLM Integration**: Automated security alert analysis and defense strategy generation
- **Full Anti-Cheat Coverage**: Countermeasures against every hack module in Meteor Client and similar cheat clients
- **Server Self-Healing**: Automatic recovery from TPS/CPU/Memory anomalies, built-in DDoS defense
- **Dual-Mode Deployment**: Plugin embedded mode and External monitoring mode
- **135+ Security Modules**: Covering anti-cheat, network security, host security, intrusion detection, and forensic analysis

---

## Version History

| Version | Date | Key Updates |
|---------|------|-------------|
| V5.3 | 2026-05 | Meteor Client world/player/misc countermeasures: SpeedMine, FastUse, NoInteract, AutoMine, VeinMiner, AutoTool, FakePlayer, PistonAura, Anchor, StashFinder |
| V5.2 | 2026-05 | Meteor Client movement countermeasures: NoSlow, Spider, Step, PacketFly, AirJump, LongJump, AntiHunger, FastFall, VClip |
| V5.1 | 2026-05 | Meteor Client combat countermeasures: Criticals, AutoTotem, Surround, AutoTrap, AutoCrystal, AutoArmor, ChestSwap, AutoLog, Hitboxes, BowAimbot |
| V5.0 | 2026-04 | Agent architecture refactoring, WebSocket real-time communication, Timer/Velocity/Phase/Blink/FastBreak/ElytraFly anti-cheat |
| V4.0 | 2026-03 | KillAura/Reach/Speed/Jesus/NoFall/Scaffold/Nuker/AutoClicker anti-cheat, player behavior, server protection |

---

## Architecture

```
+---------------------------------------------------------------------+
|                   Aluer ServerGuard System Architecture               |
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

**Communication Protocol**: All messages are single-line JSON transmitted via WebSocket text frames in both directions.

Agent-to-Server message types:
- `EVENT` -- Bukkit event data (player movement, combat, block operations, etc.)
- `METRICS` -- Server metrics (TPS, CPU, Memory, online player count)
- `ALERT` -- Security alerts
- `HEARTBEAT` -- Keep-alive heartbeat
- `HANDSHAKE` -- Initial connection handshake
- `COMMAND_RESULT` -- Command execution acknowledgment

Server-to-Agent command types:
- `COMMAND` -- Execute action (BAN_IP, BAN_PLAYER, KICK, CLEAR_LAG, etc.)
- `CONFIG` -- Dynamic configuration update
- `SHUTDOWN` -- Close connection

---

## Technology Stack

| Technology | Version | Purpose |
|------------|---------|---------|
| Java | 21 | Core language |
| Spring Boot | 3.2.0 | Application framework |
| Maven | 3.9.6 | Build management |
| PaperMC API | 1.21.1-R0.1-SNAPSHOT | Minecraft server API |
| Spring WebSocket | 3.2.0 | Agent communication |
| Spring Mail | 3.2.0 | Email alerts |
| Spring Shell | 3.1.3 | CLI interaction |
| SnakeYAML | 2.2 | YAML configuration |
| Smile | 2.6.0 | Machine learning algorithms |
| Apache Commons Math | 3.6.1 | Math/statistics |
| Gson | (embedded) | JSON serialization |

---

## Complete Security Module Inventory

### I. Anti-Cheat -- Combat (15 modules)

| Module | Hack Detected | Detection Method |
|--------|---------------|------------------|
| AntiKillAuraService | KillAura | Multi-target switching, aimbot angle consistency, max-range attack patterns |
| AntiReachService | Reach | Attack distance validation, position backtracking |
| AntiSpeedService | Speed | Horizontal movement speed anomaly analysis |
| AntiCriticalsService | Criticals | Zero-velocity crits, no-jump crits, crit rate statistics |
| AntiAutoCrystalService | AutoCrystal | Crystal placement/detonation speed, optimal position calculation detection |
| AntiAutoTotemService | AutoTotem | Totem re-equip speed (ms-level), consecutive totem usage pattern |
| AntiSurroundService | Surround | Four-direction block placement speed, defensive block pattern recognition |
| AntiAutoTrapService | AutoTrap | Target player cage construction speed, piston trap automation |
| AntiAutoArmor | AutoArmor | Multi-slot armor switching speed, backpack scan pattern |
| AntiChestSwap | ChestSwap | Chestplate/elytra swap tick-level detection |
| AntiAutoLog | AutoLog | Post-damage disconnect pattern, low-HP disengagement detection |
| AntiHitboxes | Hitboxes | Edge hit rate, ray trace distance distribution analysis |
| AntiBowAimbot | BowAimbot | Moving target hit rate, trajectory consistency, instant precision |
| AntiVelocityService | Velocity | Knockback magnitude anomaly, anti-knockback detection |
| AntiAutoClickerService | AutoClicker | CPS statistics, click interval entropy analysis |

### II. Anti-Cheat -- Movement (18 modules)

| Module | Hack Detected | Detection Method |
|--------|---------------|------------------|
| AntiFlyDetectionService | Fly | Vertical/horizontal velocity, hover duration, movement pattern analysis |
| AntiJesusService | Jesus | Water/lava surface movement validation |
| AntiNoFallService | NoFall | Landing detection, fall damage validation |
| AntiSpeedService | Speed | Horizontal movement speed anomaly analysis |
| AntiTimerService | Timer | Game tick interval anomaly, movement speed frequency analysis |
| AntiPhaseService | Phase | Block clipping/penetration detection, solid block pass-through validation |
| AntiBlinkService | Blink | Rapid disconnect damage evasion detection |
| AntiSpiderService | Spider | Non-climbable block wall movement, vertical wall movement detection |
| AntiStepService | Step | Full-block step-up without jump detection |
| AntiNoSlowService | NoSlow | Item-use movement speed detection (eating/bow/shield) |
| AntiPacketFlyService | PacketFly | Packet manipulation flight, oscillation patterns, never-landing detection |
| AntiAirJumpService | AirJump | Mid-air jump packet detection, consecutive aerial jumps |
| AntiLongJump | LongJump | Extreme horizontal jump distance detection |
| AntiAntiHunger | AntiHunger | Zero hunger consumption under high activity detection |
| AntiFastFall | FastFall | Above-terminal-velocity falling detection |
| AntiVClip | VClip | Instant vertical block penetration (excluding legitimate teleport) |
| AntiElytraFlyService | ElytraFly | Elytra speed/altitude manipulation detection |
| AntiScaffoldService | Scaffold | Block placement frequency/angle/speed pattern analysis |

### III. Anti-Cheat -- World/Player/Misc (19 modules)

| Module | Hack Detected | Detection Method |
|--------|---------------|------------------|
| AntiNukerService | Nuker | Mining speed/range/pattern recognition |
| AntiAutoMineService | AutoMine | Automated mining behavior detection |
| AntiSpeedMineService | SpeedMine | Accelerated mining (InstaMine/PacketMine) detection |
| AntiFastBreakService | FastBreak | Block breaking speed anomaly detection |
| AntiFastUseService | FastUse | Item use acceleration detection |
| AntiNoInteractService | NoInteract | Interaction bypass detection |
| AntiVeinMinerService | VeinMiner | Automated vein mining pattern detection |
| AntiAutoTool | AutoTool | Instant tool switching detection |
| AntiAutoFishService | AutoFish | Fishing behavior timing/reaction speed analysis |
| AntiChestStealService | ChestSteal | Container open/loot speed pattern recognition |
| AntiInventoryManipulationService | InventoryManipulation | Inventory operation speed, illegal slot operation detection |
| AntiBaritoneService | Baritone | Path smoothness/behavior repetition analysis |
| AntiXrayDetectionService | Xray | Diamond ratio/straight-line mining/dark-precision detection |
| AntiGriefDetectionService | Grief | Block destruction rate/TNT/arson/chest theft detection |
| AntiFakePlayer | FakePlayer | Fake player entity detection |
| AntiPistonAura | PistonAura | Piston trap automation detection |
| AntiAnchor | Anchor | Hole anchor defense detection |
| AntiStashFinder | StashFinder | Automated storage cache scanning detection |
| AntiDupeDetectionService | AntiDupe | Item duplication detection (stack anomaly, 9 duplication methods) |

### IV. Server Exploit Protection (12 modules)

| Module | Protection Target |
|--------|-------------------|
| AntiSignExploitService | Sign NBT exploits (oversized JSON, invalid components, NBT bombs) |
| AntiBookBanService | Book ban exploits (oversized pages, deep JSON nesting) |
| AntiResourcePackExploitService | Resource pack exploits (malicious URLs, oversized files, format validation) |
| AntiTabCompleteCrashService | Tab-complete crash (long text, deep nesting completion limits) |
| AntiOfflineModeSpoofService | Offline UUID spoofing (premium UUID conflicts, IP correlation) |
| CrashExploitProtectionService | Crash exploit protection (oversized packets, NBT bombs, book attacks) |
| CrashExploitSignatureDB | Crash exploit signature database (12 known signatures) |
| LagMachineDetectionService | Lag machine detection (observer chains, TNT stacks, redstone density) |
| ChunkLoadRateLimiter | Chunk load rate limiting (WARN/LIMIT/BLOCK 3-tier response) |
| EntityCountEnforcer | Entity count enforcement (per-chunk/player/type auto-removal) |
| RedstoneUpdateLimiter | Redstone update frequency limiting (degrade/freeze/exponential backoff) |
| PacketFloodProtectionService | Packet flood protection |

### V. Chat & Social Security (5 modules)

| Module | Protection Target |
|--------|-------------------|
| ChatFloodProtectionService | Chat flood (frequency, similarity, length surges) |
| AntiAdvertisementService | Advertisement detection (IP/domain/group ID regex) |
| AntiPhishingLinkService | Phishing links (suspicious domains, short links, SSL verification) |
| AntiCommandAbuseService | Command abuse (rate limiting, sensitive command interception) |
| PlayerPrivacyService | Player privacy (IP anonymization, coordinate hiding, log anonymization) |

### VI. Network Security (13 modules)

| Module | Protection Target |
|--------|-------------------|
| DDoSProtectionService | DDoS attacks (SYN/UDP/ICMP/HTTP/Slow connection/Amplification) |
| DDoSDefenseCoordinator | Multi-layer DDoS defense orchestration |
| ProtocolStateValidator | Protocol state machine (HANDSHAKE/STATUS/LOGIN/PLAY transitions) |
| BotFingerprintDetector | Bot fingerprint (login timing, naming patterns, movement entropy) |
| NBTExploitPrevention | NBT exploit prevention (depth/size limits) |
| ConnectionHandshakeValidator | Handshake validation (protocol version, hostname, ping flood, port scan) |
| PortScanDetectionService | Port scan detection |
| BruteForceProtectionService | Brute force protection (multi-window detection) |
| AntiVPNProxyService | VPN/proxy detection (known VPN IP database, hosting ASN matching) |
| DNSTunnelDetectionService | DNS tunnel detection (entropy, Base32 encoding, suspicious TLDs) |
| ReverseShellDetectionService | Reverse shell detection (50+ shell pattern matching) |
| ProcessInjectionDetectionService | Process injection detection |
| ARPSpoofDetectionService | ARP spoofing detection (MAC changes, gateway forgery) |

### VII. Host & Access Control Security (6 modules)

| Module | Protection Target |
|--------|-------------------|
| FileIntegrityMonitorService | File integrity monitoring (hash baseline, real-time monitoring) |
| BackdoorPluginScannerService | Backdoor plugin scanning (known malicious class names, remote execution) |
| ConfigTamperDetectionService | Configuration tampering detection (ops/whitelist real-time monitoring) |
| OPPrivilegeMonitorService | OP privilege monitoring (privilege changes, sensitive command auditing) |
| AntiAltAccountService | Alt account detection (IP correlation, behavioral similarity, login patterns) |
| AntiNameSpoofService | Name spoofing detection (admin/famous player nickname forgery) |

### VIII. Advanced Security Infrastructure (28 modules)

| Module | Function |
|--------|----------|
| PlayerSessionValidationService | Player session validation (UUID forgery, premium/offline detection) |
| PluginVerificationService | Plugin integrity verification (hash comparison, unauthorized modification) |
| BackupIntegrityService | Backup integrity verification (SHA-256, file count, size comparison) |
| ConnectionThrottleService | Connection rate limiting (IP/time window/incremental delay) |
| GeoBlockService | Geographic IP blocking (country/region filtering) |
| AntiSkinSpoofService | Skin spoofing detection (model data anomaly, skin URL detection) |
| JwtAuthService | JWT authentication and token management |
| AntiBotDetectionService | Anti-bot detection (name, join rate, IP correlation) |
| CSPEnforcementService | CSP security header enforcement (8 response headers) |
| SSRFProtectionService | SSRF protection (internal IP, cloud metadata, protocol restrictions) |
| XXEProtectionService | XXE protection (entity injection, Billion Laughs detection) |
| DatabaseFirewallService | Database firewall (SQL injection, UNION queries, time-based blind) |
| DataLossPreventionService | Data loss prevention (12 sensitive info rules, auto-masking) |
| MemoryProtectionService | JVM memory protection (heap/GC/memory leak detection) |
| SecureFileDeletionService | Secure file deletion (multi-pass overwrite, DoD standard) |
| ForensicsCollectorService | Forensic collection (process/network/log snapshots) |
| IncidentResponseService | Incident response (5 predefined response playbooks) |
| ThreatHuntingService | Threat hunting (10 hunt definitions, 5 categories) |
| ComplianceScannerService | Compliance scanning (7 categories, 20+ checks) |
| ExploitSignatureService | Exploit signature detection (Log4Shell, SQLi, RCE -- 15 types) |
| SecurityOrchestrationService | Multi-layer defense orchestration |
| SecurityAutomationScheduler | Security automation scheduling |
| HostEnforcementService | Host-level enforcement |
| HostIntrusionCountermeasureService | Host intrusion countermeasures |
| IntrusionDetectionService | Network intrusion detection |
| IntrusionPreventionSystem | Network intrusion prevention |
| WebApplicationFirewall | Web application firewall |
| ZeroTrustArchitectureService | Zero-trust architecture |

### IX. Network & Traffic Analysis (10 modules)

| Module | Function |
|--------|----------|
| NetworkMonitorService | Network traffic monitoring |
| NetworkSnifferService | Network packet sniffing |
| NetworkThreatFusionService | Multi-source threat intelligence fusion |
| FlowAnalyzerService | Traffic behavior analysis |
| TrafficAnalysisService | Traffic pattern analysis |
| TrafficShapingService | Traffic shaping and QoS |
| PacketInspectionService | Deep packet inspection |
| ProtocolAnalysisService | Protocol anomaly analysis |
| TokenBucketRateLimiter | Reusable token bucket rate limiting primitive |
| FirewallService | System firewall management |

### X. Infrastructure & Operations Security (8 modules)

| Module | Function |
|--------|----------|
| SIEMService | Security information and event management |
| LogAnalysisService | Log pattern analysis |
| LogCorrelationService | Cross-source log correlation |
| ThreatIntelligenceService | Threat intelligence aggregation |
| IPReputationService | IP reputation database queries |
| SSLTLSCertificateService | SSL/TLS certificate management |
| SecurityBaselineHardeningService | Security baseline hardening |
| ContainerSecurityService | Container runtime security |

### XI. ML/AI Behavioral Analysis (4 modules)

| Module | Function |
|--------|----------|
| BehavioralProfilingEngine | Player behavioral profiling (statistical baseline modeling) |
| CombatPatternRecognizer | Combat pattern recognition (anomalous combat sequence detection) |
| MovementPatternAnalyzer | Movement pattern analysis (trajectory anomalies, path entropy) |
| ThreatScoreAggregator | Threat score aggregation (multi-dimensional threat fusion and escalation) |

---

## Deployment Guide

### Mode 1: Plugin Embedded Mode (Recommended)

ServerGuard runs directly inside the Minecraft server process as a Paper plugin, achieving zero network latency and maximum real-time performance.

**Prerequisites:**
- Minecraft PaperMC 1.21.1 server installed
- Java 21 runtime
- ServerGuard engine JAR compiled

**Deployment Steps:**

1. **Build the plugin**
   ```bash
   cd /opt/AluerIII
   ./apache-maven-3.9.6/bin/mvn package -DskipTests
   ```

2. **Install plugin to Minecraft server**
   ```bash
   cp target/serverguard-4.0.0.jar /opt/minecraft/plugins/AluerServerGuard.jar
   ```

3. **Create plugin config** at `plugins/AluerServerGuard/config.yml`:
   ```yaml
   server-url: ws://localhost:8080/agent
   ```

4. **Start ServerGuard engine** (must start before Minecraft server)
   ```bash
   java -jar target/serverguard-4.0.0.jar
   ```

5. **Start Minecraft server**
   ```bash
   cd /opt/minecraft
   java -Xms4G -Xmx4G -jar paper-1.21.11.jar
   ```

Upon startup, AluerPlugin will automatically connect to the ServerGuard engine via WebSocket and begin pushing Bukkit event data.

### Mode 2: External Monitoring Mode

ServerGuard runs as an independent process, providing external protection via RCON and log monitoring. Suitable for scenarios where plugin installation is not desired.

**Deployment Steps:**

1. **Build**
   ```bash
   ./apache-maven-3.9.6/bin/mvn package -DskipTests
   ```

2. **Configure `application.yml`**
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

3. **Enable RCON in Minecraft `server.properties`**
   ```properties
   enable-rcon=true
   rcon.port=25575
   rcon.password=your_rcon_password_here
   ```

4. **Start ServerGuard**
   ```bash
   java -jar target/serverguard-4.0.0.jar
   ```

---

## Configuration Reference

### Core Configuration (serverguard.*)

```yaml
serverguard:
  mode: ${SERVERGUARD_MODE:external}  # plugin or external

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
    tps-threshold: 15           # Alert when TPS falls below this value
    cpu-threshold: 80.0         # Alert when CPU usage exceeds this value (%)
    memory-threshold: 85.0      # Alert when memory usage exceeds this value (%)
    connection-threshold: 50    # Alert when concurrent connections exceed this value
    log-watch-lines: 100        # Number of log lines to monitor
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
        per-type-seconds: 300     # Minimum interval between same-type alerts (seconds)
        max-emails-per-minute: 10 # Maximum emails per minute
```

### AI Configuration (serverguard.ai.*)

```yaml
  ai:
    enabled: true
    use-isolation-forest: true       # Enable Isolation Forest anomaly detection
    use-prediction: true              # Enable time series prediction
    sliding-window-size: 100          # Analysis sliding window size
    anomaly-threshold: 0.7            # Anomaly detection threshold (0-1)
    prediction-horizon-minutes: 60    # Prediction horizon (minutes)
    deepseek:
      enabled: true
      api-key: ${DEEPSEEK_API_KEY:}
      base-url: ${DEEPSEEK_BASE_URL:https://api.deepseek.com}
      model: ${DEEPSEEK_MODEL:deepseek-chat}
      max-tokens: 1000
      temperature: 0.35               # Analysis stability (0=precise, 1=creative)
      auto-analyze-alerts: true       # Automatically analyze alerts
      analysis-interval-seconds: 45   # Analysis interval (seconds)
      auto-execute:
        enabled: true
        ban-ip: true                  # Allow automatic IP banning
        kill-entity: true             # Allow automatic entity cleanup
        clear-lag: true               # Allow automatic lag clearing
        set-spawn-rate: true          # Allow automatic spawn rate adjustment
        kick-player: true             # Allow automatic player kicking
        whitelist: true               # Allow automatic whitelist enabling
        min-confidence: 88            # Minimum confidence for auto-execution (%)
```

### Security Configuration (serverguard.security.*)

```yaml
  security:
    enabled: true
    auto-ban-vpn: true
    check-on-login: true
    max-connections-per-ip: 3      # Maximum connections per IP
    block-common-exploits: true
    log-all-commands: true

    minecraft-defense:
      enabled: true
      game-tcp-port: 25565
      query-udp-port: 25565
      rcon-tcp-port: 25575
      status-ping-threshold: 25       # Status ping flood threshold
      login-burst-threshold: 12       # Login burst threshold
      bot-swarm-threshold: 15         # Bot swarm threshold
      query-flood-threshold: 30       # Query flood threshold
      rcon-brute-force-threshold: 5   # RCON brute force threshold
      compression-payload-threshold: 8192  # Compression payload maximum

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
      dry-run: true                      # Dry-run mode (no actual blocking)
      preferred-backend: auto            # Backend: auto/iptables/nftables/firewalld
      default-block-minutes: 60          # Default block duration (minutes)
      default-rate-limit-per-minute: 120 # Default rate limit per minute
      mirror-to-cloud-edge: true         # Mirror to cloud edge

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
      feed-refresh-minutes: 15        # Threat intel refresh interval
      posture-snapshot-minutes: 5     # Security posture snapshot interval
      integrity-rescan-minutes: 30    # Integrity rescan interval
      rule-sync-minutes: 10           # Rule sync interval
      incident-retention-minutes: 120 # Incident retention period

    autonomy:
      enabled: true
      deepseek-dominant: true              # DeepSeek-dominant decision making
      quiet-console: true                   # Quiet console mode
      loop-interval-seconds: 45             # Autonomy loop interval
      min-risk-score-for-action: 70         # Minimum risk score for action
      critical-risk-score: 90               # Critical risk score
      workflow-cooldown-seconds: 180        # Workflow cooldown
      max-actions-per-hour: 12              # Maximum actions per hour
      require-second-signal-for-containment: true  # Require second signal for containment

    shield:
      enabled: true
      auto-mode: true
      auto-enable-under-attack: true
      heat-trigger: 78                      # Heat trigger threshold
      resonance-trigger: 72                 # Resonance trigger threshold
      threat-score-trigger: 85              # Threat score trigger threshold
      edge-challenge-offender-limit: 6      # Edge challenge offender limit
      shelter-rate-limit-per-minute: 45     # Shelter rate limit per minute
      attacker-notice-enabled: true
      deterrence-message: "Your source has been identified, recorded, and isolated by Aluer."

    kernel:
      enabled: true
      pulse-interval-seconds: 30        # Pulse interval
      pulse-history-size: 180           # Pulse history size
      journal-size: 300                 # Journal size
      echo-retention-minutes: 180       # Echo retention period
      adaptive-weights: true            # Adaptive weights
      directive-heat-threshold: 60      # Directive heat threshold
      lockdown-heat-threshold: 82       # Lockdown heat threshold

    task-bus:
      enabled: true
      auto-dispatch: true
      dispatch-interval-seconds: 10
      queue-limit: 200
      history-limit: 300

    self-healing:
      enabled: true
      dry-run: true                          # Dry-run mode
      loop-interval-seconds: 45
      auto-backup-before-recovery: true      # Auto-backup before recovery
      auto-whitelist-on-swarm: true          # Auto-whitelist on bot swarm
      allow-soft-restart: true               # Allow soft restart
      tps-emergency-threshold: 12            # TPS emergency threshold
      cpu-emergency-threshold: 92.0          # CPU emergency threshold (%)
      memory-emergency-threshold: 95.0       # Memory emergency threshold (%)
      max-recovery-actions-per-hour: 8       # Maximum recovery actions per hour
```

### SuperEvolution Module Switches (serverguard.security.super-evolution.*)

```yaml
    super-evolution:
      # === V4.0 Advanced Security Modules ===
      jwt-auth: true                    # JWT authentication and token management
      brute-force: true                 # Brute force protection (multi-window detection)
      anti-bot: true                    # Anti-bot detection
      reverse-shell: true               # Reverse shell detection (50+ pattern matching)
      arp-spoof: true                   # ARP spoofing detection
      dns-tunnel: true                  # DNS tunnel detection (entropy/Base32/suspicious TLDs)
      exploit-signature: true            # Exploit signature detection (Log4Shell/SQLi/RCE -- 15 types)
      ssrf: true                        # SSRF protection
      xxe: true                         # XXE protection
      csp: true                         # CSP security header enforcement
      database-firewall: true           # Database firewall
      dlp: true                         # Data loss prevention (12 sensitive info rules)
      memory-protection: true           # JVM memory protection
      process-injection: true           # Process injection detection
      secure-delete: true               # Secure file deletion
      forensics: true                   # Forensic collection
      incident-response: true           # Incident response (5 predefined playbooks)
      threat-hunting: true              # Threat hunting (10 hunt definitions)
      compliance: true                  # Compliance scanning (7 categories, 20+ checks)
      anti-grief: true                  # Anti-grief detection
      # === Minecraft-Specific Protection ===
      anti-xray: true                   # X-ray detection
      anti-fly: true                    # Fly hack detection
      anti-dupe: true                   # Item duplication detection (9 methods)
      crash-exploit: true               # Crash exploit protection
      lag-machine: true                 # Lag machine detection
      # === V4.0 New Modules ===
      geo-block: true                   # Geographic IP blocking
      session-validation: true          # Player session validation
      plugin-verification: true         # Plugin integrity verification
      connection-throttle: true         # Connection rate limiting
      backup-integrity: true            # Backup integrity verification
      anti-skin-spoof: true             # Skin spoofing detection
      # === V4.0 Anti-Cheat Extended ===
      anti-kill-aura: true              # KillAura detection
      anti-reach: true                  # Reach detection
      anti-speed: true                  # Speed detection
      anti-jesus: true                  # Jesus detection
      anti-no-fall: true                # NoFall detection
      anti-scaffold: true               # Scaffold detection
      anti-timer: true                  # Timer detection
      anti-velocity: true               # Velocity detection
      anti-phase: true                  # Phase detection
      anti-blink: true                  # Blink detection
      anti-fast-break: true             # FastBreak detection
      anti-elytra-fly: true             # ElytraFly detection
      # === V4.0 Player Behavior ===
      anti-nuker: true                  # Nuker detection
      anti-auto-clicker: true           # AutoClicker detection
      anti-chest-steal: true            # ChestSteal detection
      anti-auto-fish: true              # AutoFish detection
      anti-inventory-manipulation: true # Inventory manipulation detection
      anti-baritone: true               # Baritone detection
      # === V4.0 Server Protection ===
      packet-flood-protection: true     # Packet flood protection
      anti-sign-exploit: true           # Sign exploit protection
      anti-book-ban: true               # Book ban protection
      anti-resource-pack-exploit: true  # Resource pack exploit protection
      anti-tab-complete-crash: true     # Tab complete crash protection
      anti-offline-mode-spoof: true     # Offline mode spoof protection
      # === V4.0 Access Control ===
      op-privilege-monitor: true        # OP privilege monitoring
      config-tamper-detection: true     # Config tamper detection
      backdoor-plugin-scanner: true     # Backdoor plugin scanner
      anti-vpn-proxy: true              # VPN/proxy detection
      anti-alt-account: true            # Alt account detection
      anti-name-spoof: true             # Name spoofing detection
      # === V4.0 Chat & Social Security ===
      chat-flood-protection: true       # Chat flood protection
      anti-advertisement: true          # Advertisement detection
      anti-phishing-link: true          # Phishing link detection
      anti-command-abuse: true          # Command abuse detection
      player-privacy: true              # Player privacy protection
      # === V5.0 Server Protection Extended ===
      chunk-load-rate-limiter: true     # Chunk load rate limiter
      entity-count-enforcer: true       # Entity count enforcer
      redstone-update-limiter: true     # Redstone update limiter
      crash-exploit-signature-db: true  # Crash exploit signature database
      # === V4.0 Network Protocol Security ===
      protocol-validator: true          # Protocol state validator
      token-bucket-rate-limiter: true   # Token bucket rate limiter
      bot-fingerprint: true             # Bot fingerprint detection
      nbt-exploit-prevention: true      # NBT exploit prevention
      handshake-validator: true         # Connection handshake validator
      # === V5.1 Anti-Cheat Combat (Meteor Client) ===
      anti-criticals: true              # Criticals detection
      anti-auto-totem: true             # AutoTotem detection
      anti-surround: true               # Surround detection
      anti-auto-trap: true              # AutoTrap detection
      anti-auto-crystal: true           # AutoCrystal detection
      anti-auto-armor: true             # AutoArmor detection
      anti-chest-swap: true             # ChestSwap detection
      anti-auto-log: true               # AutoLog detection
      anti-hitboxes: true               # Hitboxes detection
      anti-bow-aimbot: true             # BowAimbot detection
      # === V5.2 Anti-Cheat Movement (Meteor Client) ===
      anti-no-slow: true                # NoSlow detection
      anti-spider: true                 # Spider detection
      anti-step: true                   # Step detection
      anti-packet-fly: true             # PacketFly detection
      anti-air-jump: true               # AirJump detection
      anti-long-jump: true              # LongJump detection
      anti-anti-hunger: true            # AntiHunger detection
      anti-fast-fall: true              # FastFall detection
      anti-vclip: true                  # VClip detection
      # === V5.3 Anti-Cheat World/Player/Misc (Meteor Client) ===
      anti-speed-mine: true             # SpeedMine detection
      anti-fast-use: true               # FastUse detection
      anti-no-interact: true            # NoInteract detection
      anti-auto-mine: true              # AutoMine detection
      anti-vein-miner: true             # VeinMiner detection
      anti-auto-tool: true              # AutoTool detection
      anti-fake-player: true            # FakePlayer detection
      anti-piston-aura: true            # PistonAura detection
      anti-anchor: true                 # Anchor detection
      anti-stash-finder: true           # StashFinder detection
```

### Other Configuration Sections

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

## WebSocket Communication Protocol

### Message Format

All messages are single-line JSON transmitted via WebSocket text frames.

**Agent to Server event message:**

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

**Agent to Server heartbeat:**

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

**Server to Agent command:**

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

### Complete Event Types

| Event Constant | Value | Description |
|---------------|-------|-------------|
| EVENT_PLAYER_JOIN | PLAYER_JOIN | Player joined server |
| EVENT_PLAYER_QUIT | PLAYER_QUIT | Player left server |
| EVENT_PLAYER_MOVE | PLAYER_MOVE | Player moved (x/y/z coordinates, yaw/pitch angles) |
| EVENT_PLAYER_TELEPORT | PLAYER_TELEPORT | Player teleported |
| EVENT_PLAYER_CHAT | PLAYER_CHAT | Chat message |
| EVENT_PLAYER_COMMAND | PLAYER_COMMAND | Command executed |
| EVENT_PLAYER_DAMAGE | PLAYER_DAMAGE | Player took damage |
| EVENT_COMBAT_ATTACK | COMBAT_ATTACK | Attack event (attacker/target/damage) |
| EVENT_COMBAT_DEATH | COMBAT_DEATH | Death event |
| EVENT_BLOCK_BREAK | BLOCK_BREAK | Block broken (block type/coordinates/tool) |
| EVENT_BLOCK_PLACE | BLOCK_PLACE | Block placed |
| EVENT_INVENTORY_CLICK | INVENTORY_CLICK | Inventory interaction (slot/item type) |
| EVENT_ENTITY_SPAWN | ENTITY_SPAWN | Entity spawned |
| EVENT_CHUNK_LOAD | CHUNK_LOAD | Chunk loaded |

### Complete Command Types

| Command Constant | Value | Description |
|-----------------|-------|-------------|
| CMD_BAN_IP | BAN_IP | Ban IP address |
| CMD_BAN_PLAYER | BAN_PLAYER | Ban player account |
| CMD_KICK | KICK | Kick player from server |
| CMD_CLEAR_LAG | CLEAR_LAG | Remove all non-player entities |
| CMD_SET_SPAWN_RATE | SET_SPAWN_RATE | Dynamically adjust mob spawn rate |
| CMD_ENABLE_WHITELIST | ENABLE_WHITELIST | Enable server whitelist |
| CMD_DISABLE_WHITELIST | DISABLE_WHITELIST | Disable server whitelist |
| CMD_BROADCAST | BROADCAST | Broadcast message to all players |
| CMD_SAVE_ALL | SAVE_ALL | Force save all worlds |
| CMD_EXECUTE | EXECUTE | Execute arbitrary console command |

---

## Alert Types

The system supports 75 alert types defined in `AlertType.java`:

**System Monitoring (8):**
PROCESS_DEAD, TPS_LOW, CPU_HIGH, MEM_HIGH, CONNECTION_FLOOD, LOG_ATTACK, BACKUP_FAILED, AI_ANOMALY

**V4.0 Anti-Cheat (10):**
SECURITY_KILL_AURA, SECURITY_REACH, SECURITY_SPEED, SECURITY_JESUS, SECURITY_NOFALL, SECURITY_SCAFFOLD, SECURITY_NUKER, SECURITY_AUTO_CLICKER, SECURITY_AUTO_FISH, SECURITY_FLY

**V5.0 Anti-Cheat (6):**
SECURITY_TIMER, SECURITY_VELOCITY, SECURITY_PHASE, SECURITY_BLINK, SECURITY_FAST_BREAK, SECURITY_ELYTRA_FLY

**V5.1 Combat (10):**
SECURITY_CRITICALS, SECURITY_AUTO_TOTEM, SECURITY_SURROUND, SECURITY_AUTO_TRAP, SECURITY_AUTO_CRYSTAL, SECURITY_AUTO_ARMOR, SECURITY_CHEST_SWAP, SECURITY_AUTO_LOG, SECURITY_HITBOXES, SECURITY_BOW_AIMBOT

**V5.2 Movement (9):**
SECURITY_NO_SLOW, SECURITY_SPIDER, SECURITY_STEP, SECURITY_PACKET_FLY, SECURITY_AIR_JUMP, SECURITY_LONG_JUMP, SECURITY_ANTI_HUNGER, SECURITY_FAST_FALL, SECURITY_VCLIP

**V5.3 World/Misc (10):**
SECURITY_SPEED_MINE, SECURITY_FAST_USE, SECURITY_NO_INTERACT, SECURITY_AUTO_MINE, SECURITY_VEIN_MINER, SECURITY_AUTO_TOOL, SECURITY_FAKE_PLAYER, SECURITY_PISTON_AURA, SECURITY_ANCHOR, SECURITY_STASH_FINDER

**Player Behavior (6):**
SECURITY_CHEST_STEAL, SECURITY_INVENTORY_MANIPULATION, SECURITY_GRIEF, SECURITY_ALT_ACCOUNT, SECURITY_BARITONE, SECURITY_XRAY

**Server Protection (9):**
SECURITY_SIGN_EXPLOIT, SECURITY_BOOK_BAN, SECURITY_RESOURCE_PACK_EXPLOIT, SECURITY_TAB_COMPLETE_CRASH, SECURITY_OFFLINE_MODE_SPOOF, SECURITY_CHUNK_RATE, SECURITY_ENTITY_LIMIT, SECURITY_REDSTONE_LAG, SECURITY_CRASH_EXPLOIT

**Chat Security (4):**
CHAT_FLOOD, CHAT_ADVERTISEMENT, CHAT_PHISHING, COMMAND_ABUSE

**Network Security (9):**
SECURITY_DDOS, SECURITY_PORT_SCAN, SECURITY_BRUTE_FORCE, SECURITY_VPN_PROXY, SECURITY_DNS_TUNNEL, SECURITY_PROTOCOL_VIOLATION, SECURITY_BOT_FINGERPRINT, SECURITY_NBT_EXPLOIT, SECURITY_HANDSHAKE_ANOMALY

**Host Security (5):**
SECURITY_REVERSE_SHELL, SECURITY_PROCESS_INJECTION, SECURITY_FILE_TAMPER, SECURITY_BACKDOOR_PLUGIN, SECURITY_CONFIG_TAMPER

**ML Analysis (4):**
ML_BEHAVIOR_ANOMALY, ML_THREAT_ESCALATION, ML_MOVEMENT_PATTERN, ML_COMBAT_PATTERN

**General (1):**
SECURITY_OTHER

---

## Testing Guide

### Run Full Test Suite

```bash
cd /opt/AluerIII
./apache-maven-3.9.6/bin/mvn test
```

### Testing Conventions

This project follows strict testing discipline:
- **Live Fire Testing**: Tests must simulate real Minecraft server environments
- **Production Alignment**: Test data and behavior must match actual production environments
- **Dual Constructor Pattern**: Each Service class provides both a no-arg constructor (for testing) and an @Autowired constructor (for production injection)
- **Static Factory Methods**: Detection results use `clean()`, `blocked()`, `flagged()` static factory methods
- **Full Suite Validation**: Full test suite must pass before and after every code change

### Build Commands

```bash
# Compile
./apache-maven-3.9.6/bin/mvn compile

# Run full test suite
./apache-maven-3.9.6/bin/mvn test

# Package (skip tests for quick deployment)
./apache-maven-3.9.6/bin/mvn package -DskipTests

# Clean build artifacts
./apache-maven-3.9.6/bin/mvn clean
```

---

## Project Structure

```
AluerIII/
├── pom.xml                          # Maven build configuration
├── application.yml                  # Spring Boot configuration (316 lines)
├── CLAUDE.md                        # Development guidelines
├── README.md                        # Project README (Chinese)
├── README_EN.md                     # Project README (English)
├── docs/
│   ├── DEVELOPER.md                 # Developer reference
│   ├── PROJECT_SUMMARY.md           # Project overview and module breakdown
│   └── USER_MANUAL.md               # User manual
├── apache-maven-3.9.6/              # Bundled Maven 3.9.6
├── src/
│   ├── main/java/com/aluer/
│   │   ├── ServerGuardApplication.java    # Spring Boot entry point
│   │   ├── config/
│   │   │   └── ServerGuardConfig.java     # Full configuration class (1273 lines, includes SuperEvolutionConfig)
│   │   ├── model/
│   │   │   └── AlertType.java             # Alert type enum (75 alert types)
│   │   ├── agent/
│   │   │   └── AgentMessage.java          # Agent communication protocol
│   │   ├── security/                      # Security modules (123 Java files)
│   │   │   ├── AntiKillAuraService.java
│   │   │   ├── AntiReachService.java
│   │   │   ├── AntiAutoCrystalService.java
│   │   │   ├── ... (120+ more)
│   │   │   └── ZeroTrustArchitectureService.java
│   │   ├── ml/                            # ML modules (4 files)
│   │   │   ├── BehavioralProfilingEngine.java
│   │   │   ├── CombatPatternRecognizer.java
│   │   │   ├── MovementPatternAnalyzer.java
│   │   │   └── ThreatScoreAggregator.java
│   │   ├── plugin/                        # Paper plugin implementation
│   │   │   ├── AluerPlugin.java           # Plugin main class (JavaPlugin)
│   │   │   ├── AluerCommandExecutor.java  # Command registrar
│   │   │   ├── bridge/
│   │   │   │   ├── AgentWebSocketClient.java   # WebSocket client
│   │   │   │   ├── DataBridge.java              # Data format bridge
│   │   │   │   └── InternalCommandExecutor.java # Bukkit API command executor
│   │   │   └── listener/                  # Bukkit event listeners (9)
│   │   │       ├── BlockEventListener.java     # Block events (break/place)
│   │   │       ├── ChatEventListener.java      # Chat/social events
│   │   │       ├── CombatEventListener.java    # Combat events (attack/death)
│   │   │       ├── CommandEventListener.java   # Command execution events
│   │   │       ├── EntityEventListener.java    # Entity spawn/despawn events
│   │   │       ├── InventoryEventListener.java # Inventory/container events
│   │   │       ├── PacketEventListener.java    # Raw packet events
│   │   │       ├── PlayerEventListener.java    # Player join/quit/move events
│   │   │       └── WorldEventListener.java     # World/chunk events
│   │   ├── controller/
│   │   │   └── TestController.java        # Test controller
│   │   └── websocket/                     # WebSocket server
│   └── main/resources/
│       └── application.yml                # Default configuration file
└── src/test/                              # Test code directory
```

---

## Development Guide

### Quick Start

```bash
# 1. Clone repository
git clone <repo-url>
cd AluerIII

# 2. Compile
./apache-maven-3.9.6/bin/mvn compile

# 3. Run tests
./apache-maven-3.9.6/bin/mvn test

# 4. Package
./apache-maven-3.9.6/bin/mvn package -DskipTests
```

### Requirements

| Dependency | Version | Notes |
|------------|---------|-------|
| Java JDK | 21+ | Compilation and runtime |
| Maven | 3.9.6 | Bundled with project |
| PaperMC | 1.21.1 | Minecraft server (Plugin mode only) |

### Development Conventions

See `CLAUDE.md` in the project root. Core principles:
- **YOLO Mode**: Execute directly, do not wait for confirmation
- **Chinese Comments**: Detailed Chinese comments on every method and critical logic, explain WHY not WHAT
- **Testing Discipline**: Full test suite before and after every code change
- **Frequent Commits**: Each meaningful change gets its own Git commit with Chinese commit messages
- **Zero Pseudocode**: Every line of code must be compilable, runnable, and verifiable

---

## Performance Characteristics

| Metric | Plugin Mode | External Mode |
|--------|------------|---------------|
| Communication Latency | < 1ms (same-machine WebSocket) | Depends on RCON response |
| Event Throughput | 50,000+ events/sec | 10,000+ events/sec |
| Online Player Capacity | 100+ (single agent) | 100+ |
| Memory Footprint | ~50MB (plugin portion) | ~200MB (full engine) |
| Module Hot-Switching | Supported | Supported |
| Automatic Recovery | Fully automatic (self-healing) | Fully automatic |
| DDoS Defense | Multi-layer coordinated | Multi-layer coordinated |
| AI Decision Latency | ~45s (DeepSeek analysis) | ~45s |
| Use Case | Production servers (recommended) | Monitoring/backup scenarios |

---

## License

Proprietary. All rights reserved.
