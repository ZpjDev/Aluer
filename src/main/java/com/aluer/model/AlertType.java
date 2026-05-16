package com.aluer.model;

public enum AlertType {
    // ─── 系统监控 ──────────────────────────────
    PROCESS_DEAD("Process Dead", "Minecraft process not found"),
    TPS_LOW("Low TPS", "TPS below threshold"),
    CPU_HIGH("High CPU", "CPU usage above threshold"),
    MEM_HIGH("High Memory", "Memory usage above threshold"),
    CONNECTION_FLOOD("Connection Flood", "Possible DDoS attack detected"),
    LOG_ATTACK("Attack Detected", "Malicious activity in logs"),
    BACKUP_FAILED("Backup Failed", "Backup task failed"),
    AI_ANOMALY("AI Anomaly", "AI detected abnormal behavior"),

    // ─── V4.0 反作弊 ──────────────────────────
    SECURITY_KILL_AURA("KillAura", "Multi-target attack or aimbot consistency detected"),
    SECURITY_REACH("Reach", "Attack distance exceeds normal maximum"),
    SECURITY_SPEED("Speed", "Horizontal movement speed anomaly"),
    SECURITY_JESUS("Jesus", "Abnormal water walking detected"),
    SECURITY_NOFALL("NoFall", "Fall damage bypass detected"),
    SECURITY_SCAFFOLD("Scaffold", "Rapid foot-block placement detected"),
    SECURITY_NUKER("Nuker", "Rapid block breaking detected"),
    SECURITY_AUTO_CLICKER("AutoClicker", "Abnormal attack frequency detected"),
    SECURITY_AUTO_FISH("AutoFish", "Automated fishing detected"),
    SECURITY_FLY("Fly", "Illegal flight detected"),
    SECURITY_TIMER("Timer", "Game speed manipulation detected"),
    SECURITY_VELOCITY("Velocity", "Knockback manipulation detected"),
    SECURITY_PHASE("Phase", "Wall clipping/block phase detected"),
    SECURITY_BLINK("Blink", "Damage evasion disconnection detected"),
    SECURITY_FAST_BREAK("FastBreak", "Accelerated block breaking detected"),
    SECURITY_ELYTRA_FLY("ElytraFly", "Elytra speed manipulation detected"),

    // ─── V4.0 玩家行为 ────────────────────────
    SECURITY_CHEST_STEAL("ChestSteal", "Rapid container theft detected"),
    SECURITY_INVENTORY_MANIPULATION("InventoryManipulation", "Abnormal inventory interaction"),
    SECURITY_GRIEF("Grief", "Valuable block destruction pattern"),
    SECURITY_ALT_ACCOUNT("AltAccount", "Multiple accounts from same IP"),
    SECURITY_BARITONE("Baritone", "Automated mining bot detected"),
    SECURITY_XRAY("Xray", "Suspicious ore mining pattern"),

    // ─── V4.0 服务器保护 ──────────────────────
    SECURITY_SIGN_EXPLOIT("SignExploit", "Abnormal sign NBT data detected"),
    SECURITY_BOOK_BAN("BookBan", "Malicious book content detected"),
    SECURITY_RESOURCE_PACK_EXPLOIT("ResourcePackExploit", "Malicious resource pack attempt"),
    SECURITY_TAB_COMPLETE_CRASH("TabCompleteCrash", "Crash-inducing tab complete detected"),
    SECURITY_OFFLINE_MODE_SPOOF("OfflineModeSpoof", "Offline mode UUID spoof detected"),

    // ─── V4.0 聊天与社交安全 ──────────────────
    CHAT_FLOOD("ChatFlood", "Chat message spam detected"),
    CHAT_ADVERTISEMENT("Advertisement", "IP/Domain advertisement detected"),
    CHAT_PHISHING("Phishing", "Phishing link detected"),
    COMMAND_ABUSE("CommandAbuse", "Sensitive command abuse detected"),

    // ─── 网络安全 ─────────────────────────────
    SECURITY_DDOS("DDoS", "Distributed denial of service attack"),
    SECURITY_PORT_SCAN("PortScan", "Port scanning activity detected"),
    SECURITY_BRUTE_FORCE("BruteForce", "Brute force login attempt"),
    SECURITY_VPN_PROXY("VPN/Proxy", "Connection via VPN or proxy detected"),
    SECURITY_DNS_TUNNEL("DNSTunnel", "DNS tunneling detected"),
    SECURITY_PROTOCOL_VIOLATION("ProtocolViolation", "Minecraft protocol state violation detected"),
    SECURITY_BOT_FINGERPRINT("BotFingerprint", "Bot account behavioral fingerprint matched"),
    SECURITY_NBT_EXPLOIT("NBTExploit", "NBT data structure exploit detected"),
    SECURITY_HANDSHAKE_ANOMALY("HandshakeAnomaly", "Connection handshake anomaly detected"),

    // ─── 主机安全 ─────────────────────────────
    SECURITY_REVERSE_SHELL("ReverseShell", "Reverse shell connection detected"),
    SECURITY_PROCESS_INJECTION("ProcessInjection", "Process injection detected"),
    SECURITY_FILE_TAMPER("FileTamper", "File integrity violation detected"),
    SECURITY_BACKDOOR_PLUGIN("BackdoorPlugin", "Suspicious plugin detected"),
    SECURITY_CONFIG_TAMPER("ConfigTamper", "Configuration tampering detected"),

    // ─── V5.1 反作弊战斗模块 ──────────────────
    SECURITY_CRITICALS("Criticals", "Auto critical hit manipulation detected"),
    SECURITY_AUTO_TOTEM("AutoTotem", "Inhuman totem re-equip speed detected"),
    SECURITY_SURROUND("Surround", "Auto surround block placement detected"),
    SECURITY_AUTO_TRAP("AutoTrap", "Auto trap cage placement detected"),
    SECURITY_AUTO_CRYSTAL("AutoCrystal", "End crystal combat automation detected"),
    SECURITY_AUTO_ARMOR("AutoArmor", "Automated armor equip detected"),
    SECURITY_CHEST_SWAP("ChestSwap", "Instant chestplate swap detected"),
    SECURITY_AUTO_LOG("AutoLog", "Damage evasion disconnect detected"),
    SECURITY_HITBOXES("Hitboxes", "Expanded hitbox exploit pattern detected"),
    SECURITY_BOW_AIMBOT("BowAimbot", "Bow aimbot perfect prediction detected"),

    // ─── V5.2 反作弊移动模块（Meteor Client 移动类对抗） ──
    SECURITY_NO_SLOW("NoSlow", "Item use slowdown bypass detected"),
    SECURITY_SPIDER("Spider", "Wall climbing without climbable block detected"),
    SECURITY_STEP("Step", "Auto step assist detected"),
    SECURITY_PACKET_FLY("PacketFly", "Packet manipulation flight detected"),
    SECURITY_AIR_JUMP("AirJump", "Mid-air jump exploit detected"),
    SECURITY_LONG_JUMP("LongJump", "Extreme distance jump detected"),
    SECURITY_ANTI_HUNGER("AntiHunger", "Hunger loss prevention exploit detected"),
    SECURITY_FAST_FALL("FastFall", "Accelerated falling detected"),
    SECURITY_VCLIP("VClip", "Vertical phase through blocks detected"),

    // ─── V5.3 反作弊世界/玩家/杂物模块（Meteor Client 对抗） ──
    SECURITY_SPEED_MINE("SpeedMine", "Accelerated block mining detected"),
    SECURITY_FAST_USE("FastUse", "Accelerated item use detected"),
    SECURITY_NO_INTERACT("NoInteract", "Interaction bypass detected"),
    SECURITY_AUTO_MINE("AutoMine", "Automated mining behavior detected"),
    SECURITY_VEIN_MINER("VeinMiner", "Automated vein mining detected"),
    SECURITY_AUTO_TOOL("AutoTool", "Instant tool switching detected"),
    SECURITY_FAKE_PLAYER("FakePlayer", "Fake player entity detected"),
    SECURITY_PISTON_AURA("PistonAura", "Piston trap automation detected"),
    SECURITY_ANCHOR("Anchor", "Hole anchor knockback prevention detected"),
    SECURITY_STASH_FINDER("StashFinder", "Automated stash scanning detected"),

    // ─── V5.0 服务器保护扩展 ──────────────────
    SECURITY_CHUNK_RATE("ChunkRate", "Excessive chunk loading rate detected"),
    SECURITY_ENTITY_LIMIT("EntityLimit", "Entity count limit exceeded"),
    SECURITY_REDSTONE_LAG("RedstoneLag", "Redstone update storm detected"),
    SECURITY_CRASH_EXPLOIT("CrashExploit", "Known crash exploit signature matched"),

    // ─── ML 行为分析 ──────────────────────────
    ML_BEHAVIOR_ANOMALY("BehaviorAnomaly", "Statistical behavioral anomaly detected"),
    ML_THREAT_ESCALATION("ThreatEscalation", "Player threat score escalation"),
    ML_MOVEMENT_PATTERN("MovementPattern", "Suspicious movement pattern detected"),
    ML_COMBAT_PATTERN("CombatPattern", "Abnormal combat pattern detected"),

    // ─── 通用 ─────────────────────────────────
    SECURITY_OTHER("Security", "Security alert");

    private final String title;
    private final String description;

    AlertType(String title, String description) {
        this.title = title;
        this.description = description;
    }

    public String getTitle() { return title; }
    public String getDescription() { return description; }
}
