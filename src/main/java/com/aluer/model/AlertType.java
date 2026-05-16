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

    // ─── 主机安全 ─────────────────────────────
    SECURITY_REVERSE_SHELL("ReverseShell", "Reverse shell connection detected"),
    SECURITY_PROCESS_INJECTION("ProcessInjection", "Process injection detected"),
    SECURITY_FILE_TAMPER("FileTamper", "File integrity violation detected"),
    SECURITY_BACKDOOR_PLUGIN("BackdoorPlugin", "Suspicious plugin detected"),
    SECURITY_CONFIG_TAMPER("ConfigTamper", "Configuration tampering detected"),

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
