package com.aluer.model;

public enum AlertType {
    PROCESS_DEAD("Process Dead", "Minecraft process not found"),
    TPS_LOW("Low TPS", "TPS below threshold"),
    CPU_HIGH("High CPU", "CPU usage above threshold"),
    MEM_HIGH("High Memory", "Memory usage above threshold"),
    CONNECTION_FLOOD("Connection Flood", "Possible DDoS attack detected"),
    LOG_ATTACK("Attack Detected", "Malicious activity in logs"),
    BACKUP_FAILED("Backup Failed", "Backup task failed"),
    AI_ANOMALY("AI Anomaly", "AI detected abnormal behavior");

    private final String title;
    private final String description;

    AlertType(String title, String description) {
        this.title = title;
        this.description = description;
    }

    public String getTitle() { return title; }
    public String getDescription() { return description; }
}
