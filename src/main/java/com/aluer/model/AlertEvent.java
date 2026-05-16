package com.aluer.model;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;

public class AlertEvent {
    private AlertType type;
    private String message;
    private String rootCause;
    private LocalDateTime timestamp;
    private double confidence;
    private String suggestedAction;
    /** 告警来源（玩家名/IP/系统模块名） */
    private String source;

    public AlertEvent() {
        this.timestamp = LocalDateTime.now();
    }

    public AlertEvent(AlertType type, String message) {
        this();
        this.type = type;
        this.message = message;
    }

    public AlertType getType() { return type; }
    public void setType(AlertType type) { this.type = type; }
    public String getMessage() { return message; }
    public void setMessage(String message) { this.message = message; }
    public String getRootCause() { return rootCause; }
    public void setRootCause(String rootCause) { this.rootCause = rootCause; }
    public LocalDateTime getTimestamp() { return timestamp; }
    public void setTimestamp(LocalDateTime timestamp) { this.timestamp = timestamp; }
    public double getConfidence() { return confidence; }
    public void setConfidence(double confidence) { this.confidence = confidence; }
    public String getSuggestedAction() { return suggestedAction; }
    public void setSuggestedAction(String suggestedAction) { this.suggestedAction = suggestedAction; }
    public String getSource() { return source; }
    public void setSource(String source) { this.source = source; }

    /** 以 epoch millis 设置时间戳 */
    public void setTimestamp(long epochMillis) {
        this.timestamp = LocalDateTime.ofInstant(Instant.ofEpochMilli(epochMillis), ZoneId.systemDefault());
    }
}
