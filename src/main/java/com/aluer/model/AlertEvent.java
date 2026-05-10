package com.aluer.model;

import java.time.LocalDateTime;

public class AlertEvent {
    private AlertType type;
    private String message;
    private String rootCause;
    private LocalDateTime timestamp;
    private double confidence;
    private String suggestedAction;

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
}
