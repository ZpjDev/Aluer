package com.aluer.model;

import java.time.LocalDateTime;

public class MetricsData {
    private LocalDateTime timestamp;
    private double tps;
    private double cpuUsage;
    private double memoryUsage;
    private int onlinePlayers;
    private int connections;
    private double tickTime;

    public MetricsData() {
        this.timestamp = LocalDateTime.now();
    }

    public LocalDateTime getTimestamp() { return timestamp; }
    public void setTimestamp(LocalDateTime timestamp) { this.timestamp = timestamp; }
    public double getTps() { return tps; }
    public void setTps(double tps) { this.tps = tps; }
    public double getCpuUsage() { return cpuUsage; }
    public void setCpuUsage(double cpuUsage) { this.cpuUsage = cpuUsage; }
    public double getMemoryUsage() { return memoryUsage; }
    public void setMemoryUsage(double memoryUsage) { this.memoryUsage = memoryUsage; }
    public int getOnlinePlayers() { return onlinePlayers; }
    public void setOnlinePlayers(int onlinePlayers) { this.onlinePlayers = onlinePlayers; }
    public int getConnections() { return connections; }
    public void setConnections(int connections) { this.connections = connections; }
    public double getTickTime() { return tickTime; }
    public void setTickTime(double tickTime) { this.tickTime = tickTime; }

    public double[] toArray() {
        return new double[]{tps, cpuUsage, memoryUsage, onlinePlayers, connections, tickTime};
    }
}
