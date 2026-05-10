package com.aluer.monitor;

import com.aluer.config.ServerGuardConfig;
import com.aluer.model.AlertEvent;
import com.aluer.model.AlertType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

@Component
public class ProcessMonitor {
    private static final Logger logger = LoggerFactory.getLogger(ProcessMonitor.class);
    
    private final ServerGuardConfig config;
    private boolean processRunning = false;

    public ProcessMonitor(ServerGuardConfig config) {
        this.config = config;
    }

    public boolean isProcessRunning() {
        String processName = config.getMinecraft().getProcessName();
        try {
            ProcessBuilder pb = new ProcessBuilder("pgrep", "-f", processName);
            pb.redirectErrorStream(true);
            Process p = pb.start();
            BufferedReader reader = new BufferedReader(new InputStreamReader(p.getInputStream()));
            String line;
            List<String> pids = new ArrayList<>();
            while ((line = reader.readLine()) != null) {
                if (!line.trim().isEmpty()) {
                    pids.add(line.trim());
                }
            }
            p.waitFor(5, TimeUnit.SECONDS);
            processRunning = !pids.isEmpty();
        } catch (Exception e) {
            logger.warn("Failed to check process status: {}", e.getMessage());
            processRunning = false;
        }
        return processRunning;
    }

    public boolean restartProcess() {
        String serviceName = config.getMinecraft().getServiceName();
        try {
            logger.info("Attempting to restart Minecraft service: {}", serviceName);
            ProcessBuilder pb = new ProcessBuilder("sudo", "systemctl", "restart", serviceName);
            pb.redirectErrorStream(true);
            Process p = pb.start();
            p.waitFor(30, TimeUnit.SECONDS);
            
            if (p.exitValue() == 0) {
                logger.info("Minecraft service restarted successfully");
                processRunning = true;
                return true;
            } else {
                logger.error("Failed to restart Minecraft service, exit code: {}", p.exitValue());
            }
        } catch (Exception e) {
            logger.error("Failed to restart process: {}", e.getMessage());
        }
        return false;
    }

    public boolean stopProcess() {
        String serviceName = config.getMinecraft().getServiceName();
        try {
            ProcessBuilder pb = new ProcessBuilder("sudo", "systemctl", "stop", serviceName);
            pb.redirectErrorStream(true);
            Process p = pb.start();
            p.waitFor(30, TimeUnit.SECONDS);
            processRunning = false;
            return p.exitValue() == 0;
        } catch (Exception e) {
            logger.error("Failed to stop process: {}", e.getMessage());
            return false;
        }
    }

    public AlertEvent checkAndRestart() {
        if (!isProcessRunning()) {
            logger.warn("Minecraft process not found, attempting restart...");
            if (restartProcess()) {
                return new AlertEvent(AlertType.PROCESS_DEAD, "Process was dead, auto-restarted successfully");
            } else {
                return new AlertEvent(AlertType.PROCESS_DEAD, "Process was dead, restart FAILED");
            }
        }
        return null;
    }
}
