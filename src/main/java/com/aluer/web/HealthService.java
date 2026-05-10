package com.aluer.web;

import com.aluer.ai.DeepSeekClient;
import com.aluer.config.ServerGuardConfig;
import com.aluer.service.RconClient;
import org.springframework.stereotype.Service;

import java.lang.management.ManagementFactory;
import java.lang.management.MemoryMXBean;
import java.lang.management.OperatingSystemMXBean;
import java.util.LinkedHashMap;
import java.util.Map;

@Service
public class HealthService {

    private final ServerGuardConfig config;
    private final DeepSeekClient deepSeekClient;
    private final RconClient rconClient;
    private final OperatingSystemMXBean osBean;
    private final MemoryMXBean memoryBean;

    public HealthService(ServerGuardConfig config,
                         DeepSeekClient deepSeekClient,
                         RconClient rconClient) {
        this.config = config;
        this.deepSeekClient = deepSeekClient;
        this.rconClient = rconClient;
        this.osBean = ManagementFactory.getOperatingSystemMXBean();
        this.memoryBean = ManagementFactory.getMemoryMXBean();
    }

    public Map<String, Object> getHealthReport() {
        Map<String, Object> report = new LinkedHashMap<>();
        report.put("status", computeOverallStatus());
        report.put("timestamp", System.currentTimeMillis());
        report.put("uptimeSeconds", ManagementFactory.getRuntimeMXBean().getUptime() / 1000);

        report.put("components", buildComponentStatus());
        report.put("system", buildSystemInfo());
        report.put("version", "1.0.0");

        return report;
    }

    public Map<String, Object> getLiveness() {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("status", "UP");
        result.put("timestamp", System.currentTimeMillis());
        return result;
    }

    public Map<String, Object> getReadiness() {
        Map<String, Object> result = new LinkedHashMap<>();
        boolean rconOk = rconClient.isConnected() || config.getMinecraft().getRcon().isEnabled();
        result.put("status", rconOk ? "READY" : "NOT_READY");
        result.put("rcon", rconOk ? "configured" : "unavailable");
        result.put("timestamp", System.currentTimeMillis());
        return result;
    }

    private String computeOverallStatus() {
        if (!rconClient.isConnected() && config.getMinecraft().getRcon().isEnabled()) {
            return "DEGRADED";
        }
        return "HEALTHY";
    }

    private Map<String, Object> buildComponentStatus() {
        Map<String, Object> components = new LinkedHashMap<>();

        Map<String, Object> rcon = new LinkedHashMap<>();
        rcon.put("status", rconClient.isConnected() ? "UP" : "DOWN");
        rcon.put("host", config.getMinecraft().getRcon().getHost() + ":" + config.getMinecraft().getRcon().getPort());
        components.put("rcon", rcon);

        Map<String, Object> ai = new LinkedHashMap<>();
        ai.put("status", deepSeekClient.isEnabled() ? "UP" : "DISABLED");
        ai.put("model", config.getAi().getDeepseek().getModel());
        components.put("deepseek-ai", ai);

        Map<String, Object> email = new LinkedHashMap<>();
        boolean emailConfigured = !config.getAlert().getEmail().getUsername().isEmpty();
        email.put("status", emailConfigured ? "UP" : "DISABLED");
        components.put("email-alert", email);

        Map<String, Object> security = new LinkedHashMap<>();
        security.put("status", config.getSecurity().isEnabled() ? "UP" : "DISABLED");
        security.put("kernelEnabled", config.getSecurity().getKernel().isEnabled());
        security.put("autonomyEnabled", config.getSecurity().getAutonomy().isEnabled());
        components.put("security", security);

        Map<String, Object> selfHealing = new LinkedHashMap<>();
        selfHealing.put("status", config.getSecurity().getSelfHealing().isEnabled() ? "UP" : "DISABLED");
        selfHealing.put("dryRun", config.getSecurity().getSelfHealing().isDryRun());
        components.put("self-healing", selfHealing);

        return components;
    }

    private Map<String, Object> buildSystemInfo() {
        Map<String, Object> system = new LinkedHashMap<>();
        system.put("javaVersion", System.getProperty("java.version"));
        system.put("availableProcessors", Runtime.getRuntime().availableProcessors());

        long totalMemory = Runtime.getRuntime().totalMemory();
        long freeMemory = Runtime.getRuntime().freeMemory();
        long maxMemory = Runtime.getRuntime().maxMemory();
        long usedMemory = totalMemory - freeMemory;

        Map<String, Object> memory = new LinkedHashMap<>();
        memory.put("usedMB", usedMemory / (1024 * 1024));
        memory.put("freeMB", freeMemory / (1024 * 1024));
        memory.put("totalMB", totalMemory / (1024 * 1024));
        memory.put("maxMB", maxMemory / (1024 * 1024));
        memory.put("usagePercent", Math.round((double) usedMemory / maxMemory * 1000) / 10.0);
        system.put("memory", memory);

        if (osBean instanceof com.sun.management.OperatingSystemMXBean sunOsBean) {
            system.put("systemCpuLoad", Math.round(sunOsBean.getCpuLoad() * 1000) / 10.0);
            system.put("processCpuLoad", Math.round(sunOsBean.getProcessCpuLoad() * 1000) / 10.0);
        }

        system.put("heapUsedMB", memoryBean.getHeapMemoryUsage().getUsed() / (1024 * 1024));
        system.put("heapMaxMB", memoryBean.getHeapMemoryUsage().getMax() / (1024 * 1024));

        return system;
    }
}
