package com.aluer.defense;

import com.aluer.config.ServerGuardConfig;
import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

@Component
public class SecurityAutomationScheduler {
    private final ServerGuardConfig config;
    private final ThreatIntelligenceService threatIntelligenceService;
    private final FileIntegrityMonitorService fileIntegrityMonitorService;
    private final HostEnforcementService hostEnforcementService;
    private final DDoSDefenseCoordinator ddosDefenseCoordinator;
    private final HostIntrusionCountermeasureService hostIntrusionCountermeasureService;
    private final ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(1);

    private volatile boolean running = false;

    public SecurityAutomationScheduler() {
        this(new ServerGuardConfig(), new ThreatIntelligenceService(), new FileIntegrityMonitorService(),
            new HostEnforcementService(), new DDoSDefenseCoordinator(), new HostIntrusionCountermeasureService());
    }

    @Autowired
    public SecurityAutomationScheduler(ServerGuardConfig config,
                                       ThreatIntelligenceService threatIntelligenceService,
                                       FileIntegrityMonitorService fileIntegrityMonitorService,
                                       HostEnforcementService hostEnforcementService,
                                       DDoSDefenseCoordinator ddosDefenseCoordinator,
                                       HostIntrusionCountermeasureService hostIntrusionCountermeasureService) {
        this.config = config;
        this.threatIntelligenceService = threatIntelligenceService;
        this.fileIntegrityMonitorService = fileIntegrityMonitorService;
        this.hostEnforcementService = hostEnforcementService;
        this.ddosDefenseCoordinator = ddosDefenseCoordinator;
        this.hostIntrusionCountermeasureService = hostIntrusionCountermeasureService;
    }

    @PostConstruct
    public void start() {
        if (running || !config.getSecurity().getAutomation().isEnabled()) {
            return;
        }

        running = true;
        int feedMinutes = Math.max(1, config.getSecurity().getAutomation().getFeedRefreshMinutes());
        int syncMinutes = Math.max(1, config.getSecurity().getAutomation().getRuleSyncMinutes());
        int integrityMinutes = Math.max(1, config.getSecurity().getAutomation().getIntegrityRescanMinutes());

        scheduler.scheduleAtFixedRate(threatIntelligenceService::refreshFeeds, 1, feedMinutes, TimeUnit.MINUTES);
        scheduler.scheduleAtFixedRate(hostEnforcementService::syncDesiredState, 1, syncMinutes, TimeUnit.MINUTES);
        scheduler.scheduleAtFixedRate(fileIntegrityMonitorService::scanNow, 1, integrityMinutes, TimeUnit.MINUTES);
        scheduler.scheduleAtFixedRate(hostIntrusionCountermeasureService::runFullScan, 2, integrityMinutes, TimeUnit.MINUTES);
    }

    public Map<String, Object> runMaintenanceCycle() {
        Map<String, Object> cycle = new LinkedHashMap<>();
        cycle.put("feeds", threatIntelligenceService.refreshFeeds());
        cycle.put("hostRules", hostEnforcementService.syncDesiredState());
        cycle.put("integrity", fileIntegrityMonitorService.scanNow());
        cycle.put("antiIntrusion", hostIntrusionCountermeasureService.runFullScan());
        cycle.put("ddos", ddosDefenseCoordinator.getPosture());
        return cycle;
    }

    public Map<String, Object> getStatus() {
        Map<String, Object> status = new LinkedHashMap<>();
        status.put("running", running);
        status.put("automationEnabled", config.getSecurity().getAutomation().isEnabled());
        status.put("feedRefreshMinutes", config.getSecurity().getAutomation().getFeedRefreshMinutes());
        status.put("integrityRescanMinutes", config.getSecurity().getAutomation().getIntegrityRescanMinutes());
        status.put("ruleSyncMinutes", config.getSecurity().getAutomation().getRuleSyncMinutes());
        return status;
    }

    @PreDestroy
    public void shutdown() {
        running = false;
        scheduler.shutdownNow();
    }
}
