package com.aluer.web;

import com.aluer.backup.BackupService;
import com.aluer.console.AluerMirageShieldService;
import com.aluer.console.AluerOperationsCenterService;
import com.aluer.console.RemoteSshGatewayService;
import com.aluer.kernel.AluerKernelEngine;
import com.aluer.kernel.AluerKernelTaskBus;
import com.aluer.kernel.AluerSelfHealingOrchestrator;
import com.aluer.network.NetworkThreatFusionService;
import com.aluer.service.RconClient;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/console")
public class OperationsConsoleController {
    private final AluerOperationsCenterService aluerOperationsCenterService;
    private final AluerMirageShieldService aluerMirageShieldService;
    private final RemoteSshGatewayService remoteSshGatewayService;
    private final AluerKernelEngine aluerKernelEngine;
    private final AluerKernelTaskBus aluerKernelTaskBus;
    private final AluerSelfHealingOrchestrator aluerSelfHealingOrchestrator;
    private final BackupService backupService;
    private final NetworkThreatFusionService networkThreatFusionService;
    private final RconClient rconClient;

    public OperationsConsoleController(AluerOperationsCenterService aluerOperationsCenterService,
                                       AluerMirageShieldService aluerMirageShieldService,
                                       RemoteSshGatewayService remoteSshGatewayService,
                                       AluerKernelEngine aluerKernelEngine,
                                       AluerKernelTaskBus aluerKernelTaskBus,
                                       AluerSelfHealingOrchestrator aluerSelfHealingOrchestrator,
                                       BackupService backupService,
                                       NetworkThreatFusionService networkThreatFusionService,
                                       RconClient rconClient) {
        this.aluerOperationsCenterService = aluerOperationsCenterService;
        this.aluerMirageShieldService = aluerMirageShieldService;
        this.remoteSshGatewayService = remoteSshGatewayService;
        this.aluerKernelEngine = aluerKernelEngine;
        this.aluerKernelTaskBus = aluerKernelTaskBus;
        this.aluerSelfHealingOrchestrator = aluerSelfHealingOrchestrator;
        this.backupService = backupService;
        this.networkThreatFusionService = networkThreatFusionService;
        this.rconClient = rconClient;
    }

    @GetMapping("/overview")
    public Map<String, Object> overview() {
        return aluerOperationsCenterService.buildOverview();
    }

    @GetMapping("/modules")
    public List<Map<String, Object>> modules() {
        return aluerOperationsCenterService.buildModuleCatalog();
    }

    @GetMapping("/audit")
    public Map<String, Object> audit(@RequestParam(defaultValue = "16") int limit) {
        return aluerOperationsCenterService.buildAuditFeed(Math.max(4, limit));
    }

    @GetMapping("/shield")
    public Map<String, Object> shield() {
        return aluerMirageShieldService.getShieldStatus();
    }

    @PostMapping("/shield/engage")
    public ResponseEntity<Map<String, Object>> engageShield(@RequestBody(required = false) ShieldRequest request) {
        try {
            ShieldRequest actual = request == null ? new ShieldRequest("", "") : request;
            return ResponseEntity.ok(aluerMirageShieldService.engage(actual.mode(), actual.reason()));
        } catch (IllegalArgumentException | IllegalStateException e) {
            return failure(HttpStatus.BAD_REQUEST, e.getMessage());
        }
    }

    @PostMapping("/kernel/pulse")
    public Map<String, Object> pulseKernel(@RequestBody(required = false) TriggerRequest request) {
        String trigger = request == null || request.trigger() == null || request.trigger().isBlank()
            ? "web-console"
            : request.trigger().trim();
        return aluerKernelEngine.runKernelPulse(trigger).toMap();
    }

    @PostMapping("/healing/run")
    public Map<String, Object> runHealing(@RequestBody(required = false) TriggerRequest request) {
        String trigger = request == null || request.trigger() == null || request.trigger().isBlank()
            ? "web-console"
            : request.trigger().trim();
        return aluerSelfHealingOrchestrator.runHealingCycle(trigger).toMap();
    }

    @PostMapping("/task-bus/dispatch")
    public Map<String, Object> dispatchTaskBus(@RequestBody(required = false) DispatchRequest request) {
        int limit = request == null || request.limit() == null ? 4 : Math.max(1, request.limit());
        return Map.of(
            "status", "ok",
            "count", limit,
            "results", aluerKernelTaskBus.dispatchQueuedTasks(limit).stream().map(AluerKernelTaskBus.KernelTaskResult::toMap).toList()
        );
    }

    @GetMapping("/ssh/sessions")
    public Map<String, Object> sshSessions() {
        return remoteSshGatewayService.getGatewayStatus();
    }

    @PostMapping("/ssh/handshake")
    public ResponseEntity<Map<String, Object>> sshHandshake(@RequestBody RemoteSshGatewayService.HandshakeRequest request) {
        try {
            return ResponseEntity.ok(Map.of(
                "status", "ok",
                "handshake", remoteSshGatewayService.requestHandshake(request)
            ));
        } catch (IllegalArgumentException | IllegalStateException e) {
            return failure(HttpStatus.BAD_REQUEST, e.getMessage());
        }
    }

    @PostMapping("/ssh/connect")
    public ResponseEntity<Map<String, Object>> sshConnect(@RequestBody RemoteSshGatewayService.ConnectRequest request) {
        try {
            return ResponseEntity.ok(Map.of(
                "status", "connected",
                "session", remoteSshGatewayService.connect(request)
            ));
        } catch (IllegalArgumentException | IllegalStateException e) {
            return failure(HttpStatus.BAD_REQUEST, e.getMessage());
        }
    }

    @PostMapping("/ssh/execute")
    public ResponseEntity<Map<String, Object>> sshExecute(@RequestBody ExecuteRequest request) {
        try {
            return ResponseEntity.ok(Map.of(
                "status", "ok",
                "result", remoteSshGatewayService.execute(request.sessionId(), request.command())
            ));
        } catch (IllegalArgumentException e) {
            return failure(HttpStatus.BAD_REQUEST, e.getMessage());
        } catch (IllegalStateException e) {
            return failure(HttpStatus.INTERNAL_SERVER_ERROR, e.getMessage());
        }
    }

    @DeleteMapping("/ssh/{sessionId}")
    public ResponseEntity<Map<String, Object>> sshDisconnect(@PathVariable String sessionId) {
        try {
            return ResponseEntity.ok(Map.of(
                "status", "disconnected",
                "session", remoteSshGatewayService.disconnect(sessionId)
            ));
        } catch (IllegalArgumentException e) {
            return failure(HttpStatus.BAD_REQUEST, e.getMessage());
        }
    }

    @PostMapping("/quick-action")
    public ResponseEntity<Map<String, Object>> quickAction(@RequestBody QuickActionRequest request) {
        try {
            String action = request.action() == null ? "" : request.action().trim().toLowerCase();
            return switch (action) {
                case "backup-now" -> ResponseEntity.ok(Map.of(
                    "status", "ok",
                    "backup", backupService.performScheduledBackup()
                ));
                case "shield-fortify" -> ResponseEntity.ok(aluerMirageShieldService.engage("FORTIFY", request.reason()));
                case "shield-mirage" -> ResponseEntity.ok(aluerMirageShieldService.engage("MIRAGE", request.reason()));
                case "shield-shelter" -> ResponseEntity.ok(aluerMirageShieldService.engage("SHELTER", request.reason()));
                case "whitelist-on" -> ResponseEntity.ok(Map.of(
                    "status", rconClient.enableWhitelist() ? "ok" : "failed",
                    "action", "whitelist-on"
                ));
                case "quarantine-ip" -> ResponseEntity.ok(networkThreatFusionService.quarantineIP(
                    request.ip(),
                    "web-console",
                    request.reason() == null || request.reason().isBlank() ? "Quick action quarantine" : request.reason()
                ));
                default -> failure(HttpStatus.BAD_REQUEST, "未知 quick action: " + action);
            };
        } catch (IllegalArgumentException | IllegalStateException e) {
            return failure(HttpStatus.BAD_REQUEST, e.getMessage());
        }
    }

    private ResponseEntity<Map<String, Object>> failure(HttpStatus status, String message) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("status", "error");
        body.put("message", message);
        body.put("timestamp", Instant.now().toEpochMilli());
        return ResponseEntity.status(status).body(body);
    }

    public record ShieldRequest(String mode, String reason) {
    }

    public record TriggerRequest(String trigger) {
    }

    public record DispatchRequest(Integer limit) {
    }

    public record ExecuteRequest(String sessionId, String command) {
    }

    public record QuickActionRequest(String action, String reason, String ip) {
    }
}
