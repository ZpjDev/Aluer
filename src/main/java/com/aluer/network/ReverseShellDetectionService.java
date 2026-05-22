package com.aluer.network;

import com.aluer.config.ServerGuardConfig;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

@Service
public class ReverseShellDetectionService {

    private final ServerGuardConfig config;
    private final Map<String, List<ShellDetectionEvent>> detections = new ConcurrentHashMap<>();
    private final ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor();
    private final AtomicLong totalDetections = new AtomicLong(0);

    // Reverse shell command patterns
    private static final List<String> REVERSE_SHELL_PATTERNS = List.of(
            "bash -i >& /dev/tcp/",
            "bash -i &>/dev/tcp/",
            "/dev/tcp/",
            "nc -e /bin/",
            "nc -e /bin/bash",
            "nc -e /bin/sh",
            "nc -c /bin/",
            "ncat -e /bin/",
            "rm /tmp/f;mkfifo /tmp/f",
            "mknod /tmp/f p",
            "python -c 'import socket",
            "python -c 'import os,pty,socket",
            "python -c \"import socket",
            "python3 -c 'import socket",
            "perl -e 'use Socket",
            "ruby -rsocket -e",
            "php -r '$sock=fsockopen",
            "lua -e \"local s=require('socket')",
            "exec 5<>/dev/tcp/",
            "sh -i >& /dev/udp/",
            "sh -i >& /dev/tcp/",
            "zsh -c 'zmodload zsh/net/tcp",
            "socat exec:'bash -li'",
            "socat exec:'sh -i'",
            "socat tcp-connect:",
            "telnet ",
            "xterm -display ",
            "powershell -NoP -NonI -W Hidden -Exec Bypass",
            "powershell -nop -c \"$client = New-Object",
            "powershell IEX (New-Object Net.WebClient)",
            "Invoke-Expression (New-Object Net.WebClient)",
            "IEX(New-Object Net.WebClient)",
            "msfvenom",
            "meterpreter",
            "java -jar ysoserial",
            "wget http://.* -O /tmp/",
            "curl http://.* -o /tmp/",
            "wget http://.* | sh",
            "curl http://.* | bash"
    );

    // Process-level indicators
    private static final List<String> SHELL_PROCESS_INDICATORS = List.of(
            "nc ", "ncat ", "netcat", "socat", "bash -i", "sh -i",
            "/dev/tcp/", "/dev/udp/", "mkfifo", "mknod"
    );

    public ReverseShellDetectionService() {
        this(new ServerGuardConfig());
    }

    @Autowired
    public ReverseShellDetectionService(ServerGuardConfig config) {
        this.config = config;
        scheduler.scheduleAtFixedRate(this::cleanupOldDetections, 300, 600, TimeUnit.SECONDS);
    }

    public DetectionResult scanCommand(String command, String user, String source) {
        if (!config.getSecurity().getSuperEvolution().isReverseShell()) {
            return DetectionResult.clean();
        }

        if (command == null) return DetectionResult.clean();

        String lower = command.toLowerCase().trim();
        List<String> matched = new ArrayList<>();

        for (String pattern : REVERSE_SHELL_PATTERNS) {
            if (lower.contains(pattern.toLowerCase())) {
                matched.add(pattern);
            }
        }

        if (!matched.isEmpty()) {
            ShellDetectionEvent event = new ShellDetectionEvent(
                    Instant.now(), user, source, command, matched,
                    ShellSeverity.CRITICAL
            );
            detections.computeIfAbsent(source, k -> new ArrayList<>()).add(event);
            totalDetections.incrementAndGet();
            return DetectionResult.threat("Reverse shell command detected", matched, ShellSeverity.CRITICAL);
        }

        // Check for encoded/obfuscated commands
        if (isObfuscatedShellCommand(lower)) {
            ShellDetectionEvent event = new ShellDetectionEvent(
                    Instant.now(), user, source, command, List.of("OBFUSCATED"),
                    ShellSeverity.HIGH
            );
            detections.computeIfAbsent(source, k -> new ArrayList<>()).add(event);
            totalDetections.incrementAndGet();
            return DetectionResult.threat("Potentially obfuscated reverse shell command", List.of("OBFUSCATED"), ShellSeverity.HIGH);
        }

        return DetectionResult.clean();
    }

    public DetectionResult scanProcess(String processLine) {
        if (processLine == null) return DetectionResult.clean();

        String lower = processLine.toLowerCase();
        for (String indicator : SHELL_PROCESS_INDICATORS) {
            if (lower.contains(indicator.toLowerCase())) {
                return DetectionResult.threat("Suspicious process: " + indicator, List.of(indicator), ShellSeverity.MEDIUM);
            }
        }
        return DetectionResult.clean();
    }

    public Map<String, Object> getStatus() {
        Map<String, Object> status = new LinkedHashMap<>();
        status.put("totalDetections", totalDetections.get());
        status.put("trackedSources", detections.size());

        List<Map<String, Object>> recent = new ArrayList<>();
        for (Map.Entry<String, List<ShellDetectionEvent>> entry : detections.entrySet()) {
            for (ShellDetectionEvent event : entry.getValue()) {
                Map<String, Object> e = new LinkedHashMap<>();
                e.put("source", entry.getKey());
                e.put("user", event.user);
                e.put("time", event.timestamp.toString());
                e.put("patterns", event.matchedPatterns);
                e.put("severity", event.severity.name());
                e.put("command", event.command.length() > 100 ? event.command.substring(0, 100) + "..." : event.command);
                recent.add(e);
            }
        }
        recent.sort((a, b) -> b.get("time").toString().compareTo(a.get("time").toString()));
        status.put("recentDetections", recent.subList(0, Math.min(recent.size(), 20)));
        return status;
    }

    public long getTotalDetections() { return totalDetections.get(); }

    private boolean isObfuscatedShellCommand(String command) {
        int indicators = 0;
        if (command.contains("base64") && (command.contains("-d") || command.contains("--decode"))) indicators++;
        if (command.contains("eval") || command.contains("exec")) indicators++;
        if (command.contains("$(") || command.contains("`")) indicators++;
        if (command.contains("socket") || command.contains("connect")) indicators++;
        if (command.contains("subprocess") || command.contains("os.system")) indicators++;
        return indicators >= 3;
    }

    private void cleanupOldDetections() {
        Instant cutoff = Instant.now().minusSeconds(86400);
        detections.entrySet().removeIf(e -> {
            e.getValue().removeIf(d -> d.timestamp.isBefore(cutoff));
            return e.getValue().isEmpty();
        });
    }

    public enum ShellSeverity { LOW, MEDIUM, HIGH, CRITICAL }

    public static class ShellDetectionEvent {
        public final Instant timestamp;
        public final String user;
        public final String source;
        public final String command;
        public final List<String> matchedPatterns;
        public final ShellSeverity severity;

        ShellDetectionEvent(Instant timestamp, String user, String source, String command,
                            List<String> matchedPatterns, ShellSeverity severity) {
            this.timestamp = timestamp;
            this.user = user;
            this.source = source;
            this.command = command;
            this.matchedPatterns = matchedPatterns;
            this.severity = severity;
        }
    }

    public static class DetectionResult {
        private final boolean threat;
        private final String message;
        private final List<String> matchedPatterns;
        private final ShellSeverity severity;

        private DetectionResult(boolean threat, String message, List<String> matchedPatterns, ShellSeverity severity) {
            this.threat = threat;
            this.message = message;
            this.matchedPatterns = matchedPatterns;
            this.severity = severity;
        }

        public static DetectionResult clean() {
            return new DetectionResult(false, null, List.of(), ShellSeverity.LOW);
        }

        public static DetectionResult threat(String message, List<String> matchedPatterns, ShellSeverity severity) {
            return new DetectionResult(true, message, matchedPatterns, severity);
        }

        public boolean isThreat() { return threat; }
        public String getMessage() { return message; }
        public List<String> getMatchedPatterns() { return matchedPatterns; }
        public ShellSeverity getSeverity() { return severity; }
    }
}
