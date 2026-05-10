package com.aluer.command;

import com.aluer.service.TestService;
import com.aluer.service.TestService.TestResult;
import org.springframework.shell.standard.ShellComponent;
import org.springframework.shell.standard.ShellMethod;
import org.springframework.shell.standard.ShellOption;

import java.util.Map;

@ShellComponent
public class TestCommands {

    private final TestService testService;

    public TestCommands(TestService testService) {
        this.testService = testService;
    }

    @ShellMethod(key = "test all", value = "Run all system tests")
    public String testAll() {
        Map<String, TestResult> results = testService.runAllTests();
        return formatResults(results);
    }

    @ShellMethod(key = "test quick", value = "Run quick tests (config, rcon, email)")
    public String testQuick() {
        Map<String, TestResult> results = testService.runQuickTests();
        return formatResults(results);
    }

    @ShellMethod(key = "test config", value = "Test configuration")
    public String testConfig() {
        TestResult result = testService.testConfiguration();
        return formatSingleResult(result);
    }

    @ShellMethod(key = "test rcon", value = "Test RCON connection")
    public String testRcon() {
        TestResult result = testService.testRconConnection();
        return formatSingleResult(result);
    }

    @ShellMethod(key = "test process", value = "Test process monitor")
    public String testProcess() {
        TestResult result = testService.testProcessMonitor();
        return formatSingleResult(result);
    }

    @ShellMethod(key = "test resource", value = "Test resource monitor")
    public String testResource() {
        TestResult result = testService.testResourceMonitor();
        return formatSingleResult(result);
    }

    @ShellMethod(key = "test connection", value = "Test connection monitor")
    public String testConnection() {
        TestResult result = testService.testConnectionMonitor();
        return formatSingleResult(result);
    }

    @ShellMethod(key = "test email", value = "Test email service")
    public String testEmail() {
        TestResult result = testService.testEmailService();
        return formatSingleResult(result);
    }

    @ShellMethod(key = "test email send", value = "Send test email")
    public String sendTestEmail() {
        TestResult result = testService.sendTestEmail();
        return formatSingleResult(result);
    }

    @ShellMethod(key = "test deepseek", value = "Test DeepSeek API")
    public String testDeepSeek() {
        TestResult result = testService.testDeepSeekApi();
        return formatSingleResult(result);
    }

    @ShellMethod(key = "test autoexecute", value = "Test auto execute config")
    public String testAutoExecute() {
        TestResult result = testService.testAutoExecute();
        return formatSingleResult(result);
    }

    @ShellMethod(key = "test simulate attack", value = "Simulate attack for testing")
    public String simulateAttack() {
        TestResult result = testService.simulateAttack();
        return formatSingleResult(result);
    }

    @ShellMethod(key = "test rcon exec", value = "Execute RCON command")
    public String execCommand(@ShellOption(help = "Command to execute") String command) {
        TestResult result = testService.testRconCommand(command);
        return formatSingleResult(result);
    }

    private String formatResults(Map<String, TestResult> results) {
        StringBuilder sb = new StringBuilder();
        sb.append("\n=== Test Results ===\n\n");
        
        int passed = 0, failed = 0, skipped = 0;
        
        for (var entry : results.entrySet()) {
            TestResult r = entry.getValue();
            String status = r.isPassed() ? "✓ PASS" : (r.isSkipped() ? "⊘ SKIP" : "✗ FAIL");
            sb.append(String.format("%s - %s\n", status, r.getName()));
            
            for (String detail : r.getDetails()) {
                sb.append("    ").append(detail).append("\n");
            }
            
            if (!r.isPassed() && !r.isSkipped() && r.getError() != null) {
                sb.append("    Error: ").append(r.getError()).append("\n");
            }
            
            if (r.isPassed()) passed++;
            else if (r.isSkipped()) skipped++;
            else failed++;
        }
        
        sb.append("\n--- Summary ---\n");
        sb.append(String.format("Passed: %d  Failed: %d  Skipped: %d\n", passed, failed, skipped));
        
        return sb.toString();
    }

    private String formatSingleResult(TestResult result) {
        StringBuilder sb = new StringBuilder();
        String status = result.isPassed() ? "✓ PASS" : (result.isSkipped() ? "⊘ SKIP" : "✗ FAIL");
        sb.append(String.format("\n%s - %s\n\n", status, result.getName()));
        
        for (String detail : result.getDetails()) {
            sb.append(detail).append("\n");
        }
        
        if (!result.isPassed() && !result.isSkipped() && result.getError() != null) {
            sb.append("\nError: ").append(result.getError()).append("\n");
        }
        
        return sb.toString();
    }
}
