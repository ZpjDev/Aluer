package com.aluer.controller;

import com.aluer.service.TestService;
import com.aluer.service.TestService.TestResult;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/test")
public class TestController {

    private final TestService testService;

    public TestController(TestService testService) {
        this.testService = testService;
    }

    @GetMapping("/run")
    public Map<String, TestResult> runAllTests() {
        return testService.runAllTests();
    }

    @GetMapping("/quick")
    public Map<String, TestResult> runQuickTests() {
        return testService.runQuickTests();
    }

    @GetMapping("/config")
    public TestResult testConfig() {
        return testService.testConfiguration();
    }

    @GetMapping("/rcon")
    public TestResult testRcon() {
        return testService.testRconConnection();
    }

    @GetMapping("/process")
    public TestResult testProcess() {
        return testService.testProcessMonitor();
    }

    @GetMapping("/resource")
    public TestResult testResource() {
        return testService.testResourceMonitor();
    }

    @GetMapping("/connection")
    public TestResult testConnection() {
        return testService.testConnectionMonitor();
    }

    @GetMapping("/log")
    public TestResult testLog() {
        return testService.testLogMonitor();
    }

    @GetMapping("/email")
    public TestResult testEmail() {
        return testService.testEmailService();
    }

    @GetMapping("/email/send")
    public TestResult sendTestEmail() {
        return testService.sendTestEmail();
    }

    @GetMapping("/deepseek")
    public TestResult testDeepSeek() {
        return testService.testDeepSeekApi();
    }

    @GetMapping("/autoexecute")
    public TestResult testAutoExecute() {
        return testService.testAutoExecute();
    }

    @GetMapping("/simulate/attack")
    public TestResult simulateAttack() {
        return testService.simulateAttack();
    }

    @GetMapping("/rcon/exec")
    public TestResult execCommand(@RequestParam String command) {
        return testService.testRconCommand(command);
    }
}
