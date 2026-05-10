package com.aluer.alert;

import com.aluer.config.ServerGuardConfig;
import com.aluer.model.AlertEvent;
import com.aluer.model.AlertType;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.JavaMailSenderImpl;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Component;

import java.util.Queue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

@Component
public class EmailAlertService {
    private static final Logger logger = LoggerFactory.getLogger(EmailAlertService.class);
    
    private final ServerGuardConfig config;
    private final ConcurrentHashMap<AlertType, Long> lastAlertTime = new ConcurrentHashMap<>();
    private final Queue<Long> emailTimestamps = new ConcurrentLinkedQueue<>();
    private final ExecutorService executor;
    private JavaMailSender mailSender;
    private boolean initialized = false;

    public EmailAlertService(ServerGuardConfig config) {
        this.config = config;
        this.executor = Executors.newSingleThreadExecutor();
    }

    @PostConstruct
    public void init() {
        if (!config.getAlert().isEnabled()) {
            logger.info("邮件告警已禁用");
            return;
        }
        
        ServerGuardConfig.EmailConfig emailConfig = config.getAlert().getEmail();
        
        if (emailConfig.getUsername() == null || emailConfig.getUsername().isEmpty()) {
            logger.warn("邮件用户名未配置, 使用环境变量 EMAIL_PASSWORD");
            String password = System.getenv("EMAIL_PASSWORD");
            if (password != null) {
                emailConfig.setPassword(password);
            }
        }
        
        if (emailConfig.getTo() == null || emailConfig.getTo().isEmpty()) {
            logger.warn("未配置邮件收件人");
            return;
        }
        
        JavaMailSenderImpl mailSenderImpl = new JavaMailSenderImpl();
        mailSenderImpl.setHost(emailConfig.getSmtpHost());
        mailSenderImpl.setPort(emailConfig.getSmtpPort());
        mailSenderImpl.setUsername(emailConfig.getUsername());
        mailSenderImpl.setPassword(emailConfig.getPassword());
        mailSenderImpl.getJavaMailProperties().put("mail.smtp.auth", "true");
        mailSenderImpl.getJavaMailProperties().put("mail.smtp.starttls.enable", "true");
        
        this.mailSender = mailSenderImpl;
        this.initialized = true;
        
        logger.info("邮件告警服务已初始化, SMTP: {}:{}", 
            emailConfig.getSmtpHost(), emailConfig.getSmtpPort());
    }

    public void sendAlert(AlertEvent event) {
        if (!initialized || !config.getAlert().isEnabled()) {
            return;
        }
        
        if (!checkRateLimit(event.getType())) {
            logger.debug("Alert rate limited: {}", event.getType());
            return;
        }
        
        executor.submit(() -> sendEmailAsync(event));
    }

    private boolean checkRateLimit(AlertType type) {
        long now = System.currentTimeMillis();
        
        ServerGuardConfig.RateLimitConfig rateLimit = config.getAlert().getEmail().getRateLimit();
        Long lastTime = lastAlertTime.get(type);
        
        if (lastTime != null && (now - lastTime) < (rateLimit.getPerTypeSeconds() * 1000)) {
            return false;
        }
        
        emailTimestamps.add(now);
        
        long oneMinuteAgo = now - 60000;
        emailTimestamps.removeIf(t -> t < oneMinuteAgo);
        
        if (emailTimestamps.size() > rateLimit.getMaxEmailsPerMinute()) {
            return false;
        }
        
        lastAlertTime.put(type, now);
        return true;
    }

    @Async
    private void sendEmailAsync(AlertEvent event) {
        try {
            SimpleMailMessage message = new SimpleMailMessage();
            message.setFrom(config.getAlert().getEmail().getUsername());
            message.setTo(config.getAlert().getEmail().getTo().toArray(new String[0]));
            message.setSubject("[Aluer] " + event.getType().getTitle() + " - " + event.getType().getDescription());
            
            String body = buildEmailBody(event);
            message.setText(body);
            
            mailSender.send(message);
            logger.info("Alert email sent: {} - {}", event.getType(), event.getMessage());
            
        } catch (Exception e) {
            logger.error("Failed to send alert email: {}", e.getMessage());
        }
    }

    private String buildEmailBody(AlertEvent event) {
        StringBuilder body = new StringBuilder();
        body.append("Aluer ServerGuard Alert\n");
        body.append("========================\n\n");
        body.append("Event Type: ").append(event.getType().getTitle()).append("\n");
        body.append("Time: ").append(event.getTimestamp()).append("\n\n");
        body.append("Message:\n").append(event.getMessage()).append("\n\n");
        
        if (event.getConfidence() > 0) {
            body.append(String.format("Confidence: %.1f%%\n\n", event.getConfidence() * 100));
        }
        
        if (event.getRootCause() != null && !event.getRootCause().isEmpty()) {
            body.append("Root Cause: ").append(event.getRootCause()).append("\n\n");
        }
        
        if (event.getSuggestedAction() != null && !event.getSuggestedAction().isEmpty()) {
            body.append("Suggested Action:\n").append(event.getSuggestedAction()).append("\n");
        }
        
        return body.toString();
    }

    public void sendTestEmail() {
        AlertEvent testEvent = new AlertEvent(AlertType.AI_ANOMALY, "Test alert - Email system working correctly");
        testEvent.setConfidence(1.0);
        sendAlert(testEvent);
    }

    public void shutdown() {
        executor.shutdown();
    }
}
