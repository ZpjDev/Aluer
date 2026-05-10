package com.aluer.schedule;

import com.aluer.backup.BackupService;
import com.aluer.config.ServerGuardConfig;
import com.aluer.service.RconClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.time.LocalTime;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

@Component
public class ScheduledTaskService {
    private static final Logger logger = LoggerFactory.getLogger(ScheduledTaskService.class);
    
    private final ServerGuardConfig config;
    private final RconClient rconClient;
    private final BackupService backupService;
    private final ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(2);
    
    public ScheduledTaskService(ServerGuardConfig config, RconClient rconClient, BackupService backupService) {
        this.config = config;
        this.rconClient = rconClient;
        this.backupService = backupService;
    }
    
    public void start() {
        if (!config.getSchedule().isEnabled()) {
            logger.info("Scheduled tasks are disabled");
            return;
        }
        
        scheduler.scheduleAtFixedRate(this::checkScheduledTasks, 0, 1, TimeUnit.MINUTES);
        
        logger.info("Scheduled task service started");
    }
    
    private void checkScheduledTasks() {
        LocalTime now = LocalTime.now();
        String currentTime = now.format(DateTimeFormatter.ofPattern("HH:mm"));
        
        if (config.getSchedule().isDailyRestart()) {
            checkRestartTask(currentTime);
        }
        
        if (config.getSchedule().isWeeklyBackup()) {
            checkWeeklyBackup(currentTime);
        }
        
        if (config.getSchedule().isClearLagDaily()) {
            checkClearLag(currentTime);
        }
    }
    
    private void checkRestartTask(String currentTime) {
        String restartTime = config.getSchedule().getRestartTime();
        
        if (currentTime.equals(restartTime)) {
            logger.info("Scheduled restart time reached");
            
            if (config.getSchedule().isAnnounceRestart()) {
                announceRestart();
            }
            
            if (config.getSchedule().isSaveBeforeRestart()) {
                rconClient.executeCommand("save-all");
                logger.info("World saved before restart");
            }
            
            try {
                Thread.sleep(60000);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            
            logger.warn("Executing scheduled server restart");
            rconClient.restartServer();
        }
        
        if (currentTime.equals(formatTime(restartTime, -10))) {
            rconClient.executeCommand("say Server restart in 10 minutes!");
        } else if (currentTime.equals(formatTime(restartTime, -5))) {
            rconClient.executeCommand("say Server restart in 5 minutes!");
        } else if (currentTime.equals(formatTime(restartTime, -1))) {
            rconClient.executeCommand("say Server restart in 1 minute!");
        }
    }
    
    private void checkWeeklyBackup(String currentTime) {
        LocalDateTime now = LocalDateTime.now();
        String dayOfWeek = now.getDayOfWeek().name().toLowerCase();
        
        if (dayOfWeek.equals(config.getSchedule().getBackupDay())) {
            String backupTime = config.getSchedule().getBackupTime();
            
            if (currentTime.equals(backupTime)) {
                logger.info("Scheduled weekly backup starting");
                
                if (config.getSchedule().isAnnounceRestart()) {
                    rconClient.executeCommand("say Weekly backup starting...");
                }
                
                backupService.performBackup("weekly_" + now.format(DateTimeFormatter.ofPattern("yyyyMMdd")));
            }
        }
    }
    
    private void checkClearLag(String currentTime) {
        String clearLagTime = config.getSchedule().getClearLagTime();
        
        if (currentTime.equals(clearLagTime)) {
            logger.info("Scheduled clear lag running");
            
            rconClient.clearLag();
            rconClient.executeCommand("say Server lag cleared!");
        }
    }
    
    private void announceRestart() {
        String message = config.getSchedule().getAnnounceMessage();
        rconClient.executeCommand("say " + message.replace("{minutes}", "60"));
    }
    
    private String formatTime(String time, int minutes) {
        LocalTime t = LocalTime.parse(time, DateTimeFormatter.ofPattern("HH:mm"));
        t = t.plusMinutes(minutes);
        
        if (t.isBefore(LocalTime.MIN)) {
            t = t.plusHours(24);
        }
        
        return t.format(DateTimeFormatter.ofPattern("HH:mm"));
    }
    
    public void scheduleCustomTask(Runnable task, long delayMs) {
        scheduler.schedule(task, delayMs, TimeUnit.MILLISECONDS);
    }
    
    public void scheduleRepeatingTask(Runnable task, long intervalMs) {
        scheduler.scheduleAtFixedRate(task, 0, intervalMs, TimeUnit.MILLISECONDS);
    }
    
    public void shutdown() {
        scheduler.shutdown();
    }
}
