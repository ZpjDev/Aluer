package com.aluer.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import java.util.List;
import java.util.ArrayList;
import java.util.Map;

@Configuration
@ConfigurationProperties(prefix = "serverguard")
public class ServerGuardConfig {

    private MinecraftConfig minecraft = new MinecraftConfig();
    private MonitorConfig monitor = new MonitorConfig();
    private AlertConfig alert = new AlertConfig();
    private AiConfig ai = new AiConfig();
    private BackupConfig backup = new BackupConfig();
    private ScheduleConfig schedule = new ScheduleConfig();
    private ChatFilterConfig chatFilter = new ChatFilterConfig();
    private SecurityConfig security = new SecurityConfig();
    private DashboardConfig dashboard = new DashboardConfig();
    private AnnouncementConfig announcement = new AnnouncementConfig();
    private AfkConfig afk = new AfkConfig();

    public static class MinecraftConfig {
        private String serviceName = "minecraft";
        private String processName = "java";
        private String jarFile = "paper-1.21.11.jar";
        private String workingDir = "/opt/minecraft";
        private String javaOpts = "-Xms4G -Xmx4G";
        private int checkIntervalSeconds = 5;
        private RconConfig rcon = new RconConfig();

        public String getServiceName() { return serviceName; }
        public void setServiceName(String serviceName) { this.serviceName = serviceName; }
        public String getProcessName() { return processName; }
        public void setProcessName(String processName) { this.processName = processName; }
        public String getJarFile() { return jarFile; }
        public void setJarFile(String jarFile) { this.jarFile = jarFile; }
        public String getWorkingDir() { return workingDir; }
        public void setWorkingDir(String workingDir) { this.workingDir = workingDir; }
        public String getJavaOpts() { return javaOpts; }
        public void setJavaOpts(String javaOpts) { this.javaOpts = javaOpts; }
        public int getCheckIntervalSeconds() { return checkIntervalSeconds; }
        public void setCheckIntervalSeconds(int checkIntervalSeconds) { this.checkIntervalSeconds = checkIntervalSeconds; }
        public RconConfig getRcon() { return rcon; }
        public void setRcon(RconConfig rcon) { this.rcon = rcon; }
    }

    public static class RconConfig {
        private boolean enabled = true;
        private String host = "localhost";
        private int port = 25575;
        private String password = "";

        public boolean isEnabled() { return enabled; }
        public void setEnabled(boolean enabled) { this.enabled = enabled; }
        public String getHost() { return host; }
        public void setHost(String host) { this.host = host; }
        public int getPort() { return port; }
        public void setPort(int port) { this.port = port; }
        public String getPassword() { return password; }
        public void setPassword(String password) { this.password = password; }
    }

    public static class MonitorConfig {
        private int tpsThreshold = 15;
        private double cpuThreshold = 80.0;
        private double memoryThreshold = 85.0;
        private int connectionThreshold = 50;
        private int logWatchLines = 100;
        private String logPath = "/opt/minecraft/logs/latest.log";

        public int getTpsThreshold() { return tpsThreshold; }
        public void setTpsThreshold(int tpsThreshold) { this.tpsThreshold = tpsThreshold; }
        public double getCpuThreshold() { return cpuThreshold; }
        public void setCpuThreshold(double cpuThreshold) { this.cpuThreshold = cpuThreshold; }
        public double getMemoryThreshold() { return memoryThreshold; }
        public void setMemoryThreshold(double memoryThreshold) { this.memoryThreshold = memoryThreshold; }
        public int getConnectionThreshold() { return connectionThreshold; }
        public void setConnectionThreshold(int connectionThreshold) { this.connectionThreshold = connectionThreshold; }
        public int getLogWatchLines() { return logWatchLines; }
        public void setLogWatchLines(int logWatchLines) { this.logWatchLines = logWatchLines; }
        public String getLogPath() { return logPath; }
        public void setLogPath(String logPath) { this.logPath = logPath; }
    }

    public static class AlertConfig {
        private boolean enabled = true;
        private EmailConfig email = new EmailConfig();

        public boolean isEnabled() { return enabled; }
        public void setEnabled(boolean enabled) { this.enabled = enabled; }
        public EmailConfig getEmail() { return email; }
        public void setEmail(EmailConfig email) { this.email = email; }
    }

    public static class EmailConfig {
        private String smtpHost = "smtp.gmail.com";
        private int smtpPort = 587;
        private String username = "";
        private String password = "";
        private List<String> to;
        private RateLimitConfig rateLimit = new RateLimitConfig();

        public String getSmtpHost() { return smtpHost; }
        public void setSmtpHost(String smtpHost) { this.smtpHost = smtpHost; }
        public int getSmtpPort() { return smtpPort; }
        public void setSmtpPort(int smtpPort) { this.smtpPort = smtpPort; }
        public String getUsername() { return username; }
        public void setUsername(String username) { this.username = username; }
        public String getPassword() { return password; }
        public void setPassword(String password) { this.password = password; }
        public List<String> getTo() { return to; }
        public void setTo(List<String> to) { this.to = to; }
        public RateLimitConfig getRateLimit() { return rateLimit; }
        public void setRateLimit(RateLimitConfig rateLimit) { this.rateLimit = rateLimit; }
    }

    public static class RateLimitConfig {
        private int perTypeSeconds = 300;
        private int maxEmailsPerMinute = 10;

        public int getPerTypeSeconds() { return perTypeSeconds; }
        public void setPerTypeSeconds(int perTypeSeconds) { this.perTypeSeconds = perTypeSeconds; }
        public int getMaxEmailsPerMinute() { return maxEmailsPerMinute; }
        public void setMaxEmailsPerMinute(int maxEmailsPerMinute) { this.maxEmailsPerMinute = maxEmailsPerMinute; }
    }

    public static class AiConfig {
        private boolean enabled = true;
        private boolean useIsolationForest = true;
        private boolean usePrediction = true;
        private int slidingWindowSize = 100;
        private double anomalyThreshold = 0.7;
        private int predictionHorizonMinutes = 60;
        private DeepSeekConfig deepseek = new DeepSeekConfig();

        public boolean isEnabled() { return enabled; }
        public void setEnabled(boolean enabled) { this.enabled = enabled; }
        public boolean isUseIsolationForest() { return useIsolationForest; }
        public void setUseIsolationForest(boolean useIsolationForest) { this.useIsolationForest = useIsolationForest; }
        public boolean isUsePrediction() { return usePrediction; }
        public void setUsePrediction(boolean usePrediction) { this.usePrediction = usePrediction; }
        public int getSlidingWindowSize() { return slidingWindowSize; }
        public void setSlidingWindowSize(int slidingWindowSize) { this.slidingWindowSize = slidingWindowSize; }
        public double getAnomalyThreshold() { return anomalyThreshold; }
        public void setAnomalyThreshold(double anomalyThreshold) { this.anomalyThreshold = anomalyThreshold; }
        public int getPredictionHorizonMinutes() { return predictionHorizonMinutes; }
        public void setPredictionHorizonMinutes(int predictionHorizonMinutes) { this.predictionHorizonMinutes = predictionHorizonMinutes; }
        public DeepSeekConfig getDeepseek() { return deepseek; }
        public void setDeepseek(DeepSeekConfig deepseek) { this.deepseek = deepseek; }
    }

    public static class DeepSeekConfig {
        private boolean enabled = false;
        private String apiKey = "";
        private String baseUrl = "https://api.deepseek.com";
        private String model = "deepseek-chat";
        private int maxTokens = 1000;
        private double temperature = 0.7;
        private boolean autoAnalyzeAlerts = true;
        private int analysisIntervalSeconds = 60;
        private AutoExecuteConfig autoExecute = new AutoExecuteConfig();

        public boolean isEnabled() { return enabled; }
        public void setEnabled(boolean enabled) { this.enabled = enabled; }
        public String getApiKey() { return apiKey; }
        public void setApiKey(String apiKey) { this.apiKey = apiKey; }
        public String getBaseUrl() { return baseUrl; }
        public void setBaseUrl(String baseUrl) { this.baseUrl = baseUrl; }
        public String getModel() { return model; }
        public void setModel(String model) { this.model = model; }
        public int getMaxTokens() { return maxTokens; }
        public void setMaxTokens(int maxTokens) { this.maxTokens = maxTokens; }
        public double getTemperature() { return temperature; }
        public void setTemperature(double temperature) { this.temperature = temperature; }
        public boolean isAutoAnalyzeAlerts() { return autoAnalyzeAlerts; }
        public void setAutoAnalyzeAlerts(boolean autoAnalyzeAlerts) { this.autoAnalyzeAlerts = autoAnalyzeAlerts; }
        public int getAnalysisIntervalSeconds() { return analysisIntervalSeconds; }
        public void setAnalysisIntervalSeconds(int analysisIntervalSeconds) { this.analysisIntervalSeconds = analysisIntervalSeconds; }
        public AutoExecuteConfig getAutoExecute() { return autoExecute; }
        public void setAutoExecute(AutoExecuteConfig autoExecute) { this.autoExecute = autoExecute; }
    }

    public static class AutoExecuteConfig {
        private boolean enabled = false;
        private boolean banIp = true;
        private boolean killEntity = true;
        private boolean clearLag = true;
        private boolean setSpawnRate = true;
        private boolean kickPlayer = true;
        private boolean whitelist = false;
        private int minConfidence = 80;

        public boolean isEnabled() { return enabled; }
        public void setEnabled(boolean enabled) { this.enabled = enabled; }
        public boolean isBanIp() { return banIp; }
        public void setBanIp(boolean banIp) { this.banIp = banIp; }
        public boolean isKillEntity() { return killEntity; }
        public void setKillEntity(boolean killEntity) { this.killEntity = killEntity; }
        public boolean isClearLag() { return clearLag; }
        public void setClearLag(boolean clearLag) { this.clearLag = clearLag; }
        public boolean isSetSpawnRate() { return setSpawnRate; }
        public void setSetSpawnRate(boolean setSpawnRate) { this.setSpawnRate = setSpawnRate; }
        public boolean isKickPlayer() { return kickPlayer; }
        public void setKickPlayer(boolean kickPlayer) { this.kickPlayer = kickPlayer; }
        public boolean isWhitelist() { return whitelist; }
        public void setWhitelist(boolean whitelist) { this.whitelist = whitelist; }
        public int getMinConfidence() { return minConfidence; }
        public void setMinConfidence(int minConfidence) { this.minConfidence = minConfidence; }
    }

    public MinecraftConfig getMinecraft() { return minecraft; }
    public void setMinecraft(MinecraftConfig minecraft) { this.minecraft = minecraft; }
    public MonitorConfig getMonitor() { return monitor; }
    public void setMonitor(MonitorConfig monitor) { this.monitor = monitor; }
    public AlertConfig getAlert() { return alert; }
    public void setAlert(AlertConfig alert) { this.alert = alert; }
    public AiConfig getAi() { return ai; }
    public void setAi(AiConfig ai) { this.ai = ai; }
    public BackupConfig getBackup() { return backup; }
    public void setBackup(BackupConfig backup) { this.backup = backup; }
    public ScheduleConfig getSchedule() { return schedule; }
    public void setSchedule(ScheduleConfig schedule) { this.schedule = schedule; }
    public ChatFilterConfig getChatFilter() { return chatFilter; }
    public void setChatFilter(ChatFilterConfig chatFilter) { this.chatFilter = chatFilter; }
    public SecurityConfig getSecurity() { return security; }
    public void setSecurity(SecurityConfig security) { this.security = security; }
    public DashboardConfig getDashboard() { return dashboard; }
    public void setDashboard(DashboardConfig dashboard) { this.dashboard = dashboard; }
    public AnnouncementConfig getAnnouncement() { return announcement; }
    public void setAnnouncement(AnnouncementConfig announcement) { this.announcement = announcement; }
    public AfkConfig getAfk() { return afk; }
    public void setAfk(AfkConfig afk) { this.afk = afk; }

    public static class BackupConfig {
        private boolean enabled = false;
        private String backupDir = "/opt/minecraft/backups";
        private String worldDir = "/opt/minecraft/world";
        private String pluginDir = "/opt/minecraft/plugins";
        private String configDir = "/opt/minecraft";
        private int intervalHours = 24;
        private int maxBackups = 7;
        private boolean compress = true;
        private boolean backupPlugins = true;
        private boolean backupConfig = false;
        private boolean notifyOnComplete = true;

        public boolean isEnabled() { return enabled; }
        public void setEnabled(boolean enabled) { this.enabled = enabled; }
        public String getBackupDir() { return backupDir; }
        public void setBackupDir(String backupDir) { this.backupDir = backupDir; }
        public String getWorldDir() { return worldDir; }
        public void setWorldDir(String worldDir) { this.worldDir = worldDir; }
        public String getPluginDir() { return pluginDir; }
        public void setPluginDir(String pluginDir) { this.pluginDir = pluginDir; }
        public String getConfigDir() { return configDir; }
        public void setConfigDir(String configDir) { this.configDir = configDir; }
        public int getIntervalHours() { return intervalHours; }
        public void setIntervalHours(int intervalHours) { this.intervalHours = intervalHours; }
        public int getMaxBackups() { return maxBackups; }
        public void setMaxBackups(int maxBackups) { this.maxBackups = maxBackups; }
        public boolean isCompress() { return compress; }
        public void setCompress(boolean compress) { this.compress = compress; }
        public boolean isBackupPlugins() { return backupPlugins; }
        public void setBackupPlugins(boolean backupPlugins) { this.backupPlugins = backupPlugins; }
        public boolean isBackupConfig() { return backupConfig; }
        public void setBackupConfig(boolean backupConfig) { this.backupConfig = backupConfig; }
        public boolean isNotifyOnComplete() { return notifyOnComplete; }
        public void setNotifyOnComplete(boolean notifyOnComplete) { this.notifyOnComplete = notifyOnComplete; }
    }

    public static class ScheduleConfig {
        private boolean enabled = true;
        private boolean dailyRestart = true;
        private String restartTime = "04:00";
        private boolean saveBeforeRestart = true;
        private boolean announceRestart = true;
        private String announceMessage = "Server will restart in {minutes} minutes";
        private boolean weeklyBackup = true;
        private String backupDay = "sunday";
        private String backupTime = "03:00";
        private boolean clearLagDaily = true;
        private String clearLagTime = "02:00";

        public boolean isEnabled() { return enabled; }
        public void setEnabled(boolean enabled) { this.enabled = enabled; }
        public boolean isDailyRestart() { return dailyRestart; }
        public void setDailyRestart(boolean dailyRestart) { this.dailyRestart = dailyRestart; }
        public String getRestartTime() { return restartTime; }
        public void setRestartTime(String restartTime) { this.restartTime = restartTime; }
        public boolean isSaveBeforeRestart() { return saveBeforeRestart; }
        public void setSaveBeforeRestart(boolean saveBeforeRestart) { this.saveBeforeRestart = saveBeforeRestart; }
        public boolean isAnnounceRestart() { return announceRestart; }
        public void setAnnounceRestart(boolean announceRestart) { this.announceRestart = announceRestart; }
        public String getAnnounceMessage() { return announceMessage; }
        public void setAnnounceMessage(String announceMessage) { this.announceMessage = announceMessage; }
        public boolean isWeeklyBackup() { return weeklyBackup; }
        public void setWeeklyBackup(boolean weeklyBackup) { this.weeklyBackup = weeklyBackup; }
        public String getBackupDay() { return backupDay; }
        public void setBackupDay(String backupDay) { this.backupDay = backupDay; }
        public String getBackupTime() { return backupTime; }
        public void setBackupTime(String backupTime) { this.backupTime = backupTime; }
        public boolean isClearLagDaily() { return clearLagDaily; }
        public void setClearLagDaily(boolean clearLagDaily) { this.clearLagDaily = clearLagDaily; }
        public String getClearLagTime() { return clearLagTime; }
        public void setClearLagTime(String clearLagTime) { this.clearLagTime = clearLagTime; }
    }

    public static class ChatFilterConfig {
        private boolean enabled = false;
        private boolean blockIp = true;
        private boolean blockProfanity = true;
        private boolean blockAdvertising = true;
        private boolean blockSpam = true;
        private boolean blockIllegal = true;
        private int spamThreshold = 5;
        private int spamWindowSeconds = 10;
        private boolean muteOnViolation = true;
        private int muteDurationMinutes = 5;
        private boolean kickOnRepeat = true;
        private int maxViolationsBeforeKick = 3;
        private List<String> customWords = new java.util.ArrayList<>();

        public boolean isEnabled() { return enabled; }
        public void setEnabled(boolean enabled) { this.enabled = enabled; }
        public boolean isBlockIp() { return blockIp; }
        public void setBlockIp(boolean blockIp) { this.blockIp = blockIp; }
        public boolean isBlockProfanity() { return blockProfanity; }
        public void setBlockProfanity(boolean blockProfanity) { this.blockProfanity = blockProfanity; }
        public boolean isBlockAdvertising() { return blockAdvertising; }
        public void setBlockAdvertising(boolean blockAdvertising) { this.blockAdvertising = blockAdvertising; }
        public boolean isBlockSpam() { return blockSpam; }
        public void setBlockSpam(boolean blockSpam) { this.blockSpam = blockSpam; }
        public boolean isBlockIllegal() { return blockIllegal; }
        public void setBlockIllegal(boolean blockIllegal) { this.blockIllegal = blockIllegal; }
        public int getSpamThreshold() { return spamThreshold; }
        public void setSpamThreshold(int spamThreshold) { this.spamThreshold = spamThreshold; }
        public int getSpamWindowSeconds() { return spamWindowSeconds; }
        public void setSpamWindowSeconds(int spamWindowSeconds) { this.spamWindowSeconds = spamWindowSeconds; }
        public boolean isMuteOnViolation() { return muteOnViolation; }
        public void setMuteOnViolation(boolean muteOnViolation) { this.muteOnViolation = muteOnViolation; }
        public int getMuteDurationMinutes() { return muteDurationMinutes; }
        public void setMuteDurationMinutes(int muteDurationMinutes) { this.muteDurationMinutes = muteDurationMinutes; }
        public boolean isKickOnRepeat() { return kickOnRepeat; }
        public void setKickOnRepeat(boolean kickOnRepeat) { this.kickOnRepeat = kickOnRepeat; }
        public int getMaxViolationsBeforeKick() { return maxViolationsBeforeKick; }
        public void setMaxViolationsBeforeKick(int maxViolationsBeforeKick) { this.maxViolationsBeforeKick = maxViolationsBeforeKick; }
        public List<String> getCustomWords() { return customWords; }
        public void setCustomWords(List<String> customWords) { this.customWords = customWords; }
    }

    public static class SecurityConfig {
        private boolean enabled = false;
        private boolean autoBanVPN = true;
        private boolean checkOnLogin = true;
        private int maxConnectionsPerIP = 3;
        private boolean blockCommonExploits = true;
        private boolean logAllCommands = true;
        private MinecraftDefenseConfig minecraftDefense = new MinecraftDefenseConfig();
        private DDoSDefenseConfig ddosDefense = new DDoSDefenseConfig();
        private AntiIntrusionConfig antiIntrusion = new AntiIntrusionConfig();
        private HostEnforcementConfig hostEnforcement = new HostEnforcementConfig();
        private CloudEdgeConfig cloudEdge = new CloudEdgeConfig();
        private ThreatFeedsConfig threatFeeds = new ThreatFeedsConfig();
        private OrchestrationConfig orchestration = new OrchestrationConfig();
        private AutomationConfig automation = new AutomationConfig();
        private AutonomyConfig autonomy = new AutonomyConfig();
        private ShieldConfig shield = new ShieldConfig();
        private KernelConfig kernel = new KernelConfig();
        private TaskBusConfig taskBus = new TaskBusConfig();
        private SelfHealingConfig selfHealing = new SelfHealingConfig();
        private SuperEvolutionConfig superEvolution = new SuperEvolutionConfig();

        public boolean isEnabled() { return enabled; }
        public void setEnabled(boolean enabled) { this.enabled = enabled; }
        public boolean isAutoBanVPN() { return autoBanVPN; }
        public void setAutoBanVPN(boolean autoBanVPN) { this.autoBanVPN = autoBanVPN; }
        public boolean isCheckOnLogin() { return checkOnLogin; }
        public void setCheckOnLogin(boolean checkOnLogin) { this.checkOnLogin = checkOnLogin; }
        public int getMaxConnectionsPerIP() { return maxConnectionsPerIP; }
        public void setMaxConnectionsPerIP(int maxConnectionsPerIP) { this.maxConnectionsPerIP = maxConnectionsPerIP; }
        public boolean isBlockCommonExploits() { return blockCommonExploits; }
        public void setBlockCommonExploits(boolean blockCommonExploits) { this.blockCommonExploits = blockCommonExploits; }
        public boolean isLogAllCommands() { return logAllCommands; }
        public void setLogAllCommands(boolean logAllCommands) { this.logAllCommands = logAllCommands; }
        public MinecraftDefenseConfig getMinecraftDefense() { return minecraftDefense; }
        public void setMinecraftDefense(MinecraftDefenseConfig minecraftDefense) { this.minecraftDefense = minecraftDefense; }
        public DDoSDefenseConfig getDdosDefense() { return ddosDefense; }
        public void setDdosDefense(DDoSDefenseConfig ddosDefense) { this.ddosDefense = ddosDefense; }
        public AntiIntrusionConfig getAntiIntrusion() { return antiIntrusion; }
        public void setAntiIntrusion(AntiIntrusionConfig antiIntrusion) { this.antiIntrusion = antiIntrusion; }
        public HostEnforcementConfig getHostEnforcement() { return hostEnforcement; }
        public void setHostEnforcement(HostEnforcementConfig hostEnforcement) { this.hostEnforcement = hostEnforcement; }
        public CloudEdgeConfig getCloudEdge() { return cloudEdge; }
        public void setCloudEdge(CloudEdgeConfig cloudEdge) { this.cloudEdge = cloudEdge; }
        public ThreatFeedsConfig getThreatFeeds() { return threatFeeds; }
        public void setThreatFeeds(ThreatFeedsConfig threatFeeds) { this.threatFeeds = threatFeeds; }
        public OrchestrationConfig getOrchestration() { return orchestration; }
        public void setOrchestration(OrchestrationConfig orchestration) { this.orchestration = orchestration; }
        public AutomationConfig getAutomation() { return automation; }
        public void setAutomation(AutomationConfig automation) { this.automation = automation; }
        public AutonomyConfig getAutonomy() { return autonomy; }
        public void setAutonomy(AutonomyConfig autonomy) { this.autonomy = autonomy; }
        public ShieldConfig getShield() { return shield; }
        public void setShield(ShieldConfig shield) { this.shield = shield; }
        public KernelConfig getKernel() { return kernel; }
        public void setKernel(KernelConfig kernel) { this.kernel = kernel; }
        public TaskBusConfig getTaskBus() { return taskBus; }
        public void setTaskBus(TaskBusConfig taskBus) { this.taskBus = taskBus; }
        public SelfHealingConfig getSelfHealing() { return selfHealing; }
        public void setSelfHealing(SelfHealingConfig selfHealing) { this.selfHealing = selfHealing; }
        public SuperEvolutionConfig getSuperEvolution() { return superEvolution; }
        public void setSuperEvolution(SuperEvolutionConfig superEvolution) { this.superEvolution = superEvolution; }
    }

    public static class MinecraftDefenseConfig {
        private boolean enabled = true;
        private int gameTcpPort = 25565;
        private int queryUdpPort = 25565;
        private int rconTcpPort = 25575;
        private int statusPingThreshold = 25;
        private int loginBurstThreshold = 12;
        private int botSwarmThreshold = 15;
        private int queryFloodThreshold = 30;
        private int rconBruteForceThreshold = 5;
        private int compressionPayloadThreshold = 8192;

        public boolean isEnabled() { return enabled; }
        public void setEnabled(boolean enabled) { this.enabled = enabled; }
        public int getGameTcpPort() { return gameTcpPort; }
        public void setGameTcpPort(int gameTcpPort) { this.gameTcpPort = gameTcpPort; }
        public int getQueryUdpPort() { return queryUdpPort; }
        public void setQueryUdpPort(int queryUdpPort) { this.queryUdpPort = queryUdpPort; }
        public int getRconTcpPort() { return rconTcpPort; }
        public void setRconTcpPort(int rconTcpPort) { this.rconTcpPort = rconTcpPort; }
        public int getStatusPingThreshold() { return statusPingThreshold; }
        public void setStatusPingThreshold(int statusPingThreshold) { this.statusPingThreshold = statusPingThreshold; }
        public int getLoginBurstThreshold() { return loginBurstThreshold; }
        public void setLoginBurstThreshold(int loginBurstThreshold) { this.loginBurstThreshold = loginBurstThreshold; }
        public int getBotSwarmThreshold() { return botSwarmThreshold; }
        public void setBotSwarmThreshold(int botSwarmThreshold) { this.botSwarmThreshold = botSwarmThreshold; }
        public int getQueryFloodThreshold() { return queryFloodThreshold; }
        public void setQueryFloodThreshold(int queryFloodThreshold) { this.queryFloodThreshold = queryFloodThreshold; }
        public int getRconBruteForceThreshold() { return rconBruteForceThreshold; }
        public void setRconBruteForceThreshold(int rconBruteForceThreshold) { this.rconBruteForceThreshold = rconBruteForceThreshold; }
        public int getCompressionPayloadThreshold() { return compressionPayloadThreshold; }
        public void setCompressionPayloadThreshold(int compressionPayloadThreshold) { this.compressionPayloadThreshold = compressionPayloadThreshold; }
    }

    public static class DDoSDefenseConfig {
        private boolean enabled = true;
        private int synFloodThreshold = 100;
        private int udpFloodThreshold = 200;
        private int icmpFloodThreshold = 100;
        private int httpFloodThreshold = 150;
        private int slowConnectionThreshold = 150;
        private int amplificationThreshold = 20;
        private int minecraftStatusThreshold = 20;
        private int minecraftLoginThreshold = 10;
        private int minecraftRconThreshold = 5;
        private int minecraftQueryThreshold = 25;
        private int minecraftBotSwarmThreshold = 12;

        public boolean isEnabled() { return enabled; }
        public void setEnabled(boolean enabled) { this.enabled = enabled; }
        public int getSynFloodThreshold() { return synFloodThreshold; }
        public void setSynFloodThreshold(int synFloodThreshold) { this.synFloodThreshold = synFloodThreshold; }
        public int getUdpFloodThreshold() { return udpFloodThreshold; }
        public void setUdpFloodThreshold(int udpFloodThreshold) { this.udpFloodThreshold = udpFloodThreshold; }
        public int getIcmpFloodThreshold() { return icmpFloodThreshold; }
        public void setIcmpFloodThreshold(int icmpFloodThreshold) { this.icmpFloodThreshold = icmpFloodThreshold; }
        public int getHttpFloodThreshold() { return httpFloodThreshold; }
        public void setHttpFloodThreshold(int httpFloodThreshold) { this.httpFloodThreshold = httpFloodThreshold; }
        public int getSlowConnectionThreshold() { return slowConnectionThreshold; }
        public void setSlowConnectionThreshold(int slowConnectionThreshold) { this.slowConnectionThreshold = slowConnectionThreshold; }
        public int getAmplificationThreshold() { return amplificationThreshold; }
        public void setAmplificationThreshold(int amplificationThreshold) { this.amplificationThreshold = amplificationThreshold; }
        public int getMinecraftStatusThreshold() { return minecraftStatusThreshold; }
        public void setMinecraftStatusThreshold(int minecraftStatusThreshold) { this.minecraftStatusThreshold = minecraftStatusThreshold; }
        public int getMinecraftLoginThreshold() { return minecraftLoginThreshold; }
        public void setMinecraftLoginThreshold(int minecraftLoginThreshold) { this.minecraftLoginThreshold = minecraftLoginThreshold; }
        public int getMinecraftRconThreshold() { return minecraftRconThreshold; }
        public void setMinecraftRconThreshold(int minecraftRconThreshold) { this.minecraftRconThreshold = minecraftRconThreshold; }
        public int getMinecraftQueryThreshold() { return minecraftQueryThreshold; }
        public void setMinecraftQueryThreshold(int minecraftQueryThreshold) { this.minecraftQueryThreshold = minecraftQueryThreshold; }
        public int getMinecraftBotSwarmThreshold() { return minecraftBotSwarmThreshold; }
        public void setMinecraftBotSwarmThreshold(int minecraftBotSwarmThreshold) { this.minecraftBotSwarmThreshold = minecraftBotSwarmThreshold; }
    }

    public static class AntiIntrusionConfig {
        private boolean enabled = true;
        private boolean monitorCommands = true;
        private boolean monitorProcesses = true;
        private boolean monitorFiles = true;
        private boolean monitorPlugins = true;
        private boolean monitorSystemd = true;
        private boolean monitorRcon = true;
        private FileIntegrityConfig fileIntegrity = new FileIntegrityConfig();

        public boolean isEnabled() { return enabled; }
        public void setEnabled(boolean enabled) { this.enabled = enabled; }
        public boolean isMonitorCommands() { return monitorCommands; }
        public void setMonitorCommands(boolean monitorCommands) { this.monitorCommands = monitorCommands; }
        public boolean isMonitorProcesses() { return monitorProcesses; }
        public void setMonitorProcesses(boolean monitorProcesses) { this.monitorProcesses = monitorProcesses; }
        public boolean isMonitorFiles() { return monitorFiles; }
        public void setMonitorFiles(boolean monitorFiles) { this.monitorFiles = monitorFiles; }
        public boolean isMonitorPlugins() { return monitorPlugins; }
        public void setMonitorPlugins(boolean monitorPlugins) { this.monitorPlugins = monitorPlugins; }
        public boolean isMonitorSystemd() { return monitorSystemd; }
        public void setMonitorSystemd(boolean monitorSystemd) { this.monitorSystemd = monitorSystemd; }
        public boolean isMonitorRcon() { return monitorRcon; }
        public void setMonitorRcon(boolean monitorRcon) { this.monitorRcon = monitorRcon; }
        public FileIntegrityConfig getFileIntegrity() { return fileIntegrity; }
        public void setFileIntegrity(FileIntegrityConfig fileIntegrity) { this.fileIntegrity = fileIntegrity; }
    }

    public static class FileIntegrityConfig {
        private boolean enabled = true;
        private int maxDepth = 4;
        private List<String> monitoredPaths = new ArrayList<>(List.of(
            "/opt/minecraft/plugins",
            "/opt/minecraft/server.properties",
            "/opt/minecraft/paper-1.21.11.jar",
            "/opt/minecraft/start.sh",
            "/etc/systemd/system/minecraft.service"
        ));

        public boolean isEnabled() { return enabled; }
        public void setEnabled(boolean enabled) { this.enabled = enabled; }
        public int getMaxDepth() { return maxDepth; }
        public void setMaxDepth(int maxDepth) { this.maxDepth = maxDepth; }
        public List<String> getMonitoredPaths() { return monitoredPaths; }
        public void setMonitoredPaths(List<String> monitoredPaths) { this.monitoredPaths = monitoredPaths; }
    }

    public static class HostEnforcementConfig {
        private boolean enabled = false;
        private boolean dryRun = true;
        private String preferredBackend = "auto";
        private int defaultBlockMinutes = 60;
        private int defaultRateLimitPerMinute = 120;
        private boolean mirrorToCloudEdge = true;

        public boolean isEnabled() { return enabled; }
        public void setEnabled(boolean enabled) { this.enabled = enabled; }
        public boolean isDryRun() { return dryRun; }
        public void setDryRun(boolean dryRun) { this.dryRun = dryRun; }
        public String getPreferredBackend() { return preferredBackend; }
        public void setPreferredBackend(String preferredBackend) { this.preferredBackend = preferredBackend; }
        public int getDefaultBlockMinutes() { return defaultBlockMinutes; }
        public void setDefaultBlockMinutes(int defaultBlockMinutes) { this.defaultBlockMinutes = defaultBlockMinutes; }
        public int getDefaultRateLimitPerMinute() { return defaultRateLimitPerMinute; }
        public void setDefaultRateLimitPerMinute(int defaultRateLimitPerMinute) { this.defaultRateLimitPerMinute = defaultRateLimitPerMinute; }
        public boolean isMirrorToCloudEdge() { return mirrorToCloudEdge; }
        public void setMirrorToCloudEdge(boolean mirrorToCloudEdge) { this.mirrorToCloudEdge = mirrorToCloudEdge; }
    }

    public static class CloudEdgeConfig {
        private boolean enabled = false;
        private boolean dryRun = true;
        private String provider = "cloudflare";
        private String zoneId = "";
        private String apiKey = "";
        private String apiEmail = "";
        private String defaultBlockMode = "block";
        private String defaultChallengeMode = "challenge";
        private boolean enableUnderAttackOnCritical = false;

        public boolean isEnabled() { return enabled; }
        public void setEnabled(boolean enabled) { this.enabled = enabled; }
        public boolean isDryRun() { return dryRun; }
        public void setDryRun(boolean dryRun) { this.dryRun = dryRun; }
        public String getProvider() { return provider; }
        public void setProvider(String provider) { this.provider = provider; }
        public String getZoneId() { return zoneId; }
        public void setZoneId(String zoneId) { this.zoneId = zoneId; }
        public String getApiKey() { return apiKey; }
        public void setApiKey(String apiKey) { this.apiKey = apiKey; }
        public String getApiEmail() { return apiEmail; }
        public void setApiEmail(String apiEmail) { this.apiEmail = apiEmail; }
        public String getDefaultBlockMode() { return defaultBlockMode; }
        public void setDefaultBlockMode(String defaultBlockMode) { this.defaultBlockMode = defaultBlockMode; }
        public String getDefaultChallengeMode() { return defaultChallengeMode; }
        public void setDefaultChallengeMode(String defaultChallengeMode) { this.defaultChallengeMode = defaultChallengeMode; }
        public boolean isEnableUnderAttackOnCritical() { return enableUnderAttackOnCritical; }
        public void setEnableUnderAttackOnCritical(boolean enableUnderAttackOnCritical) { this.enableUnderAttackOnCritical = enableUnderAttackOnCritical; }
    }

    public static class ThreatFeedsConfig {
        private boolean enabled = true;
        private long cacheTtlMinutes = 30;
        private int refreshIntervalMinutes = 15;
        private int connectTimeoutMs = 2000;
        private int readTimeoutMs = 4000;
        private List<FeedSourceConfig> sources = new ArrayList<>();

        public boolean isEnabled() { return enabled; }
        public void setEnabled(boolean enabled) { this.enabled = enabled; }
        public long getCacheTtlMinutes() { return cacheTtlMinutes; }
        public void setCacheTtlMinutes(long cacheTtlMinutes) { this.cacheTtlMinutes = cacheTtlMinutes; }
        public int getRefreshIntervalMinutes() { return refreshIntervalMinutes; }
        public void setRefreshIntervalMinutes(int refreshIntervalMinutes) { this.refreshIntervalMinutes = refreshIntervalMinutes; }
        public int getConnectTimeoutMs() { return connectTimeoutMs; }
        public void setConnectTimeoutMs(int connectTimeoutMs) { this.connectTimeoutMs = connectTimeoutMs; }
        public int getReadTimeoutMs() { return readTimeoutMs; }
        public void setReadTimeoutMs(int readTimeoutMs) { this.readTimeoutMs = readTimeoutMs; }
        public List<FeedSourceConfig> getSources() { return sources; }
        public void setSources(List<FeedSourceConfig> sources) { this.sources = sources; }
    }

    public static class FeedSourceConfig {
        private String name = "";
        private String url = "";
        private boolean enabled = false;
        private int weight = 50;
        private String type = "IP";

        public String getName() { return name; }
        public void setName(String name) { this.name = name; }
        public String getUrl() { return url; }
        public void setUrl(String url) { this.url = url; }
        public boolean isEnabled() { return enabled; }
        public void setEnabled(boolean enabled) { this.enabled = enabled; }
        public int getWeight() { return weight; }
        public void setWeight(int weight) { this.weight = weight; }
        public String getType() { return type; }
        public void setType(String type) { this.type = type; }
    }

    public static class OrchestrationConfig {
        private boolean enabled = true;
        private boolean allowLocalBlock = true;
        private boolean allowEdgeChallenge = true;
        private boolean allowMinecraftDefense = true;
        private boolean notifyOnCritical = true;

        public boolean isEnabled() { return enabled; }
        public void setEnabled(boolean enabled) { this.enabled = enabled; }
        public boolean isAllowLocalBlock() { return allowLocalBlock; }
        public void setAllowLocalBlock(boolean allowLocalBlock) { this.allowLocalBlock = allowLocalBlock; }
        public boolean isAllowEdgeChallenge() { return allowEdgeChallenge; }
        public void setAllowEdgeChallenge(boolean allowEdgeChallenge) { this.allowEdgeChallenge = allowEdgeChallenge; }
        public boolean isAllowMinecraftDefense() { return allowMinecraftDefense; }
        public void setAllowMinecraftDefense(boolean allowMinecraftDefense) { this.allowMinecraftDefense = allowMinecraftDefense; }
        public boolean isNotifyOnCritical() { return notifyOnCritical; }
        public void setNotifyOnCritical(boolean notifyOnCritical) { this.notifyOnCritical = notifyOnCritical; }
    }

    public static class AutomationConfig {
        private boolean enabled = true;
        private int feedRefreshMinutes = 15;
        private int postureSnapshotMinutes = 5;
        private int integrityRescanMinutes = 30;
        private int ruleSyncMinutes = 10;
        private int incidentRetentionMinutes = 120;

        public boolean isEnabled() { return enabled; }
        public void setEnabled(boolean enabled) { this.enabled = enabled; }
        public int getFeedRefreshMinutes() { return feedRefreshMinutes; }
        public void setFeedRefreshMinutes(int feedRefreshMinutes) { this.feedRefreshMinutes = feedRefreshMinutes; }
        public int getPostureSnapshotMinutes() { return postureSnapshotMinutes; }
        public void setPostureSnapshotMinutes(int postureSnapshotMinutes) { this.postureSnapshotMinutes = postureSnapshotMinutes; }
        public int getIntegrityRescanMinutes() { return integrityRescanMinutes; }
        public void setIntegrityRescanMinutes(int integrityRescanMinutes) { this.integrityRescanMinutes = integrityRescanMinutes; }
        public int getRuleSyncMinutes() { return ruleSyncMinutes; }
        public void setRuleSyncMinutes(int ruleSyncMinutes) { this.ruleSyncMinutes = ruleSyncMinutes; }
        public int getIncidentRetentionMinutes() { return incidentRetentionMinutes; }
        public void setIncidentRetentionMinutes(int incidentRetentionMinutes) { this.incidentRetentionMinutes = incidentRetentionMinutes; }
    }

    public static class AutonomyConfig {
        private boolean enabled = true;
        private boolean deepseekDominant = true;
        private boolean quietConsole = true;
        private int loopIntervalSeconds = 45;
        private int minRiskScoreForAction = 70;
        private int criticalRiskScore = 90;
        private int workflowCooldownSeconds = 180;
        private int maxActionsPerHour = 12;
        private boolean requireSecondSignalForContainment = true;

        public boolean isEnabled() { return enabled; }
        public void setEnabled(boolean enabled) { this.enabled = enabled; }
        public boolean isDeepseekDominant() { return deepseekDominant; }
        public void setDeepseekDominant(boolean deepseekDominant) { this.deepseekDominant = deepseekDominant; }
        public boolean isQuietConsole() { return quietConsole; }
        public void setQuietConsole(boolean quietConsole) { this.quietConsole = quietConsole; }
        public int getLoopIntervalSeconds() { return loopIntervalSeconds; }
        public void setLoopIntervalSeconds(int loopIntervalSeconds) { this.loopIntervalSeconds = loopIntervalSeconds; }
        public int getMinRiskScoreForAction() { return minRiskScoreForAction; }
        public void setMinRiskScoreForAction(int minRiskScoreForAction) { this.minRiskScoreForAction = minRiskScoreForAction; }
        public int getCriticalRiskScore() { return criticalRiskScore; }
        public void setCriticalRiskScore(int criticalRiskScore) { this.criticalRiskScore = criticalRiskScore; }
        public int getWorkflowCooldownSeconds() { return workflowCooldownSeconds; }
        public void setWorkflowCooldownSeconds(int workflowCooldownSeconds) { this.workflowCooldownSeconds = workflowCooldownSeconds; }
        public int getMaxActionsPerHour() { return maxActionsPerHour; }
        public void setMaxActionsPerHour(int maxActionsPerHour) { this.maxActionsPerHour = maxActionsPerHour; }
        public boolean isRequireSecondSignalForContainment() { return requireSecondSignalForContainment; }
        public void setRequireSecondSignalForContainment(boolean requireSecondSignalForContainment) { this.requireSecondSignalForContainment = requireSecondSignalForContainment; }
    }

    public static class ShieldConfig {
        private boolean enabled = true;
        private boolean autoMode = true;
        private boolean autoEnableUnderAttack = true;
        private int heatTrigger = 78;
        private int resonanceTrigger = 72;
        private int threatScoreTrigger = 85;
        private int edgeChallengeOffenderLimit = 6;
        private int shelterRateLimitPerMinute = 45;
        private boolean attackerNoticeEnabled = true;
        private String deterrenceMessage = "Your source has been identified, recorded, and isolated by Aluer.";

        public boolean isEnabled() { return enabled; }
        public void setEnabled(boolean enabled) { this.enabled = enabled; }
        public boolean isAutoMode() { return autoMode; }
        public void setAutoMode(boolean autoMode) { this.autoMode = autoMode; }
        public boolean isAutoEnableUnderAttack() { return autoEnableUnderAttack; }
        public void setAutoEnableUnderAttack(boolean autoEnableUnderAttack) { this.autoEnableUnderAttack = autoEnableUnderAttack; }
        public int getHeatTrigger() { return heatTrigger; }
        public void setHeatTrigger(int heatTrigger) { this.heatTrigger = heatTrigger; }
        public int getResonanceTrigger() { return resonanceTrigger; }
        public void setResonanceTrigger(int resonanceTrigger) { this.resonanceTrigger = resonanceTrigger; }
        public int getThreatScoreTrigger() { return threatScoreTrigger; }
        public void setThreatScoreTrigger(int threatScoreTrigger) { this.threatScoreTrigger = threatScoreTrigger; }
        public int getEdgeChallengeOffenderLimit() { return edgeChallengeOffenderLimit; }
        public void setEdgeChallengeOffenderLimit(int edgeChallengeOffenderLimit) { this.edgeChallengeOffenderLimit = edgeChallengeOffenderLimit; }
        public int getShelterRateLimitPerMinute() { return shelterRateLimitPerMinute; }
        public void setShelterRateLimitPerMinute(int shelterRateLimitPerMinute) { this.shelterRateLimitPerMinute = shelterRateLimitPerMinute; }
        public boolean isAttackerNoticeEnabled() { return attackerNoticeEnabled; }
        public void setAttackerNoticeEnabled(boolean attackerNoticeEnabled) { this.attackerNoticeEnabled = attackerNoticeEnabled; }
        public String getDeterrenceMessage() { return deterrenceMessage; }
        public void setDeterrenceMessage(String deterrenceMessage) { this.deterrenceMessage = deterrenceMessage; }
    }

    public static class KernelConfig {
        private boolean enabled = true;
        private int pulseIntervalSeconds = 30;
        private int pulseHistorySize = 180;
        private int journalSize = 300;
        private int echoRetentionMinutes = 180;
        private boolean adaptiveWeights = true;
        private int directiveHeatThreshold = 60;
        private int lockdownHeatThreshold = 82;

        public boolean isEnabled() { return enabled; }
        public void setEnabled(boolean enabled) { this.enabled = enabled; }
        public int getPulseIntervalSeconds() { return pulseIntervalSeconds; }
        public void setPulseIntervalSeconds(int pulseIntervalSeconds) { this.pulseIntervalSeconds = pulseIntervalSeconds; }
        public int getPulseHistorySize() { return pulseHistorySize; }
        public void setPulseHistorySize(int pulseHistorySize) { this.pulseHistorySize = pulseHistorySize; }
        public int getJournalSize() { return journalSize; }
        public void setJournalSize(int journalSize) { this.journalSize = journalSize; }
        public int getEchoRetentionMinutes() { return echoRetentionMinutes; }
        public void setEchoRetentionMinutes(int echoRetentionMinutes) { this.echoRetentionMinutes = echoRetentionMinutes; }
        public boolean isAdaptiveWeights() { return adaptiveWeights; }
        public void setAdaptiveWeights(boolean adaptiveWeights) { this.adaptiveWeights = adaptiveWeights; }
        public int getDirectiveHeatThreshold() { return directiveHeatThreshold; }
        public void setDirectiveHeatThreshold(int directiveHeatThreshold) { this.directiveHeatThreshold = directiveHeatThreshold; }
        public int getLockdownHeatThreshold() { return lockdownHeatThreshold; }
        public void setLockdownHeatThreshold(int lockdownHeatThreshold) { this.lockdownHeatThreshold = lockdownHeatThreshold; }
    }

    public static class TaskBusConfig {
        private boolean enabled = true;
        private boolean autoDispatch = true;
        private int dispatchIntervalSeconds = 10;
        private int queueLimit = 200;
        private int historyLimit = 300;

        public boolean isEnabled() { return enabled; }
        public void setEnabled(boolean enabled) { this.enabled = enabled; }
        public boolean isAutoDispatch() { return autoDispatch; }
        public void setAutoDispatch(boolean autoDispatch) { this.autoDispatch = autoDispatch; }
        public int getDispatchIntervalSeconds() { return dispatchIntervalSeconds; }
        public void setDispatchIntervalSeconds(int dispatchIntervalSeconds) { this.dispatchIntervalSeconds = dispatchIntervalSeconds; }
        public int getQueueLimit() { return queueLimit; }
        public void setQueueLimit(int queueLimit) { this.queueLimit = queueLimit; }
        public int getHistoryLimit() { return historyLimit; }
        public void setHistoryLimit(int historyLimit) { this.historyLimit = historyLimit; }
    }

    public static class SelfHealingConfig {
        private boolean enabled = true;
        private boolean dryRun = true;
        private int loopIntervalSeconds = 45;
        private boolean autoBackupBeforeRecovery = true;
        private boolean autoWhitelistOnSwarm = true;
        private boolean allowSoftRestart = true;
        private int tpsEmergencyThreshold = 12;
        private double cpuEmergencyThreshold = 92.0;
        private double memoryEmergencyThreshold = 95.0;
        private int maxRecoveryActionsPerHour = 8;

        public boolean isEnabled() { return enabled; }
        public void setEnabled(boolean enabled) { this.enabled = enabled; }
        public boolean isDryRun() { return dryRun; }
        public void setDryRun(boolean dryRun) { this.dryRun = dryRun; }
        public int getLoopIntervalSeconds() { return loopIntervalSeconds; }
        public void setLoopIntervalSeconds(int loopIntervalSeconds) { this.loopIntervalSeconds = loopIntervalSeconds; }
        public boolean isAutoBackupBeforeRecovery() { return autoBackupBeforeRecovery; }
        public void setAutoBackupBeforeRecovery(boolean autoBackupBeforeRecovery) { this.autoBackupBeforeRecovery = autoBackupBeforeRecovery; }
        public boolean isAutoWhitelistOnSwarm() { return autoWhitelistOnSwarm; }
        public void setAutoWhitelistOnSwarm(boolean autoWhitelistOnSwarm) { this.autoWhitelistOnSwarm = autoWhitelistOnSwarm; }
        public boolean isAllowSoftRestart() { return allowSoftRestart; }
        public void setAllowSoftRestart(boolean allowSoftRestart) { this.allowSoftRestart = allowSoftRestart; }
        public int getTpsEmergencyThreshold() { return tpsEmergencyThreshold; }
        public void setTpsEmergencyThreshold(int tpsEmergencyThreshold) { this.tpsEmergencyThreshold = tpsEmergencyThreshold; }
        public double getCpuEmergencyThreshold() { return cpuEmergencyThreshold; }
        public void setCpuEmergencyThreshold(double cpuEmergencyThreshold) { this.cpuEmergencyThreshold = cpuEmergencyThreshold; }
        public double getMemoryEmergencyThreshold() { return memoryEmergencyThreshold; }
        public void setMemoryEmergencyThreshold(double memoryEmergencyThreshold) { this.memoryEmergencyThreshold = memoryEmergencyThreshold; }
        public int getMaxRecoveryActionsPerHour() { return maxRecoveryActionsPerHour; }
        public void setMaxRecoveryActionsPerHour(int maxRecoveryActionsPerHour) { this.maxRecoveryActionsPerHour = maxRecoveryActionsPerHour; }
    }

    public static class DashboardConfig {
        private boolean enabled = true;
        private String title = "Aluer Nebula Console";
        private String subtitle = "PaperMC defense, recovery, and remote operations fabric";
        private int refreshIntervalSeconds = 6;
        private boolean compactTerminal = true;
        private SshGatewayConfig sshGateway = new SshGatewayConfig();

        public boolean isEnabled() { return enabled; }
        public void setEnabled(boolean enabled) { this.enabled = enabled; }
        public String getTitle() { return title; }
        public void setTitle(String title) { this.title = title; }
        public String getSubtitle() { return subtitle; }
        public void setSubtitle(String subtitle) { this.subtitle = subtitle; }
        public int getRefreshIntervalSeconds() { return refreshIntervalSeconds; }
        public void setRefreshIntervalSeconds(int refreshIntervalSeconds) { this.refreshIntervalSeconds = refreshIntervalSeconds; }
        public boolean isCompactTerminal() { return compactTerminal; }
        public void setCompactTerminal(boolean compactTerminal) { this.compactTerminal = compactTerminal; }
        public SshGatewayConfig getSshGateway() { return sshGateway; }
        public void setSshGateway(SshGatewayConfig sshGateway) { this.sshGateway = sshGateway; }
    }

    public static class SshGatewayConfig {
        private boolean enabled = true;
        private int sessionTimeoutMinutes = 30;
        private int maxSessions = 6;
        private int commandTimeoutSeconds = 25;
        private boolean strictHostKeyChecking = false;
        private boolean allowPrivateKeyPaste = true;
        private boolean requireEngineHandshake = true;
        private int handshakeTtlSeconds = 30;

        public boolean isEnabled() { return enabled; }
        public void setEnabled(boolean enabled) { this.enabled = enabled; }
        public int getSessionTimeoutMinutes() { return sessionTimeoutMinutes; }
        public void setSessionTimeoutMinutes(int sessionTimeoutMinutes) { this.sessionTimeoutMinutes = sessionTimeoutMinutes; }
        public int getMaxSessions() { return maxSessions; }
        public void setMaxSessions(int maxSessions) { this.maxSessions = maxSessions; }
        public int getCommandTimeoutSeconds() { return commandTimeoutSeconds; }
        public void setCommandTimeoutSeconds(int commandTimeoutSeconds) { this.commandTimeoutSeconds = commandTimeoutSeconds; }
        public boolean isStrictHostKeyChecking() { return strictHostKeyChecking; }
        public void setStrictHostKeyChecking(boolean strictHostKeyChecking) { this.strictHostKeyChecking = strictHostKeyChecking; }
        public boolean isAllowPrivateKeyPaste() { return allowPrivateKeyPaste; }
        public void setAllowPrivateKeyPaste(boolean allowPrivateKeyPaste) { this.allowPrivateKeyPaste = allowPrivateKeyPaste; }
        public boolean isRequireEngineHandshake() { return requireEngineHandshake; }
        public void setRequireEngineHandshake(boolean requireEngineHandshake) { this.requireEngineHandshake = requireEngineHandshake; }
        public int getHandshakeTtlSeconds() { return handshakeTtlSeconds; }
        public void setHandshakeTtlSeconds(int handshakeTtlSeconds) { this.handshakeTtlSeconds = handshakeTtlSeconds; }
    }

    public static class SuperEvolutionConfig {
        private boolean jwtAuth = true;
        private boolean bruteForce = true;
        private boolean antiBot = true;
        private boolean reverseShell = true;
        private boolean arpSpoof = true;
        private boolean dnsTunnel = true;
        private boolean exploitSignature = true;
        private boolean ssrf = true;
        private boolean xxe = true;
        private boolean csp = true;
        private boolean databaseFirewall = true;
        private boolean dlp = true;
        private boolean memoryProtection = true;
        private boolean processInjection = true;
        private boolean secureDelete = true;
        private boolean forensics = true;
        private boolean incidentResponse = true;
        private boolean threatHunting = true;
        private boolean compliance = true;
        private boolean antiGrief = true;
        private boolean antiXray = true;
        private boolean antiFly = true;
        private boolean antiDupe = true;
        private boolean crashExploit = true;
        private boolean lagMachine = true;
        private boolean geoBlock = true;
        private boolean sessionValidation = true;
        private boolean pluginVerification = true;
        private boolean connectionThrottle = true;
        private boolean backupIntegrity = true;
        private boolean antiSkinSpoof = true;

        public boolean isJwtAuth() { return jwtAuth; }
        public void setJwtAuth(boolean jwtAuth) { this.jwtAuth = jwtAuth; }
        public boolean isBruteForce() { return bruteForce; }
        public void setBruteForce(boolean bruteForce) { this.bruteForce = bruteForce; }
        public boolean isAntiBot() { return antiBot; }
        public void setAntiBot(boolean antiBot) { this.antiBot = antiBot; }
        public boolean isReverseShell() { return reverseShell; }
        public void setReverseShell(boolean reverseShell) { this.reverseShell = reverseShell; }
        public boolean isArpSpoof() { return arpSpoof; }
        public void setArpSpoof(boolean arpSpoof) { this.arpSpoof = arpSpoof; }
        public boolean isDnsTunnel() { return dnsTunnel; }
        public void setDnsTunnel(boolean dnsTunnel) { this.dnsTunnel = dnsTunnel; }
        public boolean isExploitSignature() { return exploitSignature; }
        public void setExploitSignature(boolean exploitSignature) { this.exploitSignature = exploitSignature; }
        public boolean isSsrf() { return ssrf; }
        public void setSsrf(boolean ssrf) { this.ssrf = ssrf; }
        public boolean isXxe() { return xxe; }
        public void setXxe(boolean xxe) { this.xxe = xxe; }
        public boolean isCsp() { return csp; }
        public void setCsp(boolean csp) { this.csp = csp; }
        public boolean isDatabaseFirewall() { return databaseFirewall; }
        public void setDatabaseFirewall(boolean databaseFirewall) { this.databaseFirewall = databaseFirewall; }
        public boolean isDlp() { return dlp; }
        public void setDlp(boolean dlp) { this.dlp = dlp; }
        public boolean isMemoryProtection() { return memoryProtection; }
        public void setMemoryProtection(boolean memoryProtection) { this.memoryProtection = memoryProtection; }
        public boolean isProcessInjection() { return processInjection; }
        public void setProcessInjection(boolean processInjection) { this.processInjection = processInjection; }
        public boolean isSecureDelete() { return secureDelete; }
        public void setSecureDelete(boolean secureDelete) { this.secureDelete = secureDelete; }
        public boolean isForensics() { return forensics; }
        public void setForensics(boolean forensics) { this.forensics = forensics; }
        public boolean isIncidentResponse() { return incidentResponse; }
        public void setIncidentResponse(boolean incidentResponse) { this.incidentResponse = incidentResponse; }
        public boolean isThreatHunting() { return threatHunting; }
        public void setThreatHunting(boolean threatHunting) { this.threatHunting = threatHunting; }
        public boolean isCompliance() { return compliance; }
        public void setCompliance(boolean compliance) { this.compliance = compliance; }
        public boolean isAntiGrief() { return antiGrief; }
        public void setAntiGrief(boolean antiGrief) { this.antiGrief = antiGrief; }
        public boolean isAntiXray() { return antiXray; }
        public void setAntiXray(boolean antiXray) { this.antiXray = antiXray; }
        public boolean isAntiFly() { return antiFly; }
        public void setAntiFly(boolean antiFly) { this.antiFly = antiFly; }
        public boolean isAntiDupe() { return antiDupe; }
        public void setAntiDupe(boolean antiDupe) { this.antiDupe = antiDupe; }
        public boolean isCrashExploit() { return crashExploit; }
        public void setCrashExploit(boolean crashExploit) { this.crashExploit = crashExploit; }
        public boolean isLagMachine() { return lagMachine; }
        public void setLagMachine(boolean lagMachine) { this.lagMachine = lagMachine; }
        public boolean isGeoBlock() { return geoBlock; }
        public void setGeoBlock(boolean geoBlock) { this.geoBlock = geoBlock; }
        public boolean isSessionValidation() { return sessionValidation; }
        public void setSessionValidation(boolean sessionValidation) { this.sessionValidation = sessionValidation; }
        public boolean isPluginVerification() { return pluginVerification; }
        public void setPluginVerification(boolean pluginVerification) { this.pluginVerification = pluginVerification; }
        public boolean isConnectionThrottle() { return connectionThrottle; }
        public void setConnectionThrottle(boolean connectionThrottle) { this.connectionThrottle = connectionThrottle; }
        public boolean isBackupIntegrity() { return backupIntegrity; }
        public void setBackupIntegrity(boolean backupIntegrity) { this.backupIntegrity = backupIntegrity; }
        public boolean isAntiSkinSpoof() { return antiSkinSpoof; }
        public void setAntiSkinSpoof(boolean antiSkinSpoof) { this.antiSkinSpoof = antiSkinSpoof; }
    }

    public static class AnnouncementConfig {
        private boolean enabled = false;
        private int intervalSeconds = 300;
        private List<String> messages = new ArrayList<>();

        public boolean isEnabled() { return enabled; }
        public void setEnabled(boolean enabled) { this.enabled = enabled; }
        public int getIntervalSeconds() { return intervalSeconds; }
        public void setIntervalSeconds(int intervalSeconds) { this.intervalSeconds = intervalSeconds; }
        public List<String> getMessages() { return messages; }
        public void setMessages(List<String> messages) { this.messages = messages; }
    }

    public static class AfkConfig {
        private boolean enabled = false;
        private int afkTimeoutMinutes = 5;
        private int maxAfkMinutes = 30;
        private boolean teleportToAfkZone = false;
        private String afkZone = "0,100,0";
        private boolean autoLogout = false;

        public boolean isEnabled() { return enabled; }
        public void setEnabled(boolean enabled) { this.enabled = enabled; }
        public int getAfkTimeoutMinutes() { return afkTimeoutMinutes; }
        public void setAfkTimeoutMinutes(int afkTimeoutMinutes) { this.afkTimeoutMinutes = afkTimeoutMinutes; }
        public int getMaxAfkMinutes() { return maxAfkMinutes; }
        public void setMaxAfkMinutes(int maxAfkMinutes) { this.maxAfkMinutes = maxAfkMinutes; }
        public boolean isTeleportToAfkZone() { return teleportToAfkZone; }
        public void setTeleportToAfkZone(boolean teleportToAfkZone) { this.teleportToAfkZone = teleportToAfkZone; }
        public String getAfkZone() { return afkZone; }
        public void setAfkZone(String afkZone) { this.afkZone = afkZone; }
        public boolean isAutoLogout() { return autoLogout; }
        public void setAutoLogout(boolean autoLogout) { this.autoLogout = autoLogout; }
    }
}
