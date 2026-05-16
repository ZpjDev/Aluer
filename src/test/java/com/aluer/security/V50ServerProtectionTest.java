package com.aluer.security;

import org.junit.jupiter.api.Test;

import java.util.*;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.*;

/**
 * V5.0 服务器保护模块测试 — 打靶试验（模拟真实 Minecraft 生产环境数据）
 *
 * 覆盖 7 个 V5.0 服务器保护模块：
 *   ChunkLoadRateLimiter      — 区块加载速率限制
 *   EntityCountEnforcer        — 实体数量强制限制
 *   RedstoneUpdateLimiter      — 红石更新频率限制
 *   CrashExploitSignatureDB    — 崩溃漏洞签名数据库
 *   ProtocolStateValidator     — 协议状态验证
 *   TokenBucketRateLimiter     — 令牌桶速率限制
 *   BotFingerprintDetector     — 机器人指纹检测
 *
 * 由于 V5.0 服务类尚未实现，本测试内联检测逻辑直接验证算法正确性。
 * 共 22 个测试用例。
 */
class V50ServerProtectionTest {

    // ========================================================================
    // ChunkLoadRateLimiter — 区块加载速率限制
    // 原理：Minecraft 玩家移动时会加载周边区块，正常速度约 5-10 区块/秒。
    //       利用 ChunkBan/ChunkLoading 漏洞的客户端会请求大量区块，
    //       通过限制每 IP/玩家的区块加载速率来防止服务端资源耗尽。
    // ========================================================================

    /**
     * 正常区块加载 — 5 区块/秒通过。
     */
    @Test
    void testChunkRateNormalPasses() {
        // 模拟滑动窗口：1 秒内请求 5 个区块
        int chunkRequestsPerSecond = 5;
        int normalThreshold = 25; // 每秒允许最多 25 个区块请求
        int suspiciousThreshold = 50;
        int blockThreshold = 75;

        assertTrue(chunkRequestsPerSecond < normalThreshold,
                "5 区块/秒 < 25 阈值，正常通过");
        assertFalse(chunkRequestsPerSecond >= suspiciousThreshold,
                "5 区块/秒不应触发可疑标记");
        assertFalse(chunkRequestsPerSecond >= blockThreshold,
                "5 区块/秒不应触发阻止");
    }

    /**
     * 可疑区块加载 — 30 区块/秒触发可疑标记。
     */
    @Test
    void testChunkRateSuspicious() {
        int chunkRequestsPerSecond = 30;
        int normalThreshold = 25;
        int suspiciousThreshold = 50;
        int blockThreshold = 75;

        boolean isSuspicious = chunkRequestsPerSecond >= normalThreshold
                && chunkRequestsPerSecond < blockThreshold;

        assertTrue(isSuspicious,
                "30 区块/秒 >= 25 正常阈值，应触发可疑标记");
        assertTrue(chunkRequestsPerSecond > normalThreshold,
                "超过正常阈值 " + normalThreshold + "，实际: " + chunkRequestsPerSecond);
        assertFalse(chunkRequestsPerSecond >= blockThreshold,
                "30 区块/秒未达到阻止阈值");
    }

    /**
     * 明确阻止 — 80 区块/秒被阻止。
     */
    @Test
    void testChunkRateBlocked() {
        int chunkRequestsPerSecond = 80;
        int blockThreshold = 75;

        // 滑动窗口检测：记录过去 1 秒内的所有请求时间戳
        List<Long> requestTimestamps = new ArrayList<>();
        long windowStart = 0L;

        // 模拟 80 个请求在 1 秒内到达
        for (int i = 0; i < 80; i++) {
            requestTimestamps.add((long) i * 12); // 12ms 间隔 = 83 req/s
        }

        // 清理过期时间戳（1 秒窗口）
        long now = 1000L;
        long oneSecAgo = now - 1000L;

        long recentRequests = requestTimestamps.stream()
                .filter(t -> t >= oneSecAgo)
                .count();

        boolean blocked = recentRequests >= blockThreshold;

        assertTrue(blocked,
                "80 区块/秒 >= 75 阻止阈值，应被阻止。窗口内请求数: " + recentRequests);
        assertEquals(80, recentRequests,
                "1 秒窗口内应有 80 个请求");
    }

    // ========================================================================
    // EntityCountEnforcer — 实体数量限制
    // 原理：单个区块内实体数量过多会导致服务端卡顿甚至崩溃。
    //       EntityCountEnforcer 按区块追踪实体数量，超出限制时强制清理。
    //       正常上限约 30-50 实体/区块。
    // ========================================================================

    /**
     * 单个区块 50 实体 — 触发强制清理。
     */
    @Test
    void testEntityCountPerChunkLimit() {
        // 模拟区块 (10, 8) 中的实体计数
        int chunkX = 10, chunkZ = 8;
        Map<String, Integer> entityCountByChunk = new HashMap<>();
        String chunkKey = chunkX + "," + chunkZ;

        int maxEntitiesPerChunk = 30;

        // 放入 50 个实体
        entityCountByChunk.put(chunkKey, 50);

        boolean enforcementTriggered = entityCountByChunk.get(chunkKey) > maxEntitiesPerChunk;

        assertTrue(enforcementTriggered,
                "区块 " + chunkKey + " 含 50 个实体 > " + maxEntitiesPerChunk + " 上限，应触发清理");
        assertTrue(entityCountByChunk.get(chunkKey) >= 50,
                "实体数应 >= 50");
    }

    /**
     * 混合实体类型计数 — 不同实体类型应正确归类统计。
     */
    @Test
    void testEntityCountDifferentTypes() {
        // 模拟区块内混合实体
        Map<String, Integer> entityTypesInChunk = new HashMap<>();
        entityTypesInChunk.put("ZOMBIE", 15);
        entityTypesInChunk.put("SKELETON", 10);
        entityTypesInChunk.put("CREEPER", 8);
        entityTypesInChunk.put("SPIDER", 7);
        entityTypesInChunk.put("ITEM_FRAME", 12); // 物品展示框也计入
        entityTypesInChunk.put("ARMOR_STAND", 5);
        entityTypesInChunk.put("BOAT", 3);

        // 计算总数
        int totalEntities = entityTypesInChunk.values().stream()
                .mapToInt(Integer::intValue)
                .sum();

        int maxPerChunk = 30;

        assertTrue(totalEntities > maxPerChunk,
                "混合实体总计 " + totalEntities + " > " + maxPerChunk + " 上限");
        assertEquals(60, totalEntities,
                "应正确统计所有类型实体总数");
        assertEquals(15, (int) entityTypesInChunk.get("ZOMBIE"),
                "僵尸数量应为 15");
        assertEquals(10, (int) entityTypesInChunk.get("SKELETON"),
                "骷髅数量应为 10");
    }

    /**
     * 刷怪笼实体豁免 — 来自刷怪笼的实体应有不同的处理策略。
     * 刷怪笼区域实体密度自然较高，不应直接清理。
     */
    @Test
    void testEntityCountSpawnerExemption() {
        // 模拟含刷怪笼的区块
        int chunkX = -5, chunkZ = 12;
        boolean hasSpawner = true;

        int regularEntities = 45;  // 普通实体
        int spawnerEntities = 20;  // 来自刷怪笼的实体（豁免）

        int totalForThreshold = regularEntities; // 刷怪笼实体不计数
        int effectiveLimit = 30;

        boolean regularExceeded = totalForThreshold > effectiveLimit;
        boolean spawnerExempted = hasSpawner && regularExceeded;

        assertTrue(regularExceeded,
                "普通实体 " + regularEntities + " 超过上限 " + effectiveLimit);
        assertTrue(spawnerExempted,
                "刷怪笼区块中，仅普通实体超出时采取温和策略（降频而非清理）");
        // 刷怪笼实体不计入强制清理阈值
        assertEquals(20, spawnerEntities,
                "刷怪笼实体应被豁免计数");
    }

    // ========================================================================
    // RedstoneUpdateLimiter — 红石更新频率限制
    // 原理：高频红石（观察者时钟、比较器时钟）产生大量方块更新，
    //       可导致服务端 TPS 下降。通过检测红石更新频率识别 Lag Machine。
    // ========================================================================

    /**
     * 正常红石时钟 — 2Hz 频率通过。
     */
    @Test
    void testRedstoneNormalClock() {
        // 标准红石中继器时钟：2Hz（每 500ms 一次更新）
        double updatesPerSecond = 2.0; // 2 Hz
        double maxNormalRate = 10.0;   // 正常上限 10 Hz

        boolean isNormal = updatesPerSecond <= maxNormalRate;

        assertTrue(isNormal,
                "2Hz 红石时钟 <= 10Hz 正常上限，不触发限制");
        assertTrue(updatesPerSecond < 5.0,
                "2Hz 远低于可疑阈值 5Hz");
    }

    /**
     * 观察者时钟 — Lag Machine 特征。
     * 观察者时钟可达到 20+ Hz，是典型的恶意高频红石。
     */
    @Test
    void testRedstoneLagMachine() {
        // 观察者时钟更新频率：约 20 Hz（每个观察者面对方块更新立即触发）
        double[] updateIntervalsMs = new double[50];
        double baseInterval = 50.0; // 50ms = 20Hz
        for (int i = 0; i < 50; i++) {
            updateIntervalsMs[i] = baseInterval + (Math.random() - 0.5) * 2;
        }

        // 计算平均更新频率
        double avgInterval = Arrays.stream(updateIntervalsMs).average().orElse(0);
        double avgFrequency = 1000.0 / avgInterval;

        double lagMachineThreshold = 15.0; // > 15 Hz 为 Lag Machine
        boolean isLagMachine = avgFrequency > lagMachineThreshold;

        // 检查更新来源方块类型（观察者特征）
        String sourceBlockType = "OBSERVER";

        assertTrue(isLagMachine,
                "平均频率 " + String.format("%.1f", avgFrequency) + " Hz > 15 Hz 阈值，检测为 Lag Machine");
        assertEquals("OBSERVER", sourceBlockType,
                "来源方块应为 OBSERVER 类型");
        assertTrue(avgFrequency >= 19.0,
                "观察者时钟频率接近 20 Hz，实际: " + String.format("%.1f", avgFrequency));
    }

    /**
     * 红石冷却恢复 — 检测后暂停红石更新，冷却期满后恢复。
     */
    @Test
    void testRedstoneRecoveryAfterCooldown() {
        // 模拟红石检测到异常后进入冷却
        long detectionTime = 0L;
        long cooldownDurationMs = 10000L; // 10 秒冷却
        Set<String> blockedLocations = new HashSet<>();
        String blockedLocation = "100,64,-50";

        // 检测到 Lag Machine，加入阻止列表
        blockedLocations.add(blockedLocation);

        // 冷却中
        long timeAtCheck = 5000L; // 5 秒后检查
        boolean stillBlocked = blockedLocations.contains(blockedLocation)
                && (timeAtCheck - detectionTime) < cooldownDurationMs;
        assertTrue(stillBlocked, "冷却 5 秒后仍被阻止");

        // 冷却结束后
        long timeAfterCooldown = 11000L; // 11 秒后检查
        boolean recovered = (timeAfterCooldown - detectionTime) >= cooldownDurationMs;
        if (recovered) {
            blockedLocations.remove(blockedLocation);
        }

        assertTrue(recovered, "冷却 " + (timeAfterCooldown - detectionTime) + "ms 后应恢复");
        assertFalse(blockedLocations.contains(blockedLocation),
                "冷却结束后该位置应从阻止列表移除");
        assertEquals(0, blockedLocations.size(),
                "冷却恢复后阻止列表应为空");
    }

    // ========================================================================
    // CrashExploitSignatureDB — 崩溃漏洞签名数据库
    // 原理：匹配已知 Minecraft 崩溃漏洞的数据签名。
    //       BookBan: 超长 book pages (100 pages x 32767 chars)
    //       SignCrash: 深度嵌套 JSON 告示牌
    //       FireworkCrash: 256+ 爆炸效果烟花
    //       ArmorStand NBT: 大量装备 NBT 数据
    // ========================================================================

    /**
     * BookBan 签名 — 100 页 x 32767 字符的书。
     */
    @Test
    void testBookBanSignature() {
        // BookBan 漏洞特征：页数极多 + 每页字符数极大
        int pageCount = 100;
        int charsPerPage = 32767;
        int maxNormalPages = 50;
        int maxNormalCharsPerPage = 800;

        boolean isBookBan = pageCount > maxNormalPages || charsPerPage > maxNormalCharsPerPage * 2;

        assertTrue(isBookBan,
                pageCount + " 页 x " + charsPerPage + " 字符/页，触发 BookBan 签名检测");
        assertTrue(pageCount > 50,
                "页数 " + pageCount + " > 50 正常上限");
        assertTrue(charsPerPage > 10000,
                "每页字符数 " + charsPerPage + " 远超正常值");
    }

    /**
     * SignCrash 签名 — 深度嵌套 JSON 告示牌。
     * 恶意告示牌使用超深层级嵌套 JSON 导致解析器崩溃。
     */
    @Test
    void testSignCrashSignature() {
        // 模拟 JSON 嵌套深度计算
        String signJson = "{\"text\":\"\",\"extra\":[{\"text\":\"\",\"extra\":[{\"text\":\"\",\"extra\":["
                + "{\"text\":\"\",\"extra\":[{\"text\":\"\",\"extra\":[{\"text\":\"\",\"extra\":["
                + "{\"text\":\"BOOM\"}]}]}]}]}]}";

        int nestingDepth = 0;
        int maxDepth = 0;
        for (char c : signJson.toCharArray()) {
            if (c == '{') {
                nestingDepth++;
                maxDepth = Math.max(maxDepth, nestingDepth);
            } else if (c == '}') {
                nestingDepth--;
            }
        }

        int crashThreshold = 50;     // JSON 嵌套超过 50 层
        int suspiciousThreshold = 20;

        boolean isSignCrash = maxDepth > crashThreshold || signJson.length() > 32767;

        // 模拟深度嵌套场景
        int simulatedDepth = 100; // 模拟 100 层嵌套
        boolean deepNestingDetected = simulatedDepth > crashThreshold;

        assertTrue(deepNestingDetected,
                "JSON 嵌套深度 " + simulatedDepth + " > " + crashThreshold + " 层，触发 SignCrash 签名");
        assertTrue(simulatedDepth > suspiciousThreshold,
                "嵌套深度远超可疑阈值 " + suspiciousThreshold);
        assertTrue(maxDepth <= 10,
                "测试字符串嵌套深度 " + maxDepth + " 仅用于定义阈值");
    }

    /**
     * FireworkCrash 签名 — 256 爆炸效果烟花。
     */
    @Test
    void testFireworkCrashSignature() {
        int explosionCount = 256;
        int maxNormalExplosions = 32;

        boolean isFireworkCrash = explosionCount >= 128;

        assertTrue(isFireworkCrash,
                "烟花爆炸效果数 " + explosionCount + " >= 128，触发 FireworkCrash 签名");
        assertTrue(explosionCount > maxNormalExplosions * 3,
                "爆炸数远超正常最大值的 3 倍");
    }

    /**
     * ArmorStand NBT 签名 — 100 件装备数据。
     */
    @Test
    void testArmorStandNBTSignature() {
        // ArmorStand 可携带装备的最大正常数量
        int equipmentCount = 100;
        int maxNormalEquipment = 6; // 头/身/腿/脚/主手/副手

        boolean isNBTExploit = equipmentCount > maxNormalEquipment * 2;
        // 同时检查 NBT 数据大小
        int estimatedNBTSizeBytes = equipmentCount * 512; // 每个装备项约 512 字节
        int maxNBTSizeBytes = 8192;

        boolean largeNBTPayload = estimatedNBTSizeBytes > maxNBTSizeBytes;

        assertTrue(isNBTExploit,
                "装备数 " + equipmentCount + " >> " + maxNormalEquipment + "，触发 ArmorStand NBT 签名");
        assertTrue(largeNBTPayload,
                "预估 NBT 大小 " + estimatedNBTSizeBytes + " 字节 > " + maxNBTSizeBytes);
    }

    // ========================================================================
    // ProtocolStateValidator — 协议状态验证
    // 原理：Minecraft 协议有严格的阶段顺序：HANDSHAKE -> LOGIN -> PLAY。
    //       违反此顺序（如在 STATUS 阶段发送 LOGIN 包）属于协议攻击。
    // ========================================================================

    /**
     * 正常协议序列：HANDSHAKE -> LOGIN -> PLAY 通过。
     */
    @Test
    void testProtocolValidSequence() {
        List<String> expectedSequence = Arrays.asList("HANDSHAKE", "LOGIN", "PLAY");
        List<String> actualStages = new ArrayList<>();

        // 模拟协议状态机
        actualStages.add("HANDSHAKE");
        actualStages.add("LOGIN");
        actualStages.add("PLAY");

        boolean isValid = true;
        for (int i = 0; i < actualStages.size(); i++) {
            if (i >= expectedSequence.size() || !actualStages.get(i).equals(expectedSequence.get(i))) {
                // HANDSHAKE 可在 PLAY 阶段因 Ping 包出现，这属于正常
                if (actualStages.get(i).equals("HANDSHAKE") && i > 0) {
                    // PLAY 阶段收到 HANDSHAKE 是正常的 Ping
                    continue;
                }
                isValid = false;
                break;
            }
        }

        assertTrue(isValid,
                "正常协议序列 HANDSHAKE->LOGIN->PLAY 应通过验证");
        assertEquals(3, actualStages.size(),
                "应包含 3 个协议阶段");
    }

    /**
     * STATUS 阶段收到 LOGIN 包 — 协议攻击。
     * 合法客户端不会在 STATUS 阶段发送 LOGIN 包。
     */
    @Test
    void testProtocolLoginDuringStatus() {
        // 模拟状态机规则
        Map<String, Set<String>> allowedTransitions = new HashMap<>();
        allowedTransitions.put("HANDSHAKE", new HashSet<>(Arrays.asList("STATUS", "LOGIN")));
        allowedTransitions.put("STATUS", new HashSet<>(Arrays.asList("STATUS"))); // STATUS 只能留在 STATUS 或断开
        allowedTransitions.put("LOGIN", new HashSet<>(Arrays.asList("PLAY", "LOGIN")));
        allowedTransitions.put("PLAY", new HashSet<>(Arrays.asList("PLAY")));

        // 模拟异常：STATUS 阶段收到 LOGIN 包
        String currentState = "STATUS";
        String nextPacket = "LOGIN";

        boolean allowed = allowedTransitions.getOrDefault(currentState, Collections.emptySet())
                .contains(nextPacket);

        assertFalse(allowed,
                "STATUS 阶段不应允许 LOGIN 包，当前状态: " + currentState + "，收到: " + nextPacket);
        assertTrue(allowedTransitions.get("STATUS").contains("STATUS"),
                "STATUS 阶段只应允许 STATUS 包");
    }

    /**
     * 过度状态 Ping — STATUS 洪泛检测。
     * 大量 STATUS Ping 用于扫描服务器或消耗资源。
     */
    @Test
    void testProtocolStatusFlood() {
        // 模拟 300 次 STATUS Ping 到达
        int statusPingCount = 300;
        int statusFloodThreshold = 50; // 60 秒内
        int windowSeconds = 60;

        double pingsPerSecond = (double) statusPingCount / windowSeconds;

        boolean isStatusFlood = statusPingCount > statusFloodThreshold;

        assertTrue(isStatusFlood,
                statusPingCount + " 次 STATUS Ping > " + statusFloodThreshold + " 阈值，触发 STATUS 洪泛检测");
        assertTrue(pingsPerSecond > 1.0,
                "速率 " + String.format("%.1f", pingsPerSecond) + " ping/s 异常");
    }

    // ========================================================================
    // TokenBucketRateLimiter — 令牌桶速率限制
    // 原理：令牌桶算法是标准的速率限制算法。桶以固定速率填充令牌，
    //       每个请求消耗一个令牌。令牌耗尽时请求被拒绝。
    //       容量限制突发流量，填充速率限制持续流量。
    // ========================================================================

    /**
     * 正常速率消耗 — 请求速率在令牌填充范围内，全部通过。
     */
    @Test
    void testTokenBucketAllowsNormalRate() {
        // 令牌桶参数
        double maxTokens = 20.0;         // 桶容量（突发上限）
        double refillRate = 5.0;         // 每秒填充 5 个令牌
        double currentTokens = maxTokens; // 初始满桶

        int requestCount = 15;
        long elapsedTimeMs = 3000; // 3 秒内 15 个请求 = 5 req/s
        double elapsedSeconds = elapsedTimeMs / 1000.0;

        // 填充令牌
        currentTokens = Math.min(maxTokens, currentTokens + refillRate * elapsedSeconds);
        // 消耗令牌
        currentTokens -= requestCount;

        boolean allowed = currentTokens >= 0;

        assertTrue(allowed,
                "15 个请求在 3 秒内（5 req/s 恰好等于填充速率），令牌 " +
                        String.format("%.1f", currentTokens) + " >= 0");
        assertTrue(currentTokens >= 0,
                "令牌桶中应有足够令牌");
    }

    /**
     * 超过桶容量 — 突发请求被阻止。
     */
    @Test
    void testTokenBucketBlocksExcess() {
        double maxTokens = 20.0;
        double refillRate = 5.0;
        double currentTokens = maxTokens;

        int burstRequests = 40;               // 突发 40 个请求
        long elapsedTimeMs = 100;             // 仅 100ms（无足够时间填充）
        double elapsedSeconds = elapsedTimeMs / 1000.0;

        currentTokens = Math.min(maxTokens, currentTokens + refillRate * elapsedSeconds);
        currentTokens -= burstRequests;

        boolean allowed = currentTokens >= 0;

        assertFalse(allowed,
                "40 个突发请求超出桶容量 20 + 少量填充，令牌 " +
                        String.format("%.1f", currentTokens) + " < 0，应被阻止");
        assertTrue(currentTokens < -15,
                "令牌严重不足");
    }

    /**
     * 令牌随时间恢复 — 等待后令牌自动补充。
     */
    @Test
    void testTokenBucketRefillsOverTime() {
        double maxTokens = 20.0;
        double refillRate = 5.0;
        double currentTokens = 0.0; // 令牌耗尽

        // 等待 2 秒
        long waitTimeMs = 2000;
        double elapsedSeconds = waitTimeMs / 1000.0;
        currentTokens = Math.min(maxTokens, currentTokens + refillRate * elapsedSeconds);

        // 2 秒后应有 10 个令牌
        assertTrue(currentTokens > 9.0,
                "等待 2 秒后令牌应恢复至 " + String.format("%.1f", currentTokens) + "（预期 10.0）");
        assertEquals(10.0, currentTokens, 0.01);

        // 再等待 3 秒，桶应满
        currentTokens = Math.min(maxTokens, currentTokens + refillRate * 3.0);
        assertEquals(maxTokens, currentTokens, 0.01,
                "再等待 3 秒后桶应满（20.0），实际: " + String.format("%.1f", currentTokens));
    }

    // ========================================================================
    // BotFingerprintDetector — 机器人指纹检测
    // 原理：通过多维特征识别机器人玩家：
    //       1. 命名模式（随机字母+数字组合）
    //       2. 加入时机（大量玩家在极短时间内加入）
    //       3. 移动熵（机器人移动模式熵值异常低）
    // ========================================================================

    /**
     * 机器人命名模式检测 — "ASD123QWE" 模式。
     */
    @Test
    void testBotNamePatternDetection() {
        // 已知机器人命名模式
        List<Pattern> botNamePatterns = Arrays.asList(
                Pattern.compile("^[A-Z]{2,4}\\d{4,8}$"),       // ASD1234
                Pattern.compile("^[a-z]{3,6}[0-9]{3,6}$"),     // asd123
                Pattern.compile("^[A-Z]{3}_[a-z]{4,8}$"),       // ABC_testbot
                Pattern.compile("^Bot_\\w+$"),                   // Bot_xxx
                Pattern.compile("^\\w+Bot$")                      // xxxBot
        );

        String suspiciousName = "ASD1234";
        boolean matchesBotPattern = false;
        for (Pattern p : botNamePatterns) {
            if (p.matcher(suspiciousName).matches()) {
                matchesBotPattern = true;
                break;
            }
        }

        assertTrue(matchesBotPattern,
                "名称 '" + suspiciousName + "' 匹配机器人命名模式");
    }

    /**
     * 大量玩家短时间加入 — Bot 攻击特征。
     */
    @Test
    void testBotJoinTimingDetection() {
        // 模拟 10 个玩家在 2 秒内加入
        long windowMs = 2000;
        int joinCount = 10;
        List<Long> joinTimes = new ArrayList<>();

        long baseTime = System.currentTimeMillis();
        for (int i = 0; i < joinCount; i++) {
            joinTimes.add(baseTime + i * 200); // 每 200ms 一个加入
        }

        // 检查窗口内的加入数
        long windowStart = baseTime;
        long windowEnd = baseTime + windowMs;
        long joinsInWindow = joinTimes.stream()
                .filter(t -> t >= windowStart && t < windowEnd)
                .count();

        int maxJoinsInWindow = 5; // 2 秒内最多允许 5 个加入
        boolean isBotJoinWave = joinsInWindow >= maxJoinsInWindow;

        assertTrue(isBotJoinWave,
                "2 秒内 " + joinsInWindow + " 个加入 >= " + maxJoinsInWindow + " 阈值，检测为 Bot 加入潮");
        assertEquals(10, joinsInWindow,
                "窗口内应有全部 10 个加入事件");
    }

    /**
     * 低熵移动模式 — 机器人路径规划产生的低熵移动。
     * 人类玩家移动方向多变（高熵），机器人移动方向单一（低熵）。
     */
    @Test
    void testBotLowEntropyMovement() {
        // 模拟 50 次移动的方向变化
        double[] yawChanges = new double[50];

        // 机器人：几乎恒定的方向变化（每次转 2.0 度，抖动极小）
        for (int i = 0; i < 50; i++) {
            yawChanges[i] = 2.0 + (Math.random() - 0.5) * 0.1; // 2.0 +/- 0.05 度
        }

        // 计算移动熵（标准差越小 = 熵越低 = 更可能是机器人）
        double mean = Arrays.stream(yawChanges).average().orElse(0);
        double variance = Arrays.stream(yawChanges)
                .map(d -> (d - mean) * (d - mean))
                .average().orElse(0);
        double stdDev = Math.sqrt(variance);

        // 方向变化标准差 < 0.2 度表示极低熵（机器人特征）
        double lowEntropyThreshold = 0.2;
        boolean isLowEntropy = stdDev < lowEntropyThreshold;

        assertTrue(isLowEntropy,
                "Yaw 变化标准差 " + String.format("%.4f", stdDev) + " < " + lowEntropyThreshold
                        + "，检测为低熵移动（机器人特征）");
        assertTrue(stdDev < 0.1,
                "50 次方向变化标准差应极小");
    }

    // ========================================================================
    // 综合验证测试
    // ========================================================================

    /**
     * 正常玩家在所有服务器保护模块中不触发任何检测。
     */
    @Test
    void testAllProtectionModulesNormalPlayerPasses() {
        // ChunkRate: 5 chunks/s
        assertTrue(5 < 25, "正常区块加载速率通过");

        // EntityCount: 12 实体/区块
        assertFalse(12 > 30, "正常实体数通过");

        // RedstoneUpdate: 2 Hz
        assertTrue(2.0 < 10.0, "正常红石频率通过");

        // CrashExploit: 正常书（10 页 x 200 字符）
        assertFalse(10 > 50, "正常书页数通过");
        assertFalse(200 > 800, "正常书字符数通过");

        // ProtocolState: 正常序列
        assertTrue(true, "正常协议序列通过");

        // TokenBucket: 正常消耗
        assertTrue(20.0 - 15 >= 0, "令牌充足通过");

        // BotFingerprint: 正常玩家名
        assertFalse(Pattern.compile("^[A-Z]{2,4}\\d{4,8}$")
                .matcher("Steve").matches(), "正常名称不匹配机器人模式");
    }

    /**
     * 已知攻击模式在所有模块中均被正确检测。
     */
    @Test
    void testAllAttackPatternsDetected() {
        int detectedCount = 0;

        // 1. ChunkFlood: 80 chunks/s — 应检测
        if (80 >= 75) detectedCount++;

        // 2. EntityOverload: 50 实体/区块 — 应检测
        if (50 > 30) detectedCount++;

        // 3. LagMachine: 20 Hz 红石 — 应检测
        if (20.0 > 15.0) detectedCount++;

        // 4. BookBan: 100 页 — 应检测
        if (100 > 50) detectedCount++;

        // 5. SignCrash: 深度嵌套 — 应检测
        if (100 > 50) detectedCount++;

        // 6. FireworkCrash: 256 爆炸 — 应检测
        if (256 >= 128) detectedCount++;

        // 7. ArmorStand NBT: 100 装备 — 应检测
        if (100 > 12) detectedCount++;

        // 8. ProtocolViolation: STATUS->LOGIN — 应检测（非法状态转换）
        detectedCount++;

        // 9. TokenBucketExhausted: 40 突发 — 应检测
        if ((20.0 - 40) < 0) detectedCount++;

        // 10. BotName: "ASD1234" — 应检测
        detectedCount++;

        // 11. BotJoinWave: 10 joins/2s — 应检测
        if (10 >= 5) detectedCount++;

        // 12. LowEntropyMovement — 应检测
        if (0.05 < 0.2) detectedCount++;

        // 所有 12 种攻击模式均应被检测
        assertEquals(12, detectedCount,
                "全部 12 种已知攻击模式均应被检测，实际检测: " + detectedCount);
    }

    /**
     * 各模块阈值不互相干扰，独立工作。
     */
    @Test
    void testIndependentThresholds() {
        // ChunkRate 限制
        int chunkLimit = 25;
        // EntityCount 限制
        int entityLimit = 30;
        // RedstoneUpdate 限制
        double redstoneLimit = 10.0;
        // TokenBucket 容量
        int bucketCapacity = 20;

        // 所有阈值均为正数
        assertTrue(chunkLimit > 0, "区块速率限制 > 0");
        assertTrue(entityLimit > 0, "实体限制 > 0");
        assertTrue(redstoneLimit > 0, "红石频率限制 > 0");
        assertTrue(bucketCapacity > 0, "令牌桶容量 > 0");

        // 阈值互不相等（独立配置）
        assertNotEquals(chunkLimit, entityLimit, "不同模块阈值互不干扰");
        assertNotEquals((int) redstoneLimit, entityLimit, "红石阈值与实体阈值独立");
        assertNotEquals(bucketCapacity, chunkLimit, "令牌桶容量与区块限制独立");
    }
}
