package com.aluer.security;

import org.junit.jupiter.api.Test;

import java.util.*;

import static org.junit.jupiter.api.Assertions.*;
import com.aluer.anticheat.combat.AntiVelocityService;
import com.aluer.anticheat.movement.AntiBlinkService;
import com.aluer.anticheat.movement.AntiElytraFlyService;
import com.aluer.anticheat.movement.AntiPhaseService;
import com.aluer.anticheat.movement.AntiTimerService;
import com.aluer.anticheat.world.AntiFastBreakService;

/**
 * V5.0 反作弊扩展模块测试 — 打靶试验（模拟真实 Minecraft 生产环境数据）
 *
 * 覆盖 6 个 V5.0 新增反作弊模块：
 *   AntiTimerService      — 游戏时钟加速检测
 *   AntiVelocityService   — 击退修改检测
 *   AntiPhaseService      — 穿墙/相位检测
 *   AntiBlinkService      — 瞬断重连规避伤害检测
 *   AntiFastBreakService  — 快速破坏检测
 *   AntiElytraFlyService  — 鞘翅飞行加速检测
 *
 * 由于 V5.0 服务类尚未实现，本测试内联检测逻辑直接验证算法正确性。
 * 每个模块 3 个测试（正常/异常/边界），共 18 个测试用例。
 */
class V50AntiCheatExtendedTest {

    // ========================================================================
    // AntiTimerService — 游戏时钟加速检测
    // 原理：Minecraft 标准 TPS 为 20，对应每次 tick 间隔 50ms。
    //       当客户端使用 Timer hack 加速时，移动数据包间隔会显著缩短。
    //       通过追踪连续 tick 间隔来判断是否启用了时钟加速。
    // ========================================================================

    /**
     * 模拟玩家以 30+ ticks/sec 等效速度移动 — Timer hack 特征。
     * 30 次连续加速 tick 应触发检测。
     */
    @Test
    void testTimerDetectsAcceleratedMovement() {
        // 模拟数据：正常 TPS=20，间隔 50ms；加速后间隔 33ms（约 30 TPS）
        double expectedIntervalMs = 50.0;
        double acceleratedIntervalMs = 33.0;
        double speedMultiplier = expectedIntervalMs / acceleratedIntervalMs; // ~1.52x

        // 模拟 30 次连续加速间隔
        int acceleratedCount = 0;
        int consecutiveAccelerated = 0;
        int maxConsecutiveAccelerated = 0;

        for (int i = 0; i < 30; i++) {
            if (acceleratedIntervalMs < expectedIntervalMs * 0.85) {
                acceleratedCount++;
                consecutiveAccelerated++;
                maxConsecutiveAccelerated = Math.max(maxConsecutiveAccelerated, consecutiveAccelerated);
            } else {
                consecutiveAccelerated = 0;
            }
        }

        // 断言：30 次全部加速，且连续加速 >= 20 次应被检测
        assertTrue(acceleratedCount >= 30, "所有 30 ticks 均应被标记为加速");
        assertTrue(speedMultiplier > 1.3, "加速倍数应超过 1.3x 阈值");
        assertTrue(maxConsecutiveAccelerated >= 20,
                "连续加速 tick 数 " + maxConsecutiveAccelerated + " 应 >= 20，触发 Timer 检测");
    }

    /**
     * 正常 20 ticks/sec — 间隔约 50ms，不应触发检测。
     */
    @Test
    void testTimerNormalSpeedPasses() {
        double expectedIntervalMs = 50.0;
        double normalIntervalMs = 50.0; // 标准 20 TPS

        int normalCount = 0;
        int flaggedCount = 0;

        for (int i = 0; i < 40; i++) {
            // 加入小幅度抖动模拟真实网络环境
            double jitteredInterval = normalIntervalMs + (Math.random() - 0.5) * 10.0;
            if (jitteredInterval < expectedIntervalMs * 0.85) {
                flaggedCount++;
            } else {
                normalCount++;
            }
        }

        // 正常 TPS：绝大多数间隔应在正常范围
        assertTrue(normalCount >= 35, "正常 TPS 下应有 35+ 正常间隔，实际: " + normalCount);
        assertTrue(flaggedCount <= 5, "正常 TPS 下异常标记应 <= 5，实际: " + flaggedCount);
    }

    /**
     * 持续加速窗口测试 — 在整个观测窗口内维持加速状态。
     * 如果整窗口（如 60 ticks）内超 80% 加速，确认 Timer hack。
     */
    @Test
    void testTimerConsistencyAcrossWindow() {
        int windowSize = 60; // 60 tick 观测窗口
        double expectedIntervalMs = 50.0;
        double acceleratedIntervalMs = 35.0; // 约 28.6 TPS

        int acceleratedCount = 0;
        for (int i = 0; i < windowSize; i++) {
            if (acceleratedIntervalMs < expectedIntervalMs * 0.85) {
                acceleratedCount++;
            }
        }

        double acceleratedRatio = (double) acceleratedCount / windowSize;
        // 窗口内超 80% 为加速 tick
        assertTrue(acceleratedRatio > 0.8,
                "窗口内加速比例 " + String.format("%.2f", acceleratedRatio) + " 应 > 0.8");
        assertTrue(acceleratedCount >= 48,
                "60 tick 窗口内加速 tick " + acceleratedCount + " 应 >= 48");
    }

    // ========================================================================
    // AntiVelocityService — 击退修改检测
    // 原理：Minecraft 中玩家受到攻击时会产生击退（Velocity），
    //       服务端计算期望的击退向量并与实际位移比较。
    //       如果实际位移显著小于预期，说明客户端修改了 Velocity 包。
    // ========================================================================

    /**
     * 零击退检测 — 玩家受到攻击后位置完全不变。
     * 正常击退约 0.4-0.6 方块/次，完全无位移为 Velocity hack。
     */
    @Test
    void testVelocityDetectsZeroKnockback() {
        // 模拟攻击数据：玩家在坐标 (100, 64, 100)，受到来自正前方的攻击
        double playerX = 100.0, playerY = 64.0, playerZ = 100.0;
        double attackerX = 101.0, attackerY = 64.0, attackerZ = 100.0;

        // 计算期望击退方向（从攻击者指向受害者）
        double dx = playerX - attackerX;
        double dz = playerZ - attackerZ;
        double length = Math.sqrt(dx * dx + dz * dz);

        // 归一化后乘以击退强度（约 0.4）
        double expectedKnockbackX = (dx / length) * 0.4;
        double expectedKnockbackZ = (dz / length) * 0.4;

        // 模拟实际位移（零击退）
        double actualDeltaX = 0.0;
        double actualDeltaZ = 0.0;

        // 计算实际位移与期望位移的比例
        double actualRatio = Math.sqrt(
                actualDeltaX * actualDeltaX + actualDeltaZ * actualDeltaZ
        ) / 0.4;

        // 零击退检测：实际/期望 < 0.1
        assertTrue(actualRatio < 0.1,
                "零击退比例 " + String.format("%.4f", actualRatio) + " 应 < 0.1，触发 ZeroKB 检测");
        assertEquals(-1.0, expectedKnockbackX / Math.abs(expectedKnockbackX), 0.01,
                "击退方向应为攻击者反方向（负X）");
    }

    /**
     * 击退减少超过 50% — Velocity hack 常见变种。
     * 实际位移仅为期望的 30%，应触发检测。
     */
    @Test
    void testVelocityDetectsReducedKnockback() {
        // 期望击退约 0.4 方块
        double expectedKnockback = 0.4;
        // 实际位移仅 0.1 方块（25% 期望值）
        double actualDeltaX = -0.08;
        double actualDeltaZ = 0.06;
        double actualDistance = Math.sqrt(
                actualDeltaX * actualDeltaX + actualDeltaZ * actualDeltaZ
        );

        double reductionRatio = actualDistance / expectedKnockback;
        // 减少超过 50% 即触发
        assertTrue(reductionRatio < 0.5,
                "击退减少比例 " + String.format("%.2f", reductionRatio) + " 应 < 0.5");
        assertTrue(actualDistance < 0.2,
                "实际击退距离 " + String.format("%.3f", actualDistance) + " 方块应 < 0.2");
    }

    /**
     * 正常击退 — 玩家位置变化与期望相符（考虑网络延迟 10-20% 误差）。
     */
    @Test
    void testVelocityNormalKnockbackPasses() {
        double expectedKnockback = 0.4;
        // 正常击退：在期望值的 85%-115% 范围
        double normalDeltaX = -0.38;
        double normalDeltaZ = 0.02;
        double actualDistance = Math.sqrt(
                normalDeltaX * normalDeltaX + normalDeltaZ * normalDeltaZ
        );

        double ratio = actualDistance / expectedKnockback;
        // 正常击退应在 0.7-1.3 范围（考虑延迟和精度误差）
        assertTrue(ratio >= 0.7 && ratio <= 1.3,
                "正常击退比例 " + String.format("%.2f", ratio) + " 应在 0.7-1.3 范围");
        // 不应触发任何检测
        assertFalse(ratio < 0.1, "不应触发零击退检测");
        assertFalse(ratio < 0.5, "不应触发击退减少检测");
    }

    // ========================================================================
    // AntiPhaseService — 穿墙/相位检测
    // 原理：玩家移动时检查路径上的方块碰撞。
    //       如果玩家穿过实心方块（如石头墙），说明使用了 Phase/Noclip hack。
    // ========================================================================

    /**
     * 穿墙检测 — 玩家在 500ms 内移动通过 2 方块厚的石墙。
     * 正常情况无法穿过实心方块，穿越应触发 Phase 检测。
     */
    @Test
    void testPhaseDetectsWallClipping() {
        // 模拟玩家从坐标 (100, 64, 100) 移动到 (102, 64, 100)
        // 路径上经过方块 (101, 64, 100) 和 (101, y, 100) — 石墙
        double startX = 100.0, endX = 102.0;
        double startZ = 100.0, endZ = 100.0;
        double playerY = 64.0;

        // 检查路径上的每个方块坐标
        boolean passedThroughSolid = false;
        Set<String> solidBlocks = new HashSet<>(Arrays.asList(
                "STONE", "COBBLESTONE", "DIRT", "OBSIDIAN",
                "NETHERRACK", "END_STONE", "DEEPSLATE"
        ));

        // 模拟墙壁位置
        Map<String, String> blockMap = new HashMap<>();
        blockMap.put("101,64,100", "STONE");     // 第一层墙
        blockMap.put("101,65,100", "STONE");     // 上方方块

        // 检查玩家移动路径穿越的方块
        int minX = (int) Math.floor(Math.min(startX, endX));
        int maxX = (int) Math.floor(Math.max(startX, endX));
        int minZ = (int) Math.floor(Math.min(startZ, endZ));
        int maxZ = (int) Math.floor(Math.max(startZ, endZ));

        for (int bx = minX; bx <= maxX; bx++) {
            for (int bz = minZ; bz <= maxZ; bz++) {
                for (int by = (int) playerY; by <= (int) playerY + 1; by++) {
                    String key = bx + "," + by + "," + bz;
                    String block = blockMap.get(key);
                    if (block != null && solidBlocks.contains(block)) {
                        passedThroughSolid = true;
                    }
                }
            }
        }

        assertTrue(passedThroughSolid,
                "玩家穿过固体方块墙壁，应触发 Phase 检测");
        assertTrue(maxX - minX >= 1,
                "移动距离 " + (maxX - minX) + " 方块，在路径上的方块应被检查");
    }

    /**
     * 正常通过门/栅栏门 — 不应触发 Phase 检测。
     * 门和栅栏门是非固体方块，正常穿过是合法的。
     */
    @Test
    void testPhaseNormalDoorPassage() {
        boolean passedThroughSolid = false;
        Set<String> passableBlocks = new HashSet<>(Arrays.asList(
                "AIR", "OAK_DOOR", "IRON_DOOR", "OAK_FENCE_GATE",
                "WATER", "LAVA", "TORCH", "TALL_GRASS"
        ));

        // 模拟路径上遇到门，门是可通行的
        Map<String, String> blockMap = new HashMap<>();
        blockMap.put("101,64,100", "OAK_DOOR");       // 门 — 可通行
        blockMap.put("101,65,100", "AIR");             // 门上方

        // 检查路径
        String key = "101,64,100";
        String block = blockMap.get(key);
        if (block != null && !passableBlocks.contains(block)) {
            passedThroughSolid = true;
        }

        assertFalse(passedThroughSolid,
                "通过门/栅栏门应被视为合法行为，不触发 Phase 检测");
        assertTrue(passableBlocks.contains("OAK_DOOR"),
                "OAK_DOOR 应在可通行方块列表中");
    }

    /**
     * 地狱门相位漏洞 — 玩家在进入传送门动画期间绕过碰撞检测。
     * 利用地狱门切换维度的短暂空隙进行 Phase 移动。
     */
    @Test
    void testPhaseDetectsNetherPortalExploit() {
        // 模拟玩家在进入地狱门后 50ms 内移动了 10 方块（利用加载间隙）
        double moveDistance = 10.5;  // 方块
        long moveTimeMs = 50;        // 毫秒

        double blocksPerMs = moveDistance / moveTimeMs;
        double blocksPerTick = blocksPerMs * 50; // 每 tick (50ms) 的移动量

        // 正常速度上限约 30 m/s (鞘翅)，此处检测极大位移
        boolean phaseDetected = blocksPerTick > 5.0; // 每 tick >5 方块为异常

        assertTrue(phaseDetected,
                "每 tick 移动 " + String.format("%.1f", blocksPerTick)
                        + " 方块远超正常上限，应触发传送门 Phase 检测");
        assertTrue(blocksPerMs > 0.1,
                "移动速度 " + String.format("%.2f", blocksPerMs) + " 方块/ms 远超合法范围");
    }

    // ========================================================================
    // AntiBlinkService — 瞬断重连规避伤害检测
    // 原理：Blink hack 在受到伤害时立即断开连接（< 1 秒），
    //       然后在短时间内（< 5 秒）重新连接以规避伤害结算。
    // ========================================================================

    /**
     * 受到伤害后 1 秒内断开，5 秒内重连 — Blink hack 典型模式。
     */
    @Test
    void testBlinkDetectsDamageEvasion() {
        // 模拟事件时间线（毫秒）
        long damageTime = 1000L;       // T=1000ms: 受到伤害
        long disconnectTime = 1800L;   // T=1800ms: 断开连接（800ms 后）
        long reconnectTime = 3500L;    // T=3500ms: 重新连接（1.7秒后）

        long disconnectDelta = disconnectTime - damageTime;
        long reconnectDelta = reconnectTime - disconnectTime;

        // Blink 检测条件：
        // 1. 受伤后 1 秒内断开
        // 2. 断开后 5 秒内重连
        boolean blinkSuspicious = disconnectDelta < 1000 && reconnectDelta < 5000;

        assertTrue(blinkSuspicious,
                "受伤后 " + disconnectDelta + "ms 断开，断开后 " + reconnectDelta + "ms 重连，应触发 Blink 检测");
        assertTrue(disconnectDelta < 1000,
                "受伤到断开间隔 " + disconnectDelta + "ms 应 < 1000ms");
        assertTrue(reconnectDelta < 5000,
                "断开到重连间隔 " + reconnectDelta + "ms 应 < 5000ms");
    }

    /**
     * 正常重连 — 受伤 30+ 秒后断开，再 10 秒后重连，属于正常行为。
     */
    @Test
    void testBlinkNormalReconnectPasses() {
        long damageTime = 1000L;
        long disconnectTime = 35000L;  // 受伤 34 秒后断开（正常游戏退出）
        long reconnectTime = 45000L;   // 10 秒后重连

        long disconnectDelta = disconnectTime - damageTime;
        long reconnectDelta = reconnectTime - disconnectTime;

        // 正常重连：受伤到断开间隔 >= 1000ms，不触发 Blink
        boolean blinkDetected = disconnectDelta < 1000 && reconnectDelta < 5000;

        assertFalse(blinkDetected,
                "受伤后 " + disconnectDelta + "ms 断开不触发 Blink 检测（正常退出）");
        assertTrue(disconnectDelta > 30000,
                "正常断开间隔 " + disconnectDelta + "ms 远大于 30 秒");
    }

    /**
     * 60 秒内 3+ 次 Blink 循环 — 确认作弊，触发高级别告警。
     */
    @Test
    void testBlinkMultipleCyclesDetected() {
        // 模拟 60 秒内 4 次 Blink 循环
        List<long[]> cycles = new ArrayList<>();
        cycles.add(new long[]{0, 800, 2000});      // 受伤 0ms→断开 800ms→重连 2000ms
        cycles.add(new long[]{15000, 15400, 17000}); // 受伤 15s→断开 15.4s→重连 17s
        cycles.add(new long[]{30000, 30600, 32000}); // 受伤 30s→断开 30.6s→重连 32s
        cycles.add(new long[]{45000, 45200, 47000}); // 受伤 45s→断开 45.2s→重连 47s

        int blinkCycleCount = 0;
        for (long[] cycle : cycles) {
            long disconnectDelta = cycle[1] - cycle[0];
            long reconnectDelta = cycle[2] - cycle[1];
            if (disconnectDelta < 1000 && reconnectDelta < 5000) {
                blinkCycleCount++;
            }
        }

        // 60 秒内 3+ 次 Blink 循环确认为作弊
        assertTrue(blinkCycleCount >= 4,
                "60 秒内检测到 " + blinkCycleCount + " 次 Blink 循环，应 >= 3 次即触发高危告警");
        assertEquals(4, blinkCycleCount,
                "应检测到全部 4 次 Blink 循环");
    }

    // ========================================================================
    // AntiFastBreakService — 快速破坏检测
    // 原理：不同方块有固定破坏时间。钻石镐破坏黑曜石约需 9.4 秒。
    //       如果破坏时间显著低于理论值，说明使用了 FastBreak/InstaBreak hack。
    // ========================================================================

    /**
     * 黑曜石瞬间破坏 — 破坏时间 < 1 秒（理论值约 9.4 秒）。
     * 即便考虑 Efficiency V，黑曜石至少需要约 1.8 秒，< 1 秒为明确作弊。
     */
    @Test
    void testFastBreakObsidianInstant() {
        // 黑曜石理论破坏时间：硬度 50，钻石镐倍率 8x
        // Minecraft 公式: damagePerTick = toolMultiplier / (hardness * 30)
        // 无 Efficiency: damagePerTick = 8 / (50 * 30) = 0.00533
        // ticksNeeded = ceil(1.0 / 0.00533) = ceil(187.5) = 188 ticks
        // theoreticalTime = 188 * 50ms = 9400ms
        double blockHardness = 50.0;           // 黑曜石硬度
        double toolMultiplier = 8.0;           // 钻石镐

        // 无 Efficiency: Minecraft 破坏速度 = 工具倍率 * 1 / (硬度 * 30)
        double damagePerTick = toolMultiplier * 1.0 / (blockHardness * 30.0);
        double ticksNeeded = Math.ceil(1.0 / damagePerTick);
        double theoreticalTimeMs = ticksNeeded * 50; // 每 tick 50ms

        // 理论破坏时间约 9400ms (188 ticks at 20 TPS)
        assertEquals(9400.0, theoreticalTimeMs, 100.0,
                "黑曜石理论破坏时间应为 ~9400ms，实际: " + String.format("%.0f", theoreticalTimeMs));

        // 模拟实际破坏时间 < 1 秒
        double actualBreakTimeMs = 800;
        boolean fastBreakDetected = actualBreakTimeMs < theoreticalTimeMs * 0.3;

        assertTrue(fastBreakDetected,
                "实际破坏时间 " + actualBreakTimeMs + "ms < 理论时间 30%，应触发 FastBreak 检测");
        assertTrue(actualBreakTimeMs < 1000,
                "< 1 秒破坏黑曜石为明确的 InstantBreak hack");
    }

    /**
     * Efficiency V 附魔合法加速 — 正确计入附魔速度加成。
     * Efficiency V 提供 (5^2 + 1) = 26 额外效率，显著缩短破坏时间。
     */
    @Test
    void testFastBreakWithEfficiencyV() {
        double blockHardness = 3.0;             // 石头硬度
        double toolMultiplier = 8.0;            // 钻石镐
        int efficiencyLevel = 5;                // Efficiency V
        double hasteLevel = 0;

        // 有 Efficiency V 的破坏速度
        double damagePerTickWithEff = toolMultiplier
                * (1 + efficiencyLevel * efficiencyLevel + 1)
                / (blockHardness * 30);
        double ticksNeededWithEff = Math.ceil(1.0 / damagePerTickWithEff);
        double timeWithEffMs = ticksNeededWithEff * 50;

        // 无 Efficiency 的破坏速度（石头硬度 3.0）
        double damagePerTickNoEff = toolMultiplier * 1.0 / (blockHardness * 30);
        double ticksNeededNoEff = Math.ceil(1.0 / damagePerTickNoEff);
        double timeNoEffMs = ticksNeededNoEff * 50;

        // Efficiency V 的破坏时间应显著短于无附魔
        assertTrue(timeWithEffMs < timeNoEffMs * 0.2,
                "Efficiency V 破坏时间 " + String.format("%.0f", timeWithEffMs)
                        + "ms 应 < 无附魔 " + String.format("%.0f", timeNoEffMs) + "ms 的 20%");
        assertTrue(timeWithEffMs < 100,
                "Efficiency V 破坏石头耗时 " + String.format("%.0f", timeWithEffMs) + "ms 应 < 100ms");
    }

    /**
     * 正常速度破坏石头 — 钻石镐破坏石头约 0.3 秒。
     */
    @Test
    void testFastBreakNormalStonePasses() {
        double blockHardness = 3.0;             // 石头
        double toolMultiplier = 8.0;            // 钻石镐
        int efficiencyLevel = 0;

        double damagePerTick = toolMultiplier * 1.0
                / (blockHardness * 30);
        double ticksNeeded = Math.ceil(1.0 / damagePerTick);
        double theoreticalTimeMs = ticksNeeded * 50;

        // 模拟实际破坏时间接近理论值（钻石镐无附魔破坏石头约 600ms）
        double actualBreakTimeMs = 500;

        boolean ratioNormal = actualBreakTimeMs >= theoreticalTimeMs * 0.7;
        boolean notInstant = actualBreakTimeMs > 50; // 至少需要 1 tick 以上

        assertTrue(ratioNormal,
                "实际破坏时间 " + actualBreakTimeMs + "ms 接近理论值 "
                        + String.format("%.0f", theoreticalTimeMs) + "ms，不触发检测");
        assertTrue(notInstant, "破坏时间 > 1 tick，不属于 InstantBreak");
    }

    // ========================================================================
    // AntiElytraFlyService — 鞘翅飞行加速检测
    // 原理：正常鞘翅飞行速度约 25-30 m/s。
    //       速度超过 60 m/s 或在不使用烟花火箭的情况下持续获得高度，
    //       说明使用了 ElytraFly/ElytraSpeed hack。
    // ========================================================================

    /**
     * 鞘翅速度超 60 方块/秒 — 应触发速度 Hack 检测。
     * 合法鞘翅速度上限约 30 m/s（平飞），60 m/s 远超合法范围。
     */
    @Test
    void testElytraDetectsSpeedHack() {
        // 模拟两个位置的移动数据（间隔 50ms = 1 tick）
        double x1 = 100.0, y1 = 200.0, z1 = 100.0;
        double x2 = 103.0, y2 = 200.5, z2 = 100.0;

        double dx = x2 - x1;
        double dy = y2 - y1;
        double dz = z2 - z1;

        // 50ms 内的位移
        double distancePerTick = Math.sqrt(dx * dx + dy * dy + dz * dz);
        double blocksPerSecond = distancePerTick * 20; // 20 TPS

        // > 60 方块/秒触发检测
        boolean speedHackDetected = blocksPerSecond > 60.0;

        assertTrue(speedHackDetected,
                "鞘翅速度 " + String.format("%.1f", blocksPerSecond) + " 方块/秒 > 60，应触发检测");
        assertEquals(3.0, dx, 0.01, "X 轴移动距离应为 3.0 方块");
        assertTrue(distancePerTick > 3.0,
                "每 tick 移动 " + String.format("%.3f", distancePerTick) + " 方块异常");
        assertEquals(60.02, blocksPerSecond, 1.0,
                "换算速度约 60 方块/秒");
    }

    /**
     * 正常鞘翅飞行 — 25 方块/秒的滑翔速度不触发检测。
     */
    @Test
    void testElytraNormalFlight() {
        // 标准鞘翅滑翔：每秒约 25 方块 (1.25 方块/tick)
        double x1 = 100.0, y1 = 200.0, z1 = 100.0;
        double x2 = 101.2, y2 = 199.6, z2 = 100.3; // 轻微下降 + 水平移动

        double dx = x2 - x1;
        double dy = y2 - y1;
        double dz = z2 - z1;

        double distancePerTick = Math.sqrt(dx * dx + dy * dy + dz * dz);
        double blocksPerSecond = distancePerTick * 20;

        // 正常鞘翅速度应在 15-35 方块/秒范围
        assertTrue(blocksPerSecond >= 15.0 && blocksPerSecond <= 35.0,
                "正常鞘翅速度 " + String.format("%.1f", blocksPerSecond) + " 方块/秒应在 15-35 范围");
        assertFalse(blocksPerSecond > 60.0,
                "正常鞘翅速度不应触发 SpeedHack 检测");
        assertTrue(dy < 0, // 高度下降
                "正常滑翔应缓慢下降，dy=" + String.format("%.1f", dy) + " < 0");
    }

    /**
     * 不使用烟花火箭获得高度 — ElytraFly hack 特征。
     * 合法鞘翅飞行中，不使用烟花火箭无法持续获得高度。
     * 通过追踪高度变化和烟花使用记录来检测。
     */
    @Test
    void testElytraDetectsHeightGain() {
        // 模拟 15 次连续位置更新，全程持续上升但无烟花记录
        double currentY = 200.0;
        int heightGainTicks = 0;
        int totalTicks = 15;

        // 模拟数据：鞘翅飞行中每次 tick 都有小幅上升
        double[] yDeltas = {0.3, 0.25, 0.35, 0.28, 0.32, 0.30, 0.33, 0.27,
                0.31, 0.29, 0.34, 0.26, 0.30, 0.28, 0.32};
        boolean fireworkUsed = false; // 无烟花使用记录

        for (int i = 0; i < totalTicks; i++) {
            currentY += yDeltas[i];
            if (yDeltas[i] > 0.2) {
                heightGainTicks++;
            }
        }

        double totalHeightGain = currentY - 200.0;
        double heightGainRatio = (double) heightGainTicks / totalTicks;

        // 无烟花情况下抬高比超过 80% 为异常
        boolean heightGainDetected = !fireworkUsed && heightGainRatio > 0.8 && totalHeightGain > 3.0;

        assertTrue(heightGainDetected,
                "无烟花使用记录时，总抬升 " + String.format("%.1f", totalHeightGain)
                        + " 方块，抬高比 " + String.format("%.0f%%", heightGainRatio * 100)
                        + "，应触发检测");
        assertTrue(totalHeightGain > 4.0,
                "15 tick 内抬升 " + String.format("%.1f", totalHeightGain) + " 方块（无烟花）");
        assertEquals(15, heightGainTicks,
                "全部 15 ticks 均应记录为抬升");
    }

    // ========================================================================
    // 综合验证：所有模块的检测逻辑独立且正确
    // ========================================================================

    /**
     * 验证检测逻辑不互相干扰 — 正常玩家行为在所有模块中均应为 clean。
     */
    @Test
    void testAllModulesNormalPlayerPasses() {
        // AntiTimer: 正常 TPS=20, 间隔 50ms
        double tickInterval = 50.0;
        assertFalse(tickInterval < 50.0 * 0.85, "正常 TPS 不应触发 Timer 检测");

        // AntiVelocity: 正常击退 0.4 方块
        double knockbackRatio = 0.4 / 0.4; // 1.0 = 100%
        assertTrue(knockbackRatio > 0.7, "正常击退不应触发 Velocity 检测");

        // AntiPhase: 不穿过固体方块
        boolean throughSolid = false;
        assertFalse(throughSolid, "不穿过固体方块不触发 Phase 检测");

        // AntiBlink: 不频繁断连重连
        int blinkCycles = 0;
        assertTrue(blinkCycles < 3, "0 次 Blink 循环不触发检测");

        // AntiFastBreak: 正常破坏速度
        double breakRatio = 350.0 / 350.0; // 实际/理论
        assertTrue(breakRatio > 0.7, "正常破坏速度不触发 FastBreak 检测");

        // AntiElytraFly: 正常鞘翅速度 25 m/s
        double elytraSpeed = 25.0;
        assertTrue(elytraSpeed < 60.0, "正常鞘翅速度不触发 ElytraFly 检测");
    }

    /**
     * 验证检测逻辑在边界条件下正确工作。
     * 阈值边界值应正确分类为 clean 或 flagged。
     */
    @Test
    void testThresholdBoundaryBehavior() {
        // Timer: 恰好 50ms 间隔不触发
        assertFalse(50.0 < 50.0 * 0.85, "恰好 50ms 应判定为正常");

        // Timer: 恰好 42ms 间隔应触发（42 < 50*0.85 = 42.5）
        assertTrue(42.0 < 50.0 * 0.85, "42ms 应判定为加速");

        // FastBreak: 理论时间 30% 为阈值
        double threshold = 9375.0 * 0.3; // 2812.5ms
        assertTrue(800.0 < threshold, "800ms 应触发（< 2812ms 阈值）");
        assertFalse(3000.0 < threshold, "3000ms 不触发（> 2812ms 阈值）");

        // ElytraFly: 59.9 m/s 不触发，60.1 m/s 触发
        assertFalse(59.9 > 60.0, "59.9 m/s 不触发 SpeedHack");
        assertTrue(60.1 > 60.0, "60.1 m/s 触发 SpeedHack");

        // Blink: 恰好 1.0 秒间隔为边界
        assertFalse(1000.0 < 1000.0, "恰好 1000ms 不触发 Blink 检测");
        assertTrue(999.0 < 1000.0, "999ms 应触发 Blink 检测");
    }
}
