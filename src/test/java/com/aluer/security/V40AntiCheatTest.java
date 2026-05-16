package com.aluer.security;

import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;

/**
 * V4.0 反作弊扩展模块测试
 * 测试 6 个新增反作弊模块：AntiKillAura, AntiReach, AntiSpeed, AntiJesus, AntiNoFall, AntiScaffold
 *
 * 每个模块至少3个测试用例，覆盖正常行为、异常行为和 getStatus() 功能
 */
class V40AntiCheatTest {

    // ========================================================================
    // AntiKillAuraService 测试
    // ========================================================================

    /**
     * 正常攻击行为 — 攻击单一目标，角度有变化，距离在合理范围
     */
    @Test
    void killAuraNormalAttackReturnsClean() {
        AntiKillAuraService svc = new AntiKillAuraService();
        Instant now = Instant.now();

        // 连续攻击同一个目标
        AntiKillAuraService.KillAuraCheckResult r = null;
        for (int i = 0; i < 5; i++) {
            r = svc.detect("Player1", "uuid-1", "TargetA",
                    45.0 + i * 10, 10.0 + i * 2,
                    2.5, now.plusMillis(i * 500));
        }

        assertNotNull(r);
        assertTrue(r.isClean());
        assertFalse(r.isFlagged());
        assertFalse(r.isSuspicious());
    }

    /**
     * 短时间内攻击过多不同目标 — 应标记为可疑或flagged
     */
    @Test
    void killAuraRapidTargetSwitchDetected() {
        AntiKillAuraService svc = new AntiKillAuraService();
        Instant now = Instant.now();

        // 在3秒内切换5个不同目标 — 超过MAX_TARGET_SWITCHES(3)
        String[] targets = {"A", "B", "C", "D", "E"};
        AntiKillAuraService.KillAuraCheckResult lastResult = null;

        for (int i = 0; i < targets.length; i++) {
            lastResult = svc.detect("Player1", "uuid-1", targets[i],
                    45.0 + i * 3, 10.0,
                    2.5, now.plusMillis(i * 200));
        }

        assertNotNull(lastResult);
        assertTrue(lastResult.isSuspicious() || lastResult.isFlagged());
        assertFalse(lastResult.isClean());
    }

    /**
     * 攻击角度高度一致 — 模拟Aimbot（自动瞄准），应标记为flagged
     */
    @Test
    void killAuraAimbotAngleDetected() {
        AntiKillAuraService svc = new AntiKillAuraService();
        Instant now = Instant.now();

        AntiKillAuraService.KillAuraCheckResult lastResult = null;

        // 多次攻击角度几乎不变 — Aimbot特征
        for (int i = 0; i < 8; i++) {
            lastResult = svc.detect("Player2", "uuid-2", "Target1",
                    45.0 + (i * 0.5 % 1.0), // yaw几乎不变
                    10.0 + (i * 0.3 % 0.5),  // pitch几乎不变
                    2.0, now.plusMillis(i * 600));
        }

        assertNotNull(lastResult);
        // 角度一致性应被检测
        assertTrue(lastResult.isSuspicious() || lastResult.isFlagged());
    }

    /**
     * getStatus() 返回非空Map包含必要字段
     */
    @Test
    void killAuraGetStatusReturnsValidMap() {
        AntiKillAuraService svc = new AntiKillAuraService();
        svc.detect("P1", "u1", "T1", 45, 10, 2.0, Instant.now());

        Map<String, Object> status = svc.getStatus();
        assertNotNull(status);
        assertTrue(status.containsKey("totalChecks"));
        assertTrue(status.containsKey("flaggedCount"));
        assertTrue(status.containsKey("activeTrackedPlayers"));
        assertNotNull(status.get("totalChecks"));
        assertNotNull(status.get("flaggedCount"));
    }

    /**
     * 完美极限距离模式 — 多次在最大距离范围攻击
     */
    @Test
    void killAuraPerfectReachPatternDetected() {
        AntiKillAuraService svc = new AntiKillAuraService();
        Instant now = Instant.now();

        AntiKillAuraService.KillAuraCheckResult lastResult = null;

        // 多次在2.8-3.0精确距离攻击 — perfect reach
        for (int i = 0; i < 12; i++) {
            lastResult = svc.detect("Player3", "uuid-3", "TargetX",
                    30.0 + i * 5, 5.0,
                    2.9, // 接近极限距离
                    now.plusMillis(i * 400));
        }

        assertNotNull(lastResult);
        assertTrue(lastResult.isSuspicious() || lastResult.isFlagged());
    }

    // ========================================================================
    // AntiReachService 测试
    // ========================================================================

    /**
     * 正常攻击距离 — 3.0方块以内
     */
    @Test
    void reachNormalDistanceReturnsClean() {
        AntiReachService svc = new AntiReachService();
        Instant now = Instant.now();

        AntiReachService.ReachCheckResult r = svc.detect(
                "Player1", "uuid-1",
                0, 64, 0,
                0, 64, 2.5,
                2.5, now);

        assertNotNull(r);
        assertTrue(r.isClean());
        assertFalse(r.isFlagged());
    }

    /**
     * 绝对超距攻击 — 超过6.0方块，应标记为flagged
     */
    @Test
    void reachAbsoluteExceedDetected() {
        AntiReachService svc = new AntiReachService();
        Instant now = Instant.now();

        // 攻击距离超过6.0 — 绝对超距
        AntiReachService.ReachCheckResult r = svc.detect(
                "Hacker1", "uuid-h1",
                0, 64, 0,
                0, 64, 7.0,
                7.0, now);

        assertNotNull(r);
        assertTrue(r.isFlagged());
        assertTrue(r.getReasons().size() > 0);
    }

    /**
     * 可疑超距 — 超过3.8但不到6.0方块
     */
    @Test
    void reachSuspiciousDistanceDetected() {
        AntiReachService svc = new AntiReachService();
        Instant now = Instant.now();

        AntiReachService.ReachCheckResult r = svc.detect(
                "Player2", "uuid-2",
                0, 64, 0,
                0, 64, 4.5,
                4.5, now);

        assertTrue(r.isSuspicious() || r.isFlagged());
    }

    /**
     * 频繁超距攻击 — 多次超过阈值
     */
    @Test
    void reachFrequentViolationFlagged() {
        AntiReachService svc = new AntiReachService();
        Instant now = Instant.now();

        AntiReachService.ReachCheckResult lastResult = null;

        // 多次超过3.8可疑阈值
        for (int i = 0; i < 3; i++) {
            lastResult = svc.detect("Hacker2", "uuid-h2",
                    0, 64, 0,
                    0, 64, 4.0 + i * 0.2,
                    4.0 + i * 0.2, now.plusMillis(i * 200));
        }

        assertNotNull(lastResult);
        assertFalse(lastResult.isClean());
    }

    /**
     * getStatus() 返回有效状态Map
     */
    @Test
    void reachGetStatusReturnsValidMap() {
        AntiReachService svc = new AntiReachService();
        svc.detect("P1", "u1", 0, 64, 0, 0, 64, 2.0, 2.0, Instant.now());
        svc.detect("P1", "u1", 0, 64, 0, 0, 64, 7.0, 7.0, Instant.now());

        Map<String, Object> status = svc.getStatus();
        assertNotNull(status);
        assertTrue(status.containsKey("totalChecks"));
        assertTrue(status.containsKey("violations"));
        assertTrue(status.containsKey("recentViolations"));
        assertNotNull(status.get("totalChecks"));
    }

    // ========================================================================
    // AntiSpeedService 测试
    // ========================================================================

    /**
     * 正常步行速度 — 应返回clean
     */
    @Test
    void speedNormalWalkingReturnsClean() {
        AntiSpeedService svc = new AntiSpeedService();
        Instant now = Instant.now();

        // 模拟正常步行 ~4.0 m/s
        AntiSpeedService.SpeedCheckResult r = svc.detect(
                "Player1", "uuid-1",
                0, 64, 0,
                0.2, 64, 0.2,
                true, 0.05, now);

        assertNotNull(r);
        assertTrue(r.isClean());
    }

    /**
     * 持续超速 — 超过7.0 m/s超过1秒
     */
    @Test
    void speedSustainedOverspeedFlagged() {
        AntiSpeedService svc = new AntiSpeedService();
        Instant now = Instant.now();

        AntiSpeedService.SpeedCheckResult lastResult = null;

        // 持续超速，每次移动0.5方块，间隔50ms = 10 m/s
        for (int i = 0; i < 20; i++) {
            lastResult = svc.detect("Hacker1", "uuid-h1",
                    i * 0.5, 64, 0,
                    (i + 1) * 0.5, 64, 0,
                    true, 0.05, now.plusMillis(i * 50));
        }

        assertNotNull(lastResult);
        assertTrue(lastResult.isSuspicious() || lastResult.isFlagged());
    }

    /**
     * GroundSpoof检测 — 声称在地面但垂直速度异常
     */
    @Test
    void speedGroundSpoofDetected() {
        AntiSpeedService svc = new AntiSpeedService();
        Instant now = Instant.now();

        // onGround=true但Y轴有显著变化
        AntiSpeedService.SpeedCheckResult r = svc.detect(
                "Hacker2", "uuid-h2",
                0, 64, 0,
                0.2, 64.5, 0.2,
                true, 0.05, now);

        assertTrue(r.isSuspicious() || r.isFlagged());
    }

    /**
     * 机械性恒速模式 — 速度恒定
     */
    @Test
    void speedMechanicalPatternDetected() {
        AntiSpeedService svc = new AntiSpeedService();
        Instant now = Instant.now();

        AntiSpeedService.SpeedCheckResult lastResult = null;

        // 每次都以完全相同速度移动 — 机械性Speed hack
        for (int i = 0; i < 12; i++) {
            lastResult = svc.detect("Hacker3", "uuid-h3",
                    i * 0.3, 64, 0,
                    i * 0.3 + 0.3, 64, 0,
                    true, 0.05, now.plusMillis(i * 50));
        }

        assertNotNull(lastResult);
        assertTrue(lastResult.isSuspicious() || lastResult.isFlagged());
    }

    /**
     * getStatus() 返回包含统计信息的Map
     */
    @Test
    void speedGetStatusReturnsValidMap() {
        AntiSpeedService svc = new AntiSpeedService();
        svc.detect("P1", "u1", 0, 64, 0, 0.2, 64, 0.2, true, 0.05, Instant.now());
        svc.detect("P1", "u1", 0.2, 64, 0.2, 0.4, 64, 0.4, true, 0.05, Instant.now());

        Map<String, Object> status = svc.getStatus();
        assertNotNull(status);
        assertTrue(status.containsKey("totalSamples"));
        assertTrue(status.containsKey("speedViolations"));
        assertTrue(status.containsKey("averageSpeed"));
        assertTrue(status.containsKey("maxSpeed"));
    }

    // ========================================================================
    // AntiJesusService 测试
    // ========================================================================

    /**
     * 正常在水中游泳 — 不在液体表面行走
     */
    @Test
    void jesusNormalSwimmingReturnsClean() {
        AntiJesusService svc = new AntiJesusService();
        Instant now = Instant.now();

        // 玩家在水中（Y=61.5, 水面Y=63）— 正在下沉/游泳中
        AntiJesusService.JesusCheckResult r = svc.detect(
                "Player1", "uuid-1",
                61.5, 63.0,
                "WATER", false, true, now);

        assertNotNull(r);
        assertTrue(r.isClean());
    }

    /**
     * 水上行走 — 站在水面高度且声称在地面
     */
    @Test
    void jesusWalkingOnWaterSuspicious() {
        AntiJesusService svc = new AntiJesusService();
        Instant now = Instant.now();

        AntiJesusService.JesusCheckResult lastResult = null;

        // 连续站在水面上 — Jesus hack特征
        for (int i = 0; i < 5; i++) {
            lastResult = svc.detect("Hacker1", "uuid-h1",
                    63.1, 63.0,
                    "WATER", true, true, now.plusMillis(i * 500));
        }

        assertNotNull(lastResult);
        assertTrue(lastResult.isSuspicious() || lastResult.isFlagged());
    }

    /**
     * 持续水上行走超过1秒+抖动模式 — 双规则命中应标记为flagged
     */
    @Test
    void jesusSustainedWaterWalkingFlagged() {
        AntiJesusService svc = new AntiJesusService();
        Instant now = Instant.now();

        AntiJesusService.JesusCheckResult lastResult = null;

        // 持续站在水面上超过1秒 + 抖动振荡（触发双规则）
        double[] yValues = {63.0, 63.05, 62.95, 63.02, 62.98, 63.03, 62.97, 63.01, 63.04, 62.96};
        for (int i = 0; i < yValues.length; i++) {
            lastResult = svc.detect("Hacker2", "uuid-h2",
                    yValues[i], 63.0,
                    "WATER", true, true, now.plusMillis(i * 200));
        }

        assertNotNull(lastResult);
        assertTrue(lastResult.isFlagged());

        assertTrue(lastResult.getReasons().stream()
                .anyMatch(r -> r.contains("SUSTAINED_JESUS")));
    }

    /**
     * 抖动模式检测 — Y坐标在水面附近振荡
     */
    @Test
    void jesusJitterPatternDetected() {
        AntiJesusService svc = new AntiJesusService();
        Instant now = Instant.now();

        AntiJesusService.JesusCheckResult lastResult = null;

        // 模拟抖动：Y值在水面附近反复小幅变化
        double[] yValues = {63.0, 63.05, 62.95, 63.02, 62.98, 63.03, 62.97, 63.01};
        for (int i = 0; i < yValues.length; i++) {
            lastResult = svc.detect("Hacker3", "uuid-h3",
                    yValues[i], 63.0,
                    "WATER", true, true, now.plusMillis(i * 300));
        }

        assertNotNull(lastResult);
        assertTrue(lastResult.isSuspicious() || lastResult.isFlagged());
    }

    /**
     * getStatus() 返回有效状态Map
     */
    @Test
    void jesusGetStatusReturnsValidMap() {
        AntiJesusService svc = new AntiJesusService();
        svc.detect("P1", "u1", 62.0, 63.0, "WATER", false, true, Instant.now());

        Map<String, Object> status = svc.getStatus();
        assertNotNull(status);
        assertTrue(status.containsKey("totalChecks"));
        assertTrue(status.containsKey("jesusViolations"));
        assertTrue(status.containsKey("activeTrackedPlayers"));
    }

    // ========================================================================
    // AntiNoFallService 测试
    // ========================================================================

    /**
     * 正常坠落并受伤害 — 应返回clean
     */
    @Test
    void noFallNormalFallWithDamageReturnsClean() {
        AntiNoFallService svc = new AntiNoFallService();
        Instant now = Instant.now();

        // 记录从Y=80坠落
        svc.recordFallStart("Player1", "uuid-1", 80.0, "survival", now);
        // 著陆在Y=70，受到伤害
        AntiNoFallService.NoFallCheckResult r = svc.recordLanding(
                "Player1", "uuid-1", 70.0,
                true, 5.0,    // tookDamage=true
                false, false, false, false, false, false, // 无合法无伤害减免
                now.plusSeconds(2));

        assertNotNull(r);
        assertTrue(r.isClean());
    }

    /**
     * 短距离坠落不受伤 — 正常行为
     */
    @Test
    void noFallShortFallNoDamageNormal() {
        AntiNoFallService svc = new AntiNoFallService();
        Instant now = Instant.now();

        // 坠落不足3方块 — 不会产生伤害
        svc.recordFallStart("Player2", "uuid-2", 66.0, "survival", now);
        AntiNoFallService.NoFallCheckResult r = svc.recordLanding(
                "Player2", "uuid-2", 65.0,
                false, 0,
                false, false, false, false, false, false,
                now.plusMillis(500));

        assertNotNull(r);
        assertTrue(r.isClean());
    }

    /**
     * 高空坠落无伤害 — NoFall hack特征
     */
    @Test
    void noFallHighFallNoDamageFlagged() {
        AntiNoFallService svc = new AntiNoFallService();
        Instant now = Instant.now();

        // 从12方块高度坠落但不受伤 — 无合法理由
        svc.recordFallStart("Hacker1", "uuid-h1", 82.0, "survival", now);
        AntiNoFallService.NoFallCheckResult r = svc.recordLanding(
                "Hacker1", "uuid-h1", 70.0,
                false, 0,      // 没有受到伤害
                false, false, false, false, false, false,
                now.plusSeconds(3));

        assertNotNull(r);
        assertTrue(r.isSuspicious() || r.isFlagged());
    }

    /**
     * 合法无伤害 — 落入水中
     */
    @Test
    void noFallWaterLandingNoDamageIsLegitimate() {
        AntiNoFallService svc = new AntiNoFallService();
        Instant now = Instant.now();

        // 掉入水中 — 合法免疫摔落伤害
        svc.recordFallStart("Player3", "uuid-3", 80.0, "survival", now);
        AntiNoFallService.NoFallCheckResult r = svc.recordLanding(
                "Player3", "uuid-3", 62.0,
                false, 0,
                true,  // isInLiquid=true (水中)
                false, false, false, false, false,
                now.plusSeconds(2));

        // 落入水中是合法的无伤害情况，不应标记
        assertNotNull(r);
        assertTrue(r.isClean());
    }

    /**
     * 合法无伤害 — 鞘翅飞行
     */
    @Test
    void noFallElytraFlyingIsLegitimate() {
        AntiNoFallService svc = new AntiNoFallService();
        Instant now = Instant.now();

        // 鞘翅飞行期间不受伤 — 合法
        svc.recordFallStart("Player4", "uuid-4", 100.0, "survival", now);
        AntiNoFallService.NoFallCheckResult r = svc.recordLanding(
                "Player4", "uuid-4", 70.0,
                false, 0,
                false, false, false, false, false,
                true, // isElytraFlying=true
                now.plusSeconds(5));

        assertNotNull(r);
        assertTrue(r.isClean());
    }

    /**
     * 粘液块上无伤害 — 合法
     */
    @Test
    void noFallSlimeBlockLandingIsLegitimate() {
        AntiNoFallService svc = new AntiNoFallService();
        Instant now = Instant.now();

        // 落在粘液块上 — 合法免疫摔落伤害
        svc.recordFallStart("Player5", "uuid-5", 80.0, "survival", now);
        AntiNoFallService.NoFallCheckResult r = svc.recordLanding(
                "Player5", "uuid-5", 60.0,
                false, 0,
                false, true, // isOnSlimeBlock=true
                false, false, false, false,
                now.plusSeconds(2));

        assertNotNull(r);
        assertTrue(r.isClean());
    }

    /**
     * getStatus() 返回有效状态Map
     */
    @Test
    void noFallGetStatusReturnsValidMap() {
        AntiNoFallService svc = new AntiNoFallService();
        Instant now = Instant.now();

        svc.recordFallStart("P1", "u1", 80.0, "survival", now);
        svc.recordLanding("P1", "u1", 70.0, true, 5.0,
                false, false, false, false, false, false, now.plusSeconds(2));

        Map<String, Object> status = svc.getStatus();
        assertNotNull(status);
        assertTrue(status.containsKey("totalFalls"));
        assertTrue(status.containsKey("noFallViolations"));
        assertTrue(status.containsKey("falsePositives"));
    }

    // ========================================================================
    // AntiScaffoldService 测试
    // ========================================================================

    /**
     * 正常方块放置 — 间隔合理，角度正常
     */
    @Test
    void scaffoldNormalPlacementReturnsClean() {
        AntiScaffoldService svc = new AntiScaffoldService();
        Instant now = Instant.now();

        AntiScaffoldService.ScaffoldCheckResult r = svc.detect(
                "Player1", "uuid-1",
                10, 63, 10,
                180, 30,    // yaw=180, pitch=30（正常视角）
                false, true, "COBBLESTONE",
                now);

        assertNotNull(r);
        assertTrue(r.isClean());
    }

    /**
     * 高速连续放置 — 超过5方块/秒持续3秒
     */
    @Test
    void scaffoldRapidPlacementFlagged() {
        AntiScaffoldService svc = new AntiScaffoldService();
        Instant now = Instant.now();

        AntiScaffoldService.ScaffoldCheckResult lastResult = null;

        // 高速放置方块：每次间隔100ms = 10方块/秒
        for (int i = 0; i < 30; i++) {
            lastResult = svc.detect("Hacker1", "uuid-h1",
                    10 + i, 63, 10,
                    90, -85, // pitch=-85 (近乎垂直向下看)
                    true, true, "COBBLESTONE",
                    now.plusMillis(i * 100));
        }

        assertNotNull(lastResult);
        assertTrue(lastResult.isSuspicious() || lastResult.isFlagged());
    }

    /**
     * Scaffold角度检测 — 向下看并精确放置
     */
    @Test
    void scaffoldDownwardAngleAndPlacementPattern() {
        AntiScaffoldService svc = new AntiScaffoldService();
        Instant now = Instant.now();

        AntiScaffoldService.ScaffoldCheckResult lastResult = null;

        // 向下看 (pitch接近-90) + 脚下放置 — 典型Scaffold
        for (int i = 0; i < 10; i++) {
            lastResult = svc.detect("Hacker2", "uuid-h2",
                    10 + i, 63, 10,
                    0, -88,   // 几乎是正下方
                    true, true, "COBBLESTONE",
                    now.plusMillis(i * 150));
        }

        assertNotNull(lastResult);
        assertTrue(lastResult.isSuspicious() || lastResult.isFlagged());
    }

    /**
     * Safewalk检测 — 连续边缘放置
     */
    @Test
    void scaffoldSafewalkPattern() {
        AntiScaffoldService svc = new AntiScaffoldService();
        Instant now = Instant.now();

        AntiScaffoldService.ScaffoldCheckResult lastResult = null;

        // 大量在脚下放置方块（Safewalk行为）
        for (int i = 0; i < 20; i++) {
            lastResult = svc.detect("Hacker3", "uuid-h3",
                    10 + i, 63, 10,
                    90, -75,
                    true,  // isPlaceBelowPlayer=true（脚下放置）
                    false, "COBBLESTONE",
                    now.plusMillis(i * 80));
        }

        assertNotNull(lastResult);
        assertTrue(lastResult.isSuspicious() || lastResult.isFlagged());
    }

    /**
     * getStatus() 返回有效状态Map
     */
    @Test
    void scaffoldGetStatusReturnsValidMap() {
        AntiScaffoldService svc = new AntiScaffoldService();
        svc.detect("P1", "u1", 10, 63, 10, 180, 30,
                false, true, "STONE", Instant.now());
        svc.detect("P1", "u1", 11, 63, 10, 180, 32,
                false, true, "STONE", Instant.now());

        Map<String, Object> status = svc.getStatus();
        assertNotNull(status);
        assertTrue(status.containsKey("totalPlacements"));
        assertTrue(status.containsKey("scaffoldViolations"));
        assertTrue(status.containsKey("trackedBuilders"));
    }

    // ========================================================================
    // 模块关闭验证测试 — 通过直接创建带无参构造的服务实例测试
    // 无参构造函数使用 new ServerGuardConfig()，默认所有开关为true
    // 此处验证配置默认为true时服务正常执行检测
    // ========================================================================

    /**
     * All services instantiable and return clean for trivial inputs
     */
    @Test
    void allServicesInstantiableAndFunctional() {
        // 验证所有服务可通过无参构造实例化
        AntiKillAuraService killAura = new AntiKillAuraService();
        AntiReachService reach = new AntiReachService();
        AntiSpeedService speed = new AntiSpeedService();
        AntiJesusService jesus = new AntiJesusService();
        AntiNoFallService noFall = new AntiNoFallService();
        AntiScaffoldService scaffold = new AntiScaffoldService();

        assertNotNull(killAura);
        assertNotNull(reach);
        assertNotNull(speed);
        assertNotNull(jesus);
        assertNotNull(noFall);
        assertNotNull(scaffold);

        // 验证所有服务的 getStatus() 都可调用
        assertNotNull(killAura.getStatus());
        assertNotNull(reach.getStatus());
        assertNotNull(speed.getStatus());
        assertNotNull(jesus.getStatus());
        assertNotNull(noFall.getStatus());
        assertNotNull(scaffold.getStatus());
    }
}
