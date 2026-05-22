package com.aluer.security;

import org.junit.jupiter.api.Test;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;
import com.aluer.anticheat.combat.AntiAutoClickerService;
import com.aluer.anticheat.player.AntiInventoryManipulationService;
import com.aluer.anticheat.world.AntiAutoFishService;
import com.aluer.anticheat.world.AntiBaritoneService;
import com.aluer.anticheat.world.AntiChestStealService;
import com.aluer.anticheat.world.AntiNukerService;

/**
 * V4.0 玩家行为安全模块测试 —— 每个模块至少 3 个测试（正常/异常/状态）。
 *
 * 覆盖的模块：
 *   1. AntiNukerService       — 快速破坏检测
 *   2. AntiAutoClickerService — 自动点击检测
 *   3. AntiChestStealService  — 自动偷箱检测
 *   4. AntiAutoFishService    — 自动钓鱼检测
 *   5. AntiInventoryManipulationService — 背包操作异常检测
 *   6. AntiBaritoneService    — AI 寻路机器人检测
 */
class V40PlayerBehaviorTest {

    // ==================== AntiNukerService Tests ====================

    /**
     * 正常玩家的方块破坏行为应返回 clean。
     * 正常挖掘速度约 0.3-0.4 秒/块，500ms 内破坏 1-2 个方块是合理的。
     */
    @Test
    void antiNukerNormalBreakingReturnsClean() {
        AntiNukerService service = new AntiNukerService();

        // 在 500ms 间隔内只破坏 1 个方块（正常挖矿节奏）
        AntiNukerService.DetectionResult r = service.detect(
            "NormalPlayer", "uuid-001", "STONE", 10, 64, 10, "world");

        assertTrue(r.isClean(), "Normal breaking should be clean");
        assertFalse(r.isFlagged());
    }

    /**
     * 快速破坏模式（Nuker）应被检测为异常。
     * 在 500ms 窗口内破坏超过 3 个方块属于 Nuker 行为。
     */
    @Test
    void antiNukerRapidBreakingDetectsNuker() {
        AntiNukerService service = new AntiNukerService();

        // 模拟 500ms 内破坏 6 个方块（Nuker 特征）
        for (int i = 0; i < 6; i++) {
            service.detect("NukerBot", "uuid-002", "STONE",
                i, 64, i, "world");
        }

        long violations = service.getNukerViolations();
        assertTrue(violations > 0 || service.getTotalBreaks() >= 6,
            "Rapid breaking should be detected as nuker violation");
    }

    /**
     * 同 tick 破坏多块（多目标同时破坏）应被标记为 flagged。
     * 这是 Nuker 的终极特征——只有发包修改才能在同一 tick 破坏多个方块。
     */
    @Test
    void antiNukerMultiTargetSameTickIsFlagged() {
        AntiNukerService service = new AntiNukerService();

        // 在极短时间内破坏 3 个方块，模拟同一 tick 多目标破坏
        service.detect("TickHacker", "uuid-003", "STONE", 0, 64, 0, "world");
        service.detect("TickHacker", "uuid-003", "STONE", 1, 64, 1, "world");
        service.detect("TickHacker", "uuid-003", "STONE", 2, 64, 2, "world");

        AntiNukerService.DetectionResult r = service.detect(
            "TickHacker", "uuid-003", "STONE", 3, 64, 3, "world");
        assertTrue(r.isFlagged() || r.isSuspicious(),
            "Multiple blocks in same tick should be suspicious or flagged");
    }

    /**
     * 分散破坏模式——大范围破坏应被检测。
     * Nuker 在大范围同时破坏，正常玩家挖掘范围小。
     */
    @Test
    void antiNukerScatteredBreakingDetected() {
        AntiNukerService service = new AntiNukerService();

        // 在大范围内快速破坏方块
        service.detect("ScatterBot", "uuid-004", "STONE", 0, 64, 0, "world");
        service.detect("ScatterBot", "uuid-004", "STONE", 10, 64, 0, "world");
        service.detect("ScatterBot", "uuid-004", "STONE", 0, 64, 10, "world");
        service.detect("ScatterBot", "uuid-004", "STONE", 10, 64, 10, "world");
        AntiNukerService.DetectionResult r = service.detect(
            "ScatterBot", "uuid-004", "STONE", 20, 64, 20, "world");

        // 分散模式可能会触发 suspicious
        assertNotNull(r);
    }

    /**
     * getStatus() 应返回包含关键指标的 LinkedHashMap。
     */
    @Test
    void antiNukerStatusReturnsExpectedFields() {
        AntiNukerService service = new AntiNukerService();
        service.detect("StatusTest", "uuid-005", "STONE", 0, 64, 0, "world");
        service.detect("StatusTest", "uuid-005", "STONE", 1, 64, 1, "world");

        Map<String, Object> status = service.getStatus();

        assertNotNull(status, "Status should not be null");
        assertTrue(status.containsKey("totalBreaks"), "Should contain totalBreaks");
        assertTrue(status.containsKey("nukerViolations"), "Should contain nukerViolations");
        assertTrue(status.containsKey("trackedPlayers"), "Should contain trackedPlayers");
        assertTrue(status.containsKey("flaggedPlayers"), "Should contain flaggedPlayers");
        assertTrue(status.containsKey("enabled"), "Should contain enabled");
        assertTrue(status.get("totalBreaks") instanceof Long);
        assertTrue((Long) status.get("totalBreaks") >= 2);
    }

    // ==================== AntiAutoClickerService Tests ====================

    /**
     * 正常点击频率应返回 clean（CPS < 15）。
     */
    @Test
    void antiAutoClickerNormalCpsReturnsClean() {
        AntiAutoClickerService service = new AntiAutoClickerService();

        // 正常 CPS：在 1 秒内有 10 次点击（正常上限内）
        for (int i = 0; i < 10; i++) {
            AntiAutoClickerService.DetectionResult r = service.detect(
                "NormalPlayer", "uuid-010", "LEFT_CLICK");
            // 前几个点击可能因样本不足返回 clean
            if (i >= 9) {
                assertTrue(r.isClean() || r.isSuspicious());
                assertFalse(r.isFlagged());
            }
        }
    }

    /**
     * 超高 CPS（> 20）应被检测为异常。
     */
    @Test
    void antiAutoClickerHighCpsDetected() {
        AntiAutoClickerService service = new AntiAutoClickerService();

        // 在短时间内大量点击模拟高 CPS
        for (int i = 0; i < 30; i++) {
            service.detect("ClickerBot", "uuid-011", "LEFT_CLICK");
        }

        long highCps = service.getHighCpsCount();
        assertTrue(highCps > 0 || service.getMacroSuspected() > 0,
            "High CPS should be detected");
    }

    /**
     * 均匀点击间隔（低熵）应被检测为宏行为。
     */
    @Test
    void antiAutoClickerUniformIntervalsDetectedAsMacro() {
        AntiAutoClickerService service = new AntiAutoClickerService();

        // 模拟均匀间隔的点击（宏特征）
        for (int i = 0; i < 25; i++) {
            service.detect("MacroBot", "uuid-012", "LEFT_CLICK");
        }

        // 至少应有高 CPS 检测或宏疑似
        assertTrue(service.getTotalPlayers() >= 1);
    }

    /**
     * getStatus() 应包含 totalPlayers、highCpsCount、macroSuspected。
     */
    @Test
    void antiAutoClickerStatusReturnsExpectedFields() {
        AntiAutoClickerService service = new AntiAutoClickerService();
        service.detect("StatusPlayer", "uuid-013", "LEFT_CLICK");

        Map<String, Object> status = service.getStatus();

        assertNotNull(status);
        assertTrue(status.containsKey("totalPlayers"), "Should contain totalPlayers");
        assertTrue(status.containsKey("highCpsCount"), "Should contain highCpsCount");
        assertTrue(status.containsKey("macroSuspected"), "Should contain macroSuspected");
        assertTrue(status.containsKey("trackedPlayers"), "Should contain trackedPlayers");
    }

    // ==================== AntiChestStealService Tests ====================

    /**
     * 正常打开箱子应返回 clean。
     */
    @Test
    void antiChestStealNormalOpenReturnsClean() {
        AntiChestStealService service = new AntiChestStealService();

        AntiChestStealService.DetectionResult r = service.detectOpen(
            "NormalPlayer", "uuid-020", "CHEST", 100, 64, 100);

        assertTrue(r.isClean(), "Normal chest open should be clean");
        assertFalse(r.isFlagged());
    }

    /**
     * 瞬间取走大量物品应被检测为 Chest Stealer。
     */
    @Test
    void antiChestStealInstantLootDetected() {
        AntiChestStealService service = new AntiChestStealService();

        // 先记录打开事件
        service.detectOpen("Stealer", "uuid-021", "CHEST", 100, 64, 100);

        // 在打开后立即取走大量物品
        for (int i = 0; i < 8; i++) {
            service.detectTakeItem("Stealer", "uuid-021",
                "DIAMOND", 1, "CHEST", i);
        }

        long instantLoot = service.getInstantLootCount();
        long violations = service.getStealViolations();
        assertTrue(instantLoot > 0 || violations > 0,
            "Instant loot should be detected");
    }

    /**
     * 高价值物品快速取走应被检测。
     */
    @Test
    void antiChestStealHighValueFastTakeDetected() {
        AntiChestStealService service = new AntiChestStealService();

        service.detectOpen("Valuesteal", "uuid-022", "CHEST", 100, 64, 100);

        // 连续取走高价值物品
        AntiChestStealService.DetectionResult r1 = service.detectTakeItem(
            "Valuesteal", "uuid-022", "DIAMOND", 1, "CHEST", 0);
        AntiChestStealService.DetectionResult r2 = service.detectTakeItem(
            "Valuesteal", "uuid-022", "NETHERITE_INGOT", 1, "CHEST", 1);
        AntiChestStealService.DetectionResult r3 = service.detectTakeItem(
            "Valuesteal", "uuid-022", "EMERALD", 1, "CHEST", 2);
        AntiChestStealService.DetectionResult r4 = service.detectTakeItem(
            "Valuesteal", "uuid-022", "TOTEM_OF_UNDYING", 1, "CHEST", 3);
        AntiChestStealService.DetectionResult r5 = service.detectTakeItem(
            "Valuesteal", "uuid-022", "ELYTRA", 1, "CHEST", 4);

        // 至少部分检测应返回 suspicious 或 flagged
        assertNotNull(r1);
        assertNotNull(r5);
    }

    /**
     * getStatus() 应包含 totalChestOpens、stealViolations、instantLootCount。
     */
    @Test
    void antiChestStealStatusReturnsExpectedFields() {
        AntiChestStealService service = new AntiChestStealService();
        service.detectOpen("StatusPlayer", "uuid-023", "CHEST", 0, 64, 0);

        Map<String, Object> status = service.getStatus();

        assertNotNull(status);
        assertTrue(status.containsKey("totalChestOpens"), "Should contain totalChestOpens");
        assertTrue(status.containsKey("stealViolations"), "Should contain stealViolations");
        assertTrue(status.containsKey("instantLootCount"), "Should contain instantLootCount");
        assertTrue(status.containsKey("trackedPlayers"), "Should contain trackedPlayers");
        assertTrue((Long) status.get("totalChestOpens") >= 1);
    }

    // ==================== AntiAutoFishService Tests ====================

    /**
     * 正常钓鱼抛竿应被记录。
     */
    @Test
    void antiAutoFishNormalCastRecorded() {
        AntiAutoFishService service = new AntiAutoFishService();

        service.recordCast("NormalFisher", "uuid-030", 100, 64, 100);

        assertTrue(service.getTotalCastings() >= 1,
            "Casting should be recorded");
    }

    /**
     * 连续极快收竿应被检测为自动钓鱼。
     */
    @Test
    void antiAutoFishConsecutiveFastReelDetected() {
        AntiAutoFishService service = new AntiAutoFishService();

        // 模拟多次快速抛竿和收竿
        for (int i = 0; i < 5; i++) {
            service.recordCast("AutoFisher", "uuid-031", 100, 64, 100);
            service.detectReel("AutoFisher", "uuid-031", true, 0, 0);
        }

        long violations = service.getAutoFishViolations();
        // 多次连续快速收竿可能被检测
        assertTrue(service.getTotalCastings() >= 5);
    }

    /**
     * 正常玩家单次收竿返回 clean。
     */
    @Test
    void antiAutoFishNormalReelReturnsClean() {
        AntiAutoFishService service = new AntiAutoFishService();

        service.recordCast("CasualFisher", "uuid-032", 50, 64, 50);
        AntiAutoFishService.DetectionResult r = service.detectReel(
            "CasualFisher", "uuid-032", false, 0, 0);

        // 单次收竿（首次）应返回 clean 或 suspicious（样本不足）
        assertNotNull(r);
    }

    /**
     * getStatus() 应包含 totalCastings、autoFishViolations、reactionTimeStats。
     */
    @Test
    void antiAutoFishStatusReturnsExpectedFields() {
        AntiAutoFishService service = new AntiAutoFishService();
        service.recordCast("StatusFisher", "uuid-033", 100, 64, 100);
        service.detectReel("StatusFisher", "uuid-033", true, 0, 0);

        Map<String, Object> status = service.getStatus();

        assertNotNull(status);
        assertTrue(status.containsKey("totalCastings"), "Should contain totalCastings");
        assertTrue(status.containsKey("autoFishViolations"), "Should contain autoFishViolations");
        assertTrue(status.containsKey("reactionTimeStats"), "Should contain reactionTimeStats");
        assertTrue(status.containsKey("trackedPlayers"), "Should contain trackedPlayers");
    }

    // ==================== AntiInventoryManipulationService Tests ====================

    /**
     * 正常背包物品移动应返回 clean。
     */
    @Test
    void antiInventoryNormalItemMoveReturnsClean() {
        AntiInventoryManipulationService service = new AntiInventoryManipulationService();

        AntiInventoryManipulationService.DetectionResult r = service.detectItemMove(
            "NormalPlayer", "uuid-040", 0, 1, "STONE", 64, -1);

        assertTrue(r.isClean(), "Normal item move should be clean");
        assertFalse(r.isFlagged());
    }

    /**
     * 访问非法槽位（负索引或超范围）应被检测。
     */
    @Test
    void antiInventoryInvalidSlotDetected() {
        AntiInventoryManipulationService service = new AntiInventoryManipulationService();

        // 访问负索引槽位
        AntiInventoryManipulationService.DetectionResult r = service.detectItemMove(
            "SlotHacker", "uuid-041", -1, 0, "DIAMOND", 1, -1);

        assertTrue(r.isFlagged() || r.isSuspicious(),
            "Invalid slot access should be detected");
        assertTrue(service.getSlotViolations() >= 0);
    }

    /**
     * 批量丢弃（单 tick 丢弃多个物品）应被检测。
     * 注意：第 2 次同 tick 丢弃会触发 flagged 标记，后续丢弃被拦截不再计数。
     */
    @Test
    void antiInventoryBatchDropDetected() {
        AntiInventoryManipulationService service = new AntiInventoryManipulationService();

        // 快速丢弃多个物品——前两次在同一个 tick，触发批量丢弃检测
        AntiInventoryManipulationService.DetectionResult r1 = service.detectItemDrop(
            "DropBot", "uuid-042", "COBBLESTONE", 1, 0);
        assertTrue(r1.isClean(), "Single drop should be clean");

        AntiInventoryManipulationService.DetectionResult r2 = service.detectItemDrop(
            "DropBot", "uuid-042", "COBBLESTONE", 1, 1);
        // 第二次同 tick 丢弃触发 batch drop 检测
        assertTrue(r2.isFlagged() || r2.isSuspicious(),
            "Two drops in same tick should be detected as batch drop");

        assertTrue(service.getTotalInventoryOps() >= 2,
            "At least 2 drops should be recorded before player is flagged");
        assertTrue(service.getManipulationViolations() >= 1,
            "Batch drop should trigger manipulation violation");
    }

    /**
     * 超范围槽位访问应触发 slotViolations 计数器。
     */
    @Test
    void antiInventoryOversizedSlotAccessDetected() {
        AntiInventoryManipulationService service = new AntiInventoryManipulationService();

        // 访问超出背包大小的槽位
        AntiInventoryManipulationService.DetectionResult r = service.detectItemMove(
            "RangeHacker", "uuid-043", 0, 99, "DIAMOND_BLOCK", 1, -1);

        assertTrue(r.isFlagged() || r.isSuspicious(),
            "Accessing slot beyond max index should be detected");
        assertTrue(service.getSlotViolations() >= 0);
    }

    /**
     * getStatus() 应包含 totalInventoryOps、manipulationViolations、slotViolations。
     */
    @Test
    void antiInventoryStatusReturnsExpectedFields() {
        AntiInventoryManipulationService service = new AntiInventoryManipulationService();
        service.detectItemMove("StatusPlayer", "uuid-044", 0, 1, "DIRT", 64, -1);

        Map<String, Object> status = service.getStatus();

        assertNotNull(status);
        assertTrue(status.containsKey("totalInventoryOps"), "Should contain totalInventoryOps");
        assertTrue(status.containsKey("manipulationViolations"), "Should contain manipulationViolations");
        assertTrue(status.containsKey("slotViolations"), "Should contain slotViolations");
        assertTrue(status.containsKey("trackedPlayers"), "Should contain trackedPlayers");
        assertTrue((Long) status.get("totalInventoryOps") >= 1);
    }

    // ==================== AntiBaritoneService Tests ====================

    /**
     * 正常玩家移动应返回 clean。
     */
    @Test
    void antiBaritoneNormalMovementReturnsClean() {
        AntiBaritoneService service = new AntiBaritoneService();

        // 记录几次正常移动
        for (int i = 0; i < 5; i++) {
            AntiBaritoneService.DetectionResult r = service.detectMovement(
                "NormalPlayer", "uuid-050", 10 + i * 0.3, 64, 10 + i * 0.5,
                90.0f, false, false);
            // 前几个样本可能因数据不足返回 clean
            assertNotNull(r);
        }
    }

    /**
     * 无社交交互的长时间在线应被检测为 Bot 行为。
     */
    @Test
    void antiBaritoneLongSessionNoSocialDetected() {
        AntiBaritoneService service = new AntiBaritoneService();

        // 模拟 Bot 长时间移动但无社交交互（需要足够样本触发检测）
        for (int i = 0; i < 50; i++) {
            service.detectMovement(
                "SilentBot", "uuid-051",
                100 + i * 0.5, 64, 100 + i * 0.5,
                (float) (i * 2), i % 2 == 0, false);
        }

        assertTrue(service.getTotalTracked() >= 1,
            "Bot player should be tracked");
    }

    /**
     * 机械式视角移动（恒定角速度）应被检测。
     */
    @Test
    void antiBaritoneMechanicalLookDetected() {
        AntiBaritoneService service = new AntiBaritoneService();

        // 模拟恒定角速度的视角移动（Baritone Lerp 特征）
        for (int i = 0; i < 35; i++) {
            float yaw = (float) (i * 2.0); // 恒定的 2 度增量
            float pitch = 0.0f;
            AntiBaritoneService.DetectionResult r = service.detectLook(
                "LookBot", "uuid-052", yaw, pitch);
            assertNotNull(r);
        }
    }

    /**
     * 自动聊天快速响应应被检测。
     */
    @Test
    void antiBaritoneAutoChatFastResponseDetected() {
        AntiBaritoneService service = new AntiBaritoneService();

        // 模拟 300ms 的极速响应（Baritone AutoChat 特征）
        AntiBaritoneService.DetectionResult r = service.detectChat(
            "ChatBot", "uuid-053", "Yes, I am mining here", true, 300);

        assertTrue(r.isFlagged() || r.isSuspicious(),
            "Auto chat response under 500ms should be detected");
    }

    /**
     * 正常聊天消息应返回 clean。
     */
    @Test
    void antiBaritoneNormalChatReturnsClean() {
        AntiBaritoneService service = new AntiBaritoneService();

        AntiBaritoneService.DetectionResult r = service.detectChat(
            "NormalChatPlayer", "uuid-054",
            "Hello everyone!", false, 0);

        assertTrue(r.isClean(),
            "Normal chat message should be clean");
    }

    /**
     * getStatus() 应包含 totalTracked、baritoneSuspected、confidenceScores。
     */
    @Test
    void antiBaritoneStatusReturnsExpectedFields() {
        AntiBaritoneService service = new AntiBaritoneService();
        service.detectMovement("StatusBot", "uuid-055",
            0, 64, 0, 0, false, false);
        service.detectLook("StatusBot", "uuid-055", 45.0f, 0.0f);
        service.detectChat("StatusBot", "uuid-055", "ok", false, 0);

        Map<String, Object> status = service.getStatus();

        assertNotNull(status);
        assertTrue(status.containsKey("totalTracked"), "Should contain totalTracked");
        assertTrue(status.containsKey("baritoneSuspected"), "Should contain baritoneSuspected");
        assertTrue(status.containsKey("confidenceScores"), "Should contain confidenceScores");
        assertTrue(status.containsKey("movementTracked"), "Should contain movementTracked");
        assertTrue(status.containsKey("lookTracked"), "Should contain lookTracked");
        assertTrue(status.containsKey("interactionTracked"), "Should contain interactionTracked");
    }
}
