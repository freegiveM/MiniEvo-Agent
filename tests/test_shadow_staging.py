"""闭环最后一环：`shadow_ready` 之后由谁把候选放上影子流量。

## 钉住的缺口

`auto_propose` 的 LLM 路径固定走 `activation_policy="shadow"`，判决永远是
`shadow_ready`。在 `stage_shadow` 之前，**没有任何代码消费这个判决**——候选
要真上影子流量，得有人另外去查版本号、手动 POST 一次部署配置。于是"回放
门禁通过"和"开始收集影子证据"之间是断开的。这不是"少一个便利功能"，是
闭环在这里断第二次：前一段（消费账本）修的是"反馈进不去"，这一段修的是
"候选出不来"。

## 为什么守卫比接线本身更重要

`save_deployment` 会把 `samples/errors/shadow_samples/disagreements` 全部
重置为 0。自动接线若直接覆盖一个正在跑的部署，就擦掉了正在累积的错误
预算——而 `record_deployment_result` 的自动回滚门禁正是靠 `samples` 判断
的。那等于用一次自动化把一个安全机制静默解除，且事后从部署表上看不出
曾经有过证据。所以这批测试里关于"拒绝覆盖"的断言，比关于"能放上去"的
断言更要紧。
"""
import os
import tempfile
import unittest

from evoagent.rollout import ReleaseManager
from evoagent.store import create_store


class _Base(unittest.TestCase):
    def setUp(self):
        handle, self.path = tempfile.mkstemp(suffix=".db")
        os.close(handle)
        self.store = create_store("", self.path)
        self.releases = ReleaseManager(self.store)

    def tearDown(self):
        if os.path.exists(self.path):
            os.unlink(self.path)

    def _running(self, candidate_version=7, samples=15, errors=1):
        self.store.save_deployment("tenant", "llm-review", {
            "canary_percent": 10, "shadow_percent": 100,
            "candidate_version": candidate_version, "stable_version": 1,
            "status": "running", "min_samples": 20,
        })
        for index in range(samples):
            self.store.record_deployment_result(
                "tenant", "llm-review", index < errors)


class StagingTests(_Base):
    def test_a_gated_candidate_reaches_shadow_traffic(self):
        result = self.releases.stage_shadow("tenant", "llm-review", 5)

        self.assertTrue(result["staged"])
        self.assertEqual(5, result["deployment"]["candidate_version"])
        self.assertEqual(100, result["deployment"]["shadow_percent"])

    def test_canary_stays_zero(self):
        """影子是"跑但不采用输出"，金丝雀是"真的把结果给用户"。

        回放门禁通过只够上影子。让候选直接吃真实流量需要影子阶段的证据
        先攒够——把两步合成一步，就没有任何观测窗口了。
        """
        result = self.releases.stage_shadow("tenant", "llm-review", 5)
        self.assertEqual(0, result["deployment"]["canary_percent"])

    def test_auto_promote_is_off_unless_asked(self):
        """分歧率低也可能只是候选和基线一起漏了同一批问题。

        让"分歧率低"独自决定上线，是把一个弱信号当成了充分条件。
        """
        result = self.releases.stage_shadow("tenant", "llm-review", 5)
        self.assertEqual(0, result["deployment"]["auto_promote"])

        result = self.releases.stage_shadow(
            "tenant", "other-skill", 5, auto_promote=True)
        self.assertEqual(1, result["deployment"]["auto_promote"])

    def test_the_stable_version_defaults_to_the_active_one(self):
        self.store.save_skill_version("llm-review", "prompt v1", 0.5, True)
        result = self.releases.stage_shadow("tenant", "llm-review", 5)
        self.assertEqual(1, result["deployment"]["stable_version"])

    def test_staging_with_no_active_version_is_not_an_error(self):
        """第一轮：还没有任何上线版本。stable 为 None，不该炸。"""
        result = self.releases.stage_shadow("tenant", "llm-review", 5)
        self.assertTrue(result["staged"])
        self.assertIsNone(result["deployment"]["stable_version"])


class ClobberGuardTests(_Base):
    def test_a_running_deployment_with_a_different_candidate_is_not_overwritten(self):
        """核心断言：不擦掉正在累积的错误预算。

        覆盖会把 samples/errors 重置为 0，让一个刚要触发回滚的金丝雀重新
        变得"干净"——等于用一次自动化静默解除了自动回滚。
        """
        self._running(candidate_version=7, samples=15, errors=1)
        result = self.releases.stage_shadow("tenant", "llm-review", 9)

        self.assertFalse(result["staged"])
        self.assertFalse(result["clobbered"])
        # 证据还在，候选版本没被换掉。
        self.assertEqual(7, result["deployment"]["candidate_version"])
        self.assertEqual(15, result["deployment"]["samples"])
        self.assertEqual(1, result["deployment"]["errors"])

    def test_the_refusal_names_what_would_have_been_lost(self):
        """"拒绝了"无法行动；"版本 7 已经跑了 15 个样本"可以。"""
        self._running(candidate_version=7, samples=15, errors=1)
        result = self.releases.stage_shadow("tenant", "llm-review", 9)

        self.assertIn("7", result["reason"])
        self.assertIn("15", result["reason"])

    def test_restaging_the_same_candidate_is_idempotent(self):
        """重复调用不该重置证据。

        `auto_propose` 可能被反复触发；每次都重置影子样本数会让晋升门禁
        永远攒不够样本，而表面上一切正常。
        """
        self._running(candidate_version=7, samples=15, errors=1)
        result = self.releases.stage_shadow("tenant", "llm-review", 7)

        self.assertFalse(result["staged"])
        self.assertIn("already", result["reason"])
        self.assertEqual(15, result["deployment"]["samples"])

    def test_a_rolled_back_deployment_can_be_replaced(self):
        """已回滚的部署不再累积证据，覆盖它不丢任何东西。

        这道门禁挡的是"正在观测中"，不是"曾经存在过"——否则一次回滚会
        永久堵死这条通路，人必须手动清库才能继续。
        """
        self.store.save_deployment("tenant", "llm-review", {
            "canary_percent": 10, "shadow_percent": 100,
            "candidate_version": 7, "stable_version": 1,
            "status": "rolled_back",
        })
        result = self.releases.stage_shadow("tenant", "llm-review", 9)

        self.assertTrue(result["staged"])
        self.assertEqual(9, result["deployment"]["candidate_version"])

    def test_a_promoted_deployment_can_be_replaced(self):
        self.store.save_deployment("tenant", "llm-review", {
            "canary_percent": 10, "shadow_percent": 100,
            "candidate_version": 7, "stable_version": 1,
            "status": "promoted",
        })
        result = self.releases.stage_shadow("tenant", "llm-review", 9)
        self.assertTrue(result["staged"])

    def test_tenants_do_not_block_each_other(self):
        """部署是按 tenant 隔离的。一个 tenant 的观测不该挡住另一个。"""
        self._running(candidate_version=7)
        result = self.releases.stage_shadow("other-tenant", "llm-review", 9)
        self.assertTrue(result["staged"])


class ShadowPercentTests(_Base):
    def test_out_of_range_percentages_are_clamped(self):
        result = self.releases.stage_shadow(
            "tenant", "llm-review", 5, shadow_percent=500)
        self.assertEqual(100, result["deployment"]["shadow_percent"])

        result = self.releases.stage_shadow(
            "tenant", "other", 5, shadow_percent=-10)
        self.assertEqual(0, result["deployment"]["shadow_percent"])

    def test_shadow_traffic_actually_routes_to_the_candidate(self):
        """接线的终点检查：放上去之后 assignment 真的会命中影子。

        只断言部署表写对了还不够——那只证明配置落盘了，不证明流量真的
        会走到候选上。
        """
        self.releases.stage_shadow("tenant", "llm-review", 5)
        assignment = self.releases.assignment("tenant", "llm-review", "task-1")

        self.assertTrue(assignment["shadow"])
        # 影子不改变主链路：lane 仍是 stable，用户看到的还是上线版本。
        self.assertEqual("stable", assignment["lane"])


if __name__ == "__main__":
    unittest.main()