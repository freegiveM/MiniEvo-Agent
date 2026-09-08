"""闭环第三处断点：影子证据攒够之后，谁来判决晋升。

## 钉住的缺口

`stage_shadow` 把候选放上影子流量，`observe_shadow` 逐条记录观测——然后就
没有了。在 `evaluate_promotion` 之前，全代码库唯一的晋升路径是
`record_shadow_observation` 里的 `auto_promote` 分支，而 `stage_shadow` 刻意
把 `auto_promote` 设成 False。于是候选**上得去、下不来**：影子证据攒够之后
没有任何基于证据的判决，只能靠人手动打开 `auto_promote`——那恰恰是"让分歧率
独自决定上线"，正是设计 `stage_shadow` 时明确拒绝的做法。

## 这批测试里最要紧的一条

`test_a_silent_candidate_is_not_promoted`：候选和基线**一起漏掉同一批问题**
时，分歧率是 0.0，完美通过任何"分歧率 ≤ 阈值"的门禁。如果晋升只看分歧率，
这个什么都没做的候选会被自动上线。低分歧率只能当否决条件，不能当通过条件。
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
        self.store.save_skill_version("llm-review", "prompt v1", 0.5, True)
        self.store.save_skill_version("llm-review", "prompt v2", 0.7, False)

    def tearDown(self):
        if os.path.exists(self.path):
            os.unlink(self.path)

    def _stage(self, candidate_version=2, min_samples=5):
        self.store.save_deployment("tenant", "llm-review", {
            "canary_percent": 0, "shadow_percent": 100,
            "candidate_version": candidate_version, "stable_version": 1,
            "status": "running", "min_samples": min_samples,
        })

    def _observe(self, count, primary_keys, candidate_keys, failed=False,
                 prefix="task"):
        for index in range(count):
            self.releases.observe_shadow(
                "tenant", "llm-review", "%s-%s" % (prefix, index), "stable",
                {"finding_keys": list(primary_keys)},
                {"finding_keys": list(candidate_keys)},
                candidate_failed=failed,
            )


class EvidenceAttributionTests(_Base):
    def test_observations_are_attributed_to_the_current_candidate(self):
        self._stage(candidate_version=2)
        self._observe(3, ["a.py:1:R1"], ["a.py:1:R1", "a.py:2:R2"])

        evidence = self.store.summarise_shadow_evidence("tenant", "llm-review", 2)
        self.assertEqual(3, evidence["samples"])
        self.assertEqual(3, evidence["candidate_wins"])

    def test_a_previous_candidates_evidence_does_not_count(self):
        """核心隔离断言。

        `save_deployment` 只清零 deployments 上的计数器，
        release_observations 的历史行是留着的。不按 candidate_version 过滤，
        上一个候选的观测就会被算进新候选的晋升证据里，而且报告上看不出来。
        """
        self._stage(candidate_version=2)
        self._observe(5, ["a.py:1:R1"], ["a.py:1:R1", "a.py:2:R2"])
        self._stage(candidate_version=3)

        self.assertEqual(
            0, self.store.summarise_shadow_evidence("tenant", "llm-review", 3)["samples"])
        # 旧证据仍然查得到，只是归在旧候选名下。
        self.assertEqual(
            5, self.store.summarise_shadow_evidence("tenant", "llm-review", 2)["samples"])

    def test_disagreement_direction_is_recorded_separately(self):
        """对称分歧率分不出"候选多报了"和"候选漏掉了基线报过的"。

        这两者风险相反：前者可能是候选更强（也可能是误报），后者是能力退化。
        只存一个对称标量，晋升判决就没有依据区分它们。
        """
        self._stage()
        self._observe(2, ["a.py:1:R1"], ["a.py:1:R1", "a.py:2:R2"], prefix="win")
        self._observe(3, ["b.py:1:R1", "b.py:2:R2"], ["b.py:1:R1"], prefix="loss")

        evidence = self.store.summarise_shadow_evidence("tenant", "llm-review", 2)
        self.assertEqual(2, evidence["candidate_wins"])
        self.assertEqual(3, evidence["candidate_losses"])

    def test_rates_are_none_when_there_are_no_samples(self):
        """分母为 0 时返回 None，不是 0.0。

        0.0 会直接满足"≤ 阈值"，把"一个样本都没有"伪装成"测过了，很干净"。
        """
        evidence = self.store.summarise_shadow_evidence("tenant", "llm-review", 2)
        self.assertEqual(0, evidence["samples"])
        self.assertIsNone(evidence["disagreement_rate"])
        self.assertIsNone(evidence["failure_rate"])


class PromotionDecisionTests(_Base):
    def test_a_silent_candidate_is_not_promoted(self):
        """**本轨道最要紧的断言。**

        候选和基线一起漏掉同一批问题时分歧率是 0.0，完美通过任何
        "分歧率 ≤ 阈值"的门禁。如果晋升只看分歧率，这个什么都没做的候选
        会被自动上线。低分歧率只能当否决条件，不能当通过条件。
        """
        self._stage(min_samples=5)
        self._observe(10, ["a.py:1:R1"], ["a.py:1:R1"])

        result = self.releases.evaluate_promotion("tenant", "llm-review")

        self.assertEqual("insufficient_evidence", result["decision"])
        self.assertFalse(result["promoted"])
        self.assertEqual(0.0, result["evidence"]["disagreement_rate"])
        # 理由必须点出这个混淆，否则读者会以为"分歧率 0"是好事。
        self.assertIn("missed the same issues", result["reason"])
        self.assertEqual(
            "running", self.store.get_deployment("tenant", "llm-review")["status"])

    def test_a_candidate_that_wins_is_promoted(self):
        self._stage(min_samples=5)
        self._observe(6, ["a.py:1:R1"], ["a.py:1:R1", "a.py:2:R2"])

        result = self.releases.evaluate_promotion("tenant", "llm-review")

        self.assertEqual("promote", result["decision"])
        self.assertTrue(result["promoted"])
        self.assertEqual("promoted", result["deployment"]["status"])
        self.assertEqual(2, result["deployment"]["stable_version"])

    def test_promotion_syncs_the_active_skill_version(self):
        """否则 evolution.py 下一次读到的基线与线上服务的不是同一个东西。"""
        self._stage(min_samples=5)
        self._observe(6, ["a.py:1:R1"], ["a.py:1:R1", "a.py:2:R2"])
        self.releases.evaluate_promotion("tenant", "llm-review")

        self.assertEqual(
            2, self.store.get_active_skill_version("llm-review")["version"])

    def test_promotion_does_not_erase_the_evidence_it_used(self):
        """用增量 UPDATE 而不是 save_deployment。

        后者会把 shadow_samples/disagreements 清零——晋升时清零等于把刚刚
        用来做决定的那批证据擦掉，事后无法复核这次晋升凭什么发生。
        """
        self._stage(min_samples=5)
        self._observe(6, ["a.py:1:R1"], ["a.py:1:R1", "a.py:2:R2"])
        self.releases.evaluate_promotion("tenant", "llm-review")

        deployment = self.store.get_deployment("tenant", "llm-review")
        self.assertEqual(6, deployment["shadow_samples"])
        self.assertEqual(
            6, self.store.summarise_shadow_evidence("tenant", "llm-review", 2)["samples"])

    def test_insufficient_samples_is_not_a_rejection(self):
        """三态的意义：把"没测够"和"测了不合格"合成同一个 False，会让一个
        还没攒够样本的候选看起来像是被否决过。
        """
        self._stage(min_samples=20)
        self._observe(3, ["a.py:1:R1"], ["a.py:1:R1", "a.py:2:R2"])

        result = self.releases.evaluate_promotion("tenant", "llm-review")

        self.assertEqual("insufficient_evidence", result["decision"])
        self.assertIn("20", result["reason"])

    def test_a_high_disagreement_rate_is_rejected(self):
        self._stage(min_samples=5)
        self._observe(6, ["a.py:1:R1"], ["b.py:9:R9"])

        result = self.releases.evaluate_promotion("tenant", "llm-review")

        self.assertEqual("reject", result["decision"])
        self.assertIn("lost baseline findings", result["reason"])
        self.assertEqual(
            "running", self.store.get_deployment("tenant", "llm-review")["status"])

    def test_only_the_regression_direction_vetoes(self):
        """对称分歧率不能当否决条件。

        一个每次都多报一条问题、一条基线发现都没漏的候选，对称分歧率是
        1.00——远超默认阈值 0.20。如果门禁看对称分歧率，这个候选会被当成
        退化拦下，而它的行为恰恰是"只增不减"。门禁必须看 loss_rate。
        """
        self._stage(min_samples=5)
        self._observe(6, ["a.py:1:R1"], ["a.py:1:R1", "a.py:2:R2"])

        evidence = self.store.summarise_shadow_evidence("tenant", "llm-review", 2)
        self.assertEqual(1.0, evidence["disagreement_rate"])
        self.assertEqual(0.0, evidence["loss_rate"])
        self.assertEqual(
            "promote",
            self.releases.evaluate_promotion("tenant", "llm-review")["decision"])

    def test_candidate_failures_are_rejected(self):
        """候选在影子期崩过，就不该上线——哪怕分歧率漂亮。"""
        self._stage(min_samples=5)
        self._observe(6, ["a.py:1:R1"], ["a.py:1:R1", "a.py:2:R2"], failed=True)

        result = self.releases.evaluate_promotion("tenant", "llm-review")

        self.assertEqual("reject", result["decision"])
        self.assertIn("failed", result["reason"])

    def test_a_canary_error_budget_breach_blocks_promotion(self):
        """金丝雀错误预算与影子分歧率是两道独立的门。"""
        self._stage(min_samples=5)
        self._observe(6, ["a.py:1:R1"], ["a.py:1:R1", "a.py:2:R2"])
        # 直接写计数器：走 record_deployment_result 会先触发自动回滚，
        # 那样测到的是回滚而不是这道门。
        self.store.save_deployment("tenant", "llm-review", {
            "canary_percent": 10, "shadow_percent": 100, "candidate_version": 2,
            "stable_version": 1, "status": "running", "min_samples": 5,
        })
        for index in range(4):
            self.store.record_deployment_result("tenant", "llm-review", index < 3)

        result = self.releases.evaluate_promotion("tenant", "llm-review")
        self.assertEqual("reject", result["decision"])
        self.assertIn("error budget", result["reason"])

    def test_a_rolled_back_deployment_is_not_promoted(self):
        self._stage(min_samples=5)
        self._observe(6, ["a.py:1:R1"], ["a.py:1:R1", "a.py:2:R2"])
        self.store.save_deployment("tenant", "llm-review", {
            "canary_percent": 0, "shadow_percent": 0, "candidate_version": 2,
            "stable_version": 1, "status": "rolled_back",
        })

        result = self.releases.evaluate_promotion("tenant", "llm-review")
        self.assertEqual("insufficient_evidence", result["decision"])
        self.assertIn("rolled_back", result["reason"])

    def test_no_deployment_is_not_an_error(self):
        result = self.releases.evaluate_promotion("tenant", "llm-review")
        self.assertEqual("insufficient_evidence", result["decision"])
        self.assertIsNone(result["evidence"])

    def test_promotion_is_not_repeatable(self):
        """晋升后部署不再 running，第二次调用不该再晋升一次。"""
        self._stage(min_samples=5)
        self._observe(6, ["a.py:1:R1"], ["a.py:1:R1", "a.py:2:R2"])
        self.assertEqual(
            "promote",
            self.releases.evaluate_promotion("tenant", "llm-review")["decision"])
        self.assertEqual(
            "insufficient_evidence",
            self.releases.evaluate_promotion("tenant", "llm-review")["decision"])

    def test_the_promotion_reason_states_that_wins_are_unlabelled(self):
        """候选独有的发现也可能是误报——影子期没有人工标注无法区分。

        把它表述成"候选更准"是在把一个弱信号包装成结论。
        """
        self._stage(min_samples=5)
        self._observe(6, ["a.py:1:R1"], ["a.py:1:R1", "a.py:2:R2"])

        result = self.releases.evaluate_promotion("tenant", "llm-review")
        self.assertIn("not confirmed true positives", result["reason"])

    def test_min_wins_is_configurable(self):
        self._stage(min_samples=5)
        self._observe(5, ["a.py:1:R1"], ["a.py:1:R1"], prefix="quiet")
        self._observe(1, ["b.py:1:R1"], ["b.py:1:R1", "b.py:2:R2"], prefix="win")

        self.assertEqual(
            "insufficient_evidence",
            self.releases.evaluate_promotion(
                "tenant", "llm-review", min_wins=2)["decision"])
        self.assertEqual(
            "promote",
            self.releases.evaluate_promotion(
                "tenant", "llm-review", min_wins=1)["decision"])

    def test_tenants_are_isolated(self):
        self._stage(min_samples=5)
        self._observe(6, ["a.py:1:R1"], ["a.py:1:R1", "a.py:2:R2"])

        result = self.releases.evaluate_promotion("other-tenant", "llm-review")
        self.assertEqual("insufficient_evidence", result["decision"])


class PromoteDeploymentGuardTests(_Base):
    def test_promoting_a_stale_candidate_version_is_refused(self):
        """判决与写回之间若有人换了候选，就会把 A 的证据用到 B 的晋升上。"""
        self._stage(candidate_version=2, min_samples=5)
        self.assertIsNone(
            self.store.promote_deployment("tenant", "llm-review", 99))
        self.assertEqual(
            "running", self.store.get_deployment("tenant", "llm-review")["status"])

    def test_promoting_a_non_running_deployment_is_refused(self):
        self.store.save_deployment("tenant", "llm-review", {
            "canary_percent": 0, "shadow_percent": 0, "candidate_version": 2,
            "stable_version": 1, "status": "rolled_back",
        })
        self.assertIsNone(
            self.store.promote_deployment("tenant", "llm-review", 2))


if __name__ == "__main__":
    unittest.main()