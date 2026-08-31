"""候选呈现顺序打乱、位置一致性复核，以及 per-role 真实成本。

## 打乱顺序解决的问题

`_merge` 按 (severity, path, line) 排序，于是 critic 每次都先看到 critical、
后看到 low。LLM 评审有已知的位置偏置（序列前部/末尾的条目更容易被接受），
固定顺序让这个偏置与 severity **系统性共线**：看起来像"critic 更信任高危
结论"，实际可能只是"critic 更信任第一条"。两者在报数上无法区分，结论却
完全相反。

打乱之后偏置仍在，但变成随机噪声而非系统偏差——加宽 CI，不伪造方向。

## per-role 成本解决的问题

原实现只用 Counter 数了每个角色调用几次。但 planner 输出一个 task_graph 与
critic 逐条评审全部候选，调用次数都是 1，token 差一个量级。"多角色贵多少"
是消融必须量化的代价，只报次数就答不了"砍掉哪个角色最划算"。
"""
import json
import unittest

from evoagent.agentic_core import ModeRouterReviewer
from evoagent.diff_parser import parse_unified_diff
from evoagent.evaluation_v2 import ProductArmReviewer, _role_cost_totals, _role_costs

from tests.test_arm_separation import (
    CORRECTNESS_FINDING,
    DIFF,
    SECURITY_FINDING,
    RoleAwareClient,
    _finding,
)


class PresentationOrderTests(unittest.TestCase):
    def test_the_order_is_shuffled_away_from_the_canonical_ranking(self):
        """严重度排序不能直接当呈现顺序，否则位置偏置与 severity 共线。"""
        order = ModeRouterReviewer._presentation_order(8, DIFF)
        self.assertEqual(sorted(order), list(range(8)))
        self.assertNotEqual(list(range(8)), order)

    def test_the_order_is_reproducible_for_the_same_diff(self):
        """评测必须可复算：同一个 PR 重跑两次要得到同一个顺序。"""
        self.assertEqual(
            ModeRouterReviewer._presentation_order(10, DIFF),
            ModeRouterReviewer._presentation_order(10, DIFF),
        )

    def test_different_diffs_get_different_orders(self):
        """跨 PR 独立——否则所有 PR 用同一个置换，等于换了个固定顺序。"""
        other = DIFF.replace("threshold", "limit")
        self.assertNotEqual(
            ModeRouterReviewer._presentation_order(10, DIFF),
            ModeRouterReviewer._presentation_order(10, other),
        )

    def test_a_single_candidate_is_a_no_op(self):
        self.assertEqual([0], ModeRouterReviewer._presentation_order(1, DIFF))
        self.assertEqual([], ModeRouterReviewer._presentation_order(0, DIFF))


class DecisionRemappingTests(unittest.TestCase):
    """判定按呈现位置返回，必须映射回规范下标。"""

    def test_decisions_are_mapped_back_through_the_order(self):
        order = [2, 0, 1]
        result = {"decisions": [
            {"finding_index": 0, "accepted": True},    # 呈现第 0 位 = 规范 2
            {"finding_index": 1, "accepted": False},   # 呈现第 1 位 = 规范 0
            {"finding_index": 2, "accepted": True},    # 呈现第 2 位 = 规范 1
        ]}
        mapped = ModeRouterReviewer._decisions_by_canonical_index(result, order)
        self.assertTrue(mapped[2]["accepted"])
        self.assertFalse(mapped[0]["accepted"])
        self.assertTrue(mapped[1]["accepted"])

    def test_an_out_of_range_position_is_dropped_rather_than_wrapping(self):
        """越界下标丢弃：环绕会把判定悄悄贴到别的 finding 上。"""
        mapped = ModeRouterReviewer._decisions_by_canonical_index(
            {"decisions": [{"finding_index": 99, "accepted": True}]}, [0, 1]
        )
        self.assertEqual({}, mapped)

    def test_a_non_numeric_index_is_ignored(self):
        mapped = ModeRouterReviewer._decisions_by_canonical_index(
            {"decisions": [{"finding_index": "abc", "accepted": True},
                           {"accepted": True}]}, [0, 1]
        )
        self.assertEqual({}, mapped)


class PositionConsistencyTests(unittest.TestCase):
    def test_a_stable_critic_scores_full_agreement(self):
        first = {0: {"accepted": True}, 1: {"accepted": False}}
        report = ModeRouterReviewer._position_consistency(first, dict(first), 2)
        self.assertEqual(1.0, report["agreement"])
        self.assertEqual([], report["flipped"])

    def test_a_flip_is_recorded_with_its_index(self):
        first = {0: {"accepted": True}, 1: {"accepted": True}}
        second = {0: {"accepted": True}, 1: {"accepted": False}}
        report = ModeRouterReviewer._position_consistency(first, second, 2)
        self.assertEqual(0.5, report["agreement"])
        self.assertEqual([1], report["flipped"])

    def test_a_missing_decision_counts_as_rejection_on_both_sides(self):
        """缺判定 = 未获批准，两侧一致地缺就是一致，不算翻转。"""
        report = ModeRouterReviewer._position_consistency({}, {}, 3)
        self.assertEqual(1.0, report["agreement"])

    def test_no_candidates_yields_none_not_perfect_agreement(self):
        """空集合上没有一致性可言——报 1.0 会让"没测"看起来像"完全稳定"。"""
        report = ModeRouterReviewer._position_consistency({}, {}, 0)
        self.assertIsNone(report["agreement"])
        self.assertEqual(0, report["candidates"])

    def test_the_note_says_it_measures_stability_not_correctness(self):
        """口径纪律：一致性高不等于判得对，字段说明必须写清。"""
        report = ModeRouterReviewer._position_consistency(
            {0: {"accepted": True}}, {0: {"accepted": True}}, 1
        )
        self.assertIn("not its correctness", report["note"])


class CriticPositionCheckWiringTests(unittest.TestCase):
    def test_the_check_is_off_by_default_so_cost_does_not_double(self):
        """默认关：反序复核让 critic 调用与 token 翻倍，不该线上常开。"""
        client = RoleAwareClient()
        reviewer = ProductArmReviewer("full-agentic", client, 4096, 40)
        reviewer.review(DIFF, parse_unified_diff(DIFF))
        self.assertEqual(1, client.calls.count("critic"))
        collaboration = reviewer._last_summary["collaboration"]
        self.assertEqual({}, collaboration["position_consistency"])

    def test_enabling_the_check_runs_the_critic_twice_and_reports_agreement(self):
        client = RoleAwareClient()
        reviewer = ProductArmReviewer(
            "full-agentic", client, 4096, 40, critic_position_check=True,
        )
        reviewer.review(DIFF, parse_unified_diff(DIFF))
        self.assertEqual(2, client.calls.count("critic"))
        consistency = reviewer._last_summary["collaboration"]["position_consistency"]
        # 桩按 rule_id 判定，与呈现顺序无关，所以一致性必须是满分。
        self.assertEqual(1.0, consistency["agreement"])
        self.assertEqual(3, consistency["candidates"])

    def test_a_position_sensitive_critic_is_caught(self):
        """这是这套机制存在的理由：只按位置判定的 critic 必须被抓出来。

        桩 critic 只接受"呈现顺序里的第一条"。真实模型不会这么极端，但
        方向一致——如果一致性指标对这种情况都报满分，它就是没用的指标。
        """
        class FirstOnlyCritic(RoleAwareClient):
            def complete_json(self, role, system, user, ledger=None, max_tokens=None):
                if role == "critic":
                    self.calls.append(role)
                    if ledger:
                        ledger.record_model(
                            role, self.provider, self.model,
                            {"prompt_tokens": 10, "completion_tokens": 5}, 1,
                        )
                    managed = json.loads(user)
                    task = json.loads(managed["task"])
                    return {"action": "final", "decisions": [
                        {"finding_index": index, "accepted": index == 0,
                         "objections": [], "confidence_adjustment": 0.0}
                        for index, _item in enumerate(task["candidates"])
                    ]}
                return super().complete_json(role, system, user, ledger, max_tokens)

        reviewer = ProductArmReviewer(
            "full-agentic", FirstOnlyCritic(), 4096, 40,
            critic_position_check=True,
        )
        reviewer.review(DIFF, parse_unified_diff(DIFF))
        consistency = reviewer._last_summary["collaboration"]["position_consistency"]
        self.assertLess(consistency["agreement"], 1.0)
        self.assertTrue(consistency["flipped"])

    def test_the_critic_still_sees_every_candidate_after_shuffling(self):
        """打乱不能丢候选——顺序变了，集合不能变。"""
        seen = []

        class RecordingCritic(RoleAwareClient):
            def complete_json(self, role, system, user, ledger=None, max_tokens=None):
                if role == "critic":
                    managed = json.loads(user)
                    task = json.loads(managed["task"])
                    seen.append([item["rule_id"] for item in task["candidates"]])
                return super().complete_json(role, system, user, ledger, max_tokens)

        reviewer = ProductArmReviewer(
            "full-agentic", RecordingCritic(), 4096, 40,
            critic_position_check=True,
        )
        reviewer.review(DIFF, parse_unified_diff(DIFF))
        self.assertEqual(2, len(seen))
        self.assertEqual(sorted(seen[0]), sorted(seen[1]))
        self.assertEqual(seen[0], list(reversed(seen[1])))
        # 呈现的 finding_index 是位置而非规范下标，否则打乱就白做了。
        self.assertIn(SECURITY_FINDING, seen[0])
        self.assertIn(CORRECTNESS_FINDING, seen[0])

    def test_the_rejection_still_lands_on_the_right_finding_after_shuffling(self):
        """端到端：桩 critic 否掉 SECURITY_FINDING，打乱后仍必须否掉它。

        这条最关键——映射写错的话，否决会贴到另一条 finding 上，而输出条数
        不变，从计数上完全看不出来。
        """
        reviewer = ProductArmReviewer("full-agentic", RoleAwareClient(), 4096, 40)
        findings = reviewer.review(DIFF, parse_unified_diff(DIFF))
        ids = [item.rule_id for item in findings]
        self.assertNotIn(SECURITY_FINDING, ids)
        self.assertIn(CORRECTNESS_FINDING, ids)


class RoleCostTests(unittest.TestCase):
    def test_tokens_and_duration_are_summed_per_role(self):
        log = [
            {"role": "planner", "input_tokens": 100, "output_tokens": 20,
             "duration_ms": 30, "ok": True},
            {"role": "critic", "input_tokens": 800, "output_tokens": 200,
             "duration_ms": 90, "ok": True},
            {"role": "critic", "input_tokens": 400, "output_tokens": 100,
             "duration_ms": 40, "ok": True},
        ]
        costs = _role_costs(log)
        self.assertEqual(120, costs["planner"]["total_tokens"])
        self.assertEqual(1500, costs["critic"]["total_tokens"])
        self.assertEqual(2, costs["critic"]["calls"])
        self.assertEqual(130, costs["critic"]["duration_ms"])

    def test_call_counts_alone_would_hide_the_cost_difference(self):
        """这就是原实现的问题：调用次数相同，token 差一个量级。"""
        log = [
            {"role": "planner", "input_tokens": 100, "output_tokens": 20,
             "duration_ms": 10, "ok": True},
            {"role": "critic", "input_tokens": 2000, "output_tokens": 500,
             "duration_ms": 200, "ok": True},
        ]
        costs = _role_costs(log)
        self.assertEqual(costs["planner"]["calls"], costs["critic"]["calls"])
        self.assertGreater(
            costs["critic"]["total_tokens"], 10 * costs["planner"]["total_tokens"]
        )

    def test_failed_calls_still_count_toward_cost_but_are_flagged(self):
        """失败调用同样烧钱、同样占墙上时间，排除掉会低估真实成本。"""
        costs = _role_costs([
            {"role": "security", "input_tokens": 500, "output_tokens": 0,
             "duration_ms": 60, "ok": False},
        ])
        self.assertEqual(500, costs["security"]["total_tokens"])
        self.assertEqual(1, costs["security"]["failed"])
        self.assertEqual(1, costs["security"]["calls"])

    def test_per_pr_averages_use_the_arm_case_count_as_denominator(self):
        """分母是这一臂跑过的 PR 总数，不是"该角色被调用过的 PR 数"。

        用后者会系统性高估单角色成本，还让不同角色分母不同、无法相加对照。
        """
        cases = [
            {"role_costs": {"critic": {"calls": 1, "failed": 0, "input_tokens": 800,
                                       "output_tokens": 200, "total_tokens": 1000,
                                       "duration_ms": 100}}},
            {"role_costs": {}},   # 这个 PR 没有候选，critic 没被调用
        ]
        report = _role_cost_totals(cases, 2)
        self.assertEqual(1000, report["critic"]["total_tokens"])
        self.assertEqual(500.0, report["critic"]["tokens_per_pr"])
        self.assertEqual(50.0, report["critic"]["duration_ms_per_pr"])

    def test_no_cases_reports_nothing_rather_than_zeros(self):
        """空分母口径与 _metrics 一致：不造零。"""
        self.assertEqual({}, _role_cost_totals([], 0))

    def test_the_arm_reports_real_per_role_cost_end_to_end(self):
        reviewer = ProductArmReviewer("full-agentic", RoleAwareClient(), 4096, 40)
        reviewer.review(DIFF, parse_unified_diff(DIFF))
        costs = _role_costs(reviewer.evaluation_execution()["model_call_log"])
        self.assertEqual(
            {"planner", "security", "correctness-reliability", "critic"},
            set(costs),
        )
        for role, values in costs.items():
            self.assertGreater(values["total_tokens"], 0, role)


if __name__ == "__main__":
    unittest.main()
