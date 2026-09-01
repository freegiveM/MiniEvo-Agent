"""门禁不通过时，要能分清"回退了"和"这一档测不出来"。

## 补的是什么

`launch_gate` / `critic_gate` 的 None 处理本身是安全的：`_not_worse` 与
`_ci_lower_positive` 都把 None 收成 False，方向对——无法验证不退化，就不能
当成没退化。

但报告里丢掉了区分。`passed: false` + `f1_gain: null` 和"候选真的比基线差"
长得一模一样。读的人分不清是能力不行，还是这一档根本没有样本。这在消融表
上是致命的：`full-agentic` 门禁没过，到底该去改 Critic，还是该去补数据？

新增 `unmeasurable` 清单，只列名字，**不改任何判定**。与
`comparison_summary` 的 `not_applicable_gates` 同一纪律。
"""
import unittest

from evoagent.evaluation_v2 import (
    _ci_lower_positive, _delta_or_none, _not_worse, _unmeasurable,
)


class UnmeasurableListTests(unittest.TestCase):
    def test_a_none_input_is_listed(self):
        self.assertEqual(
            ["f1_gain"],
            _unmeasurable({"f1_gain": None, "high_risk_recall_gain": 0.04}),
        )

    def test_a_real_regression_is_not_listed(self):
        """-0.02 是个结论（测了，退了），不是"测不出来"。"""
        self.assertEqual(
            [], _unmeasurable({"f1_gain": -0.02, "high_risk_recall_gain": 0.04}),
        )

    def test_zero_is_not_listed(self):
        """0.0 也是结论：测了，没变化。"""
        self.assertEqual([], _unmeasurable({"f1_gain": 0.0}))

    def test_false_is_not_listed(self):
        """False 是"验证过，不通过"，与"没法验证"不同。"""
        self.assertEqual([], _unmeasurable({"non_regression": False}))

    def test_the_names_are_sorted_for_stable_diffing(self):
        """报告要能逐次 diff，顺序不能随字典插入序变。"""
        self.assertEqual(
            ["a_gain", "b_gain", "c_gain"],
            _unmeasurable({"c_gain": None, "a_gain": None, "b_gain": None}),
        )

    def test_an_empty_condition_set_is_empty(self):
        self.assertEqual([], _unmeasurable({}))


class GateDirectionUnchangedTests(unittest.TestCase):
    """判定方向必须没被这次改动碰过：None 仍然不放行。"""

    def test_not_worse_still_blocks_on_none(self):
        self.assertFalse(_not_worse(None, 0.5))
        self.assertFalse(_not_worse(0.5, None))
        self.assertTrue(_not_worse(0.3, 0.5))

    def test_a_missing_ci_is_still_not_significant(self):
        self.assertFalse(_ci_lower_positive({}))
        self.assertFalse(_ci_lower_positive({"ci95": [None, None]}))
        self.assertFalse(_ci_lower_positive({"ci95": [-0.01, 0.2]}))
        self.assertTrue(_ci_lower_positive({"ci95": [0.01, 0.2]}))

    def test_delta_or_none_propagates_none(self):
        self.assertIsNone(_delta_or_none(None, 0.5))
        self.assertIsNone(_delta_or_none(0.5, None))
        self.assertEqual(0.1, _delta_or_none(0.6, 0.5))


class CriticRecallThreeStateTests(unittest.TestCase):
    """critic 的 recall 未回退判定改成三态，判定处收成 False。

    原写法 `candidate is not None and baseline is not None and cand >= base-0.01`
    把 None 直接压成 False，报告里就再也看不出"这一档 recall 无定义"。
    """

    @staticmethod
    def _decide(candidate, baseline):
        delta = _delta_or_none(candidate, baseline)
        return None if delta is None else delta >= -0.01

    def test_a_missing_recall_yields_none_not_false(self):
        self.assertIsNone(self._decide(None, 0.5))
        self.assertIsNone(self._decide(0.5, None))

    def test_the_one_pp_tolerance_still_applies(self):
        self.assertTrue(self._decide(0.49, 0.50))
        self.assertFalse(self._decide(0.48, 0.50))

    def test_none_is_not_a_pass_at_the_decision_site(self):
        """门禁处用 `is True`，None 不放行。"""
        self.assertFalse(self._decide(None, 0.5) is True)


class ReportCarriesTheDistinctionTests(unittest.TestCase):
    """helper 对了不算接进去了——报告里必须真的带上这个字段。

    这是 `tiered_match` 那次的教训：函数写对、测试写全，但零生产调用方，
    于是消融表报的还是旧口径。
    """

    @staticmethod
    def _report_with_splits(splits, clean_splits=()):
        from tests.test_agentic_evaluation import DIFF, FakeClient
        from evoagent.evaluation_v2 import (
            FairAblationSuite, product_reviewer_factories,
        )

        cases = []
        for index, split in enumerate(splits, 1):
            expected = [] if split in clean_splits else [{
                "path": "app.py", "start_line": 1, "end_line": 1,
                "rule_id": "SEC-PATH-TRAVERSAL", "cwe": "CWE-22",
                "severity": "high", "should_comment": True,
            }]
            cases.append({
                "id": "case-%d" % index, "repository": "repo-%d" % index,
                "pull_request": index, "split": split,
                "source": {"kind": "synthetic-controlled"}, "diff": DIFF,
                "expected_findings": expected,
            })
        suite = FairAblationSuite(
            product_reviewer_factories(FakeClient(), 40),
            "fake-model", 4096, require_production_ready=False,
            bootstrap_iterations=200,
        )
        return suite.run(cases)

    def _report(self):
        return self._report_with_splits(("train", "validation", "holdout"))

    def test_both_gates_report_which_conditions_were_unmeasurable(self):
        report = self._report()
        for gate in ("launch_gate", "critic_gate"):
            self.assertIn("unmeasurable", report[gate], gate)
            self.assertIsInstance(report[gate]["unmeasurable"], list, gate)

    def test_the_critic_gate_exposes_the_recall_delta_it_judged_on(self):
        """判定用的中间量要能看见，否则"未回退=False"没法复核。"""
        report = self._report()
        self.assertIn("recall_delta", report["critic_gate"])

    def test_a_measurable_zero_gain_is_not_listed_as_unmeasurable(self):
        """写这条测试时的一个错误前提，留下来当反例。

        我原以为"1 个 holdout case 撑不起自助法区间"，实际 CI 是
        `[0.0, 0.0]`——算得出来，只是宽度为零且不为正。`_ci_lower_positive`
        返回 False 是因为 `0.0 > 0` 不成立，**不是**因为区间缺失。所以
        `unmeasurable` 为空是对的：一切都测到了，只是没有增益。
        """
        report = self._report()
        self.assertEqual([], report["launch_gate"]["unmeasurable"])
        self.assertEqual(0.0, report["launch_gate"]["f1_gain"])
        self.assertFalse(report["launch_gate"]["statistically_positive"])

    def test_no_holdout_cases_makes_every_holdout_condition_unmeasurable(self):
        """真正测不出来的形态之一：holdout 一个 case 都没有。

        此时门禁没过与"候选不行"无关，该去补数据而不是去改 Critic——报告
        必须让人看出这个区别。
        """
        report = self._report_with_splits(("train", "validation"))
        self.assertIsNone(report["launch_gate"]["f1_gain"])
        self.assertEqual(
            ["f1_gain", "high_risk_recall_gain", "multi_agent_f1_ci",
             "multi_agent_high_risk_recall_ci"],
            report["launch_gate"]["unmeasurable"],
        )
        self.assertIn(
            "recall_non_regression_with_1pp_tolerance",
            report["critic_gate"]["unmeasurable"],
        )

    def test_a_holdout_without_high_risk_truths_is_unmeasurable_on_that_metric(self):
        """形态之二：holdout 有样本，但没有高风险真值。

        `high_risk_recall` 分母为零 → 增益无定义。这是反转 fix PR 数据集上
        很容易出现的形态（缺陷等级分布不均）。
        """
        report = self._report_with_splits(
            ("train", "validation", "holdout"), clean_splits=("holdout",),
        )
        self.assertIsNone(report["launch_gate"]["high_risk_recall_gain"])
        self.assertIn(
            "high_risk_recall_gain", report["launch_gate"]["unmeasurable"],
        )

    def test_the_gate_still_does_not_pass_on_unmeasurable_input(self):
        """透明化不能顺手把门禁放宽。"""
        report = self._report()
        self.assertFalse(report["launch_gate"]["passed"])
        self.assertFalse(report["critic_gate"]["passed"])


class CliReachabilityTests(unittest.TestCase):
    def test_the_critic_position_check_flag_reaches_the_factories(self):
        """诊断打不开就等于没有：`--critic-position-check` 必须能传到工厂。

        `critic_position_check` 在 f3421b5 加进了 `product_reviewer_factories`，
        但消融脚本没传，默认 False——这个诊断从 CLI 根本打不开，和
        `tiered_match` 零调用方是同一形态的问题。
        """
        import inspect

        from evoagent.evaluation_v2 import product_reviewer_factories

        import os

        signature = inspect.signature(product_reviewer_factories)
        self.assertIn("critic_position_check", signature.parameters)

        # 直接读脚本文件，不 import：入口带 argparse，import 会有副作用。
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        path = os.path.join(root, "scripts", "run_agentic_evaluation.py")
        with open(path, encoding="utf-8") as handle:
            script = handle.read()
        self.assertIn("--critic-position-check", script)
        self.assertIn("critic_position_check=args.critic_position_check", script)


if __name__ == "__main__":
    unittest.main()
