"""e2e_security_fix_rate 的"没跑过"与"跑了没成"之别。

这个 bug 是链路审计时发现的，和空分母是同一类口径错误的**镜像**：
- 空分母那次：分母为 0 时编造 1.0（"没测过"说成"全对"）。
- 这次：分母非零但分子恒 0，因为修复环节根本没配置。报出 0.0，
  读作"试了 100% 都失败"，真相是"从来没试"。

发现时全套 290 个测试全绿——绿本身就是结论：这条路径此前零覆盖。
"""
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from evoagent.evaluation_harness import (  # noqa: E402
    EndToEndEvaluationHarness,
    FixtureRepairer,
)
from evoagent.evaluation_v2 import ProductionEvaluationHarness  # noqa: E402
from evoagent.reviewer import LocalRuleReviewer  # noqa: E402


DIFF = "--- a/app.py\n+++ b/app.py\n@@ -0,0 +1 @@\n+result = eval(payload)\n"


def _case(case_id="c1", split="validation"):
    return {
        "id": case_id, "repository": "r/%s" % case_id, "pull_request": 1,
        "split": split, "source": {"kind": "public-github-pr"}, "diff": DIFF,
        "expected_findings": [{
            "path": "app.py", "start_line": 1, "end_line": 1,
            "rule_id": "SEC-EVAL", "cwe": "CWE-95", "severity": "critical",
            "should_comment": True,
        }],
    }


class NoRepairerTests(unittest.TestCase):
    """修复环节未配置时，e2e 必须是 None 而不是 0.0。"""

    def test_the_production_harness_has_no_repairer(self):
        # 前置事实。若哪天接上了 repairer，本组测试的前提就变了，
        # 这条会转红提醒去改，而不是让下面几条静默失去意义。
        self.assertIsNone(ProductionEvaluationHarness().repairer)

    def test_e2e_is_none_when_repair_never_ran(self):
        metrics = ProductionEvaluationHarness().run(
            LocalRuleReviewer(), [_case()], "arm")["metrics"]
        # 分母非零、分子恒 0 —— 正是会算出 0.0 的形状。
        self.assertEqual(1, metrics["risk_cases"])
        self.assertEqual(0, metrics["e2e_successes"])
        self.assertIsNone(metrics["e2e_security_fix_rate"])

    def test_safe_fix_rate_is_none_for_a_different_reason(self):
        """safe_fix_rate 也是 None，但它是**碰巧**对的，不是设计对的。

        它的分母恰好也是 repair_attempted（= 0），所以空分母规则自动兜住了。
        e2e 的分母是 risk_cases（非零），兜不住。把这个区别写下来：
        两个指标都对，但只有一个是有意为之。
        """
        metrics = ProductionEvaluationHarness().run(
            LocalRuleReviewer(), [_case()], "arm")["metrics"]
        self.assertEqual(0, metrics["repair_attempted"])
        self.assertIsNone(metrics["safe_fix_rate"])

    def test_every_split_also_reports_none(self):
        # 分 split 的指标各算一次，标记必须随数据走到每一个 split。
        report = ProductionEvaluationHarness().run(
            LocalRuleReviewer(),
            [_case("c1", "validation"), _case("c2", "holdout")], "arm")
        for split, values in report["by_split"].items():
            self.assertIsNone(values["e2e_security_fix_rate"],
                              "split %s should be n/a" % split)


class RepairerPresentTests(unittest.TestCase):
    """修复环节配置了就必须给出数值结论，包括 0.0。"""

    def _harness(self):
        return EndToEndEvaluationHarness(repairer=FixtureRepairer())

    def test_the_flag_is_true_when_a_repairer_is_configured(self):
        report = self._harness().run(LocalRuleReviewer(), [_case()], "arm")
        self.assertTrue(report["metrics"]["repair_stage_active"])

    def test_e2e_is_a_number_not_none_when_repair_ran(self):
        """跑了修复就要报数，哪怕是 0.0。

        这条守住修复方向：不能为了消掉误报的 0.0 就把所有 e2e 都变 None，
        那会把"试了没成"这个真实结论也抹掉。
        """
        report = self._harness().run(LocalRuleReviewer(), [_case()], "arm")
        self.assertIsNotNone(report["metrics"]["e2e_security_fix_rate"])


class EmptyBatchTests(unittest.TestCase):
    def test_zero_cases_keeps_the_flag_false(self):
        totals = EndToEndEvaluationHarness._empty_totals()
        self.assertFalse(totals["repair_stage_active"])
        # 一个 case 都没跑，e2e 当然无定义。
        self.assertIsNone(
            EndToEndEvaluationHarness._metrics(totals)["e2e_security_fix_rate"]
        )


if __name__ == "__main__":
    unittest.main()
