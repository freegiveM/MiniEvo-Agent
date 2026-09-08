"""Track E：门禁统计显著性（Wilson 区间 + 报告项）的测试。

## 修的是什么

`_metric_non_regressing` 是纯阈值比较（`candidate + margin >= baseline`），
不看样本量。当前数据集只有 95 条、切分后单侧更少，"候选涨了 1-2 个点"在这个
规模下有多大概率只是噪声，原逻辑给不出答案。D6 实测里
`high_severity_recall` 的分母只有 18——5/18 的 95% 区间是 [0.125, 0.509]，
宽度超过 0.38，这个事实必须在报告里出现。

## 为什么用 Wilson 而不是正态近似

正态近似 `p ± z·sqrt(p(1-p)/n)` 在 p 贴近 0/1 时给出退化或越界的区间：
18/18 会算出 [1.0, 1.0]，宣称"确定无疑"。Wilson 在两端自动收缩，永远落在
[0,1] 内。`test_a_perfect_score_does_not_produce_a_degenerate_interval`
钉住这条。

## 为什么 significant 不接门禁

现有阈值判断已经跑过一段时间、行为可预期。直接改成显著性判断会让大量原本
能通过的候选突然被拦，这个变化要先看一段时间报告数据再决定。所以
`gates["significant"]` 只展示，`decision` 完全不看它——
`SignificanceIsReportOnlyTests` 钉住"加了这个字段之后 decision 不变"。
"""
import unittest

from evoagent.evolution import (
    EvolutionEngine, RegressionEvaluator, _intervals_disjoint, _wilson_interval,
)


class WilsonIntervalTests(unittest.TestCase):
    def test_a_textbook_case_matches_the_hand_computed_value(self):
        """50/100 的 95% Wilson 区间，教科书值 [0.4038, 0.5962]。"""
        self.assertEqual([0.4038, 0.5962], _wilson_interval(50, 100))

    def test_a_perfect_score_does_not_produce_a_degenerate_interval(self):
        """18/18 不是"确定无疑"。正态近似会给 [1.0, 1.0]，Wilson 不会。"""
        low, high = _wilson_interval(18, 18)
        self.assertEqual(1.0, high)
        self.assertLess(low, 1.0)
        self.assertGreater(low, 0.8)

    def test_a_zero_score_does_not_produce_a_degenerate_interval(self):
        low, high = _wilson_interval(0, 18)
        self.assertEqual(0.0, low)
        self.assertGreater(high, 0.0)

    def test_the_interval_never_leaves_the_unit_range(self):
        for successes, total in ((0, 1), (1, 1), (1, 3), (2, 5), (0, 200), (200, 200)):
            low, high = _wilson_interval(successes, total)
            self.assertGreaterEqual(low, 0.0)
            self.assertLessEqual(high, 1.0)
            self.assertLessEqual(low, high)

    def test_an_empty_denominator_is_none_not_a_full_range(self):
        """同 `_ratio` 的空分母口径：没样本 → None，不是 [0.0, 1.0]。

        [0.0, 1.0] 会被下游当成一个真实区间参与重叠比较（且必然与一切重叠，
        永远判"不显著"），None 则明确表示这一档算不出来。
        """
        self.assertIsNone(_wilson_interval(0, 0))
        self.assertIsNone(_wilson_interval(0, -1))

    def test_more_samples_at_the_same_rate_narrow_the_interval(self):
        """同一个比例、样本量更大 → 区间更窄。这是这个字段存在的全部意义。"""
        narrow = _wilson_interval(500, 1000)
        wide = _wilson_interval(5, 10)
        self.assertLess(narrow[1] - narrow[0], wide[1] - wide[0])

    def test_the_d6_high_severity_denominator_is_honestly_wide(self):
        """5/18 —— D6 实测的 high_severity_recall。区间宽 0.38，如实报出来。

        这条不是在测实现，是把"当前数据规模撑不起精确结论"这个事实钉进
        测试里：哪天有人把区间调窄了，得先解释是样本变多了还是口径松了。
        """
        low, high = _wilson_interval(5, 18)
        self.assertGreater(high - low, 0.3)


class IntervalOverlapTests(unittest.TestCase):
    def test_clearly_separated_intervals_are_disjoint(self):
        self.assertTrue(_intervals_disjoint([0.7, 0.9], [0.1, 0.3]))

    def test_the_direction_does_not_matter(self):
        """候选更低时同样算"差异显著"——显著≠改进，两件事分开判。"""
        self.assertTrue(_intervals_disjoint([0.1, 0.3], [0.7, 0.9]))

    def test_overlapping_intervals_are_not_disjoint(self):
        self.assertFalse(_intervals_disjoint([0.4, 0.8], [0.6, 0.9]))

    def test_touching_intervals_are_not_disjoint(self):
        """边界相接算重叠。判显著要保守一侧。"""
        self.assertFalse(_intervals_disjoint([0.5, 0.9], [0.1, 0.5]))

    def test_a_missing_interval_is_none_not_false(self):
        """算不出来 ≠ 不显著。None 不能塌成 False。"""
        self.assertIsNone(_intervals_disjoint(None, [0.1, 0.5]))
        self.assertIsNone(_intervals_disjoint([0.1, 0.5], None))


DIFF = "--- a/app.py\n+++ b/app.py\n@@ -0,0 +1 @@\n+x = eval(p)\n"


class Silent:
    name = "silent"

    def review(self, diff, parsed):
        return []


class EvaluatorReportsIntervalsTests(unittest.TestCase):
    def test_run_emits_an_interval_for_every_proportion_metric(self):
        case = {
            "name": "c", "diff": DIFF,
            "expected": [{"path": "app.py", "line": 1, "min_severity": "high"}],
        }
        metrics = RegressionEvaluator(lambda prompt: Silent()).run("p", [case])
        # recall 有分母（1 条期望），precision 没有（一条都没报）。
        self.assertEqual([0.0, 0.7935], metrics["recall_ci"])
        self.assertIsNone(metrics["precision_ci"])
        self.assertIsNotNone(metrics["high_severity_recall_ci"])
        # clean case 一条都没有 → 区间是 None，与 clean_accuracy 点估计一致。
        self.assertIsNone(metrics["clean_accuracy_ci"])
        self.assertIsNone(metrics["clean_accuracy"])

    def test_the_existing_point_estimates_are_untouched(self):
        """Track E 是纯新增。旧字段的语义和取值一个都不能变。"""
        case = {
            "name": "c", "diff": DIFF,
            "expected": [{"path": "app.py", "line": 1, "min_severity": "high"}],
        }
        metrics = RegressionEvaluator(lambda prompt: Silent()).run("p", [case])
        self.assertEqual(0.0, metrics["recall"])
        self.assertIsNone(metrics["precision"])
        self.assertEqual(2, metrics["schema_version"])


class SignificanceIsReportOnlyTests(unittest.TestCase):
    """`gates["significant"]` 只展示，不参与 decision。

    这里直接测 `_significance_report`（decision 不看它这件事由
    `propose()` 里那行 `if no_errors and improved and validation_safe and
    holdout_safe` 保证——四个条件里没有 significant，加一个字段进 gates 字典
    不可能改变它的取值）。
    """

    report = staticmethod(EvolutionEngine._significance_report)

    def test_a_separated_metric_makes_the_run_significant(self):
        self.assertTrue(self.report(
            {"recall_ci": [0.7, 0.9]}, {"recall_ci": [0.1, 0.3]},
        ))

    def test_all_metrics_overlapping_is_not_significant(self):
        self.assertFalse(self.report(
            {"recall_ci": [0.4, 0.8], "precision_ci": [0.3, 0.7]},
            {"recall_ci": [0.5, 0.9], "precision_ci": [0.2, 0.6]},
        ))

    def test_one_separated_metric_is_enough(self):
        """任意一个受保护指标显著就算显著——不要求全部显著。"""
        self.assertTrue(self.report(
            {"recall_ci": [0.4, 0.8], "precision_ci": [0.9, 1.0]},
            {"recall_ci": [0.5, 0.9], "precision_ci": [0.1, 0.2]},
        ))

    def test_no_computable_interval_is_none_not_false(self):
        """一个区间都算不出来时，"显著与否"无从判断。

        塌成 False 就是把"没测"伪装成"测了，不显著"——正是这个项目
        三态口径反复要禁的形态。
        """
        self.assertIsNone(self.report({}, {}))
        self.assertIsNone(self.report({"recall_ci": None}, {"recall_ci": None}))

    def test_a_partially_measurable_run_uses_what_it_has(self):
        """一档能算、一档不能算 → 按能算的那档判，不因为有 None 就整体 None。"""
        self.assertTrue(self.report(
            {"recall_ci": [0.7, 0.9], "clean_accuracy_ci": None},
            {"recall_ci": [0.1, 0.3], "clean_accuracy_ci": None},
        ))


if __name__ == "__main__":
    unittest.main()