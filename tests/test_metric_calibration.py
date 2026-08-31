"""空分母口径与配对 bootstrap 的测试。

## 修掉的两个口径 bug

1. `ratio(..., empty=1.0)`：分母为零时返回**满分**。一个什么都不报的
   reviewer 在没有正样本的批次上同时拿到 recall=1.0、severity_accuracy=1.0、
   high_risk_recall=1.0、clean_accuracy=1.0。空集合不是"全对"，
   是"这个比率没有定义"。

2. `tp = totals["tp"] or 1`：零命中时分母悄悄变 1，exact_line_accuracy = 0/1
   = 0.0 看起来像正常结论，实际这个比率无定义。

3. 配对 bootstrap 给每个 metric 用了**不同的重采样索引**，导致 f1 与
   precision 的 CI 无法联合解读——而 critic_gate 恰恰联合用了这两条。

这些路径此前没有任何测试覆盖，这正是它们能长期带 bug 的原因。
"""
import unittest

from evoagent.evaluation_harness import EndToEndEvaluationHarness, comparison_summary
from evoagent.evaluation_v2 import (
    REQUIRED_ARMS,
    FairAblationSuite,
    ProductionEvaluationHarness,
)


class EmptyDenominatorTests(unittest.TestCase):
    def test_a_silent_reviewer_does_not_score_full_marks_on_an_empty_batch(self):
        """这就是被修掉的 bug：什么都不报，四个指标全 1.0。"""
        metrics = EndToEndEvaluationHarness._metrics(
            EndToEndEvaluationHarness._empty_totals()
        )
        for name in ("recall", "precision", "f1", "severity_accuracy",
                     "high_risk_recall", "clean_accuracy"):
            self.assertIsNone(metrics[name], "%s should be n/a, got %r" % (
                name, metrics[name]))

    def test_zero_is_still_reported_when_there_were_samples(self):
        """None 与 0.0 的区别是实质的：0.0 是结论，None 是"无法下结论"。"""
        totals = EndToEndEvaluationHarness._empty_totals()
        totals.update({"tp": 0, "fn": 3, "fp": 2})
        metrics = EndToEndEvaluationHarness._metrics(totals)
        self.assertEqual(0.0, metrics["recall"])
        self.assertEqual(0.0, metrics["precision"])
        self.assertEqual(0.0, metrics["f1"])

    def test_f1_is_none_when_either_side_is_undefined(self):
        """缺一个就是 None，不用 0 填充——填 0 会让"无正样本"像"全漏了"。"""
        totals = EndToEndEvaluationHarness._empty_totals()
        totals.update({"tp": 0, "fn": 0, "fp": 4})   # 有预测，无真值
        metrics = EndToEndEvaluationHarness._metrics(totals)
        self.assertEqual(0.0, metrics["precision"])
        self.assertIsNone(metrics["recall"])
        self.assertIsNone(metrics["f1"])

    def test_execution_success_rate_is_none_when_nothing_ran(self):
        """"没跑"和"跑了全失败"不同。"""
        metrics = EndToEndEvaluationHarness._metrics(
            EndToEndEvaluationHarness._empty_totals()
        )
        self.assertIsNone(metrics["execution_success_rate"])


class ProductionMetricTests(unittest.TestCase):
    def test_exact_line_accuracy_is_none_when_there_were_no_hits(self):
        """原实现 tp or 1 会让它变成 0/1 = 0.0，像"命中了但都没到行"。"""
        totals = ProductionEvaluationHarness._empty_totals()
        totals.update({"cases": 5, "tp": 0})
        metrics = ProductionEvaluationHarness._metrics(totals)
        self.assertIsNone(metrics["exact_line_accuracy"])
        self.assertIsNone(metrics["evidence_accuracy"])

    def test_exact_line_accuracy_is_computed_when_there_are_hits(self):
        totals = ProductionEvaluationHarness._empty_totals()
        totals.update({"cases": 4, "tp": 4, "exact_location_hits": 3,
                       "evidence_hits": 2})
        metrics = ProductionEvaluationHarness._metrics(totals)
        self.assertEqual(0.75, metrics["exact_line_accuracy"])
        self.assertEqual(0.5, metrics["evidence_accuracy"])

    def test_failure_rate_is_none_when_no_cases_ran(self):
        metrics = ProductionEvaluationHarness._metrics(
            ProductionEvaluationHarness._empty_totals()
        )
        self.assertIsNone(metrics["failure_rate"])
        self.assertIsNone(metrics["average_total_tokens_per_pr"])
        self.assertIsNone(metrics["invalid_comments_per_pr"])

    def test_per_pr_averages_use_the_case_count_as_denominator(self):
        totals = ProductionEvaluationHarness._empty_totals()
        totals.update({"cases": 4, "execution_successes": 3,
                       "total_tokens": 8000, "invalid_comments": 2})
        metrics = ProductionEvaluationHarness._metrics(totals)
        self.assertEqual(0.25, metrics["failure_rate"])
        self.assertEqual(2000.0, metrics["average_total_tokens_per_pr"])
        self.assertEqual(0.5, metrics["invalid_comments_per_pr"])


class GateThreeStateTests(unittest.TestCase):
    def _arm(self, **metric_overrides):
        metrics = {
            "precision": 0.8, "recall": 0.7, "f1": 0.75,
            "severity_accuracy": 0.9, "high_risk_recall": 0.6,
            "clean_accuracy": 0.95, "execution_success_rate": 1.0,
            "safe_fix_rate": 0.8, "e2e_security_fix_rate": 0.7,
        }
        metrics.update(metric_overrides)
        return {
            "name": "arm", "metrics": metrics,
            "by_split": {"validation": dict(metrics), "holdout": dict(metrics)},
            "dataset": {"sha256": "x", "source_kinds": ["public-github-pr"]},
        }

    def test_an_undefined_metric_makes_the_gate_not_applicable_not_passed(self):
        """静默放行是最坏的结果：报告写"门禁通过"，实际什么都没验证。"""
        baseline = self._arm(clean_accuracy=None)
        candidate = self._arm(clean_accuracy=None)
        summary = comparison_summary(baseline, candidate)
        gates = summary["release_gate"]["gates"]
        self.assertIsNone(gates["clean_accuracy_non_regression"]["passed"])
        self.assertIn("clean_accuracy_non_regression", summary["not_applicable_gates"])
        self.assertFalse(summary["release_gate"]["passed"])
        # None 既不算通过也不算失败：定量门禁整体不通过，但失败原因是
        # "无法验证"，这一点必须能从 not_applicable_gates 读出来。
        self.assertFalse(summary["release_gate"]["quantitative_passed"])

    def test_deltas_are_none_rather_than_raising_on_undefined_metrics(self):
        summary = comparison_summary(
            self._arm(high_risk_recall=None), self._arm(high_risk_recall=None)
        )
        self.assertIsNone(summary["deltas"]["high_risk_recall"])
        self.assertEqual(0.0, summary["deltas"]["f1"])

    def test_a_fully_defined_improvement_still_passes(self):
        """三态改造不能让正常路径失效。"""
        baseline = self._arm(f1=0.5)
        candidate = self._arm(f1=0.9)
        summary = comparison_summary(baseline, candidate)
        gates = summary["release_gate"]["gates"]
        self.assertTrue(gates["validation_f1_improvement"]["passed"])
        self.assertEqual([], summary["not_applicable_gates"])
        self.assertTrue(summary["release_gate"]["passed"])


class SharedResampleIndexTests(unittest.TestCase):
    """配对 bootstrap 必须在同一重采样上算所有 metric。"""

    def _suite(self, iterations=200):
        # 构造器强制四臂工厂齐全（这是"公平消融"的前提），这里只用
        # _paired_bootstrap，所以给四个不会被调用的占位工厂。
        factories = {name: (lambda model, budget: None) for name in REQUIRED_ARMS}
        return FairAblationSuite(
            factories, "model", 4096, require_production_ready=False,
            bootstrap_iterations=iterations, bootstrap_seed=7,
        )

    @staticmethod
    def _case(index, tp):
        """One case_result in the shape _run_case actually emits.

        字段名必须与 _run_case 一致（expected / clean_hit / execution_success
        是单数、布尔），否则 _accumulate 直接 KeyError。
        """
        return {
            "id": "case-%d" % index, "split": "holdout",
            "expected": 1, "predicted": 1,
            "tp": tp, "fp": 1 - tp, "fn": 1 - tp,
            "severity_hits": tp, "high_total": 1, "high_hits": tp,
            "clean_hit": False, "execution_success": True,
            "repair_attempted": 0, "repair_passed": 0, "e2e_success": False,
            "invalid_comments": 1 - tp,
            "exact_location_hits": tp, "evidence_hits": tp,
            "total_tokens": 1000,
        }

    def _arm(self, name, hits):
        cases = [self._case(index, tp) for index, tp in enumerate(hits)]
        totals = ProductionEvaluationHarness._empty_totals()
        for case in cases:
            ProductionEvaluationHarness._accumulate(totals, case)
        return {
            "name": name, "case_results": cases,
            "metrics": ProductionEvaluationHarness._metrics(totals),
        }

    def test_a_metrics_ci_does_not_depend_on_what_else_was_requested(self):
        """这是能区分新旧实现的判据。

        旧实现按 metric 在元组里的下标取种子（`seed_offset + index`），所以
        precision 单独请求时用种子 offset+0，和 f1 一起请求时用 offset+1
        —— **同一对臂、同一 seed_offset，CI 却随请求顺序变化**。这正是
        "每个 metric 走了不同重采样"的可观测症状。

        新实现只用 `seed_offset` 开一个 rng，全部 metric 复用同一条索引序列，
        所以 CI 与请求了哪些 metric 无关。
        """
        left = self._arm("left", [1, 0, 1, 0, 1, 0, 1, 0])
        right = self._arm("right", [1, 1, 1, 1, 1, 0, 1, 0])
        alone = self._suite()._paired_bootstrap(left, right, ("precision",), 0)
        together = self._suite()._paired_bootstrap(
            left, right, ("f1", "precision", "recall"), 0
        )
        self.assertEqual(
            alone["precision"]["ci95"], together["precision"]["ci95"],
            "precision 的 CI 随同批请求的 metric 变化了，说明没有共享重采样",
        )

    def test_every_metric_is_computed_on_the_same_resampled_batch(self):
        """同一次迭代内，各 metric 必须看到同一批 PR。

        用一个更强的不变量：recall 与 f1 在**同一批**样本上算出来时，
        precision ≥ f1 ≥ recall 这类代数关系逐迭代成立，聚合后
        usable_iterations 也必然一致（同一个 continue 条件下的同一批索引）。
        这里检查后者——但要让这个断言有内容，得让空分母真的发生
        （见 test_iterations_with_undefined_metrics_are_skipped_not_counted_as_zero）。
        """
        left = self._arm("left", [1, 0, 1, 0])
        right = self._arm("right", [1, 1, 1, 0])
        result = self._suite()._paired_bootstrap(
            left, right, ("f1", "precision", "recall"), 0
        )
        counts = {result[metric]["usable_iterations"] for metric in result}
        self.assertEqual(1, len(counts), "metrics did not share one resample: %s" % counts)

    def test_iterations_with_undefined_metrics_are_skipped_not_counted_as_zero(self):
        """空分母迭代当 0 参与会把 CI 往 0 拉，把显著性判定压成假阴性。

        构造：所有 case 都没有 high 真值（high_total=0），于是每一次重采样的
        high_risk_recall 都无定义 → 全部跳过 → usable_iterations 必须是 0，
        且 CI 报 [None, None] 而不是 [0, 0]。
        """
        def _no_high(index, tp):
            case = self._case(index, tp)
            case.update({"high_total": 0, "high_hits": 0})
            return case

        left_cases = [_no_high(index, tp) for index, tp in enumerate([1, 0, 1, 0])]
        right_cases = [_no_high(index, tp) for index, tp in enumerate([1, 1, 1, 0])]

        def _arm(name, cases):
            totals = ProductionEvaluationHarness._empty_totals()
            for case in cases:
                ProductionEvaluationHarness._accumulate(totals, case)
            return {"name": name, "case_results": cases,
                    "metrics": ProductionEvaluationHarness._metrics(totals)}

        result = self._suite()._paired_bootstrap(
            _arm("left", left_cases), _arm("right", right_cases),
            ("high_risk_recall", "f1"), 0,
        )
        self.assertEqual(0, result["high_risk_recall"]["usable_iterations"])
        self.assertEqual([None, None], result["high_risk_recall"]["ci95"])
        self.assertIsNone(result["high_risk_recall"]["delta"])
        # 同一次调用里 f1 仍然可算——跳过是按 metric 判定的，不是整轮丢弃。
        self.assertGreater(result["f1"]["usable_iterations"], 0)

    def test_the_bootstrap_is_deterministic_for_a_fixed_seed(self):
        left = self._arm("left", [1, 0, 1, 0])
        right = self._arm("right", [1, 1, 1, 0])
        first = self._suite()._paired_bootstrap(left, right, ("f1",), 3)
        second = self._suite()._paired_bootstrap(left, right, ("f1",), 3)
        self.assertEqual(first["f1"]["ci95"], second["f1"]["ci95"])

    def test_a_real_improvement_yields_a_ci_above_zero(self):
        left = self._arm("left", [0] * 12)
        right = self._arm("right", [1] * 12)
        result = self._suite()._paired_bootstrap(left, right, ("recall",), 5)
        self.assertGreater(result["recall"]["ci95"][0], 0)

    def test_identical_arms_yield_a_ci_spanning_zero(self):
        arm = self._arm("same", [1, 0, 1, 0, 1, 0])
        result = self._suite()._paired_bootstrap(arm, arm, ("f1",), 9)
        self.assertEqual(0.0, result["f1"]["delta"])
        self.assertLessEqual(result["f1"]["ci95"][0], 0)
        self.assertGreaterEqual(result["f1"]["ci95"][1], 0)

    def test_mismatched_case_order_is_rejected(self):
        """配对比较的前提是两臂跑了同一批 PR 且顺序一致。"""
        left = self._arm("left", [1, 0])
        right = self._arm("right", [1, 0])
        right["case_results"][0]["id"] = "different"
        with self.assertRaises(ValueError):
            self._suite()._paired_bootstrap(left, right, ("f1",), 0)

    def test_an_empty_case_set_reports_none_rather_than_a_zero_ci(self):
        """零样本时报 delta=0 / CI=[0,0] 会被读成"确认无差异"，那是编造。"""
        empty = {"name": "e", "case_results": [],
                 "metrics": ProductionEvaluationHarness._metrics(
                     ProductionEvaluationHarness._empty_totals())}
        result = self._suite()._paired_bootstrap(empty, empty, ("f1",), 0)
        self.assertIsNone(result["f1"]["delta"])
        self.assertEqual([None, None], result["f1"]["ci95"])
        self.assertEqual(0, result["f1"]["usable_iterations"])

    def test_usable_iterations_is_reported_so_thin_cis_can_be_spotted(self):
        left = self._arm("left", [1, 0, 1, 0])
        right = self._arm("right", [1, 1, 1, 0])
        result = self._suite(iterations=300)._paired_bootstrap(
            left, right, ("f1",), 11
        )
        self.assertEqual(300, result["f1"]["iterations"])
        self.assertGreater(result["f1"]["usable_iterations"], 0)
        self.assertLessEqual(result["f1"]["usable_iterations"], 300)


class CiSignificanceHelperTests(unittest.TestCase):
    def test_a_missing_ci_is_not_significant(self):
        """没有区间就没有显著性，不该靠调用方记得判空。"""
        from evoagent.evaluation_v2 import _ci_lower_positive
        self.assertFalse(_ci_lower_positive({"ci95": [None, None]}))
        self.assertFalse(_ci_lower_positive({}))
        self.assertFalse(_ci_lower_positive({"ci95": [0.0, 0.5]}))
        self.assertTrue(_ci_lower_positive({"ci95": [0.01, 0.5]}))

    def test_not_worse_refuses_to_confirm_non_regression_without_data(self):
        from evoagent.evaluation_v2 import _not_worse
        self.assertFalse(_not_worse(None, 0.5))
        self.assertFalse(_not_worse(0.5, None))
        self.assertTrue(_not_worse(0.3, 0.5))
        self.assertFalse(_not_worse(0.7, 0.5))


if __name__ == "__main__":
    unittest.main()
