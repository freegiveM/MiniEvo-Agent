"""进化层空分母口径的测试。

## 修的是什么

`RegressionEvaluator.run` 是项目里第三处独立的指标计算（另两处在
`evaluation_harness._metrics` 和 `evaluation_v2._metrics`），它保留了空分母
返回 1.0 的老写法：

    recall = tp / (tp + fn) if tp + fn else 1.0
    clean_accuracy = clean_hits / clean_total if clean_total else 1.0
    high_severity_recall = hits / total if total else 1.0

这不是纯理论问题。反转 fix PR 的每个 case 都必带种子缺陷（`validate_case`
要求 finding 覆盖一行新增行），所以 `datasets/real-pr-v1.jsonl` 上
`clean_total` **恒为 0**——D6 把 Holdout 换成真实数据集时这个 bug 必然触发，
而且触发形态是"编造一个满分喂给门禁"。

## 为什么门禁的 None 处理是非对称的

`baseline is None` → 放行（本来没测过，无从回退）。
`candidate is None` 而 baseline 有数 → 拦（把可测指标变成测不出来了）。
一律跳过 None 是不行的：`all([])` 是 True，指标全 None 会得到"门禁全通过"。
"""
import unittest

from evoagent.evolution import (
    EvolutionEngine, RegressionEvaluator, _metric_non_regressing, _ratio,
)

DIFF = "--- a/app.py\n+++ b/app.py\n@@ -0,0 +1 @@\n+x = eval(p)\n"


class Silent:
    """一条 finding 都不报的 reviewer。"""
    name = "silent"

    def review(self, diff, parsed):
        return []


def _defect_case(index, severity="low"):
    """反转 fix PR 的形状：必带种子缺陷，没有 clean case。"""
    return {
        "name": "c%d" % index, "diff": DIFF,
        "expected": [{"path": "app.py", "line": 1, "min_severity": severity}],
    }


def _run(cases, reviewer=None):
    factory = (lambda prompt: reviewer or Silent())
    return RegressionEvaluator(factory).run("prompt", cases)


class RatioCaliberTests(unittest.TestCase):
    def test_an_empty_denominator_is_none_not_full_marks(self):
        self.assertIsNone(_ratio(0, 0))

    def test_zero_over_a_real_denominator_is_a_conclusion(self):
        """0.0 与 None 不是同一件事：前者是"测过了一条没中"。"""
        self.assertEqual(0.0, _ratio(0, 5))

    def test_a_negative_denominator_is_also_none(self):
        self.assertIsNone(_ratio(0, -1))


class EvaluatorEmptyDenominatorTests(unittest.TestCase):
    def test_a_dataset_without_clean_cases_reports_none_not_one(self):
        """这就是 D6 会踩的形态：全是带缺陷的 case，0 个 clean case。"""
        metrics = _run([_defect_case(i) for i in range(5)])
        self.assertEqual(0, metrics["clean_cases"])
        self.assertIsNone(metrics["clean_accuracy"])

    def test_a_dataset_without_high_severity_truths_reports_none(self):
        metrics = _run([_defect_case(i, "low") for i in range(3)])
        self.assertIsNone(metrics["high_severity_recall"])

    def test_recall_is_still_zero_when_there_are_truths_to_miss(self):
        """有真值可漏时 recall 必须报 0.0——不能被空分母改动带成 None。"""
        metrics = _run([_defect_case(i) for i in range(3)])
        self.assertEqual(0.0, metrics["recall"])

    def test_precision_is_none_when_nothing_was_predicted(self):
        """一条都不报 → precision 无定义。原写法在无真值时给 1.0。"""
        metrics = _run([_defect_case(0)])
        self.assertIsNone(metrics["precision"])

    def test_f1_comes_from_the_confusion_matrix_not_the_product(self):
        """f1 走 2tp/(2tp+fp+fn)，precision 为 None 时它仍有定义。

        若按 2PR/(P+R) 算，precision=None 会让 f1 整体变 None，而"报了 0 条、
        漏了 3 条"的 f1 明确是 0.0，不是"测不出来"。
        """
        metrics = _run([_defect_case(i) for i in range(3)])
        self.assertIsNone(metrics["precision"])
        self.assertEqual(0.0, metrics["f1"])

    def test_an_empty_case_list_reports_none_across_the_board(self):
        metrics = _run([])
        for name in ("precision", "recall", "f1", "severity_accuracy",
                     "clean_accuracy", "high_severity_recall"):
            self.assertIsNone(metrics[name], name)
        self.assertEqual(0.0, metrics["score"])

    def test_score_stays_a_float_so_the_improvement_comparison_still_works(self):
        """score 是加权聚合，调用方拿它做 >= 比较，不能是 None。"""
        metrics = _run([_defect_case(i) for i in range(3)])
        self.assertIsInstance(metrics["score"], float)

    def test_a_none_component_is_dropped_before_normalising(self):
        """None 分量剔掉再归一化，不能当 0 参与加权。

        全漏时 matched == 0 → severity_accuracy 是 None，它占 0.15 权重。
        当 0 算会把 score 压低，等于把"没测到这一档"记成"这一档零分"。
        """
        metrics = _run([_defect_case(i) for i in range(3)])
        self.assertIsNone(metrics["severity_accuracy"])
        # f1=0.0 是唯一有效分量，归一化后 score 仍是 0.0；关键是没抛异常。
        self.assertEqual(0.0, metrics["score"])


class NonRegressionNoneHandlingTests(unittest.TestCase):
    def test_a_baseline_that_was_never_measured_lets_the_candidate_through(self):
        self.assertTrue(_metric_non_regressing(None, None, 0.0))
        self.assertTrue(_metric_non_regressing(0.3, None, 0.0))

    def test_a_candidate_that_stopped_being_measurable_is_blocked(self):
        """把可测指标变成测不出来 = 实质回退，不是"不适用"。"""
        self.assertFalse(_metric_non_regressing(None, 0.8, 0.0))

    def test_the_margin_still_applies_when_both_sides_are_numbers(self):
        self.assertFalse(_metric_non_regressing(0.7, 0.8, 0.0))
        self.assertTrue(_metric_non_regressing(0.7, 0.8, 0.15))

    def test_a_regression_exactly_at_the_margin_is_blocked_by_float_error(self):
        """记录一个既有行为，不是本次改动引入的。

        `0.7 + 0.1 == 0.7999999999999999 < 0.8`，所以"正好等于容差"的回退会
        被拦。没有加 epsilon 去放宽它：误差方向是**偏严**（该放行的被拦），
        对发布门禁来说这是安全的一侧。加 epsilon 会让门禁比声明的更松，那是
        危险的一侧。
        """
        self.assertFalse(_metric_non_regressing(0.7, 0.8, 0.1))

    def test_the_fabricated_full_mark_no_longer_passes_the_gate(self):
        """回归测试：修复前这个组合判 True 放行。

        baseline 真实测到 clean_accuracy=0.4，候选的数据集 0 个 clean case，
        老写法给候选一个编造的 1.0，于是 1.0 >= 0.4 判"未回退"。
        """
        engine = EvolutionEngine.__new__(EvolutionEngine)
        engine.max_metric_regression = 0.0
        baseline = {
            "score": 0.5, "precision": 0.5, "recall": 0.5,
            "high_severity_recall": 0.8, "clean_accuracy": 0.4,
            "severity_accuracy": 0.9, "positive_cases": 3, "clean_cases": 2,
        }
        candidate = dict(
            baseline, score=0.6, high_severity_recall=None,
            clean_accuracy=None, clean_cases=0,
        )
        self.assertFalse(engine._non_regressing(candidate, baseline))

    def test_a_normal_improvement_still_passes(self):
        engine = EvolutionEngine.__new__(EvolutionEngine)
        engine.max_metric_regression = 0.0
        baseline = {
            "score": 0.5, "precision": 0.5, "recall": 0.5,
            "high_severity_recall": 0.8, "clean_accuracy": 0.4,
            "severity_accuracy": 0.9, "positive_cases": 3, "clean_cases": 2,
        }
        self.assertTrue(engine._non_regressing(dict(baseline, score=0.6), baseline))

    def test_an_all_none_metric_set_does_not_pass_vacuously(self):
        """指标全 None 时门禁不能因为 all([]) 而全绿。

        受保护列表里 score 恒是 float，precision/recall/high_severity_recall
        在 baseline 有数时必须被 candidate 的 None 拦住。
        """
        engine = EvolutionEngine.__new__(EvolutionEngine)
        engine.max_metric_regression = 0.0
        baseline = {
            "score": 0.5, "precision": 0.5, "recall": 0.5,
            "high_severity_recall": 0.8, "positive_cases": 0, "clean_cases": 0,
        }
        candidate = {
            "score": 0.9, "precision": None, "recall": None,
            "high_severity_recall": None, "positive_cases": 0, "clean_cases": 0,
        }
        self.assertFalse(engine._non_regressing(candidate, baseline))


class SkillEvolutionGateParityTests(unittest.TestCase):
    def test_both_gates_share_one_none_policy(self):
        """两处 _non_regressing 读同一个 evaluator 的输出，口径必须一致。"""
        from evoagent.skill_evolution import SkillEvolutionEngine

        for cls in (EvolutionEngine, SkillEvolutionEngine):
            engine = cls.__new__(cls)
            engine.max_metric_regression = 0.0
            baseline = {
                "score": 0.5, "precision": 0.5, "recall": 0.5,
                "high_severity_recall": 0.8, "success_rate": 1.0,
                "positive_cases": 0, "clean_cases": 0,
            }
            candidate = dict(baseline, score=0.9, high_severity_recall=None)
            self.assertFalse(
                engine._non_regressing(candidate, baseline), cls.__name__
            )


if __name__ == "__main__":
    unittest.main()
