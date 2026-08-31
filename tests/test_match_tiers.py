"""三档命中口径的测试。

## 改掉的问题

原实现只有一档：路径 + 行窗口 + **CWE 号完全相等**。这一档会把正确的发现
判成漏报——RULE_TO_CWE["SEC-EVAL"] == "CWE-95"，而数据集给 injection 类标
CWE-78；reviewer 正确指出了 eval( 这一行却不算命中。CWE-78/89/94/95 同属
CWE-74（注入）之下，是兄弟节点，要求兄弟号码相等测的是"标注者和 reviewer
是否选了同一个兄弟"，不是"reviewer 是否发现了这个缺陷"。

三档分别回答：指对行了吗（location）／认出类别了吗（category）／
CWE 号一致吗（cwe-exact，只在 CVE 子集上有意义）。
"""
import unittest

from evoagent.evaluation_harness import (
    MATCH_CATEGORY,
    MATCH_CWE_EXACT,
    MATCH_LOCATION,
    MATCH_TIERS,
    cwe_family,
    one_to_one_match,
    tiered_match,
)
from evoagent.models import Finding, Severity


def _finding(rule_id, path="app.py", line=10, severity=Severity.HIGH):
    return Finding(
        rule_id, severity, "title", "category", path, line,
        "content", "fix", "test", 0.9,
    )


def _truth(cwe, path="app.py", start=10, end=10, severity="high"):
    return {
        "path": path, "start_line": start, "end_line": end,
        "cwe": cwe, "severity": severity,
    }


class SiblingCweTests(unittest.TestCase):
    """被修掉的核心问题。"""

    def test_sibling_cwe_misses_at_exact_but_hits_at_category(self):
        expected = [_truth("CWE-78")]              # 数据集标 injection = CWE-78
        predicted = [_finding("SEC-EVAL")]         # RULE_TO_CWE 给 CWE-95
        self.assertEqual(
            [], one_to_one_match(expected, predicted, tier=MATCH_CWE_EXACT)
        )
        self.assertEqual(
            1, len(one_to_one_match(expected, predicted, tier=MATCH_CATEGORY))
        )
        self.assertEqual(
            1, len(one_to_one_match(expected, predicted, tier=MATCH_LOCATION))
        )

    def test_identical_cwe_hits_at_every_tier(self):
        expected = [_truth("CWE-95")]
        predicted = [_finding("SEC-EVAL")]
        for tier in MATCH_TIERS:
            self.assertEqual(
                1, len(one_to_one_match(expected, predicted, tier=tier)),
                "tier %s should hit" % tier,
            )

    def test_a_different_family_misses_at_category_but_hits_at_location(self):
        """指对了行、判错了类：定位对、归因错。这两件事必须能区分开。"""
        expected = [_truth("CWE-328")]             # crypto-weak
        predicted = [_finding("SEC-EVAL")]         # injection
        self.assertEqual(
            [], one_to_one_match(expected, predicted, tier=MATCH_CATEGORY)
        )
        self.assertEqual(
            1, len(one_to_one_match(expected, predicted, tier=MATCH_LOCATION))
        )

    def test_an_unmapped_truth_cwe_falls_back_to_exact_rather_than_matching_all(self):
        """族信息缺失时"同族"没有定义，宁可保守回退严格相等。"""
        expected = [_truth("CWE-601")]             # 刻意未映射到八类
        predicted = [_finding("SEC-EVAL")]
        self.assertEqual(
            [], one_to_one_match(expected, predicted, tier=MATCH_CATEGORY)
        )
        exact = [_finding("SEC-OPEN-REDIRECT")]    # RULE_TO_CWE → CWE-601
        self.assertEqual(
            1, len(one_to_one_match(expected, exact, tier=MATCH_CATEGORY))
        )


class MonotonicityTests(unittest.TestCase):
    def test_hits_are_monotonic_across_tiers(self):
        """cwe-exact ≤ category ≤ location 恒成立：严格档的边集是宽档的子集。

        这条不变量被破坏说明某一档的边构造写错了。
        """
        cases = [
            ([_truth("CWE-78")], [_finding("SEC-EVAL")]),
            ([_truth("CWE-328")], [_finding("SEC-WEAK-HASH")]),
            ([_truth("CWE-22")], [_finding("REL-DEBUG-PRINT")]),
            ([_truth("CWE-95"), _truth("CWE-328", start=20, end=20)],
             [_finding("SEC-EVAL"), _finding("SEC-WEAK-HASH", line=20)]),
            ([_truth("CWE-601")], [_finding("SEC-EVAL")]),
        ]
        for expected, predicted in cases:
            counts = [
                len(one_to_one_match(expected, predicted, tier=tier))
                for tier in (MATCH_CWE_EXACT, MATCH_CATEGORY, MATCH_LOCATION)
            ]
            self.assertEqual(sorted(counts), counts, "monotonicity broken: %s" % counts)


class LineWindowTests(unittest.TestCase):
    def test_line_tolerance_still_applies_at_every_tier(self):
        expected = [_truth("CWE-95", start=10, end=10)]
        for tier in MATCH_TIERS:
            self.assertEqual(
                1, len(one_to_one_match(
                    expected, [_finding("SEC-EVAL", line=12)], 2, tier
                )),
            )
            self.assertEqual(
                [], one_to_one_match(
                    expected, [_finding("SEC-EVAL", line=13)], 2, tier
                ),
            )

    def test_a_different_path_never_matches(self):
        expected = [_truth("CWE-95", path="app.py")]
        for tier in MATCH_TIERS:
            self.assertEqual(
                [], one_to_one_match(expected, [_finding("SEC-EVAL", path="other.py")],
                                     2, tier),
            )


class BackwardCompatibilityTests(unittest.TestCase):
    def test_the_default_tier_preserves_the_original_behaviour(self):
        """现有调用方不传 tier 时行为必须不变，否则历史数字无法复算。"""
        expected = [_truth("CWE-78")]
        predicted = [_finding("SEC-EVAL")]
        self.assertEqual(
            one_to_one_match(expected, predicted),
            one_to_one_match(expected, predicted, tier=MATCH_CWE_EXACT),
        )
        self.assertEqual([], one_to_one_match(expected, predicted))

    def test_an_unknown_tier_is_rejected_rather_than_silently_defaulted(self):
        with self.assertRaises(ValueError):
            one_to_one_match([_truth("CWE-95")], [_finding("SEC-EVAL")],
                             2, "whatever")

    def test_one_to_one_ness_is_preserved_at_the_widest_tier(self):
        """匹配算法未改动：两个 finding 指同一个真值仍只算一次命中。"""
        expected = [_truth("CWE-95")]
        predicted = [_finding("SEC-EVAL"), _finding("SEC-EVAL", line=11)]
        matches = one_to_one_match(expected, predicted, tier=MATCH_LOCATION)
        self.assertEqual(1, len(matches))


class TieredReportTests(unittest.TestCase):
    def test_all_three_tiers_plus_the_out_of_label_count_are_reported(self):
        expected = [_truth("CWE-78")]
        predicted = [_finding("SEC-EVAL"), _finding("REL-DEBUG-PRINT", line=50)]
        report = tiered_match(expected, predicted)
        self.assertEqual(0, report[MATCH_CWE_EXACT]["tp"])
        self.assertEqual(1, report[MATCH_CATEGORY]["tp"])
        self.assertEqual(1, report[MATCH_LOCATION]["tp"])
        self.assertEqual(1, report[MATCH_CWE_EXACT]["fn"])
        self.assertEqual(0, report[MATCH_LOCATION]["fn"])
        # 第 50 行那条落在标注之外。
        self.assertEqual(1, report["unlabelled"]["count"])
        self.assertEqual(2, report["unlabelled"]["total_predicted"])

    def test_out_of_label_is_counted_at_the_widest_tier(self):
        """指对了行但判错类的 finding 不该被算成标注外——否则虚增噪声量。"""
        report = tiered_match([_truth("CWE-328")], [_finding("SEC-EVAL")])
        self.assertEqual(0, report[MATCH_CATEGORY]["tp"])
        self.assertEqual(0, report["unlabelled"]["count"])

    def test_the_out_of_label_field_is_not_named_false_positive(self):
        """口径纪律：字段名本身就是纪律。标注外 ≠ 误报。"""
        report = tiered_match([_truth("CWE-95")], [_finding("SEC-EVAL")])
        self.assertNotIn("false_positives", report)
        self.assertIn("NOT false positives", report["unlabelled"]["note"])

    def test_an_empty_prediction_set_yields_zero_not_a_free_pass(self):
        report = tiered_match([_truth("CWE-95")], [])
        for tier in MATCH_TIERS:
            self.assertEqual(0, report[tier]["tp"])
            self.assertEqual(1, report[tier]["fn"])
        self.assertEqual(0, report["unlabelled"]["count"])


class CweFamilyTests(unittest.TestCase):
    def test_the_injection_family_covers_the_cwe_74_siblings(self):
        for cwe in ("CWE-78", "CWE-89", "CWE-94", "CWE-95", "CWE-502"):
            self.assertEqual("injection", cwe_family(cwe), cwe)

    def test_lookup_is_case_and_whitespace_insensitive(self):
        self.assertEqual("crypto-weak", cwe_family("  cwe-328 "))

    def test_an_unknown_cwe_maps_to_the_empty_family(self):
        self.assertEqual("", cwe_family("CWE-99999"))
        self.assertEqual("", cwe_family(""))

    def test_every_family_name_is_one_of_the_eight_defect_classes(self):
        """族名与 dataset_builder 的八类必须一致，否则分档报数对不上分类报数。

        刻意用值比较而非 import 常量：评测口径不该依赖数据集构造模块
        （否则给采集器加一类会回溯改变历史评测结果），但两边的八类名字
        必须对齐，所以在测试里显式校验这个约定。
        """
        from evoagent.dataset_builder import DEFECT_CLASSES
        from evoagent.evaluation_harness import CWE_FAMILY

        self.assertEqual(
            {item.name for item in DEFECT_CLASSES}, set(CWE_FAMILY.values())
        )


if __name__ == "__main__":
    unittest.main()
