"""三档口径接进评测链路的测试。

## 补的是什么缺口

`tiered_match` 与它的 18 条测试在上一轮就写好了，但**没有任何生产调用方**
——评测链路上四处 `one_to_one_match` 全部走默认的 `cwe-exact` 档。于是三档
口径只存在于测试里，消融表实际报的仍是单档数字。口径改对了但没接进去，
等于没改。

这组测试钉住"接进去了"这件事本身：`_run_case` 要累计三档，`_metrics` 要
按档报，消融报告要能读到。
"""
import unittest

from evoagent.evaluation_harness import (
    MATCH_CATEGORY,
    MATCH_CWE_EXACT,
    MATCH_LOCATION,
    MATCH_TIERS,
)
from evoagent.evaluation_v2 import ProductionEvaluationHarness
from evoagent.reviewer import LocalRuleReviewer

DIFF = (
    "--- a/app.py\n"
    "+++ b/app.py\n"
    "@@ -0,0 +1 @@\n"
    "+result = eval(payload)\n"
)


def _case(cwe, case_id="c1", split="validation", expected=True):
    findings = []
    if expected:
        findings = [{
            "path": "app.py", "start_line": 1, "end_line": 1,
            "rule_id": "SEC-EVAL", "cwe": cwe, "severity": "critical",
            "should_comment": True,
        }]
    return {
        "id": case_id, "repository": "r/%s" % case_id, "pull_request": 1,
        "split": split, "source": {"kind": "public-github-pr"},
        "diff": DIFF, "expected_findings": findings,
    }


def _run(cases):
    return ProductionEvaluationHarness().run(LocalRuleReviewer(), cases, "arm")


class TierWiringTests(unittest.TestCase):
    def test_a_sibling_cwe_is_a_hit_at_two_tiers_and_a_miss_only_at_the_strictest(self):
        """这就是三档存在的理由，端到端验证一遍。

        数据集给 injection 标 CWE-78，`RULE_TO_CWE["SEC-EVAL"]` 是 CWE-95，
        同属 CWE-74 之下的兄弟节点。reviewer 正确指出了 eval( 这一行——
        旧的单档口径把它判成漏报（recall=0.0）。
        """
        report = _run([_case("CWE-78")])
        tiers = report["metrics"]["by_tier"]
        self.assertEqual(1.0, tiers[MATCH_LOCATION]["recall"])
        self.assertEqual(1.0, tiers[MATCH_CATEGORY]["recall"])
        self.assertEqual(0.0, tiers[MATCH_CWE_EXACT]["recall"])
        # 基类那条单档指标仍是严格档，保持向后兼容（历史数字要可复算）。
        self.assertEqual(0.0, report["metrics"]["recall"])

    def test_an_exact_cwe_hits_at_every_tier(self):
        report = _run([_case("CWE-95")])
        for tier in MATCH_TIERS:
            self.assertEqual(
                1.0, report["metrics"]["by_tier"][tier]["recall"], tier
            )

    def test_tier_counts_are_summed_across_cases(self):
        """累计必须跨 case 相加，否则只报了最后一个 case。"""
        report = _run([
            _case("CWE-95", "c1"),     # 三档全中
            _case("CWE-78", "c2"),     # 只有 cwe-exact 不中
        ])
        tiers = report["metrics"]["by_tier"]
        self.assertEqual(2, tiers[MATCH_LOCATION]["tp"])
        self.assertEqual(0, tiers[MATCH_LOCATION]["fn"])
        self.assertEqual(1, tiers[MATCH_CWE_EXACT]["tp"])
        self.assertEqual(1, tiers[MATCH_CWE_EXACT]["fn"])
        self.assertEqual(0.5, tiers[MATCH_CWE_EXACT]["recall"])

    def test_the_tier_recalls_are_monotonic(self):
        """cwe-exact ≤ category ≤ location 必须恒成立。

        这条不变量在 tiered_match 层已有测试，这里验证累计与求比之后仍然成立
        ——分档累计写错（比如 tp/fn 错位）会破坏它。
        """
        report = _run([_case("CWE-95", "c1"), _case("CWE-78", "c2"),
                       _case("CWE-328", "c3")])
        tiers = report["metrics"]["by_tier"]
        recalls = [
            tiers[MATCH_CWE_EXACT]["recall"],
            tiers[MATCH_CATEGORY]["recall"],
            tiers[MATCH_LOCATION]["recall"],
        ]
        self.assertEqual(sorted(recalls), recalls, recalls)

    def test_an_empty_tier_denominator_reports_none_not_full_marks(self):
        """无正样本时三档召回全报 None——与其他指标的空分母口径一致。"""
        report = _run([_case("", "c1", expected=False)])
        for tier in MATCH_TIERS:
            self.assertIsNone(
                report["metrics"]["by_tier"][tier]["recall"], tier
            )

    def test_the_tiers_are_reported_per_split(self):
        """Validation→Holdout 的下降要能按档看，否则看不出降在哪一档。"""
        report = _run([
            _case("CWE-95", "c1", "validation"),
            _case("CWE-78", "c2", "holdout"),
        ])
        for split in ("validation", "holdout"):
            self.assertIn("by_tier", report["by_split"][split])
        self.assertEqual(
            1.0,
            report["by_split"]["validation"]["by_tier"][MATCH_CWE_EXACT]["recall"],
        )
        self.assertEqual(
            0.0,
            report["by_split"]["holdout"]["by_tier"][MATCH_CWE_EXACT]["recall"],
        )


class UnlabelledCaliberTests(unittest.TestCase):
    def test_the_out_of_label_count_uses_the_widest_tier(self):
        """指对行、判错类的 finding 不算标注外——按严格档算会虚增噪声量。

        真值标 CWE-328（crypto-weak），reviewer 报 eval(（injection）：
        category 档不中，但行指对了，所以标注外条数是 0 而不是 1。
        """
        report = _run([_case("CWE-328")])
        tiers = report["metrics"]["by_tier"]
        self.assertEqual(0, tiers[MATCH_CATEGORY]["tp"])
        self.assertEqual(1, tiers[MATCH_LOCATION]["tp"])
        self.assertEqual(0.0, report["metrics"]["unlabelled_per_pr"])

    def test_invalid_comments_now_follows_the_widest_tier_too(self):
        """修掉的口径问题：invalid_comments 原先等于严格档的 fp。

        `invalid_comments = result["fp"]`，而 fp 来自严格档未命中数。于是一个
        "指对行但选了兄弟 CWE"的正确发现会被计成 invalid_comment——字段名
        本身就把它读成了误报。字段名保留（外部报告在读），语义改为按最宽档。
        """
        report = _run([_case("CWE-78")])
        # 严格档 fp = 1（那条 finding 在 cwe-exact 下不算命中）
        self.assertEqual(1, report["metrics"]["by_tier"][MATCH_CWE_EXACT]["fn"])
        # 但它指对了行，所以不是标注外条目。
        self.assertEqual(0.0, report["metrics"]["invalid_comments_per_pr"])
        self.assertEqual(
            report["metrics"]["invalid_comments_per_pr"],
            report["metrics"]["unlabelled_per_pr"],
        )

    def test_a_genuinely_unlabelled_finding_is_counted(self):
        """真正落在标注外的 finding 要计入噪声量，不能一并抹掉。

        行距必须大于 `line_tolerance`（默认 2）。写这条测试时第一版把真值放在
        第 1 行、eval 在第 2 行，落在容差窗口内于是 location 档仍然命中——
        断言失败暴露的是测试设计错误，不是口径错误。
        """
        case = _case("CWE-95")
        # 把真值挪到容差窗口之外，于是 reviewer 报的那条落在标注之外。
        case["diff"] = (
            "--- a/app.py\n"
            "+++ b/app.py\n"
            "@@ -0,0 +1,6 @@\n"
            "+harmless = 1\n"
            "+padding_a = 2\n"
            "+padding_b = 3\n"
            "+padding_c = 4\n"
            "+padding_d = 5\n"
            "+result = eval(payload)\n"
        )
        case["expected_findings"] = [{
            "path": "app.py", "start_line": 1, "end_line": 1,
            "rule_id": "OTHER", "cwe": "CWE-400", "severity": "low",
            "should_comment": True,
        }]
        report = _run([case])
        self.assertEqual(1.0, report["metrics"]["unlabelled_per_pr"])

    def test_the_field_name_discipline_is_visible_in_the_metric_names(self):
        """口径纪律：自动层不存在名为 false_positive 的指标。"""
        report = _run([_case("CWE-95")])
        for name in report["metrics"]:
            self.assertNotIn("false_positive", name)


if __name__ == "__main__":
    unittest.main()
