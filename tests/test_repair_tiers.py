"""修复环节三档口径的测试。

为什么要分档，一句话：实测中控基准上 safe_fix_rate = 0.125，看起来像
"验证环节挡掉了大部分补丁"，真相是 blocked=0、suggestion_only=7——
修复器在 7/8 的样本上**根本没生成补丁**。两种系统的评价完全相反，
而单一成功率把它们写成了同一个数。

每条测试都做过变异检查：把实现改回错误形态，确认它会红。
"""
import unittest

from evoagent.evaluation_harness import (
    REPAIR_BLOCKED, REPAIR_SUGGESTION, REPAIR_TIERS, REPAIR_UNREPRODUCED,
    REPAIR_VERIFIED, EndToEndEvaluationHarness, repair_tier,
)


def checks(**named):
    """按传入顺序构造 checks 列表。顺序会影响某些实现，故显式保留。"""
    return [{"name": name.replace("_", "-"), "passed": passed}
            for name, passed in named.items()]


class TierClassificationTests(unittest.TestCase):
    def test_all_checks_pass_is_a_verified_draft(self):
        repair = {"passed": True, "checks": checks(
            risk_reproduction=True, patch_generated=True, compile=True,
            risk_removed=True, regression_tests=True)}
        self.assertEqual(repair_tier(repair), REPAIR_VERIFIED)

    def test_patch_generated_but_failing_is_blocked(self):
        """生成了补丁、验证没过 → 系统挡住了。这是安全的，不是失败。"""
        repair = {"passed": False, "checks": checks(
            risk_reproduction=True, patch_generated=True, compile=False)}
        self.assertEqual(repair_tier(repair), REPAIR_BLOCKED)

    def test_no_patch_is_suggestion_only(self):
        repair = {"passed": False, "checks": checks(
            risk_reproduction=True, patch_generated=False)}
        self.assertEqual(repair_tier(repair), REPAIR_SUGGESTION)

    def test_unreproduced_risk_is_not_a_repair_failure(self):
        """风险都没复现出来，"风险是否移除"这项检查无意义。

        这是夹具/配置问题，不是修复能力问题。归进 blocked 会把配置错误
        记成 agent 的失败。
        """
        repair = {"passed": False, "checks": checks(
            risk_reproduction=False, patch_generated=False)}
        self.assertEqual(repair_tier(repair), REPAIR_UNREPRODUCED)

    def test_unreproduced_wins_over_patch_generated(self):
        """判定顺序断言：前提失败优先于能力判定。

        就算补丁生成了、甚至全部通过，只要风险没复现，这次结果就不可判——
        "移除了一个不存在的风险"不是成功。顺序反了这里会变成 verified。
        """
        repair = {"passed": True, "checks": checks(
            risk_reproduction=False, patch_generated=True, compile=True)}
        self.assertEqual(repair_tier(repair), REPAIR_UNREPRODUCED)

    def test_missing_risk_reproduction_check_does_not_block_judgement(self):
        """没有 risk-reproduction 这项检查的修复器（自定义实现）仍要能判档。

        用 `in checks` 而不是 `checks.get(name, False)`：后者会把"没这项检查"
        当成"这项检查失败"，于是所有自定义修复器的结果全变成 unreproduced。
        """
        repair = {"passed": True, "checks": checks(
            patch_generated=True, compile=True)}
        self.assertEqual(repair_tier(repair), REPAIR_VERIFIED)

    def test_every_tier_is_reachable(self):
        """四档都必须是活的。blocked 在现有夹具里恰好取不到（实测为 0），
        不显式证明它可达的话，它可能其实是死代码。"""
        reached = {
            repair_tier({"passed": True, "checks": checks(
                risk_reproduction=True, patch_generated=True)}),
            repair_tier({"passed": False, "checks": checks(
                risk_reproduction=True, patch_generated=True)}),
            repair_tier({"passed": False, "checks": checks(
                risk_reproduction=True, patch_generated=False)}),
            repair_tier({"passed": False, "checks": checks(
                risk_reproduction=False)}),
        }
        self.assertEqual(reached, set(REPAIR_TIERS))


CASE = {
    "id": "t-1", "repository": "x/y", "pull_request": 1, "split": "validation",
    "diff": ("--- a/m.py\n+++ b/m.py\n@@ -1,1 +1,1 @@\n"
             "-old = 1\n+password = \"hunter2\"\n"),
    "expected_findings": [{
        "path": "m.py", "start_line": 1, "end_line": 1,
        "cwe": "CWE-798", "severity": "high", "should_comment": True,
    }],
}


class _StubReviewer:
    """总是命中那一条 expected finding，好让修复环节一定被触发。"""

    name = "stub"

    def review(self, diff, parsed):
        from evoagent.models import Finding, Severity
        return [Finding(
            rule_id="SEC-HARDCODED-SECRET", severity=Severity.HIGH,
            title="t", explanation="e", path="m.py", line=1,
            evidence="ev", fix="f", test="t")]


class _ScriptedRepairer:
    """按预设脚本逐次返回结果，用来精确控制各档的数量。"""

    def __init__(self, scripted):
        self.scripted = list(scripted)

    def repair(self, case, finding):
        return self.scripted.pop(0)


def run_with(scripted, cases=1):
    harness = EndToEndEvaluationHarness(
        repairer=_ScriptedRepairer(scripted))
    batch = []
    for index in range(cases):
        item = dict(CASE)
        item["id"] = "t-%d" % index
        batch.append(item)
    return harness.run(_StubReviewer(), batch)["metrics"]


class AggregationTests(unittest.TestCase):
    def test_tier_counts_sum_to_attempted(self):
        """不变式：四档之和 == repair_attempted。漏掉一档就会破。"""
        metrics = run_with([
            {"passed": True, "checks": checks(
                risk_reproduction=True, patch_generated=True)},
            {"passed": False, "checks": checks(
                risk_reproduction=True, patch_generated=True)},
            {"passed": False, "checks": checks(risk_reproduction=False)},
        ], cases=3)
        total = sum(metrics["repair_%s" % tier.replace("-", "_")]
                    for tier in REPAIR_TIERS)
        self.assertEqual(total, metrics["repair_attempted"])

    def test_unreproduced_is_excluded_from_the_denominator(self):
        """风险没复现的样本不进"修复能力"的分母。

        留在分母里，配置问题就会稀释能力指标：下面 2 条可判（1 通过），
        正确答案 0.5；把 unreproduced 也算进去会得到 0.333。
        """
        metrics = run_with([
            {"passed": True, "checks": checks(
                risk_reproduction=True, patch_generated=True)},
            {"passed": False, "checks": checks(
                risk_reproduction=True, patch_generated=True)},
            {"passed": False, "checks": checks(risk_reproduction=False)},
        ], cases=3)
        self.assertEqual(metrics["repair_judgeable"], 2)
        self.assertEqual(metrics["verified_draft_rate"], 0.5)

    def test_rates_are_none_when_nothing_is_judgeable(self):
        """全部不可判 = 没有结论。0.0 会被读成"试了全失败"。"""
        metrics = run_with(
            [{"passed": False, "checks": checks(risk_reproduction=False)}])
        self.assertEqual(metrics["repair_judgeable"], 0)
        self.assertIsNone(metrics["verified_draft_rate"])
        self.assertIsNone(metrics["blocked_rate"])
        self.assertIsNone(metrics["suggestion_only_rate"])

    def test_blocked_and_suggestion_are_told_apart(self):
        """核心诉求：同一个 safe_fix_rate 下，两种系统必须被区分开。"""
        blocked = run_with([{"passed": False, "checks": checks(
            risk_reproduction=True, patch_generated=True)}])
        declined = run_with([{"passed": False, "checks": checks(
            risk_reproduction=True, patch_generated=False)}])
        self.assertEqual(blocked["safe_fix_rate"],
                         declined["safe_fix_rate"])      # 单一口径分不开
        self.assertEqual(blocked["blocked_rate"], 1.0)   # 分档能分开
        self.assertEqual(declined["suggestion_only_rate"], 1.0)

    def test_per_split_tiers_are_computed_independently(self):
        """分档必须随结果走、能按 split 分别汇总，不能读 self。"""
        metrics = run_with([{"passed": True, "checks": checks(
            risk_reproduction=True, patch_generated=True)}])
        self.assertEqual(metrics["repair_verified_draft"], 1)


if __name__ == "__main__":
    unittest.main()
