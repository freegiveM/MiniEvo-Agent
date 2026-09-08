"""`RegressionEvaluator` 行容差口径的测试。

## 修的是什么

`RegressionEvaluator.run` 原来是**精确行匹配**（容差 0），而同一个项目里
`evaluation_harness.one_to_one_match` 默认 `line_tolerance=2`，
`docs/alert-rubric.md` 也明写标注口径的 ±2 必须与评测的 `line_tolerance`
一致。两把尺子刻度不同，两边算出来的 recall 就不能相互解释。

不是理论问题。D6 首次全量 replay 实测：18 条 high/critical 期望里，有 4 条
reviewer 明明定位到了同一处缺陷，只因行号差 1-7 行被判成漏报
（paramiko-pr-1065 报 214 行、期望 213；mitmproxy-pr-8326 报 54、期望 53）。
对齐到容差 2 后 `high_severity_recall` 从 2/18=0.11 变成 5/18=0.28，
**没有重跑任何一次 API 调用**——差的全部是尺子。

## 为什么这不是"放宽标准"

diff 里相邻几行属于同一个语句、同一个缺陷是常态。要求行号精确相等，测的是
"reviewer 报的是缺陷的第几行"，不是"reviewer 有没有发现这个缺陷"。容差仍然
是有限的（2 行），报到十几行开外照样算漏——下面
`test_a_finding_outside_the_window_is_still_a_miss` 钉住这条。

而且容差是双向生效的：多报的 finding 落在窗口内会被配成真阳性（recall 涨），
落在窗口外仍然计假阳性（precision 不会被免费抬高）。
"""
import unittest

from evoagent.evolution import RegressionEvaluator, _line_distance
from evoagent.models import Finding, Severity

DIFF = "--- a/app.py\n+++ b/app.py\n@@ -0,0 +1 @@\n+x = eval(p)\n"


class Fixed:
    """按构造时给定的 (path, line, severity) 列表报 finding 的假 reviewer。"""

    name = "fixed"

    def __init__(self, findings):
        self._findings = findings

    def review(self, diff, parsed):
        return [
            Finding(
                rule_id="R%d" % index, severity=Severity(severity),
                title="t", explanation="e", path=path, line=line,
                evidence="ev", fix="f", test="t",
            )
            for index, (path, line, severity) in enumerate(self._findings)
        ]


def _run(expected, reported, tolerance=2):
    case = {"name": "c", "diff": DIFF, "expected": expected}
    evaluator = RegressionEvaluator(
        lambda prompt: Fixed(reported), line_tolerance=tolerance,
    )
    metrics = evaluator.run("prompt", [case])
    # run() 把 review() 抛的异常吞进 errors 并把整条 case 记成全漏。不显式
    # 断言就会出现"测试因为假 reviewer 构造错误而通过"——它期望的也是 0 命中，
    # 两种 0 长得一模一样。这一行保证测到的是匹配逻辑，不是异常分支。
    assert not metrics["errors"], metrics["errors"]
    # 混淆矩阵只在 case_results 里，顶层没有 tp/fp/fn 字段。单 case 直接取。
    metrics.update(metrics["case_results"][0])
    return metrics


def _expect(line, end_line=None, severity="low"):
    item = {"path": "app.py", "line": line, "min_severity": severity}
    if end_line is not None:
        item["end_line"] = end_line
    return item


class LineDistanceTests(unittest.TestCase):
    def test_inside_the_interval_is_zero_not_distance_to_an_edge(self):
        """长区间的中段不能因为离两端都远就被判成"远"。"""
        self.assertEqual(0, _line_distance(50, 10, 90))

    def test_distance_is_measured_to_the_nearest_edge(self):
        self.assertEqual(3, _line_distance(7, 10, 90))
        self.assertEqual(5, _line_distance(95, 10, 90))

    def test_a_degenerate_interval_behaves_like_a_point(self):
        self.assertEqual(2, _line_distance(12, 10, 10))


class LineToleranceMatchingTests(unittest.TestCase):
    def test_an_off_by_one_finding_now_counts_as_a_hit(self):
        """D6 实测的形态：期望 213，reviewer 报 214。"""
        metrics = _run([_expect(213)], [("app.py", 214, "low")])
        self.assertEqual(1, metrics["tp"])
        self.assertEqual(0, metrics["fn"])
        self.assertEqual(0, metrics["fp"])

    def test_a_finding_outside_the_window_is_still_a_miss(self):
        """容差是有限的。报到窗口外照样是漏报 + 假阳性，两头都记账。"""
        metrics = _run([_expect(213)], [("app.py", 220, "low")])
        self.assertEqual(0, metrics["tp"])
        self.assertEqual(1, metrics["fn"])
        self.assertEqual(1, metrics["fp"])

    def test_the_window_boundary_is_inclusive(self):
        self.assertEqual(1, _run([_expect(10)], [("app.py", 12, "low")])["tp"])
        self.assertEqual(0, _run([_expect(10)], [("app.py", 13, "low")])["tp"])

    def test_tolerance_zero_restores_the_old_exact_behaviour(self):
        """旧行为仍然可达——容差是参数，不是写死的新默认。"""
        metrics = _run([_expect(213)], [("app.py", 214, "low")], tolerance=0)
        self.assertEqual(0, metrics["tp"])

    def test_a_negative_tolerance_is_clamped_rather_than_inverting_matching(self):
        evaluator = RegressionEvaluator(lambda prompt: Fixed([]), line_tolerance=-5)
        self.assertEqual(0, evaluator.line_tolerance)

    def test_a_finding_inside_the_expected_interval_matches(self):
        """expected_finding 是行区间，报在中段不该算漏。"""
        metrics = _run([_expect(10, end_line=40)], [("app.py", 25, "low")])
        self.assertEqual(1, metrics["tp"])

    def test_a_different_file_never_matches_however_close_the_line_is(self):
        metrics = _run([_expect(213)], [("other.py", 213, "low")])
        self.assertEqual(0, metrics["tp"])
        self.assertEqual(1, metrics["fp"])


class NearestFirstPairingTests(unittest.TestCase):
    def test_the_nearest_candidate_wins_over_the_more_severe_one(self):
        """两条期望挨得近时，配对必须先按距离。

        若先按严重度挑（原实现的 max(SEVERITY_RANK)），一条报在容差边缘的
        critical 会抢走本该属于近处期望的配对，把两条本来都能命中的期望
        压成一命中一漏报。
        """
        metrics = _run(
            [_expect(10), _expect(12)],
            [("app.py", 10, "low"), ("app.py", 12, "critical")],
        )
        self.assertEqual(2, metrics["tp"])
        self.assertEqual(0, metrics["fn"])

    def test_one_finding_cannot_be_credited_to_two_expectations(self):
        """一报一配。一条 finding 落在两条期望的窗口里也只能算一次。"""
        metrics = _run([_expect(10), _expect(11)], [("app.py", 10, "low")])
        self.assertEqual(1, metrics["tp"])
        self.assertEqual(1, metrics["fn"])


class SeverityUnderToleranceTests(unittest.TestCase):
    def test_a_tolerated_match_still_has_to_meet_the_severity_floor(self):
        """容差只放宽定位，不放宽严重度——两件事不能混为一谈。"""
        metrics = _run([_expect(213, severity="high")], [("app.py", 214, "low")])
        self.assertEqual(1, metrics["tp"])
        self.assertEqual(0.0, metrics["high_severity_recall"])
        self.assertEqual(0.0, metrics["severity_accuracy"])

    def test_a_tolerated_match_at_or_above_the_floor_counts_for_high_recall(self):
        metrics = _run([_expect(213, severity="high")], [("app.py", 214, "critical")])
        self.assertEqual(1.0, metrics["high_severity_recall"])


class CleanCaseIsolationTests(unittest.TestCase):
    def test_tolerance_does_not_touch_clean_cases(self):
        """负样本没有 expected，行容差碰不到它——自洽性检查。

        D6 全量 replay 上 clean_accuracy 在容差 0/2 两次计算里完全相同
        （0.7308），正是这条性质的实测印证。
        """
        clean = {"name": "clean", "diff": DIFF, "expected": []}
        evaluator = RegressionEvaluator(
            lambda prompt: Fixed([("app.py", 1, "low")]), line_tolerance=2,
        )
        metrics = evaluator.run("prompt", [clean])
        self.assertEqual(1, metrics["clean_cases"])
        self.assertEqual(0.0, metrics["clean_accuracy"])


if __name__ == "__main__":
    unittest.main()