"""RepairVerifier.compare 的语义回归测试 + stdout 解析测试。

## 修掉的 bug

旧实现：`passed = before.passed and after.passed and ...`
即"基线必须已经全绿"。修复场景里存在缺陷时基线**本该失败**，于是真正修好
bug 的补丁（红 → 绿）被判 blocked，patching.py:190 据此拒绝发布。
修复环节的三档比例全部偏向 blocked。

这些测试锁住四种 before/after 转移的语义，以及证据等级降级的行为。
没有它们，改回聚合判据不会有任何测试报警。
"""
import unittest

from evoagent.outcome_parser import parse_test_outcomes
from evoagent.verifier import RepairVerifier


def _run(passed, outcomes=None):
    """Shape a verify_archive-style result."""
    result = {
        "passed": passed,
        "checks": [{"name": "repository-tests", "passed": passed}],
    }
    if outcomes is not None:
        result["test_outcomes"] = outcomes
    return result


class PerTestTransitionTests(unittest.TestCase):
    """四种转移，逐个锁定。"""

    def test_failed_to_passed_is_a_gain_even_though_the_baseline_was_red(self):
        """这条就是被修掉的 bug：旧实现在这里返回 False。"""
        result = RepairVerifier.compare(
            _run(False, {"t::a": "failed", "t::b": "passed"}),
            _run(True, {"t::a": "passed", "t::b": "passed"}),
        )
        self.assertTrue(result["passed"])
        self.assertEqual(["t::a"], result["fixed_tests"])
        self.assertEqual([], result["regressed_tests"])
        self.assertFalse(result["baseline_passed"])

    def test_passed_to_failed_is_a_regression_and_blocks(self):
        result = RepairVerifier.compare(
            _run(True, {"t::a": "passed", "t::b": "passed"}),
            _run(False, {"t::a": "passed", "t::b": "failed"}),
        )
        self.assertFalse(result["passed"])
        self.assertEqual(["t::b"], result["regressed_tests"])
        self.assertTrue(result["behavioral_regression_detected"])

    def test_failed_to_failed_is_neutral_not_a_regression(self):
        result = RepairVerifier.compare(
            _run(False, {"t::a": "failed"}),
            _run(False, {"t::a": "failed"}),
        )
        self.assertFalse(result["passed"])
        self.assertEqual(["t::a"], result["still_failing_tests"])
        self.assertEqual([], result["regressed_tests"])
        self.assertFalse(result["behavioral_regression_detected"])

    def test_passed_to_passed_yields_no_gain_so_it_does_not_pass(self):
        """无回归但零收益：补丁改了代码却没解决任何问题，没有理由发布。"""
        result = RepairVerifier.compare(
            _run(True, {"t::a": "passed"}),
            _run(True, {"t::a": "passed"}),
        )
        self.assertFalse(result["passed"])
        self.assertEqual([], result["fixed_tests"])
        self.assertEqual([], result["regressed_tests"])

    def test_a_regression_outweighs_any_number_of_fixes(self):
        """回归一票否决：回归是确定的伤害，收益是待验证的改进。

        不做"收益多于回归就放行"的权衡——APR 的核心问题是 patch overfitting
        （测试通过但语义错误），这个方向上必须保守。
        """
        result = RepairVerifier.compare(
            _run(False, {"a": "failed", "b": "failed", "c": "failed", "d": "passed"}),
            _run(False, {"a": "passed", "b": "passed", "c": "passed", "d": "failed"}),
        )
        self.assertFalse(result["passed"])
        self.assertEqual(3, len(result["fixed_tests"]))
        self.assertEqual(["d"], result["regressed_tests"])

    def test_a_disappearing_test_counts_as_a_regression(self):
        """补丁不该让测试凭空不见——可能是删了它，也可能是收集阶段崩了。"""
        result = RepairVerifier.compare(
            _run(False, {"t::a": "failed", "t::b": "passed"}),
            _run(True, {"t::a": "passed"}),
        )
        self.assertFalse(result["passed"])
        self.assertEqual(["t::b"], result["regressed_tests"])

    def test_a_new_failing_test_counts_as_a_regression(self):
        result = RepairVerifier.compare(
            _run(False, {"t::a": "failed"}),
            _run(False, {"t::a": "passed", "t::new": "failed"}),
        )
        self.assertFalse(result["passed"])
        self.assertEqual(["t::new"], result["regressed_tests"])

    def test_a_new_passing_test_is_not_a_gain_by_itself(self):
        """新增通过的测试不算收益：收益的定义是"原本失败的现在通过"。"""
        result = RepairVerifier.compare(
            _run(True, {"t::a": "passed"}),
            _run(True, {"t::a": "passed", "t::new": "passed"}),
        )
        self.assertFalse(result["passed"])
        self.assertEqual([], result["fixed_tests"])

    def test_skipped_tests_do_not_move_the_verdict(self):
        result = RepairVerifier.compare(
            _run(False, {"t::a": "failed", "t::s": "skipped"}),
            _run(True, {"t::a": "passed", "t::s": "skipped"}),
        )
        self.assertTrue(result["passed"])
        self.assertEqual(["t::a"], result["fixed_tests"])


class EvidenceLevelTests(unittest.TestCase):
    def test_missing_test_evidence_can_never_pass(self):
        self.assertFalse(
            RepairVerifier.compare({"passed": True, "checks": []},
                                   {"passed": True, "checks": []})["passed"]
        )

    def test_aggregate_only_accepts_red_to_green(self):
        """降级路径：拿不到 per-test 时要求整套由红转绿。仍比旧实现正确。"""
        result = RepairVerifier.compare(_run(False), _run(True))
        self.assertTrue(result["passed"])
        self.assertEqual("aggregate-only", result["evidence_level"])

    def test_aggregate_only_rejects_green_to_green(self):
        result = RepairVerifier.compare(_run(True), _run(True))
        self.assertFalse(result["passed"])

    def test_aggregate_only_rejects_still_red(self):
        self.assertFalse(RepairVerifier.compare(_run(False), _run(False))["passed"])

    def test_aggregate_only_flags_green_to_red_as_a_regression(self):
        result = RepairVerifier.compare(_run(True), _run(False))
        self.assertFalse(result["passed"])
        self.assertTrue(result["behavioral_regression_detected"])

    def test_evidence_level_is_reported_so_numbers_can_be_split_by_it(self):
        """报数必须按等级分开：聚合等级下"整套仍失败"无法区分部分修好与搞坏。"""
        self.assertEqual(
            "per-test",
            RepairVerifier.compare(
                _run(False, {"a": "failed"}), _run(True, {"a": "passed"})
            )["evidence_level"],
        )

    def test_one_sided_per_test_data_falls_back_to_aggregate(self):
        """只有一侧有 per-test 数据时不能做逐测试对照，必须降级。"""
        result = RepairVerifier.compare(_run(False), _run(True, {"a": "passed"}))
        self.assertEqual("aggregate-only", result["evidence_level"])
        self.assertTrue(result["passed"])


class OutcomeParsingTests(unittest.TestCase):
    def test_pytest_verbose_lines_are_parsed(self):
        outcomes = parse_test_outcomes(
            "tests/test_a.py::test_one PASSED                    [ 33%]\n"
            "tests/test_a.py::test_two FAILED                    [ 66%]\n"
            "tests/test_a.py::test_three SKIPPED                 [100%]\n"
        )
        self.assertEqual(
            {"tests/test_a.py::test_one": "passed",
             "tests/test_a.py::test_two": "failed",
             "tests/test_a.py::test_three": "skipped"},
            outcomes,
        )

    def test_pytest_class_and_parametrised_ids_are_parsed(self):
        outcomes = parse_test_outcomes(
            "tests/test_a.py::TestGroup::test_x PASSED\n"
            "tests/test_a.py::test_y[case-1] FAILED\n"
        )
        self.assertEqual("passed", outcomes["tests/test_a.py::TestGroup::test_x"])
        self.assertEqual("failed", outcomes["tests/test_a.py::test_y[case-1]"])

    def test_pytest_short_summary_lines_are_parsed(self):
        outcomes = parse_test_outcomes(
            "=========================== short test summary info ===========================\n"
            "FAILED tests/test_a.py::test_two - AssertionError: nope\n"
        )
        self.assertEqual({"tests/test_a.py::test_two": "failed"}, outcomes)

    def test_failure_wins_when_a_test_appears_twice(self):
        """pytest 会同时打 verbose 行和 short summary；顺序不该决定结论。"""
        both_orders = (
            "tests/test_a.py::test_two FAILED  [100%]\n"
            "FAILED tests/test_a.py::test_two - boom\n",
            "FAILED tests/test_a.py::test_two - boom\n"
            "tests/test_a.py::test_two FAILED  [100%]\n",
        )
        for output in both_orders:
            self.assertEqual(
                {"tests/test_a.py::test_two": "failed"}, parse_test_outcomes(output)
            )

    def test_unittest_verbose_lines_are_parsed(self):
        outcomes = parse_test_outcomes(
            "test_one (tests.test_a.TestA) ... ok\n"
            "test_two (tests.test_a.TestA) ... FAIL\n"
            "test_three (tests.test_a.TestA) ... ERROR\n"
        )
        self.assertEqual(
            {"tests.test_a.TestA.test_one": "passed",
             "tests.test_a.TestA.test_two": "failed",
             "tests.test_a.TestA.test_three": "failed"},
            outcomes,
        )

    def test_unittest_ids_are_normalised_across_python_versions(self):
        """3.10 与 3.11+ 的 id 格式不同；不归一化会把所有测试误报成回归。"""
        old_style = parse_test_outcomes("test_one (tests.test_a.TestA) ... ok\n")
        new_style = parse_test_outcomes(
            "test_one (tests.test_a.TestA.test_one) ... ok\n"
        )
        self.assertEqual(old_style, new_style)
        self.assertEqual({"tests.test_a.TestA.test_one": "passed"}, old_style)

    def test_unparseable_output_yields_no_outcomes_rather_than_guesses(self):
        self.assertEqual({}, parse_test_outcomes("make: *** [test] Error 1\n"))
        self.assertEqual({}, parse_test_outcomes(""))

    def test_xfail_and_xpass_are_treated_as_skipped(self):
        """xpass 常意味着标记过期，当 passed 会让 fail→pass 统计混入噪声。"""
        outcomes = parse_test_outcomes(
            "tests/test_a.py::test_x XFAIL   [ 50%]\n"
            "tests/test_a.py::test_y XPASS   [100%]\n"
        )
        self.assertEqual(
            {"tests/test_a.py::test_x": "skipped",
             "tests/test_a.py::test_y": "skipped"},
            outcomes,
        )

    def test_a_dot_progress_line_is_not_mistaken_for_a_result(self):
        """pytest 不带 -v 时只打点；解析不出来必须诚实返回空，而不是猜。"""
        self.assertEqual({}, parse_test_outcomes("......F...   [100%]\n"))


class WorktreeIntegrationTests(unittest.TestCase):
    def test_verify_worktree_reports_per_test_outcomes_from_a_real_run(self):
        """端到端：真跑一次 unittest -v，确认 per-test 结果能落到结果字典里。

        用 unittest 而不是 pytest：被测仓库不一定装 pytest，
        而 unittest 在标准库里，这个测试才不会因环境而假失败。
        """
        import os
        import tempfile
        import sys

        with tempfile.TemporaryDirectory(prefix="evoagent-verify-test-") as root:
            with open(os.path.join(root, "test_sample.py"), "w", encoding="utf-8") as handle:
                handle.write(
                    "import unittest\n"
                    "class T(unittest.TestCase):\n"
                    "    def test_ok(self):\n        self.assertTrue(True)\n"
                    "    def test_bad(self):\n        self.assertTrue(False)\n"
                )
            verifier = RepairVerifier(
                test_command="%s -m unittest -v test_sample" % sys.executable,
                timeout_seconds=60,
            )
            result = verifier.verify_worktree(root)

        self.assertFalse(result["passed"])
        self.assertEqual("per-test", result["evidence_level"])
        outcomes = result["test_outcomes"]
        self.assertEqual("passed", outcomes["test_sample.T.test_ok"])
        self.assertEqual("failed", outcomes["test_sample.T.test_bad"])

    def test_no_test_command_reports_aggregate_only(self):
        result = RepairVerifier(test_command="").verify_worktree(".")
        self.assertTrue(result["passed"])
        # 没配测试命令时没有任何逐测试证据，compare 必须拿不到 per-test。
        self.assertEqual({}, result.get("test_outcomes", {}))


if __name__ == "__main__":
    unittest.main()
