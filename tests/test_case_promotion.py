"""轨道 F：反馈提升成评测样本时的口径。

每一条测试对应交接文档第 5 节的一个口径问题，或对应一个"这样写会造出一个
方向反的样本"的形态。测试名说的是结论，不是操作。
"""
import json
import os
import tempfile
import unittest

from evoagent.case_promotion import (
    REFUSED_CATEGORIES, apply_promotions, plan_promotions, promote_case,
    split_index,
)
from evoagent.store import TaskStore

DIRTY_DIFF = """--- a/app.py
+++ b/app.py
@@ -1,2 +1,4 @@
 import os
+def read(name):
+    return open("/data/" + name).read()
"""

CLEAN_DIFF = """--- a/docs.py
+++ b/docs.py
@@ -1,2 +1,4 @@
 import os
+def title():
+    return "hello"
"""


def _positive_case(case_id="case-1", repository="acme/api", split="validation"):
    return {
        "id": case_id, "repository": repository, "pull_request": 7,
        "split": split, "diff": DIRTY_DIFF,
        "expected_findings": [{
            "path": "app.py", "start_line": 3, "end_line": 3,
            "severity": "high", "cwe": "CWE-22", "should_comment": True,
        }],
    }


def _clean_case(case_id="clean-1", repository="acme/docs", split="validation"):
    return {
        "id": case_id, "repository": repository, "pull_request": 9,
        "split": split, "diff": CLEAN_DIFF, "expected_findings": [],
    }


def _failure_case(category, case_id="case-1", identifier=11, **finding):
    # 与 `feedback_import.build_payload` 一致：cwe 在源标注有的时候会带上，
    # rule_id 只在人工填了的时候才有。
    payload_finding = {
        "path": "app.py", "line": 3, "severity": "high", "cwe": "CWE-22"}
    payload_finding.update(finding)
    return {
        "id": identifier,
        "task_id": "d6-feedback-%s" % identifier,
        "category": category,
        "resolved": 0,
        "payload": {
            "finding": payload_finding,
            "note": "",
            "provenance": {
                "source": "d6-replay-human-confirmed",
                "candidate_id": "abc123",
                "case_id": case_id,
                "kind": "unmatched_expected",
                "label": "should-have-caught",
            },
        },
    }


class SplitIndexTests(unittest.TestCase):
    def test_a_repository_keeps_the_side_it_already_has(self):
        index = split_index([
            _positive_case("a", "acme/api", "validation"),
            _positive_case("b", "acme/web", "holdout"),
        ])
        self.assertEqual({"acme/api": "validation", "acme/web": "holdout"}, index)

    def test_a_corpus_that_already_crosses_the_boundary_is_refused(self):
        """在坏语料上继续提升只会把污染扩大。

        下游那道 `test_repositories_do_not_cross_the_split_boundary` 检查的
        是语料而不是提升结果，不会替我们发现。
        """
        with self.assertRaises(ValueError) as caught:
            split_index([
                _positive_case("a", "acme/api", "validation"),
                _positive_case("b", "acme/api", "holdout"),
            ])
        self.assertIn("acme/api", str(caught.exception))

    def test_a_case_without_a_repository_is_skipped_not_keyed_as_empty(self):
        index = split_index([{"id": "x", "repository": "", "split": "validation"}])
        self.assertEqual({}, index)


class MissedIssuePromotionTests(unittest.TestCase):
    def test_a_confirmed_missed_issue_becomes_a_positive_sample(self):
        cases = [_positive_case()]
        verdict = promote_case(_failure_case("missed_issue"), cases)

        self.assertTrue(verdict["promotable"], verdict["reason"])
        promoted = verdict["case"]
        self.assertEqual("validation", promoted["split"])
        self.assertEqual(DIRTY_DIFF, promoted["diff"])
        self.assertEqual(
            [{"path": "app.py", "line": 3, "min_severity": "high",
              "cwe": "CWE-22"}],
            promoted["expected"],
        )

    def test_the_severity_becomes_a_min_severity_floor(self):
        """字段名不同：评测样本用 `min_severity`（下限，`>=` 判定）。

        缺失时**不**补 "low"：把"不知道多严重"写成"最轻"会让
        `high_severity_recall` 的分母少一个，而那是一道受保护指标。
        """
        cases = [_positive_case()]
        broken = _failure_case("missed_issue")
        broken["payload"]["finding"].pop("severity")
        verdict = promote_case(broken, cases)

        self.assertFalse(verdict["promotable"])
        self.assertIn("severity", verdict["reason"])

    def test_a_rule_id_is_only_carried_when_a_human_filled_it(self):
        """cwe 不顶替 rule_id，理由见 feedback_import.build_payload。"""
        cases = [_positive_case()]
        without = promote_case(_failure_case("missed_issue"), cases)["case"]
        self.assertNotIn("rule_id", without["expected"][0])

        with_rule = promote_case(
            _failure_case("missed_issue", rule_id="SEC-PATH-TRAVERSAL"), cases,
        )["case"]
        self.assertEqual(
            "SEC-PATH-TRAVERSAL", with_rule["expected"][0]["rule_id"])

    def test_a_finding_off_the_added_lines_is_refused_not_snapped(self):
        """挪过行号的样本看起来完全正常，而它断言的位置不是人确认的那个。"""
        cases = [_positive_case()]
        verdict = promote_case(
            _failure_case("missed_issue", line=99), cases)

        self.assertFalse(verdict["promotable"])
        self.assertIn("validate_case", verdict["reason"])


class FalsePositivePromotionTests(unittest.TestCase):
    """**本组是第 5 节口径 2 真正的坑。**"""

    def test_a_clean_source_case_becomes_a_negative_sample(self):
        cases = [_clean_case()]
        verdict = promote_case(
            _failure_case("false_positive", case_id="clean-1"), cases)

        self.assertTrue(verdict["promotable"], verdict["reason"])
        self.assertEqual([], verdict["case"]["expected"])

    def test_a_source_case_carrying_a_seed_defect_is_refused(self):
        """口径 2 原文"false_positive 该进负样本"只在源样本本身干净时成立。

        反转 fix PR 的 diff 里含着种子缺陷。配上空 `expected_findings` 写进
        评测集，断言的是"这里不该报任何东西"——而那是假的，于是"报对了真
        缺陷"会被记成 clean_accuracy 上的一次失败，方向正好教反。
        """
        cases = [_positive_case()]
        verdict = promote_case(
            _failure_case("false_positive", case_id="case-1"), cases)

        self.assertFalse(verdict["promotable"])
        self.assertIn("seed defect", verdict["reason"])
        self.assertIn("clean-accuracy failure", verdict["reason"])


class RefusedCategoryTests(unittest.TestCase):
    def test_bad_fix_is_refused_because_there_is_no_fix_quality_truth(self):
        """第 13 节 B 的选项 3：显式记为局限，不静默跳过。

        一条被静默丢掉的反馈和一条被评估过后判定不该提升的反馈，在报告上
        长得一模一样。
        """
        verdict = promote_case(
            _failure_case("bad_fix"), [_positive_case()])

        self.assertFalse(verdict["promotable"])
        self.assertIn("no ground truth for fix quality", verdict["reason"])

    def test_every_refused_category_states_a_reason(self):
        for category, reason in REFUSED_CATEGORIES.items():
            self.assertTrue(reason.strip(), category)

    def test_accepted_and_execution_error_are_refused_too(self):
        for category in ("accepted", "execution_error"):
            verdict = promote_case(
                _failure_case(category), [_positive_case()])
            self.assertFalse(verdict["promotable"], category)
            self.assertTrue(verdict["reason"], category)

    def test_an_unconfirmed_category_never_reaches_the_evaluation_set(self):
        """`merged_without_addressing` 是推断出来的类别（轨道 C）。

        它被 `HUMAN_CONFIRMED_CATEGORIES` 挡在提示词进化之外；这里必须同样
        挡住，否则它绕过那道白名单从评测集这一侧进来了。
        """
        verdict = promote_case(
            _failure_case("merged_without_addressing"), [_positive_case()])

        self.assertFalse(verdict["promotable"])
        self.assertIn("HUMAN_CONFIRMED_CATEGORIES", verdict["reason"])


class SplitBoundaryTests(unittest.TestCase):
    def test_a_holdout_repository_is_refused(self):
        """holdout 的反馈进了进化回路就等于拿隐藏集调参。

        `derive_candidates` 的 `splits` 默认只取 validation，但那个默认值
        可以被 `--splits` 覆盖，所以这里再拦一道。
        """
        cases = [_positive_case(split="holdout")]
        verdict = promote_case(_failure_case("missed_issue"), cases)

        self.assertFalse(verdict["promotable"])
        self.assertIn("holdout", verdict["reason"])

    def test_a_repository_absent_from_the_corpus_is_refused_not_guessed(self):
        cases = [_positive_case("other", "acme/web")]
        verdict = promote_case(
            _failure_case("missed_issue", case_id="other"),
            cases, splits={},
        )

        self.assertFalse(verdict["promotable"])
        self.assertIn("no existing side", verdict["reason"])

    def test_a_source_case_missing_from_the_corpus_is_refused(self):
        """diff 必须来自语料，不能来自反馈里的片段。

        `diff_excerpt` 只是目标行附近几行；拿它当完整 diff 会给评测埋一个
        截断的输入，而它看起来完全正常。
        """
        verdict = promote_case(
            _failure_case("missed_issue", case_id="nope"), [_positive_case()])

        self.assertFalse(verdict["promotable"])
        self.assertIn("no diff to promote", verdict["reason"])


class PlanTests(unittest.TestCase):
    def test_refusals_are_reported_per_case_with_a_reason(self):
        """"7 条被拒"不说明该做什么；理由不同则行动完全不同。"""
        cases = [_positive_case(), _clean_case()]
        plan = plan_promotions([
            _failure_case("missed_issue", identifier=1),
            _failure_case("bad_fix", identifier=2),
            _failure_case("false_positive", case_id="case-1", identifier=3),
        ], cases)

        self.assertEqual(1, plan["promoted_count"])
        self.assertEqual(2, plan["refused_count"])
        for item in plan["refused"]:
            self.assertTrue(item["reason"])
        self.assertEqual({"missed_issue": 1}, plan["by_category"])

    def test_the_clean_sample_count_is_reported(self):
        """clean 侧为 0 时 `clean_accuracy` 在进化回路里没有分母。

        那是一道空门禁，与 holdout 的 high_severity_recall 同一形态——必须
        在报告里看得出来。
        """
        cases = [_positive_case(), _clean_case()]
        plan = plan_promotions([
            _failure_case("missed_issue", identifier=1),
        ], cases)
        self.assertEqual(0, plan["clean_samples"])

        plan = plan_promotions([
            _failure_case("false_positive", case_id="clean-1", identifier=2),
        ], cases)
        self.assertEqual(1, plan["clean_samples"])

    def test_promoted_names_are_distinct_per_candidate(self):
        cases = [_positive_case(), _positive_case("case-2", "acme/api")]
        first = _failure_case("missed_issue", identifier=1)
        second = _failure_case("missed_issue", case_id="case-2", identifier=2)
        second["payload"]["provenance"]["candidate_id"] = "def456"
        plan = plan_promotions([first, second], cases)

        names = {case["name"] for case in plan["promoted"]}
        self.assertEqual(2, len(names))


class ApplyTests(unittest.TestCase):
    def setUp(self):
        handle, self.path = tempfile.mkstemp(suffix=".db")
        os.close(handle)
        self.store = TaskStore(self.path)

    def tearDown(self):
        os.unlink(self.path)

    def _plan(self):
        return plan_promotions(
            [_failure_case("missed_issue", identifier=1)], [_positive_case()])

    def test_a_promoted_case_lands_in_the_evaluation_set(self):
        result = apply_promotions(self.store, self._plan())

        self.assertEqual(1, result["written_count"])
        self.assertEqual([], result["conflicts"])
        stored = self.store.list_evaluation_cases(split="validation", limit=50)
        self.assertEqual(1, len(stored))
        self.assertEqual("d6-feedback-promoted", stored[0]["source"])

    def test_rerunning_is_idempotent(self):
        """脚本会被重跑。同名同内容不该被计成一次新写入。"""
        apply_promotions(self.store, self._plan())
        second = apply_promotions(self.store, self._plan())

        self.assertEqual(0, second["written_count"])
        self.assertEqual(1, len(second["already_present"]))
        self.assertEqual(
            1, len(self.store.list_evaluation_cases(split="validation", limit=50)))

    def test_a_name_collision_with_different_content_is_a_conflict_not_a_silent_overwrite(self):
        """同名不同内容意味着这次算出了不同的样本内容（比如语料被改过）。

        静默覆盖会让评测集与它声称的来源不一致，而这在报告上看不出来。
        """
        apply_promotions(self.store, self._plan())
        plan = self._plan()
        plan["promoted"][0]["diff"] = CLEAN_DIFF
        plan["promoted"][0]["expected"] = []
        result = apply_promotions(self.store, plan)

        self.assertEqual(0, result["written_count"])
        self.assertEqual(1, len(result["conflicts"]))
        self.assertIn("immutable", result["conflicts"][0]["error"])


class ScriptReachabilityTests(unittest.TestCase):
    """写好了没人调用等于没写——这个仓库已经犯过两次（`tiered_match` 零调用方、
    `shadow_ready` 无人消费）。"""

    def _script(self):
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        with open(os.path.join(root, "scripts", "promote_failure_cases.py"),
                  encoding="utf-8") as handle:
            return handle.read()

    def test_the_script_calls_both_layers(self):
        script = self._script()
        self.assertIn("plan_promotions(", script)
        self.assertIn("apply_promotions(", script)

    def test_writing_to_the_evaluation_set_requires_a_plan_on_disk(self):
        """写库的那次一定留下一份计划，事后能回答"这条样本凭什么在评测集里"。"""
        script = self._script()
        self.assertIn("--out is required unless --dry-run", script)

    def test_the_clean_corpus_is_a_separate_flag(self):
        """不给负样本语料时 false_positive 全被拒，报告里的理由会是误导的。"""
        self.assertIn("--clean-dataset", self._script())


if __name__ == "__main__":
    unittest.main()