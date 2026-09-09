"""轨道 C：PR 合并推断出的反馈，以及它**不**被允许做的事。

## 为什么这批测试的重点在"不做什么"

推断信号很容易写成一条捷径：PR 合并了 → 我们报的问题没人改 → 判成
`false_positive` → 喂给提示词进化。每一步都像是合理的，合起来是一条
把弱代理信号直接接到门禁上的通路。

而门禁拦不住这类污染。门禁看的是"候选在验证集上是否更好"，它无法
分辨提示词里那句"少报这类问题"来自人类确认还是来自一次赶版本的合并。
污染发生在信号进入之前，所以只能在信号入口挡。

因此这个文件里绝大多数断言是负向的：默认关闭、关闭未合并不记、
推断类别不进生成器、不复用人工类别名。正向路径只有一条。

## 这个信号的真实含义

"PR 带着我们报的 N 条问题被合并了"。至少三条混淆同时存在：维护者可能
明知有问题仍合并；报告可能压根没回写到 PR 上（`auto_post_review` 关着
时没人看见过）；合并前的 commit 可能已经顺手修掉了。所以它落盘、计数、
可供人工分诊，但不自动驱动任何东西。
"""
import os
import tempfile
import unittest

from evoagent.config import Settings
from evoagent.evolution import EvolutionEngine
from evoagent.service import ReviewService

DIFF = "--- a/a.py\n+++ b/a.py\n@@ -1 +1 @@\n-old\n+eval(data)\n"


def _closed_payload(merged=True, repository="org/repo", number=1):
    return {
        "action": "closed",
        "number": number,
        "repository": {"full_name": repository},
        "pull_request": {
            "merged": merged,
            "merge_commit_sha": "deadbeef",
            "issue_url": "https://api.github.com/repos/org/repo/issues/1",
        },
    }


class _Base(unittest.TestCase):
    infer = True

    def setUp(self):
        handle, self.path = tempfile.mkstemp(suffix=".db")
        os.close(handle)
        self.settings = Settings(
            host="127.0.0.1", port=8080, db_path=self.path, max_diff_bytes=10000,
            max_steps=8, timeout_seconds=10, llm_base_url="", llm_api_key="",
            llm_model="", github_webhook_secret="", github_token="",
            auto_post_review=False, infer_feedback_from_merge=self.infer,
        )
        self.service = ReviewService(self.settings)

    def tearDown(self):
        self.service.queue.close()
        if os.path.exists(self.path):
            os.unlink(self.path)

    def _reviewed_pr(self, number=1, diff=DIFF):
        """先跑一次真实审查，让这个 PR 有一份可比对的报告。"""
        return self.service.create_review("org/repo", diff, number)

    def _closed(self, **kwargs):
        return self.service.handle_github_pull_request(
            _closed_payload(**kwargs), "delivery-%s" % id(kwargs), "sha256", "default",
        )


class DefaultOffTests(_Base):
    infer = False

    def test_the_inference_is_off_by_default(self):
        """默认值的方向决定了忘记配置的后果。

        推断反馈的置信度低于人工确认。默认开启意味着任何一个接了 webhook
        的部署都会静默开始积累弱信号，而使用者没有做出过这个选择。
        """
        self.assertFalse(Settings.__dataclass_fields__[
            "infer_feedback_from_merge"].default)

    def test_a_merged_pr_records_nothing_while_disabled(self):
        review = self._reviewed_pr()
        result = self._closed(merged=True)
        self.assertTrue(result["ignored"])
        self.assertIn("EVOAGENT_INFER_FEEDBACK_FROM_MERGE", result["reason"])
        self.assertEqual(
            [], self.service.store.list_task_failure_cases(review["task_id"], "default"),
        )


class InferenceTests(_Base):
    def test_a_merged_pr_with_findings_records_a_weak_signal(self):
        review = self._reviewed_pr()
        result = self._closed(merged=True)

        self.assertTrue(result["recorded"])
        self.assertEqual("inferred-from-merge", result["source"])
        cases = self.service.store.list_task_failure_cases(review["task_id"], "default")
        self.assertEqual(1, len(cases))
        payload = cases[0]["payload"]
        self.assertEqual("inferred-from-merge", payload["source"])
        self.assertEqual("weak", payload["confidence"])
        self.assertEqual("SEC-EVAL", payload["findings"][0]["rule_id"])

    def test_the_category_is_not_one_of_the_human_confirmed_names(self):
        """刻意不叫 false_positive。

        `record_feedback` 的那四个类别意味着"人看过并确认了"。把推断结果
        写进同一个字段，下游就再也分不出哪一条有人背书——而这正是
        `severity_labelling` 里同一条硬约束：不同置信度的标注不能合并成
        同一个字段。
        """
        self._reviewed_pr()
        result = self._closed(merged=True)
        self.assertEqual("merged_without_addressing", result["category"])
        self.assertNotIn(
            result["category"],
            {"false_positive", "missed_issue", "bad_fix", "accepted"},
        )

    def test_whether_the_review_was_visible_is_recorded(self):
        """`auto_post_review` 关着时，报告压根没出现在 PR 上。

        此时"合并了"与"我们报的问题被无视了"没有因果关系——没人看见过
        它。这个前提必须跟着信号一起落盘，否则事后无法判断这条推断有多少
        解释力。
        """
        self._reviewed_pr()
        self._closed(merged=True)
        cases = self.service.store.list_failure_cases(True, 10, "default")
        self.assertFalse(cases[0]["payload"]["review_was_visible_on_pr"])

    def test_a_pr_closed_without_merging_records_nothing(self):
        """弃掉的 PR 与代码质量基本无关，算成误报确认纯粹是噪声。"""
        review = self._reviewed_pr()
        result = self._closed(merged=False)
        self.assertTrue(result["ignored"])
        self.assertIn("without merging", result["reason"])
        self.assertEqual(
            [], self.service.store.list_task_failure_cases(review["task_id"], "default"),
        )

    def test_a_clean_review_merged_is_not_recorded_as_a_failure(self):
        """审出 0 条 + 合并了，是弱**正**例，不是失败案例。

        把它写进同一个类别会与"报了但被无视"混成一个数，那个数就再也
        没有方向性了。
        """
        self._reviewed_pr(diff="--- a/a.py\n+++ b/a.py\n@@ -1 +1 @@\n-old\n+x = 1\n")
        result = self._closed(merged=True)
        self.assertFalse(result["recorded"])
        self.assertIn("no findings", result["reason"])

    def test_a_merge_without_any_review_task_is_ignored_not_invented(self):
        """没审过的 PR 合并了，什么也推断不出来。"""
        result = self._closed(merged=True, number=999)
        self.assertTrue(result["ignored"])
        self.assertIn("no successful review task", result["reason"])

    def test_the_latest_review_is_used_not_the_first(self):
        """`synchronize` 会为同一个 PR 反复建任务。

        早先几轮审的是已经被后续 commit 改掉的代码，拿它们推断"报告对不
        对"是在评价一份已经过期的报告。
        """
        first = self._reviewed_pr(number=7)
        second = self.service.create_review("org/repo", DIFF, 7)
        self.assertNotEqual(first["task_id"], second["task_id"])
        result = self._closed(merged=True, number=7)
        self.assertEqual(second["task_id"], result["task_id"])

    def test_a_duplicate_delivery_does_not_double_count(self):
        """同一个 delivery 重放两次只应记一条。

        webhook 幂等由 `claim_webhook` 提供，这里钉住 closed 分支同样走了
        那道闸——否则 GitHub 的自动重试会让一次合并变成 N 条信号。
        """
        review = self._reviewed_pr()
        payload = _closed_payload(merged=True)
        first = self.service.handle_github_pull_request(
            payload, "same-delivery", "sha256", "default")
        second = self.service.handle_github_pull_request(
            payload, "same-delivery", "sha256", "default")
        self.assertTrue(first["recorded"])
        self.assertTrue(second.get("duplicate"))
        self.assertEqual(
            1, len(self.service.store.list_task_failure_cases(review["task_id"], "default")),
        )

    def test_an_invalid_payload_raises_rather_than_recording_a_blank(self):
        with self.assertRaises(ValueError):
            self.service.handle_github_pull_request(
                {"action": "closed", "number": None, "repository": {}},
                "bad-delivery", "sha256", "default",
            )


class ConsumptionTests(_Base):
    """推断信号进不了提示词进化——这是本轨道最要紧的一条。"""

    def test_the_inferred_category_is_excluded_from_candidate_generation(self):
        review = self._reviewed_pr()
        self._closed(merged=True)
        self.service.record_feedback(
            review["task_id"], "missed_issue",
            {"rule_id": "SEC-EVAL", "path": "a.py", "line": 1}, "确认漏了",
        )

        evolution = EvolutionEngine(self.service.store, seed_defaults=False)
        result = evolution.auto_propose("llm-review", "default")

        # 两条未解决反馈，只有人工那条参与生成。
        self.assertEqual(1, result["failure_cases_used"])
        self.assertEqual(1, result["inferred_cases_excluded"])

    def test_an_inferred_case_alone_produces_no_candidate(self):
        """只有推断信号时不生成任何候选，且如实说明原因。

        静默返回"没有可学信号"会让人以为反馈没记上；把排除条数报出来，
        读者才能看出是记上了但不够格。
        """
        self._reviewed_pr()
        self._closed(merged=True)

        evolution = EvolutionEngine(self.service.store, seed_defaults=False)
        result = evolution.auto_propose("llm-review", "default")

        self.assertEqual(0, result["failure_cases_used"])
        self.assertEqual(1, result["inferred_cases_excluded"])
        self.assertIsNone(result["version"])

    def test_the_filter_is_a_whitelist_so_new_inferred_kinds_default_out(self):
        """白名单而不是黑名单。

        将来新增一个推断类别时，默认是被排除而不是默认混进来。忘记改这里
        的后果方向，由这个选择决定。
        """
        self.assertNotIn(
            "merged_without_addressing", EvolutionEngine.HUMAN_CONFIRMED_CATEGORIES,
        )
        self.assertIn("missed_issue", EvolutionEngine.HUMAN_CONFIRMED_CATEGORIES)

    def test_an_execution_error_does_not_drive_prompt_evolution(self):
        """`execution_error` 由 `harness.py` 的 `except Exception` 兜底写入。

        它曾经在白名单里，靠的是白名单只看 category 字面值、看不出这个
        category 背后有没有人。两个后果：

        1. 一次崩溃（超时、provider 挂了、JSON 截断）被当成人工确认的评审
           缺陷去改提示词，而这类故障与提示词内容无关。
        2. 它的 payload 没有 `finding`，指纹退化成只含 category，于是所有
           执行错误无论异常、仓库、文件全部塌进同一个桶，最快撞上重试上限
           并把彼此无关的故障一起标成 exhausted。

        `case_promotion.REFUSED_CATEGORIES` 早就以同样的理由拒绝它进评测集。
        """
        self.assertNotIn(
            "execution_error", EvolutionEngine.HUMAN_CONFIRMED_CATEGORIES,
        )

    def test_the_counts_separate_inferred_from_human_sources(self):
        """报数时两种来源必须分开看，合成一个"未解决反馈数"没有意义。"""
        review = self._reviewed_pr()
        self._closed(merged=True)
        self.service.record_feedback(review["task_id"], "false_positive", None, "误报")

        counts = self.service.store.count_failure_cases_by_category("default")
        self.assertEqual(1, counts["merged_without_addressing"])
        self.assertEqual(1, counts["false_positive"])


if __name__ == "__main__":
    unittest.main()