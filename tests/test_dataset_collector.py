"""采集器编排逻辑的离线测试（用假 client，不联网）。

dataset_builder 的测试覆盖"一个 case 长什么样"；这里覆盖采集器自己的决策：
配额、跳过未合并 PR、淘汰计数、缓存、坏数据不中断整轮。
这些都曾是"只能真跑一遍才知道对不对"的地方。
"""
import importlib.util
import json
import os
import sys
import tempfile
import unittest


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

# scripts/ 不是包，按路径加载。
_spec = importlib.util.spec_from_file_location(
    "collect_reverted_fix_dataset",
    os.path.join(ROOT, "scripts", "collect_reverted_fix_dataset.py"),
)
collector = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(collector)


GOOD_DIFF = """diff --git a/pkg/digest.py b/pkg/digest.py
index 1111111..2222222 100644
--- a/pkg/digest.py
+++ b/pkg/digest.py
@@ -10,7 +10,7 @@ def compute_token(payload):
     data = payload.encode("utf-8")
-    digest = hashlib.md5(data).hexdigest()
+    digest = hashlib.sha256(data).hexdigest()
     return digest
"""


def good_diff(seed=0):
    """每个 PR 一份**内容不同**的 diff。

    为什么需要它：采集器加了内容级去重后，让所有 PR 共用同一个 GOOD_DIFF
    会被正确地判成重复，配额类测试就失去意义了。这不是去重的 bug——
    原先的 fixture 不真实：真实世界里不同 PR 的 diff 内容不同，
    而"内容完全相同的多个 PR"恰恰就是去重要拦的那种情况。
    改动函数名即可，行号不变，指纹按内容行算。
    """
    if not seed:
        return GOOD_DIFF
    return GOOD_DIFF.replace("compute_token", "compute_token_%d" % seed).replace(
        "digest = hashlib", "digest%d = hashlib" % seed
    ).replace("return digest", "return digest%d" % seed)

FEATURE_DIFF = GOOD_DIFF


class FakeGitHub:
    """Stands in for the real client: same two methods, no network."""

    def __init__(self, pages_by_repo, diffs):
        self.pages_by_repo = pages_by_repo
        self.diffs = diffs
        self.requests = 0
        self.cache_hits = 0
        self.diff_calls = []

    def list_merged_pulls(self, repository, page):
        pages = self.pages_by_repo.get(repository, [])
        # 真 client 已在这里过滤掉未合并 PR；假 client 保持同样契约。
        return pages[page - 1] if page <= len(pages) else []

    def pull_diff(self, repository, number):
        self.diff_calls.append((repository, number))
        return self.diffs[(repository, number)]


def _pull(number, title="Fix weak hash", merged_at="2025-03-01T00:00:00Z"):
    return {
        "number": number, "title": title, "body": "",
        "merged_at": merged_at,
        "html_url": "https://github.com/octocat/hello/pull/%d" % number,
    }


class CollectTests(unittest.TestCase):
    def _plan(self, **overrides):
        entry = {
            "name": "octocat/hello", "split": "validation",
            "domain": "crypto-ssh", "target_prs": 2,
        }
        entry.update(overrides)
        return {"repos": [entry], "defaults": {"max_pages": 3}}

    def test_stops_at_the_per_repository_quota(self):
        pulls = [_pull(n) for n in (1, 2, 3, 4, 5)]
        client = FakeGitHub(
            {"octocat/hello": [pulls]},
            {("octocat/hello", n): good_diff(n) for n in (1, 2, 3, 4, 5)},
        )
        cases, _rejections, _clean_cases, _clean_rejections = collector.collect(client, self._plan(), "2024-07-01", 100)
        self.assertEqual(2, len(cases))
        # 配额满了就不再抓 diff：多抓一次就是白烧一次配额。
        self.assertEqual(2, len(client.diff_calls))

    def test_rejections_are_counted_by_reason_for_the_funnel(self):
        pulls = [
            _pull(1, "Add streaming upload support"),   # not-a-bugfix
            _pull(2, 'Revert "use sha256"'),            # excluded-keyword
            _pull(3, "Fix weak hash"),                  # accepted
        ]
        client = FakeGitHub(
            {"octocat/hello": [pulls]},
            {("octocat/hello", n): good_diff(n) for n in (1, 2, 3)},
        )
        cases, rejections, _clean_cases, _clean_rejections = collector.collect(client, self._plan(), "2024-07-01", 100)
        self.assertEqual(1, len(cases))
        self.assertEqual(1, rejections["not-a-bugfix"])
        self.assertEqual(1, rejections["excluded-keyword"])

    def test_a_missing_diff_is_skipped_not_fatal(self):
        """仓库改名/PR 下架不该毁掉一轮几百次请求的成果。"""
        class Flaky(FakeGitHub):
            def pull_diff(self, repository, number):
                if number == 1:
                    raise LookupError("HTTP 404")
                return super().pull_diff(repository, number)

        client = Flaky(
            {"octocat/hello": [[_pull(1), _pull(2)]]},
            {("octocat/hello", 2): GOOD_DIFF},
        )
        cases, rejections, _clean_cases, _clean_rejections = collector.collect(client, self._plan(), "2024-07-01", 100)
        self.assertEqual(1, len(cases))
        self.assertEqual(1, rejections["diff-unavailable"])

    def test_pages_beyond_the_first_are_walked_when_the_quota_is_unmet(self):
        client = FakeGitHub(
            {"octocat/hello": [
                [_pull(1, "Add feature")],      # 整页都被淘汰
                [_pull(2), _pull(3)],
            ]},
            {("octocat/hello", n): good_diff(n) for n in (1, 2, 3)},
        )
        cases, _rejections, _clean_cases, _clean_rejections = collector.collect(client, self._plan(), "2024-07-01", 100)
        self.assertEqual(2, len(cases))

    def test_global_target_stops_collection_across_repositories(self):
        plan = {
            "repos": [
                {"name": "octocat/one", "split": "validation", "target_prs": 2},
                {"name": "octocat/two", "split": "holdout", "target_prs": 2},
            ],
            "defaults": {"max_pages": 1},
        }
        client = FakeGitHub(
            {
                "octocat/one": [[_pull(1), _pull(2)]],
                "octocat/two": [[_pull(3), _pull(4)]],
            },
            {(repo, n): good_diff(n)
             for repo, n in (("octocat/one", 1), ("octocat/one", 2),
                             ("octocat/two", 3), ("octocat/two", 4))},
        )
        cases, _rejections, _clean_cases, _clean_rejections = collector.collect(client, plan, "2024-07-01", 2)
        self.assertEqual(2, len(cases))
        self.assertEqual({"octocat/one"}, {case["repository"] for case in cases})

    def test_split_and_domain_come_from_the_plan_not_the_pr(self):
        client = FakeGitHub(
            {"octocat/hello": [[_pull(1)]]},
            {("octocat/hello", 1): GOOD_DIFF},
        )
        cases, _rejections, _clean_cases, _clean_rejections = collector.collect(
            client, self._plan(split="holdout", domain="security-tool", target_prs=1),
            "2024-07-01", 100,
        )
        self.assertEqual("holdout", cases[0]["split"])
        self.assertEqual("security-tool", cases[0]["domain"])

    def test_cutoff_drives_the_contamination_label(self):
        client = FakeGitHub(
            {"octocat/hello": [[
                _pull(1, merged_at="2022-01-01T00:00:00Z"),
                _pull(2, merged_at="2026-01-01T00:00:00Z"),
            ]]},
            {("octocat/hello", 1): good_diff(1), ("octocat/hello", 2): good_diff(2)},
        )
        cases, _rejections, _clean_cases, _clean_rejections = collector.collect(client, self._plan(), "2024-07-01", 100)
        self.assertEqual(
            {"pre-cutoff", "post-cutoff"},
            {case["contamination_split"] for case in cases},
        )


class DedupTests(unittest.TestCase):
    """内容级去重的编排行为。指纹函数本身的测试在 test_dataset_dedup.py。"""

    def test_two_prs_with_the_same_diff_yield_one_case(self):
        plan = {"repos": [{"name": "octocat/hello", "split": "validation",
                           "target_prs": 3}],
                "defaults": {"max_pages": 1}}
        client = FakeGitHub(
            {"octocat/hello": [[_pull(1), _pull(2), _pull(3)]]},
            # 三个 PR 同一份 diff：真实世界里这就是 backport 或重复落地。
            {("octocat/hello", n): GOOD_DIFF for n in (1, 2, 3)},
        )
        cases, rejections, _clean_cases, _clean_rejections = collector.collect(client, plan, "2024-07-01", 100)
        self.assertEqual(1, len(cases))
        self.assertEqual(2, rejections.get("duplicate-diff"))

    def test_dedup_spans_repositories_to_stop_split_leakage(self):
        """跨仓库去重，不是每仓库一份。

        切分泄漏恰恰发生在 validation 与 holdout 各拿到同一修复的一份时。
        per-repo 去重看不见它——两个仓库各自都只有一份，都"不重复"。
        """
        plan = {"repos": [
            {"name": "octocat/one", "split": "validation", "target_prs": 1},
            {"name": "octocat/two", "split": "holdout", "target_prs": 1},
        ], "defaults": {"max_pages": 1}}
        client = FakeGitHub(
            {"octocat/one": [[_pull(1)]], "octocat/two": [[_pull(2)]]},
            {("octocat/one", 1): GOOD_DIFF, ("octocat/two", 2): GOOD_DIFF},
        )
        cases, rejections, _clean_cases, _clean_rejections = collector.collect(client, plan, "2024-07-01", 100)
        self.assertEqual(1, len(cases))
        self.assertEqual(1, rejections.get("duplicate-diff"))
        # 留下的是先遇到的那个，holdout 那份被拦住。
        self.assertEqual("octocat/one", cases[0]["repository"])

    def test_distinct_diffs_are_all_kept(self):
        # 去重不能过度：内容不同就都留下。
        plan = {"repos": [{"name": "octocat/hello", "split": "validation",
                           "target_prs": 3}],
                "defaults": {"max_pages": 1}}
        client = FakeGitHub(
            {"octocat/hello": [[_pull(1), _pull(2), _pull(3)]]},
            {("octocat/hello", n): good_diff(n) for n in (1, 2, 3)},
        )
        cases, rejections, _clean_cases, _clean_rejections = collector.collect(client, plan, "2024-07-01", 100)
        self.assertEqual(3, len(cases))
        self.assertIsNone(rejections.get("duplicate-diff"))


class PreScreenTests(unittest.TestCase):
    """标题级淘汰必须发生在抓 diff 之前，否则白烧配额。"""

    def test_a_bump_pr_costs_no_diff_request(self):
        plan = {"repos": [{"name": "octocat/hello", "split": "validation",
                           "target_prs": 2}],
                "defaults": {"max_pages": 1}}
        client = FakeGitHub(
            {"octocat/hello": [[
                _pull(1, title="Bump click from 8.3.1 to 8.4.1"),
                _pull(2, title="[PR #9/abc backport][3.1] Fix deadlock"),
                _pull(3, title="Fix weak hash"),
            ]]},
            {("octocat/hello", n): good_diff(n) for n in (1, 2, 3)},
        )
        cases, rejections, _clean_cases, _clean_rejections = collector.collect(client, plan, "2024-07-01", 100)
        self.assertEqual(1, len(cases))
        # 核心断言：只为第 3 个 PR 抓了 diff。前两个一次请求都没花。
        self.assertEqual([("octocat/hello", 3)], client.diff_calls)
        self.assertEqual(1, rejections.get("excluded-keyword"))
        self.assertEqual(1, rejections.get("backport-duplicate"))


class ReportTests(unittest.TestCase):
    def test_split_overlap_makes_the_run_fail(self):
        """仓库不相交是硬约束，违反必须让退出码非零，不能只打印一行警告。"""
        case = {
            "repository": "octocat/hello", "split": "validation", "difficulty": "L1",
            "defect_class": "crypto-weak", "contamination_split": "post-cutoff",
            "label_provenance": "title-keyword",
        }
        overlapping = dict(case, split="holdout")
        self.assertFalse(collector.print_report([case, overlapping], {}))

    def test_thin_coverage_warns_but_does_not_fail(self):
        """类别不足是"要复核"，不是"数据集不可用"——区别要体现在退出码上。"""
        case = {
            "repository": "octocat/hello", "split": "validation", "difficulty": "L1",
            "defect_class": "crypto-weak", "contamination_split": "post-cutoff",
            "label_provenance": "title-keyword",
        }
        self.assertTrue(collector.print_report([case], {"not-a-bugfix": 5}))


class ReportOnlyTests(unittest.TestCase):
    def test_report_only_reads_an_existing_jsonl(self):
        case = {
            "repository": "octocat/hello", "split": "validation", "difficulty": "L2",
            "defect_class": "injection", "contamination_split": "pre-cutoff",
            "label_provenance": "cve",
        }
        handle, path = tempfile.mkstemp(suffix=".jsonl")
        os.close(handle)
        try:
            with open(path, "w", encoding="utf-8") as out:
                out.write(json.dumps(case) + "\n")
            argv = sys.argv
            sys.argv = ["collect", "--report-only", "--output", path]
            try:
                self.assertEqual(0, collector.main())
            finally:
                sys.argv = argv
        finally:
            os.unlink(path)


class CleanCaseCollectionTests(unittest.TestCase):
    """负样本路径复用同一次分页/diff 请求，且与正样本互斥。"""

    # 冷却期从 merged_at 起算 >= CLEAN_COOLDOWN_DAYS(180)。
    AS_OF = "2026-01-01T00:00:00Z"

    def _plan(self, **overrides):
        entry = {
            "name": "octocat/hello", "split": "validation",
            "domain": "crypto-ssh", "target_prs": 0, "clean_target_prs": 2,
        }
        entry.update(overrides)
        return {"repos": [entry], "defaults": {"max_pages": 3}}

    def test_ordinary_feature_prs_are_collected_as_clean_cases(self):
        pulls = [_pull(n, title="Add CSV export for reports") for n in (1, 2)]
        client = FakeGitHub(
            {"octocat/hello": [pulls]},
            {("octocat/hello", n): good_diff(n) for n in (1, 2)},
        )
        cases, rejections, clean_cases, clean_rejections = collector.collect(
            client, self._plan(), "2024-07-01", 0, 2, self.AS_OF,
        )
        self.assertEqual([], cases)
        self.assertEqual(2, len(clean_cases))
        self.assertTrue(all(c["expected_findings"] == [] for c in clean_cases))
        self.assertTrue(all(c["source"]["kind"] == "real-pr-clean" for c in clean_cases))

    def test_a_bugfix_looking_pr_never_ends_up_in_the_clean_split(self):
        """正样本配额用完后，看起来像 bugfix 的 PR 仍不能滑进负样本。

        target_prs=1 的第一个 PR 先填满正样本配额；第二个 PR 标题同样
        像 bugfix，此时只有负样本配额还空——它必须被 screen_title_for_clean
        拒绝（looks-like-a-bugfix），不能因为"反正配额还有空位"就被当成
        负样本收进去。
        """
        pulls = [
            _pull(1, title="Fix weak hash in token computation"),
            _pull(2, title="Fix another crash on empty input"),
        ]
        client = FakeGitHub(
            {"octocat/hello": [pulls]},
            {("octocat/hello", n): good_diff(n) for n in (1, 2)},
        )
        plan = self._plan(target_prs=1, clean_target_prs=1)
        cases, rejections, clean_cases, clean_rejections = collector.collect(
            client, plan, "2024-07-01", 1, 1, self.AS_OF,
        )
        self.assertEqual(1, len(cases))
        self.assertEqual([], clean_cases)
        self.assertEqual(1, clean_rejections.get("looks-like-a-bugfix", 0))

    def test_the_positive_and_clean_paths_share_the_same_diff_fetch(self):
        """两条路径复用同一次 list/diff 请求，不为负样本单独发一轮请求。"""
        pulls = [_pull(1, title="Add CSV export for reports")]
        client = FakeGitHub(
            {"octocat/hello": [pulls]},
            {("octocat/hello", 1): good_diff(1)},
        )
        collector.collect(client, self._plan(clean_target_prs=1), "2024-07-01", 0, 1, self.AS_OF)
        self.assertEqual([("octocat/hello", 1)], client.diff_calls)


if __name__ == "__main__":
    unittest.main()
