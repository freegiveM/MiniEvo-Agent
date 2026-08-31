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
            {("octocat/hello", n): GOOD_DIFF for n in (1, 2, 3, 4, 5)},
        )
        cases, _rejections = collector.collect(client, self._plan(), "2024-07-01", 100)
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
            {("octocat/hello", n): GOOD_DIFF for n in (1, 2, 3)},
        )
        cases, rejections = collector.collect(client, self._plan(), "2024-07-01", 100)
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
        cases, rejections = collector.collect(client, self._plan(), "2024-07-01", 100)
        self.assertEqual(1, len(cases))
        self.assertEqual(1, rejections["diff-unavailable"])

    def test_pages_beyond_the_first_are_walked_when_the_quota_is_unmet(self):
        client = FakeGitHub(
            {"octocat/hello": [
                [_pull(1, "Add feature")],      # 整页都被淘汰
                [_pull(2), _pull(3)],
            ]},
            {("octocat/hello", n): GOOD_DIFF for n in (1, 2, 3)},
        )
        cases, _rejections = collector.collect(client, self._plan(), "2024-07-01", 100)
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
            {(repo, n): GOOD_DIFF
             for repo, n in (("octocat/one", 1), ("octocat/one", 2),
                             ("octocat/two", 3), ("octocat/two", 4))},
        )
        cases, _rejections = collector.collect(client, plan, "2024-07-01", 2)
        self.assertEqual(2, len(cases))
        self.assertEqual({"octocat/one"}, {case["repository"] for case in cases})

    def test_split_and_domain_come_from_the_plan_not_the_pr(self):
        client = FakeGitHub(
            {"octocat/hello": [[_pull(1)]]},
            {("octocat/hello", 1): GOOD_DIFF},
        )
        cases, _rejections = collector.collect(
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
            {("octocat/hello", 1): GOOD_DIFF, ("octocat/hello", 2): GOOD_DIFF},
        )
        cases, _rejections = collector.collect(client, self._plan(), "2024-07-01", 100)
        self.assertEqual(
            {"pre-cutoff", "post-cutoff"},
            {case["contamination_split"] for case in cases},
        )


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


if __name__ == "__main__":
    unittest.main()
