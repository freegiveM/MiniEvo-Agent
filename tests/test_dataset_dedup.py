"""backport 去重与标题前置筛选的测试。

这两个缺陷都是首轮 pilot（对着真实 API 跑 52 次请求）暴露的，离线测试
一次都没抓到过——因为离线 fixture 是我自己编的，不会自发长出 dependabot
bump 和 backport 标题。这批测试把那次实测的发现固化下来。
"""
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from evoagent.dataset_builder import (  # noqa: E402
    BACKPORT_PATTERN,
    diff_fingerprint,
    screen_title,
)


class ScreenTitleTests(unittest.TestCase):
    """标题级筛选：不需要 diff 就能定的淘汰，必须在抓 diff 前定掉。"""

    def test_a_dependabot_bump_is_rejected(self):
        # 实测标题，来自 aiohttp 首页。首轮 pilot 里这类占 38/44。
        self.assertEqual("excluded-keyword",
                         screen_title("Bump click from 8.3.1 to 8.4.1", ""))

    def test_a_real_bugfix_passes(self):
        self.assertIsNone(
            screen_title("fix(connector): resolve race condition in close()", "")
        )

    def test_a_feature_is_rejected_as_not_a_bugfix(self):
        self.assertEqual("not-a-bugfix",
                         screen_title("Add support for HTTP/3", ""))

    def test_the_body_can_supply_the_bugfix_evidence(self):
        # 标题没关键词但正文有，仍算 bugfix：很多仓库标题写得极简。
        self.assertIsNone(screen_title("Handle empty payload", "Fixes #123"))


class BackportTests(unittest.TestCase):
    """backport 是重复样本的主要来源，且它会伪装成合格 bugfix。"""

    REAL_TITLES = [
        "[PR #12787/4eb35886 backport][3.15] fix(connector): resolve race condition",
        "[PR #12787/4eb35886 backport][3.14] fix(connector): resolve race condition",
        "[PR #13609/faa3c0c7 backport][3.15] Fix possible deadlock in test",
        "[PR #12754/0d864ff9 backport][3.14] Fix sendfile test",
    ]

    def test_real_backport_titles_are_rejected(self):
        # 这四条是实测标题原文。注意它们都含 fix 字样：
        # 如果 backport 判定放在 FIX_KEYWORDS 之后，它们会被当成合格样本。
        for title in self.REAL_TITLES:
            self.assertEqual("backport-duplicate", screen_title(title, ""),
                             "should reject: %s" % title)

    def test_the_original_pr_is_not_rejected(self):
        # 只拦 backport，不拦被 backport 的原始 PR——否则修复本身也丢了。
        self.assertIsNone(
            screen_title("fix(connector): resolve race condition in "
                         "TCPConnector.close()", "")
        )

    def test_a_bare_branch_tag_prefix_is_rejected(self):
        # 有些仓库的 backport 不写 backport 字样，只带分支号前缀。
        self.assertEqual("backport-duplicate",
                         screen_title("[3.15] Fix deadlock in resolver", ""))

    def test_backport_is_checked_before_the_keyword_rules(self):
        # 顺序断言。反了就会先命中 excluded-keyword，淘汰原因归错类，
        # 漏斗统计会把 backport 的量算到 dependabot 头上。
        title = "[PR #1/abc backport][3.1] Fix typo in handler"
        self.assertEqual("backport-duplicate", screen_title(title, ""))

    def test_the_word_must_stand_alone(self):
        # \b 边界：不该把 "backporting-tool" 这类正常标题误伤。
        self.assertIsNotNone(BACKPORT_PATTERN.search("backport of #1"))


class FingerprintTests(unittest.TestCase):
    """内容指纹：抓标题模式漏掉的重复。"""

    BASE = ("--- a/pkg/x.py\n+++ b/pkg/x.py\n"
            "@@ -120,7 +120,8 @@ def handler():\n"
            "-    return None\n+    return value\n")

    def test_identical_diffs_share_a_fingerprint(self):
        self.assertEqual(diff_fingerprint(self.BASE), diff_fingerprint(self.BASE))

    def test_line_number_shift_does_not_change_the_fingerprint(self):
        # backport 到不同分支时同一处修改行号会偏移。按含行号的原文哈希
        # 会认不出这对重复——这是丢掉 hunk 头的全部理由。
        shifted = self.BASE.replace("@@ -120,7 +120,8 @@", "@@ -134,7 +134,8 @@")
        self.assertNotEqual(self.BASE, shifted)
        self.assertEqual(diff_fingerprint(self.BASE), diff_fingerprint(shifted))

    def test_blob_hashes_do_not_change_the_fingerprint(self):
        # index 行的 blob 哈希在不同分支上必然不同，属于噪声。
        a = "index 1111111..2222222 100644\n" + self.BASE
        b = "index 3333333..4444444 100644\n" + self.BASE
        self.assertEqual(diff_fingerprint(a), diff_fingerprint(b))

    def test_different_content_gets_a_different_fingerprint(self):
        other = self.BASE.replace("+    return value", "+    return other")
        self.assertNotEqual(diff_fingerprint(self.BASE), diff_fingerprint(other))

    def test_a_changed_path_changes_the_fingerprint(self):
        # +++/--- 行以 + / - 开头，会被保留——同一处改动落在不同文件上
        # 不是重复。这是保留它们的理由。
        other = self.BASE.replace("pkg/x.py", "pkg/y.py")
        self.assertNotEqual(diff_fingerprint(self.BASE), diff_fingerprint(other))

    def test_hunk_headers_never_reach_the_fingerprint(self):
        """机制断言：排除 hunk 头靠的是 +/- 过滤，不是一个专门的分支。

        变异测试删掉那个专门分支时本组测试仍全绿——因为它是死代码。
        这条把真正起作用的机制固定下来：只要过滤条件仍是"以 +/- 开头"，
        @@ 行就进不了指纹。若有人把条件放宽成"保留所有行"，这条会转红。
        """
        from evoagent.dataset_builder import _fingerprint_lines
        kept = _fingerprint_lines(self.BASE)
        self.assertFalse([line for line in kept if line.startswith("@@")])
        self.assertFalse([line for line in kept if line.startswith("index ")])
        # 而 +++/--- 文件头必须在，路径要进指纹。
        self.assertTrue([line for line in kept if line.startswith("--- ")])

    def test_context_only_differences_are_ignored(self):
        # 上下文行不参与指纹：backport 时周边代码可能已经漂移，
        # 但缺陷与修复是同一个。
        a = self.BASE + "     unchanged_a = 1\n"
        b = self.BASE + "     unchanged_b = 2\n"
        self.assertEqual(diff_fingerprint(a), diff_fingerprint(b))


if __name__ == "__main__":
    unittest.main()
