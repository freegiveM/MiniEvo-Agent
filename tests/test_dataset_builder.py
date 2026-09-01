"""反转构造数据集的离线测试。

这些测试锁住 D2 的全部判定逻辑，不需要网络。设计意图：采集器只负责翻页，
所有"一个 case 长什么样"的决定都在 dataset_builder 里，因此都能在这里验证。

重点覆盖三类容易静默出错的地方：
1. diff 反转的行号交换（错了会让所有 expected_findings 偏移，指标全假）
2. 筛选规则的边界（放宽一条就引入标注噪声，收紧一条就丢样本）
3. 覆盖复核的警告（不达标必须报，否则设计承诺变成没人核过的话）
"""
import unittest

from evoagent.dataset_builder import (
    MAX_FIX_LINES,
    CaseRejected,
    PullRequest,
    build_case,
    classify_defect,
    classify_defect_with_basis,
    contamination_split,
    count_changed_lines,
    count_touched_functions,
    grade_difficulty,
    reverse_unified_diff,
    split_diff_by_file,
    summarise,
)
from evoagent.evaluation_harness import validate_case
from evoagent.diff_parser import parse_unified_diff


# 一个真实形态的 fix diff：把 md5 换成 sha256。含 index 行、hunk section
# heading、上下文行——这些都是 GitHub 实际返回的样子。
CRYPTO_FIX = """diff --git a/pkg/digest.py b/pkg/digest.py
index 1111111..2222222 100644
--- a/pkg/digest.py
+++ b/pkg/digest.py
@@ -10,7 +10,7 @@ def compute_token(payload):
     data = payload.encode("utf-8")
-    digest = hashlib.md5(data).hexdigest()
+    digest = hashlib.sha256(data).hexdigest()
     return digest
"""


def _pull(diff, title="Fix weak hash in token computation", **kwargs):
    defaults = {
        "repository": "octocat/hello",
        "number": 42,
        "title": title,
        "body": "",
        "merged_at": "2025-03-01T00:00:00Z",
        "diff": diff,
    }
    defaults.update(kwargs)
    return PullRequest(**defaults)


class ReverseDiffTests(unittest.TestCase):
    def test_reversal_swaps_signs_and_hunk_line_numbers(self):
        reverted = reverse_unified_diff(
            "diff --git a/a.py b/a.py\n"
            "--- a/a.py\n+++ b/a.py\n"
            "@@ -10,7 +20,9 @@ def f():\n"
            " ctx\n-gone\n+added\n"
        )
        self.assertIn("@@ -20,9 +10,7 @@ def f():", reverted)
        self.assertIn("+gone", reverted)
        self.assertIn("-added", reverted)
        # section heading 必须保留：count_touched_functions 依赖它判 L3。
        self.assertIn("def f():", reverted)

    def test_reversal_drops_the_index_line_rather_than_swapping_it(self):
        """交换后的 blob hash 是错的；写一个错的 hash 比不写更糟。"""
        reverted = reverse_unified_diff(CRYPTO_FIX)
        self.assertNotIn("index ", reverted)

    def test_reversal_preserves_single_line_hunk_header_without_counts(self):
        reverted = reverse_unified_diff(
            "--- a/a.py\n+++ b/a.py\n@@ -3 +7 @@\n-old\n+new\n"
        )
        self.assertIn("@@ -7 +3 @@", reverted)

    def test_reverted_seed_line_is_the_buggy_code(self):
        reverted = reverse_unified_diff(CRYPTO_FIX)
        added = parse_unified_diff(reverted).added_lines
        self.assertEqual(1, len(added))
        self.assertIn("hashlib.md5", added[0].content)
        # 行号取自原 fix 的删除侧起点（-10），这是缺陷在待审 PR 里的真实位置。
        self.assertEqual(11, added[0].line)

    def test_reversal_is_an_involution(self):
        """反转两次应回到原始内容（index 行除外）。反转错了这条最先炸。"""
        once = reverse_unified_diff(CRYPTO_FIX)
        twice = reverse_unified_diff(once)
        original = "\n".join(
            line for line in CRYPTO_FIX.splitlines() if not line.startswith("index ")
        ) + "\n"
        self.assertEqual(original, twice)


class SplitDiffTests(unittest.TestCase):
    def test_multi_file_diff_splits_on_the_git_header(self):
        chunks = split_diff_by_file(
            "diff --git a/x.py b/x.py\n--- a/x.py\n+++ b/x.py\n@@ -1 +1 @@\n-a\n+b\n"
            "diff --git a/y.py b/y.py\n--- a/y.py\n+++ b/y.py\n@@ -1 +1 @@\n-c\n+d\n"
        )
        self.assertEqual(["x.py", "y.py"], [path for path, _text in chunks])
        self.assertIn("+b", chunks[0][1])
        self.assertNotIn("+d", chunks[0][1])


class ClassificationTests(unittest.TestCase):
    def test_crypto_beats_the_logic_boundary_catch_all(self):
        """logic-boundary 特征最弱（比较运算符谁都有），必须排在最后。"""
        defect = classify_defect(["    if hashlib.md5(x).hexdigest() == expected:"])
        self.assertEqual("crypto-weak", defect.name)

    def test_injection_is_detected_on_shell_true(self):
        defect = classify_defect(["    subprocess.run(cmd, shell=True)"])
        self.assertEqual("injection", defect.name)
        self.assertEqual("CWE-78", defect.cwe)

    def test_unremarkable_comparison_falls_back_to_logic_boundary(self):
        defect = classify_defect(["    if index > len(items):"])
        self.assertEqual("logic-boundary", defect.name)

    def test_the_basis_distinguishes_a_judgement_from_a_default(self):
        """同样返回 logic-boundary，来源不同，含义完全不同。

        兜底样本的 defect_class 只表示"八类特征都没匹配上"。不留这个痕迹，
        报告里"logic-boundary 90.5%"就会被读成一个关于数据的结论，
        而它实际上是关于分类器的结论。
        """
        # 有字面特征 -> 判出来的
        _defect, basis = classify_defect_with_basis(
            ["    digest = hashlib.md5(data).hexdigest()"])
        self.assertEqual("code-pattern", basis)

        # 八类特征一个都没中、标题也没线索 -> 兜底
        #
        # 注意这里**不能**用 `if index > len(items):`：比较运算符是
        # logic-boundary 自己的特征，那条会走 code-pattern 分支，
        # 测不到兜底。要用一行连比较都没有的普通赋值。
        defect, basis = classify_defect_with_basis(["    self.retries = retries"])
        self.assertEqual("logic-boundary", defect.name)
        self.assertEqual("fallback-default", basis)

        # 无字面特征但标题点明了类别 -> 靠标题
        _defect, basis = classify_defect_with_basis(
            ["    self.value = other"], title="fix concurrency issue in worker")
        self.assertEqual("title-word", basis)

    def test_build_case_records_the_classification_basis(self):
        """两种来源都要测。

        只测 code-pattern 那一条的话，把字段写死成 "code-pattern" 也能通过
        （变异实测确认过）——而写死正是这个字段最可能出的错，因为写死之后
        兜底样本会伪装成判出来的，硬约束告警永远不触发。
        """
        judged = build_case(_pull(CRYPTO_FIX), "validation", "2024-07-01")
        self.assertEqual("code-pattern", judged["defect_class_basis"])

        # 一行既无字面特征也无比较运算符的普通赋值 -> 必须记成兜底
        plain = (
            "diff --git a/pkg/conf.py b/pkg/conf.py\n"
            "--- a/pkg/conf.py\n+++ b/pkg/conf.py\n"
            "@@ -1,2 +1,2 @@\n"
            "-        self.retries = retries\n"
            "+        self.retries = default_retries\n"
            " value = 1\n"
        )
        defaulted = build_case(_pull(plain, title="Fix wrong retry source"),
                               "validation", "2024-07-01")
        self.assertEqual("fallback-default", defaulted["defect_class_basis"])

    def test_four_classes_are_outside_the_deterministic_rule_set(self):
        """臂 A（rules-only）在这四类上的召回上限是 0——可事先算出，不靠实验。"""
        uncovered = {
            item.name for item in __import__(
                "evoagent.dataset_builder", fromlist=["DEFECT_CLASSES"]
            ).DEFECT_CLASSES if not item.rule_covered
        }
        self.assertEqual(
            {"auth-bypass", "resource-leak", "logic-boundary", "concurrency"},
            uncovered,
        )


class DifficultyTests(unittest.TestCase):
    def test_single_line_with_a_literal_signature_is_l1(self):
        self.assertEqual(
            "L1",
            grade_difficulty(["digest = hashlib.md5(data)"], ["a.py"], 1, "crypto-weak"),
        )

    def test_single_line_without_a_literal_signature_is_not_l1(self):
        """把 > 改成 >= 是单行，但规则集碰不到它，难度不等于 L1。"""
        self.assertEqual(
            "L2",
            grade_difficulty(["if n >= limit:"], ["a.py"], 1, "logic-boundary"),
        )

    def test_two_files_is_l3(self):
        self.assertEqual(
            "L3",
            grade_difficulty(["x = 1"], ["a.py", "b.py"], 1, "logic-boundary"),
        )

    def test_concurrency_outranks_context_span(self):
        """并发缺陷即使只改一行一个文件仍是 L4：范围小不等于容易。"""
        self.assertEqual(
            "L4",
            grade_difficulty(["await self._flush()"], ["a.py"], 1, "concurrency"),
        )

    def test_touched_function_count_reads_both_hunk_heading_and_body(self):
        diff = (
            "@@ -1,3 +1,3 @@ def outer():\n-a\n+b\n"
            "@@ -20,4 +20,4 @@\n+def inner():\n+    pass\n"
        )
        self.assertEqual(2, count_touched_functions(diff))

    def test_touched_function_count_never_returns_zero(self):
        """数不出来时退回 1：分级只用于分层报数，不参与命中判定。"""
        self.assertEqual(1, count_touched_functions("@@ -1 +1 @@\n-a\n+b\n"))


class ContaminationSplitTests(unittest.TestCase):
    def test_before_cutoff_is_marked_possibly_memorised(self):
        self.assertEqual(
            "pre-cutoff", contamination_split("2023-05-01T00:00:00Z", "2024-07-01")
        )

    def test_after_cutoff_is_clean(self):
        self.assertEqual(
            "post-cutoff", contamination_split("2025-11-20T10:00:00Z", "2024-07-01")
        )

    def test_naive_timestamps_are_treated_as_utc(self):
        self.assertEqual(
            "pre-cutoff", contamination_split("2024-06-30T23:00:00", "2024-07-01")
        )


class BuildCaseTests(unittest.TestCase):
    def test_a_real_shaped_fix_pr_becomes_a_case_that_passes_validate_case(self):
        case = build_case(_pull(CRYPTO_FIX), "validation", "2024-07-01", "crypto-ssh")
        # 与既有校验器一致是硬要求：数据集要能直接喂进现有 harness。
        validate_case(case)
        self.assertEqual("real-pr-reverted-fix", case["source"]["kind"])
        self.assertEqual("crypto-weak", case["defect_class"])
        self.assertEqual("L1", case["difficulty"])
        self.assertEqual("post-cutoff", case["contamination_split"])
        self.assertEqual(1, len(case["expected_findings"]))
        self.assertEqual("CWE-328", case["expected_findings"][0]["cwe"])

    def test_the_human_fix_patch_is_retained_as_repair_ground_truth(self):
        case = build_case(_pull(CRYPTO_FIX), "validation", "2024-07-01")
        self.assertIn("+    digest = hashlib.sha256(data).hexdigest()",
                      case["human_patch"])

    def test_reverts_are_rejected_because_reversing_them_inverts_the_label(self):
        with self.assertRaises(CaseRejected) as ctx:
            build_case(
                _pull(CRYPTO_FIX, title='Revert "use sha256 for tokens"'),
                "validation", "2024-07-01",
            )
        self.assertEqual("excluded-keyword", ctx.exception.reason)

    def test_dependency_bumps_and_formatting_are_rejected(self):
        for title in ("Bump requests from 2.30 to 2.31", "chore: run black on pkg/"):
            with self.assertRaises(CaseRejected):
                build_case(_pull(CRYPTO_FIX, title=title), "validation", "2024-07-01")

    def test_a_word_that_is_ordinary_vocabulary_mid_sentence_is_not_a_kill(self):
        """这几条标题是 pilot 实测被误杀的真样本，必须放行。

        全都坏在同一处：upgrade / docs / cleanup / comment / style 做
        依赖动作或 PR 主题时该杀，做句中普通名词时不该杀。而被误杀的
        恰好集中在 L3/L4 协议边界、并发/资源生命周期、parser 边界
        ——采样计划里最难凑够的三类。

        用 CRYPTO_FIX 的 diff 只是为了让 build_case 能跑完；
        这里断言的是标题判定，不是分类结果。
        """
        for title in (
            "Fix pipelining a rejected upgrade",
            "websocket_ping: fix ping interval with non-zero timeout and improve docs",
            "Fix race condition in connector cleanup",
            "fix resource cleanup on cancel",
            "Fix incorrect comment handling in parser",
            "fix crash in style attribute parsing",
        ):
            case = build_case(_pull(CRYPTO_FIX, title=title),
                              "validation", "2024-07-01")
            self.assertEqual(title, case["fix_pr_title"])

    def test_the_same_words_as_a_pr_subject_are_still_rejected(self):
        """放宽不能把主题式写法一起放进来，否则等于删掉了这几个词。"""
        for title in (
            "docs: fix typos in comments and documentation",
            "docs(api): rewrite the intro",
            "cleanup: remove dead code",
            "comment: clarify why we retry",
            "style: reformat with black",
            "Upgrade requests to 2.31.0",
            "upgrade deps for security",
        ):
            with self.assertRaises(CaseRejected) as ctx:
                build_case(_pull(CRYPTO_FIX, title=title),
                           "validation", "2024-07-01")
            self.assertEqual("excluded-keyword", ctx.exception.reason, title)

    def test_a_new_file_elsewhere_in_the_pr_does_not_disqualify_the_case(self):
        """加了个测试文件不该让整条样本作废。

        重放 977 个已缓存 diff 量出来的：unsupported-diff 占 37.5%，
        其中 new file mode 占 91.8% —— 约三分之一候选是这么丢的。
        而新增的那个文件（测试/changelog/新模块）本来就会被 code_chunks
        筛掉，不进待审 diff，为它丢掉整条样本是纯损失。
        """
        mixed = (
            "diff --git a/pkg/digest.py b/pkg/digest.py\n"
            "--- a/pkg/digest.py\n+++ b/pkg/digest.py\n"
            "@@ -3,3 +3,3 @@ def token(data):\n"
            "-    digest = hashlib.md5(data).hexdigest()\n"
            "+    digest = hashlib.sha256(data).hexdigest()\n"
            "     return digest\n"
            "diff --git a/tests/test_digest.py b/tests/test_digest.py\n"
            "new file mode 100644\n"
            "--- /dev/null\n+++ b/tests/test_digest.py\n"
            "@@ -0,0 +1,2 @@\n"
            "+def test_token():\n"
            "+    assert token(b'x')\n"
        )
        case = build_case(_pull(mixed, title="Fix weak digest for tokens"),
                          "validation", "2024-07-01")
        # 待审 diff 里只剩生产文件，新增的测试文件没被带进来
        self.assertIn("pkg/digest.py", case["diff"])
        self.assertNotIn("tests/test_digest.py", case["diff"])
        self.assertNotIn("new file mode", case["diff"])

    def test_an_unsupported_marker_in_a_used_block_is_still_rejected(self):
        """逐块判不等于放开：标记落在要用的块里照样拒。

        新增文件的 a/ 侧不存在，反转后要生成"删掉整个文件"的 diff，
        待审 diff 里出现删文件会让缺陷定位失去意义。
        """
        added_prod = (
            "diff --git a/pkg/brand_new.py b/pkg/brand_new.py\n"
            "new file mode 100644\n"
            "--- /dev/null\n+++ b/pkg/brand_new.py\n"
            "@@ -0,0 +1,2 @@\n"
            "+def handler():\n"
            "+    return None\n"
        )
        with self.assertRaises(CaseRejected) as ctx:
            build_case(_pull(added_prod, title="Fix missing handler"),
                       "validation", "2024-07-01")
        self.assertEqual("unsupported-diff", ctx.exception.reason)

    def test_size_limits_count_the_review_diff_not_the_whole_pr(self):
        """规模上限按筛完之后的块算。

        阈值本身没动（3 个文件 / 20 行）；改的是分母——测试文件不进
        待审 diff，就不该占额度。这条锁住的是口径，不是宽松度。
        """
        # 生产文件只改 2 行、1 个文件；测试文件很大，加起来会超两条上限
        big_tests = "".join(
            "+    assert step_%d()\n" % i for i in range(30)
        )
        mixed = (
            "diff --git a/pkg/digest.py b/pkg/digest.py\n"
            "--- a/pkg/digest.py\n+++ b/pkg/digest.py\n"
            "@@ -3,3 +3,3 @@ def token(data):\n"
            "-    digest = hashlib.md5(data).hexdigest()\n"
            "+    digest = hashlib.sha256(data).hexdigest()\n"
            "     return digest\n"
            "diff --git a/tests/test_a.py b/tests/test_a.py\n"
            "--- a/tests/test_a.py\n+++ b/tests/test_a.py\n"
            "@@ -1,0 +1,30 @@\n" + big_tests +
            "diff --git a/tests/test_b.py b/tests/test_b.py\n"
            "--- a/tests/test_b.py\n+++ b/tests/test_b.py\n"
            "@@ -1,0 +1,2 @@\n"
            "+def test_b():\n"
            "+    assert True\n"
            "diff --git a/tests/test_c.py b/tests/test_c.py\n"
            "--- a/tests/test_c.py\n+++ b/tests/test_c.py\n"
            "@@ -1,0 +1,2 @@\n"
            "+def test_c():\n"
            "+    assert True\n"
        )
        # 整份 diff：4 个文件（> 3）、30+ 行（> 20）——旧口径会双重拒收
        case = build_case(_pull(mixed, title="Fix weak digest for tokens"),
                          "validation", "2024-07-01")
        self.assertEqual(1, case["diff"].count("diff --git"))
        self.assertLessEqual(count_changed_lines(case["diff"]), MAX_FIX_LINES)

    def test_too_many_production_files_is_still_rejected(self):
        """把分母改成 code_chunks 之后，这条上限仍然要挡得住。

        补这条是因为变异测试暴露了一个空白：把 MAX_FIX_FILES 从 3 放到 30
        时整个测试文件仍然全绿——说明没有任何测试真的走到"生产文件太多"
        这条路上（原有的用例都是测试文件超额，不是生产文件超额）。
        """
        many = "".join(
            "diff --git a/pkg/m%d.py b/pkg/m%d.py\n"
            "--- a/pkg/m%d.py\n+++ b/pkg/m%d.py\n"
            "@@ -1,2 +1,2 @@\n-x = %d\n+x = %d\n" % (i, i, i, i, i, i + 1)
            for i in range(4)
        )
        with self.assertRaises(CaseRejected) as ctx:
            build_case(_pull(many, title="Fix wrong constants"),
                       "validation", "2024-07-01")
        self.assertEqual("too-many-files", ctx.exception.reason)

    def test_a_comment_only_fix_is_stopped_by_content_not_by_title(self):
        """放宽 comment 之后留了一个口子，这条钉住兜它的是哪一层。

        `web: Fix an incomplete comment...` 这种真文档 PR 现在过得了标题层
        （主题前缀是 web:，不是 comment:）。刻意不再收紧标题规则，因为
        收紧的代价是杀掉整类 parser 缺陷样本。

        兜它的是 fix-adds-only —— 挑删除行时跳过 "#" 开头的行，所以纯改
        注释的 PR 反转后没有非注释新增行。注意**不是** no-production-python：
        那条只管"有没有碰非测试 .py"，这个 diff 碰的正是 .py。
        """
        comment_only = (
            "diff --git a/pkg/parser.py b/pkg/parser.py\n"
            "--- a/pkg/parser.py\n+++ b/pkg/parser.py\n"
            "@@ -10,3 +10,3 @@\n"
            "-# incomplete comment\n"
            "+# complete and accurate comment\n"
            " value = 1\n"
        )
        with self.assertRaises(CaseRejected) as ctx:
            build_case(
                _pull(comment_only,
                      title="web: Fix an incomplete comment that was omitted"),
                "validation", "2024-07-01",
            )
        self.assertEqual("fix-adds-only", ctx.exception.reason)

    def test_feature_prs_without_a_fix_keyword_are_rejected(self):
        with self.assertRaises(CaseRejected) as ctx:
            build_case(
                _pull(CRYPTO_FIX, title="Add support for streaming uploads"),
                "validation", "2024-07-01",
            )
        self.assertEqual("not-a-bugfix", ctx.exception.reason)

    def test_add_only_fixes_are_rejected_with_an_explicit_reason(self):
        """构造方法的固有边界：纯新增的 fix 反转后没有新增行，无法标注。"""
        add_only = (
            "diff --git a/pkg/view.py b/pkg/view.py\n"
            "--- a/pkg/view.py\n+++ b/pkg/view.py\n"
            "@@ -5,2 +5,4 @@ def handler(request):\n"
            " def handler(request):\n"
            "+    if not request.user.has_perm('edit'):\n"
            "+        raise PermissionDenied\n"
            "     return render(request)\n"
        )
        with self.assertRaises(CaseRejected) as ctx:
            build_case(
                _pull(add_only, title="Fix missing permission check"),
                "validation", "2024-07-01",
            )
        self.assertEqual("fix-adds-only", ctx.exception.reason)

    def test_test_only_changes_are_rejected(self):
        test_only = (
            "diff --git a/tests/test_digest.py b/tests/test_digest.py\n"
            "--- a/tests/test_digest.py\n+++ b/tests/test_digest.py\n"
            "@@ -1 +1 @@\n-assert old\n+assert new\n"
        )
        with self.assertRaises(CaseRejected) as ctx:
            build_case(
                _pull(test_only, title="Fix broken assertion"),
                "validation", "2024-07-01",
            )
        self.assertEqual("no-production-python", ctx.exception.reason)

    def test_test_file_changes_are_stripped_from_a_mixed_pr(self):
        """测试文件留在待审 diff 里会让 agent 从测试内容反推答案。"""
        mixed = CRYPTO_FIX + (
            "diff --git a/tests/test_digest.py b/tests/test_digest.py\n"
            "--- a/tests/test_digest.py\n+++ b/tests/test_digest.py\n"
            "@@ -1 +1 @@\n-assert md5\n+assert sha256\n"
        )
        case = build_case(
            _pull(mixed, title="Fix weak hash and update test"),
            "validation", "2024-07-01",
        )
        self.assertNotIn("test_digest", case["diff"])
        self.assertEqual(["pkg/digest.py"], parse_unified_diff(case["diff"]).files)

    def test_large_fixes_are_rejected(self):
        body = "".join("-old_%d\n+new_%d\n" % (i, i) for i in range(15))
        big = (
            "diff --git a/pkg/a.py b/pkg/a.py\n--- a/pkg/a.py\n+++ b/pkg/a.py\n"
            "@@ -1,30 +1,30 @@\n" + body
        )
        with self.assertRaises(CaseRejected) as ctx:
            build_case(_pull(big, title="Fix bug"), "validation", "2024-07-01")
        self.assertEqual("too-many-lines", ctx.exception.reason)

    def test_binary_and_rename_diffs_are_rejected(self):
        for marker in ("Binary files a/x.png and b/x.png differ\n",
                       "rename from old.py\n"):
            with self.assertRaises(CaseRejected) as ctx:
                build_case(
                    _pull(CRYPTO_FIX + marker, title="Fix bug"),
                    "validation", "2024-07-01",
                )
            self.assertEqual("unsupported-diff", ctx.exception.reason)

    def test_comment_only_reversal_is_rejected(self):
        comment_fix = (
            "diff --git a/pkg/a.py b/pkg/a.py\n--- a/pkg/a.py\n+++ b/pkg/a.py\n"
            "@@ -1,2 +1,2 @@\n-# wrong note\n+# right note\n"
        )
        # 标题刻意不含 "comment"/"typo"——那些词会先被排除规则拦掉，
        # 走不到反转这一步。这里要验的是反转后种子行全是注释的情况。
        with self.assertRaises(CaseRejected) as ctx:
            build_case(_pull(comment_fix, title="Fix incorrect wording"),
                      "validation", "2024-07-01")
        self.assertEqual("fix-adds-only", ctx.exception.reason)

    def test_cve_mentions_are_recorded_so_strict_cwe_can_be_scoped(self):
        """严格 CWE 命中率只在 CVE 子集上报数，需要这个字段划出分母。"""
        case = build_case(
            _pull(CRYPTO_FIX, title="Fix CVE-2024-12345: weak token hash"),
            "validation", "2024-07-01",
        )
        self.assertEqual("cve", case["label_provenance"])

    def test_linked_issue_provenance_is_distinguished_from_title_keyword(self):
        case = build_case(
            _pull(CRYPTO_FIX, title="Fix token hashing", body="Fixes #1234"),
            "validation", "2024-07-01",
        )
        self.assertEqual("linked-issue", case["label_provenance"])

    def test_separate_hunks_become_separate_seed_findings(self):
        two_spots = (
            "diff --git a/pkg/a.py b/pkg/a.py\n--- a/pkg/a.py\n+++ b/pkg/a.py\n"
            "@@ -3,3 +3,3 @@ def one():\n ctx\n-md5(a)\n+sha256(a)\n"
            "@@ -40,3 +40,3 @@ def two():\n ctx\n-md5(b)\n+sha256(b)\n"
        )
        case = build_case(_pull(two_spots), "validation", "2024-07-01")
        self.assertEqual(2, len(case["expected_findings"]))
        # 不并成一条宽区间：区间越宽命中判定越松，指标越虚高。
        for finding in case["expected_findings"]:
            self.assertEqual(finding["start_line"], finding["end_line"])

    def test_wide_contiguous_seed_spans_are_rejected(self):
        body = "".join("-old_%d\n" % i for i in range(12)) + "+new\n"
        wide = (
            "diff --git a/pkg/a.py b/pkg/a.py\n--- a/pkg/a.py\n+++ b/pkg/a.py\n"
            "@@ -1,14 +1,3 @@\n" + body
        )
        with self.assertRaises(CaseRejected) as ctx:
            build_case(_pull(wide, title="Fix bug"), "validation", "2024-07-01")
        self.assertEqual("seed-span-too-wide", ctx.exception.reason)


class CoverageReportTests(unittest.TestCase):
    def _case(self, **kwargs):
        base = {
            "repository": "octocat/hello", "split": "validation",
            "difficulty": "L1", "defect_class": "crypto-weak",
            "contamination_split": "post-cutoff", "label_provenance": "title-keyword",
        }
        base.update(kwargs)
        return base

    def test_thin_defect_classes_are_warned_about(self):
        report = summarise([self._case()])
        self.assertTrue(any("injection" in text for text in report.warnings))

    def test_a_mostly_defaulted_class_distribution_is_a_hard_violation(self):
        """兜底占多数时，类别分布不是结论，必须硬失败。

        实测触发过这条：第三批 95 条里 60 条（63%）的 defect_class 是
        兜底默认值，而报告把它们和 26 条判出来的合并成 "logic-boundary
        90.5%"。那个数字会被读成"这批数据以边界缺陷为主"，
        真相是"这批数据的类别大多判不出来"。
        """
        cases = [self._case(defect_class="logic-boundary",
                            defect_class_basis="fallback-default")
                 for _ in range(7)]
        cases += [self._case(defect_class_basis="code-pattern") for _ in range(3)]
        report = summarise(cases)
        violation = [t for t in report.warnings if "HARD CONSTRAINT VIOLATED" in t]
        self.assertTrue(violation)
        self.assertIn("fallback default", violation[0])
        self.assertIn("7/10", violation[0])

    def test_a_mostly_judged_distribution_does_not_trigger_the_violation(self):
        """判出来的占多数时不能报这条，否则告警失去区分力。"""
        cases = [self._case(defect_class_basis="code-pattern") for _ in range(8)]
        cases += [self._case(defect_class="logic-boundary",
                             defect_class_basis="fallback-default")
                  for _ in range(2)]
        report = summarise(cases)
        self.assertFalse([t for t in report.warnings
                          if "fallback default" in t])

    def test_the_fallback_warning_comes_before_the_thin_class_warnings(self):
        """顺序有意义：先说"类别分布不成立"，再说"某类不足"。

        反了的话读者会先去补那几个稀缺类，而真正该先做的是修分类器
        或者承认类别报不了。
        """
        cases = [self._case(defect_class="logic-boundary",
                            defect_class_basis="fallback-default")
                 for _ in range(9)]
        report = summarise(cases)
        texts = report.warnings
        hard = next(i for i, t in enumerate(texts) if "HARD CONSTRAINT" in t)
        thin = next(i for i, t in enumerate(texts) if "has 0 cases" in t)
        self.assertLess(hard, thin)

    def test_repository_overlap_across_splits_is_reported_as_a_hard_violation(self):
        report = summarise([
            self._case(split="validation"),
            self._case(split="holdout"),
        ])
        self.assertTrue(
            any("HARD CONSTRAINT VIOLATED" in text for text in report.warnings)
        )

    def test_summarise_accepts_a_generator_without_losing_the_overlap_check(self):
        """两次遍历的坑：传生成器时第二次会拿到空序列，硬约束会静默失效。"""
        cases = [self._case(split="validation"), self._case(split="holdout")]
        report = summarise(iter(cases))
        self.assertEqual(2, report.total)
        self.assertTrue(
            any("HARD CONSTRAINT VIOLATED" in text for text in report.warnings)
        )

    def test_rejection_reasons_are_carried_through_for_the_funnel(self):
        report = summarise([self._case()], {"not-a-bugfix": 120, "too-many-lines": 30})
        self.assertEqual(120, report.rejections["not-a-bugfix"])


if __name__ == "__main__":
    unittest.main()
