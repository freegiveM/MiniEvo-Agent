"""补丁改动范围断言的测试。

为什么要这道断言：没有它时，一个改遍全文件的补丁能拿到 verified-draft。
实测 REL-DEBUG-PRINT 的修复是全文 re.sub，finding 指向第 2 行，补丁把
文件末尾第 50 行的 print 也删了——compile 过、风险移除过、回归断言过，
于是判为"可复核的草稿"，可它动了与缺陷无关的代码。

与 MAX_SEED_SPAN 是同一条纪律的两端：那条管标注范围别太宽，这条管补丁
范围别太宽。两者宽了都会让"命中"失去意义。

每条测试都做过变异检查。
"""
import unittest

from evoagent.evaluation_harness import (
    SCOPE_WINDOW, FixtureRepairer, patch_scope_check,
)
from evoagent.models import Finding, Severity


def numbered(count, start=1):
    return "".join("line%d\n" % index for index in range(start, start + count))


class InScopeTests(unittest.TestCase):
    def test_single_line_edit_at_the_finding_passes(self):
        before = numbered(20)
        after = before.replace("line10\n", "line10_fixed\n")
        self.assertTrue(patch_scope_check(before, after, 10)["passed"])

    def test_edit_at_the_window_edge_passes(self):
        """边界本身算在内（闭区间）。写成开区间会把正常的连带改动判越界。"""
        before = numbered(30)
        target = 10 + SCOPE_WINDOW
        after = before.replace("line%d\n" % target, "fixed\n")
        self.assertTrue(patch_scope_check(before, after, 10)["passed"])

    def test_no_change_is_not_a_scope_violation(self):
        """没生成补丁不是越界，由 patch-generated 那项负责。"""
        before = numbered(10)
        result = patch_scope_check(before, before, 5)
        self.assertTrue(result["passed"])
        self.assertEqual(result["changed_lines"], [])


class OutOfScopeTests(unittest.TestCase):
    def test_edit_one_line_past_the_window_fails(self):
        before = numbered(30)
        target = 10 + SCOPE_WINDOW + 1
        after = before.replace("line%d\n" % target, "fixed\n")
        result = patch_scope_check(before, after, 10)
        self.assertFalse(result["passed"])
        self.assertEqual(result["out_of_scope"], [target])

    def test_whole_file_rewrite_fails(self):
        before = numbered(30)
        after = "".join("rewritten%d\n" % index for index in range(1, 31))
        self.assertFalse(patch_scope_check(before, after, 10)["passed"])

    def test_the_real_repairer_gets_caught(self):
        """端到端断言：现有修复器的全文 re.sub 必须被这道断言抓住。

        不用构造的输入而是走真实 _transform，否则这条测试只证明断言函数
        自己能算，不证明它接在了修复链路上。
        """
        before = ("value = 1\n"
                  + "".join("pad%d = 0\n" % index for index in range(2, 50))
                  + 'print("x")\n')
        finding = Finding(
            rule_id="REL-DEBUG-PRINT", severity=Severity.LOW, title="t",
            explanation="e", path="m.py", line=2, evidence="ev", fix="f",
            test="t")
        after = FixtureRepairer._transform(before, finding)
        result = patch_scope_check(before, after, finding.line)
        self.assertFalse(result["passed"])
        self.assertEqual(result["out_of_scope"], [50])


class ImportInsertionTests(unittest.TestCase):
    """import 插入必须按**段**放行，不能整体判。"""

    def test_import_only_insertion_at_the_top_passes(self):
        """_ensure_import 插在第 1 行，finding 可能在第 300 行。
        不放行的话每个要补 import 的修复都会被判越界。"""
        before = numbered(20)
        after = "import os\n" + before
        self.assertTrue(patch_scope_check(before, after, 15)["passed"])

    def test_import_plus_in_scope_fix_passes(self):
        """secret/eval 修复最常见的形态：头部插 import + 改 finding 那行。

        整体判"补丁是否只插了 import"会把这种正常补丁判成越界
        （实测确认过）。所以必须逐段判。
        """
        before = numbered(20)
        after = ("import os\n" + before).replace("line15\n", "fixed\n")
        result = patch_scope_check(before, after, 15)
        self.assertTrue(result["passed"], result)
        self.assertEqual(result["import_insertions"], 1)

    def test_import_plus_out_of_scope_fix_still_fails(self):
        """放行只对 import 那一段生效，不给整个补丁开免检。"""
        before = numbered(30)
        after = ("import os\n" + before).replace("line25\n", "fixed\n")
        self.assertFalse(patch_scope_check(before, after, 10)["passed"])

    def test_non_import_insertion_is_not_exempt(self):
        before = numbered(20)
        after = "danger = 1\n" + before
        self.assertFalse(patch_scope_check(before, after, 15)["passed"])

    def test_deleting_an_import_is_not_exempt(self):
        """放行只覆盖插入。删 import 是实质改动，不该免检。"""
        before = "import os\n" + numbered(20)
        after = numbered(20)
        self.assertFalse(patch_scope_check(before, after, 15)["passed"])


class AlignmentTests(unittest.TestCase):
    """行号对齐必须用 SequenceMatcher，不能逐下标比较。"""

    def test_insertion_does_not_mark_everything_below_as_changed(self):
        """在 finding 邻域内插一行，不该把它下面所有行都算成改动过。

        逐下标比较会让插入点之后的每一行都错位一格、被判为"不同"，
        于是任何插入类补丁都误报越界。这条测试锁死那个实现。
        """
        before = numbered(40)
        after = before.replace("line10\n", "line10\nguard = True\n")
        result = patch_scope_check(before, after, 10)
        self.assertTrue(result["passed"], result)
        self.assertLessEqual(len(result["changed_lines"]), 2, result)

    def test_deletion_does_not_shift_reported_line_numbers(self):
        """删一行同理：下方行号不该被算成改动。"""
        before = numbered(40)
        after = before.replace("line10\n", "")
        result = patch_scope_check(before, after, 10)
        self.assertTrue(result["passed"], result)
        self.assertEqual(result["changed_lines"], [10])

    def test_line_numbers_are_reported_against_the_original(self):
        """越界行号按**原文**行号报。按补丁后行号报的话，读报告的人
        对不上原始文件，定位不了问题。"""
        before = numbered(40)
        after = "import os\n" + before.replace("line30\n", "fixed\n")
        result = patch_scope_check(before, after, 10)
        self.assertEqual(result["out_of_scope"], [30])


class IntegrationTests(unittest.TestCase):
    def test_scope_check_is_part_of_the_repair_checks(self):
        """断言必须真的接在修复链路上，不是一个没人调用的函数。"""
        case = {
            "after_files": {"m.py": "value = 1\n" + 'print("x")\n' * 3},
            "repair_validation": {
                "auto_fixable": True, "risk_pattern": r"print\(",
            },
        }
        finding = Finding(
            rule_id="REL-DEBUG-PRINT", severity=Severity.LOW, title="t",
            explanation="e", path="m.py", line=2, evidence="ev", fix="f",
            test="t")
        repair = FixtureRepairer().repair(case, finding)
        names = [item["name"] for item in repair["checks"]]
        self.assertIn("patch-scope", names)

    def test_out_of_scope_patch_lands_in_blocked(self):
        """越界不单独设一档：改了无关代码的补丁人类同样不能直接用 → blocked。"""
        from evoagent.evaluation_harness import REPAIR_BLOCKED, repair_tier
        repair = {"passed": False, "checks": [
            {"name": "risk-reproduction", "passed": True},
            {"name": "patch-generated", "passed": True},
            {"name": "patch-scope", "passed": False},
        ]}
        self.assertEqual(repair_tier(repair), REPAIR_BLOCKED)


if __name__ == "__main__":
    unittest.main()
