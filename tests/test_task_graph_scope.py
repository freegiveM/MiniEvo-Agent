"""planner 分配的文件范围，以及工具层的强制。

这一层最容易写错的是**兜底方向**。范围给窄了会漏报且不报错，给宽了
只是多花 token——代价不对称，所以分不出来时必须退回全集。
下面有一整个 class 专门钉这件事。
"""
import unittest

from evoagent.agentic_core import _plan_scopes
from evoagent.diff_parser import parse_unified_diff
from evoagent.repository_tools import RepositoryToolSuite, _normalise_scope_path
from evoagent.telemetry import ExecutionLedger

DIFF = (
    "diff --git a/app/api.py b/app/api.py\n"
    "--- a/app/api.py\n"
    "+++ b/app/api.py\n"
    "@@ -1,0 +1,1 @@\n"
    "+token = \"abc\"\n"
    "diff --git a/app/db.py b/app/db.py\n"
    "--- a/app/db.py\n"
    "+++ b/app/db.py\n"
    "@@ -1,0 +1,1 @@\n"
    "+query = \"SELECT 1\"\n"
)
FILES = ["app/api.py", "app/db.py"]


class ScopeAssignmentTests(unittest.TestCase):

    def test_a_listed_scope_is_honoured(self):
        graph = [{"specialist": "security", "files": ["app/api.py"]}]
        self.assertEqual(_plan_scopes(graph, FILES), {"security": {"app/api.py"}})

    def test_diff_prefixes_are_normalised(self):
        """planner 常照抄 diff 里的 b/ 前缀。不归一化就一个都匹配不上，
        范围会被判成空，然后走兜底——约束静默失效。"""
        graph = [{"specialist": "security", "files": ["b/app/api.py"]}]
        self.assertEqual(_plan_scopes(graph, FILES), {"security": {"app/api.py"}})

    def test_files_outside_the_change_set_are_dropped(self):
        """planner 可能凭空编路径。放进范围等于给了一个不存在的许可，
        事后查越界记录时会误导。"""
        graph = [{"specialist": "security",
                  "files": ["app/api.py", "app/nonexistent.py"]}]
        self.assertEqual(_plan_scopes(graph, FILES), {"security": {"app/api.py"}})

    def test_each_specialist_gets_its_own_scope(self):
        graph = [
            {"specialist": "security", "files": ["app/api.py"]},
            {"specialist": "correctness-reliability", "files": ["app/db.py"]},
        ]
        scopes = _plan_scopes(graph, FILES)
        self.assertEqual(scopes["security"], {"app/api.py"})
        self.assertEqual(scopes["correctness-reliability"], {"app/db.py"})


class FallbackTests(unittest.TestCase):
    """兜底必须是全集，不能是空集。

    这四条测的是同一个决定的四种触发路径。写成空集的话，planner 一犯错
    就有文件没人看，缺陷漏报，而且不报错——报出来的是"评审通过"。
    """

    def _has_no_scope(self, graph):
        """返回 True 表示该角色没有范围限制，即走了兜底（看全集）。"""
        return "security" not in _plan_scopes(graph, FILES)

    def test_missing_files_key_falls_back(self):
        self.assertTrue(self._has_no_scope([{"specialist": "security"}]))

    def test_empty_file_list_falls_back(self):
        self.assertTrue(self._has_no_scope([{"specialist": "security", "files": []}]))

    def test_all_files_invalid_falls_back(self):
        """给的文件全都不在改动集里 → 退回全集，而不是"一个都不许看"。"""
        self.assertTrue(self._has_no_scope(
            [{"specialist": "security", "files": ["other/thing.py"]}]))

    def test_a_string_instead_of_a_list_falls_back(self):
        """files 给成字符串（模型常犯）要退回全集。

        注意这条**不能**用来验证类型检查：字符串会逐字符迭代成
        ['a','p','p','/',...]，与改动集交集为空，靠兜底也能退回全集。
        真正需要类型检查的是下一条（实测确认过）。
        """
        self.assertTrue(self._has_no_scope(
            [{"specialist": "security", "files": "app/api.py"}]))

    def test_a_dict_instead_of_a_list_falls_back(self):
        """dict 才是必须靠类型检查挡住的输入。

        dict 迭代出的是 key，而 key 可能正好是真实路径——那样它就绕过了
        "交集为空则兜底"，被当成一份合法范围接受。少了 isinstance 判定
        这条就会红（实测确认过）。
        """
        self.assertTrue(self._has_no_scope(
            [{"specialist": "security", "files": {"app/api.py": "why"}}]))

    def test_an_empty_task_graph_gives_no_scopes_at_all(self):
        self.assertEqual(_plan_scopes([], FILES), {})


class ToolLayerEnforcementTests(unittest.TestCase):
    """约束在工具层，不在 prompt。"""

    def setUp(self):
        self.parsed = parse_unified_diff(DIFF)
        self.ledger = ExecutionLedger("agentic")
        self.suite = RepositoryToolSuite("", DIFF, self.parsed, self.ledger)

    def test_in_scope_path_is_allowed(self):
        registry = self.suite.registry(
            "security", {"changed_line"}, {"app/api.py"})
        value = registry.invoke("changed_line", {"path": "app/api.py", "line": 1})
        self.assertTrue(value["output"]["found"])

    def test_out_of_scope_path_is_refused(self):
        registry = self.suite.registry(
            "security", {"changed_line"}, {"app/api.py"})
        with self.assertRaises(Exception) as caught:
            registry.invoke("changed_line", {"path": "app/db.py", "line": 1})
        self.assertIn("out of assigned scope", str(caught.exception))

    def test_the_refusal_names_the_assigned_scope(self):
        """只说"不许"的话 specialist 只能盲试，给出范围它能立刻改到
        该看的文件上，一次工具预算不白花。"""
        registry = self.suite.registry(
            "security", {"changed_line"}, {"app/api.py"})
        with self.assertRaises(Exception) as caught:
            registry.invoke("changed_line", {"path": "app/db.py", "line": 1})
        self.assertIn("app/api.py", str(caught.exception))

    def test_a_refusal_is_recorded_in_the_ledger(self):
        """越界必须留痕。没有痕迹就分不清"planner 分错了范围"和
        "specialist 不守范围"，而这两件事的修法不同。"""
        registry = self.suite.registry(
            "security", {"changed_line"}, {"app/api.py"})
        with self.assertRaises(Exception):
            registry.invoke("changed_line", {"path": "app/db.py", "line": 1})
        failed = [item for item in self.ledger.tool_calls if not item.ok]
        self.assertEqual(len(failed), 1)
        self.assertIn("out of assigned scope", failed[0].error)

    def test_no_scope_means_no_restriction(self):
        """allowed_paths=None 时不做检查。这是兜底路径在工具层的体现。"""
        registry = self.suite.registry("security", {"changed_line"}, None)
        self.assertTrue(
            registry.invoke(
                "changed_line", {"path": "app/db.py", "line": 1})["output"]["found"])

    def test_tools_without_a_path_argument_are_untouched(self):
        """search_diff 不带 path，不能被范围检查误拦。"""
        registry = self.suite.registry(
            "security", {"search_diff"}, {"app/api.py"})
        self.assertIsNotNone(registry.invoke("search_diff", {"query": "token"}))

    def test_prefixed_path_cannot_bypass_the_check(self):
        """`b/app/db.py` 必须和 `app/db.py` 判成同一个文件，
        否则加个前缀就绕过了整个约束。"""
        registry = self.suite.registry(
            "security", {"changed_line"}, {"app/api.py"})
        with self.assertRaises(Exception):
            registry.invoke("changed_line", {"path": "b/app/db.py", "line": 1})


class NormalisationTests(unittest.TestCase):

    def test_backslashes_become_slashes(self):
        self.assertEqual(_normalise_scope_path("app\\db.py"), "app/db.py")

    def test_diff_prefixes_are_stripped(self):
        self.assertEqual(_normalise_scope_path("a/app/db.py"), "app/db.py")
        self.assertEqual(_normalise_scope_path("b/app/db.py"), "app/db.py")
        self.assertEqual(_normalise_scope_path("./app/db.py"), "app/db.py")

    def test_a_bare_path_is_unchanged(self):
        self.assertEqual(_normalise_scope_path("app/db.py"), "app/db.py")

    def test_a_filename_starting_with_a_is_not_mangled(self):
        """`api/x.py` 不能被当成 `a` 前缀切掉。

        用 lstrip("ab/") 就会踩这个坑（它按字符集剥，不按前缀），
        所以实现用的是逐个 startswith 判定。
        """
        self.assertEqual(_normalise_scope_path("api/x.py"), "api/x.py")
        self.assertEqual(_normalise_scope_path("build/x.py"), "build/x.py")


if __name__ == "__main__":
    unittest.main()
