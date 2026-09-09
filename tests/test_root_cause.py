"""根因指纹：分桶计数的键，以及它刻意**不**依赖 LLM 聚类这件事。

## 为什么这批测试盯着"确定性"

指纹是频率门禁的输入。一个会漂的键会让门禁行为不可复现——今天同一批
数据达标，明天不达标，而没人改过代码。所以这里的核心断言是：同一个
根因的不同书写形式（大小写、路径分隔符、`./` 前缀）必须落到同一个桶，
而不同根因必须落到不同桶。

`partition_by_occurrence` 的低频档同样要钉住：低于阈值的 case 不是被
丢弃，它仍然在返回值里，只是不该为它发起一次候选生成 + 全量回放。
"""
import unittest

from evoagent.root_cause import (
    count_by_fingerprint,
    describe,
    fingerprint,
    fingerprint_case,
    normalize_path,
    partition_by_occurrence,
)


def _case(category="missed_issue", rule_id="SEC-EVAL", path="a/b.py"):
    return {
        "category": category,
        "payload": {"finding": {"rule_id": rule_id, "path": path}},
    }


class NormalizePathTests(unittest.TestCase):
    def test_separators_and_case_are_normalized(self):
        """Windows 与 POSIX 分隔符、大小写都不该分出两个桶。

        同一份代码在两台机器上产生的反馈必须归到一处，否则计数被腰斩，
        阈值永远达不到。
        """
        self.assertEqual("a/b.py", normalize_path("a\\b.py"))
        self.assertEqual("a/b.py", normalize_path("./A/b.py"))
        self.assertEqual("a/b.py", normalize_path("a//b.py"))
        self.assertEqual("a/b.py", normalize_path("  a/b.py  "))

    def test_distinct_files_stay_distinct(self):
        """不做"只留文件名"这类激进归一化。

        `a/utils.py` 和 `b/utils.py` 是两个文件；合并它们会把不相关的
        缺陷算进同一个桶，虚高计数并让阈值提前达标。
        """
        self.assertNotEqual(normalize_path("a/utils.py"), normalize_path("b/utils.py"))

    def test_empty_and_degenerate_paths_collapse_to_blank(self):
        for raw in ("", "   ", ".", "/", None):
            self.assertEqual("", normalize_path(raw))

    def test_a_leading_dot_in_a_filename_survives(self):
        """点文件的前导点不能被吃掉。

        这里曾经以 `lstrip("./")` 收尾，而 `lstrip` 的参数是字符集合而不是
        前缀，于是 `.github/workflows/ci.yml` 被削成 `github/workflows/ci.yml`、
        `.env` 被削成 `env`。两个后果：`describe()` 用同一个函数，报告里的
        路径与仓库里的真实路径对不上；仓库里真有 `env` 或 `github/` 时，两个
        不相关的根因会共用一个桶和一份重试计数。
        """
        self.assertEqual(".github/workflows/ci.yml",
                         normalize_path(".github/workflows/ci.yml"))
        self.assertEqual(".env", normalize_path(".env"))
        self.assertNotEqual(normalize_path(".env"), normalize_path("env"))

    def test_dot_slash_is_still_stripped(self):
        """去掉 lstrip 之后 `./` 仍然要被消掉——那是 normpath 的活。"""
        self.assertEqual("a/b.py", normalize_path("./a/b.py"))
        self.assertEqual("a/b.py", normalize_path("./a/./b.py"))

    def test_a_path_escaping_the_repo_is_not_merged_with_one_inside(self):
        """`../a.py` 与 `a.py` 不是同一个文件。

        与"不剥目录只留文件名"同因：合并它们会把不相关的缺陷算进同一个桶。
        """
        self.assertNotEqual(normalize_path("../a.py"), normalize_path("a.py"))


class FingerprintTests(unittest.TestCase):
    def test_the_same_root_cause_written_differently_is_one_bucket(self):
        self.assertEqual(
            fingerprint_case(_case(rule_id="sec-eval", path="./A/b.py")),
            fingerprint_case(_case(rule_id="SEC-EVAL", path="a\\b.py")),
        )

    def test_each_component_changes_the_bucket(self):
        base = fingerprint_case(_case())
        self.assertNotEqual(base, fingerprint_case(_case(category="false_positive")))
        self.assertNotEqual(base, fingerprint_case(_case(rule_id="SEC-OTHER")))
        self.assertNotEqual(base, fingerprint_case(_case(path="c/d.py")))

    def test_a_missing_finding_degrades_instead_of_raising(self):
        """没有 rule_id 的反馈信息量确实更少，它归入一个更粗的桶。

        粗桶更容易达标阈值，但那如实反映了"这个类别反复出现"——不精确，
        不虚构。这里要的是不抛异常、且仍然确定性。
        """
        for payload in ({}, {"finding": None}, {"finding": "not-a-dict"}):
            case = {"category": "bad_fix", "payload": payload}
            self.assertEqual(
                fingerprint("bad_fix", "", ""), fingerprint_case(case),
            )

    def test_the_fingerprint_is_short_and_hex(self):
        value = fingerprint_case(_case())
        self.assertEqual(16, len(value))
        int(value, 16)

    def test_describe_is_readable_and_names_the_gaps(self):
        self.assertEqual("missed_issue@SEC-EVAL:a/b.py", describe(_case()))
        self.assertEqual(
            "bad_fix@no-rule:no-path",
            describe({"category": "bad_fix", "payload": {}}),
        )


class OccurrenceTests(unittest.TestCase):
    def test_counting_groups_equivalent_cases(self):
        counts = count_by_fingerprint([
            _case(path="a/b.py"), _case(path="./A/b.py"), _case(path="c/d.py"),
        ])
        self.assertEqual({2, 1}, set(counts.values()))
        self.assertEqual(2, len(counts))

    def test_a_root_cause_at_the_threshold_is_systematic(self):
        """边界取 >=，不是 >。阈值 3 的含义是"出现 3 次就算系统性"。"""
        case = _case()
        history = {fingerprint_case(case): 3}
        parts = partition_by_occurrence([case], history, 3)
        self.assertEqual([case], parts["systematic"])
        self.assertEqual([], parts["sporadic"])

    def test_a_low_frequency_case_is_returned_not_discarded(self):
        """低频档仍在返回值里——调用方应当写进记忆，只是不发起候选生成。

        静默丢弃会让"报了反馈但什么都没发生"看起来像 bug，而实际上是
        这条根因还不够格触发一次几十次 LLM 调用的回放。
        """
        case = _case()
        parts = partition_by_occurrence([case], {fingerprint_case(case): 2}, 3)
        self.assertEqual([], parts["systematic"])
        self.assertEqual([case], parts["sporadic"])

    def test_an_unseen_root_cause_is_sporadic_not_an_error(self):
        parts = partition_by_occurrence([_case()], {}, 3)
        self.assertEqual([_case()], parts["sporadic"])

    def test_a_threshold_below_one_is_clamped(self):
        """阈值 0 会让"从未出现过"也算系统性，那个门禁等于不存在。"""
        case = _case()
        parts = partition_by_occurrence([case], {fingerprint_case(case): 1}, 0)
        self.assertEqual([case], parts["systematic"])


if __name__ == "__main__":
    unittest.main()