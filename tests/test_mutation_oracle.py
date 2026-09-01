"""变异 Oracle 的测试。

重点不在"算子能跑"，而在**效度**：
  - 变异体不能带视觉线索（`return not (100)` 这类真实代码不会出现的写法）
  - 说不清"正确形态"的点位必须跳过（链式比较、有 else 的 if、跨行）
  - 等价性三档必须真的分开，尤其 no-difference 不能和 not-attempted 混
每条测试都做过变异检查：把实现改回错误形态，确认它会红。
"""
import ast
import unittest

from evoagent.mutation_oracle import (
    OPERATORS, build_mutation_case, build_mutation_dataset, check_equivalence,
    equivalence_summary, generate_mutations, ratio_or_none, synthesize_diff,
)
from evoagent.evaluation_harness import validate_case


def operators_of(source):
    return [m.operator for m in generate_mutations(source)]


def only(source, operator):
    return [m for m in generate_mutations(source) if m.operator == operator]


class ComparisonTests(unittest.TestCase):
    def test_lt_becomes_lte(self):
        """< → <=，也就是真实 off-by-one 的形态。"""
        mutation, = only("x = 1\nif x < 10:\n    pass\n",
                         "comparison-boundary")
        self.assertEqual(mutation.mutated_line.strip(), "if x <= 10:")

    def test_gte_becomes_gt(self):
        mutation, = only("x = 1\nif x >= 10:\n    pass\n",
                         "comparison-boundary")
        self.assertEqual(mutation.mutated_line.strip(), "if x > 10:")

    def test_equality_is_not_mutated(self):
        """== / != 不动：改成 < 之类不是边界缺陷，是完全不同的逻辑。"""
        self.assertNotIn("comparison-boundary",
                         operators_of("x = 1\nif x == 10:\n    pass\n"))

    def test_chained_comparison_is_skipped(self):
        """链式比较跳过：改一个算子后"正确形态"说不清，标签就不可靠。

        用 `0 <= x < 10` 而不是 `0 < x < 10`。后者里 `<` 出现两次，会被
        _swap_operator_in_line 的歧义检查挡掉——那样这条测试通过的是
        另一个机制，删掉 len(ops)==1 这道判定也不会红（实测确认过）。
        `<=` 只出现一次，才真正测到"排除链式"这件事。
        """
        self.assertNotIn("comparison-boundary",
                         operators_of("x = 1\nif 0 <= x < 10:\n    pass\n"))

    def test_ambiguous_line_is_skipped(self):
        """一行里同一个算子出现两次就放弃：改哪一个都说不清。"""
        self.assertEqual(
            [], only("a = b = 1\nif a < 5 or b < 6:\n    pass\n",
                     "comparison-boundary"))


class BooleanTests(unittest.TestCase):
    def test_and_becomes_or(self):
        mutation, = only("a = b = 1\nif a and b:\n    pass\n",
                         "boolean-operator")
        self.assertEqual(mutation.mutated_line.strip(), "if a or b:")

    def test_or_becomes_and(self):
        mutation, = only("a = b = 1\nc = a or b\n", "boolean-operator")
        self.assertEqual(mutation.mutated_line.strip(), "c = a and b")


class ConstantTests(unittest.TestCase):
    def test_constant_gets_plus_one(self):
        mutation, = only("size = 4096\n", "constant-offset")
        self.assertEqual(mutation.mutated_line.strip(), "size = 4097")

    def test_zero_and_one_are_skipped(self):
        """0 和 1 不动：+1 后往往是另一种合法写法，不构成缺陷。"""
        self.assertEqual([], only("a = 0\nb = 1\n", "constant-offset"))

    def test_booleans_are_not_treated_as_ints(self):
        """bool 是 int 的子类。不显式排除的话 True 会变成 2。"""
        self.assertEqual([], only("flag = True\n", "constant-offset"))


class WeakenedGuardTests(unittest.TestCase):
    SOURCE = "a = b = 1\nif a and b:\n    pass\n"

    def test_guard_drops_the_last_conjunct(self):
        mutation, = only(self.SOURCE, "weakened-guard")
        self.assertEqual(mutation.mutated_line.strip(), "if a:")

    def test_weakened_guard_is_high_severity(self):
        """少一道检查比算错边界严重，严重度必须体现出来。"""
        mutation, = only(self.SOURCE, "weakened-guard")
        self.assertEqual(mutation.severity, "high")

    def test_guard_with_else_is_skipped(self):
        """有 else 的跳过：改了说不清是"少检查"还是"走错分支"。"""
        self.assertEqual([], only(
            "a = b = 1\nif a and b:\n    pass\nelse:\n    pass\n",
            "weakened-guard"))

    def test_single_condition_guard_is_skipped(self):
        """只有一个条件时没有可删的合取项。"""
        self.assertEqual([], only("a = 1\nif a:\n    pass\n",
                                  "weakened-guard"))


class NegatedReturnTests(unittest.TestCase):
    """这一组全是**效度**测试：变异体不能带视觉线索。"""

    def test_bool_literal_is_flipped_not_wrapped(self):
        """return False → return True，不是 return not (False)。

        后者是真实代码里不会出现的写法，agent 单看"这行很怪"就能报出来，
        样本因此因为错误的理由变简单。
        """
        mutation, = only("def f():\n    return False\n", "negated-return")
        self.assertEqual(mutation.mutated_line.strip(), "return True")

    def test_existing_not_is_dropped(self):
        """return not x → return x，模拟"漏写 not"，也是真实缺陷形态。"""
        mutation, = only("def f(x):\n    return not x\n", "negated-return")
        self.assertEqual(mutation.mutated_line.strip(), "return x")

    def test_comparison_gets_wrapped(self):
        mutation, = only("def f(x):\n    return x > 3\n", "negated-return")
        self.assertEqual(mutation.mutated_line.strip(), "return not (x > 3)")

    def test_non_boolean_return_is_skipped_entirely(self):
        """return 100 不产出变异：not (100) 是 False，返回类型都变了。"""
        self.assertEqual([], only("def f():\n    return 100\n",
                                  "negated-return"))

    def test_bare_name_return_is_skipped(self):
        """裸变量名跳过：语法层判不出 flag 是 bool 还是 list。"""
        self.assertEqual([], only("def f(flag):\n    return flag\n",
                                  "negated-return"))

    def test_no_mutation_ever_produces_not_on_an_int(self):
        """跨算子的整体断言：任何变异体都不该出现 `not (<整数>)`。"""
        source = "def f(n):\n    if n > 5:\n        return 100\n    return 200\n"
        for mutation in generate_mutations(source):
            self.assertNotRegex(mutation.mutated_line, r"not \(\s*\d+\s*\)")


class SynthesisTests(unittest.TestCase):
    SOURCE = ("def check(size):\n"
              "    if size < 4096:\n"
              "        return False\n"
              "    return True\n")

    def test_every_case_passes_the_shared_validator(self):
        """验收标准：变异样本走的是同一套 validate_case 与匹配代码。"""
        for index, mutation in enumerate(generate_mutations(self.SOURCE)):
            case = build_mutation_case("pkg/m.py", self.SOURCE, mutation, index)
            validate_case(case)        # 不合法会抛

    def test_mutated_line_is_the_added_line(self):
        """方向断言：变异后的代码是 `+` 行，和反转修复数据集方向一致。"""
        mutation, = only(self.SOURCE, "weakened-guard") or only(
            self.SOURCE, "comparison-boundary")
        diff = synthesize_diff("pkg/m.py", self.SOURCE, mutation)
        added = [line[1:] for line in diff.splitlines()
                 if line.startswith("+") and not line.startswith("+++")]
        self.assertEqual(added, [mutation.mutated_line])

    def test_finding_range_is_a_single_line(self):
        """范围放宽会稀释命中判定，必须是单行。"""
        mutation = generate_mutations(self.SOURCE)[0]
        case = build_mutation_case("pkg/m.py", self.SOURCE, mutation, 0)
        finding, = case["expected_findings"]
        self.assertEqual(finding["start_line"], finding["end_line"])

    def test_hunk_header_line_count_matches_the_body(self):
        """@@ 里的行数写错，parse_unified_diff 算出的行号就会偏。"""
        mutation = generate_mutations(self.SOURCE)[0]
        diff = synthesize_diff("pkg/m.py", self.SOURCE, mutation)
        header = [line for line in diff.splitlines()
                  if line.startswith("@@")][0]
        declared = int(header.split()[2].split(",")[1])
        body = diff.splitlines()[4:]
        new_side = [line for line in body if not line.startswith("-")]
        self.assertEqual(declared, len(new_side))

    def test_cases_land_in_holdout_by_default(self):
        """变异集默认 holdout：进 validation 会被间接拟合，独立性就没了。"""
        mutation = generate_mutations(self.SOURCE)[0]
        case = build_mutation_case("pkg/m.py", self.SOURCE, mutation, 0)
        self.assertEqual(case["split"], "holdout")


class EquivalenceTests(unittest.TestCase):
    def test_behaviour_difference_is_proven(self):
        source = "def f(n):\n    return n > 3\n"
        mutation, = only(source, "comparison-boundary")
        checked = check_equivalence(source, mutation)
        self.assertEqual(checked.equivalence_status, "proven")
        self.assertTrue(checked.equivalence_checked)

    def test_dead_code_mutation_reports_no_difference(self):
        """x 未被使用，改它不影响行为——真等价体，假标签就在这一档。"""
        source = "def f(n):\n    x = 5\n    return n > 0\n"
        mutation, = only(source, "constant-offset")
        checked = check_equivalence(source, mutation)
        self.assertEqual(checked.equivalence_status, "no-difference")
        self.assertFalse(checked.equivalence_checked)

    def test_no_difference_is_not_the_same_as_not_attempted(self):
        """三档的核心：跑了没测出差异 ≠ 没跑。前者才有反向证据。"""
        ran = check_equivalence(
            "def f(n):\n    x = 5\n    return n > 0\n",
            only("def f(n):\n    x = 5\n    return n > 0\n",
                 "constant-offset")[0])
        self.assertNotEqual(ran.equivalence_status, "not-attempted")

    def test_method_is_not_attempted(self):
        """类方法要先造 self，跑不动。必须标 not-attempted 而不是无差异。"""
        source = "class C:\n    def f(self, n):\n        return n > 3\n"
        mutation, = only(source, "comparison-boundary")
        self.assertEqual(check_equivalence(source, mutation)
                         .equivalence_status, "not-attempted")

    def test_impure_function_is_not_attempted(self):
        """碰磁盘的不跑：评测过程不该有副作用。"""
        source = "def f(n):\n    if n > 3:\n        return open(str(n))\n"
        mutation, = only(source, "comparison-boundary")
        self.assertEqual(check_equivalence(source, mutation)
                         .equivalence_status, "not-attempted")

    def test_constant_harvesting_reaches_code_specific_boundaries(self):
        """探测值必须含函数体里的常量及邻居。

        `n > 100` 改成 `n > 101` 只在 n == 101 时行为不同。固定网格不可能
        预置 101——不采常量的话这个样本会被误报成 no-difference。
        """
        source = "def clamp(n):\n    if n > 100:\n        return 100\n    return n\n"
        mutation, = [m for m in generate_mutations(source)
                     if m.operator == "constant-offset" and m.line == 2]
        self.assertEqual(check_equivalence(source, mutation)
                         .equivalence_status, "proven")

    def test_exception_type_alone_can_prove_a_difference(self):
        """两侧都抛异常、只有**类型**不同时也必须判为非等价。

        构造成两侧都抛是刻意的：如果一侧正常返回、另一侧抛异常，
        那么就算把异常一律记成同一个值，两侧仍然不同——测试会通过，
        测到的却是"返回值不同"这个别的机制（实测确认过 GREEN）。
        只有都抛异常，才逼着比较必须区分异常类型。
        n == 1 时：原始走 10 // 0 → ZeroDivisionError
                   变异走 "x" + 1 → TypeError
        """
        source = ("def f(n):\n"
                  "    if n >= 1:\n"
                  "        return 10 // (n - 1)\n"
                  '    return "x" + 1\n')
        mutation, = [m for m in generate_mutations(source)
                     if m.operator == "comparison-boundary"]
        self.assertEqual(check_equivalence(source, mutation)
                         .equivalence_status, "proven")


class SummaryTests(unittest.TestCase):
    def test_suspect_rate_is_none_when_nothing_ran(self):
        """一个样本都没跑过差分执行 = 没有结论。0.0 会被读成"没有可疑样本"。"""
        cases = [{"equivalence_status": "not-attempted",
                  "mutation_operator": "constant-offset"}] * 3
        self.assertIsNone(equivalence_summary(cases)["suspect_rate"])

    def test_not_attempted_stays_out_of_the_denominator(self):
        """分母只含真跑过的样本，否则可疑率会被大量"没跑"稀释成好看的小数。"""
        cases = [
            {"equivalence_status": "proven", "mutation_operator": "a"},
            {"equivalence_status": "no-difference", "mutation_operator": "a"},
            {"equivalence_status": "not-attempted", "mutation_operator": "a"},
        ] * 1
        self.assertEqual(equivalence_summary(cases)["suspect_rate"], 0.5)

    def test_ratio_or_none_never_returns_zero_for_an_empty_denominator(self):
        self.assertIsNone(ratio_or_none(0, 0))
        self.assertEqual(ratio_or_none(0, 4), 0.0)


class DatasetTests(unittest.TestCase):
    SOURCES = [
        ("pkg/a.py", "def f(n):\n    if n < 10 and n:\n        return False\n"),
        ("pkg/b.py", "def g(n):\n    if n > 20 and n:\n        return True\n"),
    ]

    def test_per_operator_quota_is_respected(self):
        """配额存在的理由：各算子点位数差一个数量级，不配额的话总体
        召回率其实主要在测点位最多的那一个算子。"""
        cases = build_mutation_dataset(self.SOURCES, per_operator=1, check=False)
        counts = {}
        for case in cases:
            key = case["mutation_operator"]
            counts[key] = counts.get(key, 0) + 1
        self.assertTrue(all(value == 1 for value in counts.values()), counts)

    def test_output_is_deterministic(self):
        """评测要可复算：同样输入必须给出同一批样本，不能依赖集合序。"""
        first = build_mutation_dataset(self.SOURCES, check=False)
        second = build_mutation_dataset(self.SOURCES, check=False)
        self.assertEqual([case["id"] for case in first],
                         [case["id"] for case in second])

    def test_all_generated_cases_are_valid(self):
        for case in build_mutation_dataset(self.SOURCES, check=False):
            validate_case(case)

    def test_every_declared_operator_can_fire(self):
        """OPERATORS 里列的算子必须都是活的，不能有名存实亡的。"""
        source = ("def f(n, m):\n"
                  "    if n < 10 and m:\n"
                  "        return False\n"
                  "    return n > 20\n")
        self.assertEqual(set(OPERATORS), set(operators_of(source)))


if __name__ == "__main__":
    unittest.main()
