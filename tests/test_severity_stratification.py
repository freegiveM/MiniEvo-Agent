#!/usr/bin/env python3
"""缺陷层内部按严重度分层的取样契约。

这批测试钉的是**同一个毛病的第二次复发**。第一次是干净样本：入库晚、
id 大，`ORDER BY id LIMIT n` 永远取不到，`clean_accuracy` 分母恒为 0
（见 test_clean_corpus.py）。修好之后往 holdout 补高危缺陷样本，它们同样
排在最后（实测 id 182-214，缺陷层从 id 26 起），于是缺陷层内部
`positive[:quota]` 又把它们全截掉了——holdout 缺陷分母从 1 涨到 110，
而 `high_severity_denominator` 在 `limit=20` 下**仍然是 1**。

为什么这一次更隐蔽：`high_severity_recall` 在 `_protected_metrics` 里是
**无条件**列入的受保护指标，没有 `clean_accuracy` 那种
`if baseline["clean_cases"]` 把关。分母为 0 时 `_metric_non_regressing`
按"本来没测过，无从回退"放行，它恒通过；分母为 1 时指标照常打印一个
0.0/1.0 的读数，看不出它只有两档。**一道分母为 1 的门禁和一道分母为 0 的
门禁一样，都是在假装工作。**
"""

from __future__ import annotations

import os
import shutil
import tempfile
import unittest

from evoagent.store import TaskStore

DIFF_TEMPLATE = """diff --git a/mod_%(index)d.py b/mod_%(index)d.py
index 1111111..2222222 100644
--- a/mod_%(index)d.py
+++ b/mod_%(index)d.py
@@ -1,2 +1,3 @@
 import os
+value_%(index)d = os.environ["TOKEN_%(index)d"]
 print(os.name)
"""


def is_high(case: dict) -> bool:
    """和 `evaluation_harness` 里 `high_severity_recall` 的口径对齐。"""

    return any(
        str(item.get("min_severity", "")).lower() in ("high", "critical")
        for item in case["expected"]
    )


class _SeverityFixture(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.store = TaskStore(os.path.join(self.tmp, "evo.db"))
        self._next = 0

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _seed(
        self, medium: int, high: int, cleans: int = 0, split: str = "validation",
    ) -> None:
        """先灌 medium、再灌 high、最后灌干净，复现真实入库顺序。

        高危样本是后来为了补 `high_severity_recall` 的分母才导入的，
        id 必然更大——这正是缺陷层内部按 id 截断取不到它们的原因。
        """

        for severity, count in (("medium", medium), ("high", high)):
            for _ in range(count):
                self._next += 1
                index = self._next
                self.store.save_evaluation_case(
                    "%s-%d" % (severity, index),
                    split,
                    DIFF_TEMPLATE % {"index": index},
                    [{
                        "path": "mod_%d.py" % index,
                        "line": 2,
                        "min_severity": severity,
                    }],
                )
        for _ in range(cleans):
            self._next += 1
            index = self._next
            self.store.save_evaluation_case(
                "clean-%d" % index, split, DIFF_TEMPLATE % {"index": index}, []
            )


class HighSeveritySamplingTests(_SeverityFixture):
    def test_the_flat_path_never_reaches_the_high_severity_stratum(self) -> None:
        """先把被修的行为钉下来，否则没人说得清这个改动修了什么。"""

        self._seed(medium=90, high=17)
        old = self.store.list_evaluation_cases("validation", True, 20)
        self.assertEqual(
            0,
            sum(1 for case in old if is_high(case)),
            "高危样本 id 更大，平铺取样取不到——这正是分母恒为 1 的成因",
        )

    def test_the_high_severity_stratum_is_never_sampled_to_zero(self) -> None:
        """真实数字：holdout 补到 110 条缺陷，其中 17 条高危。"""

        self._seed(medium=93, high=17)
        for limit in (2, 5, 10, 20, 50):
            with self.subTest(limit=limit):
                cases = self.store.select_evaluation_cases(
                    "validation", True, limit
                )
                high = sum(1 for case in cases if is_high(case))
                self.assertGreaterEqual(
                    high, 1, "high_severity_recall 仍然没有分母"
                )
                self.assertGreaterEqual(
                    len(cases) - high, 1, "普通缺陷层不能被挤空"
                )

    def test_it_survives_the_clean_stratum_split(self) -> None:
        """两层分层要能叠起来用：干净 / 缺陷，再在缺陷里分严重度。

        这是引擎真实面对的形状——`select_evaluation_cases` 一次调用要同时
        给出 `clean_accuracy`、`recall` 和 `high_severity_recall` 三个分母。
        """

        self._seed(medium=93, high=17, cleans=16)
        cases = self.store.select_evaluation_cases("validation", True, 20)
        clean = [case for case in cases if not case["expected"]]
        defect = [case for case in cases if case["expected"]]
        self.assertGreaterEqual(len(clean), 1, "clean_accuracy 没有分母")
        self.assertGreaterEqual(len(defect), 1, "recall 没有分母")
        self.assertGreaterEqual(
            sum(1 for case in defect if is_high(case)),
            1,
            "high_severity_recall 没有分母",
        )

    def test_limit_is_still_a_budget(self) -> None:
        self._seed(medium=93, high=17, cleans=16)
        for limit in (1, 2, 5, 20, 100):
            with self.subTest(limit=limit):
                cases = self.store.select_evaluation_cases(
                    "validation", True, limit
                )
                self.assertLessEqual(len(cases), limit)

    def test_the_high_stratum_cannot_squeeze_out_ordinary_defects(self) -> None:
        """高危样本目前全部来自 mutation-v1 的 weakened-guard 单一算子。

        让它占满缺陷层，`recall` 测的就变成"对减弱守卫这一类变异的敏感
        度"，不是泛化的缺陷召回。所以高危层同样受"不超过实际取到的普通
        缺陷条数"约束——与 `max_clean_share` 同一条理由。
        """

        self._seed(medium=5, high=80)
        for limit in (4, 10, 20, 40):
            with self.subTest(limit=limit):
                cases = self.store.select_evaluation_cases(
                    "validation", True, limit
                )
                high = sum(1 for case in cases if is_high(case))
                self.assertGreaterEqual(
                    len(cases) - high, high, "高危层挤掉了普通缺陷层"
                )
                self.assertGreaterEqual(high, 1)

    def test_a_single_severity_stratum_is_unchanged(self) -> None:
        """库里只有一档严重度时，不能为了分层反而改变既有评测集构成。"""

        for medium, high in ((12, 0), (0, 12)):
            with self.subTest(medium=medium, high=high):
                self.setUp()
                self._seed(medium=medium, high=high, cleans=4)
                cases = self.store.select_evaluation_cases(
                    "validation", True, 8
                )
                self.assertLessEqual(len(cases), 8)
                self.assertTrue(cases)

    def test_selection_stays_deterministic_and_ordered(self) -> None:
        """指纹的唯一含义是"这两轮跑的是同一套评测集"。

        缺陷层内部再分一层同样不能引入随机性，否则同一个库连续两轮算出
        不同的 `validation_dataset_fingerprint`。
        """

        self._seed(medium=93, high=17, cleans=16)
        first = [
            case["id"]
            for case in self.store.select_evaluation_cases("validation", True, 20)
        ]
        self.assertEqual(sorted(first), first)
        for _ in range(4):
            self.assertEqual(
                first,
                [
                    case["id"]
                    for case in self.store.select_evaluation_cases(
                        "validation", True, 20
                    )
                ],
            )

    def test_a_budget_covering_the_whole_table_still_returns_everything(self) -> None:
        """全表分支不受这一层影响：预算装得下就不做任何取舍。

        `rejection_proof` 按 `max_cases=len(cases)` 请求全集，这一支少了
        会让 `holdout_dataset_ready` 失败。
        """

        self._seed(medium=6, high=4, cleans=10)
        for limit in (20, 21, 500):
            with self.subTest(limit=limit):
                self.assertEqual(
                    20,
                    len(self.store.select_evaluation_cases(
                        "validation", True, limit)),
                )


if __name__ == "__main__":
    unittest.main()