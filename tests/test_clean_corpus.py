#!/usr/bin/env python3
"""干净语料（负样本）在评测集里的取样契约。

这批测试钉住的是一个「看起来在工作的门禁」：`evaluation_cases` 里明明有干净
样本，但取样是 `ORDER BY id LIMIT n`，干净样本入库晚、id 大，永远排在缺陷
样本后面取不到。结果 `_score` 里的 `clean_total` 恒为 0，误报侧的 0.20 权重
和 `clean_accuracy` 的门禁保护一起静默消失——飞轮只被「漏报」一个方向拉，会
持续朝「多报」漂，而所有指标看上去都正常。
"""

from __future__ import annotations

import json
import os
import shutil
import sqlite3
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


def make_diff(index: int) -> str:
    return DIFF_TEMPLATE % {"index": index}


def is_clean(case: dict) -> bool:
    """和 `_score` 里的 `int(not expected_items)` 对齐。"""

    return not case["expected"]


class _CaseFixture(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.store = TaskStore(os.path.join(self.tmp, "evo.db"))
        self._next = 0

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _seed(self, defects: int, cleans: int, split: str = "validation") -> None:
        """先灌缺陷样本、后灌干净样本，复现真实入库顺序。

        干净语料是后来补的，id 必然更大——这正是平铺取样取不到它们的原因。
        """

        for _ in range(defects):
            self._next += 1
            index = self._next
            self.store.save_evaluation_case(
                "defect-%d" % index,
                split,
                make_diff(index),
                [
                    {
                        "path": "mod_%d.py" % index,
                        "line": 2,
                        "min_severity": "high",
                    }
                ],
            )
        for _ in range(cleans):
            self._next += 1
            index = self._next
            self.store.save_evaluation_case(
                "clean-%d" % index, split, make_diff(index), []
            )


class CleanCaseSamplingTests(_CaseFixture):
    def test_old_path_never_reaches_the_clean_stratum(self) -> None:
        """先把被修的行为本身钉下来，否则没人说得清这个改动修了什么。"""

        self._seed(defects=20, cleans=8)
        old = self.store.list_evaluation_cases("validation", True, 5)
        self.assertEqual(
            0,
            sum(1 for case in old if is_clean(case)),
            "平铺取样在干净样本 id 更大时取不到它们——这正是分母为 0 的成因",
        )

    def test_clean_stratum_is_never_sampled_to_zero(self) -> None:
        self._seed(defects=20, cleans=8)
        for limit in (2, 3, 5, 10, 27):
            with self.subTest(limit=limit):
                cases = self.store.select_evaluation_cases(
                    "validation", True, limit
                )
                clean = sum(1 for case in cases if is_clean(case))
                self.assertGreaterEqual(clean, 1, "误报侧必须有分母")
                self.assertGreaterEqual(
                    len(cases) - clean, 1, "漏报侧同样不能被挤空"
                )

    def test_limit_is_a_budget_and_is_never_exceeded(self) -> None:
        self._seed(defects=20, cleans=8)
        for limit in (1, 2, 3, 5, 10, 28, 500):
            with self.subTest(limit=limit):
                cases = self.store.select_evaluation_cases(
                    "validation", True, limit
                )
                self.assertLessEqual(len(cases), max(1, min(limit, 500)))

    def test_budget_of_one_falls_back_instead_of_returning_two(self) -> None:
        """两层各留 1 条在 limit=1 时会超预算；超限比少一层更糟。"""

        self._seed(defects=20, cleans=8)
        self.assertEqual(
            1, len(self.store.select_evaluation_cases("validation", True, 1))
        )

    def test_single_defect_stratum_behaviour_is_unchanged(self) -> None:
        """库里只有一层时，不能为了「分层」反而改变既有评测集的构成。"""

        self._seed(defects=12, cleans=0)
        for limit in (1, 5, 12, 50):
            with self.subTest(limit=limit):
                self.assertEqual(
                    self.store.list_evaluation_cases("validation", True, limit),
                    self.store.select_evaluation_cases(
                        "validation", True, limit
                    ),
                )

    def test_single_clean_stratum_behaviour_is_unchanged(self) -> None:
        self._seed(defects=0, cleans=9)
        for limit in (1, 4, 9, 50):
            with self.subTest(limit=limit):
                self.assertEqual(
                    self.store.list_evaluation_cases("validation", True, limit),
                    self.store.select_evaluation_cases(
                        "validation", True, limit
                    ),
                )

    def test_selection_is_deterministic_across_calls(self) -> None:
        """`_propose` 会把 `validation_dataset_fingerprint` 落盘。

        取样一旦带随机性，同一个库在两轮之间会算出不同指纹，指纹就失去了
        「这两轮跑的是同一套评测集」这个唯一含义。
        """

        self._seed(defects=20, cleans=8)
        first = [
            case["id"]
            for case in self.store.select_evaluation_cases("validation", True, 7)
        ]
        for _ in range(4):
            self.assertEqual(
                first,
                [
                    case["id"]
                    for case in self.store.select_evaluation_cases(
                        "validation", True, 7
                    )
                ],
            )

    def test_selection_stays_ordered_by_id(self) -> None:
        self._seed(defects=20, cleans=8)
        ids = [
            case["id"]
            for case in self.store.select_evaluation_cases("validation", True, 10)
        ]
        self.assertEqual(sorted(ids), ids)

    def test_quota_tracks_the_real_ratio_when_defects_dominate(self) -> None:
        """按存量比例分配，而不是固定对半——对半会凭空放大稀缺的那一层。"""

        self._seed(defects=90, cleans=10)
        cases = self.store.select_evaluation_cases("validation", True, 20)
        self.assertEqual(20, len(cases))
        self.assertEqual(2, sum(1 for case in cases if is_clean(case)))

    def test_clean_stratum_cannot_squeeze_out_the_defect_stratum(self) -> None:
        """干净语料便宜、缺陷语料贵，库内比例会倒挂。

        真实数字：干净 PR 批量抓到 78 条，人工确认过的缺陷样本只有 20 条。
        纯按比例取样时 limit=20 会取出 4 缺陷 + 15 干净，recall 步长变成
        0.25——等于用「补上误报侧的分母」换掉了漏报侧的分母。
        """

        self._seed(defects=20, cleans=78)
        for limit in (10, 20, 40, 80):
            with self.subTest(limit=limit):
                cases = self.store.select_evaluation_cases(
                    "validation", True, limit
                )
                clean = sum(1 for case in cases if is_clean(case))
                self.assertGreaterEqual(
                    len(cases) - clean,
                    clean,
                    "干净层挤掉了缺陷层，precision/recall 退化成噪声",
                )
                self.assertGreaterEqual(clean, 1)

    def test_share_cap_holds_when_the_defect_stratum_runs_short(self) -> None:
        """份额上限按预算算时，缺陷层存量不足就会失效。

        实测过：20 缺陷 + 78 干净、limit=98 时取出 20 缺陷 + 49 干净
        （71% 干净）——正是这个上限本该拦住的形态，而 limit≤40 的用例全绿。
        所以上限必须按**实际取到的缺陷条数**算，不是按预算算。
        """

        self._seed(defects=20, cleans=78)
        cases = self.store.select_evaluation_cases("validation", True, 90)
        clean = sum(1 for case in cases if is_clean(case))
        self.assertEqual(20, len(cases) - clean)
        self.assertLessEqual(clean, 20)

    def test_a_budget_covering_the_whole_table_returns_everything(self) -> None:
        """预算装得下整张表时没有取舍要做，份额上限不该删减语料。

        少了这一支，调用方明明请求全集却拿到子集，
        `holdout_dataset_ready`（比较 len(cases) 与 min_holdout_cases）会
        失败——`rejection_proof` 正是这么被打断的，它按 `max_cases=len(cases)`
        请求全部 20 条 holdout，却只拿到 12 条。取样在这种情形下悄悄丢掉
        8 条，等于对数据集规模说谎。
        """

        self._seed(defects=6, cleans=14)
        for limit in (20, 21, 500):
            with self.subTest(limit=limit):
                self.assertEqual(
                    20, len(self.store.select_evaluation_cases(
                        "validation", True, limit))
                )

    def test_sample_shrinks_honestly_when_a_stratum_runs_out(self) -> None:
        """缺陷层取完后，干净层的份额上限就没有可交换的对手了。

        这时返回条数少于 limit 是诚实结果，不是缺陷：硬凑到 limit 只能靠
        突破份额上限，那会把测出来的分数重新变成干净样本的分数。

        注意 limit 必须**小于**总存量，否则走的是"预算装得下整张表"那一支，
        测的就是另一件事了（见
        test_a_budget_covering_the_whole_table_returns_everything）。
        """

        self._seed(defects=20, cleans=78)
        cases = self.store.select_evaluation_cases("validation", True, 90)
        clean = sum(1 for case in cases if is_clean(case))
        self.assertLess(len(cases), 90)
        self.assertEqual(20, len(cases) - clean)
        self.assertGreaterEqual(clean, 1)

    def test_expected_json_can_never_be_null(self) -> None:
        """NULL 这一半由 schema 的 NOT NULL 兜住，取样口径不必自己防。

        钉住它是因为分层判定用的是 `expected_json = '[]'` 这个存储形态，
        它成立的前提就是这个列恒为合法 JSON。哪天有人放宽了约束，这条会先
        响，而不是等到 `json.loads(None)` 在评测中途炸掉。
        """

        with self.assertRaises(sqlite3.IntegrityError):
            with self.store._connect() as conn:
                conn.execute(
                    "INSERT INTO evaluation_cases(name,split,diff,expected_json,"
                    "source,active,created_at) VALUES (?,?,?,?,?,1,?)",
                    (
                        "null-expected",
                        "validation",
                        make_diff(900),
                        None,
                        "test",
                        "2026-09-07T00:00:00Z",
                    ),
                )

    def test_a_corrupt_expected_json_fails_the_same_way_on_both_paths(self) -> None:
        """空串绕过了 NOT NULL，两条取样路径都会在反序列化时炸。

        钉住「两边一样」而不是「不炸」：这不是本次改动引入的问题，
        `list_evaluation_cases` 早就如此。写在这里是为了留一条线索——
        取样口径里那个 `IS NULL OR TRIM(...) = ''` 分支是纯防御，真出现这种
        行时崩溃发生在 hydration，比分层判定更早，那个分支根本轮不到生效。
        修它要在写入侧加约束，不是在取样侧兜。
        """

        self._seed(defects=4, cleans=0)
        with self.store._connect() as conn:
            conn.execute(
                "INSERT INTO evaluation_cases(name,split,diff,expected_json,"
                "source,active,created_at) VALUES (?,?,?,?,?,1,?)",
                (
                    "blank-expected",
                    "validation",
                    make_diff(900),
                    "  ",
                    "test",
                    "2026-09-07T00:00:00Z",
                ),
            )
        for name, call in (
            ("list", self.store.list_evaluation_cases),
            ("select", self.store.select_evaluation_cases),
        ):
            with self.subTest(path=name):
                with self.assertRaises(json.JSONDecodeError):
                    call("validation", True, 500)

    def test_split_and_active_filters_still_apply(self) -> None:
        self._seed(defects=6, cleans=4, split="validation")
        self._seed(defects=3, cleans=3, split="holdout")
        for split in ("validation", "holdout"):
            with self.subTest(split=split):
                cases = self.store.select_evaluation_cases(split, True, 50)
                self.assertTrue(cases)
                self.assertEqual({split}, {case["split"] for case in cases})
        self.assertTrue(
            all(
                case["active"]
                for case in self.store.select_evaluation_cases(None, True, 500)
            )
        )


class EngineWiringTests(_CaseFixture):
    """一个写好但没人调用的取样函数修不了任何东西——这里钉住接线本身。"""

    def _engine(self, max_cases: int):
        # 只装取样路径用得到的属性：这两处调用不碰 reviewer / llm，把整个
        # 引擎构造起来只会让测试被无关依赖绑住。
        from evoagent.evolution import EvolutionEngine

        engine = EvolutionEngine.__new__(EvolutionEngine)
        engine.store = self.store
        engine.max_cases = max_cases
        return engine

    def test_status_reports_a_clean_denominator_on_both_splits(self) -> None:
        for split in ("validation", "holdout"):
            self._seed(defects=20, cleans=8, split=split)
        engine = self._engine(10)
        for split in ("validation", "holdout"):
            with self.subTest(split=split):
                cases = engine.store.select_evaluation_cases(split, True, 10)
                self.assertGreaterEqual(
                    sum(1 for case in cases if is_clean(case)),
                    1,
                    "clean_accuracy 在这一侧仍然没有分母",
                )

    def test_engine_call_sites_no_longer_use_the_flat_path(self) -> None:
        """接线是这次改动的全部价值，所以直接钉调用点。

        单测很容易只测 `select_evaluation_cases` 本身而放过接线，那样
        `clean_cases` 依然是 0，而测试全绿。
        """

        import inspect

        from evoagent.evolution import EvolutionEngine

        for method in (EvolutionEngine.status, EvolutionEngine._propose):
            with self.subTest(method=method.__name__):
                source = inspect.getsource(method)
                self.assertIn("select_evaluation_cases", source)
                self.assertNotIn(
                    "self.store.list_evaluation_cases",
                    source,
                    "还有调用点走平铺取样，干净样本取不到",
                )


if __name__ == "__main__":
    unittest.main()