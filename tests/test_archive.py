"""版本档案与选亲：把单一血统爬山换成档案搜索。

## 被钉住的缺陷

改动之前，`_propose` 的 baseline 恒等于 `get_active_skill_version()`，
被拒的候选存进 `skill_versions` 之后再无人问津，`parent_version` 有值但
没有任何代码读它选亲。搜索退化成"从当前最优爬一步，爬不上去就原地不动"。

- **DGM**（arXiv:2505.22954）：保留**档案**而不是单一血统，因为
  "stepping stones"——当下分数平庸的版本可能是后来突破的必要祖先。
- **GEPA**（arXiv:2507.19457）：用聚合分数选亲会淘汰"专才"，改在**逐样本
  Pareto 前沿**上采样。

## 这批测试最要紧的两条

1. `test_the_gate_baseline_is_still_the_active_version` —— 选亲**不能**动
   门禁。门禁要回答"能不能替换掉正在服务真实流量的版本"，把基线也改成
   档案里最优就失去意义了。
2. `test_selection_is_reproducible` —— 选亲影响候选内容，候选内容进落盘
   记录。用真随机源会让"这次为什么产出了这个候选"再也无法复现，而可复现
   是这个项目现有评测记录（提示词 SHA-256、数据集指纹）一直在维护的性质。
"""
import os
import tempfile
import unittest

from evoagent.archive import (
    build_archive, frontier_weights, pareto_frontier, select_parent, summarise,
)
from evoagent.evolution import EvolutionEngine
from evoagent.store import create_store


def _version(version, score, active=False, parent=None):
    return {
        "version": version, "prompt": "prompt v%d" % version, "score": score,
        "active": int(active), "parent_version": parent, "created_at": "2026-01-01",
    }


def _run(version, decision="rejected", case_scores=None, errors=()):
    """构造一条 evolution_run，逐样本结果按 tp/fp/fn 表达。

    `case_scores` 是 {case_id: (tp, fp, fn)}。
    """
    results = [
        {"id": case_id, "name": "case-%s" % case_id, "tp": tp, "fp": fp, "fn": fn,
         "error": None}
        for case_id, (tp, fp, fn) in (case_scores or {}).items()
    ]
    results.extend(
        {"id": case_id, "name": "case-%s" % case_id, "tp": 0, "fp": 0, "fn": 2,
         "error": "boom"}
        for case_id in errors
    )
    return {
        "id": "run-%d" % version, "skill_name": "llm-review",
        "candidate_version": version, "baseline_version": None,
        "decision": decision, "candidate_score": 0.0, "baseline_score": 0.0,
        "metrics": {"candidate": {"case_results": results}},
        "created_at": "2026-01-01",
    }


class ArchiveBuildTests(unittest.TestCase):
    def test_versions_without_runs_stay_in_the_archive(self):
        """没跑过评测的版本不剔掉。

        DGM 的 stepping-stone 论点是"当下看不出价值的版本可能是后来突破的
        祖先"，而"没测过"比"测了很差"离"没价值"更远。
        """
        archive = build_archive([_version(1, 0.5), _version(2, 0.0)], [])
        self.assertEqual([2, 1], [item["version"] for item in archive])
        self.assertEqual({}, archive[0]["case_scores"])

    def test_case_scores_come_from_the_recorded_run(self):
        archive = build_archive(
            [_version(1, 0.5)], [_run(1, case_scores={"a": (1, 0, 0)})])
        self.assertEqual({"a": 1.0}, archive[0]["case_scores"])
        self.assertEqual("rejected", archive[0]["decision"])

    def test_f1_matches_the_evaluator_formula(self):
        """逐样本分数用 2tp/(2tp+fp+fn)，与全局 f1 同一个公式。

        口径不一致的话，逐样本前沿和总分排序会讲两个互相矛盾的故事。
        """
        archive = build_archive(
            [_version(1, 0.5)], [_run(1, case_scores={"a": (1, 1, 1)})])
        self.assertAlmostEqual(0.5, archive[0]["case_scores"]["a"])

    def test_an_errored_case_is_not_scored_as_zero(self):
        """一次调用失败不等于"测了得零分"。

        算成 0 会让一次网络抖动看起来像能力退化，而这个版本可能因此被从
        前沿上剔掉——一个真实存在的踏脚石被一次超时抹掉了。
        """
        archive = build_archive([_version(1, 0.5)], [_run(1, errors=["a"])])
        self.assertEqual({}, archive[0]["case_scores"])

    def test_a_clean_case_correctly_passed_scores_full_marks(self):
        """没有期望、也没有误报 = 干净样本被正确放过，满分。"""
        archive = build_archive(
            [_version(1, 0.5)], [_run(1, case_scores={"clean": (0, 0, 0)})])
        self.assertEqual(1.0, archive[0]["case_scores"]["clean"])

    def test_a_clean_case_with_a_false_positive_scores_zero(self):
        archive = build_archive(
            [_version(1, 0.5)], [_run(1, case_scores={"clean": (0, 1, 0)})])
        self.assertEqual(0.0, archive[0]["case_scores"]["clean"])

    def test_the_most_recent_run_wins_for_a_rerun_version(self):
        """同一版本重跑过多次时取最近一条。store 按 created_at DESC 返回。"""
        archive = build_archive(
            [_version(1, 0.5)],
            [_run(1, case_scores={"a": (1, 0, 0)}),
             _run(1, case_scores={"a": (0, 0, 1)})],
        )
        self.assertEqual(1.0, archive[0]["case_scores"]["a"])

    def test_a_run_for_an_unknown_version_is_ignored(self):
        archive = build_archive([_version(1, 0.5)], [_run(99)])
        self.assertEqual(1, len(archive))


class ParetoTests(unittest.TestCase):
    def _specialist_archive(self):
        """v1 总分高但在 case c 上全错；v2 总分低、唯独 c 做对。

        这就是 GEPA 说的"专才"：用总分排序会把 v2 淘汰，但它携带着 v1
        没有的信息。
        """
        return build_archive(
            [_version(1, 0.80), _version(2, 0.40)],
            [
                _run(1, case_scores={"a": (1, 0, 0), "b": (1, 0, 0), "c": (0, 0, 1)}),
                _run(2, case_scores={"a": (0, 0, 1), "b": (0, 0, 1), "c": (1, 0, 0)}),
            ],
        )

    def test_a_specialist_survives_on_the_frontier(self):
        self.assertEqual([1, 2], pareto_frontier(self._specialist_archive()))

    def test_the_specialist_is_not_the_best_by_aggregate_score(self):
        """对照：总分排序会选掉专才。这条说明前沿不是多余的一层。"""
        archive = self._specialist_archive()
        best = max(archive, key=lambda item: item["score"])
        self.assertEqual(1, best["version"])
        self.assertIn(2, pareto_frontier(archive))

    def test_a_strictly_dominated_version_is_off_the_frontier(self):
        archive = build_archive(
            [_version(1, 0.9), _version(2, 0.1)],
            [
                _run(1, case_scores={"a": (1, 0, 0), "b": (1, 0, 0)}),
                _run(2, case_scores={"a": (0, 0, 1), "b": (0, 0, 1)}),
            ],
        )
        self.assertEqual([1], pareto_frontier(archive))

    def test_ties_put_both_versions_on_the_frontier(self):
        """并列最优都算在前沿上（`>=`）。

        用 `>` 会让"两个版本一样好"变成"只有先遍历到的那个在前沿"，
        前沿内容依赖遍历顺序，那就不是一个定义清楚的集合了。
        """
        archive = build_archive(
            [_version(1, 0.5), _version(2, 0.5)],
            [_run(1, case_scores={"a": (1, 0, 0)}),
             _run(2, case_scores={"a": (1, 0, 0)})],
        )
        self.assertEqual([1, 2], pareto_frontier(archive))

    def test_no_per_case_data_yields_an_empty_frontier(self):
        """不是返回全部版本。

        把"没有可比数据"伪装成"所有版本都在前沿"会让选亲变成随机抽取，
        而调用方以为自己在用 Pareto。空列表让调用方能显式回落。
        """
        self.assertEqual([], pareto_frontier(build_archive([_version(1, 0.5)], [])))

    def test_frontier_weights_count_leading_cases(self):
        weights = frontier_weights(self._specialist_archive())
        self.assertEqual({1: 2, 2: 1}, weights)


class SelectionTests(unittest.TestCase):
    def setUp(self):
        self.archive = build_archive(
            [_version(1, 0.80), _version(2, 0.40, active=True), _version(3, 0.90)],
            [
                _run(1, case_scores={"a": (1, 0, 0), "c": (0, 0, 1)}),
                _run(2, case_scores={"a": (0, 0, 1), "c": (1, 0, 0)}),
                _run(3, case_scores={"a": (1, 0, 0), "c": (0, 0, 1)}),
            ],
        )

    def test_the_default_strategy_is_the_active_version(self):
        """默认行为与档案选亲加入之前完全一致。"""
        chosen = select_parent(self.archive)
        self.assertEqual(2, chosen["version"])
        self.assertEqual("active", chosen["selection"]["resolved"])

    def test_best_picks_the_top_aggregate_score(self):
        self.assertEqual(3, select_parent(self.archive, strategy="best")["version"])

    def test_selection_is_reproducible(self):
        """同一份输入两次必须选出同一个亲本。

        选亲影响候选内容，候选内容进 `evolution_runs`。用 random.random()
        会让"这次为什么产出了这个候选"再也无法复现，而可复现是这个项目
        现有评测记录一直在维护的性质。
        """
        first = select_parent(self.archive, strategy="pareto", seed="batch-7")
        second = select_parent(self.archive, strategy="pareto", seed="batch-7")
        self.assertEqual(first["version"], second["version"])

    def test_different_seeds_can_reach_different_parents(self):
        """确定性不等于恒定：不同输入之间分布仍然是散的。

        否则 pareto 退化成"永远选同一个"，前沿上的其他版本白算了。
        """
        picked = {
            select_parent(self.archive, strategy="pareto", seed="s%d" % i)["version"]
            for i in range(40)
        }
        self.assertGreater(len(picked), 1)

    def test_pareto_only_picks_from_the_frontier(self):
        frontier = set(pareto_frontier(self.archive))
        for i in range(40):
            chosen = select_parent(self.archive, strategy="pareto", seed="s%d" % i)
            self.assertIn(chosen["version"], frontier)

    def test_pareto_falls_back_visibly_without_per_case_data(self):
        """回落必须可见。静默回落会让人以为 pareto 正在生效。"""
        archive = build_archive([_version(1, 0.5, active=True)], [])
        chosen = select_parent(archive, strategy="pareto")
        self.assertEqual(1, chosen["version"])
        self.assertEqual("pareto", chosen["selection"]["fell_back_from"])

    def test_epsilon_zero_never_explores(self):
        for i in range(20):
            chosen = select_parent(
                self.archive, strategy="epsilon_greedy", seed="s%d" % i, epsilon=0.0)
            self.assertEqual("exploit", chosen["selection"]["resolved"])
            self.assertEqual(3, chosen["version"])

    def test_epsilon_one_always_explores(self):
        for i in range(20):
            chosen = select_parent(
                self.archive, strategy="epsilon_greedy", seed="s%d" % i, epsilon=1.0)
            self.assertEqual("explore", chosen["selection"]["resolved"])

    def test_an_empty_archive_selects_nothing(self):
        self.assertIsNone(select_parent([]))

    def test_an_unknown_strategy_raises(self):
        """不静默回落到 active——那会让拼错的环境变量看起来完全正常。"""
        with self.assertRaises(ValueError):
            select_parent(self.archive, strategy="paretto")


class SummaryTests(unittest.TestCase):
    def test_never_evaluated_versions_are_reported_separately(self):
        """"档案里有多少条其实没有可比数据"决定了选亲此刻有多少信息可用。

        混在总数里会让一个 20 版本的档案看起来比它实际能支撑的搜索更丰富。
        """
        archive = build_archive(
            [_version(1, 0.5), _version(2, 0.0), _version(3, 0.0)],
            [_run(1, case_scores={"a": (1, 0, 0)})],
        )
        report = summarise(archive)
        self.assertEqual(3, report["versions"])
        self.assertEqual(1, report["versions_evaluated"])
        self.assertEqual(2, report["versions_never_evaluated"])

    def test_an_empty_archive_summarises_without_error(self):
        report = summarise([])
        self.assertEqual(0, report["versions"])
        self.assertIsNone(report["active_version"])
        self.assertIsNone(report["best_version"])


class EngineIntegrationTests(unittest.TestCase):
    """档案接进引擎之后的行为。"""

    def setUp(self):
        handle, self.path = tempfile.mkstemp(suffix=".db")
        os.close(handle)
        self.store = create_store("", self.path)

    def tearDown(self):
        if os.path.exists(self.path):
            os.unlink(self.path)

    def _engine(self, strategy="active"):
        return EvolutionEngine(
            self.store, seed_defaults=False, parent_strategy=strategy)

    def test_the_gate_baseline_is_still_the_active_version(self):
        """核心：选亲不动门禁。

        门禁要回答的是"候选能不能替换掉正在服务真实流量的版本"。把基线
        也改成"档案里最优"会让这个问题无法回答——一个比最优差、但比 active
        好的候选会被拒，而它本该上线。
        """
        import inspect
        source = inspect.getsource(EvolutionEngine._propose)
        self.assertIn('baseline_prompt = active["prompt"] if active else DEFAULT_PROMPT',
                      source)
        # 亲本只经由 save_skill_version 落到血统列，不进 baseline_*。
        self.assertIn("parent_version=parent_version", source)
        self.assertNotIn("baseline_prompt = parent", source)

    def test_an_explicit_parent_is_recorded_over_the_active_version(self):
        """血统记录必须如实。

        `parent_version` 是事后重建搜索路径的唯一依据；候选实际从 v1 改起
        却记 active 的 v2 当亲本，"这个提示词是从哪一支演化来的"就永远查
        不回来了。
        """
        self.store.save_skill_version("llm-review", "v1", 0.5, activate=True)
        self.store.save_skill_version("llm-review", "v2", 0.6, activate=True)
        saved = self.store.save_skill_version(
            "llm-review", "v3", 0.7, parent_version=1)

        versions = {item["version"]: item for item in
                    self.store.list_skill_versions("llm-review")}
        self.assertEqual(1, versions[saved["version"]]["parent_version"])

    def test_omitting_the_parent_still_falls_back_to_active(self):
        """本参数加入之前的唯一行为，不能改。"""
        self.store.save_skill_version("llm-review", "v1", 0.5, activate=True)
        saved = self.store.save_skill_version("llm-review", "v2", 0.6)
        versions = {item["version"]: item for item in
                    self.store.list_skill_versions("llm-review")}
        self.assertEqual(1, versions[saved["version"]]["parent_version"])

    def test_runs_are_filtered_by_skill(self):
        """不同 skill 的版本号各自从 1 开始，不过滤会互相污染。

        而这种污染在报告里看不出来——前沿照样算得出来，只是算错了。
        """
        self.store.save_evolution_run(_run(1, case_scores={"a": (1, 0, 0)}))
        other = _run(1, case_scores={"a": (0, 0, 1)})
        other["id"] = "run-other"
        other["skill_name"] = "other-skill"
        self.store.save_evolution_run(other)

        self.assertEqual(
            1, len(self.store.list_evolution_runs(200, skill_name="llm-review")))
        self.assertEqual(2, len(self.store.list_evolution_runs(200)))

    def test_the_engine_archive_uses_only_this_skill(self):
        self.store.save_skill_version("llm-review", "v1", 0.5, activate=True)
        self.store.save_skill_version("other-skill", "o1", 0.9, activate=True)
        archive = self._engine().build_archive("llm-review")
        self.assertEqual([1], [item["version"] for item in archive])

    def test_the_archive_report_states_the_active_strategy(self):
        """只报前沿不报策略，会让人以为搜索正在利用它。

        strategy="active" 下"前沿上有 4 个版本"是**没有被使用**的信息。
        """
        self.store.save_skill_version("llm-review", "v1", 0.5, activate=True)
        report = self._engine().archive_report("llm-review")
        self.assertEqual("active", report["parent_strategy"])
        self.assertIsNone(report["parent_epsilon"])

    def test_epsilon_is_only_reported_for_the_strategy_that_uses_it(self):
        report = self._engine("epsilon_greedy").archive_report("llm-review")
        self.assertEqual(0.1, report["parent_epsilon"])

    def test_an_unknown_strategy_is_rejected_at_construction(self):
        """拼错的环境变量要在启动时就炸，不要静默跑成 active。"""
        with self.assertRaises(ValueError):
            EvolutionEngine(self.store, seed_defaults=False, parent_strategy="paretto")

    def test_the_default_settings_keep_the_previous_behaviour(self):
        from evoagent.config import Settings
        fields = Settings.__dataclass_fields__
        self.assertEqual("active", fields["evolution_parent_strategy"].default)

    def test_selecting_from_an_empty_archive_returns_none(self):
        self.assertIsNone(self._engine().select_parent("llm-review"))


if __name__ == "__main__":
    unittest.main()