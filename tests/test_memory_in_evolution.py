"""轨道 D：候选生成阶段的记忆召回，以及"过往尝试"这条反思信号。

## 两个注入点必须分清

`memory.py` 的模块文档说明了记忆刻意**没有**接进 `agentic_core`：跨 case
召回会让第二次的"发现"变成召回而不是检出，指标朝着我们希望的方向虚高，
而 Validation 上调过的提示词其收益会通过记忆漏到 Holdout，那条唯一能挡
过拟合的检验就失效了。

这里的注入点不同：候选生成发生在两轮评测**之间**，被评测的 reviewer 对
记忆一无所知。所以这批测试里有一条专门钉住这个区分——`RegressionEvaluator`
用的 reviewer 不该因为记忆开关而改变行为。

## 为什么读开关要独立

`MemoryManager.enabled` 同时控制写入和读取。消融实验要切的只是"生成候选
时读不读"；写入链路必须全程开着，否则两组实验面对的记忆库内容都不一样，
差异就无法归因到"记忆机制有没有用"。所以读开关是 generator 的 `memory`
构造参数，不是 `MemoryManager.enabled`。

## 过往尝试（GEPA 式反思）

没有这个信号，生成器对自己上一轮的失败一无所知，会反复提出等价修改。
GEPA（arXiv:2507.19457）的观察是：把门禁判决以自然语言反馈回生成器，
信息量远大于只给一个标量分数。
"""
import json
import os
import tempfile
import unittest

from evoagent.evolution import EvolutionEngine
from evoagent.evolution_v2 import RootCauseEvolutionGenerator
from evoagent.memory import MemoryManager
from evoagent.store import create_store


class _RecordingClient:
    """记下喂给模型的那份 JSON，好断言注入了什么。"""

    provider = "stub"
    model = "stub-model"

    def __init__(self):
        self.payloads = []

    def complete_json(self, name, system, user, ledger, budget):
        self.payloads.append(json.loads(user))
        return {
            "clusters": [],
            "candidate": {"prompt_additions": ["be careful about eval"]},
            "rationale": "stub",
        }

    @property
    def last(self):
        return self.payloads[-1]


class _Base(unittest.TestCase):
    def setUp(self):
        handle, self.path = tempfile.mkstemp(suffix=".db")
        os.close(handle)
        self.store = create_store("", self.path)
        self.client = _RecordingClient()
        self.memory = MemoryManager(self.store, enabled=True)

    def tearDown(self):
        if os.path.exists(self.path):
            os.unlink(self.path)

    def _case(self, case_id=1, rule_id="SEC-EVAL", path="a.py"):
        return {
            "id": case_id, "category": "missed_issue", "task_id": "task-1",
            "payload": {
                "finding": {"rule_id": rule_id, "path": path, "line": 1},
                "note": "confirmed miss",
            },
        }

    def _remember(self, rule_id="SEC-EVAL", path="a.py", note="always flag eval"):
        return self.memory.remember_feedback(
            "default", "org/repo", "task-0", "missed_issue",
            {"rule_id": rule_id, "path": path, "line": 1}, note,
        )


class MemoryRecallTests(_Base):
    def test_without_memory_no_prior_conclusions_are_sent(self):
        """默认关闭：传 None 就是关，行为与本改动之前一致。"""
        generator = RootCauseEvolutionGenerator(self.client)
        self._remember()
        result = generator.generate([self._case()], "base prompt")

        self.assertEqual([], self.client.last["prior_conclusions"])
        self.assertEqual([], result["prior_conclusions"])
        self.assertFalse(result["generator"]["memory_recall_enabled"])

    def test_with_memory_the_prior_conclusion_reaches_the_model(self):
        self._remember(note="always flag eval on user input")
        generator = RootCauseEvolutionGenerator(
            self.client, memory=self.memory, repository="org/repo",
        )
        result = generator.generate([self._case()], "base prompt")

        conclusions = self.client.last["prior_conclusions"]
        self.assertTrue(conclusions)
        self.assertIn("always flag eval", conclusions[0]["conclusion"])
        self.assertEqual("missed_issue@SEC-EVAL:a.py", conclusions[0]["root_cause"])
        self.assertTrue(result["generator"]["memory_recall_enabled"])

    def test_the_recall_switch_is_independent_of_the_write_switch(self):
        """核心：读开关不是 `MemoryManager.enabled`。

        消融实验要求写入全程开启、只切读取。如果读开关复用了 enabled，
        关掉读的同时也关掉了写，两组实验的记忆库内容就不同了。
        """
        self._remember()
        off = RootCauseEvolutionGenerator(self.client, memory=None, repository="org/repo")
        off.generate([self._case()], "base prompt")
        self.assertEqual([], self.client.last["prior_conclusions"])

        # 写开关始终是 True——记忆确实写进去了，只是上面那次没读。
        self.assertTrue(self.memory.enabled)
        on = RootCauseEvolutionGenerator(
            self.client, memory=self.memory, repository="org/repo")
        on.generate([self._case()], "base prompt")
        self.assertTrue(self.client.last["prior_conclusions"])

    def test_recall_only_uses_semantic_scope(self):
        """episodic 是一次次任务的流水，拼进提示词只会挤占预算。

        semantic 才是 `remember_feedback` 写入的 scope，也是"关于这类
        缺陷的稳定结论"该待的地方。
        """
        self.memory.remember(
            "default", "org/repo", "episodic", "finding_approved",
            "episodic note about SEC-EVAL in a.py",
        )
        generator = RootCauseEvolutionGenerator(
            self.client, memory=self.memory, repository="org/repo")
        generator.generate([self._case()], "base prompt")
        self.assertEqual([], self.client.last["prior_conclusions"])

    def test_duplicate_root_causes_are_recalled_once(self):
        """同一根因的多条 case 不该触发多次相同召回。

        重复内容占预算，且会让模型以为这条结论"更重要"。
        """
        self._remember()
        generator = RootCauseEvolutionGenerator(
            self.client, memory=self.memory, repository="org/repo")
        generator.generate(
            [self._case(1), self._case(2), self._case(3)], "base prompt")

        conclusions = self.client.last["prior_conclusions"]
        self.assertEqual(1, len(conclusions))

    def test_an_empty_memory_is_not_an_error(self):
        generator = RootCauseEvolutionGenerator(
            self.client, memory=self.memory, repository="org/repo")
        result = generator.generate([self._case()], "base prompt")
        self.assertEqual([], result["prior_conclusions"])
        self.assertTrue(result["candidate_prompt"])

    def test_the_fingerprint_travels_with_each_sanitized_case(self):
        """落盘的 failure_cases 要带指纹，否则事后无法按根因归并报告。"""
        generator = RootCauseEvolutionGenerator(self.client)
        result = generator.generate([self._case()], "base prompt")
        self.assertEqual(
            16, len(result["failure_cases"][0]["root_cause_fingerprint"]),
        )


class PriorAttemptTests(_Base):
    def _record(self, case, baseline_version, run_id="run-1", case_id=1, **kwargs):
        from evoagent.root_cause import fingerprint_case
        payload = {
            "decision": "rejected", "reason": "holdout recall regressed",
            "candidate_version": 3,
        }
        payload.update(kwargs)
        return self.store.record_evolution_attempts(
            run_id, "llm-review", payload["decision"], payload["reason"],
            payload["candidate_version"], [(case_id, fingerprint_case(case))],
            baseline_version=baseline_version, edits=payload.get("edits"),
        )

    def test_past_verdicts_are_fed_back_to_the_generator(self):
        """被拒的候选必须让下一轮知道，否则会反复提等价修改。"""
        self._record(self._case(), 3)
        engine = EvolutionEngine(self.store, seed_defaults=False)
        prior = engine._prior_attempts("llm-review", [self._case()], 3)

        self.assertEqual(1, len(prior["attempts"]))
        self.assertEqual("rejected", prior["attempts"][0]["decision"])
        self.assertIn("holdout", prior["attempts"][0]["reason"])
        self.assertEqual(0, prior["dropped"])

    def test_unrelated_root_causes_are_not_fed_back(self):
        """无关根因的失败记录挤占预算，且易被误读成"这个方向也别碰"。"""
        self._record(self._case(rule_id="SEC-SQL", path="z.py"), 3, case_id=9)
        engine = EvolutionEngine(self.store, seed_defaults=False)
        prior = engine._prior_attempts("llm-review", [self._case()], 3)
        self.assertEqual([], prior["attempts"])
        self.assertEqual(0, prior["considered"])

    def test_a_verdict_from_an_older_baseline_is_withheld(self):
        """针对 v1 被拒的结论，在提示词走到 v6 之后不再是证据。

        那条"别这么改"是相对一个已经不存在的基线得出的——当前基线里可能
        压根没有那段文本。继续回传它既挤占预算，又把生成器往一个已经无效的
        禁区上引。
        """
        self._record(self._case(), 1)
        engine = EvolutionEngine(self.store, seed_defaults=False)
        self.assertEqual(
            [], engine._prior_attempts("llm-review", [self._case()], 6)["attempts"],
        )
        # 同一行在它自己的基线上仍然是有效证据——过期是相对的，不是删除。
        self.assertEqual(
            1, len(engine._prior_attempts("llm-review", [self._case()], 1)["attempts"]),
        )

    def test_expiry_does_not_refund_the_retry_budget(self):
        """反思信号会随基线过期，重试计数**不会**。

        跟着过期的话，每激活一个新版本就等于给所有根因重置额度，
        `max_attempts_per_root_cause` 名存实亡——又一道假装在工作的门禁。
        """
        from evoagent.root_cause import fingerprint_case
        for index in range(3):
            self._record(self._case(), 1, run_id="run-%d" % index)
        key = fingerprint_case(self._case())
        # 基线已经走到 6，反思信号一条都不回传……
        engine = EvolutionEngine(self.store, seed_defaults=False)
        self.assertEqual(
            [], engine._prior_attempts("llm-review", [self._case()], 6)["attempts"],
        )
        # ……但那三次全量回放的钱花过了，计数照旧是 3。
        self.assertEqual(
            3, self.store.count_attempts_by_fingerprint("llm-review")[key],
        )

    def test_a_missing_baseline_yields_no_reflection_signal(self):
        """第一轮还没有 active 版本时没有"同一基线"可言。

        老账本行（本列加入之前写的）的 baseline 是 NULL，同样不回传：
        它们归属不到任何基线，当成当前有效会把陈旧结论伪装成新鲜的。
        """
        self._record(self._case(), None)
        engine = EvolutionEngine(self.store, seed_defaults=False)
        self.assertEqual(
            [], engine._prior_attempts("llm-review", [self._case()], None)["attempts"],
        )
        self.assertEqual(
            [], engine._prior_attempts("llm-review", [self._case()], 3)["attempts"],
        )

    def test_the_reflection_signal_is_capped_and_the_drop_is_reported(self):
        """账本随轮次单调增长，而它整条进候选生成的**输入**。

        `token_budget` 封的是输出（max_tokens），封不住输入。所以不设上限的
        后果不是报错，是反思信号挤掉真正要看的 `failure_cases`，且看不出来。
        截断条数必须报出：只报送进去的条数会让"这轮只有 2 条历史"和"这轮有
        40 条但只送了 2 条"长得一样。
        """
        for index in range(5):
            self._record(self._case(), 3, run_id="run-%d" % index)
        engine = EvolutionEngine(
            self.store, seed_defaults=False, max_reflection_attempts=2)
        prior = engine._prior_attempts("llm-review", [self._case()], 3)
        self.assertEqual(2, len(prior["attempts"]))
        self.assertEqual(5, prior["considered"])
        self.assertEqual(3, prior["dropped"])

    def test_the_edits_and_score_delta_travel_with_the_verdict(self):
        """只给 decision + reason 说明不了上次试的是**哪个**改法。

        生成器完全可能再提一遍等价修改，门禁再拒一次，重试额度就这么烧完。
        照 SkillOpt 的 step buffer 形状回传具体 edits 加 score_before →
        score_after。
        """
        self._record(self._case(), 3, edits={
            "edits": ["Require evidence from an added line"],
            "score_before": 0.62, "score_after": 0.55,
            "regressed_metrics": ["recall"],
        })
        engine = EvolutionEngine(self.store, seed_defaults=False)
        entry = engine._prior_attempts(
            "llm-review", [self._case()], 3)["attempts"][0]
        self.assertEqual(
            ["Require evidence from an added line"], entry["edits"])
        self.assertEqual(0.62, entry["score_before"])
        self.assertEqual(0.55, entry["score_after"])
        self.assertEqual(["recall"], entry["regressed_metrics"])

    def test_an_unscored_attempt_reports_no_score_rather_than_zero(self):
        """没跑到评测的尝试与测出 0.0 的尝试意义完全相反。

        填 0 会让生成器以为上次那个改法把分数打到了零，从而绕开一个其实
        没被检验过的方向。与 `_empty_metrics` 里 CI 用 None 同一条纪律。
        """
        self._record(self._case(), 3, edits={"edits": ["something"]})
        engine = EvolutionEngine(self.store, seed_defaults=False)
        entry = engine._prior_attempts(
            "llm-review", [self._case()], 3)["attempts"][0]
        self.assertNotIn("score_before", entry)
        self.assertNotIn("score_after", entry)

    def test_a_generator_with_the_old_signature_still_works(self):
        """第三方 generator 只接受两个参数时退化，但如实标明没有反思信号。

        不标的话，事后会把"生成器不支持"读成"有历史但模型没利用"——
        那是两个完全不同的结论。
        """

        class _LegacyGenerator:
            def generate(self, failures, base_prompt):
                return {
                    "candidate_prompt": base_prompt + "\nx",
                    "candidate": {}, "clusters": [], "rationale": "",
                    "change_diff": "", "generation": {}, "generator": {},
                    "failure_cases": failures,
                }

        self._record(self._case(), 3, reason="regressed")
        engine = EvolutionEngine(
            self.store, seed_defaults=False, candidate_generator=_LegacyGenerator())
        generated = engine._generate_candidate(
            "llm-review", [self._case()], "base", 3)

        self.assertEqual([], generated["prior_attempts"])
        self.assertTrue(generated["prior_attempts_unsupported"])
        # 退化路径同样要报出规模：这一轮**有** 1 条相关历史，只是生成器
        # 接不了。这两个数放在一起才能得出那个结论。
        self.assertEqual(1, generated["reflection"]["sent"])
        self.assertEqual(1, generated["reflection"]["considered"])


class IsolationTests(_Base):
    def test_the_reviewer_under_evaluation_never_sees_memory(self):
        """钉住两个注入点的区分。

        候选生成阶段读记忆是允许的；被评测的 reviewer 读记忆会毁掉
        holdout 独立性。`RegressionEvaluator` 只拿到一个 prompt 字符串，
        构造 reviewer 的工厂签名里没有记忆这个概念——这条断言就是防止
        以后有人"顺手"把 memory 传进 reviewer_factory。
        """
        import inspect
        from evoagent.evolution import RegressionEvaluator

        signature = inspect.signature(RegressionEvaluator.__init__)
        self.assertNotIn("memory", signature.parameters)
        signature = inspect.signature(RegressionEvaluator.run)
        self.assertEqual(
            ["self", "prompt", "cases"], list(signature.parameters),
        )


if __name__ == "__main__":
    unittest.main()