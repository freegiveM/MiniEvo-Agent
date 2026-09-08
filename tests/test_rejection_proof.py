"""轨道 0：证明"拒绝"这条路径真的会打响，且因为**正确的**理由打响。

## 为什么这批测试有存在价值

在这个模块之前，翻遍 `output/` 下全部历史报告，`decision` 只出现过一个值：
`activated`。拒绝路径从未在一次真实回放里执行过——只有单测直接构造指标字典
去戳 `_non_regressing`。而 holdout 门禁是这套系统里唯一的抗过拟合检查。
一道从没在端到端回放里打响过的门禁不能算已知可用：它可能因为某个取值口径
错误而永远返回 True，报告上什么都看不出来。

## 为什么断言"因为哪道门禁被拒"而不只断言"被拒了"

因为错误的理由被拒绝，说明这次回放并没有验证我们以为它验证了的那道门禁。
最初这个语料跑出来是四道门禁一起 False——其中 `evaluation_success` 是我
构造 `Finding` 时漏了必填字段，所有 `set_cookie(` 样本直接抛异常。那一版
`decision` 也是 `rejected`，如果只断言"被拒绝了"，这批测试会全绿，而真正
要证明的东西（门禁靠**误报**拦下过拟合）一条都没被验证。所以
`failing_gates` 必须精确匹配。
"""
import os
import shutil
import tempfile
import unittest

from evoagent.rejection_proof import (
    GATE_NAMES,
    SCENARIOS,
    OverBroadPolicyReviewer,
    _failing_gates,
    generate_rejection_cases,
    render_markdown,
    run_rejection_proof,
    write_jsonl,
    write_report,
)


class DatasetTests(unittest.TestCase):
    def setUp(self):
        self.cases = generate_rejection_cases()

    def test_repositories_do_not_cross_the_split_boundary(self):
        """与 evolution_proof 同一约束：仓库不跨分区。

        一个仓库同时出现在两边，holdout 就不再是"没见过的分布"，这个证明
        自己会变成它要防的那个错误。
        """
        sides = {}
        for case in self.cases:
            sides.setdefault(case["repository"], set()).add(case["split"])
        for repository, splits in sides.items():
            self.assertEqual(1, len(splits), "%s 跨了分区：%s" % (repository, splits))

    def test_both_splits_have_positive_and_clean_cases(self):
        """两边都要有干净样本，否则 clean_accuracy 的分母是 0，门禁失效。

        `_non_regressing` 只在 baseline 有 clean_cases 时才保护
        clean_accuracy——分母为 0 时这道保护是空的。
        """
        for split in ("validation", "holdout"):
            subset = [case for case in self.cases if case["split"] == split]
            self.assertTrue(any(case["expected_findings"] for case in subset))
            self.assertTrue(any(not case["expected_findings"] for case in subset))

    def test_validation_has_no_secure_set_cookie_call(self):
        """过拟合机制的前提条件。

        验证集里若出现 `secure=True` 的 set_cookie，过宽规则在验证集上就会
        产生误报，`validation_non_regression` 会跟着一起 False——那时拒绝
        就不再是 holdout 独自完成的了，这个证明的意义就没了。
        """
        for case in self.cases:
            if case["split"] != "validation":
                continue
            for line in case["diff"].splitlines():
                if line.startswith("+") and "set_cookie(" in line:
                    self.assertIn("secure=False", line)

    def test_holdout_contains_the_legitimate_usage(self):
        """holdout 必须真的有正当用法，否则没有任何东西会被误报。"""
        secure = [
            case for case in self.cases
            if case["split"] == "holdout" and "secure=True" in case["diff"]
        ]
        self.assertTrue(secure)
        # 正当用法是干净样本：期望结果必须为空，否则它就成了漏报而非误报。
        for case in secure:
            self.assertEqual([], case["expected_findings"])

    def test_case_names_are_unique(self):
        """样本名在 store 里是不可覆盖的主键，重名会直接抛异常。"""
        ids = [case["id"] for case in self.cases]
        self.assertEqual(len(ids), len(set(ids)))

    def test_source_is_labelled_synthetic(self):
        """来源如实标注。这批数据不是公开 PR，生产来源门禁应当因此失败。"""
        for case in self.cases:
            self.assertEqual("synthetic-controlled", case["source"]["kind"])


class ReviewerTests(unittest.TestCase):
    """reviewer 的行为必须**只**由提示词版本决定，否则回放对比无意义。"""

    def _findings(self, prompt, line):
        from evoagent.diff_parser import parse_unified_diff

        diff = "--- a/a.py\n+++ b/a.py\n@@ -1 +1 @@\n-old\n+%s\n" % line
        return OverBroadPolicyReviewer(prompt).review(diff, parse_unified_diff(diff))

    def test_the_baseline_prompt_misses_insecure_cookies(self):
        """基线漏报是反馈的来源。基线若本来就能抓到，候选无从提升。"""
        findings = self._findings(
            "base", 'response.set_cookie("sid", value, secure=False)')
        self.assertEqual([], [f for f in findings if "COOKIE" in f.rule_id])

    def test_the_broad_rule_flags_the_insecure_form(self):
        findings = self._findings(
            "base [broad-rule:SEC-INSECURE-COOKIE]",
            'response.set_cookie("sid", value, secure=False)')
        self.assertEqual(
            ["SEC-INSECURE-COOKIE"],
            [f.rule_id for f in findings if "COOKIE" in f.rule_id])

    def test_the_broad_rule_also_flags_the_secure_form(self):
        """这就是"过宽"的定义，也是 holdout 上被拦的直接原因。"""
        findings = self._findings(
            "base [broad-rule:SEC-INSECURE-COOKIE]",
            'response.set_cookie("sid", value, secure=True)')
        self.assertEqual(
            ["SEC-INSECURE-COOKIE"],
            [f.rule_id for f in findings if "COOKIE" in f.rule_id])

    def test_the_broad_rule_ignores_the_other_api(self):
        """验证集里的安全写法走另一个 API，过宽规则看不见它。

        这条是"验证集上零误报"的机制保证。
        """
        findings = self._findings(
            "base [broad-rule:SEC-INSECURE-COOKIE]",
            'response.headers["Set-Cookie"] = build_secure_cookie(sid)')
        self.assertEqual([], [f for f in findings if "COOKIE" in f.rule_id])

    def test_reviewing_never_raises(self):
        """任何异常都会变成 evaluation_success=False，把拒绝理由污染掉。

        第一次跑这个证明时正是这里出的问题：漏填 Finding 的必填字段，
        所有 set_cookie 样本都抛异常，四道门禁一起 False。
        """
        for case in generate_rejection_cases():
            from evoagent.diff_parser import parse_unified_diff

            parsed = parse_unified_diff(case["diff"])
            for prompt in ("base", "base [broad-rule:SEC-INSECURE-COOKIE]",
                           "base [focus-rule:SEC-YAML-LOAD]"):
                OverBroadPolicyReviewer(prompt).review(case["diff"], parsed)


class FailingGateTests(unittest.TestCase):
    def test_significance_is_not_treated_as_a_gate(self):
        """`gates` 字典里不是每一项都是门禁。

        `significant` / `holdout_significant` 是 Track E 的纯报告项，
        `decision` 完全不看它们。把它们算成门禁，会让"差异不显著"被报成
        "某道门禁没过"，而这次回放要证明的恰恰是"被哪道门禁拦下"准确。
        """
        gates = {"significant": False, "holdout_significant": False,
                 "holdout_non_regression": False}
        self.assertEqual(["holdout_non_regression"], _failing_gates(gates))

    def test_none_is_not_a_failure(self):
        """None = 还没跑到那一步，不是"没通过"。"""
        self.assertEqual([], _failing_gates({name: None for name in GATE_NAMES}))

    def test_every_gate_name_is_recognised(self):
        gates = {name: False for name in GATE_NAMES}
        self.assertEqual(sorted(GATE_NAMES), _failing_gates(gates))


class ProofRunTests(unittest.TestCase):
    """端到端：真的跑一次回放，真的落盘。"""

    def setUp(self):
        self.directory = tempfile.mkdtemp(prefix="rejection-proof-")

    def tearDown(self):
        shutil.rmtree(self.directory, ignore_errors=True)

    def _run(self, scenario):
        dataset = os.path.join(self.directory, "%s.jsonl" % scenario)
        write_jsonl(generate_rejection_cases(), dataset)
        database = os.path.join(self.directory, "%s.db" % scenario)
        return run_rejection_proof(dataset, database, scenario)

    def test_the_overfitting_candidate_is_rejected_by_the_holdout_gate(self):
        """本轨道的核心断言。"""
        report = self._run("holdout_regression")

        self.assertEqual("rejected", report["evolution_run"]["decision"])
        self.assertEqual(
            ["holdout_non_regression"], report["evolution_run"]["failing_gates"])
        self.assertTrue(report["verdict"]["proof_passed"])

    def test_the_candidate_really_did_look_better_on_validation(self):
        """如果候选在验证集上也更差，那它只是个坏候选，不是过拟合。

        holdout 门禁的价值恰恰在于拦住"在能看见的数据上确实更好"的候选。
        """
        report = self._run("holdout_regression")
        gates = report["evolution_run"]["gates"]

        self.assertTrue(gates["validation_improvement"])
        self.assertTrue(gates["validation_non_regression"])
        self.assertGreater(report["validation"]["delta"]["score"], 0)

    def test_the_rejection_came_from_false_positives_not_crashes(self):
        """success_rate 必须保持 1.0。

        崩溃也会压低指标并触发拒绝，但那证明的是"异常会被记账"，不是
        "门禁能识别过拟合"。
        """
        report = self._run("holdout_regression")

        self.assertTrue(report["evolution_run"]["gates"]["evaluation_success"])
        self.assertEqual(1.0, report["holdout"]["candidate"]["success_rate"])
        # 真相：holdout 上精确率和干净样本准确率一起塌。
        self.assertLess(report["holdout"]["delta"]["precision"], -0.02)
        self.assertLess(report["holdout"]["delta"]["clean_accuracy"], -0.02)

    def test_recall_still_went_up_on_the_holdout(self):
        """过拟合候选在 holdout 上召回率其实更高。

        这条钉住的是：一个只看召回率（或只看单一指标）的门禁会**放它过去**。
        受保护指标是一组而不是一个，原因就在这里。
        """
        report = self._run("holdout_regression")
        self.assertGreater(report["holdout"]["delta"]["recall"], 0)

    def test_the_active_version_is_unchanged_after_a_rejection(self):
        """拦下了却已经换掉线上提示词，比不拦更糟。"""
        report = self._run("holdout_regression")

        self.assertTrue(report["verdict"]["active_version_unchanged"])
        active = [item for item in report["versions"] if item["active"]]
        self.assertEqual([1], [item["version"] for item in active])

    def test_the_rejected_candidate_is_still_persisted_for_audit(self):
        """被拒的版本要留档：它是 DGM 意义上的 stepping stone，也是审计对象。"""
        report = self._run("holdout_regression")
        versions = {item["version"]: item for item in report["versions"]}

        self.assertIn(2, versions)
        self.assertFalse(versions[2]["active"])
        self.assertEqual(1, versions[2]["parent_version"])

    def test_a_useless_candidate_is_rejected_by_the_improvement_gate(self):
        """另一条拒绝路径：不有害，但也没提升。"""
        report = self._run("no_improvement")

        self.assertEqual("rejected", report["evolution_run"]["decision"])
        self.assertEqual(
            ["validation_improvement"], report["evolution_run"]["failing_gates"])
        self.assertTrue(report["verdict"]["proof_passed"])

    def test_the_run_is_recorded_in_evolution_runs(self):
        """"可审计"不能只是报告里的一句话，得真的能从库里查到。"""
        report = self._run("holdout_regression")

        self.assertIsNotNone(report["evolution_run"]["run_id"])
        self.assertGreaterEqual(report["audit"]["evolution_runs_recorded"], 1)

    def test_an_unknown_scenario_raises(self):
        """不静默回落到默认场景：那会让报告标题与实际跑的东西不一致。"""
        dataset = os.path.join(self.directory, "unknown.jsonl")
        write_jsonl(generate_rejection_cases(), dataset)
        with self.assertRaises(ValueError):
            run_rejection_proof(
                dataset, os.path.join(self.directory, "unknown.db"), "not-a-scenario")

    def test_the_claim_scope_states_what_is_not_proven(self):
        """证据等级必须随报告一起走，不能只靠 README 里的一段话。"""
        report = self._run("holdout_regression")
        scope = report["claim_scope"]

        self.assertIn("does_not_prove", scope)
        self.assertTrue(scope["does_not_prove"].strip())
        self.assertEqual(["synthetic-controlled"], report["dataset"]["source_kinds"])

    def test_report_files_are_written(self):
        report = self._run("holdout_regression")
        paths = write_report(report, os.path.join(self.directory, "out"))

        for path in paths.values():
            self.assertTrue(os.path.exists(path))
        markdown = render_markdown(report)
        self.assertIn("holdout_non_regression", markdown)
        self.assertIn("PASS", markdown)


class MarkdownTests(unittest.TestCase):
    def test_missing_metrics_render_as_not_available(self):
        """None 渲染成 0.00% 会被读成"测了一条没中"，那是个结论。"""
        block = {
            "baseline": {"precision": None}, "candidate": {"precision": None},
            "delta": {key: None for key in (
                "score", "precision", "recall", "f1", "severity_accuracy",
                "high_severity_recall", "clean_accuracy", "success_rate")},
        }
        report = {
            "scenario": dict(SCENARIOS["holdout_regression"], key="holdout_regression",
                             expected_failing_gates=["holdout_non_regression"]),
            "verdict": {"proof_passed": False, "active_version_unchanged": True},
            "evolution_run": {"decision": "rejected", "reason": "r",
                              "failing_gates": [], "run_id": "id"},
            "validation": block, "holdout": block, "versions": [],
            "audit": {"candidate_prompt_sha256": "a", "baseline_prompt_sha256": "b"},
            "dataset": {"sha256": "c", "cases": 0, "validation_cases": 0,
                        "holdout_cases": 0, "repositories": 0},
        }
        markdown = render_markdown(report)

        self.assertIn("n/a", markdown)
        self.assertNotIn("0.00%", markdown)
        # 证明没通过时不能印出 PASS。
        self.assertIn("FAIL", markdown)


if __name__ == "__main__":
    unittest.main()