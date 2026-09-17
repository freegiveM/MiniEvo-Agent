import json
import unittest

from evoagent.diff_parser import parse_unified_diff
from evoagent.evaluation_benchmark import ContextRuleReviewer
from evoagent.evaluation_v2 import (
    FairAblationSuite,
    ProductArmReviewer,
    product_reviewer_factories,
)
from evoagent.reviewer import LocalRuleReviewer


DIFF = (
    "--- a/app.py\n"
    "+++ b/app.py\n"
    "@@ -0,0 +1 @@\n"
    "+value = open(base / user_path)\n"
)


class FakeClient:
    provider = "fake"
    model = "fake-model"

    def complete_json(self, role, _system, user, ledger=None, max_tokens=None):
        if ledger:
            ledger.record_model(
                role, self.provider, self.model,
                {"prompt_tokens": 10, "completion_tokens": 5}, 1,
            )
        if role == "planner":
            return {
                "action": "final",
                "task_graph": [
                    {"specialist": "security", "objective": "Review security"},
                    {
                        "specialist": "correctness-reliability",
                        "objective": "Review correctness",
                    },
                ],
            }
        if role in {"hybrid-reviewer", "security", "correctness-reliability"}:
            return {"action": "final", "findings": []}
        if role == "critic":
            managed = json.loads(user)
            task = json.loads(managed["task"])
            return {
                "action": "final",
                "decisions": [
                    {
                        "finding_index": index,
                        "accepted": True,
                        "objections": [],
                        "confidence_adjustment": 0.0,
                    }
                    for index, _item in enumerate(task["candidates"])
                ],
            }
        raise AssertionError(role)


class AgenticEvaluationTests(unittest.TestCase):
    def test_all_arms_share_exactly_fourteen_rules_and_real_role_topologies(self):
        self.assertEqual(14, len(LocalRuleReviewer.RULES) + len(ContextRuleReviewer.RULES))
        expected_calls = {
            "rules-only": {},
            "single-llm": {"hybrid-reviewer": 1},
            "multi-llm-no-critic": {
                "planner": 1, "security": 1, "correctness-reliability": 1,
            },
            "full-agentic": {
                "planner": 1, "security": 1,
                "correctness-reliability": 1, "critic": 1,
            },
        }
        parsed = parse_unified_diff(DIFF)
        for arm, calls in expected_calls.items():
            reviewer = ProductArmReviewer(arm, FakeClient(), 4096, 40)
            findings = reviewer.review(DIFF, parsed)
            self.assertEqual(["SEC-PATH-TRAVERSAL"], [item.rule_id for item in findings])
            actual = {}
            for item in reviewer.evaluation_execution()["model_call_log"]:
                actual[item["role"]] = actual.get(item["role"], 0) + 1
            self.assertEqual(calls, actual)
            self.assertEqual(14, reviewer.evaluation_config()["deterministic_rules"])

    def test_non_production_data_can_debug_but_cannot_prove_claims(self):
        cases = []
        for index, split in enumerate(("train", "validation", "holdout"), 1):
            cases.append({
                "id": "case-%d" % index,
                "repository": "repo-%d" % index,
                "pull_request": index,
                "split": split,
                "source": {"kind": "synthetic-controlled"},
                "diff": DIFF,
                "expected_findings": [{
                    "path": "app.py", "start_line": 1, "end_line": 1,
                    "rule_id": "SEC-PATH-TRAVERSAL", "cwe": "CWE-22",
                    "severity": "high", "should_comment": True,
                }],
            })
        suite = FairAblationSuite(
            product_reviewer_factories(FakeClient(), 40),
            "fake-model", 4096, require_production_ready=False,
            bootstrap_iterations=200,
        )
        report = suite.run(cases)
        self.assertFalse(report["dataset"]["ready"])
        self.assertFalse(report["launch_gate"]["passed"])
        self.assertFalse(report["critic_gate"]["passed"])
        self.assertEqual(
            {"planner": 3, "security": 3, "correctness-reliability": 3, "critic": 3},
            report["arms"]["full-agentic"]["execution"]["model_role_calls"],
        )


class ActionNormalisationTests(unittest.TestCase):
    """动作标签的同义词归一。

    实测背景：164 条 × 4 臂的跑批里 36 条死于 "returned an invalid action"。
    模型并没有产出坏 JSON，只是没照抄 "final" 这个字面量——会写 complete、
    finish，或者干脆省掉 action 字段直接给 findings。把这些判成执行失败会记
    成漏报，等于拿模型的用词习惯去惩罚它的审查能力。
    """

    def _role(self, responses):
        from evoagent.agentic_core import BoundedRole
        from evoagent.runtime import ToolRegistry
        from evoagent.telemetry import ExecutionLedger

        queue = list(responses)

        class Client:
            provider = "fake"
            model = "fake-model"

            def complete_json(self, role, _system, _user, ledger=None,
                              max_tokens=None):
                return queue.pop(0)

        role = BoundedRole("security", "p", Client(), 10000, 60)
        return role, ToolRegistry(()), ExecutionLedger("test")

    def test_final_synonyms_are_accepted(self):
        for word in ("complete", "finish", "done", "answer", "submit",
                     "FINAL", " Completed "):
            role, tools, ledger = self._role(
                [{"action": word, "findings": []}]
            )
            result = role.run("task", tools, ledger)
            self.assertEqual([], result["findings"], word)

    def test_a_missing_action_is_inferred_from_the_payload(self):
        role, tools, ledger = self._role([{"findings": []}])
        self.assertEqual([], role.run("task", tools, ledger)["findings"])

        role, tools, ledger = self._role([{"task_graph": []}])
        self.assertEqual([], role.run("task", tools, ledger)["task_graph"])

    def test_a_genuinely_unrecognisable_action_still_fails_loudly(self):
        """放宽不等于什么都收：既没有已知标签、也没有终态载荷，仍须报错。

        而且错误消息必须带上实际收到的 action 和字段名——原来只有一句
        "invalid action"，排查时完全不知道模型说了什么。
        """
        role, tools, ledger = self._role([{"action": "ponder", "thoughts": "hm"}])
        with self.assertRaises(ValueError) as caught:
            role.run("task", tools, ledger)
        message = str(caught.exception)
        self.assertIn("ponder", message)
        self.assertIn("thoughts", message)


if __name__ == "__main__":
    unittest.main()
