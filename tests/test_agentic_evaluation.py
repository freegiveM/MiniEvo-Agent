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


if __name__ == "__main__":
    unittest.main()
