"""critic 的两路输入：上游 trace 摘要 + gate 证据缺口。

这一层的价值不在"字段传过去了"，而在几条口径：
  - 缺口按呈现位置挂，不泄露规范顺序（否则前面的盲审打乱白做）
  - 给的是"缺什么证据"而不是"会被拒"（否则两道关卡塌成一道）
  - stopped_early 要能被看见（预算掐断 ≠ 查过了没问题）
  - critic 没跑时三个计数是 None 而不是 0
"""
import json
import unittest

from evoagent.agentic_core import (
    CRITIC_PROMPT, gate_gaps, specialist_activity,
)
from evoagent.diff_parser import parse_unified_diff
from evoagent.gates import FindingGate
from evoagent.models import Finding, Severity
from evoagent.telemetry import ExecutionLedger

DIFF = (
    "diff --git a/app.py b/app.py\n"
    "--- a/app.py\n"
    "+++ b/app.py\n"
    "@@ -1,0 +1,2 @@\n"
    "+token = \"abc123\"\n"
    "+print(token)\n"
)


def _finding(**kwargs) -> Finding:
    base = dict(
        rule_id="SEC-X", severity=Severity.HIGH, title="t",
        explanation="e", path="app.py", line=1,
        evidence='token = "abc123"', confidence=0.9,
        fix="use env var", test="assert no literal",
    )
    base.update(kwargs)
    return Finding(**base)


class SpecialistActivityTests(unittest.TestCase):

    def test_reports_tools_actually_invoked(self):
        ledger = ExecutionLedger("agentic")
        ledger.trace("security", "started", tools=["ast_analyze"])
        ledger.trace("security", "tool_observation", step=1,
                     tool="ast_analyze", ok=True)
        ledger.trace("security", "finished", step=2)
        activity = specialist_activity(ledger, ("security",))
        self.assertEqual(activity[0]["tools_invoked"], ["ast_analyze"])
        self.assertEqual(activity[0]["tool_calls"], 1)

    def test_budget_exhaustion_is_visible(self):
        """预算掐断必须能看见。

        中途停下的 specialist 没报的问题不等于不存在。critic 看不到这件事
        就会把"没查完"读成"查过了没问题"，这两个结论方向相反。
        """
        ledger = ExecutionLedger("agentic")
        ledger.trace("security", "started")
        ledger.trace("security", "budget_exhausted", step=3)
        self.assertTrue(specialist_activity(ledger, ("security",))[0]["stopped_early"])

    def test_normal_finish_is_not_marked_early(self):
        ledger = ExecutionLedger("agentic")
        ledger.trace("security", "started")
        ledger.trace("security", "finished", step=2)
        self.assertFalse(specialist_activity(ledger, ("security",))[0]["stopped_early"])

    def test_failed_tool_calls_are_counted_separately(self):
        """调过但失败 ≠ 没调过。前者说明查了没查到，后者说明没查。"""
        ledger = ExecutionLedger("agentic")
        ledger.trace("security", "tool_observation", step=1, tool="symbol", ok=False)
        activity = specialist_activity(ledger, ("security",))[0]
        self.assertEqual(activity["tool_calls"], 1)
        self.assertEqual(activity["failed_tool_calls"], 1)

    def test_roles_with_no_trace_are_omitted(self):
        """没跑过的角色不出现，而不是出现一条全 0 的记录。

        全 0 记录会被读成"跑了但什么都没查"，那是另一个意思。
        """
        ledger = ExecutionLedger("agentic")
        ledger.trace("security", "started")
        roles = [item["role"]
                 for item in specialist_activity(ledger, ("security", "planner"))]
        self.assertEqual(roles, ["security"])


class GateGapTests(unittest.TestCase):

    def test_a_finding_missing_strong_evidence_reports_a_gap(self):
        parsed = parse_unified_diff(DIFF)
        gaps = gate_gaps([_finding()], parsed, FindingGate())
        self.assertIn(0, gaps)
        self.assertTrue(any("evidence gate" in reason for reason in gaps[0]))

    def test_a_complete_finding_reports_no_gap(self):
        parsed = parse_unified_diff(DIFF)
        complete = _finding(call_chain=[{"from": "a", "to": "b"}])
        self.assertEqual(gate_gaps([complete], parsed, FindingGate()), {})

    def test_the_dry_run_does_not_drop_candidates(self):
        """空跑只取副作用，不能把候选过滤掉。

        gate 真正生效必须在 critic **之后**：提前过滤会让 critic 看不到
        全部候选，也就没机会把缺证据的那些救回来。
        """
        parsed = parse_unified_diff(DIFF)
        candidates = [_finding(), _finding(line=2, evidence="print(token)")]
        gate_gaps(candidates, parsed, FindingGate())
        self.assertEqual(len(candidates), 2)


class _FakeTools:
    def names(self):
        return []

    def catalog(self):
        return []

    def invoke(self, name, arguments):
        raise AssertionError("critic should finish without tools in this test")


class _FakeSuite:
    def registry(self, role, permissions):
        return _FakeTools()


class _PayloadCapturingClient:
    """记下 critic 实际收到的 payload，什么都不判。"""

    provider = "fake"
    model = "fake-model"

    def __init__(self):
        self.payloads = []

    def complete_json(self, role, _system, user, ledger=None, max_tokens=None):
        # BoundedRole 把 user_context 原样放进 managed["task"]，而
        # _run_critic 传进去的本身是一串 JSON，所以要解两层。
        self.payloads.append(json.loads(json.loads(user)["task"]))
        return {"action": "final", "decisions": []}


class BlindingTests(unittest.TestCase):
    """缺口的挂法不能泄露规范顺序。"""

    def _capture(self, candidates, order):
        from evoagent.agentic_core import BoundedRole, ModeRouterReviewer

        client = _PayloadCapturingClient()
        parsed = parse_unified_diff(DIFF)
        gaps = gate_gaps(candidates, parsed, FindingGate())
        reviewer = ModeRouterReviewer.__new__(ModeRouterReviewer)
        critic = BoundedRole("critic", CRITIC_PROMPT, client, 10_000, 30)
        reviewer._run_critic(
            critic, candidates, order, DIFF, _FakeSuite(),
            ExecutionLedger("agentic"), None, gaps,
        )
        return client.payloads[0], gaps

    def test_gaps_follow_the_presentation_position_not_the_canonical_index(self):
        """规范下标 1 缺证据、呈现顺序 [1, 0] 时，缺口必须落在呈现第 0 位。

        这是这个文件里最重要的一条。缺口若按规范下标挂，critic 就能从
        "第几条带缺口"反推出规范顺序，而规范顺序是按 severity 排的——
        前面打乱呈现顺序防位置偏置的功夫就全废了。
        """
        # 规范 0 证据完整（有 call_chain），规范 1 缺强证据。
        candidates = [
            _finding(call_chain=[{"from": "a", "to": "b"}]),
            _finding(line=2, evidence="print(token)"),
        ]
        payload, gaps = self._capture(candidates, [1, 0])
        self.assertEqual(list(gaps), [1])            # 规范下标 1 有缺口
        blinded = payload["candidates"]
        self.assertTrue(blinded[0]["missing_evidence"])   # 呈现第 0 位 = 规范 1
        self.assertFalse(blinded[1]["missing_evidence"])  # 呈现第 1 位 = 规范 0

    def test_activity_is_top_level_not_per_candidate(self):
        """活动摘要是跨候选的上下文，挂在单条候选上会被误读成那条的证据。"""
        candidates = [_finding()]
        from evoagent.agentic_core import BoundedRole, ModeRouterReviewer

        client = _PayloadCapturingClient()
        reviewer = ModeRouterReviewer.__new__(ModeRouterReviewer)
        critic = BoundedRole("critic", CRITIC_PROMPT, client, 10_000, 30)
        reviewer._run_critic(
            critic, candidates, [0], DIFF, _FakeSuite(),
            ExecutionLedger("agentic"),
            [{"role": "security", "stopped_early": True}], {},
        )
        payload = client.payloads[0]
        self.assertIn("specialist_activity", payload)
        self.assertNotIn("specialist_activity", payload["candidates"][0])


class PromptContractTests(unittest.TestCase):

    def test_prompt_says_gaps_are_not_verdicts(self):
        """口径写进 prompt，不是靠模型自己领会。

        只把缺口塞进 payload 不说清含义，模型最自然的读法就是
        "gate 都说不行了那就拒"——两道独立关卡塌成一道，
        加了这个信息反而让整体变差。
        """
        self.assertIn("NOT verdicts", CRITIC_PROMPT)
        self.assertIn("missing_evidence", CRITIC_PROMPT)

    def test_prompt_tells_the_critic_to_supply_the_evidence(self):
        """反馈回路的意义是"补证据"，所以 prompt 必须明确要求去补。"""
        self.assertIn("supply that evidence", CRITIC_PROMPT)

    def test_prompt_warns_about_self_reported_evidence(self):
        """evidence_refs 是 specialist 自己填的，可以填没调过的工具。"""
        self.assertIn("self-reported", CRITIC_PROMPT)

    def test_prompt_warns_that_early_stop_is_not_absence(self):
        self.assertIn("not evidence of absence", CRITIC_PROMPT)


if __name__ == "__main__":
    unittest.main()
