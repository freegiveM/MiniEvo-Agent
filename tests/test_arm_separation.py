"""四臂消融是否真的在测不同的东西。

## 为什么需要这组测试

现有的 `test_agentic_evaluation.FakeClient` 对**每个** LLM 角色都返回
`{"findings": []}`。后果：四臂的输出恒等于 14 条确定性规则的结果，而那条
测试还把这个恒等断言固化了：

    self.assertEqual(["SEC-PATH-TRAVERSAL"], [item.rule_id for item in findings])
    # 四臂全都断言同一个结果

它验证的是**调用拓扑**（谁调了哪些角色、调了几次），这部分是对的、有价值的。
但"LLM 贡献了 finding"这条路径一次都没走过。于是消融实验最核心的前提
——四臂在同一个 PR 上会给出不同结论——没有任何测试支撑。

一个只验证拓扑的消融，无法排除这种失败模式：角色都调用了，但返回值被丢弃
或被去重掉，四臂输出其实一样，而报表上的 f1 差异全部来自随机性。这正是
"数字看起来正常、实际什么都没测"的那一类问题。

这组测试补的就是这一段：让桩 client 按角色返回**可辨识的** finding，
断言四臂的输出集合逐级不同。

## 桩的设计

每个角色报一条自己独占的 rule_id，且 path/line 必须落在 diff 的新增行上
（`_parse_findings` 会丢掉不在 `parsed.added_lines` 里的条目——这个约束本身
就值得被测到）。critic 否掉 security 报的那条，于是 full-agentic 的输出
严格少于 multi-llm-no-critic，方向可预期。
"""
import json
import unittest

from evoagent.diff_parser import parse_unified_diff
from evoagent.evaluation_v2 import ARM_TOPOLOGY, ProductArmReviewer

# 三行新增：第 1 行触发确定性规则（path traversal），另两行留给 LLM 角色，
# 这样"规则命中"与"LLM 命中"在结果里可以分开看。
DIFF = (
    "--- a/app.py\n"
    "+++ b/app.py\n"
    "@@ -0,0 +1,3 @@\n"
    "+value = open(base / user_path)\n"
    "+threshold = compute(payload)\n"
    "+cache[key] = threshold\n"
)

RULE_FINDING = "SEC-PATH-TRAVERSAL"
HYBRID_FINDING = "LLM-HYBRID-ONLY"
SECURITY_FINDING = "LLM-SECURITY-ONLY"
CORRECTNESS_FINDING = "LLM-CORRECTNESS-ONLY"


# diff 里第 2、3 行的原文，桩要按 FindingGate 的要求原样引用。
LINE_SOURCE = {
    1: "value = open(base / user_path)",
    2: "threshold = compute(payload)",
    3: "cache[key] = threshold",
}


def _finding(rule_id, line, severity="high"):
    """A stub finding shaped to pass FindingGate, the way a real model must.

    这里必须满足三条产品约束，不能绕过——绕过了就等于测了一条生产环境
    走不到的路径：

    1. evidence 必须是该行**原文的子串**（evidence gate：没有对得上的代码
       就没有证据）。
    2. high/critical 还额外要求 call_chain 或强工具证据，且必须带 fix 与
       test（release gate：高危结论要能落地）。这里给 call_chain。
    3. confidence ≥ 0.55（confidence gate）。

    medium 走的是较松的分支，所以两档都被覆盖到了。
    """
    return {
        "rule_id": rule_id, "severity": severity, "title": rule_id,
        "explanation": "stub explanation for %s" % rule_id,
        "path": "app.py", "line": line,
        "evidence": LINE_SOURCE[line],
        "call_chain": [{"path": "app.py", "line": line, "symbol": "stub"}],
        "fix": "stub fix", "test": "stub test", "confidence": 0.8,
    }


class RoleAwareClient:
    """Each role contributes a distinguishable finding; the critic rejects one."""

    provider = "fake"
    model = "fake-model"

    def __init__(self):
        self.calls = []

    def complete_json(self, role, _system, user, ledger=None, max_tokens=None):
        self.calls.append(role)
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
                    {"specialist": "correctness-reliability",
                     "objective": "Review correctness"},
                ],
            }
        if role == "hybrid-reviewer":
            return {"action": "final", "findings": [_finding(HYBRID_FINDING, 2)]}
        if role == "security":
            return {"action": "final", "findings": [_finding(SECURITY_FINDING, 2)]}
        if role == "correctness-reliability":
            return {
                "action": "final",
                "findings": [_finding(CORRECTNESS_FINDING, 3, "medium")],
            }
        if role == "critic":
            # 盲评：critic 只看到 candidates 的下标与内容，看不到来源角色。
            managed = json.loads(user)
            task = json.loads(managed["task"])
            decisions = []
            for index, candidate in enumerate(task["candidates"]):
                rejected = candidate.get("rule_id") == SECURITY_FINDING
                decisions.append({
                    "finding_index": index,
                    "accepted": not rejected,
                    "objections": ["stub objection"] if rejected else [],
                    "confidence_adjustment": 0.0,
                })
            return {"action": "final", "decisions": decisions}
        raise AssertionError("unexpected role: %s" % role)


def _rule_ids(arm, client=None):
    reviewer = ProductArmReviewer(arm, client or RoleAwareClient(), 4096, 40)
    findings = reviewer.review(DIFF, parse_unified_diff(DIFF))
    return sorted(item.rule_id for item in findings)


class ArmsProduceDifferentOutputsTests(unittest.TestCase):
    """消融的前提：四臂在同一个 PR 上给出不同结论。"""

    def test_rules_only_reports_only_the_deterministic_rule(self):
        self.assertEqual([RULE_FINDING], _rule_ids("rules-only"))

    def test_single_llm_adds_what_the_rules_cannot_see(self):
        """臂 B 相对臂 A 的增量，就是"LLM 能看见规则看不见的东西"这个论点。"""
        self.assertEqual(
            [HYBRID_FINDING, RULE_FINDING], _rule_ids("single-llm")
        )

    def test_multi_role_covers_more_than_one_generalist_role(self):
        """臂 C 相对臂 B：两个专才各报一条，单个通才只报一条。"""
        self.assertEqual(
            [CORRECTNESS_FINDING, SECURITY_FINDING, RULE_FINDING],
            _rule_ids("multi-llm-no-critic"),
        )

    def test_the_critic_suppresses_a_candidate_so_the_full_arm_reports_fewer(self):
        """臂 D 相对臂 C：critic 的作用是**减少**输出，方向必须可验证。

        这条是四臂里唯一"输出更少反而更好"的臂——precision 上升、recall 可能
        下降。如果 critic 的否决没有真的生效，臂 C 与臂 D 输出全等，
        critic_gate 报的 precision 提升就纯属噪声。
        """
        self.assertEqual(
            [CORRECTNESS_FINDING, RULE_FINDING], _rule_ids("full-agentic")
        )

    def test_no_two_arms_produce_the_same_finding_set(self):
        """总断言：四臂两两不同。

        这是整组测试的核心不变量。任何一次重构让两臂输出相同，消融实验
        就失去意义，而这件事从报表数字上看不出来（只会显示"差异不显著"）。
        """
        outputs = {arm: tuple(_rule_ids(arm)) for arm in ARM_TOPOLOGY}
        self.assertEqual(
            len(ARM_TOPOLOGY), len(set(outputs.values())),
            "arms collapsed to identical outputs: %s" % outputs,
        )

    def test_the_arms_are_monotonic_in_what_the_rules_contribute(self):
        """确定性规则的那条命中在四臂里都必须存在。

        14 条规则是共享底座，臂之间的差异只应来自 LLM 层。规则命中在某一臂
        消失，说明 LLM 层的合并/去重逻辑吃掉了规则结果——那是 bug，不是消融。
        """
        for arm in ARM_TOPOLOGY:
            self.assertIn(RULE_FINDING, _rule_ids(arm), arm)


class LlmFindingValidationTests(unittest.TestCase):
    """LLM 报的 finding 必须落在新增行上，否则丢弃。"""

    def test_a_finding_off_the_added_lines_is_dropped(self):
        """这是防幻觉的硬约束：模型可以编造行号，评测口径不能跟着编造。

        没有这条约束，一个报满所有行号的 reviewer 会靠撞运气拿到高 recall。
        """
        class OffDiffClient(RoleAwareClient):
            def complete_json(self, role, system, user, ledger=None, max_tokens=None):
                if role == "hybrid-reviewer":
                    self.calls.append(role)
                    if ledger:
                        ledger.record_model(
                            role, self.provider, self.model,
                            {"prompt_tokens": 10, "completion_tokens": 5}, 1,
                        )
                    off_diff = _finding(HYBRID_FINDING, 2)
                    off_diff.update({"rule_id": "LLM-OFF-DIFF", "line": 999})
                    return {
                        "action": "final",
                        "findings": [
                            _finding(HYBRID_FINDING, 2),   # 新增行，保留
                            off_diff,                      # 不在 diff 里，丢弃
                        ],
                    }
                return super().complete_json(role, system, user, ledger, max_tokens)

        client = OffDiffClient()
        ids = _rule_ids("single-llm", client)
        self.assertIn(HYBRID_FINDING, ids)
        self.assertNotIn("LLM-OFF-DIFF", ids)

    def test_a_finding_on_another_file_is_dropped(self):
        class WrongFileClient(RoleAwareClient):
            def complete_json(self, role, system, user, ledger=None, max_tokens=None):
                if role == "hybrid-reviewer":
                    self.calls.append(role)
                    if ledger:
                        ledger.record_model(
                            role, self.provider, self.model,
                            {"prompt_tokens": 10, "completion_tokens": 5}, 1,
                        )
                    raw = _finding("LLM-WRONG-FILE", 2)
                    raw["path"] = "other.py"
                    return {"action": "final", "findings": [raw]}
                return super().complete_json(role, system, user, ledger, max_tokens)

        ids = _rule_ids("single-llm", WrongFileClient())
        self.assertNotIn("LLM-WRONG-FILE", ids)
        self.assertEqual([RULE_FINDING], ids)


class ExecutionAccountingTests(unittest.TestCase):
    def test_each_arm_records_exactly_the_roles_its_topology_declares(self):
        """拓扑声明与实际调用必须一致——声明了不调用等于虚报架构。"""
        for arm, topology in ARM_TOPOLOGY.items():
            reviewer = ProductArmReviewer(arm, RoleAwareClient(), 4096, 40)
            reviewer.review(DIFF, parse_unified_diff(DIFF))
            logged = {
                item["role"] for item in
                reviewer.evaluation_execution()["model_call_log"]
            }
            self.assertEqual(set(topology["roles"]), logged, arm)

    def test_the_critic_decision_log_records_the_rejection(self):
        """否决要留痕：报告里说"critic 抑制了 N 条"必须有出处。

        顺带钉住一个容易被误解的设计细节：critic 评判的是**全部** 3 条候选
        （2 条 LLM + 1 条确定性规则命中），不是只评 LLM 那部分。也就是说
        critic 有权否掉规则命中。这是合理的——规则也会误报——但它意味着
        臂 D 的 precision 提升不能全部归因于"约束了 LLM"。
        """
        reviewer = ProductArmReviewer("full-agentic", RoleAwareClient(), 4096, 40)
        reviewer.review(DIFF, parse_unified_diff(DIFF))
        summary = reviewer._last_summary
        collaboration = summary.get("collaboration") or {}
        self.assertEqual(3, collaboration["candidate_findings_before_critic"])
        self.assertEqual(2, collaboration["accepted_findings"])
        rejected = [
            item for item in collaboration["critic_decisions"]
            if not item["accepted"]
        ]
        self.assertEqual(1, len(rejected))
        self.assertEqual(["stub objection"], rejected[0]["objections"])

    def test_rules_only_still_refuses_to_call_the_model(self):
        client = RoleAwareClient()
        ProductArmReviewer("rules-only", client, 4096, 40).review(
            DIFF, parse_unified_diff(DIFF)
        )
        self.assertEqual([], client.calls)


if __name__ == "__main__":
    unittest.main()
