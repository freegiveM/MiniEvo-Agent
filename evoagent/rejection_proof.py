"""轨道 0：让"拒绝"在一次真实回放里打响。

## 为什么需要这个

翻遍 `output/` 下的全部历史报告，`decision` 只出现过一个值：`activated`。
也就是说**拒绝路径从未在真实回放里执行过**。这是个问题：holdout 门禁是这
套系统里唯一的抗过拟合检查，而一道从没打响过的门禁不能算已知可用——它可
能因为一个取值口径错误而永远返回 True，报告上却什么都看不出来。

`evolution_proof.py` 证明的是"反馈能推动提示词进化并通过门禁"。这个模块
证明相反的一半：**该被拦的候选确实会被拦住，且拦截理由能落盘复现**。两者
合起来才说明门禁是一个门禁，而不是一条直通管道。

## 过拟合机制是真的，不是硬编码一个 False

刻意不采用"直接构造一个分数更低的候选"那种做法——那只证明了比大小能工作。
这里复现的是 holdout 真正要防的那类失效：

- Validation 的 8 个仓库里，每一处 `set_cookie(` 调用都恰好是不安全的
  （`secure=False`）；安全的 cookie 写法在这些仓库里用的是另一个 API
  （`response.headers["Set-Cookie"] = ...`）。
- 于是从 Validation 反馈中学到的"`set_cookie(` 就是风险"这条规则，在
  Validation 上**一个误报都不会产生**：precision、clean_accuracy 全部不
  退化，recall 显著上升，改进门禁与验证集非退化门禁都通过。
- 但 Holdout 的 2 个仓库里存在 `secure=True` 的正当用法。同一条规则在那里
  变成误报机器，precision 与 clean_accuracy 双双下跌。

这正是 holdout 存在的理由：一条在验证集上看起来完美的规则，其"完美"来自
验证集的表面统计规律而非真实因果。**分布差异不是这个构造的缺陷，而是它的
定义**——如果两个分区同分布，过拟合在验证集上就已经暴露了，根本轮不到
holdout 去拦。

## 这个证明不声称什么

它证明门禁在遇到这类候选时会拒绝，并且拒绝理由可审计。它**不**声称：

- 真实的候选生成器会以多大概率产出这类过拟合候选（这需要真实反馈流的数据，
  目前 `failure_cases` 里是 0 条）；
- 门禁能拦住所有类型的过拟合（这里只覆盖了"学到过宽规则"这一种）。

报告里的 `claim_scope` 原样写着这两条。
"""

import hashlib
import json
import os
import re
from typing import Any, Dict, Iterable, List, Optional, Set

from .evaluation_benchmark import ContextRuleReviewer
from .evaluation_harness import RULE_TO_CWE, dataset_fingerprint, load_jsonl
from .evolution import DEFAULT_PROMPT, EvolutionEngine, RegressionEvaluator
from .models import Finding, Severity
from .reviewer import LocalRuleReviewer, Reviewer
from .store import TaskStore, utc_now


FOCUS_RULE = re.compile(r"\[focus-rule:([A-Z][A-Z0-9_-]{1,79})\]")
BROAD_RULE = re.compile(r"\[broad-rule:([A-Z][A-Z0-9_-]{1,79})\]")

# 过宽规则：只看 API 名，不看关键参数。这是"从验证集表面规律学到的规则"
# 的直白建模——在验证集里这个 API 恰好每次都被误用，于是规则退化成认 API。
BROAD_PATTERNS = {
    "SEC-INSECURE-COOKIE": (Severity.MEDIUM, re.compile(r"set_cookie\s*\(")),
}


def generate_rejection_cases() -> List[dict]:
    """构造一个"验证集上完美、隐藏集上有害"的语料。

    仓库 1-8 是 Validation，9-10 是 Holdout，仓库之间不交叉（与
    `evolution_proof` 同一约束）。两个分区的差别是刻意的，见模块文档：
    Validation 里 `set_cookie(` 全部是不安全用法，Holdout 里存在
    `secure=True` 的正当用法。
    """
    cases: List[dict] = []
    case_number = 0

    def add(repository, split, scenario_number, line, rule_id=None, severity=None):
        nonlocal case_number
        case_number += 1
        path = "src/repo_%02d_case_%02d.py" % (
            int(repository.rsplit("-", 1)[1]), scenario_number,
        )
        expected = []
        if rule_id:
            expected.append({
                "path": path, "start_line": 1, "end_line": 1,
                "rule_id": rule_id, "cwe": RULE_TO_CWE[rule_id],
                "severity": severity,
            })
        cases.append({
            "schema_version": 1,
            "id": "rejection-proof-%04d" % case_number,
            "repository": repository,
            "pull_request": 2000 + scenario_number,
            "split": split,
            "diff": (
                "--- a/%s\n+++ b/%s\n@@ -1 +1 @@\n-old_value\n+%s\n"
                % (path, path, line)
            ),
            "expected_findings": expected,
            "after_files": {path: line + "\n"},
            "repair_validation": {},
            "source": {
                "kind": "synthetic-controlled",
                "generator": "rejection-proof-v1",
                "public_url": None,
            },
        })

    for number in range(1, 11):
        repository = "proof/reject-%02d" % number
        split = "validation" if number <= 8 else "holdout"
        scenario = 0

        # 两个分区都有的高风险样本：基线规则本来就能抓到。作用是把
        # high_severity_recall 钉在 1.0，让拒绝理由不会混入"高危召回退化"
        # 这个无关变量。
        scenario += 1
        add(repository, split, scenario,
            "result = eval(payload_%d)" % number, "SEC-EVAL", "critical")
        scenario += 1
        add(repository, split, scenario,
            'api_key = "production-secret-%d"' % number,
            "SEC-HARDCODED-SECRET", "high")

        if split == "validation":
            # 不安全的 cookie 用法 —— 基线漏报，是反馈的来源。
            for index in range(3):
                scenario += 1
                add(repository, split, scenario,
                    'response.set_cookie("sid_%d_%d", value, secure=False)'
                    % (number, index),
                    "SEC-INSECURE-COOKIE", "medium")
            # 安全的 cookie 用法，但走的是**另一个 API**。过宽规则认的是
            # `set_cookie(`，所以在验证集上一个误报都不会产生。
            scenario += 1
            add(repository, split, scenario,
                'response.headers["Set-Cookie"] = build_secure_cookie(sid_%d)' % number)
        else:
            scenario += 1
            add(repository, split, scenario,
                'response.set_cookie("sid_%d", value, secure=False)' % number,
                "SEC-INSECURE-COOKIE", "medium")
            # Holdout 里的正当用法：同一个 API，参数是安全的。过宽规则会把
            # 这些全部误报。
            for index in range(4):
                scenario += 1
                add(repository, split, scenario,
                    'response.set_cookie("sid_%d_%d", value, secure=True)'
                    % (number, index))

        # 两个分区共有的其他干净样本，避免 clean_accuracy 的分母过小。
        for index, template in enumerate((
            "result = json.loads(payload_%d)",
            "subprocess.run(command_%d, shell=False)",
            "digest_%d = hashlib.sha256(payload).hexdigest()",
        )):
            scenario += 1
            add(repository, split, scenario, template % number)

    return cases


class OverBroadPolicyReviewer(Reviewer):
    """行为完全由提示词版本决定的确定性 reviewer。

    识别两种标记：

    - `[focus-rule:X]`：启用 `ContextRuleReviewer` 里那条**精确**规则；
    - `[broad-rule:X]`：启用一条**过宽**规则，只认 API 名不看关键参数。

    两者的区别就是这个证明的全部内容。精确规则在两个分区上都正确；过宽规则
    在验证集上碰巧也正确，在隐藏集上变成误报机器。
    """

    name = "over-broad-policy-reviewer"

    def __init__(self, prompt: str):
        self.prompt = prompt
        self.focus_rules: Set[str] = set(FOCUS_RULE.findall(prompt))
        self.broad_rules: Set[str] = set(BROAD_RULE.findall(prompt))
        self.local = LocalRuleReviewer()
        self.context = ContextRuleReviewer()

    def review(self, diff: str, parsed) -> List[Finding]:
        findings = list(self.local.review(diff, parsed))
        findings.extend(
            finding for finding in self.context.review(diff, parsed)
            if finding.rule_id in self.focus_rules
        )
        for rule_id in sorted(self.broad_rules):
            entry = BROAD_PATTERNS.get(rule_id)
            if entry is None:
                continue
            severity, pattern = entry
            for line in parsed.added_lines:
                if not pattern.search(line.content):
                    continue
                findings.append(Finding(
                    rule_id=rule_id, severity=severity,
                    title="Over-broad learned rule",
                    explanation=(
                        "The candidate prompt learned to flag this API without "
                        "inspecting its security-relevant arguments."
                    ),
                    path=line.path, line=line.line,
                    evidence=line.content.strip()[:240],
                    fix="Inspect the arguments before reporting the call as unsafe.",
                    test="Add a case covering the secure form of this call.",
                ))
        deduplicated = {}
        for finding in findings:
            deduplicated[(finding.rule_id, finding.path, int(finding.line))] = finding
        return list(deduplicated.values())


def _evolution_case(case: dict) -> dict:
    return {
        "name": "reject-%s" % case["id"],
        "split": case["split"],
        "diff": case["diff"],
        "expected": [
            {
                "path": item["path"], "line": int(item["start_line"]),
                "rule_id": item.get("rule_id", item["cwe"]),
                "min_severity": item["severity"],
            }
            for item in case["expected_findings"]
        ],
        "source": (case.get("source") or {}).get("kind", "unknown"),
    }


def _prompt_sha256(prompt: str) -> str:
    return hashlib.sha256(prompt.encode("utf-8")).hexdigest()


# `gates` 字典里**不是每一项都是门禁**：`significant` / `holdout_significant`
# 是 Track E 的纯报告项，三态，`decision` 完全不看它们（见 evolution.py 的
# `_significance_report` 文档）。所以这里用白名单，不扫整个字典——否则一个
# "差异不显著"会被报成"某道门禁没过"，而这次回放要证明的恰恰是"被哪道门禁
# 拦下"这件事本身准确。
GATE_NAMES = (
    "safety",
    "validation_dataset_ready",
    "holdout_dataset_ready",
    "evaluation_success",
    "validation_improvement",
    "validation_non_regression",
    "holdout_non_regression",
)


def _failing_gates(gates: Dict[str, Any]) -> List[str]:
    # 只收 False。None = 还没跑到那一步，不是"没通过"。
    return sorted(
        name for name in GATE_NAMES if gates.get(name) is False
    )


def _metric_delta(candidate: dict, baseline: dict) -> Dict[str, Optional[float]]:
    names = (
        "score", "precision", "recall", "f1", "severity_accuracy",
        "high_severity_recall", "clean_accuracy", "success_rate",
    )

    def delta(name: str) -> Optional[float]:
        # 任一端 None → 差值 None。拿 None 当 0 会造出一个假数字。
        left, right = candidate.get(name), baseline.get(name)
        if left is None or right is None:
            return None
        return round(float(left) - float(right), 4)

    return {name: delta(name) for name in names}


# 两个被证明的场景。每个都给出"预期被哪道门禁拦下"，报告会把预期与实际
# 逐条比对——只断言"被拒绝了"是不够的：因为错误的理由被拒绝，说明门禁在
# 用一个我们没打算依赖的条件工作。
SCENARIOS = {
    "holdout_regression": {
        "title": "过拟合候选：验证集完美、隐藏集退化",
        "suffix": (
            "\n\nValidated evolution constraints:\n"
            "- Explicitly check added lines for confirmed rule "
            "SEC-INSECURE-COOKIE [broad-rule:SEC-INSECURE-COOKIE]."
        ),
        "expected_decision": "rejected",
        "expected_failing_gates": ["holdout_non_regression"],
        "mechanism": (
            "验证集里每一处 set_cookie( 都是不安全用法，于是学到的规则退化成"
            "只认 API 名。该规则在验证集上零误报（安全写法走的是另一个 API），"
            "在隐藏集上把 secure=True 的正当用法全部误报。"
        ),
    },
    "no_improvement": {
        "title": "无效候选：安全但没有带来提升",
        "suffix": (
            "\n\nValidated evolution constraints:\n"
            "- Explicitly check added lines for confirmed rule "
            "SEC-YAML-LOAD [focus-rule:SEC-YAML-LOAD]."
        ),
        "expected_decision": "rejected",
        "expected_failing_gates": ["validation_improvement"],
        "mechanism": (
            "候选启用的规则在语料里一个实例都没有，因此指标完全不变。"
            "它不有害，但也没有达到最小提升阈值。"
        ),
    },
}


def run_rejection_proof(
    dataset_path: str, database_path: str, scenario: str = "holdout_regression",
) -> Dict[str, Any]:
    """跑一次拒绝证明，返回可审计报告。"""
    if scenario not in SCENARIOS:
        raise ValueError(
            "unknown scenario: %s (expected one of %s)"
            % (scenario, ", ".join(sorted(SCENARIOS)))
        )
    spec = SCENARIOS[scenario]
    cases = load_jsonl(dataset_path)
    source_kinds = sorted({
        str((case.get("source") or {}).get("kind", "unknown")) for case in cases
    })
    store = TaskStore(database_path)
    for case in cases:
        converted = _evolution_case(case)
        store.save_evaluation_case(
            converted["name"], converted["split"], converted["diff"],
            converted["expected"], converted["source"], True,
        )

    validation_count = sum(case["split"] == "validation" for case in cases)
    holdout_count = sum(case["split"] == "holdout" for case in cases)

    baseline_validation = RegressionEvaluator(OverBroadPolicyReviewer).run(
        DEFAULT_PROMPT,
        store.list_evaluation_cases("validation", True, len(cases)),
    )
    store.save_skill_version(
        "llm-review", DEFAULT_PROMPT, baseline_validation["score"], activate=True
    )

    engine = EvolutionEngine(
        store,
        reviewer_factory=OverBroadPolicyReviewer,
        min_cases=validation_count,
        max_cases=len(cases),
        min_improvement=0.02,
        min_holdout_cases=holdout_count,
        max_metric_regression=0.02,
        seed_defaults=False,
    )
    candidate_prompt = DEFAULT_PROMPT.rstrip() + spec["suffix"]
    result = engine.propose("llm-review", candidate_prompt)

    gates = result.get("gates") or {}
    failing = _failing_gates(gates)
    active_after = store.get_active_skill_version("llm-review")
    versions = list(reversed(store.list_skill_versions("llm-review")))
    runs = store.list_evolution_runs(50, skill_name="llm-review")

    decision_matches = result.get("decision") == spec["expected_decision"]
    # 只断言"被拒绝"是不够的。因为一个我们没打算依赖的条件而被拒绝，说明
    # 这次回放并没有验证我们以为它验证了的那道门禁。
    gates_match = failing == sorted(spec["expected_failing_gates"])
    # 拒绝之后上线版本必须没变——门禁拦下了却已经换掉线上提示词，是比不拦
    # 更糟的失效。
    active_unchanged = bool(
        active_after and active_after["prompt"].strip() == DEFAULT_PROMPT.strip()
    )

    return {
        "schema_version": 1,
        "generated_at": utc_now(),
        "scenario": {
            "key": scenario,
            "title": spec["title"],
            "mechanism": spec["mechanism"],
            "expected_decision": spec["expected_decision"],
            "expected_failing_gates": sorted(spec["expected_failing_gates"]),
        },
        "claim_scope": {
            "level": "controlled-offline-gate-rejection",
            "proves": (
                "回放门禁在遇到一个验证集表现更好、隐藏集退化的候选时确实会拒绝，"
                "拒绝理由与受影响指标可落盘复现，且上线版本保持不变。"
            ),
            "does_not_prove": (
                "真实候选生成器产出这类过拟合候选的概率（需要真实反馈流数据，"
                "当前 failure_cases 为 0 条）；也不证明门禁能拦住所有类型的过拟合"
                "（此处只覆盖『学到过宽规则』一种）。"
            ),
        },
        "dataset": {
            "path": os.path.abspath(dataset_path),
            "cases": len(cases),
            "validation_cases": validation_count,
            "holdout_cases": holdout_count,
            "repositories": len({case["repository"] for case in cases}),
            "source_kinds": source_kinds,
            "sha256": dataset_fingerprint(cases),
        },
        "evolution_run": {
            "run_id": result.get("run_id"),
            "decision": result.get("decision"),
            "reason": result.get("reason"),
            "gates": gates,
            "failing_gates": failing,
        },
        "versions": [
            {
                "version": item["version"],
                "active": bool(item["active"]),
                "parent_version": item.get("parent_version"),
                "score": item["score"],
                "prompt_sha256": _prompt_sha256(item["prompt"]),
            }
            for item in versions
        ],
        "validation": {
            "baseline": result["baseline"],
            "candidate": result["candidate"],
            "delta": _metric_delta(result["candidate"], result["baseline"]),
        },
        "holdout": {
            "baseline": result["baseline_holdout"],
            "candidate": result["candidate_holdout"],
            "delta": _metric_delta(
                result["candidate_holdout"], result["baseline_holdout"]),
        },
        "verdict": {
            "decision_matches_expectation": decision_matches,
            "failing_gates_match_expectation": gates_match,
            "active_version_unchanged": active_unchanged,
            "proof_passed": decision_matches and gates_match and active_unchanged,
        },
        "audit": {
            "evolution_runs_recorded": len(runs),
            "candidate_prompt_sha256": _prompt_sha256(candidate_prompt.strip()),
            "baseline_prompt_sha256": _prompt_sha256(DEFAULT_PROMPT),
        },
    }


def write_jsonl(cases: Iterable[dict], path: str) -> None:
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        for case in cases:
            handle.write(json.dumps(case, ensure_ascii=False, sort_keys=True) + "\n")


def render_markdown(report: Dict[str, Any]) -> str:
    def pct(value: Optional[float]) -> str:
        # None → n/a。渲染成 0.00% 会被读成"测了一条没中"，那是个结论。
        if value is None:
            return "n/a"
        return "%.2f%%" % (100.0 * float(value))

    def row(label: str, key: str, block: dict) -> str:
        delta = block["delta"][key]
        return "| %s | %s | %s | %s |" % (
            label, pct(block["baseline"].get(key)), pct(block["candidate"].get(key)),
            "n/a" if delta is None else "%+.2f pp" % (100.0 * delta),
        )

    verdict = report["verdict"]
    scenario = report["scenario"]
    lines = [
        "# EvoAgent 回放门禁拒绝证明",
        "",
        "## 结论",
        "",
        "- 场景：%s（`%s`）" % (scenario["title"], scenario["key"]),
        "- 进化决策：`%s`（预期 `%s`）" % (
            report["evolution_run"]["decision"], scenario["expected_decision"]),
        "- 未通过的门禁：`%s`（预期 `%s`）" % (
            "`, `".join(report["evolution_run"]["failing_gates"]) or "无",
            "`, `".join(scenario["expected_failing_gates"]),
        ),
        "- 上线版本保持不变：`%s`" % str(verdict["active_version_unchanged"]).lower(),
        "- 证明结果：`%s`" % ("PASS" if verdict["proof_passed"] else "FAIL"),
        "",
        "> 本报告证明门禁**会拒绝**该被拒绝的候选，与 "
        "`prompt-evolution-proof` 证明的『能通过』互为另一半。",
        "> 它不声称真实生成器产出这类候选的概率，也不声称覆盖了所有过拟合类型。",
        "",
        "## 过拟合机制",
        "",
        scenario["mechanism"],
        "",
        "## Validation 回放（候选在这里看起来更好）",
        "",
        "| 指标 | Prompt v1 | 候选 | 变化 |",
        "|---|---:|---:|---:|",
        row("Precision", "precision", report["validation"]),
        row("Recall", "recall", report["validation"]),
        row("F1", "f1", report["validation"]),
        row("高风险召回率", "high_severity_recall", report["validation"]),
        row("干净样本准确率", "clean_accuracy", report["validation"]),
        row("综合得分", "score", report["validation"]),
        "",
        "## Holdout 回放（真相在这里显现）",
        "",
        "| 指标 | Prompt v1 | 候选 | 变化 |",
        "|---|---:|---:|---:|",
        row("Precision", "precision", report["holdout"]),
        row("Recall", "recall", report["holdout"]),
        row("F1", "f1", report["holdout"]),
        row("高风险召回率", "high_severity_recall", report["holdout"]),
        row("干净样本准确率", "clean_accuracy", report["holdout"]),
        row("综合得分", "score", report["holdout"]),
        "",
        "## 审计证据",
        "",
        "- Evolution run：`%s`" % report["evolution_run"]["run_id"],
        "- 拒绝原因：%s" % report["evolution_run"]["reason"],
        "- 候选提示词 SHA-256：`%s`" % report["audit"]["candidate_prompt_sha256"],
        "- 基线提示词 SHA-256：`%s`" % report["audit"]["baseline_prompt_sha256"],
        "- 数据集指纹：`%s`" % report["dataset"]["sha256"],
        "- 样本：%s（Validation %s / Holdout %s，仓库 %s 个不交叉）" % (
            report["dataset"]["cases"], report["dataset"]["validation_cases"],
            report["dataset"]["holdout_cases"], report["dataset"]["repositories"],
        ),
    ]
    for version in report["versions"]:
        lines.append(
            "- Prompt v%s：active=`%s`，parent=`%s`，SHA-256=`%s`" % (
                version["version"], str(version["active"]).lower(),
                version["parent_version"], version["prompt_sha256"],
            )
        )
    lines.append("")
    return "\n".join(lines)


def write_report(report: Dict[str, Any], output_dir: str) -> Dict[str, str]:
    os.makedirs(output_dir, exist_ok=True)
    json_path = os.path.join(output_dir, "rejection-proof.json")
    markdown_path = os.path.join(output_dir, "rejection-proof.md")
    with open(json_path, "w", encoding="utf-8", newline="\n") as handle:
        json.dump(report, handle, ensure_ascii=False, indent=2, sort_keys=True)
        handle.write("\n")
    with open(markdown_path, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(render_markdown(report))
    return {"json": json_path, "markdown": markdown_path}