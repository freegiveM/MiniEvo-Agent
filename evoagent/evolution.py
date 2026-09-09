import hashlib
import json
import math
import re
import threading
import uuid
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from .diff_parser import parse_unified_diff
from .prompt_rules import (
    apply_delta,
    compose_prompt,
    entries_from_prompt,
    retention_gate,
)
from .root_cause import count_by_fingerprint, describe, fingerprint_case
from . import archive as archive_module
from .store import utc_now


DEFAULT_PROMPT = (
    "Review the unified diff. Return JSON findings with severity, fix and test. "
    "Report only actionable defects introduced by added lines."
)

DEFAULT_EVALUATION_CASES = [
    {
        "name": "security-dynamic-execution",
        "diff": "--- a/app.py\n+++ b/app.py\n@@ -1 +1 @@\n-old\n+result = eval(user_input)\n",
        "expected": [{"path": "app.py", "line": 1, "min_severity": "high"}],
    },
    {
        "name": "security-hardcoded-secret",
        "diff": "--- a/config.py\n+++ b/config.py\n@@ -1 +1 @@\n-old\n+api_key = \"production-secret\"\n",
        "expected": [{"path": "config.py", "line": 1, "min_severity": "high"}],
    },
    {
        "name": "reliability-swallowed-error",
        "diff": "--- a/jobs.py\n+++ b/jobs.py\n@@ -1 +1 @@\n-old\n+except Exception: pass\n",
        "expected": [{"path": "jobs.py", "line": 1, "min_severity": "medium"}],
    },
    {
        "name": "clean-parameterized-query",
        "diff": "--- a/db.py\n+++ b/db.py\n@@ -1 +1 @@\n-old\n+cursor.execute(\"SELECT * FROM users WHERE id = ?\", (user_id,))\n",
        "expected": [],
    },
    {
        "name": "clean-input-validation",
        "diff": "--- a/api.py\n+++ b/api.py\n@@ -1 +1 @@\n-old\n+limit = min(max(int(raw_limit), 1), 100)\n",
        "expected": [],
    },
    {
        "name": "holdout-security-shell-execution",
        "split": "holdout",
        "diff": "--- a/runner.py\n+++ b/runner.py\n@@ -1 +1 @@\n-old\n+subprocess.run(command, shell=True)\n",
        "expected": [{"path": "runner.py", "line": 1, "min_severity": "high"}],
    },
    {
        "name": "holdout-clean-environment-secret",
        "split": "holdout",
        "diff": "--- a/config.py\n+++ b/config.py\n@@ -1 +1 @@\n-old\n+api_key = os.environ[\"API_KEY\"]\n",
        "expected": [],
    },
]

SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def _ratio(numerator: int, denominator: int) -> Optional[float]:
    """分母为 0 时给 None，不给 1.0 也不给 0.0。

    三个数各不相同，混用会编造结论：
      - 0.0 = 测过了，一条没中（这是个结论）
      - 1.0 = 测过了，全中（这也是个结论）
      - None = 没有样本，得不出结论

    与 evaluation_harness._metrics 的 `ratio(..., empty=None)` 同一口径。
    """
    if denominator <= 0:
        return None
    return numerator / denominator


def _round(value: Optional[float]) -> Optional[float]:
    """round() 对 None 会抛，指标层要能原样透传 None。"""
    return None if value is None else round(value, 4)


def _line_distance(reported: int, start: int, end: int) -> int:
    """报告行到期望区间 [start, end] 的距离，落在区间内为 0。

    与 evaluation_harness._candidate_edges 的
    `min(abs(line - start), abs(line - end))` 同一口径——区间内是 0 而不是
    到端点的距离，避免长区间的中段反而被判成远离。
    """
    if start <= reported <= end:
        return 0
    return min(abs(reported - start), abs(reported - end))


# 95% 双侧正态分位数。写成常量而不是散在调用点：改置信水平要一处改，
# 且 1.96 这个数字裸出现在代码里没人看得出是哪一档。
_Z_95 = 1.959963984540054


def _wilson_interval(
    successes: int, total: int, z: float = _Z_95,
) -> Optional[List[float]]:
    """比例的 Wilson score 置信区间。分母为 0 → None（同 `_ratio` 口径）。

    用 Wilson 而不是正态近似（p ± z·sqrt(p(1-p)/n)）：后者在小样本或 p 贴近
    0/1 时会给出越界的区间（比如 p=1.0, n=18 算出上界 1.0、下界 1.0，宣称
    "确定无疑"），而这正是当前数据规模最常出现的形态——`high_severity_recall`
    的分母只有 18。Wilson 在两端自动收缩且永远落在 [0,1] 内。

    区间宽度如实反映 95 条量级数据集的局限。**不要**为了让区间变窄去调参数：
    区间宽说明样本量不足以支撑结论，这是要如实报告的事实，不是要掩盖的瑕疵。
    """
    if total <= 0:
        return None
    n = float(total)
    p = successes / n
    denominator = 1.0 + z * z / n
    centre = (p + z * z / (2 * n)) / denominator
    spread = (
        z * math.sqrt(p * (1.0 - p) / n + z * z / (4 * n * n)) / denominator
    )
    return [round(max(0.0, centre - spread), 4), round(min(1.0, centre + spread), 4)]


def _intervals_disjoint(
    candidate_ci: Optional[Sequence[float]], baseline_ci: Optional[Sequence[float]],
) -> Optional[bool]:
    """两个置信区间是否不重叠。任一侧缺区间 → None（判断不出来）。

    不重叠是"差异显著"的**保守充分条件**，不是充要条件：两个 95% 区间轻微
    重叠时差异仍可能显著（正确做法是对差值本身做检验）。这里刻意取保守的
    那一侧，因为这个字段现阶段只用于报告"我们有多确信"，宁可少报显著也
    不要多报。
    """
    if not candidate_ci or not baseline_ci:
        return None
    return candidate_ci[0] > baseline_ci[1] or baseline_ci[0] > candidate_ci[1]


def _metric_non_regressing(
    candidate: Optional[float], baseline: Optional[float], margin: float,
) -> bool:
    """单个受保护指标的未回退判定，对 None 做非对称处理。

    - baseline 是 None：这一档 baseline 本来就没测过，无从回退 → 放行。
    - baseline 有数、candidate 是 None：**拦**。候选把一个原本可测的指标变
      成测不出来了（比如一条 finding 都不报 → precision 无定义），这是实质
      回退，不是"不适用"。把它当放行就是本次修的那个漏洞的镜像。
    - 两边都有数：照常比。

    为什么不直接 skip 掉所有 None：`all()` 对空序列返回 True。若把 None 一律
    跳过，一份指标全 None 的评测会得到"全部门禁通过"，正是三态门禁纪律里
    「None 当 True 就是静默放行」要禁止的形态。
    """
    if baseline is None:
        return True
    if candidate is None:
        return False
    return float(candidate) + margin >= float(baseline)


class RegressionEvaluator:
    """Replay a fixed dataset against one prompt and compute objective review metrics."""

    def __init__(
        self, reviewer_factory: Callable[[str], object], line_tolerance: int = 2,
    ):
        self.reviewer_factory = reviewer_factory
        # 行容差。原实现是精确匹配（容差 0），而 evaluation_harness 的
        # one_to_one_match 默认 line_tolerance=2——同一个项目里两把尺子
        # 刻度不同，两边的数字就不能相互解释。默认对齐到 2。
        #
        # 这不是"放宽标准"：D6 首次全量 replay 实测，18 条 high/critical
        # 期望里有 4 条 reviewer 明明定位对了却判成漏报，偏差 1-7 行
        # （paramiko-pr-1065 报 214 行、期望 213；mitmproxy-pr-8326 报 54、
        # 期望 53）。diff 里相邻几行属于同一个语句/同一个缺陷是常态，
        # 要求行号精确相等测的是"reviewer 报的是缺陷的第几行"，不是
        # "有没有发现这个缺陷"。
        self.line_tolerance = max(0, int(line_tolerance))

    def run(self, prompt: str, cases: List[dict]) -> Dict[str, Any]:
        reviewer = self.reviewer_factory(prompt)
        reviewer_name = str(getattr(reviewer, "name", reviewer.__class__.__name__))
        true_positive = false_positive = false_negative = 0
        severity_hits = matched = clean_hits = clean_total = 0
        high_severity_hits = high_severity_total = 0
        expected_total = predicted_total = 0
        errors = []
        case_results = []

        for case in cases:
            expected_items = list(case.get("expected", []))
            expected_total += len(expected_items)
            clean_total += int(not expected_items)
            try:
                parsed = parse_unified_diff(case["diff"])
                findings = reviewer.review(case["diff"], parsed)
                predicted = {}
                for finding in findings:
                    key = (finding.path, int(finding.line), finding.rule_id)
                    current = predicted.get(key)
                    severity = finding.severity.value
                    if current is None or SEVERITY_RANK[severity] > SEVERITY_RANK[current]:
                        predicted[key] = severity
                predicted_total += len(predicted)

                unmatched = set(predicted)
                tp = severity_ok = high_hits = 0
                for expected in expected_items:
                    path = str(expected["path"])
                    line = int(expected["line"])
                    rule_id = str(expected.get("rule_id", "")).strip()
                    minimum = str(expected.get("min_severity", "low")).lower()
                    # end_line 缺省回落到 line：数据集里 expected_finding 是
                    # [start_line, end_line] 的区间，只比 start_line 会把
                    # "报在缺陷区间中段"误判成漏报。取到区间的距离，与
                    # evaluation_harness._candidate_edges 同一种算法。
                    end_line = int(expected.get("end_line", line))
                    if end_line < line:
                        end_line = line
                    candidates = [
                        key for key in unmatched
                        if key[0] == path
                        and _line_distance(key[1], line, end_line) <= self.line_tolerance
                        and (not rule_id or key[2] == rule_id)
                    ]
                    if not candidates:
                        continue
                    # 先按距离近的挑，再按严重度高的挑。反过来（先严重度）
                    # 会让一条报在容差边缘的高危 finding 抢走本该属于近处
                    # 期望的配对，同一 case 内多条期望挨得近时尤其明显。
                    selected = min(
                        candidates,
                        key=lambda key: (
                            _line_distance(key[1], line, end_line),
                            -SEVERITY_RANK[predicted[key]],
                        ),
                    )
                    unmatched.remove(selected)
                    tp += 1
                    severity_passed = SEVERITY_RANK[predicted[selected]] >= SEVERITY_RANK[minimum]
                    severity_ok += int(severity_passed)
                    if SEVERITY_RANK[minimum] >= SEVERITY_RANK["high"]:
                        high_hits += int(severity_passed)

                fp = len(unmatched)
                fn = len(expected_items) - tp
                true_positive += tp
                false_positive += fp
                false_negative += fn
                matched += tp
                severity_hits += severity_ok
                case_high_total = sum(
                    SEVERITY_RANK[str(item.get("min_severity", "low")).lower()]
                    >= SEVERITY_RANK["high"]
                    for item in expected_items
                )
                high_severity_total += case_high_total
                high_severity_hits += high_hits
                if not expected_items:
                    clean_hits += int(not predicted)
                case_results.append({
                    "id": case.get("id"), "name": case["name"], "tp": tp, "fp": fp, "fn": fn,
                    "findings": len(predicted), "severity_hits": severity_ok, "error": None,
                })
            except Exception as exc:
                # A failed replay is a missed positive (or a failed clean case), not a
                # successful empty prediction. This keeps partial outages from inflating scores.
                false_negative += len(expected_items)
                high_severity_total += sum(
                    SEVERITY_RANK.get(str(item.get("min_severity", "low")).lower(), 0)
                    >= SEVERITY_RANK["high"]
                    for item in expected_items
                )
                errors.append({"name": case["name"], "error": str(exc)[:500]})
                case_results.append({
                    "id": case.get("id"), "name": case["name"], "tp": 0, "fp": 0,
                    "fn": len(expected_items), "findings": 0, "severity_hits": 0,
                    "error": str(exc)[:500],
                })

        # 空分母口径：没有样本 → None（无法得出结论），不是 1.0（满分）也不是
        # 0.0（测过了没中）。原先 recall/clean_accuracy/high_severity_recall 在
        # 分母为 0 时返回 1.0，这会让 `_non_regressing` 拿一个编造的满分去比
        # 真实 baseline 并判"未回退"。反转 fix PR 的每个 case 都带种子缺陷，
        # 所以真实数据集上 clean_total 恒为 0——这个 bug 到 D6 必然触发。
        #
        # 后续状态（2026-09，Track A）：这个 bug 已经在数据集层面修复，见
        # dataset_builder.build_clean_case——它从同一批仓库里采"看起来不像
        # bugfix 的普通已合并 PR"作为负样本，expected_findings=[]，产出到
        # 独立文件 datasets/real-pr-clean-v1.jsonl（不与正样本混在同一份
        # real-pr-v1.jsonl 里，见 datasets/README.md 第八节）。只要 D6 replay
        # 时把这批 clean cases 一并传入 cases 列表，clean_total 就会 >0，
        # clean_accuracy 不再是 None。这里的 None 分母口径本身不用改——它
        # 从一开始就是对的，缺的是"真实数据集里从未有过 clean case"这个
        # 上游前提，不是这段计算逻辑的问题。
        precision = _ratio(true_positive, true_positive + false_positive)
        recall = _ratio(true_positive, true_positive + false_negative)
        # f1 直接由混淆矩阵算，不走 precision/recall 的乘积——后者只要有一边
        # 是 None 就得整体 None，而 2tp/(2tp+fp+fn) 只要有过预测或有过真值
        # 就有定义。
        f1 = _ratio(
            2 * true_positive, 2 * true_positive + false_positive + false_negative
        )
        severity_accuracy = _ratio(severity_hits, matched)
        clean_accuracy = _ratio(clean_hits, clean_total)
        high_severity_recall = _ratio(high_severity_hits, high_severity_total)
        successful_cases = len(cases) - len(errors)
        success_rate = successful_cases / len(cases) if cases else 0.0
        # None 分量要剔掉再归一化，不能当 0 参与加权——否则"没测"会被算成
        # "测了得零分"，正是空分母口径要区分的两件事。severity_accuracy 在
        # expected_total > 0 但 matched == 0（全漏）时就是 None。
        components = []
        if expected_total:
            components.extend(((f1, 0.65), (severity_accuracy, 0.15)))
        if clean_total:
            components.append((clean_accuracy, 0.20))
        components = [item for item in components if item[0] is not None]
        score = (
            sum(value * weight for value, weight in components)
            / sum(weight for _, weight in components)
            if components else 0.0
        )
        score *= success_rate
        return {
            "schema_version": 2,
            "reviewer": reviewer_name,
            # score 保持 float：它是加权聚合，没有分量时 0.0 的含义是"这份数据
            # 集给不出任何分数"，而调用方用它做 >= 比较，None 会直接抛。
            "score": round(score, 4),
            "precision": _round(precision),
            "recall": _round(recall),
            "f1": _round(f1),
            "severity_accuracy": _round(severity_accuracy),
            "high_severity_recall": _round(high_severity_recall),
            "clean_accuracy": _round(clean_accuracy),
            # 比例型指标的 95% Wilson 置信区间（Track E）。纯新增，不改动
            # 上面任何点估计字段的语义，也不参与 decision——现阶段只是诊断
            # 信息。分母为 0 时为 None，与点估计的空分母口径一致。
            #
            # 当前 95 条量级下这些区间会相当宽（high_severity_recall 分母
            # 只有 18，区间宽度接近 ±0.2），这是如实反映数据规模的局限，
            # 不是要"调到区间变窄"去掩盖。f1 不给区间：它不是一个简单
            # 比例（分母 2tp+fp+fn 里的样本不独立），套 Wilson 会得到一个
            # 看着像置信区间、实际没有对应统计含义的数。
            "precision_ci": _wilson_interval(
                true_positive, true_positive + false_positive),
            "recall_ci": _wilson_interval(
                true_positive, true_positive + false_negative),
            "severity_accuracy_ci": _wilson_interval(severity_hits, matched),
            "high_severity_recall_ci": _wilson_interval(
                high_severity_hits, high_severity_total),
            "clean_accuracy_ci": _wilson_interval(clean_hits, clean_total),
            "cases": len(cases),
            # severity_accuracy 的分子分母。留着比值不留分母，比较就无从知道
            # 两个比值可不可比——severity_accuracy = severity_hits / matched，
            # 而 matched 是候选自己挣来的：多抓一条真缺陷，分母就大一格。
            # 见 `_severity_accuracy_verdict`。
            "matched": matched,
            "severity_hits": severity_hits,
            "positive_cases": sum(bool(case.get("expected")) for case in cases),
            "clean_cases": clean_total,
            "expected_findings": expected_total,
            "predicted_findings": predicted_total,
            "successful_cases": successful_cases,
            "success_rate": round(success_rate, 4),
            "errors": errors,
            "case_results": case_results,
        }


class EvolutionEngine:
    """Prompt evolution backed by replay evaluation, audit records and activation gates."""

    # 注入指令的黑名单。这里要拦的是"候选提示词试图关掉审查纪律"，不是
    # "候选提示词谈到了绕过"——后者正是安全 reviewer 该谈的话题。
    #
    # 原来这一项是裸的 "bypass" 子串。它把第一个真实候选拦掉了，理由是
    # 提示词里写了 "bypassed timeout settings are visible"：一条要求
    # reviewer 去发现被绕过的超时配置的规则，被当成了绕过审查的指令。
    # 而 "bypass" 是安全评审的核心词汇，这等于让安全门禁永久拒绝一切
    # 讨论绕过的候选——门禁方向是反的。
    #
    # 与语料里 d37c17b820f3565c 是同一个缺陷类：子串匹配没有 token 边界，
    # 那一处让非法 token 通过，这一处让合法文本被拒。改成带动词宾语的
    # 短语，取"指令"这一义项。
    FORBIDDEN = (
        "ignore previous", "ignore all previous", "disregard previous",
        "disable safety", "bypass safety", "bypass the safety",
        "bypass review", "bypass the review", "bypass validation",
        "bypass the gate", "直接执行生产",
    )
    FEEDBACK_RULE_ID = re.compile(r"^[A-Z][A-Z0-9_-]{1,79}$")

    def __init__(
        self, store, reviewer_factory: Optional[Callable[[str], object]] = None,
        min_cases: int = 3, max_cases: int = 20, min_improvement: float = 0.01,
        min_holdout_cases: int = 0, max_metric_regression: float = 0.0,
        seed_defaults: bool = True, candidate_generator=None,
        root_cause_min_occurrences: int = 1,
        max_attempts_per_root_cause: int = 3,
        parent_strategy: str = "active", parent_epsilon: float = 0.1,
    ):
        self.store = store
        self.reviewer_factory = reviewer_factory
        self.min_cases = min_cases
        self.max_cases = max_cases
        self.min_improvement = min_improvement
        self.min_holdout_cases = min_holdout_cases
        self.max_metric_regression = max_metric_regression
        self.candidate_generator = candidate_generator
        self.root_cause_min_occurrences = max(1, int(root_cause_min_occurrences))
        self.max_attempts_per_root_cause = max(0, int(max_attempts_per_root_cause))
        # 未知策略名不静默回落到 active。回落会让一个拼错的环境变量看起来
        # 完全正常工作，而使用者以为自己开了 pareto。
        if parent_strategy not in archive_module.STRATEGIES:
            raise ValueError(
                "unsupported parent selection strategy: %s (expected one of %s)"
                % (parent_strategy, ", ".join(archive_module.STRATEGIES))
            )
        self.parent_strategy = parent_strategy
        self.parent_epsilon = max(0.0, min(1.0, float(parent_epsilon)))
        self._lock = threading.RLock()
        if seed_defaults:
            self._seed_default_cases()

    def _seed_default_cases(self) -> None:
        for case in DEFAULT_EVALUATION_CASES:
            self.store.save_evaluation_case(
                case["name"], case.get("split", "validation"), case["diff"],
                case["expected"], "builtin", True
            )

    @staticmethod
    def validate_case(name: str, diff: str, expected: list, split: str = "validation") -> None:
        if not name or len(name) > 120:
            raise ValueError("evaluation case name is required and must be at most 120 characters")
        if split not in {"train", "validation", "holdout"}:
            raise ValueError("evaluation split must be train, validation or holdout")
        if len(diff.encode("utf-8")) > 1024 * 1024:
            raise ValueError("evaluation case diff must be at most 1 MiB")
        parsed = parse_unified_diff(diff)
        if not parsed.added_lines:
            raise ValueError("evaluation case must contain a valid unified diff with added lines")
        valid_locations = {(line.path, line.line) for line in parsed.added_lines}
        if not isinstance(expected, list):
            raise ValueError("expected_findings must be an array")
        if len(expected) > 100:
            raise ValueError("expected_findings must contain at most 100 items")
        seen = set()
        for item in expected:
            if not isinstance(item, dict):
                raise ValueError("each expected finding must be an object")
            try:
                location = (str(item.get("path", "")), int(item.get("line", 0)))
            except (TypeError, ValueError) as exc:
                raise ValueError("expected finding line must be an integer") from exc
            if location not in valid_locations:
                raise ValueError("expected finding must point to an added line: %s:%s" % location)
            if str(item.get("min_severity", "low")).lower() not in SEVERITY_RANK:
                raise ValueError("invalid min_severity")
            rule_id = str(item.get("rule_id", "")).strip()
            if "rule_id" in item and (not rule_id or len(rule_id) > 80):
                raise ValueError("rule_id must be non-empty and at most 80 characters")
            identity = location + (rule_id,)
            if identity in seen:
                raise ValueError("duplicate expected finding: %s:%s:%s" % identity)
            seen.add(identity)

    def add_evaluation_case(
        self, name: str, diff: str, expected: list, split: str = "validation",
        source: str = "manual",
    ) -> dict:
        name = name.strip()
        split = split.strip().lower()
        self.validate_case(name, diff, expected, split)
        return self.store.save_evaluation_case(name, split, diff, expected, source[:120], True)

    def safety_evaluate(self, prompt: str) -> Dict[str, Any]:
        """确定性安全检查。

        原来只报一个 `safety_passed: False`，三个失败原因（空、超长、命中
        黑名单）在报告上完全无法区分——第一个真实候选被拒时，报告写着
        `completeness: 1.0, missing_terms: []`，看上去一切正常却判了拒绝，
        只能回来读源码才知道是哪一条。所以把原因一并落盘。
        """
        normalized = prompt.strip()
        lowered = normalized.lower()
        forbidden_hits = [token for token in self.FORBIDDEN if token in lowered]
        too_long = len(normalized) > 12000
        safety = bool(normalized) and not too_long and not forbidden_hits
        required = ("diff", "severity", "fix", "test", "json")
        completeness = sum(token in lowered for token in required) / len(required)
        return {
            "safety_passed": safety,
            "completeness": round(completeness, 4),
            "missing_terms": [token for token in required if token not in lowered],
            "forbidden_hits": forbidden_hits,
            "empty_prompt": not normalized,
            "too_long": too_long,
            "prompt_length": len(normalized),
        }

    def status(self) -> Dict[str, Any]:
        # 分层取样，理由见 `select_evaluation_cases`：平铺按 id 截断时，
        # 后灌进来的干净样本永远排在缺陷样本之后取不到，`clean_total` 恒为 0，
        # 于是打分公式里误报侧的 0.20 权重和 `clean_accuracy` 的门禁保护
        # 一起静默失效。status() 也必须走同一条口径，否则概览报的评测集
        # 和 `_propose` 实跑的评测集不是同一套，指纹也对不上。
        cases = self.store.select_evaluation_cases("validation", True, self.max_cases)
        holdout = self.store.select_evaluation_cases("holdout", True, self.max_cases)
        return {
            "model_configured": self.reviewer_factory is not None,
            "validation_cases": len(cases),
            "holdout_cases": len(holdout),
            "minimum_cases": self.min_cases,
            "minimum_holdout_cases": self.min_holdout_cases,
            "maximum_cases_per_run": self.max_cases,
            "minimum_improvement": self.min_improvement,
            "maximum_metric_regression": self.max_metric_regression,
            "validation_dataset_fingerprint": self._dataset_fingerprint(cases),
            "holdout_dataset_fingerprint": self._dataset_fingerprint(holdout),
            # 选亲策略进 status，因为它决定了"下一轮从哪改起"，而这件事
            # 从评测记录里读不出来——两次 run 的亲本不同、原因却只存在于
            # 当时的环境变量里。不报出来，事后无法解释搜索轨迹。
            # 档案本身按 skill 而不同，见 `archive_report(skill_name)`。
            "parent_strategy": self.parent_strategy,
            "ready": (
                self.reviewer_factory is not None
                and len(cases) >= self.min_cases
                and len(holdout) >= self.min_holdout_cases
            ),
        }

    def propose(
        self, skill_name: str, prompt: str, regression_score: Optional[float] = None,
        parent_version: Optional[int] = None,
    ) -> Dict[str, Any]:
        skill_name = skill_name.strip()
        if not skill_name or len(skill_name) > 120:
            raise ValueError("skill_name is required and must be at most 120 characters")
        with self._lock:
            return self._propose(
                skill_name, prompt, regression_score, parent_version=parent_version,
            )

    def _propose(
        self, skill_name: str, prompt: str, regression_score: Optional[float],
        activation_policy: str = "auto", parent_version: Optional[int] = None,
    ) -> Dict[str, Any]:
        """评测一个候选并落盘判决。

        `parent_version` 只影响血统记录（`skill_versions.parent_version`），
        **不影响门禁基线**。基线恒为 active 版本：门禁要回答的是"能不能
        替换掉现在正在服务真实流量的这个"，跟候选是从哪一支演化来的无关。
        默认 None 时回落到 active，与档案选亲加入之前一致。
        """
        safety = self.safety_evaluate(prompt)
        active = self.store.get_active_skill_version(skill_name)
        if active and prompt.strip() == active["prompt"].strip():
            return {
                "version": {
                    "skill_name": active["skill_name"],
                    "version": active["version"],
                    "score": active["score"],
                    "active": bool(active["active"]),
                },
                "decision": "deferred",
                "reason": "candidate prompt is identical to the active version",
                "candidate": self._empty_metrics(0),
                "baseline": self._empty_metrics(0),
                "candidate_holdout": self._redact_holdout_metrics(self._empty_metrics(0)),
                "baseline_holdout": self._redact_holdout_metrics(self._empty_metrics(0)),
                "safety": safety,
                "run_id": None,
            }
        baseline_prompt = active["prompt"] if active else DEFAULT_PROMPT
        # 与 status() 同一条取样口径，见 `select_evaluation_cases`。
        cases = self.store.select_evaluation_cases("validation", True, self.max_cases)
        holdout_cases = self.store.select_evaluation_cases("holdout", True, self.max_cases)

        decision = "deferred"
        reason = ""
        candidate_metrics = self._empty_metrics(len(cases))
        baseline_metrics = self._empty_metrics(len(cases))
        candidate_holdout = self._empty_metrics(len(holdout_cases))
        baseline_holdout = self._empty_metrics(len(holdout_cases))
        gates = {
            "safety": safety["safety_passed"] and safety["completeness"] == 1.0,
            "validation_dataset_ready": len(cases) >= self.min_cases,
            "holdout_dataset_ready": len(holdout_cases) >= self.min_holdout_cases,
            "evaluation_success": None,
            "validation_improvement": None,
            "validation_non_regression": None,
            "holdout_non_regression": None,
            # 纯报告项，**不参与** decision（与 significant 同一档，轨道 I）。
            # 三态：False = 候选静默删掉了基线里的已验证规则；None = 基线
            # 一条标记规则都没有（现存全部 v1 提示词都是这样），无从判断。
            #
            # 为什么先不当门禁：None 覆盖了最常见的情形，顺手当 True 会让
            # 这道门禁在那个情形下静默失效；当 False 又会把第一次进化拦死，
            # 因为亲本必然是无标记的 v1。先落盘观察几轮真实数据，再决定要
            # 不要升格——这与 `_significance_report` 当初的处理完全一致。
            #
            # 对应地，`rejection_proof.GATE_NAMES` **不加**这一项：那是个
            # 白名单，加进去会让 `_failing_gates` 把一个纯报告项算成门禁失败。
            "rule_retention": retention_gate(baseline_prompt, prompt)["passed"],
        }
        if not safety["safety_passed"] or safety["completeness"] < 1.0:
            decision = "rejected"
            reason = "candidate prompt failed the deterministic safety/completeness gate"
        elif self.reviewer_factory is None:
            reason = "candidate saved but no LLM provider is configured; replay evaluation was not run"
        elif len(cases) < self.min_cases:
            reason = "candidate saved but the validation dataset is smaller than the activation minimum"
        elif len(holdout_cases) < self.min_holdout_cases:
            reason = "candidate saved but the holdout dataset is smaller than the activation minimum"
        else:
            evaluator = RegressionEvaluator(self.reviewer_factory)
            baseline_metrics = evaluator.run(baseline_prompt, cases)
            candidate_metrics = evaluator.run(prompt, cases)
            if holdout_cases:
                baseline_holdout = evaluator.run(baseline_prompt, holdout_cases)
                candidate_holdout = evaluator.run(prompt, holdout_cases)
            no_errors = not (
                baseline_metrics["errors"] or candidate_metrics["errors"]
                or baseline_holdout["errors"] or candidate_holdout["errors"]
            )
            improved = candidate_metrics["score"] >= baseline_metrics["score"] + self.min_improvement
            validation_report = self._non_regression_report(
                candidate_metrics, baseline_metrics)
            holdout_report = self._non_regression_report(
                candidate_holdout, baseline_holdout)
            validation_safe = validation_report["passed"]
            holdout_safe = holdout_report["passed"]
            gates.update({
                "evaluation_success": no_errors,
                "validation_improvement": improved,
                "validation_non_regression": validation_safe,
                "holdout_non_regression": holdout_safe,
                # 纯报告项，**不参与** decision。列出哪几个受保护指标其实
                # 没有分母——holdout 里 0 条 high/critical 样本时
                # `high_severity_recall` 就在这里，它恒通过而报告上看不出。
                "non_regression_unmeasurable": {
                    "validation": validation_report["unmeasurable"],
                    "holdout": holdout_report["unmeasurable"],
                },
                # 纯报告项，**不参与**下面的 decision 判断（Track E）。
                # 三态：True/False/None，None = 没样本，算不出区间。
                "significant": self._significance_report(
                    candidate_metrics, baseline_metrics),
                "holdout_significant": self._significance_report(
                    candidate_holdout, baseline_holdout),
            })
            if no_errors and improved and validation_safe and holdout_safe:
                decision = "activated" if activation_policy == "auto" else "shadow_ready"
                reason = (
                    "candidate improved on validation and passed the non-regression holdout gate"
                    if decision == "activated" else
                    "candidate passed replay gates and is awaiting shadow/canary approval"
                )
            else:
                decision = "rejected"
                reasons = []
                if not no_errors:
                    reasons.append("one or more baseline or candidate evaluations failed")
                if not improved:
                    reasons.append("score improvement was below the configured threshold")
                if not validation_safe:
                    reasons.append(
                        "a protected validation metric regressed (%s)"
                        % ", ".join(validation_report["regressed"])
                    )
                if not holdout_safe:
                    reasons.append(
                        "a protected holdout metric regressed (%s)"
                        % ", ".join(holdout_report["regressed"])
                    )
                reason = "; ".join(reasons)

        version = self.store.save_skill_version(
            skill_name, prompt.strip(), candidate_metrics["score"],
            decision == "activated", parent_version=parent_version,
        )
        run = {
            "id": str(uuid.uuid4()),
            "skill_name": skill_name,
            "candidate_version": version["version"],
            "baseline_version": active["version"] if active else None,
            "decision": decision,
            "candidate_score": candidate_metrics["score"],
            "baseline_score": baseline_metrics["score"],
            "metrics": {
                "candidate": candidate_metrics,
                "baseline": baseline_metrics,
                "candidate_holdout": self._redact_holdout_metrics(candidate_holdout),
                "baseline_holdout": self._redact_holdout_metrics(baseline_holdout),
                "safety": safety,
                "gates": gates,
                "reason": reason,
                "reproducibility": {
                    "evaluation_schema_version": 2,
                    "candidate_prompt_sha256": self._sha256(prompt.strip()),
                    "baseline_prompt_sha256": self._sha256(baseline_prompt),
                    "validation_dataset_sha256": self._dataset_fingerprint(cases),
                    "holdout_dataset_sha256": self._dataset_fingerprint(holdout_cases),
                    "validation_case_ids": [case.get("id") for case in cases],
                    "holdout_case_count": len(holdout_cases),
                },
                "external_regression_score_ignored": regression_score is not None,
            },
            "created_at": utc_now(),
        }
        self.store.save_evolution_run(run)
        return {
            "version": version,
            "decision": decision,
            "reason": reason,
            "candidate": candidate_metrics,
            "baseline": baseline_metrics,
            "candidate_holdout": self._redact_holdout_metrics(candidate_holdout),
            "baseline_holdout": self._redact_holdout_metrics(baseline_holdout),
            "safety": safety,
            "gates": gates,
            "run_id": run["id"],
        }

    def rollback(self, skill_name: str, version: int) -> bool:
        with self._lock:
            return self.store.activate_skill_version(skill_name, version)

    def build_archive(self, skill_name: str) -> List[Dict[str, Any]]:
        """当前 skill 的版本档案，含逐样本分数表。

        `list_evolution_runs` 必须传 skill_name 过滤：不同 skill 的版本号
        各自从 1 开始，不过滤会让别的 skill 的 v3 污染这里的 v3。
        """
        return archive_module.build_archive(
            self.store.list_skill_versions(skill_name),
            self.store.list_evolution_runs(200, skill_name=skill_name),
        )

    def archive_report(self, skill_name: str = "llm-review") -> Dict[str, Any]:
        """档案的可读视图，给 status/API 用。

        带上当前策略，因为"前沿上有 4 个版本"这件事在 strategy="active"
        下是**没有被使用**的信息——只报前沿不报策略，会让人以为搜索正在
        利用它。
        """
        report = archive_module.summarise(self.build_archive(skill_name))
        report["parent_strategy"] = self.parent_strategy
        report["parent_epsilon"] = (
            self.parent_epsilon if self.parent_strategy == "epsilon_greedy" else None
        )
        return report

    def select_parent(
        self, skill_name: str, seed: str = "",
    ) -> Optional[Dict[str, Any]]:
        """选出这一轮候选要从哪个版本改起。

        ## 这**不是**门禁基线

        两个问题必须分开：

        1. "候选比正在服务真实流量的版本更好吗" → 门禁，baseline 恒为
           active 版本，`_propose` 里那段没有改。
        2. "下一轮从哪个提示词改起" → 搜索，这里管。

        把 1 也改成跟档案里最优比，门禁就失去意义了——它要回答的正是
        "能不能替换掉现在这个"。所以选亲的产出只影响生成起点，不进入
        `decision` 的计算。

        `seed` 让选择可复现，见 `archive.select_parent` 的说明。
        """
        return archive_module.select_parent(
            self.build_archive(skill_name), strategy=self.parent_strategy,
            seed=seed, epsilon=self.parent_epsilon,
        )

    # 只有人工确认过的反馈可以驱动提示词候选。推断来源（轨道 C 的
    # `merged_without_addressing`）落盘、计数、可供人工分诊，但**不**进
    # 生成器：把"PR 合并了"当成"人类确认这条是误报"，等于让一个弱代理
    # 信号直接改提示词，而门禁只看验证集分数，拦不住这类污染。
    #
    # 这里用白名单而不是黑名单：将来新增一个推断类别时，默认是被排除，
    # 而不是默认混进来。默认值的方向决定了忘记改这里的后果。
    #
    # `execution_error` **不在**这里，尽管它曾经在。它由
    # `harness.py` 的 `except Exception` 兜底写入，没有任何人参与——白名单
    # 挡的是 category 字面值，对"这个 category 背后有没有人"一无所知，所以
    # 它当初是靠字面值混进来的。两个具体后果：
    #
    # 1. 一次崩溃（超时、provider 挂了、JSON 截断）会被当成人工确认的评审
    #    缺陷去改提示词，而这类故障与提示词内容无关。
    # 2. 它的 payload 没有 `finding`，`fingerprint_case` 会退化成只含
    #    category 的指纹，于是**所有**执行错误无论异常、仓库、文件全部塌进
    #    同一个桶。那个桶最快撞上 `max_attempts_per_root_cause`，把彼此无关
    #    的故障一起标成 exhausted。
    #
    # `case_promotion.REFUSED_CATEGORIES` 早就以同样的理由拒绝它进评测集
    # （"an execution error is an outage, not a review defect"）；这里与那边
    # 现在口径一致。执行错误仍然落盘、仍然计数、仍可人工分诊，只是不再自己
    # 改提示词。
    HUMAN_CONFIRMED_CATEGORIES = frozenset({
        "false_positive", "missed_issue", "bad_fix", "accepted",
    })

    def _select_cases(self, skill_name: str, all_cases: List[dict]) -> Dict[str, Any]:
        """把未解决反馈分成"这轮要学的"和"这轮不学的"，并说明为什么不学。

        三道过滤，顺序有讲究：

        1. **来源白名单**（轨道 C）。只有人工确认过的类别能驱动提示词。
        2. **消费账本**。已经喂给过生成器的 case 不再重复喂。这是让闭环
           能往前走的关键：没有这道过滤，同一批反馈每轮重新生成一次相同
           的候选，第二轮开始固定返回"没有新信号"，循环停在原地。
        3. **频率分流**（轨道 D）+ **重试上限**。低频根因只进记忆；反复
           尝试反复失败的根因不再重试。

        每一档被排除的条数都如实返回。静默丢弃会让"有 40 条反馈却没生成
        候选"看起来像 bug，而实际上每一条都有具体原因。
        """
        human = [
            case for case in all_cases
            if case.get("category") in self.HUMAN_CONFIRMED_CATEGORIES
        ]
        inferred_excluded = len(all_cases) - len(human)

        attempted = self.store.list_attempted_failure_case_ids(skill_name)
        fresh = [case for case in human if int(case.get("id", 0)) not in attempted]
        already_attempted = len(human) - len(fresh)

        # 频率统计的范围是**全部人工确认反馈**（含已尝试过的），不只是
        # 本轮新增的。一个根因在历史上出现 5 次、其中 4 次已尝试过，它
        # 依然是一个系统性问题；只数本轮会让它看起来像偶发。
        history = count_by_fingerprint(human)
        attempts = self.store.count_attempts_by_fingerprint(skill_name)

        selected: List[dict] = []
        sporadic: List[dict] = []
        exhausted: List[dict] = []
        for case in fresh:
            key = fingerprint_case(case)
            if (
                self.max_attempts_per_root_cause
                and attempts.get(key, 0) >= self.max_attempts_per_root_cause
            ):
                exhausted.append(case)
            elif history.get(key, 0) >= self.root_cause_min_occurrences:
                selected.append(case)
            else:
                sporadic.append(case)
        return {
            "selected": selected,
            "inferred_cases_excluded": inferred_excluded,
            "already_attempted": already_attempted,
            "sporadic_cases_deferred": len(sporadic),
            "exhausted_root_causes": len(exhausted),
            "deferred_root_causes": sorted({describe(case) for case in sporadic}),
            "exhausted_root_cause_names": sorted({describe(case) for case in exhausted}),
            "root_cause_min_occurrences": self.root_cause_min_occurrences,
        }

    def _triage_summary(self, triage: Dict[str, Any]) -> Dict[str, Any]:
        """triage 里适合放进 auto_propose 返回值的那部分。"""
        return {
            key: value for key, value in triage.items() if key != "selected"
        }

    def auto_propose(
        self, skill_name: str = "llm-review", tenant_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        all_cases = self.store.list_failure_cases(True, 100, tenant_id)
        triage = self._select_cases(skill_name, all_cases)
        cases = triage["selected"]
        summary = self._triage_summary(triage)
        excluded = triage["inferred_cases_excluded"]
        active = self.store.get_active_skill_version(skill_name)
        # 选亲（DGM 的档案 + GEPA 的逐样本前沿）。种子取本轮要学的根因指纹，
        # 所以同一批反馈永远选出同一个亲本——选亲结果影响候选内容，而候选
        # 内容进落盘记录，用真随机源会让"这次为什么产出了这个候选"再也无法
        # 复现。
        seed = "|".join(sorted(fingerprint_case(case) for case in cases))
        parent = self.select_parent(skill_name, seed=seed) if cases else None
        if parent is not None:
            base = parent["prompt"] or DEFAULT_PROMPT
            parent_version = parent["version"]
            parent_selection = dict(parent["selection"])
            parent_selection["parent_version"] = parent_version
        else:
            # 档案为空（第一轮，还没有任何版本）。
            base = active["prompt"] if active else DEFAULT_PROMPT
            parent_version = active["version"] if active else None
            parent_selection = {
                "strategy": self.parent_strategy, "resolved": "empty_archive",
                "fell_back_from": "", "parent_version": parent_version,
            }
        if self.candidate_generator is not None and cases:
            generated = self._generate_candidate(skill_name, cases, base)
            generated["parent_selection"] = parent_selection
            candidate = generated["candidate_prompt"]
            if candidate.strip() == base.strip():
                # 记账。生成器看过这批反馈、判断无需改提示词，这是一个
                # 真实的判决，不是"没发生"。不记的话下一轮会重跑同一次
                # LLM 调用，得到同一个结论。
                #
                # 注意这一支**该**消费，虽然它同样没跑评测：判决是生成器
                # 对着这批反馈下的。`_verdict_is_about_the_feedback` 只
                # 管 `_propose` 那条路——那里的中止（safety / 数据集不足）
                # 才是与反馈无关的。两者的区别不是"跑没跑评测"，是
                # "有没有人对着这批反馈做出判断"。
                self._record_attempts(
                    None, skill_name, "deferred",
                    "root-cause analysis produced no prompt change", None, cases,
                )
                return {
                    "version": None, "decision": "deferred",
                    "reason": "root-cause analysis produced no prompt change",
                    "candidate_change": generated,
                    "failure_cases_used": len(cases),
                    "inferred_cases_excluded": excluded,
                    "triage": summary,
                    "feedback_consumed": True,
                    "parent_selection": parent_selection, "run_id": None,
                }
            result = self._propose(
                skill_name, candidate, None, activation_policy="shadow",
                parent_version=parent_version,
            )
            result["candidate_change"] = generated
            result["parent_selection"] = parent_selection
            result["failure_cases_used"] = len(cases)
            result["inferred_cases_excluded"] = excluded
            result["triage"] = summary
            result["rollback_point"] = (
                {"skill_name": skill_name, "version": active["version"]}
                if active else None
            )
            result["evaluation_data"] = {
                "validation_sha256": self.status()["validation_dataset_fingerprint"],
                "holdout_sha256": self.status()["holdout_dataset_fingerprint"],
            }
            # 只有真进了评测的轮次才记消费，见
            # `_verdict_is_about_the_feedback`。被 safety / 评测集不足 /
            # 无 provider 拦在评测之前的轮次，判决与这批反馈无关，记进去
            # 就等于把反馈烧在一个跟它无关的缺陷上。
            result["feedback_consumed"] = self._verdict_is_about_the_feedback(result)
            if result["feedback_consumed"]:
                self._record_attempts(
                    result.get("run_id"), skill_name, result["decision"],
                    result.get("reason", ""),
                    (result.get("version") or {}).get("version"), cases,
                )
            if result.get("run_id"):
                runs = self.store.list_evolution_runs(200)
                run = next((item for item in runs if item["id"] == result["run_id"]), None)
                if run:
                    metrics = dict(run["metrics"])
                    metrics["structured_candidate"] = {
                        "generator": generated["generator"],
                        "failure_cases": generated["failure_cases"],
                        "clusters": generated["clusters"],
                        "change_diff": generated["change_diff"],
                        "candidate": generated["candidate"],
                        "generation_execution": generated["generation"],
                        "parent_selection": parent_selection,
                        "evaluation_data": result["evaluation_data"],
                        "rollback_point": result["rollback_point"],
                        "source_code_changes_allowed": False,
                    }
                    self.store.update_evolution_run(
                        result["run_id"], result["decision"], metrics
                    )
            return result
        counts = {}
        for case in cases:
            counts[case["category"]] = counts.get(case["category"], 0) + 1
        directives = []
        if counts.get("false_positive"):
            directives.append("Avoid style-only findings and require direct evidence from an added line.")
        if counts.get("missed_issue"):
            directives.append("Check boundary conditions, authorization, input validation and error paths explicitly.")
        if counts.get("bad_fix"):
            directives.append("Propose minimal fixes that preserve behavior and always include a regression test.")
        # 这里曾经有一条 `execution_error` 的 directive（"Keep output valid
        # JSON..."）。`cases` 是 `_select_cases` 过滤后的结果，而
        # `execution_error` 已不在 `HUMAN_CONFIRMED_CATEGORIES` 里（理由见那
        # 里），所以那个 counts 键永远为空，条件永远不成立。删掉而不是留着：
        # 一条不可达的分支会让后来的人以为执行错误仍在驱动提示词，从而在排查
        # "崩溃为什么没改进提示词"时找错方向。
        # A missed-issue feedback item may carry the reviewer rule identifier that a
        # human confirmed.  Preserve that signal in the prompt without accepting
        # arbitrary feedback text as an instruction.  The bracketed marker is both
        # human-readable to an LLM and machine-auditable in offline replay.
        learned_rule_ids = sorted({
            str((case.get("payload", {}).get("finding") or {}).get("rule_id", "")).strip()
            for case in cases
            if case.get("category") == "missed_issue"
        })
        learned_rule_ids = [
            rule_id for rule_id in learned_rule_ids
            if self.FEEDBACK_RULE_ID.fullmatch(rule_id)
        ]
        directives.extend(
            "Explicitly check added lines for confirmed rule %s [focus-rule:%s]."
            % (rule_id, rule_id)
            for rule_id in learned_rule_ids
        )
        # 带 rule_id 的规则走 delta 合并，通用指令走 unstructured。两者的
        # 区别是**有没有稳定身份**：规则能按 rule_id 认出同一条，通用指令
        # 只能按正文比对，正文一改就变成"删一条加一条"。
        generic = [
            directive for directive in directives
            if directive.lower() not in base.lower()
        ]
        lifted = entries_from_prompt(base)
        known = {str(entry["rule_id"]) for entry in lifted["entries"]}
        delta = [
            {
                "op": "add",
                "rule_id": rule_id,
                "text": "Explicitly check added lines for confirmed rule %s "
                        "[focus-rule:%s]." % (rule_id, rule_id),
            }
            for rule_id in learned_rule_ids if rule_id not in known
        ]
        merged = apply_delta(lifted["entries"], delta)
        additions = generic + merged["applied"]
        if not additions:
            # 同上：delta 合并对着这批反馈得出"没有可支持的新信号"，
            # 也是一次真实判决，该消费。
            self._record_attempts(
                None, skill_name, "deferred",
                "no new supported learning signal was found in unresolved feedback",
                None, cases,
            )
            return {
                "version": None,
                "decision": "deferred",
                "reason": "no new supported learning signal was found in unresolved feedback",
                "candidate": self._empty_metrics(0),
                "baseline": self._empty_metrics(0),
                "candidate_holdout": self._empty_metrics(0),
                "baseline_holdout": self._empty_metrics(0),
                "safety": self.safety_evaluate(base),
                "run_id": None,
                "failure_cases_used": len(cases),
                "inferred_cases_excluded": excluded,
                "triage": summary,
                "feedback_consumed": True,
                "parent_selection": parent_selection,
                "learned_categories": counts,
            }
        candidate = compose_prompt(
            lifted["body"],
            merged["entries"],
            list(lifted["unstructured"]) + generic,
        )
        result = self.propose(skill_name, candidate, parent_version=parent_version)
        result["failure_cases_used"] = len(cases)
        result["inferred_cases_excluded"] = excluded
        result["triage"] = summary
        result["parent_selection"] = parent_selection
        result["learned_categories"] = counts
        result["learned_rule_ids"] = learned_rule_ids
        # 同上：与反馈无关的中止不消费反馈。
        result["feedback_consumed"] = self._verdict_is_about_the_feedback(result)
        if result["feedback_consumed"]:
            self._record_attempts(
                result.get("run_id"), skill_name, result["decision"],
                result.get("reason", ""),
                (result.get("version") or {}).get("version"), cases,
            )
        if result["decision"] == "activated":
            self.store.resolve_failure_cases([case["id"] for case in cases])
        return result

    def _prior_attempts(self, skill_name: str, cases: List[dict]) -> List[Dict[str, Any]]:
        """这些根因过去被尝试过什么、门禁怎么判的。

        喂回生成器，让它知道自己上一轮失败在哪。没有这个信号，生成器对
        自己的历史一无所知，会反复提出等价的修改——GEPA
        （arXiv:2507.19457）的核心观察正是：把判决以自然语言反馈回生成
        器，信息量远大于只给一个标量分数。

        只回传与**本轮根因相关**的尝试，不是全部历史：无关根因的失败记录
        挤占 token 预算，且容易被模型误读成"这个方向也别碰"。
        """
        keys = {fingerprint_case(case) for case in cases}
        prior = []
        for row in self.store.list_evolution_attempts(skill_name, 200):
            if row.get("fingerprint") not in keys:
                continue
            prior.append({
                "root_cause_fingerprint": row.get("fingerprint"),
                "decision": row.get("decision"),
                "reason": row.get("reason"),
                "candidate_version": row.get("candidate_version"),
            })
        return prior

    def _generate_candidate(
        self, skill_name: str, cases: List[dict], base: str,
    ) -> Dict[str, Any]:
        """调生成器，尽力把过往尝试一起传进去。

        `candidate_generator` 是一个注入点，第三方实现可能只接受
        `(failures, base_prompt)` 两个参数。所以这里对 TypeError 退化到
        旧签名，而不是硬要求所有实现都跟着改——但退化时会在返回值里标明
        这一轮**没有**反思信号，避免事后把"生成器不支持"读成"有历史但
        模型没利用"。
        """
        attempts = self._prior_attempts(skill_name, cases)
        try:
            return self.candidate_generator.generate(cases, base, attempts=attempts)
        except TypeError:
            generated = self.candidate_generator.generate(cases, base)
            generated.setdefault("prior_attempts", [])
            generated["prior_attempts_unsupported"] = bool(attempts)
            return generated

    @staticmethod
    def _verdict_is_about_the_feedback(result: Dict[str, Any]) -> bool:
        """这一轮的判决，是对这批反馈本身下的，还是被无关缺陷打断的？

        只有前者该计入消费账本。判据用现成的 `gates.evaluation_success`
        三态：

        - **不是 None** —— 候选真的跑完了基线与候选的全量回放。无论最后
          是 activated 还是 rejected，门禁都是在回答"照这批反馈改出来的
          提示词，好不好"。这是一次针对反馈的真实判决，该消费。
        - **是 None** —— 压根没跑到评测。safety 门禁拒了、评测集不够大、
          没配 LLM provider、候选与 active 逐字相同……这些失败**与反馈的
          内容无关**，反馈没有得到任何检验。

        第 16.6 节记的就是后者：一个 `bypass` 门禁缺陷把候选拒在评测之
        前，20 条反馈却被一次性记进账本，第二轮 `_select_cases` 直接返回
        空。回路 A 就是这么断的——不是数据不够，是记账把它烧了。

        不写账本不会丢审计线索：走到这一支的轮次全都产出了一条
        `evolution_runs` 记录，中止原因连同完整 gates 都在那里。
        """
        gates = result.get("gates") or {}
        return gates.get("evaluation_success") is not None

    def _record_attempts(
        self, run_id: Optional[str], skill_name: str, decision: str, reason: str,
        candidate_version: Optional[int], cases: List[dict],
    ) -> None:
        """把这批 case 记进消费账本。

        `run_id` 可能为 None——生成器判断"无需改提示词"时根本不会产生
        一次 evolution_run。仍然要记：那也是一次真实的尝试，花了一次 LLM
        调用，得出了一个结论。用 `no-run:<uuid>` 占位而不是空串，这样
        `count_attempts_by_fingerprint` 的 `COUNT(DISTINCT run_id)` 能把
        多次无 run 的尝试数成多次，而不是全部折叠成一次。

        **调用方负责先判断这一轮该不该消费**，见
        `_verdict_is_about_the_feedback`。这里不自己判：两个"生成器认为
        无需改动"的调用点根本没有 result 可查，而它们恰恰是该消费的。
        """
        if not cases:
            return
        self.store.record_evolution_attempts(
            run_id or ("no-run:%s" % uuid.uuid4()), skill_name, decision, reason,
            candidate_version,
            [(int(case["id"]), fingerprint_case(case)) for case in cases],
        )

    @staticmethod
    def _empty_metrics(case_count: int) -> Dict[str, Any]:
        return {
            "schema_version": 2,
            "reviewer": "",
            "score": 0.0, "precision": 0.0, "recall": 0.0, "f1": 0.0,
            "severity_accuracy": 0.0, "high_severity_recall": 0.0, "clean_accuracy": 0.0,
            # 空指标里区间是 None 而不是 [0,0]：没跑过评测就没有区间，
            # [0.0, 0.0] 会被读成"测过了，确信是 0"。
            "precision_ci": None, "recall_ci": None, "severity_accuracy_ci": None,
            "high_severity_recall_ci": None, "clean_accuracy_ci": None,
            "cases": case_count, "matched": 0, "severity_hits": 0,
            "positive_cases": 0, "clean_cases": 0,
            "expected_findings": 0, "predicted_findings": 0,
            "successful_cases": 0, "success_rate": 0.0, "errors": [], "case_results": [],
        }

    def _protected_metrics(self, baseline: Dict[str, Any]) -> List[str]:
        protected = ["score", "precision", "recall", "high_severity_recall"]
        if baseline.get("positive_cases", 0):
            protected.append("severity_accuracy")
        if baseline.get("clean_cases", 0):
            protected.append("clean_accuracy")
        return protected

    def _non_regression_report(
        self, candidate: Dict[str, Any], baseline: Dict[str, Any],
    ) -> Dict[str, Any]:
        """未回退判定 + **哪几项其实没测**。

        判定方向一个字没改：`_metric_non_regressing` 在 baseline 为 None 时
        放行（本来就没测过，无从回退）。问题在报告——holdout 里 0 条
        high/critical 样本，`high_severity_recall` 恒为 None vs None，于是
        这道受保护指标恒不退化、恒通过。报告上看着有四道受保护指标，实际
        只有三道在工作，而 `passed: true` 与真的没退化长得一模一样。

        这与 `completeness` 恒 1.0、"低分歧率当通过条件"是同一类错误：
        **一道假装在工作的门禁，比一个缺失的门禁更危险**——前者会让人以为
        已经被保护了。

        所以这里只做一件事：把 baseline 侧无定义的指标列进 `unmeasurable`。
        不改放行与否，只让报告分得出"没退化"和"测不出来"。与
        `evaluation_v2._unmeasurable`、`comparison_summary` 的
        `not_applicable_gates` 是同一条纪律。
        """
        protected = self._protected_metrics(baseline)
        verdicts = {
            metric: _metric_non_regressing(
                candidate.get(metric), baseline.get(metric),
                self.max_metric_regression,
            )
            for metric in protected
        }
        # severity_accuracy 的分母由候选自己决定，得单独判。见该方法的文档。
        incomparable = []
        if "severity_accuracy" in protected:
            verdict, note = self._severity_accuracy_verdict(candidate, baseline)
            verdicts["severity_accuracy"] = verdict
            if note:
                incomparable.append(note)
        return {
            "passed": all(verdicts.values()),
            "protected": protected,
            "regressed": sorted(
                name for name, ok in verdicts.items() if not ok
            ),
            # baseline 侧无定义 = 这一档根本没样本，判定是靠"无从回退"放行的，
            # 不是靠"确实没退化"。分母口径不同的 severity_accuracy 也进这里：
            # 它同样是"这道门禁这次没验证到什么"，不能与"验证了，没退化"混同。
            "unmeasurable": sorted(
                [metric for metric in protected if baseline.get(metric) is None]
                + incomparable
            ),
        }

    def _severity_accuracy_verdict(
        self, candidate: Dict[str, Any], baseline: Dict[str, Any],
    ) -> Tuple[bool, str]:
        """severity_accuracy 的未回退判定：分母不同就不比比值。

        `severity_accuracy = severity_hits / matched`，而 `matched` 是候选
        **自己挣来的**——多匹配上一条真缺陷，分母就大一格。于是一个把召回
        从 0.67 提到 1.0 的候选，只要新抓到的那条严重度判低了，比值就从
        2/2=1.0 掉到 2/3=0.67，被这道门禁判为"回退"。

        它没有把任何一条原本判对的判错。**这道门禁惩罚的是召回率提升**，
        这正好是进化最该鼓励的方向，也是本仓库反复出现的那类错误的又一
        变体：一道看着在保护质量、实际在保护现状的门禁。

        所以分母不同时不比比值，改比绝对的 `severity_hits`：没有哪条原本
        判对严重度的变判错，就不算回退。同时把这一项列进 `unmeasurable`
        ——比值这次确实没验证，报告里不能显示成"验证了，没退化"。

        分母相同时（候选与 baseline 匹配上同样多的缺陷）比值可比，照常比。
        """
        base_matched = baseline.get("matched")
        cand_matched = candidate.get("matched")
        # 老 run 的 metrics 里没有 matched（schema 早于本次改动），此时无从
        # 判断可比性，退回原来的比值判定，不悄悄放宽。
        if base_matched is None or cand_matched is None or base_matched == cand_matched:
            return _metric_non_regressing(
                candidate.get("severity_accuracy"),
                baseline.get("severity_accuracy"),
                self.max_metric_regression,
            ), ""
        base_hits = int(baseline.get("severity_hits") or 0)
        cand_hits = int(candidate.get("severity_hits") or 0)
        return cand_hits >= base_hits, "severity_accuracy"

    def _non_regressing(self, candidate: Dict[str, Any], baseline: Dict[str, Any]) -> bool:
        return self._non_regression_report(candidate, baseline)["passed"]

    @staticmethod
    def _significance_report(
        candidate: Dict[str, Any], baseline: Dict[str, Any],
    ) -> Optional[bool]:
        """候选与 baseline 的差异是否统计显著（Track E，**纯报告项**）。

        刻意不接入门禁：现有阈值判断已经跑过一段时间、行为可预期，直接改成
        显著性判断会让大量原本能通过的候选突然被拦。这个变化要先观察一段
        时间的报告数据再决定要不要真接入，不能一步到位改变生产行为。所以
        `gates["significant"]` 只进 gates 字典展示，`decision` 的
        rejected/activated 计算完全不看它——见 propose() 里的
        `if no_errors and improved and validation_safe and holdout_safe`。

        三态：True = 至少一个受保护指标的区间与 baseline 不重叠；
        False = 都重叠（涨跌可能只是噪声）；None = 一个区间都算不出来
        （没样本），此时"显著与否"根本无从判断，不能塞成 False——那会把
        "没测"伪装成"测了，不显著"。
        """
        metrics = ("precision", "recall", "high_severity_recall",
                   "severity_accuracy", "clean_accuracy")
        verdicts = [
            _intervals_disjoint(
                candidate.get(name + "_ci"), baseline.get(name + "_ci"))
            for name in metrics
        ]
        comparable = [item for item in verdicts if item is not None]
        if not comparable:
            return None
        return any(comparable)

    @staticmethod
    def _redact_holdout_metrics(metrics: Dict[str, Any]) -> Dict[str, Any]:
        redacted = {
            key: value for key, value in metrics.items()
            if key not in {"errors", "case_results"}
        }
        redacted["error_count"] = len(metrics.get("errors", []))
        return redacted

    @staticmethod
    def _sha256(value: str) -> str:
        return hashlib.sha256(value.encode("utf-8")).hexdigest()

    @classmethod
    def _dataset_fingerprint(cls, cases: List[dict]) -> str:
        canonical = [
            {
                "name": case.get("name"),
                "split": case.get("split"),
                "diff": case.get("diff"),
                "expected": case.get("expected", []),
            }
            for case in cases
        ]
        payload = json.dumps(canonical, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        return cls._sha256(payload)
