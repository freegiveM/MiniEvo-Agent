"""Fair product-backed ablation suite for labelled PRs."""
from collections import Counter
import random
import time
from typing import Any, Callable, Dict, List, Mapping, Optional

from .agentic_core import ModeRouterReviewer
from .evaluation_benchmark import ContextRuleReviewer
from .evaluation_harness import (
    MATCH_TIERS,
    EndToEndEvaluationHarness,
    dataset_fingerprint,
    one_to_one_match,
    tiered_match,
)
from .llm import JsonChatClient


REQUIRED_ARMS = (
    "rules-only", "single-llm", "multi-llm-no-critic", "full-agentic",
)

ARM_TOPOLOGY = {
    "rules-only": {
        "mode": "rules-only", "roles": (),
    },
    "single-llm": {
        "mode": "hybrid", "roles": ("hybrid-reviewer",),
    },
    "multi-llm-no-critic": {
        "mode": "agentic",
        "roles": ("planner", "security", "correctness-reliability"),
    },
    "full-agentic": {
        "mode": "agentic",
        "roles": ("planner", "security", "correctness-reliability", "critic"),
    },
}


def validate_real_dataset(cases: List[dict], minimum_cases: int = 300) -> Dict[str, Any]:
    repositories_by_split = {}
    source_kinds = set()
    for case in cases:
        split = str(case.get("split", ""))
        if split not in {"train", "validation", "holdout"}:
            raise ValueError("every case must use train, validation or holdout split")
        repositories_by_split.setdefault(split, set()).add(str(case.get("repository", "")))
        source_kinds.add(str((case.get("source") or {}).get("kind", "unknown")))
        if not isinstance(case.get("expected_findings"), list):
            raise ValueError("every real PR must include human expected_findings")
        for finding in case["expected_findings"]:
            if "should_comment" not in finding:
                raise ValueError("human labels must include should_comment")
            if not all(key in finding for key in ("severity", "path")):
                raise ValueError("human labels require severity and path")
    overlaps = {}
    splits = sorted(repositories_by_split)
    for index, left in enumerate(splits):
        for right in splits[index + 1:]:
            shared = repositories_by_split[left].intersection(repositories_by_split[right])
            if shared:
                overlaps["%s:%s" % (left, right)] = sorted(shared)
    public_or_historical = source_kinds.issubset({
        "public-github-pr", "private-historical-pr",
    }) and bool(source_kinds)
    gates = {
        "minimum_300_cases": len(cases) >= minimum_cases,
        "real_provenance": public_or_historical,
        "repository_isolation": not overlaps,
        "train_present": bool(repositories_by_split.get("train")),
        "validation_present": bool(repositories_by_split.get("validation")),
        "hidden_holdout_present": bool(repositories_by_split.get("holdout")),
    }
    return {
        "ready": all(gates.values()), "gates": gates, "cases": len(cases),
        "repositories": len({str(case.get("repository")) for case in cases}),
        "repositories_by_split": {
            key: len(value) for key, value in repositories_by_split.items()
        },
        "repository_overlap": overlaps, "source_kinds": sorted(source_kinds),
        "dataset_sha256": dataset_fingerprint(cases),
    }


def _delta_or_none(candidate, baseline):
    """Difference of two metrics, or None when either side is undefined."""
    if candidate is None or baseline is None:
        return None
    return round(float(candidate) - float(baseline), 4)


def _not_worse(candidate, baseline) -> bool:
    """True when candidate is no worse than baseline on a lower-is-better metric.

    任一侧为 None 时返回 False：无法验证不退化，就不能当成没退化。
    """
    if candidate is None or baseline is None:
        return False
    return float(candidate) <= float(baseline)


def _ci_lower_positive(entry: dict) -> bool:
    """True only when the CI is present and its lower bound is above zero.

    CI 缺失（分母为零导致无可用重采样）时返回 False——**不能**当成显著。
    没有区间就没有显著性，这一点不该靠调用方记得去判空。
    """
    bounds = (entry or {}).get("ci95") or [None, None]
    return bounds[0] is not None and bounds[0] > 0


def _role_costs(model_call_log: List[dict]) -> Dict[str, Dict[str, int]]:
    """Aggregate real per-role token and latency cost from the ledger.

    ## 为什么要按角色拆，而不是只报每 PR 总量

    "多角色更贵"是消融必须量化的代价——臂 C/D 相对臂 B 的 f1 提升，要放在
    成本增量旁边才有意义。但原实现只用 Counter 数了每个角色**调用了几次**：

        result["model_roles"] = dict(Counter(str(item.get("role")) for item in ...))

    而 model_call_log 每条都带 input_tokens / output_tokens / duration_ms。
    调用次数不能代替成本：planner 输出一个 task_graph 与 critic 逐条评审
    全部候选，调用次数都是 1，token 量差一个量级。只报次数会让"哪个角色贵"
    这个问题无法回答，也就无法讨论"砍掉哪个角色最划算"。

    ## 两个刻意的选择

    - **失败调用照样计入 token 与延迟。** 失败的调用同样烧钱、同样占用墙上
      时间；把它排除会低估真实成本。`failed` 单独计数，这样"贵"与"白花"
      能分开看。
    - **duration_ms 逐调用相加，不等于 PR 墙上时间。** 角色之间可能并行，
      相加会高于实际耗时。所以这里叫 duration_ms 而非 latency_ms：它衡量
      "占用了多少模型时间"（成本口径），PR 端到端延迟另有
      execution.duration_ms（体验口径）。两者混用会得出矛盾的结论。
    """
    totals: Dict[str, Dict[str, int]] = {}
    for item in model_call_log:
        role = str(item.get("role"))
        bucket = totals.setdefault(role, {
            "calls": 0, "failed": 0, "input_tokens": 0,
            "output_tokens": 0, "total_tokens": 0, "duration_ms": 0,
        })
        bucket["calls"] += 1
        bucket["failed"] += int(not bool(item.get("ok", True)))
        input_tokens = int(item.get("input_tokens", 0) or 0)
        output_tokens = int(item.get("output_tokens", 0) or 0)
        bucket["input_tokens"] += input_tokens
        bucket["output_tokens"] += output_tokens
        bucket["total_tokens"] += input_tokens + output_tokens
        bucket["duration_ms"] += int(item.get("duration_ms", 0) or 0)
    return dict(sorted(totals.items()))


def _role_cost_totals(case_results: List[dict], cases: int) -> Dict[str, dict]:
    """Sum per-role costs across cases and report per-PR averages.

    分母用**这一臂跑过的 PR 总数**，不是"该角色被调用过的 PR 数"。理由：
    "critic 平均每个 PR 花多少 token"里，没有触发 critic 的 PR 花的是 0，
    那也是真实成本的一部分。按"被调用过的 PR"做分母会系统性高估单角色成本，
    并且让不同角色的分母不一样、无法横向相加对照。

    cases 为 0 时返回空字典而不是造零——与 _metrics 的空分母口径一致。
    """
    if not cases:
        return {}
    totals: Dict[str, Dict[str, int]] = {}
    for case in case_results:
        for role, values in (case.get("role_costs") or {}).items():
            bucket = totals.setdefault(role, {
                "calls": 0, "failed": 0, "input_tokens": 0,
                "output_tokens": 0, "total_tokens": 0, "duration_ms": 0,
            })
            for key, value in values.items():
                bucket[key] = bucket.get(key, 0) + int(value)
    report = {}
    for role, values in sorted(totals.items()):
        report[role] = dict(values)
        report[role]["tokens_per_pr"] = round(values["total_tokens"] / cases, 2)
        report[role]["duration_ms_per_pr"] = round(values["duration_ms"] / cases, 2)
    return report


class _EvaluationTaskStore:
    """Minimal task input provider used by ModeRouterReviewer during replay."""

    def __init__(self, task_input: dict):
        self.task_input = dict(task_input)

    def get(self, _task_id: str, _tenant_id: Optional[str] = None) -> dict:
        return {"input": dict(self.task_input)}


class ProductArmReviewer:
    """Run one ablation arm through the product ModeRouterReviewer."""

    def __init__(
        self, arm: str, client: JsonChatClient, total_token_budget: int,
        total_time_budget_seconds: int = 120,
        critic_position_check: bool = False,
    ):
        if arm not in ARM_TOPOLOGY:
            raise ValueError("unknown evaluation arm: %s" % arm)
        topology = ARM_TOPOLOGY[arm]
        roles = tuple(topology["roles"])
        llm_role_count = max(1, len(roles))
        if arm != "rules-only" and total_token_budget < 256 * llm_role_count:
            raise ValueError(
                "%s requires at least %d total tokens" % (arm, 256 * llm_role_count)
            )
        if total_time_budget_seconds < llm_role_count:
            raise ValueError("total_time_budget_seconds is too small for %s" % arm)
        per_role_tokens = max(256, total_token_budget // llm_role_count)
        per_role_seconds = max(1, total_time_budget_seconds // llm_role_count)
        enabled = {
            item for item in roles if item != "hybrid-reviewer"
        }
        task_input = {
            "mode": topology["mode"],
            "enabled_agents": sorted(enabled),
        }
        self.arm = arm
        self.name = arm
        self.client = client
        self.total_token_budget = int(total_token_budget)
        self.total_time_budget_seconds = int(total_time_budget_seconds)
        self.per_role_token_budget = per_role_tokens
        self.per_role_time_budget_seconds = per_role_seconds
        self.expected_roles = roles
        self.store = _EvaluationTaskStore(task_input)
        # LocalRuleReviewer contributes six rules. ContextRuleReviewer contributes
        # the same eight supplemental rules to every arm, for exactly 14 total.
        self.router = ModeRouterReviewer(
            self.store, client,
            default_token_budget=per_role_tokens,
            default_time_budget=per_role_seconds,
            enabled_roles=enabled,
            scanners=[ContextRuleReviewer()],
            critic_position_check=bool(critic_position_check),
        )
        self._sequence = 0
        self._last_summary: Dict[str, Any] = {}

    def review(self, diff: str, parsed) -> list:
        return self.review_case({"diff": diff, "repository": ""}, parsed)

    def review_case(self, case: dict, parsed) -> list:
        self._sequence += 1
        task_id = "evaluation:%s:%d" % (self.arm, self._sequence)
        repository_root = str(case.get("repository_root") or "")
        findings = self.router.review_with_context(
            task_id, case["diff"], parsed,
            repository=repository_root or str(case.get("repository") or ""),
        )
        self._last_summary = self.router.collaboration_summary(task_id)
        self._validate_execution()
        return findings

    def _validate_execution(self) -> None:
        execution = self._last_summary.get("execution") or {}
        calls = execution.get("model_call_log") or []
        actual = Counter(
            str(item.get("role")) for item in calls if bool(item.get("ok", True))
        )
        if self.arm == "rules-only":
            if calls:
                raise RuntimeError("rules-only arm made an LLM call")
            return
        required = set(self.expected_roles)
        if self.arm == "full-agentic":
            collaboration = self._last_summary.get("collaboration") or {}
            proposed = int(
                collaboration.get("candidate_findings_before_critic", 0) or 0
            )
            if proposed == 0:
                required.discard("critic")
        missing = sorted(role for role in required if actual[role] < 1)
        if missing:
            raise RuntimeError(
                "%s completed without successful LLM role(s): %s"
                % (self.arm, ", ".join(missing))
            )

    def evaluation_execution(self) -> dict:
        return dict(self._last_summary.get("execution") or {})

    def evaluation_config(self) -> dict:
        return {
            "arm": self.arm,
            "mode": ARM_TOPOLOGY[self.arm]["mode"],
            "roles": list(self.expected_roles),
            "deterministic_rules": 14,
            "total_token_budget_per_pr": self.total_token_budget,
            "per_role_token_budget": self.per_role_token_budget,
            "total_time_budget_seconds_per_pr": self.total_time_budget_seconds,
            "per_role_time_budget_seconds": self.per_role_time_budget_seconds,
        }


def product_reviewer_factories(
    client: JsonChatClient, total_time_budget_seconds: int = 120,
    critic_position_check: bool = False,
) -> Dict[str, Callable[[str, int], ProductArmReviewer]]:
    """Create all four arms with one model client and a shared total budget.

    `critic_position_check` 默认关：打开会让 critic 的调用与 token 翻倍。
    想报 critic 的位置稳定性时显式打开，并且要意识到此时臂 D 的成本数字
    包含了复核那一次——报成本和报稳定性不能用同一次运行的数字。
    """

    def build(arm: str, model: str, token_budget: int) -> ProductArmReviewer:
        if str(client.model) != str(model):
            raise ValueError(
                "evaluation model %s does not match client model %s"
                % (model, client.model)
            )
        return ProductArmReviewer(
            arm, client, token_budget, total_time_budget_seconds,
            critic_position_check=critic_position_check,
        )

    return {
        arm: (
            lambda model, budget, selected=arm: build(selected, model, budget)
        )
        for arm in REQUIRED_ARMS
    }


class ProductionEvaluationHarness(EndToEndEvaluationHarness):
    def _run_case(self, reviewer, case):
        class RecordingReviewer:
            def __init__(self, delegate):
                self.delegate = delegate
                self.name = delegate.name
                self.findings = []

            def review(self, diff, parsed):
                self.findings = self.delegate.review(diff, parsed)
                return self.findings

            def review_case(self, case, parsed):
                method = getattr(self.delegate, "review_case", None)
                self.findings = (
                    method(case, parsed)
                    if method else self.delegate.review(case["diff"], parsed)
                )
                return self.findings

        recording = RecordingReviewer(reviewer)
        started = time.monotonic()
        result = super()._run_case(recording, case)
        result.update({
            # 口径纪律：这个数是"落在标注之外的 finding 条数"，**不是误报数**。
            # 数据集只标注了反转出来的那个种子缺陷，仓库里可能真有别的问题，
            # reviewer 指出它们是对的。字段名保留 invalid_comments 是因为外部
            # 报告已在读它（改名等于无声破坏），但语义以 unlabelled 为准，
            # 且按最宽的 location 档计算——见下方 tiered_match 调用。
            "invalid_comments": result["fp"],
            "unlabelled": result["fp"],
            "tier_tp": {tier: 0 for tier in MATCH_TIERS},
            "tier_fn": {tier: len([
                item for item in case["expected_findings"]
                if bool(item.get("should_comment", True))
            ]) for tier in MATCH_TIERS},
            "exact_location_hits": 0,
            "evidence_hits": 0,
            "accepted_comments": int(case.get("accepted_comments", 0) or 0),
            "closed_comments": int(case.get("closed_comments", 0) or 0),
            "cost_usd": 0.0,
            "latency_ms": int((time.monotonic() - started) * 1000),
            "llm_calls": 0,
            "input_tokens": 0,
            "output_tokens": 0,
            "total_tokens": 0,
            "model_roles": {},
            "role_costs": {},
        })
        if result["execution_success"]:
            findings = recording.findings
            expected = [
                item for item in case["expected_findings"]
                if bool(item.get("should_comment", True))
            ]
            # 三档命中同时累计。基类只算了默认的 cwe-exact 档，那一档会把
            # 兄弟 CWE（CWE-78 vs CWE-95，同属 CWE-74）判成漏报——测的是
            # "标注者和 reviewer 选了同一个兄弟"，不是"reviewer 是否发现了
            # 缺陷"。三档分别回答：指对行了吗 / 认出类别了吗 / CWE 号一致吗。
            tiers = tiered_match(expected, findings, self.line_tolerance)
            for tier in MATCH_TIERS:
                result["tier_tp"][tier] = tiers[tier]["tp"]
                result["tier_fn"][tier] = tiers[tier]["fn"]
            # 标注外条数按最宽的 location 档算：一个 finding 只要指对了行，
            # 就不该被算成"标注外"，即使它把类别判错了。按严格档算会虚增
            # 噪声量——那会让"归类错了"和"完全报错了"变成同一个数字。
            result["unlabelled"] = tiers["unlabelled"]["count"]
            result["invalid_comments"] = result["unlabelled"]
            matches = one_to_one_match(
                expected, findings, self.line_tolerance
            )
            for match in matches:
                finding = findings[match.predicted_index]
                result["exact_location_hits"] += int(match.location_distance == 0)
                result["evidence_hits"] += int(bool(
                    finding.evidence_refs or finding.call_chain or finding.evidence.strip()
                ))
            summary_reader = getattr(reviewer, "evaluation_execution", None)
            if summary_reader:
                execution = summary_reader() or {}
                result["cost_usd"] = float(execution.get("cost_usd", 0) or 0)
                result["latency_ms"] = int(execution.get("duration_ms", result["latency_ms"]))
                result["llm_calls"] = int(execution.get("llm_calls", 0) or 0)
                result["input_tokens"] = int(execution.get("input_tokens", 0) or 0)
                result["output_tokens"] = int(execution.get("output_tokens", 0) or 0)
                result["total_tokens"] = int(execution.get("total_tokens", 0) or 0)
                result["model_roles"] = dict(Counter(
                    str(item.get("role"))
                    for item in execution.get("model_call_log") or []
                ))
                result["role_costs"] = _role_costs(
                    execution.get("model_call_log") or []
                )
        return result

    @staticmethod
    def _empty_totals():
        values = EndToEndEvaluationHarness._empty_totals()
        values.update({
            "invalid_comments": 0, "exact_location_hits": 0, "evidence_hits": 0,
            "accepted_comments": 0, "closed_comments": 0,
            "latency_ms": 0, "cost_microusd": 0,
            "llm_calls": 0, "input_tokens": 0,
            "output_tokens": 0, "total_tokens": 0,
            "unlabelled": 0,
            "tier_tp": {tier: 0 for tier in MATCH_TIERS},
            "tier_fn": {tier: 0 for tier in MATCH_TIERS},
        })
        return values

    @staticmethod
    def _accumulate(totals, result):
        EndToEndEvaluationHarness._accumulate(totals, result)
        for field in (
            "invalid_comments", "exact_location_hits", "evidence_hits",
            "accepted_comments", "closed_comments", "latency_ms",
            "llm_calls", "input_tokens", "output_tokens", "total_tokens",
            "unlabelled",
        ):
            totals[field] += int(result.get(field, 0))
        totals["cost_microusd"] += int(float(result.get("cost_usd", 0)) * 1_000_000)
        for tier in MATCH_TIERS:
            totals["tier_tp"][tier] += int((result.get("tier_tp") or {}).get(tier, 0))
            totals["tier_fn"][tier] += int((result.get("tier_fn") or {}).get(tier, 0))

    @staticmethod
    def _metrics(totals):
        """Extend the base metrics, reporting None for undefined denominators.

        ## 修掉的口径 bug

        原实现 `tp = totals["tp"] or 1`（本文件旧第 311 行）。tp == 0 时分母被
        悄悄换成 1，于是 exact_line_accuracy = 0/1 = 0.0 看起来像一个正常结论。
        但 tp == 0 意味着**一个命中都没有**，"命中里有多少是精确到行的"这个
        比率没有定义。报 0.0 会让人以为"命中了但都没到行"，那是另一回事。

        `cases or 1` 同理：cases == 0 时 failure_rate = 1 - 0/1 = 1.0，
        看起来像"全失败"，实际是"根本没跑"。

        两处都改成分母为零时返回 None，报告渲染成 n/a。
        """
        values = EndToEndEvaluationHarness._metrics(totals)
        cases = totals["cases"]
        tp = totals["tp"]
        commented = totals["accepted_comments"] + totals["closed_comments"]

        def per(numerator, denominator, digits=4):
            return round(numerator / denominator, digits) if denominator else None

        values.update({
            "invalid_comments_per_pr": per(totals["invalid_comments"], cases),
            # 分母是 tp：没有命中就没有"命中的质量"可言。
            "exact_line_accuracy": per(totals["exact_location_hits"], tp),
            "evidence_accuracy": per(totals["evidence_hits"], tp),
            "comment_acceptance_rate": per(totals["accepted_comments"], commented),
            "average_cost_usd_per_pr": per(
                totals["cost_microusd"] / 1_000_000, cases, 8
            ),
            "average_latency_ms_per_pr": per(totals["latency_ms"], cases, 2),
            "average_llm_calls_per_pr": per(totals["llm_calls"], cases),
            "average_input_tokens_per_pr": per(totals["input_tokens"], cases, 2),
            "average_output_tokens_per_pr": per(totals["output_tokens"], cases, 2),
            "average_total_tokens_per_pr": per(totals["total_tokens"], cases, 2),
            "failure_rate": (
                round(1 - totals["execution_successes"] / cases, 4) if cases else None
            ),
            # 每 PR 的标注外条数 = 噪声量。刻意与 invalid_comments_per_pr 同值
            # 而换个名字：后者的字段名会被读成"误报率"，前者不会。真实误报率
            # 要靠人工复核（D5 rubric + 抽样），自动层给不出。
            "unlabelled_per_pr": per(totals["unlabelled"], cases),
        })
        # 三档召回：location（指对行了吗）/ category（认出类别了吗）/
        # cwe-exact（CWE 号一致吗）。分档报而不取一个数，因为"定位对了但归类
        # 错了"和"完全没找到"对系统改进的指示完全不同——前者改 prompt 的分类
        # 部分，后者改扫描覆盖。取一个数会把这两件事压成同一个数字。
        tier_metrics = {}
        for tier in MATCH_TIERS:
            tier_tp = totals["tier_tp"][tier]
            tier_fn = totals["tier_fn"][tier]
            tier_metrics[tier] = {
                "tp": tier_tp,
                "fn": tier_fn,
                # 分母是真值总数。为零时报 None 而非 1.0——没有正样本时
                # "召回率"没有定义，报满分会让一个什么都不报的 reviewer 拿分。
                "recall": per(tier_tp, tier_tp + tier_fn),
            }
        values["by_tier"] = tier_metrics
        return values


class FairAblationSuite:
    """Run all arms with a shared model id and per-PR token budget."""

    def __init__(
        self, reviewer_factories: Mapping[str, Callable[[str, int], Any]],
        model: str, token_budget: int, require_production_ready: bool = True,
        bootstrap_iterations: int = 2000, bootstrap_seed: int = 20260819,
    ):
        missing = set(REQUIRED_ARMS).difference(reviewer_factories)
        if missing:
            raise ValueError("missing ablation arms: %s" % ", ".join(sorted(missing)))
        self.factories = reviewer_factories
        self.model = model
        self.token_budget = token_budget
        self.require_production_ready = bool(require_production_ready)
        self.bootstrap_iterations = max(200, int(bootstrap_iterations))
        self.bootstrap_seed = int(bootstrap_seed)

    @staticmethod
    def _role_totals(case_results: List[dict]) -> dict:
        totals = Counter()
        for case in case_results:
            totals.update(case.get("model_roles") or {})
        return dict(sorted(totals.items()))

    def _paired_bootstrap(
        self, left: dict, right: dict, metrics: tuple, seed_offset: int,
    ) -> dict:
        """Paired bootstrap CI for several metrics over ONE shared resample index.

        ## 改掉的问题：每个 metric 用了不同的重采样

        原实现 `_comparison` 给每个 metric 传 `seed_offset + index`，即
        f1 / precision / recall / high_risk_recall 各自在**不同的重采样**上
        计算 CI。后果是这些 CI 无法联合解读——而 critic_gate 的
        `critic_statistically_positive` 恰恰联合用了 f1 与 precision 两条 CI：

            critic_comparison["f1"]["ci95"][0] > 0
            or (critic_comparison["precision"]["ci95"][0] > 0 and ...)

        两条 CI 来自不同重采样时，这个 or 没有统一的概率解释。

        改为：一次重采样同时算全部 metric。这也是计划里"paired bootstrap，
        共享重采样索引"的本意——四臂跑的是同一批 PR，配对比较必须在同一
        重采样上做，否则比较的一部分方差来自"抽到了不同的 PR"而不是
        "两臂表现不同"。

        ## 空分母的处理

        某次重采样可能抽出一批没有正样本的 PR，此时 metric 为 None
        （见 _metrics 的口径修正）。这些迭代**跳过**而不是当 0 参与：
        当 0 会把"这次抽样无法计算"混进"两臂差为 0"，人为把 CI 往 0 拉，
        使显著性判定偏保守到失真。跳过的次数如实报出来
        （`usable_iterations`），少于总数的一半就说明这个 metric 在
        当前样本量下不该报 CI。
        """
        left_cases = left["case_results"]
        right_cases = right["case_results"]
        if [item["id"] for item in left_cases] != [item["id"] for item in right_cases]:
            raise ValueError("paired comparison requires identical ordered case ids")
        count = len(left_cases)
        empty = {
            metric: {
                "delta": None, "ci95": [None, None],
                "iterations": 0, "usable_iterations": 0,
            }
            for metric in metrics
        }
        if not count:
            return empty

        rng = random.Random(self.bootstrap_seed + seed_offset)
        samples = {metric: [] for metric in metrics}
        for _ in range(self.bootstrap_iterations):
            left_totals = ProductionEvaluationHarness._empty_totals()
            right_totals = ProductionEvaluationHarness._empty_totals()
            # 一个索引列表，两臂共用 —— 这是"配对"的全部含义。
            for _sample in range(count):
                index = rng.randrange(count)
                ProductionEvaluationHarness._accumulate(left_totals, left_cases[index])
                ProductionEvaluationHarness._accumulate(right_totals, right_cases[index])
            left_metrics = ProductionEvaluationHarness._metrics(left_totals)
            right_metrics = ProductionEvaluationHarness._metrics(right_totals)
            for metric in metrics:
                left_value = left_metrics[metric]
                right_value = right_metrics[metric]
                if left_value is None or right_value is None:
                    continue
                samples[metric].append(float(right_value) - float(left_value))

        result = {}
        for metric in metrics:
            deltas = sorted(samples[metric])
            point = _delta_or_none(
                right["metrics"][metric], left["metrics"][metric]
            )
            if not deltas:
                result[metric] = {
                    "delta": point, "ci95": [None, None],
                    "iterations": self.bootstrap_iterations, "usable_iterations": 0,
                }
                continue
            lower = deltas[int((len(deltas) - 1) * 0.025)]
            upper = deltas[int((len(deltas) - 1) * 0.975)]
            result[metric] = {
                "delta": point,
                "ci95": [round(lower, 4), round(upper, 4)],
                "iterations": self.bootstrap_iterations,
                "usable_iterations": len(deltas),
            }
        return result

    def _comparison(self, left: dict, right: dict, seed_offset: int) -> dict:
        metrics = ("f1", "precision", "recall", "high_risk_recall")
        return self._paired_bootstrap(left, right, metrics, seed_offset)

    @staticmethod
    def _split_view(arm: dict, split: str) -> dict:
        return {
            "metrics": arm["by_split"][split],
            "case_results": [
                item for item in arm["case_results"] if item["split"] == split
            ],
        }

    def run(self, cases: List[dict]) -> Dict[str, Any]:
        readiness = validate_real_dataset(cases)
        if self.require_production_ready and not readiness["ready"]:
            raise ValueError("real PR dataset failed readiness gates: %s" % readiness["gates"])
        harness = ProductionEvaluationHarness()
        arms = {}
        for name in REQUIRED_ARMS:
            reviewer = self.factories[name](self.model, self.token_budget)
            arms[name] = harness.run(reviewer, cases, name)
            config_reader = getattr(reviewer, "evaluation_config", None)
            arms[name]["fairness"] = {
                "model": self.model, "token_budget_per_pr": self.token_budget,
                "product_runtime": type(getattr(reviewer, "router", reviewer)).__name__,
                "configuration": config_reader() if config_reader else {},
            }
            arms[name]["execution"] = {
                "model_role_calls": self._role_totals(arms[name]["case_results"]),
                # 真实 per-role 成本（从 ledger 的 model_call_log 聚合），
                # 让"多角色贵多少"可以和 f1 提升并排看。
                "role_costs": _role_cost_totals(
                    arms[name]["case_results"], len(cases)
                ),
            }
            # 消融表的核心对照：三档召回 + 噪声量。定位召回与严格召回分开报，
            # 否则"指对行了但归类错了"会和"完全没找到"混成一个数字。
            arms[name]["by_tier"] = {
                "overall": arms[name]["metrics"]["by_tier"],
                "validation": arms[name]["by_split"]["validation"]["by_tier"],
                "holdout": arms[name]["by_split"]["holdout"]["by_tier"],
                "unlabelled_per_pr": arms[name]["metrics"]["unlabelled_per_pr"],
                "average_llm_calls_per_pr": arms[name]["metrics"]["average_llm_calls_per_pr"],
                "average_total_tokens_per_pr": arms[name]["metrics"]["average_total_tokens_per_pr"],
                "average_latency_ms_per_pr": arms[name]["metrics"]["average_latency_ms_per_pr"],
                "average_cost_usd_per_pr": arms[name]["metrics"]["average_cost_usd_per_pr"],
            }
        single_holdout = self._split_view(arms["single-llm"], "holdout")
        no_critic_holdout = self._split_view(
            arms["multi-llm-no-critic"], "holdout",
        )
        full_holdout = self._split_view(arms["full-agentic"], "holdout")
        baseline = single_holdout["metrics"]
        candidate = full_holdout["metrics"]
        # 所有比较都过 _delta_or_none / _not_worse：指标为 None（分母为零，
        # 比率无定义）时门禁判不通过而不是崩溃，也不静默当 0 放行。
        f1_gain = _delta_or_none(candidate["f1"], baseline["f1"])
        high_gain = _delta_or_none(
            candidate["high_risk_recall"], baseline["high_risk_recall"]
        )
        false_positive_non_regression = _not_worse(
            candidate["invalid_comments_per_pr"], baseline["invalid_comments_per_pr"]
        )
        launch = bool(
            ((f1_gain is not None and f1_gain >= 0.03)
             or (high_gain is not None and high_gain >= 0.05))
            and false_positive_non_regression
        )
        multi_comparison = self._comparison(
            single_holdout, full_holdout, 100,
        )
        critic_comparison = self._comparison(
            no_critic_holdout, full_holdout, 200,
        )
        multi_statistically_positive = (
            _ci_lower_positive(multi_comparison["f1"])
            or _ci_lower_positive(multi_comparison["high_risk_recall"])
        )
        no_critic = no_critic_holdout["metrics"]
        critic_false_positive_non_regression = _not_worse(
            candidate["invalid_comments_per_pr"], no_critic["invalid_comments_per_pr"]
        )
        critic_recall_non_regression = (
            candidate["recall"] is not None and no_critic["recall"] is not None
            and candidate["recall"] >= no_critic["recall"] - 0.01
        )
        critic_statistically_positive = (
            _ci_lower_positive(critic_comparison["f1"])
            or (
                _ci_lower_positive(critic_comparison["precision"])
                and critic_recall_non_regression
            )
        )
        return {
            "schema_version": 3, "dataset": readiness, "arms": arms,
            "comparisons": {
                "scope": "hidden-holdout",
                "multi_agent_vs_single_agent": multi_comparison,
                "critic_vs_no_critic": critic_comparison,
            },
            "launch_gate": {
                "passed": bool(readiness["ready"] and launch and multi_statistically_positive),
                "metric_threshold_passed": launch,
                "statistically_positive": multi_statistically_positive,
                "production_dataset_ready": readiness["ready"], "f1_gain": f1_gain,
                "minimum_f1_gain": 0.03, "high_risk_recall_gain": high_gain,
                "minimum_high_risk_recall_gain": 0.05,
                "false_positive_non_regression": false_positive_non_regression,
                "decision": (
                    "launch" if readiness["ready"] and launch and multi_statistically_positive
                    else "insufficient-evidence"
                ),
            },
            "critic_gate": {
                "passed": bool(
                    readiness["ready"] and critic_statistically_positive
                    and critic_false_positive_non_regression
                    and critic_recall_non_regression
                ),
                "statistically_positive": critic_statistically_positive,
                "false_positive_non_regression": critic_false_positive_non_regression,
                "recall_non_regression_with_1pp_tolerance": critic_recall_non_regression,
                "production_dataset_ready": readiness["ready"],
                "decision": (
                    "keep-critic" if (
                        readiness["ready"] and critic_statistically_positive
                        and critic_false_positive_non_regression
                        and critic_recall_non_regression
                    ) else "critic-not-proven"
                ),
            },
            "claim_scope": (
                "Evidence applies to this labelled holdout and model version; "
                "it does not prove universal superiority."
            ),
        }
