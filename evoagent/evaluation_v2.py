"""Fair product-backed ablation suite for labelled PRs."""
from collections import Counter
import random
import time
from typing import Any, Callable, Dict, List, Mapping, Optional

from .agentic_core import ModeRouterReviewer
from .evaluation_benchmark import ContextRuleReviewer
from .evaluation_harness import EndToEndEvaluationHarness, dataset_fingerprint, one_to_one_match
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
) -> Dict[str, Callable[[str, int], ProductArmReviewer]]:
    """Create all four arms with one model client and a shared total budget."""

    def build(arm: str, model: str, token_budget: int) -> ProductArmReviewer:
        if str(client.model) != str(model):
            raise ValueError(
                "evaluation model %s does not match client model %s"
                % (model, client.model)
            )
        return ProductArmReviewer(
            arm, client, token_budget, total_time_budget_seconds,
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
            "invalid_comments": result["fp"],
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
        })
        if result["execution_success"]:
            findings = recording.findings
            expected = [
                item for item in case["expected_findings"]
                if bool(item.get("should_comment", True))
            ]
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
        })
        return values

    @staticmethod
    def _accumulate(totals, result):
        EndToEndEvaluationHarness._accumulate(totals, result)
        for field in (
            "invalid_comments", "exact_location_hits", "evidence_hits",
            "accepted_comments", "closed_comments", "latency_ms",
            "llm_calls", "input_tokens", "output_tokens", "total_tokens",
        ):
            totals[field] += int(result.get(field, 0))
        totals["cost_microusd"] += int(float(result.get("cost_usd", 0)) * 1_000_000)

    @staticmethod
    def _metrics(totals):
        values = EndToEndEvaluationHarness._metrics(totals)
        cases = totals["cases"] or 1
        tp = totals["tp"] or 1
        commented = totals["accepted_comments"] + totals["closed_comments"]
        values.update({
            "invalid_comments_per_pr": round(totals["invalid_comments"] / cases, 4),
            "exact_line_accuracy": round(totals["exact_location_hits"] / tp, 4),
            "evidence_accuracy": round(totals["evidence_hits"] / tp, 4),
            "comment_acceptance_rate": round(
                totals["accepted_comments"] / commented, 4
            ) if commented else None,
            "average_cost_usd_per_pr": round(
                totals["cost_microusd"] / 1_000_000 / cases, 8
            ),
            "average_latency_ms_per_pr": round(totals["latency_ms"] / cases, 2),
            "average_llm_calls_per_pr": round(totals["llm_calls"] / cases, 4),
            "average_input_tokens_per_pr": round(totals["input_tokens"] / cases, 2),
            "average_output_tokens_per_pr": round(totals["output_tokens"] / cases, 2),
            "average_total_tokens_per_pr": round(totals["total_tokens"] / cases, 2),
            "failure_rate": round(
                1 - totals["execution_successes"] / cases, 4
            ),
        })
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

    def _paired_delta(
        self, left: dict, right: dict, metric: str, seed_offset: int,
    ) -> dict:
        left_cases = left["case_results"]
        right_cases = right["case_results"]
        if [item["id"] for item in left_cases] != [item["id"] for item in right_cases]:
            raise ValueError("paired comparison requires identical ordered case ids")
        count = len(left_cases)
        if not count:
            return {"delta": 0.0, "ci95": [0.0, 0.0], "iterations": 0}
        rng = random.Random(self.bootstrap_seed + seed_offset)
        deltas = []
        for _ in range(self.bootstrap_iterations):
            left_totals = ProductionEvaluationHarness._empty_totals()
            right_totals = ProductionEvaluationHarness._empty_totals()
            for _sample in range(count):
                index = rng.randrange(count)
                ProductionEvaluationHarness._accumulate(left_totals, left_cases[index])
                ProductionEvaluationHarness._accumulate(right_totals, right_cases[index])
            left_value = ProductionEvaluationHarness._metrics(left_totals)[metric]
            right_value = ProductionEvaluationHarness._metrics(right_totals)[metric]
            deltas.append(float(right_value) - float(left_value))
        deltas.sort()
        lower = deltas[int((len(deltas) - 1) * 0.025)]
        upper = deltas[int((len(deltas) - 1) * 0.975)]
        point = float(right["metrics"][metric]) - float(left["metrics"][metric])
        return {
            "delta": round(point, 4),
            "ci95": [round(lower, 4), round(upper, 4)],
            "iterations": self.bootstrap_iterations,
        }

    def _comparison(self, left: dict, right: dict, seed_offset: int) -> dict:
        metrics = ("f1", "precision", "recall", "high_risk_recall")
        return {
            metric: self._paired_delta(left, right, metric, seed_offset + index)
            for index, metric in enumerate(metrics)
        }

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
        f1_gain = round(candidate["f1"] - baseline["f1"], 4)
        high_gain = round(
            candidate["high_risk_recall"] - baseline["high_risk_recall"], 4
        )
        false_positive_non_regression = (
            candidate["invalid_comments_per_pr"]
            <= baseline["invalid_comments_per_pr"]
        )
        launch = (
            (f1_gain >= 0.03 or high_gain >= 0.05)
            and false_positive_non_regression
        )
        multi_comparison = self._comparison(
            single_holdout, full_holdout, 100,
        )
        critic_comparison = self._comparison(
            no_critic_holdout, full_holdout, 200,
        )
        multi_statistically_positive = (
            multi_comparison["f1"]["ci95"][0] > 0
            or multi_comparison["high_risk_recall"]["ci95"][0] > 0
        )
        no_critic = no_critic_holdout["metrics"]
        critic_false_positive_non_regression = (
            candidate["invalid_comments_per_pr"]
            <= no_critic["invalid_comments_per_pr"]
        )
        critic_recall_non_regression = candidate["recall"] >= no_critic["recall"] - 0.01
        critic_statistically_positive = (
            critic_comparison["f1"]["ci95"][0] > 0
            or (
                critic_comparison["precision"]["ci95"][0] > 0
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
