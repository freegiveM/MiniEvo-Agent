#!/usr/bin/env python3
"""连跑两轮 `auto_propose`，观察回路 A 到底转不转。

## 这个脚本要回答的问题

第 19.1 节修了消费账本，但那只有单元测试在保证。真实条件下第二轮会怎样，
没人跑过。单元测试用的是 stub 生成器和空评审器，**它证明不了真实 LLM
生成的候选会不会被门禁拦在评测之前**——而恰恰是"拦在评测之前"那一档决定
反馈该不该被消费。

判据（第二轮的行为必须与第一轮不同）：

- 第一轮 `feedback_consumed` 为真 → 第二轮 `failure_cases_used` 应为 0、
  `triage.already_attempted` 应等于第一轮消费的条数。**账本在起作用。**
- 第一轮 `feedback_consumed` 为假（被 safety / 数据集 / provider 拦在评测
  之前）→ 第二轮 `failure_cases_used` 应与第一轮**相同**。反馈没被烧掉，
  这正是第 16.6 节那个缺口的修复点。

两种都是通过。**不通过**的形状只有一个：第一轮没进评测、第二轮却选不到
反馈了——那说明账本仍然在为无关失败记账。

## 为什么逐样本落盘

一轮 = 一次候选生成（LLM）+ 基线与候选各一次全量回放（每条样本一次 LLM
调用）。`max_cases=20` 下那是 81 次调用、一个多小时。所以两级落盘：每条
样本回放完立刻写 `replay.jsonl`，每轮结束写 `rounds.jsonl`，都是 append +
flush + fsync。中途崩了续跑时，已回放的样本直接复用，不重复花钱——失败的
调用也是照常计费的。

## 只读写指定的库

`--db` 必填，没有默认值：这个脚本会往库里写 `evolution_runs`、
`evolution_attempts`、`skill_versions`，绝不能对着主库或 `datasets/`
误跑一次。
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


class ReplayCheckpoint:
    """逐次回放落盘 + 断点续跑。

    ## 为什么"逐轮落盘"不够

    一轮 = 一次候选生成 + 基线与候选各一次全量回放。`max_cases=20` 下那是
    81 次 LLM 调用、一个多小时，而这个脚本原来只在**整轮结束**时才写一行。
    于是两件事同时成立：跑到第 70 次失败会让前 69 次的钱全部作废（失败的
    调用照常计费），而且从外部完全看不出进度——"跑到第 60 条了"和"卡在
    某次调用上"长得一模一样。

    ## 键是 (prompt, diff)，不是样本 id

    这个脚本拿不到样本 id：`RegressionEvaluator.run` 只把 `diff` 和 `parsed`
    交给评审器。但 (prompt, diff) 恰好是**正确**的键——同一份提示词加同一份
    diff 就是同一个回放单元，所以基线与候选天然分到两个键上，不会互相顶掉。
    拿样本 id 当键反而是错的：基线和候选在同一条样本上会撞键。

    ## 不缓存异常

    一次超时或 provider 抖动如果被写进检查点，续跑时会把它当成"这条样本的
    结论"永久重放——一个瞬时故障就变成了固定结果。所以只落成功的结果，
    失败的下次重跑。这与 `RegressionEvaluator` 把失败算作漏报是两回事：
    那是评测口径，这里是缓存纪律。
    """

    def __init__(self, path: Path):
        self.path = path
        self.cache: dict = {}
        self.hits = 0
        self.misses = 0
        if path.exists():
            with path.open(encoding="utf-8") as handle:
                for line in handle:
                    line = line.strip()
                    if line:
                        record = json.loads(line)
                        self.cache[record["key"]] = record["findings"]

    @staticmethod
    def key(prompt: str, diff: str) -> str:
        digest = hashlib.sha256()
        # 分隔符不可省：没有它，("ab", "c") 与 ("a", "bc") 会算出同一个键。
        digest.update(prompt.encode("utf-8"))
        digest.update(b"\x00")
        digest.update(diff.encode("utf-8"))
        return digest.hexdigest()

    def get(self, key: str):
        if key in self.cache:
            self.hits += 1
            return self.cache[key]
        return None

    def put(self, key: str, findings: list, meta: dict) -> None:
        self.misses += 1
        self.cache[key] = findings
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(
                {"key": key, "findings": findings, **meta},
                ensure_ascii=False, default=str) + "\n")
            handle.flush()
            os.fsync(handle.fileno())


def checkpointing_factory(inner, checkpoint: ReplayCheckpoint, progress):
    """把 reviewer_factory 包一层，逐次回放走检查点。

    包在工厂这一层而不是改 `RegressionEvaluator`：引擎是被测对象，为了观测
    它而改它，测到的就不再是生产路径上那段代码。工厂是引擎的注入点，包在
    这里对引擎完全透明。
    """

    from evoagent.models import Finding, Severity

    def to_json(findings):
        return [item.to_dict() for item in findings]

    def from_json(records):
        restored = []
        for record in records:
            value = dict(record)
            value["severity"] = Severity(value["severity"])
            restored.append(Finding(**value))
        return restored

    def factory(prompt: str):
        reviewer = inner(prompt)

        class Checkpointed:
            name = getattr(reviewer, "name", reviewer.__class__.__name__)

            def review(self, diff, parsed):
                key = checkpoint.key(prompt, diff)
                cached = checkpoint.get(key)
                if cached is not None:
                    progress("cached", key, 0.0, len(cached))
                    return from_json(cached)
                started = time.monotonic()
                findings = reviewer.review(diff, parsed)
                elapsed = time.monotonic() - started
                # 只落成功的结果。异常直接往上抛给 RegressionEvaluator，
                # 由它按自己的口径记成漏报。
                checkpoint.put(key, to_json(findings), {
                    "prompt_sha": hashlib.sha256(
                        prompt.encode("utf-8")).hexdigest()[:12],
                    "elapsed_ms": int(elapsed * 1000),
                })
                progress("fresh", key, elapsed, len(findings))
                return findings

        return Checkpointed()

    return factory


def snapshot(store, skill_name: str) -> dict:
    """取一份账本与语料的现状，用于跨轮比较。"""

    return {
        "unresolved_failure_cases": len(store.list_failure_cases(True, 500)),
        "attempted_case_ids": len(store.list_attempted_failure_case_ids(skill_name)),
        "ledger_rows": len(store.list_evolution_attempts(skill_name)),
        "skill_versions": len(store.list_skill_versions(skill_name)),
    }


def digest(result: dict) -> dict:
    """只留判据相关的字段。

    完整 result 里嵌着候选提示词全文和逐样本回放明细，几千行，读不动。
    完整版另外落盘到 rounds.jsonl。
    """

    gates = result.get("gates") or {}
    triage = result.get("triage") or {}
    return {
        "decision": result.get("decision"),
        "reason": (result.get("reason") or "")[:300],
        "feedback_consumed": result.get("feedback_consumed"),
        "failure_cases_used": result.get("failure_cases_used"),
        "already_attempted": triage.get("already_attempted"),
        "sporadic_cases_deferred": triage.get("sporadic_cases_deferred"),
        "exhausted_root_causes": triage.get("exhausted_root_causes"),
        "evaluation_success": gates.get("evaluation_success"),
        "validation_dataset_ready": gates.get("validation_dataset_ready"),
        "holdout_dataset_ready": gates.get("holdout_dataset_ready"),
        "safety": gates.get("safety"),
        # 键名必须与 `_propose` 里 gates.update 用的完全一致。写成
        # `improved` / `non_regression` 会取到 None，而 None 在这个项目里
        # 恰好是"没跑到"的意思——于是一个纯粹的拼写错误会被读成"这道门禁
        # 没执行"。第一轮的报告就这么误报过一次。
        "validation_improvement": gates.get("validation_improvement"),
        "validation_non_regression": gates.get("validation_non_regression"),
        "holdout_non_regression": gates.get("holdout_non_regression"),
        "non_regression_unmeasurable": gates.get("non_regression_unmeasurable"),
        "significant": gates.get("significant"),
        "run_id": result.get("run_id"),
        "version": (result.get("version") or {}).get("version"),
        "baseline_score": (result.get("baseline") or {}).get("score"),
        "candidate_score": (result.get("candidate") or {}).get("score"),
    }


def verdict(rounds: list) -> dict:
    """把"账本有没有在正确的时候记账"判成一句话。"""

    if len(rounds) < 2:
        return {"conclusive": False, "note": "需要两轮才能判"}
    first, second = rounds[0]["digest"], rounds[1]["digest"]
    used_first = first.get("failure_cases_used") or 0

    if first.get("feedback_consumed"):
        passed = (second.get("failure_cases_used") or 0) == 0
        return {
            "conclusive": True,
            "shape": "consumed",
            "passed": passed,
            "note": "第一轮进过评测并消费；第二轮应选不到反馈（不重复消费）"
                    if passed else
                    "第一轮已消费，第二轮却仍在选反馈——账本没起作用",
        }

    passed = (second.get("failure_cases_used") or 0) == used_first
    return {
        "conclusive": True,
        "shape": "unrelated_abort",
        "passed": passed,
        "note": "第一轮被无关失败拦在评测之前、未消费；第二轮仍选得到"
                "同样条数的反馈——第 16.6 节的缺口已修"
                if passed else
                "第一轮未进评测，第二轮却选不到反馈了——账本仍在为无关失败记账",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", required=True, help="要跑的库（会被写入）")
    parser.add_argument("--skill", default="llm-review")
    parser.add_argument("--rounds", type=int, default=2)
    parser.add_argument("--out", default="output/loop-a")
    parser.add_argument(
        "--checkpoint", default="",
        help="逐样本回放检查点（默认 <out>/replay.jsonl）。已在里面的样本"
             "直接复用，不再发起调用——续跑不重复花钱。",
    )
    args = parser.parse_args()

    if not Path(args.db).exists():
        raise SystemExit("找不到库：%s" % args.db)

    # 必须在 import service 之前设好：Settings.from_env 在构造时读它。
    os.environ["EVOAGENT_DB_PATH"] = args.db
    os.environ["EVOAGENT_DATABASE_URL"] = ""

    from evoagent.config import Settings
    from evoagent.service import ReviewService

    settings = Settings.from_env()
    service = ReviewService(settings)
    store = service.store

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    detail = out / "rounds.jsonl"

    # 逐样本检查点。装在服务已经构造好的引擎上，因为服务层才知道
    # llm_config —— 探针自己没有重建 reviewer 的信息。引擎的 reviewer_factory
    # 是 None 时（没配 LLM）什么都不包：那种情况下压根不会发生回放。
    checkpoint = None
    if service.evolution.reviewer_factory is not None:
        checkpoint = ReplayCheckpoint(
            Path(args.checkpoint) if args.checkpoint else out / "replay.jsonl"
        )
        replayed = [0]

        def progress(kind: str, key: str, elapsed: float, findings: int) -> None:
            replayed[0] += 1
            print(json.dumps({
                "replay": replayed[0], "kind": kind, "key": key[:12],
                "elapsed_ms": int(elapsed * 1000), "findings": findings,
            }, ensure_ascii=False), flush=True)

        service.evolution.reviewer_factory = checkpointing_factory(
            service.evolution.reviewer_factory, checkpoint, progress
        )
        print(json.dumps({
            "checkpoint": str(checkpoint.path), "preloaded": len(checkpoint.cache),
        }, ensure_ascii=False), flush=True)

    config = {
        "db": args.db,
        "skill": args.skill,
        "llm_configured": bool(service.llm_config),
        "provider": (service.llm_config or {}).get("provider"),
        "model": (service.llm_config or {}).get("model"),
        "min_cases": settings.eval_min_cases,
        "max_cases": settings.eval_max_cases,
        "min_holdout_cases": settings.eval_min_holdout_cases,
        "min_improvement": settings.eval_min_improvement,
        "max_metric_regression": settings.eval_max_metric_regression,
        "root_cause_min_occurrences": settings.evolution_root_cause_min_occurrences,
        "max_attempts_per_root_cause": settings.evolution_max_attempts_per_root_cause,
    }
    print(json.dumps({"config": config}, ensure_ascii=False), flush=True)

    rounds = []
    for index in range(1, args.rounds + 1):
        before = snapshot(store, args.skill)
        replay_before = (checkpoint.hits + checkpoint.misses) if checkpoint else 0
        try:
            result = service.evolution.auto_propose(args.skill, settings.default_tenant_id)
        except Exception as exc:                     # noqa: BLE001
            # 崩了也要落盘：崩溃本身是这次探测的结果之一，而重跑一轮很贵。
            record = {
                "round": index, "before": before,
                "replays": (checkpoint.hits + checkpoint.misses - replay_before)
                           if checkpoint else None,
                "error": "%s: %s" % (type(exc).__name__, exc),
            }
            rounds.append({"round": index, "digest": {}, "error": record["error"]})
            with detail.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(record, ensure_ascii=False, default=str) + "\n")
                handle.flush()
                os.fsync(handle.fileno())
            print(json.dumps(record, ensure_ascii=False), flush=True)
            break

        record = {
            "round": index,
            "before": before,
            "after": snapshot(store, args.skill),
            # 这一轮里有多少次回放是真花了钱的。续跑时 fresh 会明显小于总数。
            "replays": (checkpoint.hits + checkpoint.misses - replay_before)
                       if checkpoint else None,
            "replay_cache_hits": checkpoint.hits if checkpoint else None,
            "digest": digest(result),
            "result": result,
        }
        rounds.append({"round": index, "digest": record["digest"]})
        with detail.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, ensure_ascii=False, default=str) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        print(json.dumps(
            {"round": index, "before": before, "after": record["after"],
             "digest": record["digest"]},
            ensure_ascii=False, indent=2,
        ), flush=True)

    summary = {"config": config, "rounds": rounds, "verdict": verdict(rounds)}
    (out / "summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    print(json.dumps({"verdict": summary["verdict"]}, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())