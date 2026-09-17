#!/usr/bin/env python3
"""跑四臂消融（`FairAblationSuite`），逐样本断点续跑，不改测量代码本身。

## 为什么包在 reviewer 这一层，而不是重写 `FairAblationSuite.run`

`evoagent/evaluation_v2.py` 的四臂套件是这次实验的测量工具，不是被测对象——
`scripts/run_loop_a_probe.py` 已经验证过这个原则：观测对象和被观测代码分开，包
一层 reviewer 工厂，不碰被观测的引擎。这里同理：`FairAblationSuite.run()` 内部
的聚合、paired bootstrap、门禁判定全部原样复用，一行不改；只在每个 arm 的
`ProductArmReviewer` 外面包一层检查点。好处是"重跑"就是把这个脚本原样再跑一
次——已经跑过的 case 从检查点秒回，没跑过的才真花钱，`FairAblationSuite.run()`
自己完全不知道发生过中断。

## 缓存单元是 (arm, case_id, diff) 的哈希，不是纯 case_id

同一个 case 在不同臂下必须分别计费和分别缓存——rules-only 不该被 single-llm 的
结果污染。diff 进哈希是为了在数据集内容变化时让缓存自动失效，而不是悄悄复用一份
对不上号的结果。

## 只缓存成功结果

`review_case` 抛异常时不落检查点，直接向上抛给 `_run_case`——那是评测口径该管的
事（execution_success=False 记漏报），不是缓存该管的事。一次瞬时失败被当成永久
结论，比多花一次钱更贵。
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


class ExecutionCheckpoint:
    """(config_fingerprint, arm, case_id, diff) -> (findings_json, execution_dict)。

    ## 为什么 key 里必须有配置指纹

    第一版的 key 只有 (arm, case_id, diff)。实测代价：把 `--token-budget` 从
    24000 抬到 80000、又把 `max_call_tokens` 从 16000 抬到 32000 之后，旧结果
    照旧命中缓存，于是一份报告里混着两种预算跑出来的样本——而预算恰恰直接
    决定了执行成功率。那份数据只能整批作废。

    配置指纹解决的就是这个：任何影响模型行为的参数一改，哈希全变，旧缓存
    自动全部失效。宁可重跑花钱，也不要一份说不清是哪个配置跑出来的数字。
    """

    def __init__(self, path: Path, fingerprint: str):
        self.path = path
        self.fingerprint = fingerprint
        self.cache: dict = {}
        self.hits = 0
        self.misses = 0
        self.foreign = 0
        if path.exists():
            with path.open(encoding="utf-8") as handle:
                for line in handle:
                    line = line.strip()
                    if not line:
                        continue
                    record = json.loads(line)
                    # 别的配置留下的行原样留在文件里（保留审计痕迹），但不进
                    # 缓存：它们描述的是另一次实验。
                    if record.get("fingerprint") != fingerprint:
                        self.foreign += 1
                        continue
                    self.cache[record["key"]] = record

    def key(self, arm: str, case_id: str, diff: str) -> str:
        digest = hashlib.sha256()
        for part in (self.fingerprint, arm, case_id, diff):
            digest.update(part.encode("utf-8"))
            digest.update(b"\x00")
        return digest.hexdigest()

    def get(self, key: str):
        if key in self.cache:
            self.hits += 1
            return self.cache[key]
        return None

    def put(self, key: str, findings_json: list, execution: dict) -> None:
        self.misses += 1
        record = {
            "key": key, "fingerprint": self.fingerprint,
            "findings": findings_json, "execution": execution,
        }
        self.cache[key] = record
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, ensure_ascii=False, default=str) + "\n")
            handle.flush()
            os.fsync(handle.fileno())


def checkpointing_factory(arm: str, inner_build, checkpoint: ExecutionCheckpoint, progress):
    """包一层 `product_reviewer_factories()[arm]`。"""

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

    def build(model: str, token_budget: int):
        reviewer = inner_build(model, token_budget)

        class Checkpointed:
            name = reviewer.name

            def __getattr__(self, item):
                return getattr(reviewer, item)

            def review(self, diff, parsed):
                return self.review_case({"diff": diff, "repository": ""}, parsed)

            def review_case(self, case, parsed):
                key = checkpoint.key(arm, str(case["id"]), str(case["diff"]))

                cached = checkpoint.get(key)
                if cached is not None:
                    self._cached_execution = cached["execution"]
                    progress(arm, "cached", key, 0.0, len(cached["findings"]))
                    return from_json(cached["findings"])
                started = time.monotonic()
                findings = reviewer.review_case(case, parsed)
                elapsed = time.monotonic() - started
                execution = dict(reviewer.evaluation_execution())
                checkpoint.put(key, to_json(findings), execution)
                self._cached_execution = None
                progress(arm, "fresh", key, elapsed, len(findings))
                return findings

            def evaluation_execution(self):
                if getattr(self, "_cached_execution", None) is not None:
                    return dict(self._cached_execution)
                return reviewer.evaluation_execution()

            def evaluation_config(self):
                return reviewer.evaluation_config()

        return Checkpointed()

    return build


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dataset", help="Human-labelled PR JSONL (subset ok)")
    parser.add_argument("--base-url", default=os.getenv("EVOAGENT_LLM_BASE_URL", ""))
    parser.add_argument("--api-key", default=os.getenv("EVOAGENT_LLM_API_KEY", ""))
    parser.add_argument("--model", default=os.getenv("EVOAGENT_LLM_MODEL", ""))
    parser.add_argument("--provider", default=os.getenv("EVOAGENT_LLM_PROVIDER", "custom"))
    parser.add_argument("--timeout", type=int, default=180)
    parser.add_argument("--token-budget", type=int, default=12000)
    parser.add_argument("--time-budget", type=int, default=240)
    parser.add_argument("--bootstrap-iterations", type=int, default=2000)
    parser.add_argument("--bootstrap-seed", type=int, default=20260819)
    parser.add_argument(
        "--max-call-tokens", type=int, default=32000,
        help="单次模型调用的 max_tokens 上限。推理模型上 reasoning + content "
             "共享这个额度，16000 时实测 55/656 条死于 finish_reason=length",
    )
    parser.add_argument(
        "--agent-loop-max-steps", type=int, default=6,
        help="BoundedRole 每个角色的最大步数。4 时实测 36/656 条死于步数耗尽",
    )
    parser.add_argument("--allow-non-production-data", action="store_true")
    parser.add_argument(
        "--out", default=str(ROOT / "output" / "ablation-pilot"),
        help="checkpoint.jsonl 和 evaluation.json 都写在这个目录下",
    )
    args = parser.parse_args()
    if not args.base_url or not args.api_key or not args.model:
        parser.error("--base-url, --api-key and --model are required")

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    # 单写入者锁。检查点防的是崩溃，防不了两个进程同时写——实测发生过一次：
    # Git Bash 的 `ps` 看不见 Windows 的 python.exe，我据此误判进程已死而启动
    # 了第二个，两个进程往同一个文件追加，428 行里 109 行是重复调用。数据没坏
    # （加载是 last-write-wins），但白花了钱。
    lock_path = out / "run.lock"
    if lock_path.exists():
        stale = lock_path.read_text(encoding="utf-8").strip()
        print(json.dumps({
            "error": "another run holds the lock", "lock": str(lock_path),
            "holder": stale,
            "hint": "确认那个进程真的死了再删除锁文件；Windows 上用 "
                    "`tasklist | grep python.exe` 查，Git Bash 的 ps 看不到",
        }, ensure_ascii=False), flush=True)
        return 2
    lock_path.write_text(
        "pid=%d started=%s" % (os.getpid(), time.strftime("%Y-%m-%d %H:%M:%S")),
        encoding="utf-8",
    )

    # 指纹只包含**会改变模型行为**的参数。bootstrap 的迭代次数和种子不在内：
    # 它们只影响置信区间的计算，不影响每个样本跑出什么结果，放进去会让重算
    # CI 也得重新调 API。
    #
    # provider 在内（2026-09-13 补）。它原先不在，于是同一个模型名换 provider
    # 走（直连 vs 中转 vs OpenRouter）缓存照样复用——但同名模型在不同 provider
    # 下的量化、上下文上限、JSON 模式实现都可能不同，那是"会改变模型行为"的
    # 参数，符合上面这条纪律。
    fingerprint = hashlib.sha256(json.dumps({
        "model": args.model,
        "provider": args.provider,
        "token_budget": args.token_budget,
        "time_budget": args.time_budget,
        "max_call_tokens": args.max_call_tokens,
        "agent_loop_max_steps": args.agent_loop_max_steps,
        "timeout": args.timeout,
    }, sort_keys=True).encode("utf-8")).hexdigest()[:16]

    try:
        return _run(args, out, fingerprint)
    finally:
        lock_path.unlink(missing_ok=True)


def _run(args, out: Path, fingerprint: str) -> int:
    from evoagent.evaluation_harness import load_jsonl
    from evoagent.evaluation_v2 import FairAblationSuite, product_reviewer_factories
    from evoagent.llm import JsonChatClient

    checkpoint = ExecutionCheckpoint(out / "checkpoint.jsonl", fingerprint)
    # 把**全部**进指纹的参数原样打进日志第一行。
    #
    # 这一条是事后补的：2026-09-13 那次中断后重启，`.env` 里只有 api key 和
    # provider，base-url / model 得从 config.py 的默认值猜，猜出来的组合跟原来
    # 那次不一致，指纹一变 335 条缓存全部失效。当时想反解原参数——900 种组合
    # 全试过没命中（指纹的字典结构本身也变过），只能重跑。
    #
    # 根因不是猜错了，是**参数没留痕**：指纹是单向哈希，日志里不记原值就永远
    # 反推不出来。所以这里记的字段必须与上面 fingerprint 字典逐项对应，改那边
    # 就要改这边。api_key 当然不记。
    print(json.dumps({
        "checkpoint": str(out / "checkpoint.jsonl"),
        "config_fingerprint": fingerprint,
        "preloaded": len(checkpoint.cache),
        "ignored_other_config": checkpoint.foreign,
        "fingerprint_inputs": {
            "model": args.model,
            "provider": args.provider,
            "token_budget": args.token_budget,
            "time_budget": args.time_budget,
            "max_call_tokens": args.max_call_tokens,
            "agent_loop_max_steps": args.agent_loop_max_steps,
            "timeout": args.timeout,
        },
        "base_url": args.base_url,
        "dataset": args.dataset,
        "pid": os.getpid(),
        "started": time.strftime("%Y-%m-%d %H:%M:%S"),
    }, ensure_ascii=False), flush=True)

    counters = {"n": 0}

    def progress(arm, kind, key, elapsed, findings):
        counters["n"] += 1
        print(json.dumps({
            "n": counters["n"], "arm": arm, "kind": kind, "key": key[:12],
            "elapsed_ms": int(elapsed * 1000), "findings": findings,
        }, ensure_ascii=False), flush=True)

    client = JsonChatClient(
        args.base_url, args.api_key, args.model,
        provider=args.provider, timeout=args.timeout,
    )
    raw_factories = product_reviewer_factories(
        client, args.time_budget,
        max_call_tokens=args.max_call_tokens,
        agent_loop_max_steps=args.agent_loop_max_steps,
    )
    wrapped_factories = {
        arm: checkpointing_factory(arm, build, checkpoint, progress)
        for arm, build in raw_factories.items()
    }
    suite = FairAblationSuite(
        wrapped_factories, args.model, args.token_budget,
        require_production_ready=not args.allow_non_production_data,
        bootstrap_iterations=args.bootstrap_iterations,
        bootstrap_seed=args.bootstrap_seed,
    )
    cases = load_jsonl(args.dataset)
    report = suite.run(cases)

    output_path = out / "evaluation.json"
    with output_path.open("w", encoding="utf-8", newline="\n") as handle:
        json.dump(report, handle, ensure_ascii=False, indent=2, sort_keys=True)
        handle.write("\n")
    print(json.dumps({
        "output": str(output_path),
        "checkpoint_hits": checkpoint.hits, "checkpoint_misses": checkpoint.misses,
    }, ensure_ascii=False), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
