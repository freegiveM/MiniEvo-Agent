"""Track A 收尾：把 real-pr-v1（正样本）+ real-pr-clean-v1（负样本）一起接入
`RegressionEvaluator`，用真实 LLM reviewer 跑一次 D6 replay。

在这之前，`clean_total` 在真实数据集上恒为 0（数据集里从没有过一条
expected_findings=[] 的记录），`clean_accuracy` 因此从未在真实数据上算出过值
——见 evoagent/evolution.py:191 附近的历史注释。现在两个数据集都存在，
这个脚本把它们合并喂给同一个 evaluator，第一次能同时报告 precision（正样本）
和 clean_accuracy≈1-FPR（负样本）。

逐条落盘 + 硬超时（2026-09 加）：第一次真跑全量时，某一条 case 卡住超过两小时
没有返回也没有报错——`OpenAICompatibleReviewer._request_json` 用的
`urllib.request.urlopen(..., timeout=...)` 是逐次 socket 读超时，不是总请求
时长上限：只要服务端/代理间歇性吐字节（trickle 或 keep-alive），每次 recv()
都能在超时窗口内收到数据，timeout 就永远不触发，单条 case 可以无限期挂住。
而 `RegressionEvaluator.run` 又是全部跑完才一次性返回结果，中途杀掉进程等于
已经花掉的 API 调用全部作废。`CheckpointedReviewer` 用一个线程 + 硬性
join(timeout) 包住每次 review() 调用，超时就强制放弃这一条（不受 socket
trickle 影响），并且每跑完一条（无论成功还是失败）立刻 append 写入 JSONL
checkpoint；重跑时会先读这个 checkpoint，跳过已经在里面的 case，不重新
调用、不重新花钱。
"""
import argparse
import json
import os
import sys
import threading

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from evoagent.config import Settings  # noqa: E402
from evoagent.evaluation_harness import load_jsonl  # noqa: E402
from evoagent.evolution import DEFAULT_PROMPT, RegressionEvaluator  # noqa: E402
from evoagent.models import Finding, Severity  # noqa: E402
from evoagent.reviewer import OpenAICompatibleReviewer  # noqa: E402


def _to_case(record: dict) -> dict:
    # 数据集里的 expected_findings 从来没有原生 rule_id 字段（见
    # dataset_builder.build_case / build_clean_case），只有 cwe。之前这里
    # 曾经把 cwe 当 rule_id 的兜底值填进去，但 evolution.py 的命中判定是
    # `not rule_id or key[2] == rule_id`——CWE 字符串（"CWE-193"）永远不会
    # 等于 LLM reviewer 返回的自由文本 rule_id（比如
    # "PARSER_FEED_DATA_RETURN_IGNORED"），于是每一条本来命中了 path+line
    # 的真阳性都被 rule_id 不匹配悄悄判成漏报，precision/recall/f1 全部
    # 归零。留空字符串触发 evolution.py 里的通配分支，只按 path+line 匹配，
    # 这也是 min_severity 早就在用的同一种"忽略掉数据集里不存在的字段"的
    # 处理方式。
    expected = [
        {
            "path": item["path"],
            "line": int(item["start_line"]),
            # end_line 一起传：expected_finding 本来就是行区间，只传起始行
            # 会让"报在缺陷区间中段"被算成漏报。evolution.py 的匹配按
            # [line, end_line] 加行容差判定，缺省时回落到 line。
            "end_line": int(item.get("end_line", item["start_line"])),
            "rule_id": item.get("rule_id", ""),
            "min_severity": item.get("severity", "low"),
        }
        for item in record["expected_findings"]
    ]
    return {
        "id": record["id"],
        "name": record["id"],
        "split": record["split"],
        "diff": record["diff"],
        "expected": expected,
    }


class _HardTimeout(Exception):
    pass


def _call_with_hard_timeout(fn, args, timeout):
    box = {}

    def _target():
        try:
            box["value"] = fn(*args)
        except BaseException as exc:  # noqa: BLE001 - propagate whatever review() raised
            box["error"] = exc

    thread = threading.Thread(target=_target, daemon=True)
    thread.start()
    thread.join(timeout)
    if thread.is_alive():
        # 线程被弃用，不 join 等它结束——它多半卡在一次 recv() 上，daemon=True
        # 保证它不会挡住进程退出，代价是这条底层连接直到进程退出前都不会被
        # 显式关闭，可接受（批处理脚本，不是常驻服务）。
        raise _HardTimeout(
            "review() 超过硬超时 %ss 未返回（socket 读超时可能被间歇性字节"
            "持续重置，从未真正触发），强制放弃这一条 case" % timeout
        )
    if "error" in box:
        raise box["error"]
    return box["value"]


def _load_checkpoint(path: str) -> dict:
    cache = {}
    if path and os.path.exists(path):
        with open(path, "r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                record = json.loads(line)
                cache[record["id"]] = record
    return cache


def _append_checkpoint(path: str, record: dict) -> None:
    if not path:
        return
    os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
    with open(path, "a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, ensure_ascii=False) + "\n")
        handle.flush()
        os.fsync(handle.fileno())


class CheckpointedReviewer:
    """按 `cases` 顺序包一层缓存 + 硬超时。`RegressionEvaluator.run` 对同一个
    reviewer 实例按 cases 顺序逐条调用 review()，这里假设调用顺序与构造时
    传入的 `cases` 完全一致（同一个列表对象），据此把每次调用映射回具体的
    case id，不需要改 RegressionEvaluator 本身的调用签名。
    """

    def __init__(self, inner, cases, checkpoint_path: str, hard_timeout: int):
        self.inner = inner
        self.name = getattr(inner, "name", inner.__class__.__name__)
        self.cases = cases
        self.checkpoint_path = checkpoint_path
        self.hard_timeout = hard_timeout
        self.cache = _load_checkpoint(checkpoint_path)
        self.index = 0

    def review(self, diff, parsed):
        case = self.cases[self.index]
        self.index += 1
        case_id = case.get("id") or case["name"]
        cached = self.cache.get(case_id)
        if cached is not None:
            status = cached.get("error") or ("%d findings" % len(cached.get("findings", [])))
            print(
                "  [%d/%d] %s -> cached (%s)" % (self.index, len(self.cases), case_id, status),
                flush=True,
            )
            if cached.get("error"):
                raise RuntimeError(cached["error"])
            return [
                Finding(**{**item, "severity": Severity(item["severity"])})
                for item in cached["findings"]
            ]
        try:
            findings = _call_with_hard_timeout(self.inner.review, (diff, parsed), self.hard_timeout)
        except Exception as exc:
            _append_checkpoint(self.checkpoint_path, {"id": case_id, "error": str(exc)[:500]})
            print(
                "  [%d/%d] %s -> ERROR %s" % (self.index, len(self.cases), case_id, str(exc)[:200]),
                flush=True,
            )
            raise
        _append_checkpoint(
            self.checkpoint_path,
            {"id": case_id, "findings": [f.to_dict() for f in findings]},
        )
        print(
            "  [%d/%d] %s -> %d findings" % (self.index, len(self.cases), case_id, len(findings)),
            flush=True,
        )
        return findings


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", default="datasets/real-pr-v1.jsonl")
    parser.add_argument("--clean-dataset", default="datasets/real-pr-clean-v1.jsonl")
    parser.add_argument("--split", default="", choices=["", "validation", "holdout"])
    parser.add_argument(
        "--limit", type=int, default=0,
        help="0 = 不限；花钱之前先用小数字做通路 sanity check",
    )
    parser.add_argument("--prompt", default=DEFAULT_PROMPT)
    parser.add_argument(
        "--timeout", type=int, default=240,
        help="单次 HTTP 请求的 socket 读超时（urllib 的 timeout 参数，逐次 recv() 生效，"
             "不是总请求时长上限）",
    )
    parser.add_argument(
        "--hard-timeout", type=int, default=0,
        help="单条 case 的硬性总时长上限（线程 join，不受 socket trickle 影响，超时"
             "就强制放弃这一条）。0 = 默认取 --timeout + 60 秒的余量。",
    )
    parser.add_argument("--output", default="")
    parser.add_argument(
        "--checkpoint", default="",
        help="逐条落盘的 JSONL 路径。默认取 --output 加 .checkpoint.jsonl 后缀。"
             "重跑时自动跳过已经在里面的 case id，不重新调用、不重新花钱。",
    )
    args = parser.parse_args()

    hard_timeout = args.hard_timeout or (args.timeout + 60)

    resolved = Settings.from_env().resolved_llm()
    if not resolved:
        raise SystemExit(
            "未配置 LLM：设置 EVOAGENT_LLM_PROVIDER=deepseek 和 "
            "EVOAGENT_DEEPSEEK_API_KEY（或对应 provider 的 key）后重跑。"
        )

    def factory(prompt: str) -> OpenAICompatibleReviewer:
        return OpenAICompatibleReviewer(
            base_url=resolved["base_url"], api_key=resolved["api_key"],
            model=resolved["model"], provider=resolved["provider"],
            extra_headers=resolved.get("headers") or {}, timeout=args.timeout,
            system_prompt=prompt,
        )

    positive = [_to_case(r) for r in load_jsonl(args.dataset)]
    clean = [_to_case(r) for r in load_jsonl(args.clean_dataset)]
    if args.split:
        positive = [c for c in positive if c["split"] == args.split]
        clean = [c for c in clean if c["split"] == args.split]
    if args.limit:
        # 分别限流，不是先拼接再截断：正样本排在前面，合并后再截断会让
        # 小样本 sanity check 永远抽不到负样本，等于没测负样本路径。
        positive = positive[: args.limit]
        clean = clean[: args.limit]
    cases = positive + clean

    checkpoint_path = args.checkpoint
    if not checkpoint_path and args.output:
        checkpoint_path = args.output + ".checkpoint.jsonl"

    print(
        "replaying %d cases (%d positive, %d clean)%s against %s "
        "[per-request timeout=%ss, hard-timeout=%ss, checkpoint=%s]"
        % (
            len(cases), len(positive), len(clean),
            (" [split=%s]" % args.split) if args.split else "",
            resolved["model"], args.timeout, hard_timeout,
            checkpoint_path or "(none)",
        ),
        flush=True,
    )

    reviewer = factory(args.prompt)
    checkpointed = CheckpointedReviewer(reviewer, cases, checkpoint_path, hard_timeout)
    if checkpointed.cache:
        print(
            "resuming: %d/%d cases already in checkpoint" % (len(checkpointed.cache), len(cases)),
            flush=True,
        )

    metrics = RegressionEvaluator(lambda _prompt: checkpointed).run(args.prompt, cases)
    summary = {k: v for k, v in metrics.items() if k != "case_results"}
    print(json.dumps(summary, indent=2, ensure_ascii=False, sort_keys=True))
    if metrics["clean_cases"] <= 0:
        print("! clean_cases 仍然是 0 —— 检查 --clean-dataset 是否传对了", file=sys.stderr)
    if args.output:
        os.makedirs(os.path.dirname(os.path.abspath(args.output)) or ".", exist_ok=True)
        with open(args.output, "w", encoding="utf-8") as handle:
            json.dump(metrics, handle, indent=2, ensure_ascii=False, sort_keys=True)
        print("wrote", args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
