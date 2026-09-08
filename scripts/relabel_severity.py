"""用 LLM-as-judge 重标 real-pr-v1 的 expected_findings 严重度与类别。

    python scripts/relabel_severity.py --limit 2          # 先做小样本通路检查
    python scripts/relabel_severity.py                    # 全量 95 条 case / 165 条 finding

配套 rubric 见 docs/severity-rubric.md，口径实现见 evoagent/severity_labelling.py。

为什么要这个脚本：原 expected_findings 的 severity 是
`dataset_builder.DEFECT_CLASSES` 的八类正则查表得来的（类别 → 固定
severity），不是影响评估。`classify_defect_with_basis` 的 docstring 记录
过 63.2% 是 fallback-default。D6 replay 首次算出
high_severity_recall = 2/18 = 0.11，抽查发现分母本身可疑（httpx-pr-3109
的 4 条 high 实际是类型注解契约变更）。分母不可信时这个比例的绝对值
不必讨论，所以先修分母。

**不覆盖 real-pr-v1.jsonl**：重标结果写独立文件，原字段原样保留，新增
severity_llm/defect_class_llm/label_source。数据集是权威资产，合并要走
人工确认这道闸（同轨道 F 的设计）。

硬超时 + 逐条落盘沿用 run_real_pr_regression_replay.py 的做法，那次全量
replay 单条卡死两小时、进度全丢的教训：urllib 的 timeout 是逐次 socket
读超时，不是总时长上限，服务端间歇性吐字节就永远不触发。
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
from evoagent.reviewer import OpenAICompatibleReviewer  # noqa: E402
from evoagent.severity_labelling import (  # noqa: E402
    CheckpointStore,
    DEFECT_CLASSES,
    LABEL_SOURCE,
    RUBRIC_VERSION,
    SEVERITIES,
    build_judge_payload,
    finding_id,
    normalise_verdict,
    relabel_summary,
)

# rubric 的四步判定顺序写进 prompt。顺序固定是可复现的前提：同一条按
# 不同顺序问会得到不同答案（同 alert-rubric 的"判定顺序，不得调整"）。
JUDGE_SYSTEM_PROMPT = """You are labelling the SEVERITY and DEFECT CLASS of known \
defects in a code review evaluation dataset. You are acting as a careful human \
annotator, not as a code reviewer: the defect locations are GIVEN to you and are \
already confirmed to be real. Your job is to judge HOW SEVERE each one is.

You are given privileged context a normal reviewer would not have: the human's \
ACTUAL fix patch (human_patch) and the fix PR title. Use them - the shape of the \
fix reveals the nature of the defect (adding a lock -> concurrency; adding a check \
-> input validation; changing a comparison operator -> boundary).

Judge severity by IMPACT AND REACHABILITY, never by defect category. Apply these \
steps IN THIS FIXED ORDER and stop at the first match:

1. No externally visible impact? (pure type annotations, docs, log wording, test-only \
code, dead code, or a behaviourally equivalent refactor) -> "low", stop.
2. Can unauthenticated external input directly reach it and cause privilege bypass, \
code execution, data disclosure, or silent data corruption? -> "critical", stop.
3. Security impact requiring a precondition (authenticated user, specific config, a \
race window), OR a crash/hang/wrong-result on a core path? -> "high", stop.
4. Otherwise -> "medium".

Anchors:
- critical: RCE, auth bypass, credential disclosure, cross-user data mixing, \
large-scale silent data loss. NOT "theoretically abusable" with no reachable path.
- high: authenticated privilege escalation, missing TLS/cert verification, panic/hang \
on the core request path, protocol state machine corruption losing requests.
- medium: wrong results off the core path, boundary-condition deviations, resource \
leaks accumulating over time, exceptions on rare inputs.
- low: type annotations, logging, comments, naming, test-only, equivalent refactors.

Do NOT penalise for CWE imprecision - CWE is hierarchical and sibling disputes \
(77/78/89/94/95) measure annotator taste, not defect nature.

Defect class must be one of: %s

Use "no-defect" if the privileged context shows this location is NOT actually a defect \
(e.g. a pure style change the collector misclassified as a bugfix). Do not invent a \
category for a non-defect.

Return JSON only:
{"verdicts":[{"path":"...","start_line":1,"severity":"low|medium|high|critical",\
"defect_class":"...","cwe":"CWE-123","confidence":0.0,"basis":"..."}]}

"basis" must quote specific content from the diff or human_patch. "Based on experience" \
is not acceptable. Return exactly one verdict per entry in locations_to_judge, in the \
same order.""" % ", ".join(DEFECT_CLASSES)


class _HardTimeout(Exception):
    pass


def _call_with_hard_timeout(fn, args, timeout):
    """线程 + join(timeout) 的硬性总时长上限。

    不能靠 urllib 的 timeout：那是逐次 socket 读超时，服务端间歇性吐
    字节时每次 recv() 都在窗口内收到数据，永远不触发。线程杀不掉，
    但 daemon=True 保证它不挡进程退出，超时就弃用这一条。
    """
    box = {}

    def _target():
        try:
            box["value"] = fn(*args)
        except BaseException as exc:  # noqa: BLE001 - 原样传回
            box["error"] = exc

    thread = threading.Thread(target=_target, daemon=True)
    thread.start()
    thread.join(timeout)
    if thread.is_alive():
        raise _HardTimeout("judge 调用超过硬超时 %ss 未返回，强制放弃这一条 case" % timeout)
    if "error" in box:
        raise box["error"]
    return box["value"]


def _judge_case(reviewer, record: dict, hard_timeout: int) -> list:
    """判一条 case 的全部 expected_findings，返回归一化后的 verdict 列表。

    整条 case 一次调用而不是每条 finding 一次：同一个 case 的多条共享
    diff 与 human_patch 上下文，拆开调用会把同一份上下文重复发送 N 次，
    既贵又可能让同 case 的判定互相不一致。
    """
    payload_body = build_judge_payload(record)
    expected = record.get("expected_findings", [])
    payload = {
        "model": reviewer.model,
        "temperature": 0,
        "messages": [
            {"role": "system", "content": JUDGE_SYSTEM_PROMPT},
            {
                "role": "user",
                "content": "Label these %d location(s):\n\n%s" % (
                    len(expected),
                    json.dumps(payload_body, ensure_ascii=False, indent=2),
                ),
            },
        ],
        "response_format": {"type": "json_object"},
    }
    body = _call_with_hard_timeout(reviewer._request_json, (payload,), hard_timeout)
    raw_verdicts = body.get("verdicts") or []
    verdicts = []
    for index, item in enumerate(expected):
        # 按下标对齐（prompt 要求同序同数）。judge 少答了就补一条空的，
        # 让它在 invalid_fields 里显形，而不是静默少一条导致分母悄悄变小。
        raw = raw_verdicts[index] if index < len(raw_verdicts) else {}
        verdict = normalise_verdict(raw)
        verdict["finding_id"] = finding_id(
            record["id"], item["path"], int(item["start_line"]))
        verdict["path"] = item["path"]
        verdict["start_line"] = int(item["start_line"])
        # 原标签在结果里保留：对比要用，且"不覆盖原字段"是硬约束。
        verdict["original_severity"] = item.get("severity")
        verdict["original_defect_class"] = item.get("defect_class")
        verdict["original_cwe"] = item.get("cwe")
        if index >= len(raw_verdicts):
            verdict["invalid_fields"] = list(verdict["invalid_fields"]) + ["missing-verdict"]
        verdicts.append(verdict)
    return verdicts


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", default="datasets/real-pr-v1.jsonl")
    parser.add_argument(
        "--output", default="output/severity-relabel/relabel-v1.json",
        help="汇总结果。**不**写回 real-pr-v1.jsonl——合并要走人工确认。",
    )
    parser.add_argument(
        "--checkpoint", default="",
        help="逐条落盘路径，默认 --output 加 .checkpoint.jsonl。重跑跳过已完成的 case。",
    )
    parser.add_argument(
        "--limit", type=int, default=0,
        help="0 = 不限；花钱之前先用小数字做通路 sanity check",
    )
    parser.add_argument("--timeout", type=int, default=240)
    parser.add_argument(
        "--hard-timeout", type=int, default=0,
        help="单条 case 的硬性总时长上限。0 = 取 --timeout + 60 秒余量。",
    )
    args = parser.parse_args()

    hard_timeout = args.hard_timeout or (args.timeout + 60)
    checkpoint_path = args.checkpoint or (args.output + ".checkpoint.jsonl")

    resolved = Settings.from_env().resolved_llm()
    if not resolved:
        raise SystemExit(
            "未配置 LLM：设置 EVOAGENT_LLM_PROVIDER=deepseek 和 "
            "EVOAGENT_DEEPSEEK_API_KEY 后重跑。"
        )

    reviewer = OpenAICompatibleReviewer(
        base_url=resolved["base_url"], api_key=resolved["api_key"],
        model=resolved["model"], provider=resolved["provider"],
        extra_headers=resolved.get("headers") or {}, timeout=args.timeout,
    )

    records = load_jsonl(args.dataset)
    if args.limit:
        records = records[: args.limit]
    total_findings = sum(len(r.get("expected_findings", [])) for r in records)

    store = CheckpointStore(checkpoint_path)
    print(
        "relabelling %d cases / %d findings with %s [rubric=%s, source=%s, "
        "hard-timeout=%ss, checkpoint=%s]" % (
            len(records), total_findings, resolved["model"], RUBRIC_VERSION,
            LABEL_SOURCE, hard_timeout, checkpoint_path,
        ),
        flush=True,
    )
    if store.done:
        print("resuming: %d cases already in checkpoint" % len(store.done), flush=True)

    for index, record in enumerate(records, start=1):
        case_id = record["id"]
        if case_id in store.done:
            print("  [%d/%d] %s -> cached" % (index, len(records), case_id), flush=True)
            continue
        try:
            verdicts = _judge_case(reviewer, record, hard_timeout)
        except Exception as exc:
            # 失败也落盘：不然重跑会反复撞同一条，而且分母会静默少掉。
            store.append({"case_id": case_id, "error": str(exc)[:500], "verdicts": []})
            print(
                "  [%d/%d] %s -> ERROR %s" % (index, len(records), case_id, str(exc)[:160]),
                flush=True,
            )
            continue
        store.append({"case_id": case_id, "error": None, "verdicts": verdicts})
        shifts = sum(
            1 for v in verdicts if v["severity_llm"] != v["original_severity"]
        )
        print(
            "  [%d/%d] %s -> %d verdicts (%d changed)" % (
                index, len(records), case_id, len(verdicts), shifts),
            flush=True,
        )

    pairs = [v for rec in store.done.values() for v in rec.get("verdicts", [])]
    errors = [
        {"case_id": rec["case_id"], "error": rec["error"]}
        for rec in store.done.values() if rec.get("error")
    ]
    summary = relabel_summary(pairs)
    summary["errored_cases"] = errors
    print(json.dumps(summary, indent=2, ensure_ascii=False, sort_keys=True))

    os.makedirs(os.path.dirname(os.path.abspath(args.output)) or ".", exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as handle:
        json.dump(
            {"summary": summary, "verdicts": pairs}, handle,
            indent=2, ensure_ascii=False, sort_keys=True,
        )
    print("wrote", args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())