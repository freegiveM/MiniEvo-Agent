#!/usr/bin/env python3
"""轨道 H 的两步 CLI：派生待确认候选 → 导入已确认反馈。

    # 第一步：把 D6 回放对成候选，label 留空
    python scripts/import_replay_feedback.py derive \
        --replay output/real-pr-regression/d6-replay.checkpoint.jsonl \
        --dataset datasets/real-pr-v1.jsonl \
        --out datasets/feedback-candidates-d6.json \
        --stamp 2026-09-07

    # 人工填 label（每条候选的 label 字段），然后：
    python scripts/import_replay_feedback.py check \
        --candidates datasets/feedback-candidates-d6.json

    # 第二步：只导入填了确认标签的
    python scripts/import_replay_feedback.py import \
        --candidates datasets/feedback-candidates-d6.json \
        --dataset datasets/real-pr-v1.jsonl --db evoagent.db

人工那一步不必去手改 194 条的嵌套 JSON——在嵌套 JSON 里填 label 最容易填错
位置，而填错位置的表现是一条判定被挂到别人身上。用清单：

    # 确定性抽一小批，渲染成 Markdown 清单
    python scripts/import_replay_feedback.py worksheet \
        --candidates datasets/feedback-candidates-d6.json \
        --out output/feedback-labelling/worksheet-expected.md \
        --kind unmatched_expected --size 30 --seed 20260907

    # 人填完清单里的 label: / note: / rule_id: 之后写回
    python scripts/import_replay_feedback.py apply-worksheet \
        --candidates datasets/feedback-candidates-d6.json \
        --worksheet output/feedback-labelling/worksheet-expected.md

清单只负责让人的那一步快，**不产出任何 label**：一条由程序写出来的 label
是推断结论，而两步之间那道闸门的全部意义就是推断结论不得进 `failure_cases`。

两步之间隔着人不是流程繁琐，是这个仓库已有的口径：自动对出来的差集
不是反馈。理由见 `evoagent/feedback_import.py` 的模块文档。

`--stamp` 必填而不是取当前时间：同一份输入在不同日子跑出不同文件，
就无法验证"这批候选确实来自那次回放"（与 sample_alerts_for_labelling 同因）。
"""
import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from evoagent.evaluation_harness import MATCH_CWE_EXACT, MATCH_TIERS
from evoagent.feedback_import import (
    KIND_UNMATCHED_EXPECTED,
    KIND_UNMATCHED_FINDING,
    KINDS,
    apply_worksheet,
    blind,
    derive_candidates,
    import_confirmed,
    load_candidates,
    load_replay_checkpoint,
    parse_worksheet,
    render_worksheet,
    sample_candidates,
    save_candidates,
    validate_labels,
)
from evoagent.store import create_store


def _load_dataset(path):
    cases = []
    with open(path, encoding="utf-8") as handle:
        for raw in handle:
            if raw.strip():
                cases.append(json.loads(raw))
    return cases


def _derive(args):
    cases = _load_dataset(args.dataset)
    replay = load_replay_checkpoint(args.replay)
    splits = tuple(item.strip() for item in args.splits.split(",") if item.strip())
    candidates = derive_candidates(
        cases, replay, tier=args.tier, line_tolerance=args.line_tolerance,
        splits=splits,
    )
    if args.blind:
        candidates = blind(candidates)
    save_candidates(
        args.out, candidates, source=os.path.basename(args.dataset),
        tier=args.tier, stamp=args.stamp, replay=os.path.basename(args.replay),
    )
    kinds = {
        KIND_UNMATCHED_EXPECTED: sum(
            1 for item in candidates if item["kind"] == KIND_UNMATCHED_EXPECTED),
        KIND_UNMATCHED_FINDING: sum(
            1 for item in candidates if item["kind"] == KIND_UNMATCHED_FINDING),
    }
    missing_excerpt = sum(1 for item in candidates if not item.get("diff_excerpt"))
    print(json.dumps({
        "out": args.out,
        "cases_in_dataset": len(cases),
        "cases_in_replay": len(replay),
        "splits": list(splits),
        "candidates": len(candidates),
        "by_kind": kinds,
        # 定位不到 diff 片段的候选人工无从判断，得单独说，别让它们静静地
        # 变成一批 unlabelled。
        "candidates_without_excerpt": missing_excerpt,
        "next": "填写每条候选的 label，然后跑 check / import",
    }, ensure_ascii=False, indent=2))


def _check(args):
    payload = load_candidates(args.candidates)
    report = validate_labels(payload.get("candidates", []))
    print(json.dumps({
        "total": report["total"],
        "counts": report["counts"],
        "importable": report["importable"],
        "missing_label": len(report["missing_label"]),
        "invalid_label": report["invalid_label"],
    }, ensure_ascii=False, indent=2))
    # 非法标签是"有人填错了"，得让 CI/脚本调用方看得出失败。
    return 1 if report["invalid_label"] else 0


def _import(args):
    payload = load_candidates(args.candidates)
    diffs = {}
    if args.dataset:
        diffs = {str(case["id"]): case.get("diff", "")
                 for case in _load_dataset(args.dataset)}
    store = create_store("", args.db)
    result = import_confirmed(
        store, payload, tenant_id=args.tenant, diffs=diffs)
    print(json.dumps({
        "imported_count": result["imported_count"],
        "categories": result["categories"],
        "skipped_already_imported": len(result["skipped_already_imported"]),
        "skipped_not_feedback": len(result["skipped_not_feedback"]),
        "skipped_unconfirmed": len(result["skipped_unconfirmed"]),
        "rejected": result["rejected"],
    }, ensure_ascii=False, indent=2))
    return 1 if result["rejected"] else 0


def _worksheet(args):
    payload = load_candidates(args.candidates)
    candidates = payload.get("candidates", [])
    picked = sample_candidates(
        candidates, args.size, args.seed,
        kind=args.kind if args.kind != "all" else None,
    )
    text = render_worksheet(payload, picked)
    directory = os.path.dirname(args.out)
    if directory:
        os.makedirs(directory, exist_ok=True)
    with open(args.out, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(text)
    print(json.dumps({
        "out": args.out,
        "candidates_in_pool": len(candidates),
        "sampled": len(picked),
        "seed": args.seed,
        "kind": args.kind,
        # 抽到的这批里有几条定位不到 diff 片段——它们凭清单判不了，得让人
        # 事先知道，别让它们静静地变成一批 unlabelled。
        "sampled_without_excerpt": sum(
            1 for item in picked if not item.get("diff_excerpt")),
        "next": "填写清单里每条的 label，然后跑 apply-worksheet",
    }, ensure_ascii=False, indent=2))


def _apply_worksheet(args):
    payload = load_candidates(args.candidates)
    with open(args.worksheet, encoding="utf-8") as handle:
        parsed = parse_worksheet(handle.read())
    if parsed["problems"]:
        print(json.dumps({
            "problems": parsed["problems"],
            "written": False,
            "why": "清单有问题时不部分写回：部分写回会产出一份看起来标了"
                   "一半的候选文件，而其中有几条的归属是错的",
        }, ensure_ascii=False, indent=2))
        return 1
    result = apply_worksheet(payload, parsed["entries"])
    if result["unknown_candidate_ids"]:
        print(json.dumps({
            "unknown_candidate_ids": result["unknown_candidate_ids"],
            "written": False,
            "why": "清单与候选文件对不上（清单可能来自上一版候选），"
                   "此时其它条目的归属也不可信",
        }, ensure_ascii=False, indent=2))
        return 1
    with open(args.candidates, "w", encoding="utf-8", newline="\n") as handle:
        json.dump(result["payload"], handle, ensure_ascii=False, indent=2)
        handle.write("\n")
    print(json.dumps({
        "candidates": args.candidates,
        "applied": len(result["applied"]),
        "skipped_blank": len(result["skipped_blank"]),
        # 已有标签且与清单不一致：重标是显式动作，不能作为"又跑了一次
        # apply"的副产品发生。
        "conflicts": result["conflicts"],
        "written": True,
        "next": "跑 check，然后 import",
    }, ensure_ascii=False, indent=2))
    return 1 if result["conflicts"] else 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    derive = sub.add_parser("derive", help="派生待人工确认的候选")
    derive.add_argument("--replay", required=True)
    derive.add_argument("--dataset", default="datasets/real-pr-v1.jsonl")
    derive.add_argument("--out", required=True)
    derive.add_argument("--stamp", required=True, help="YYYY-MM-DD，由调用方给定")
    derive.add_argument("--tier", default=MATCH_CWE_EXACT, choices=list(MATCH_TIERS))
    derive.add_argument("--line-tolerance", type=int, default=2)
    # 默认只取 validation：holdout 的反馈进了提示词进化就等于拿隐藏集调参。
    derive.add_argument("--splits", default="validation")
    derive.add_argument("--blind", action="store_true",
                        help="剥掉标注外 finding 候选上的真值线索")

    check = sub.add_parser("check", help="校验人工填的标签")
    check.add_argument("--candidates", required=True)

    sheet = sub.add_parser(
        "worksheet", help="确定性抽一小批，渲染成人能直接填的 Markdown 清单")
    sheet.add_argument("--candidates", required=True)
    sheet.add_argument("--out", required=True)
    # 一小批而不是 194 条：全量标完再说等于让 failure_cases 无限期停在 0 条。
    sheet.add_argument("--size", type=int, default=30)
    # 种子入库式地写进报告，否则第二轮抽不到同一批（与 sample_alerts 同因）。
    sheet.add_argument("--seed", type=int, default=20260907)
    # 两类候选问的问题不同、盲标要求不同，混在一份清单里让人来回切换判据。
    sheet.add_argument("--kind", default=KIND_UNMATCHED_EXPECTED,
                       choices=list(KINDS) + ["all"])

    applier = sub.add_parser(
        "apply-worksheet", help="把填好的清单写回候选文件")
    applier.add_argument("--candidates", required=True)
    applier.add_argument("--worksheet", required=True)

    importer = sub.add_parser("import", help="导入已确认的候选")
    importer.add_argument("--candidates", required=True)
    importer.add_argument("--db", default="evoagent.db")
    importer.add_argument("--tenant", default="default")
    importer.add_argument("--dataset", default="datasets/real-pr-v1.jsonl",
                          help="用于把样本 diff 一并存进 task_payloads")

    args = parser.parse_args()
    if args.command == "derive":
        return _derive(args) or 0
    if args.command == "check":
        return _check(args)
    if args.command == "worksheet":
        return _worksheet(args) or 0
    if args.command == "apply-worksheet":
        return _apply_worksheet(args)
    return _import(args)


if __name__ == "__main__":
    raise SystemExit(main())