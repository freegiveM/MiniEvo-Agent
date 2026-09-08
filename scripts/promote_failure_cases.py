#!/usr/bin/env python3
"""轨道 F 的提升脚本：已确认的 `failure_case` → `evaluation_cases` 样本。

    # 先只看计划，不写库
    python scripts/promote_failure_cases.py --db evoagent.db \
        --dataset datasets/real-pr-v1.jsonl \
        --clean-dataset datasets/real-pr-clean-v1.jsonl \
        --dry-run

    # 确认之后写库
    python scripts/promote_failure_cases.py --db evoagent.db \
        --dataset datasets/real-pr-v1.jsonl \
        --clean-dataset datasets/real-pr-clean-v1.jsonl \
        --out output/case-promotion/plan.json

`--dry-run` 是默认之外的一个独立开关而不是默认行为：默认写库、靠人记得加
`--dry-run` 的话，第一次跑就会往评测集里塞东西。这里默认 `--dry-run` 为假
但要求显式给 `--out`，两者合起来的效果是"写库的那次一定留下一份计划"，
事后能回答"这条样本凭什么在评测集里"。

`--clean-dataset` 必须显式给：`false_positive` 只能从**本身干净**的源样本
提升（理由见 `evoagent/case_promotion.py` 模块文档）。不给的话那一类会全部
被拒，报告里会写明是因为源样本带种子缺陷——那是个误导的理由，真实原因是
调用方没把负样本语料传进来。
"""
import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from evoagent.case_promotion import apply_promotions, plan_promotions
from evoagent.store import create_store


def _load_dataset(path):
    cases = []
    with open(path, encoding="utf-8") as handle:
        for raw in handle:
            if raw.strip():
                cases.append(json.loads(raw))
    return cases


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", default="evoagent.db")
    parser.add_argument("--dataset", default="datasets/real-pr-v1.jsonl")
    parser.add_argument("--clean-dataset", default="",
                        help="负样本语料；不给则 false_positive 一律无法提升")
    parser.add_argument("--tenant", default="default")
    parser.add_argument("--limit", type=int, default=500)
    parser.add_argument("--name-prefix", default="d6-confirmed")
    parser.add_argument("--dry-run", action="store_true",
                        help="只产出计划，不写 evaluation_cases")
    parser.add_argument("--out", default="",
                        help="计划落盘路径；非 dry-run 时必填")
    args = parser.parse_args()

    if not args.dry_run and not args.out:
        parser.error("--out is required unless --dry-run: a run that writes to "
                     "the evaluation set must leave a plan behind")

    cases = _load_dataset(args.dataset)
    if args.clean_dataset:
        cases.extend(_load_dataset(args.clean_dataset))

    store = create_store("", args.db)
    # 只取未解决的：已解决的反馈说明它对应的缺陷已经被某一版提示词学会了，
    # 再提升成样本不是错的，但那是另一个决定（"回归样本"），不该顺手带上。
    failure_cases = store.list_failure_cases(
        unresolved_only=True, limit=args.limit, tenant_id=args.tenant)

    plan = plan_promotions(failure_cases, cases, name_prefix=args.name_prefix)
    report = {
        "db": args.db,
        "failure_cases_read": len(failure_cases),
        "corpus_cases": len(cases),
        "promoted_count": plan["promoted_count"],
        "refused_count": plan["refused_count"],
        "by_split": plan["by_split"],
        "by_category": plan["by_category"],
        "clean_samples": plan["clean_samples"],
        "refused": plan["refused"],
        "dry_run": bool(args.dry_run),
    }

    if not args.dry_run:
        applied = apply_promotions(store, plan)
        report.update({
            "written_count": applied["written_count"],
            "already_present": len(applied["already_present"]),
            "conflicts": applied["conflicts"],
        })

    if args.out:
        directory = os.path.dirname(args.out)
        if directory:
            os.makedirs(directory, exist_ok=True)
        with open(args.out, "w", encoding="utf-8", newline="\n") as handle:
            json.dump({**report, "plan": plan["promoted"]}, handle,
                      ensure_ascii=False, indent=2)
            handle.write("\n")

    print(json.dumps(report, ensure_ascii=False, indent=2))
    # 名字冲突意味着同一个 candidate_id 这次算出了不同的样本内容，得让调用方
    # 看得出失败。被拒绝的反馈不算失败——那是正常的判定结果。
    return 1 if report.get("conflicts") else 0


if __name__ == "__main__":
    raise SystemExit(main())