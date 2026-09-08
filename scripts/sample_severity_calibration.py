"""抽一批重标结果出来人工校准，产出 judge 判定已剥离的待判文件。

    # 抽样（每个新 severity 桶 10 条，种子入库保证可复现）
    python scripts/sample_severity_calibration.py --seed 20260905

    # 人工填完 severity_human 后出数
    python scripts/sample_severity_calibration.py --report \
        --input output/severity-relabel/calibration-v1.json

判定方式：打开产出的 json，逐条按 docs/severity-rubric.md 的四步顺序填
`severity_human`（low/medium/high/critical），判不动的**留 None** 而不是
硬凑——硬凑出来的一致率没有意义。`defect_class_human` 选填。

## 这个脚本判的是什么

不是"judge 答得对不对"，是"judge 的档位和人的档位对不对得上"。所以
人工看到的上下文与 judge 完全一致（同一份 human_patch + diff）：多给
会让一致率虚高（人有 judge 没有的信息还判一样，说明什么都不说明），
少给测的是另一个问题（人在信息更少的情况下能不能重现）。

## 门禁

κ ≥ 0.6 **且**原始一致率 ≥ 0.85 才允许在报告里写"LLM 标注，人工抽查
校准一致率 x%"。仍不得简写成"人工标注数据集"。未达标只能写"LLM 重标，
未通过人工校准"，且不得用于门禁。

两条同时要求的理由：原标签分布里 147/165 是 medium，一个常量猜测器就能
拿到约 0.89 的原始一致率——单看一致率无法区分"judge 判得准"和"两边
都在猜同一个众数"。κ 扣掉这部分期望。反过来 κ 单独达标也可能建立在
少数极端档位上，所以两条并列。
"""
import argparse
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from evoagent.evaluation_harness import load_jsonl  # noqa: E402
from evoagent.severity_labelling import (  # noqa: E402
    SEVERITIES,
    blind_for_calibration,
    calibration_report,
    stratified_calibration_sample,
)


def _load_verdicts(path: str) -> list:
    with open(path, encoding="utf-8") as handle:
        payload = json.load(handle)
    return payload.get("verdicts") or []


def _sample(args: argparse.Namespace) -> int:
    verdicts = _load_verdicts(args.relabel)
    picked = stratified_calibration_sample(
        verdicts, per_bucket=args.per_bucket, seed=args.seed,
    )

    # 把 judge 看过的同一份上下文补给人工。verdict 记录里只有定位，
    # 光凭 path+行号判不了严重度。上下文必须**完全一致**：多给会让
    # 一致率虚高（人拿着 judge 没有的信息判出一样，说明不了 judge 准），
    # 少给测的是另一个问题（人在更少信息下能不能重现）。
    context = {}
    for record in load_jsonl(args.dataset):
        context[record["id"]] = {
            "repository": record.get("repository", ""),
            "fix_pr_title": record.get("fix_pr_title", ""),
            "human_patch": record.get("human_patch", ""),
            "diff_under_review": record.get("diff", ""),
        }

    counts = {name: 0 for name in SEVERITIES}
    for item in picked:
        counts[item["severity_llm"]] = counts.get(item["severity_llm"], 0) + 1
    print("抽出 %d 条（源 %d 条）：%s" % (len(picked), len(verdicts), counts))
    for name in SEVERITIES:
        if counts[name] < args.per_bucket:
            # 不静默：桶不足会让那一档的一致率建立在极少样本上，报数时
            # 必须带上 n。v1 的 critical 只有 1 条，这一行一定会打印。
            print("! %s 桶只有 %d 条，少于目标 %d。这一档的一致率 n 很小，"
                  "报数时必须带上 n，不能只报比例。"
                  % (name, counts[name], args.per_bucket))

    if os.path.exists(args.output) and not args.force:
        # 抽样文件里可能已经有人工填好的判定，覆盖等于把人工劳动删掉。
        raise SystemExit(
            "%s 已存在。人工判定可能已写在里面，不覆盖。"
            "确认要重抽请加 --force，或换 --output。" % args.output
        )

    items = []
    missing_context = 0
    for verdict in picked:
        item = blind_for_calibration(verdict)
        # finding_id 是 "case_id|path|line"，case_id 里本身可能不含 "|"。
        case_id = str(verdict.get("finding_id", "")).split("|")[0]
        found = context.get(case_id)
        if found is None:
            missing_context += 1
        item["context"] = found or {}
        items.append(item)
    if missing_context:
        print("! %d 条在 %s 里找不到对应 case，上下文为空——这几条判不了，"
              "留 None。" % (missing_context, args.dataset))

    payload = {
        "seed": args.seed,
        "per_bucket": args.per_bucket,
        "source": args.relabel,
        "dataset": args.dataset,
        "stamp": args.stamp,
        # 剥离在工具层完成：产出文件里根本不含 judge 的 severity/basis，
        # 标注者不需要自觉，也没法不小心瞄到。
        "items": items,
    }
    os.makedirs(os.path.dirname(os.path.abspath(args.output)) or ".", exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, ensure_ascii=False, indent=2)
    print("已写出 %s（severity_human 留空，待人工填）" % args.output)
    print("填完跑：python scripts/sample_severity_calibration.py --report "
          "--input %s" % args.output)
    return 0


def _report(args: argparse.Namespace) -> int:
    with open(args.input, encoding="utf-8") as handle:
        filled = json.load(handle)
    # judge 的判定不在人工文件里（被剥掉了），按 finding_id 从重标结果
    # 回连——这样人工文件从头到尾都不含 judge 答案。
    by_id = {item["finding_id"]: item for item in _load_verdicts(args.relabel)}
    pairs = []
    missing = 0
    for item in filled.get("items", []):
        source = by_id.get(item.get("finding_id"))
        if source is None:
            missing += 1
            continue
        pairs.append({
            "severity_human": item.get("severity_human"),
            "severity_llm": source.get("severity_llm"),
        })
    if missing:
        print("! %d 条在 %s 里找不到对应 finding_id，已跳过。"
              "两个文件可能来自不同轮次的重标。" % (missing, args.relabel))

    report = calibration_report(pairs)
    report["seed"] = filled.get("seed")
    print(json.dumps(report, ensure_ascii=False, indent=2))

    unjudged = report["sampled"] - report["judged_by_human"]
    if unjudged:
        print("\n! %d 条人工未判，未计入分母。占比高说明 rubric 覆盖不足，"
              "这个一致率能说明的事情有限。" % unjudged)
    if report["meets_gate"] is None:
        print("\n判定：样本不足或 κ 无定义，**没有结论**（不是未达标）。")
    elif report["meets_gate"]:
        print("\n判定：达标。可写「%s」。仍不得简写成「人工标注数据集」。"
              % report["claim_allowed"])
    else:
        print("\n判定：未达标。只能写「%s」。" % report["claim_allowed"])

    if args.output:
        with open(args.output, "w", encoding="utf-8") as handle:
            json.dump(report, handle, ensure_ascii=False, indent=2)
        print("报告写入 %s" % args.output)
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--relabel", default="output/severity-relabel/relabel-v1.json",
        help="LLM 重标结果，抽样与出数都从这里读 judge 的判定",
    )
    parser.add_argument(
        "--dataset", default="datasets/real-pr-v1.jsonl",
        help="给人工看的上下文来源，必须与 judge 当时用的是同一份",
    )
    parser.add_argument("--report", action="store_true", help="出数模式")
    parser.add_argument(
        "--input", default="output/severity-relabel/calibration-v1.json",
        help="出数模式：人工填好的抽样文件",
    )
    parser.add_argument(
        "--output", default="",
        help="抽样模式的产出路径；出数模式下可选，指定则把报告也落盘",
    )
    parser.add_argument(
        "--seed", type=int, default=0,
        help="抽样种子。入库保证可复现——加大 --per-bucket 时同种子下"
             "已抽中的条目仍会被抽中，两批结果可以合并",
    )
    parser.add_argument("--per-bucket", type=int, default=10)
    parser.add_argument("--stamp", default="", help="抽样日期 YYYY-MM-DD")
    parser.add_argument("--force", action="store_true",
                        help="允许覆盖已存在的抽样文件（会丢掉已填的人工判定）")
    args = parser.parse_args()

    if args.report:
        return _report(args)
    args.output = args.output or "output/severity-relabel/calibration-v1.json"
    if not args.seed:
        raise SystemExit("--seed 必填：种子入库才能复现这一批抽样。")
    return _sample(args)


if __name__ == "__main__":
    raise SystemExit(main())