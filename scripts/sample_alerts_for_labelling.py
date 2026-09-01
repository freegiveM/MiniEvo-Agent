"""抽一批告警出来人工标注，产出 label 留空的待标注文件。

用法：
  python scripts/sample_alerts_for_labelling.py --round r1 --seed 20260901
  # 隔 >=3 天，用**同一个种子**抽第二轮，并且必须 --blind
  python scripts/sample_alerts_for_labelling.py --round r2 --seed 20260901 \
      --size 40 --blind

标注方式：打开产出的 json，逐条把 "label" 填成 rubric 的四个值之一
（见 docs/alert-rubric.md），判不了的填 unlabelled 而不是硬凑。
填完用 scripts/report_alert_labelling.py 出数。
"""
import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from evoagent.alert_labelling import (  # noqa: E402
    collect_alerts, sample_alerts, save_round,
)


def load_cases(path: str):
    """数据集来源。优先真实 PR 集，没有就退回受控基准。

    退回时会明确打印出来：两个来源的告警分布不同（受控基准只有 6 条
    规则命中），有效告警率的代表性差很多，不能混着看。
    """
    if path and os.path.exists(path):
        with open(path, encoding="utf-8") as handle:
            return [json.loads(line) for line in handle if line.strip()], path
    from evoagent.evaluation_benchmark import generate_controlled_pr_cases
    cases = [item.to_dict() if hasattr(item, "to_dict") else item
             for item in generate_controlled_pr_cases()]
    return cases, "controlled-benchmark"


def build_reviewer(kind: str):
    if kind == "rules":
        from evoagent.reviewer import LocalRuleReviewer
        return LocalRuleReviewer()
    raise SystemExit("未知 reviewer: %s" % kind)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset", default="datasets/real-pr-v1.jsonl")
    parser.add_argument("--reviewer", default="rules", choices=["rules"])
    parser.add_argument("--round", default="r1")
    parser.add_argument("--seed", type=int, required=True,
                        help="两轮重测必须用同一个种子，否则抽的不是同一批")
    parser.add_argument("--size", type=int, default=120)
    parser.add_argument("--stamp", required=True, help="标注日期 YYYY-MM-DD")
    parser.add_argument("--output", default="")
    parser.add_argument("--blind", action="store_true",
                        help="第二轮必须加。产出文件里不带 label/note 字段")
    args = parser.parse_args()

    cases, source = load_cases(args.dataset)
    if source == "controlled-benchmark":
        print("! 没找到 %s，退回受控基准。" % args.dataset)
        print("  受控基准的告警分布窄（规则集只覆盖 6 类），"
              "算出的有效告警率代表性有限，不能与真实 PR 集的数字混看。")

    records = collect_alerts(build_reviewer(args.reviewer), cases)
    print("告警总数 %d，落在标注集范围内 %d"
          % (len(records), sum(1 for item in records if item.in_label_scope)))
    if len(records) < args.size:
        print("! 只有 %d 条，少于目标 %d 条。样本量不足时置信区间很宽，"
              "报数时必须带上 n。" % (len(records), args.size))

    picked = sample_alerts(records, args.size, args.seed)
    output = args.output or "datasets/labelling-%s.json" % args.round
    if args.blind:
        # 盲标产出：直接写剥过的形态，避免标注者顺手打开另一轮的文件。
        for item in picked:
            item.label, item.note = None, ""
    save_round(output, picked, seed=args.seed, round_name=args.round,
               stamp=args.stamp, source=source)
    print("已写出 %d 条到 %s（label 留空，待人工填）" % (len(picked), output))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
