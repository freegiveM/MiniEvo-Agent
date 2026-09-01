#!/usr/bin/env python
"""生成变异测试评测集。

    python scripts/build_mutation_dataset.py --per-operator 20

为什么变异源码用**本仓库自己的代码**：变异 Oracle 测的是"agent 能不能
看出一处注入的逻辑缺陷"，源码是什么项目不影响这个能力的测量，而用自己的
代码省掉了一整套外部仓库下载与许可问题。它和反转修复 PR 数据集是互补关系：
后者提供真实缺陷分布，前者提供强标注 + 可控难度。

两个数据集**分开报，不合并成一个召回率**：变异算子产出的缺陷几乎全是
logic-boundary 一类，碰不到 crypto-weak / injection / secret-exposure。
合并会让总体数字随两边样本量配比漂移，那个配比是人为选的。
"""
import argparse
import glob
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from evoagent.mutation_oracle import (          # noqa: E402
    build_mutation_dataset, equivalence_summary,
)
from evoagent.evaluation_harness import validate_case      # noqa: E402

DEFAULT_OUTPUT = "datasets/mutation-v1.jsonl"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-glob", default="evoagent/*.py")
    parser.add_argument("--per-operator", type=int, default=20,
                        help="每个算子取多少条。配额取样，不是一路取满。")
    parser.add_argument("--output", default=DEFAULT_OUTPUT)
    parser.add_argument("--split", default="holdout",
                        choices=("train", "validation", "holdout"))
    parser.add_argument("--no-equivalence-check", action="store_true",
                        help="跳过差分执行（快，但所有标签都是未证明）")
    args = parser.parse_args()
    return run(args)


def run(args) -> int:
    paths = sorted(glob.glob(args.source_glob))
    # 排除测试文件：往测试代码里注入缺陷，"正确形态"是测试自己的断言，
    # 审查语义完全不同。
    paths = [path for path in paths
             if "test" not in os.path.basename(path)]
    sources = []
    for path in paths:
        with open(path, encoding="utf-8") as handle:
            sources.append((path.replace("\\", "/"), handle.read()))
    if not sources:
        print("no sources matched %s" % args.source_glob)
        return 1
    print("源文件 %d 个" % len(sources))

    cases = build_mutation_dataset(
        sources, per_operator=args.per_operator, split=args.split,
        check=not args.no_equivalence_check,
    )
    for index, case in enumerate(cases, 1):
        # 自己的产出也过一遍公共校验：合成逻辑写错时要在这里就炸，
        # 不要等到评测阶段才发现样本不合法。
        validate_case(case, index)

    directory = os.path.dirname(args.output)
    if directory:
        os.makedirs(directory, exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as handle:
        for case in cases:
            handle.write(json.dumps(case, ensure_ascii=False) + "\n")

    summary = equivalence_summary(cases)
    print("样本 %d 条 → %s" % (len(cases), args.output))
    print("等价性三档：", json.dumps(summary["by_status"], ensure_ascii=False))
    suspect = summary["suspect_rate"]
    print("可疑率（跑过差分执行、但没测出行为差异的占比）：%s" % (
        "n/a（一条都没跑过，没有结论）" if suspect is None
        else "%.1f%%" % (100.0 * suspect)))
    print("分算子：")
    for name in sorted(summary["by_operator"]):
        bucket = summary["by_operator"][name]
        print("  %-22s 共 %3d  已证明 %3d  无差异 %3d" % (
            name, bucket["total"], bucket["proven"], bucket["no-difference"]))
    if suspect is not None and suspect > 0.5:
        # 不 fail，只提示：可疑率高说明这批样本标签可信度存疑，
        # 但那是读数时要带上的限制，不是构建失败。
        print("\n注意：可疑率过半。这批样本里可能有相当比例的等价变异体，")
        print("      也就是标签为假。报召回率时必须带上这个限制。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
