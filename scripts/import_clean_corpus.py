#!/usr/bin/env python3
"""把 datasets/real-pr-clean-v1.jsonl 里的干净语料导入 evaluation_cases。

为什么需要这一步：评测集里只有「有缺陷」的样本时，`_score` 里的
`clean_total` 恒为 0，于是误报侧的 0.20 权重和 `clean_accuracy` 的门禁保护
一起静默消失。门禁只从「漏报」一个方向拉候选，飞轮会持续朝「多报」漂——而
所有指标看上去都正常，这比缺一个门禁更危险。

两点必须记住：

1. 干净语料的标签是「缺陷缺席」，是**代理信号**，不是「已验证正确」。语料
   自己的 `source.note` 就是这么写的（180 天观察窗内未见 bugfix 型后续
   提交）。所以 `clean_accuracy` 只能当误报压力的近似量，不能当正确性证明。
2. 干净样本入库会改变 validation 集的构成，`_propose` 落盘的
   `validation_dataset_fingerprint` 因此必然变化。导入前后的分数不可直接
   比较，基线要重跑。

只写库，不改 `datasets/` 下的任何文件。
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from evoagent.evolution import EvolutionEngine
from evoagent.store import TaskStore

DEFAULT_CORPUS = Path("datasets/real-pr-clean-v1.jsonl")
VALID_SPLITS = ("validation", "holdout")


def load_corpus(path: Path) -> list:
    cases = []
    with path.open(encoding="utf-8") as handle:
        for lineno, line in enumerate(handle, 1):
            line = line.strip()
            if not line:
                continue
            try:
                cases.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise SystemExit("%s:%d 不是合法 JSON：%s" % (path, lineno, exc))
    return cases


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", required=True)
    parser.add_argument("--corpus", default=str(DEFAULT_CORPUS))
    parser.add_argument("--limit", type=int, default=0, help="0 表示不限")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    corpus = Path(args.corpus)
    if not corpus.exists():
        raise SystemExit("找不到语料：%s" % corpus)

    cases = load_corpus(corpus)
    store = TaskStore(args.db)

    # 直接查库拿已有 name，不走 list_evaluation_cases：它的 limit 硬封在
    # 500，超过之后去重集合会静默停止增长，于是重复导入变成"看起来成功"。
    with store._connect() as conn:
        seen = {
            row["name"]
            for row in conn.execute("SELECT name FROM evaluation_cases")
        }

    stats = {
        "corpus": str(corpus),
        "total": len(cases),
        "inserted": 0,
        "skipped_duplicate": 0,
        "skipped_not_clean": 0,
        "skipped_bad_split": 0,
        "skipped_unscoreable_diff": 0,
        "by_split": {},
        "dry_run": bool(args.dry_run),
        "rejected": [],
    }

    for case in cases:
        if args.limit and stats["inserted"] >= args.limit:
            break

        # 这个脚本只负责干净语料。带 expected_findings 的样本必须走
        # import_replay_feedback / promote_failure_cases 那条有人工确认闸门
        # 的路，不能从这里绕进来。
        if case.get("expected_findings"):
            stats["skipped_not_clean"] += 1
            continue

        split = case.get("split")
        if split not in VALID_SPLITS:
            stats["skipped_bad_split"] += 1
            continue

        name = str(case.get("id") or "").strip()
        diff = case.get("diff") or ""

        # 走引擎的校验，而不是直接写库：`validate_case` 会拒掉没有新增行、
        # 因此打不出分的 diff。绕过它就是把「取样能取到但评测跑不了」的行
        # 塞进评测集——分母有了，分子永远算不出来。
        try:
            EvolutionEngine.validate_case(name, diff, [], split)
        except ValueError as exc:
            stats["skipped_unscoreable_diff"] += 1
            stats["rejected"].append({"id": name, "reason": str(exc)})
            continue

        # 先查存在性再写。`save_evaluation_case` 对同名同内容的行是幂等的
        # （直接返回已有行），所以光看它的返回值分不出"新插入"和"早就有了"
        # ——重跑会照样报 inserted=78，而表根本没变。一个在无事发生时报告
        # 78 次插入的 loader，比一个报错的 loader 更难发现问题。
        if name in seen:
            stats["skipped_duplicate"] += 1
            continue

        if not args.dry_run:
            try:
                store.save_evaluation_case(
                    name, split, diff, [], "real-pr-clean-v1", True
                )
            except ValueError as exc:
                # 同名但内容不同会抛错（name 不可变）。这不是幂等重跑，是真
                # 冲突，必须报出来而不是当重复跳过。
                stats["rejected"].append({"id": name, "reason": str(exc)})
                continue
        seen.add(name)
        stats["inserted"] += 1
        stats["by_split"][split] = stats["by_split"].get(split, 0) + 1

    # 导入后立刻把分层取样的实际结果打出来。只报「插入了 N 条」不够：干净
    # 样本 id 更大，如果取样仍是平铺的，插进去也照样选不中，分母还是 0。
    for split in VALID_SPLITS:
        for limit in (20, 500):
            selected = store.select_evaluation_cases(split, True, limit)
            clean = sum(1 for row in selected if not row["expected"])
            stats.setdefault("selected", {})["%s@%d" % (split, limit)] = {
                "cases": len(selected),
                "clean_denominator": clean,
            }

    print(json.dumps(stats, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())