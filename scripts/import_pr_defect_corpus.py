#!/usr/bin/env python3
"""把缺陷语料导入 evaluation_cases（默认 datasets/real-pr-v1.jsonl）。

为什么需要这一步：第 17 节给误报侧补上分母之后，holdout 里只剩 **1 条**
缺陷样本（`holdout-security-shell-execution`）。后果是 `recall` 只有一个
步长——它要么 0.0 要么 1.0，测不出任何东西。而 `holdout_non_regression`
是参与 `decision` 的四道门之一，它现在形同虚设。

这与第 17 节修的是同一种病：**一道假装在工作的门禁**。区别只是那次的
分母是 0（`clean_accuracy` 直接消失），这次的分母是 1（指标照常打印，
但读数没有信息量）。

## 两批语料，两个 --source 标签

`real-pr-v1` 的 holdout **全是 medium**（实测 40 条期望、0 条
high/critical）。所以只导它能修好 `recall` 的步长，却修不了
`high_severity_recall`——那也是参与 decision 的四道受保护指标之一。
补 high/critical 要另一批：

```bash
# 1) 真实 PR 缺陷，修 recall 的步长
python scripts/import_pr_defect_corpus.py --db <path>

# 2) 变异语料的 weakened-guard 算子，补 high 档
python scripts/import_pr_defect_corpus.py --db <path> \
    --corpus datasets/mutation-v1.jsonl --source mutation-v1 \
    --skip-suspect-labels
```

**两批必须用不同的 `--source` 标签。** 它们的标签可信度不是一个档次，
事后要能分开看、也要能整批移除；混成一个来源就再也拆不开了。

## 只导 holdout

默认 `--split holdout`，因为 validation 侧已经有 23 条缺陷样本，不缺。
更重要的是**不能两边都导**：`real-pr-v1` 的 validation 与 holdout 是同一
批采集里切开的，把它的 validation 也灌进来不会增加独立信号，只会让
holdout 与 validation 的相关性升高，而 holdout 的全部意义就是独立。

## 标签口径

语料的 `expected_findings` 用 `start_line`/`end_line`/`severity`，
`evaluation_cases` 用 `line`/`end_line`/`min_severity`。这里做映射，
`severity` 直接当 `min_severity`——语料的 severity 是"这个缺陷至少有多
严重"，与 `min_severity` 语义一致。

## 三点必须记住

1. `real-pr-v1` 的 `source.note` 自己写明："Buggy code is real (it existed
   in repository history), but the 'incoming PR' framing is synthetic.
   Positive rate is inflated by construction; not comparable to organic PR
   benchmarks." 所以它撑得起 recall 的步长，但**不能**用它的绝对正例率去
   推断线上表现。
2. 变异语料的标签分三档可信度。`--skip-suspect-labels` 只挡
   `no-difference`（跑过差分执行却没测出行为差异，假标签集中在这里）；
   `not-attempted` 保留——那只是没探到，不是证否。**这批 20 条 high 样本
   全部来自 weakened-guard 一个算子**，所以 `high_severity_recall` 之后
   测的其实是"对减弱守卫这一类变异的敏感度"，不是泛化的高危召回。
3. 导入会改变 holdout 集的构成，`_propose` 落盘的
   `holdout_dataset_fingerprint` 因此必然变化。导入前后的分数不可直接
   比较，基线要重跑。

只写库，不改 `datasets/` 下的任何文件。
"""

from __future__ import annotations

import argparse
import collections
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from evoagent.evolution import EvolutionEngine
from evoagent.store import TaskStore

DEFAULT_CORPUS = Path("datasets/real-pr-v1.jsonl")
VALID_SPLITS = ("validation", "holdout")
HIGH_SEVERITIES = ("high", "critical")


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


def to_expected(findings: list) -> list:
    """把语料的 expected_findings 映射成 evaluation_cases 的 expected 口径。

    `end_line` 必须带上：`RegressionEvaluator` 按 [line, end_line] 区间配
    对，只给 start_line 会把"报在缺陷区间中段"误判成漏报。
    """
    expected = []
    for finding in findings:
        start = int(finding["start_line"])
        expected.append({
            "path": str(finding["path"]),
            "line": start,
            "end_line": int(finding.get("end_line", start)),
            "min_severity": str(finding.get("severity", "low")).lower(),
            "cwe": str(finding.get("cwe", "")),
        })
    return expected


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", required=True)
    parser.add_argument("--corpus", default=str(DEFAULT_CORPUS))
    parser.add_argument(
        "--split", default="holdout", choices=VALID_SPLITS,
        help="只导语料里这个 split 的样本（默认 holdout，理由见模块 docstring）",
    )
    parser.add_argument("--limit", type=int, default=0, help="0 表示不限")
    parser.add_argument(
        "--source", default="real-pr-v1",
        help="写进 evaluation_cases.source 的来源标签。不同语料必须给不同"
             "标签，否则事后分不出哪批样本的标签可信度更低、也无法整批移除。",
    )
    parser.add_argument(
        "--skip-suspect-labels", action="store_true",
        help="跳过 equivalence_status == 'no-difference' 的样本。变异语料里"
             "这一档跑过差分执行却没测出任何行为差异，假标签集中在这里"
             "（见 mutation_oracle.equivalence_summary 的 suspect_rate）。"
             "把它们当缺陷样本会凭空压低 recall，而压低量方向未知。",
    )
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
        "target_split": args.split,
        "source": args.source,
        "total": len(cases),
        "inserted": 0,
        "skipped_duplicate": 0,
        "skipped_other_split": 0,
        "skipped_not_defect": 0,
        "skipped_suspect_label": 0,
        "skipped_unscoreable_diff": 0,
        "dry_run": bool(args.dry_run),
        "rejected": [],
    }
    severities: collections.Counter = collections.Counter()

    for case in cases:
        if args.limit and stats["inserted"] >= args.limit:
            break

        if case.get("split") != args.split:
            stats["skipped_other_split"] += 1
            continue

        # 这个脚本只负责缺陷语料。没有 expected_findings 的样本要走
        # import_clean_corpus.py——两条路的标签语义完全不同（"缺陷缺席"是
        # 代理信号），混在一个脚本里会让来源分不清。
        findings = case.get("expected_findings") or []
        if not findings:
            stats["skipped_not_defect"] += 1
            continue

        # 变异语料的标签可信度分三档。`no-difference` = 跑过差分执行、却
        # 没测出任何行为差异，假标签集中在这里。把它当缺陷样本会凭空压低
        # recall，而压低多少方向未知——那比样本少更糟：分母有了，读数带
        # 着一个不可知的偏差。`not-attempted` 保留（只是没探到，不是证否）。
        if args.skip_suspect_labels:
            if str(case.get("equivalence_status", "")) == "no-difference":
                stats["skipped_suspect_label"] += 1
                continue

        name = str(case.get("id") or "").strip()
        diff = case.get("diff") or ""
        expected = to_expected(findings)

        # 走引擎的校验，而不是直接写库：`validate_case` 会拒掉期望位置
        # 不在新增行上的样本。绕过它就是把"取样能取到但永远算作漏报"的
        # 行塞进评测集——那会把 recall 压到一个与 reviewer 无关的上限。
        try:
            EvolutionEngine.validate_case(name, diff, expected, args.split)
        except ValueError as exc:
            stats["skipped_unscoreable_diff"] += 1
            stats["rejected"].append({"id": name, "reason": str(exc)})
            continue

        if name in seen:
            stats["skipped_duplicate"] += 1
            continue

        if not args.dry_run:
            try:
                store.save_evaluation_case(
                    name, args.split, diff, expected, args.source[:120], True
                )
            except ValueError as exc:
                # 同名但内容不同会抛错（name 不可变）。这不是幂等重跑，是真
                # 冲突，必须报出来而不是当重复跳过。
                stats["rejected"].append({"id": name, "reason": str(exc)})
                continue
        seen.add(name)
        stats["inserted"] += 1
        for item in expected:
            severities[item["min_severity"]] += 1

    stats["inserted_severities"] = dict(severities)

    # 导入后立刻把分层取样的实际结果打出来。只报"插入了 N 条"不够：
    # 取样有份额上限，插进去和选得中是两回事。
    for split in VALID_SPLITS:
        for limit in (20, 500):
            selected = store.select_evaluation_cases(split, True, limit)
            defect = [row for row in selected if row["expected"]]
            high = sum(
                1 for row in defect
                if any(
                    str(item.get("min_severity", "")).lower() in HIGH_SEVERITIES
                    for item in row["expected"]
                )
            )
            stats.setdefault("selected", {})["%s@%d" % (split, limit)] = {
                "cases": len(selected),
                "defect_denominator": len(defect),
                "clean_denominator": len(selected) - len(defect),
                # `high_severity_recall` 是参与 decision 的四道受保护指标
                # 之一。它的分母单独报：为 0 时这道门禁恒通过而报告上看不
                # 出，为 1 时读数只有两档、同样没有信息量。
                "high_severity_denominator": high,
            }

    print(json.dumps(stats, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())