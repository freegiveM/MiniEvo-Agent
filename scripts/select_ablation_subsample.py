#!/usr/bin/env python3
"""从 real-pr-v1 + real-pr-clean-v1 里按分层配额抽一批子样本，喂给四臂消融。

## 为什么要分层，不能直接随机抽

四臂消融本身就贵（四种 reviewer 各跑一遍），全量 190 条真实调用一次要好几个小
时。先用小样本探一轮成本和结论方向再决定要不要扩到全量，但随机抽样可能把
positive/clean 或 validation/holdout 的比例抽歪——四臂对照的核心指标（recall、
clean_accuracy）恰恰依赖这两个维度的比例，比例失真会让小样本的结论没法外推到全
量。所以按 (split, is_clean) 四格分层，配额按各格在全量里的占比换算，格内再按仓
库分散，确保「样本量小」不等于「只看到一两个仓库的行为」。

## 为什么写 case id 而不是重新构造 case

`real-pr-v1.jsonl` / `real-pr-clean-v1.jsonl` 里的每条已经是
`evaluation_harness.validate_case` 要求的完整 schema（diff 是真实反转出来的补
丁，expected_findings 的行号是相对这份 diff 算的）。重新拼一份等于要把这套对齐关
系重算一遍，且极容易在字段漂移时悄悄产出跑不过 validate_case 的样本。原样搬运是
唯一不引入新错误面的做法。
"""

from __future__ import annotations

import argparse
import json
import random
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# 全量 190 条里各格的真实占比（split=holdout/validation × 是否 clean）。
# 45 是目标总量，先按占比算配额、四舍五入后再手工核对求和是否接近目标——
# 不动态算是因为这批配额本身就是这次实验设计的一部分，写死才可审计。
QUOTAS = {
    ("holdout", False): 6,
    ("holdout", True): 8,
    ("validation", False): 17,
    ("validation", True): 15,
}


def load(path: Path, is_clean: bool) -> list[dict]:
    cases = []
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            case = json.loads(line)
            case["_is_clean"] = is_clean
            cases.append(case)
    return cases


def stratified_sample(cases: list[dict], seed: int) -> list[dict]:
    by_quota_key: dict[tuple, list[dict]] = defaultdict(list)
    for case in cases:
        key = (case["split"], case["_is_clean"])
        by_quota_key[key].append(case)

    rng = random.Random(seed)
    selected: list[dict] = []
    for key, quota in QUOTAS.items():
        pool = by_quota_key.get(key, [])
        if len(pool) < quota:
            raise SystemExit(
                "quota %s needs %d cases but pool only has %d" % (key, quota, len(pool))
            )
        # 先按仓库分组，轮询取样：保证配额允许的范围内，每个出现过的仓库
        # 至少抽到 1 条，不是纯随机导致某个仓库被抽空。
        by_repo: dict[str, list[dict]] = defaultdict(list)
        for case in pool:
            by_repo[case["repository"]].append(case)
        for repo_cases in by_repo.values():
            rng.shuffle(repo_cases)
        repos = sorted(by_repo)
        rng.shuffle(repos)
        picked: list[dict] = []
        round_robin = list(repos)
        while len(picked) < quota and round_robin:
            next_round = []
            for repo in round_robin:
                if len(picked) >= quota:
                    break
                if by_repo[repo]:
                    picked.append(by_repo[repo].pop())
                if by_repo[repo]:
                    next_round.append(repo)
            round_robin = next_round
        selected.extend(picked)
    return selected


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--positive", default=str(ROOT / "datasets" / "real-pr-v1.jsonl")
    )
    parser.add_argument(
        "--clean", default=str(ROOT / "datasets" / "real-pr-clean-v1.jsonl")
    )
    parser.add_argument("--seed", type=int, default=20260910)
    parser.add_argument(
        "--out", default=str(ROOT / "output" / "ablation-pilot" / "subset.jsonl")
    )
    args = parser.parse_args()

    cases = load(Path(args.positive), False) + load(Path(args.clean), True)
    selected = stratified_sample(cases, args.seed)

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8", newline="\n") as handle:
        for case in selected:
            case.pop("_is_clean", None)
            handle.write(json.dumps(case, ensure_ascii=False) + "\n")

    summary = defaultdict(lambda: defaultdict(int))
    for case in selected:
        clean = not case["expected_findings"]
        summary[(case["split"], clean)][case["repository"]] += 1
    print(json.dumps({
        "total": len(selected),
        "by_quota": {
            "%s/%s" % (split, "clean" if clean else "positive"): dict(repos)
            for (split, clean), repos in sorted(summary.items())
        },
        "out": str(out_path),
    }, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
