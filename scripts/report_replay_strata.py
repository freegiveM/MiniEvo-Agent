"""把 D6 replay 的 173 条结果按三个维度分档重算，**零 API 调用**。

    python scripts/report_replay_strata.py

## 为什么这个脚本必须存在

`datasets/README.md` 第二节花了整节论证污染问题（引 arXiv:2506.12286、
SWE-bench Verified 停用、SWE-bench-Live 的立项前提），并明文承诺"按模型
知识截止切两个子集，**分别报数**"。

实际上 `contamination_split` 这个字段只在 `dataset_builder.py` 和
`collect_reverted_fix_dataset.py` 里出现——构造时算了，**评测侧一次都没
用过**。D6 报出来的每一个数都是 pre+post 混在一起的。

这是全项目最大的一处"说了没做"。而补上它不需要任何新的 API 调用：
`d6-replay.checkpoint.jsonl` 里存着全部 173 条的原始 findings。

## 为什么复用 RegressionEvaluator 而不是自己算

自己重写一遍混淆矩阵，就会有第二把尺子——行容差、nearest-first 配对、
severity 门槛任何一处对不上，分档数字就无法与 D6 总体数字相互解释。
这正是上一轮"两把尺子"问题的教训。这里把 checkpoint 包装成一个假
reviewer 喂回同一个 evaluator，尺子在定义上完全一致。

验证方式：不加任何过滤跑一次，结果必须与 d6-replay.json 逐字段相等。
脚本会自己做这个断言（`--verify`，默认开）。

## 分档口径

- `contamination`：pre-cutoff（可能被记忆）vs post-cutoff（干净）
- `split`：validation vs holdout（holdout 的意义在于没被看过，
  混进 validation 一起报，这个意义就消失了）
- `sample`：positive vs clean（正样本给 precision/recall，
  负样本给 clean_accuracy，两者的分母本来就不是一回事）

每一档都带 Wilson 区间。分档必然让分母变小、区间变宽——这是如实反映，
不是缺陷。区间宽到跨过对比档位就说明**这个分档比较得不出结论**，
必须这样报，不能只报点估计让读者以为有差异。
"""
import argparse
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from evoagent.evaluation_harness import load_jsonl  # noqa: E402
from evoagent.evolution import RegressionEvaluator  # noqa: E402
from evoagent.models import Finding, Severity  # noqa: E402

# 与 run_real_pr_regression_replay.py 的 _to_case 保持一致。不 import 是
# 因为那个模块在 import 时会要求 LLM 配置；这里刻意不需要任何凭据。
def _to_case(record: dict) -> dict:
    expected = [
        {
            "path": item["path"],
            "line": int(item["start_line"]),
            "end_line": int(item.get("end_line", item["start_line"])),
            "rule_id": item.get("rule_id", ""),
            "min_severity": item.get("severity", "low"),
        }
        for item in record["expected_findings"]
    ]
    return {
        "id": record["id"],
        "name": record["id"],
        "diff": record["diff"],
        "expected": expected,
        # 分档键。evaluator 不认识这几个字段，原样带着走。
        "split": record["split"],
        "contamination": record["contamination_split"],
        "sample": "clean" if not expected else "positive",
        "repository": record["repository"],
    }


class ReplayCache:
    """把 checkpoint 里存好的 findings 当成一个 reviewer 重放。

    不发任何网络请求。找不到对应 case 时抛异常而不是返回空列表——
    返回空会被 evaluator 记成"全漏报"，与"这条根本没跑过"长得一模一样，
    正是上一轮在测试里堵掉的那类"因为错误的原因而看起来正常"。
    """

    name = "replay-cache"

    def __init__(self, cache: dict):
        self._cache = cache
        self._case_id = None

    def bind(self, case_id: str) -> "ReplayCache":
        self._case_id = case_id
        return self

    def review(self, _diff, _parsed):
        record = self._cache.get(self._case_id)
        if record is None:
            raise KeyError("checkpoint 里没有 %s" % self._case_id)
        return [
            Finding(
                rule_id=item.get("rule_id", ""),
                severity=Severity(item["severity"]),
                title=item.get("title", ""),
                explanation=item.get("explanation", ""),
                path=item["path"],
                line=int(item["line"]),
                evidence=item.get("evidence", ""),
                fix=item.get("fix", ""),
                test=item.get("test", ""),
            )
            for item in record.get("findings") or []
        ]


def _evaluate(cases: list, cache: dict) -> dict:
    """跑一批 case。每条 case 绑定自己的 cache 条目后交给同一个 evaluator。"""
    reviewer = ReplayCache(cache)

    # evaluator 每次 run() 调一次 factory，而我们需要 per-case 绑定，
    # 所以逐条 run 再自己汇总会引入第二把尺子。改为让 factory 返回一个
    # 按 case 名查表的 reviewer：evaluator 传给 review() 的是 diff，
    # 我们用 diff 反查不了 id——所以改用 case 顺序绑定。
    class _Sequential:
        name = "replay-cache"

        def __init__(self):
            self._index = 0

        def review(self, diff, parsed):
            case = cases[self._index]
            self._index += 1
            return reviewer.bind(case["id"]).review(diff, parsed)

    return RegressionEvaluator(lambda _prompt: _Sequential()).run("", cases)


def _slim(metrics: dict) -> dict:
    """只留下报数要用的字段，去掉 173 条明细。

    刻意按字段名丢，不按类型丢：`*_ci` 区间本身就是 list，
    "丢掉所有 list" 会把区间一起丢掉——而区间正是分档报数的重点。
    """
    return {
        key: value for key, value in metrics.items()
        if key != "case_results"
    }


def _fmt(value) -> str:
    return "—" if value is None else ("%.4f" % value)


def _fmt_ci(ci) -> str:
    return "—" if not ci else "[%.3f, %.3f]" % (ci[0], ci[1])


def _row(label: str, metrics: dict, key: str) -> str:
    return "| %s | %s | %s |" % (
        label, _fmt(metrics.get(key)), _fmt_ci(metrics.get(key + "_ci")),
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--positive", default="datasets/real-pr-v1.jsonl")
    parser.add_argument("--clean", default="datasets/real-pr-clean-v1.jsonl")
    parser.add_argument(
        "--checkpoint",
        default="output/real-pr-regression/d6-replay.checkpoint.jsonl",
    )
    parser.add_argument(
        "--baseline", default="output/real-pr-regression/d6-replay.json",
        help="用于校验：不分档重算的结果必须与它逐字段相等",
    )
    parser.add_argument(
        "--output", default="output/real-pr-regression/d6-strata.json",
    )
    args = parser.parse_args()

    cache = {}
    with open(args.checkpoint, encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if line:
                record = json.loads(line)
                cache[record["id"]] = record

    cases = [_to_case(item) for item in load_jsonl(args.positive)]
    cases += [_to_case(item) for item in load_jsonl(args.clean)]
    print("载入 %d 条 case，checkpoint %d 条" % (len(cases), len(cache)))

    overall = _evaluate(cases, cache)

    # 尺子一致性校验。分档数字若与总体口径不同，两边就不能相互解释。
    if args.baseline and os.path.exists(args.baseline):
        with open(args.baseline, encoding="utf-8") as handle:
            baseline = json.load(handle)
        mismatch = [
            key for key in
            ("precision", "recall", "f1", "severity_accuracy",
             "high_severity_recall", "clean_accuracy", "score", "cases")
            if overall.get(key) != baseline.get(key)
        ]
        if mismatch:
            raise SystemExit(
                "重算结果与 %s 不一致，字段：%s。分档数字在尺子对齐前不可信，"
                "先查 _to_case 与 replay 脚本是否已经分叉。"
                % (args.baseline, mismatch)
            )
        print("[OK] 尺子校验通过：不分档重算与 d6-replay.json 逐字段相等")

    strata = {"overall": _slim(overall)}
    for dimension in ("contamination", "split", "sample"):
        buckets = {}
        for case in cases:
            buckets.setdefault(case[dimension], []).append(case)
        strata[dimension] = {
            name: _slim(_evaluate(subset, cache))
            for name, subset in sorted(buckets.items())
        }

    os.makedirs(os.path.dirname(os.path.abspath(args.output)) or ".", exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as handle:
        json.dump(strata, handle, ensure_ascii=False, indent=2)

    for dimension in ("contamination", "split", "sample"):
        print("\n=== %s ===" % dimension)
        print("| 档 | n | precision | recall | high_sev_recall | clean_acc |")
        print("|---|---|---|---|---|---|")
        for name, metrics in strata[dimension].items():
            print("| %s | %d | %s %s | %s %s | %s %s | %s %s |" % (
                name, metrics["cases"],
                _fmt(metrics["precision"]), _fmt_ci(metrics["precision_ci"]),
                _fmt(metrics["recall"]), _fmt_ci(metrics["recall_ci"]),
                _fmt(metrics["high_severity_recall"]),
                _fmt_ci(metrics["high_severity_recall_ci"]),
                _fmt(metrics["clean_accuracy"]), _fmt_ci(metrics["clean_accuracy_ci"]),
            ))
    print("\n写入 %s" % args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())