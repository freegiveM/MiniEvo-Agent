"""读标注文件出数：有效告警率，以及两轮的重测一致率。

用法：
  python scripts/report_alert_labelling.py datasets/labelling-r1.json
  python scripts/report_alert_labelling.py datasets/labelling-r1.json \
      --retest datasets/labelling-r2.json
"""
import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from evoagent.alert_labelling import (  # noqa: E402
    LABEL_UNLABELLED, effective_alert_rate, load_round, retest_summary,
)


def _fmt(value) -> str:
    """None 打印成 n/a 而不是 0.00。

    两者含义相反：0.00 是"量过了，一条都没有"（结论），
    n/a 是"没有样本，得不出结论"。打成同一个样子就分不出来了。
    """
    return "n/a" if value is None else "%.4f" % value


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("round_one")
    parser.add_argument("--retest", default="")
    args = parser.parse_args()

    payload = load_round(args.round_one)
    labels = [item.get("label") or LABEL_UNLABELLED
              for item in payload["alerts"]]
    summary = effective_alert_rate(labels)

    print("rubric 版本 %s | 来源 %s | 标注于 %s"
          % (payload.get("rubric_version"), payload.get("source"),
             payload.get("labelled_at")))
    print("样本 n=%d，可判 %d" % (summary["total"], summary["judgeable"]))
    for label, count in summary["counts"].items():
        print("  %-16s %d" % (label, count))
    print("有效告警率(valid+noise/可判)  %s"
          % _fmt(summary["effective_alert_rate"]))
    print("严格有效率(valid/可判)        %s" % _fmt(summary["strict_valid_rate"]))
    print("判不了占比(unlabelled/总数)   %s" % _fmt(summary["unlabelled_share"]))
    if summary["judgeable"] and summary["judgeable"] < 100:
        print("! 可判样本 %d < 100，置信区间宽，这个数只能当量级看"
              % summary["judgeable"])

    if args.retest:
        if not os.path.exists(args.retest):
            print("! 找不到第二轮文件 %s" % args.retest)
            return 1
        retest = retest_summary(payload, load_round(args.retest))
        print("\n-- test-retest --")
        print("配对 %d 条，未配对 %d 条"
              % (retest["paired"], len(retest["unpaired"])))
        if retest["unpaired"]:
            print("! 两轮抽的不是同一批（种子或数据集变了），"
                  "一致率算的是交集，代表性已经变了")
        print("原始一致率        %s" % _fmt(retest["raw_agreement"]))
        print("Cohen's kappa     %s" % _fmt(retest["cohens_kappa"]))
        print("两轮都可判的一致率 %s (n=%d)"
              % (_fmt(retest["judgeable_agreement"]), retest["judgeable_paired"]))
        print("两轮有效告警率     %s -> %s"
              % (_fmt(retest["round_one_rate"]), _fmt(retest["round_two_rate"])))
        kappa = retest["cohens_kappa"]
        if kappa is not None and kappa < 0.6:
            print("! kappa < 0.6，判定标准本身不够稳。此时有效告警率的"
                  "小数位没有意义，应先修 rubric 再重标")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
