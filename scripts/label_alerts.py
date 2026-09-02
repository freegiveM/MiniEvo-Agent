"""逐条标注告警的交互工具。按 rubric v1 的固定判定顺序提问。

    python scripts/label_alerts.py datasets/labelling-r1.json

第二轮重测（必须隐藏第一轮标签，工具层强制）：

    python scripts/label_alerts.py datasets/labelling-r2.json --blind

为什么要专门写这个，而不是直接手编 JSON——三条都是 rubric 已经写明、
但手编时**必然**做不到的约束：

1. rubric 的判定顺序是"固定，不得调整"，理由是同一条告警按不同顺序问会
   得到不同答案，顺序不固定则重测一致率测的是提问顺序而非判断标准。
   手编 JSON 时你面对的是一个 label 字段，没有顺序可言。这里把四步做成
   四次提问，第 1 步用工具算好的 in_label_scope 直接跳过。

2. 第 1 步（是否落在标注集内）rubric 明确要求"用工具算，不靠人看真值"。
   抽样阶段已经算进 in_label_scope 了。手编时这个字段就在同一个对象里，
   眼睛会扫到，但也可能被忽略而按自己的判断填——两种都不对。

3. 中途退出必须能续标。30 条一次标完是不现实的，而手编 JSON 的"续标"
   等于每次重新找上次停在哪，容易漏条或重标。这里每答一条就落盘，
   下次自动跳过已标的。

刻意**不做**的事：

- 不显示 expected_findings。rubric 写了标注时看到真值会让判定向真值靠拢。
  数据文件里本来就没有这个字段（AlertRecord 刻意不含），这里也不去数据集
  里查回来。
- 不提供"批量标同一个值"。那是凑分母的捷径，rubric 最后一条明确禁止
  为了凑数硬判。
- 不在标注中途修改 rubric。遇到覆盖不到的形态记 note，走 v2。
"""
import argparse
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from evoagent.alert_labelling import (  # noqa: E402
    LABEL_INVALID,
    LABEL_NOISE,
    LABEL_UNLABELLED,
    LABEL_VALID,
    RUBRIC_VERSION,
)


BAR = "=" * 72


def _die(message: str) -> int:
    print(message, file=sys.stderr)
    return 2


def _prompt(question: str, options: dict) -> str:
    """问一个单选题。只接受列出的键，不做模糊匹配。

    不做模糊匹配是刻意的：把 "y" 猜成 "yes" 在这里的代价是**默默记下一个
    你没打算给的标签**，而标签是这一整轮的产出。宁可让你重敲一次。
    """
    keys = "/".join(options)
    while True:
        print("\n  " + question)
        for key, (label, _hint) in options.items():
            print("    [%s] %s" % (key, label))
        answer = input("  选择 (%s，或 q 退出保存): " % keys).strip().lower()
        if answer == "q":
            return "q"
        if answer in options:
            return answer
        print("  ! 只接受 %s 或 q" % keys)


def _show(item: dict, index: int, total: int) -> None:
    print("\n" + BAR)
    print("第 %d/%d 条   alert_id=%s   case=%s"
          % (index, total, item["alert_id"], item["case_id"]))
    print("位置  %s:%s" % (item["path"], item["line"]))
    print("规则  %s  (severity=%s)" % (item["rule_id"], item["severity"]))
    print("标题  %s" % item["title"])
    print("说明  %s" % item["explanation"])
    print("-" * 72)
    print(item["diff_excerpt"])
    print("-" * 72)


def _ask_label(item: dict) -> "tuple":
    """按 rubric v1 的四步顺序问，返回 (label, note) 或 ("q", "")。

    第 2 步在第 3 步之前，这个顺序不能调：一条既不成立、又与改动无关的
    告警是 invalid，不是 valid-but-noise。反了会把事实错误洗成"噪声"。
    """
    # 第 1 步不问人：rubric 要求用工具算。
    if not item.get("in_label_scope"):
        print("\n  第1步 落在标注集范围内吗 -> 否（工具判定，不由人改）")
        print("  => %s" % LABEL_UNLABELLED)
        return LABEL_UNLABELLED, "out of label scope (tool-decided)"

    print("\n  第1步 落在标注集范围内吗 -> 是（工具判定）")

    answer = _prompt(
        "第2步 它描述的问题在代码里成立吗？"
        "（只看代码事实；措辞、severity、CWE 判错不在这一步扣分）",
        {
            "1": ("成立 —— 那个调用/赋值/分支真的在，描述的因果路径存在", ""),
            "2": ("不成立 —— 误读语义、指向不存在的标识符、事实错误", ""),
            "3": ("拿不定主意 —— 判 unlabelled 并记入待议形态", ""),
        },
    )
    if answer == "q":
        return "q", ""
    if answer == "2":
        return LABEL_INVALID, ""
    if answer == "3":
        note = input("  待议形态，简述（会进 rubric v2 讨论）: ").strip()
        return LABEL_UNLABELLED, note or "undecided at step 2"

    answer = _prompt(
        "第3步 这个问题与本次改动相关吗？",
        {
            "1": ("相关 —— 在新增行里，或本次改动使它可达/加重", ""),
            "2": ("不相关 —— 既有代码里的问题，与本次改动无因果关系", ""),
            "3": ("拿不定主意 —— 判 unlabelled 并记入待议形态", ""),
        },
    )
    if answer == "q":
        return "q", ""
    if answer == "2":
        return LABEL_NOISE, ""
    if answer == "3":
        note = input("  待议形态，简述（会进 rubric v2 讨论）: ").strip()
        return LABEL_UNLABELLED, note or "undecided at step 3"

    return LABEL_VALID, ""


def _save(path: str, payload: dict) -> None:
    """整份重写。

    不做增量写：这个文件是一轮标注的完整产出，部分写入失败会留下一个
    既不是旧版也不是新版的文件。整写 + 临时文件替换，要么全成要么不动。
    """
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, ensure_ascii=False, indent=2)
    os.replace(tmp, path)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("path", help="标注文件，例如 datasets/labelling-r1.json")
    parser.add_argument(
        "--blind", action="store_true",
        help=("重测第二轮必须加这个：把已有的 label/note 清空后再标。"
              "看到上轮标签会锚定，一致率虚高——那测的是记忆不是标准。"
              "会先要求确认，因为它会丢弃该文件里已有的标签。"),
    )
    parser.add_argument(
        "--relabel", action="store_true",
        help="重标已标过的条目（默认跳过已标的，用于续标）",
    )
    args = parser.parse_args()

    if not os.path.exists(args.path):
        return _die("找不到 %s。先用 scripts/sample_alerts_for_labelling.py 抽样。"
                    % args.path)

    with open(args.path, encoding="utf-8") as handle:
        payload = json.load(handle)

    if payload.get("rubric_version") != RUBRIC_VERSION:
        # 不静默继续：rubric 版本不同意味着标签空间或判定顺序可能变了，
        # 混标出来的一轮数据没法解释。
        return _die("rubric 版本不符：文件是 %s，当前代码是 %s。"
                    "不同版本的标注不能混在一轮里。"
                    % (payload.get("rubric_version"), RUBRIC_VERSION))

    alerts = payload["alerts"]
    if args.blind:
        already = sum(1 for item in alerts if item.get("label"))
        if already:
            print("--blind 会清空这个文件里已有的 %d 条标签。" % already)
            if input("确认？输入 yes 继续: ").strip().lower() != "yes":
                return _die("已取消，文件未改动。")
        for item in alerts:
            item["label"] = None
            item["note"] = ""
        _save(args.path, payload)
        print("已清空标签，开始盲标。\n")

    total = len(alerts)
    print(BAR)
    print("rubric %s | round %s | 来源 %s | 共 %d 条"
          % (payload.get("rubric_version"), payload.get("round"),
             payload.get("source"), total))
    print("判定顺序固定：范围 -> 事实成立 -> 相关性。判据见 docs/alert-rubric.md")
    print("每答一条即落盘，可以 q 退出后再跑本脚本续标。")

    changed = 0
    for index, item in enumerate(alerts, start=1):
        if item.get("label") and not args.relabel:
            continue
        _show(item, index, total)
        label, note = _ask_label(item)
        if label == "q":
            print("\n已退出。%d 条本次标完，进度已保存。" % changed)
            break
        item["label"] = label
        if note:
            item["note"] = note
        _save(args.path, payload)
        changed += 1
        print("  => %s" % label)
    else:
        print("\n" + BAR)
        print("全部 %d 条已标完。" % total)

    labelled = sum(1 for item in alerts if item.get("label"))
    print("已标 %d/%d 条。出数：" % (labelled, total))
    print("  python scripts/report_alert_labelling.py %s" % args.path)
    if labelled == total:
        # 重测的 ≥3 天间隔是 rubric 的硬要求，标完时提醒一次，
        # 因为这个时钟从标完那天才开始走。
        print("\n下一步（rubric 要求间隔 ≥3 天，从今天算）：")
        print("  cp %s datasets/labelling-r2.json" % args.path)
        print("  python scripts/label_alerts.py datasets/labelling-r2.json --blind")
        print("  python scripts/report_alert_labelling.py %s --retest "
              "datasets/labelling-r2.json" % args.path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
