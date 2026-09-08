"""轨道 H：让 `failure_cases` 有真实数据——经人工确认，不是推断出来的。

## 缺口

闭环的六段基建（消费账本 → 指纹分流 → 记忆召回 → 档案选亲 → 影子放量
→ 晋升判决）现在每一段都通了，但 `failure_cases` 里是 **0 条真实反馈**。
于是档案的逐样本分数是空的（`versions_evaluated` 为 0，Pareto 前沿为空），
选亲策略切到 `pareto` 也无事可做，轨道 F 的口径也没有真实样本可验证。
整条流水线是通的，但没有水。

D6 回放（`output/real-pr-regression/`）跑过 173 个真实 PR 样本，checkpoint
里逐条存着模型实际产出的 findings。把它和数据集的 `expected_findings` 对
一遍，就能得到"模型漏了什么""模型多报了什么"——这是 `failure_cases` 唯一
现成的真实来源。

## 为什么不能直接导入

因为**自动对出来的差集不是反馈**。这不是谨慎，是这个仓库已经写下的口径：

- `tiered_match` 的文档原话——`unlabelled` 统计的是"落在标注之外的
  finding"，它**不等于误报**：数据集只标注了反转出来的那个种子缺陷，
  仓库里可能真有别的问题，reviewer 指出它们是对的。把这个数写成"误报"
  是口径造假。实测 r1 那 88 条标注里 83 条是 `valid`——绝大多数标注外
  告警其实是对的。若把它们当 `false_positive` 灌进去，等于教模型别再报
  真问题。
- 漏报一侧稍好但也不干净：`label_provenance` 是 `title-keyword` 56 条、
  `linked-issue` 37 条、`cve` 2 条。"PR 标题里有 fix 字样"不等于"人类确认
  reviewer 应该在这里报警"。

轨道 C 已经为这件事立过规矩：PR 关闭事件推断出的类别叫
`merged_without_addressing` 而不是 `false_positive`，并且被
`HUMAN_CONFIRMED_CATEGORIES` 白名单挡在提示词进化之外。用回放的自动判定
当反馈，会把同一个错误换个地方再犯一次——而且这次是绕过那道白名单，因为
写进去的 category 字面上就是 `false_positive`。

## 所以这个模块做的是两步，中间隔着人

1. `derive_candidates`：把回放结果对成**待确认候选**，`label` 留空。
2. `import_confirmed`：只有人工填了确认标签的候选才写进 `failure_cases`。

第 2 步拒绝导入任何 `label` 为空的候选，且拒绝把"标注外但确认有效"的
finding 当成误报——那是模型报对了。

## 盲标纪律的不对称

沿用 `alert_labelling` 的做法，但两类候选的盲标要求**不同**，原因不同：

- 标注外 finding（判是否误报）：**必须**盲。看到 `expected_findings`
  就是看答案，判定会向真值靠拢（`AlertRecord` 的文档写过这一条）。
- 漏报（判 reviewer 是否本该报）：**不能**盲。这里要问的问题本身就是
  "这个已知缺陷该不该被报出来"，不给出缺陷就无从判断。它的偏倚风险在
  另一处——数据集标签本身的 provenance，所以每条候选都带着
  `label_provenance` 一起给人看。
"""

import json
import os
from typing import Any, Dict, Iterable, List, Optional, Sequence

from .diff_parser import HUNK as _HUNK
from .evaluation_harness import (
    MATCH_CWE_EXACT,
    MATCH_TIERS,
    one_to_one_match,
)
from .models import Finding, Severity

SCHEMA_VERSION = 1

# 两类候选。名字刻意不叫 false_positive / missed_issue——那是**确认之后**
# 才能用的词。候选阶段只描述"它相对标注集处在什么位置"。
KIND_UNMATCHED_FINDING = "unmatched_finding"   # 模型报了，标注集里没有
KIND_UNMATCHED_EXPECTED = "unmatched_expected"  # 标注集里有，模型没报
KINDS = (KIND_UNMATCHED_FINDING, KIND_UNMATCHED_EXPECTED)

# 人工标签空间。前三个沿用 docs/alert-rubric.md 的口径，第四个是漏报侧
# 专用的确认标签。
LABEL_VALID = "valid"                    # 模型报对了（标注外的真问题）
LABEL_NOISE = "valid-but-noise"          # 问题真实，但不该在这个 PR 里提
LABEL_INVALID = "invalid"                # 确认误报
LABEL_SHOULD_HAVE = "should-have-caught"  # 确认漏报：reviewer 本该报这条
LABEL_NOT_EXPECTED = "not-expected"      # 标注有，但不该要求 reviewer 报
LABEL_UNLABELLED = "unlabelled"          # 判不了。不进任何分子分母
LABELS = (
    LABEL_VALID, LABEL_NOISE, LABEL_INVALID,
    LABEL_SHOULD_HAVE, LABEL_NOT_EXPECTED, LABEL_UNLABELLED,
)

# 哪些标签会真的产出一条 failure_case，产出什么 category。
#
# `valid` / `valid-but-noise` **不在这里**：一条标注外但确认有效的 finding
# 说明模型报对了，它不是反馈。把它当 false_positive 导入会教模型别再报真
# 问题——这正是这个模块存在的理由。
# `not-expected` 同理不产出：它说明数据集标注偏严，是数据集的问题不是
# 模型的问题，该去修标注而不是喂给提示词进化。
LABEL_TO_CATEGORY = {
    LABEL_INVALID: "false_positive",
    LABEL_SHOULD_HAVE: "missed_issue",
}

# 每类候选允许的标签。填错类的标签直接报错，不静默忽略：一个填在漏报
# 候选上的 `invalid` 到底是什么意思无人知道，猜它等于编造反馈。
ALLOWED_LABELS = {
    KIND_UNMATCHED_FINDING: (
        LABEL_VALID, LABEL_NOISE, LABEL_INVALID, LABEL_UNLABELLED),
    KIND_UNMATCHED_EXPECTED: (
        LABEL_SHOULD_HAVE, LABEL_NOT_EXPECTED, LABEL_UNLABELLED),
}

# 标注是谁做的。写进 `payload.provenance.source` 和任务元数据。
#
# 这两个值**不可互换**，也不允许调用方随手传字符串：`import_confirmed`
# 只看 label 和 kind，它无从知道那个 label 是人填的还是模型填的。溯源
# 是唯一记录这件事的地方，所以它必须由调用方显式声明，且只能取这两个值
# 之一——写死成"human-confirmed"会让模型标注的反馈冒充人工确认，而
# `HUMAN_CONFIRMED_CATEGORIES` 那道白名单挡的是 category，对来源不实的
# provenance 完全无感。
SOURCE_HUMAN_CONFIRMED = "d6-replay-human-confirmed"
SOURCE_MODEL_LABELLED = "d6-replay-model-labelled"
SOURCES = (SOURCE_HUMAN_CONFIRMED, SOURCE_MODEL_LABELLED)


def load_replay_checkpoint(path: str) -> Dict[str, List[Finding]]:
    """读回放 checkpoint，还原成 case_id → findings。

    出错的 case（checkpoint 里带 `error`）**跳过而不是当成零 findings**：
    零 findings 意味着"模型看过这个 diff，认为没问题"，那会被算成一批漏报；
    而实际上模型根本没跑完。把执行失败读成漏报是凭空造反馈。
    """
    findings: Dict[str, List[Finding]] = {}
    with open(path, encoding="utf-8") as handle:
        for raw in handle:
            if not raw.strip():
                continue
            record = json.loads(raw)
            if record.get("error"):
                continue
            findings[str(record["id"])] = [
                Finding(**{**item, "severity": Severity(item["severity"])})
                for item in record.get("findings", [])
            ]
    return findings


def _candidate_id(case_id: str, kind: str, path: str, line: int, key: str) -> str:
    """候选的稳定标识。

    与 `alert_labelling.alert_id` 同一思路：用内容而不是序号，否则模型
    输出顺序一变，两份文件就对不上，已经标好的标签全部作废。
    """
    import hashlib

    raw = "%s|%s|%s|%d|%s" % (
        case_id, kind, str(path).replace("\\", "/"), int(line), key)
    return hashlib.sha1(raw.encode("utf-8")).hexdigest()[:16]


def _excerpt(diff: str, path: str, line: int, span: int = 6) -> str:
    """diff 里目标行附近的片段，供人工判断时看代码。

    走一遍 diff 直接记录每个原始行对应的新文件行号，而不是先 parse 出内容
    再回头到原文里找那段字符串——同一个 diff 里出现两条一模一样的新增行
    （`+    }`、空行、重复的 import）是常态，按内容找会命中错误的 hunk，
    于是人工看到的是另一处代码。判定错的对象比判不了更糟。

    找不到目标行时返回空串，不退回到 diff 开头：开头那几行几乎必然是无关
    代码，把它当成"目标附近"会让人以为自己看到了现场。
    """
    lines = diff.splitlines()
    normalized = str(path).replace("\\", "/")
    if normalized.startswith(("a/", "b/")):
        normalized = normalized[2:]
    current_path = ""
    new_line = 0
    in_hunk = False
    center = None

    for index, raw in enumerate(lines):
        if raw.startswith("+++ "):
            current_path = raw[4:].strip()
            if current_path.startswith("b/"):
                current_path = current_path[2:]
            in_hunk = False
            continue
        match = _HUNK.match(raw)
        if match:
            new_line = int(match.group(1))
            in_hunk = True
            continue
        if not in_hunk:
            continue
        if raw.startswith("-") and not raw.startswith("---"):
            continue
        if raw.startswith("\\ No newline"):
            continue
        # 新增行与上下文行都占新文件的一个行号；命中即定位。
        if current_path == normalized and new_line == int(line):
            center = index
            break
        new_line += 1

    if center is None:
        return ""
    return "\n".join(lines[max(0, center - span):center + span + 1])


def derive_candidates(
    cases: Sequence[dict], replay: Dict[str, List[Finding]],
    tier: str = MATCH_CWE_EXACT, line_tolerance: int = 2,
    splits: Optional[Sequence[str]] = None,
) -> List[dict]:
    """把回放结果对成待人工确认的候选。`label` 一律留空。

    匹配走 `one_to_one_match`——评测用的同一个函数、同一个 tier 参数。
    刻意不另写一套对齐逻辑：口径分叉之后，"回放里算漏报的"和"评测里算
    漏报的"会是两批不同的东西，而两边的数字还会被放在同一段话里比较。

    `splits` 默认只取 validation。holdout 的反馈不能进提示词进化——那等于
    拿隐藏集调参，holdout 门禁当场失效。这个默认值是防呆，不是偏好。
    """
    if tier not in MATCH_TIERS:
        raise ValueError("unknown match tier: %s" % tier)
    allowed_splits = tuple(splits) if splits is not None else ("validation",)
    candidates: List[dict] = []
    for case in cases:
        if case.get("split") not in allowed_splits:
            continue
        case_id = str(case["id"])
        if case_id not in replay:
            # 回放里没有这一条（没跑到 / 跑失败）。跳过，不当成零 findings。
            continue
        predicted = replay[case_id]
        expected = case.get("expected_findings") or []
        matches = one_to_one_match(expected, predicted, line_tolerance, tier)
        matched_expected = {item.expected_index for item in matches}
        matched_predicted = {item.predicted_index for item in matches}

        for index, truth in enumerate(expected):
            if index in matched_expected:
                continue
            line = int(truth["start_line"])
            candidates.append({
                "candidate_id": _candidate_id(
                    case_id, KIND_UNMATCHED_EXPECTED, truth["path"], line,
                    str(truth.get("cwe", ""))),
                "kind": KIND_UNMATCHED_EXPECTED,
                "case_id": case_id,
                "repository": case.get("repository", ""),
                "pull_request": case.get("pull_request"),
                "path": truth["path"],
                "line": line,
                "cwe": truth.get("cwe", ""),
                "severity": truth.get("severity", ""),
                "defect_class": truth.get("defect_class", ""),
                # 标签来源随每条候选一起给人看。`title-keyword` 的可信度
                # 与 `cve` 差很远，判"该不该报"时这是必要信息。
                "label_provenance": case.get("label_provenance", ""),
                "fix_pr_url": case.get("fix_pr_url", ""),
                "diff_excerpt": _excerpt(case["diff"], truth["path"], line),
                # 漏报侧刻意**不**盲：要问的问题就是"这个已知缺陷该不该被
                # 报出来"，不给缺陷无从判断。见模块文档"盲标纪律的不对称"。
                "label": None,
                "note": "",
                # 人工可填。留空时导入不会伪造 rule_id，见 build_payload。
                "rule_id": "",
            })

        for index, finding in enumerate(predicted):
            if index in matched_predicted:
                continue
            candidates.append({
                "candidate_id": _candidate_id(
                    case_id, KIND_UNMATCHED_FINDING, finding.path, finding.line,
                    finding.rule_id),
                "kind": KIND_UNMATCHED_FINDING,
                "case_id": case_id,
                "repository": case.get("repository", ""),
                "pull_request": case.get("pull_request"),
                "path": finding.path,
                "line": finding.line,
                "rule_id": finding.rule_id,
                "severity": getattr(finding.severity, "value", finding.severity),
                "title": finding.title,
                "explanation": finding.explanation,
                "diff_excerpt": _excerpt(case["diff"], finding.path, finding.line),
                "label": None,
                "note": "",
            })
    return sorted(candidates, key=lambda item: item["candidate_id"])


def blind(candidates: Iterable[dict]) -> List[dict]:
    """剥掉标注外 finding 候选上的真值线索，供盲标。

    只剥 `unmatched_finding` 那一类。漏报候选剥掉真值就没有可判的对象了
    ——两类候选的盲标要求不同，见模块文档。
    """
    stripped = []
    for candidate in candidates:
        item = dict(candidate)
        if item["kind"] == KIND_UNMATCHED_FINDING:
            for key in ("cwe", "defect_class", "label_provenance", "fix_pr_url"):
                item.pop(key, None)
        item["label"], item["note"] = None, ""
        stripped.append(item)
    return stripped


def save_candidates(
    path: str, candidates: Sequence[dict], source: str, tier: str,
    stamp: str, replay: str = "",
) -> None:
    """落盘一批待确认候选。

    `stamp` 由调用方传入而不是取当前时间：取当前时间会让同一份输入产出
    不同文件，测试无法断言内容（与 `alert_labelling.save_round` 同因）。
    """
    payload = {
        "schema_version": SCHEMA_VERSION,
        "source": source,
        "replay": replay,
        "match_tier": tier,
        "prepared_at": stamp,
        "labels": list(LABELS),
        "note": (
            "label 留空表示未确认，导入时会被拒绝。unmatched_finding 不等于"
            "误报，unmatched_expected 不等于该报——两者都要人工判定。"
        ),
        "candidates": list(candidates),
    }
    directory = os.path.dirname(path)
    if directory:
        os.makedirs(directory, exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        json.dump(payload, handle, ensure_ascii=False, indent=2)
        handle.write("\n")


def load_candidates(path: str) -> Dict[str, Any]:
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def validate_labels(candidates: Sequence[dict]) -> Dict[str, Any]:
    """检查人工填的标签是否合法。返回统计，不抛异常。

    非法标签**单列**而不是并进 unlabelled：前者是填错了（需要有人回去改），
    后者是判不了（是一个合法的结论）。合并之后就分不出该找谁。
    """
    counts = {label: 0 for label in LABELS}
    unlabelled_ids: List[str] = []
    invalid_ids: List[str] = []
    for candidate in candidates:
        label = candidate.get("label")
        if label is None or label == "":
            unlabelled_ids.append(candidate["candidate_id"])
            continue
        allowed = ALLOWED_LABELS.get(candidate.get("kind"), ())
        if label not in allowed:
            invalid_ids.append(candidate["candidate_id"])
            continue
        counts[label] = counts.get(label, 0) + 1
    return {
        "counts": counts,
        "total": len(candidates),
        "missing_label": unlabelled_ids,
        "invalid_label": invalid_ids,
        "importable": sum(
            counts.get(label, 0) for label in LABEL_TO_CATEGORY
        ),
    }


def build_payload(
    candidate: dict, source: str = SOURCE_HUMAN_CONFIRMED,
) -> Dict[str, Any]:
    """一条确认候选对应的 `failure_cases.payload`。

    ## rule_id 只在人工填了的时候才写

    `auto_propose` 会把 `payload.finding.rule_id` 直接拼成
    `[focus-rule:<rule_id>]` 注入提示词。数据集的 `expected_findings`
    **没有 rule_id**，只有 `cwe`——而 `CWE-193` 恰好能通过
    `FEEDBACK_RULE_ID` 那个 `^[A-Z][A-Z0-9_-]{1,79}$` 正则。拿 cwe 顶替
    rule_id 会往提示词里注入一条 `[focus-rule:CWE-193]`，而没有任何
    reviewer 认识这个标识符：候选提示词会多出一条谁也执行不了的指令，
    指标不动，然后被改进门禁判成"无提升"。表面看是模型学不动，实际是
    这里造了一个假字段。

    所以 rule_id 留给人工填；没填就不写这个键，`learned_rule_ids` 自然
    跳过它，反馈仍然通过类别计数生效。

    ## source 必须由调用方声明，不能写死

    这个字段曾经是常量 `d6-replay-human-confirmed`。模型标注的那批候选
    走同一条路径进库，于是 provenance 会声称有人确认过——而实际没有。
    note 里的 `[model-labelled]` 前缀挡不住这个：溯源字段才是三个月后
    有人拿来判断"这条 failure_case 凭什么存在"的东西，它撒谎比没有更糟。
    `HUMAN_CONFIRMED_CATEGORIES` 那道白名单挡的是 category，对一个字面
    合法但来源不实的 provenance 完全无感。
    """
    if source not in SOURCES:
        raise ValueError("unknown feedback source: %s" % source)
    finding: Dict[str, Any] = {
        "path": candidate["path"],
        "line": int(candidate["line"]),
        "severity": candidate.get("severity", ""),
    }
    if candidate.get("cwe"):
        finding["cwe"] = candidate["cwe"]
    rule_id = str(candidate.get("rule_id", "")).strip()
    if rule_id:
        finding["rule_id"] = rule_id
    return {
        "finding": finding,
        "note": str(candidate.get("note", ""))[:2000],
        # 溯源：这条反馈是从哪次回放、哪个样本、哪个标签来的。没有这个，
        # 三个月后没人能回答"这条 failure_case 凭什么存在"。
        "provenance": {
            "source": source,
            "candidate_id": candidate["candidate_id"],
            "case_id": candidate["case_id"],
            "kind": candidate["kind"],
            "label": candidate["label"],
            "label_provenance": candidate.get("label_provenance", ""),
        },
    }


def import_confirmed(
    store, payload: Dict[str, Any], tenant_id: str = "default",
    task_prefix: str = "d6-feedback",
    diffs: Optional[Dict[str, str]] = None,
    source: str = SOURCE_HUMAN_CONFIRMED,
) -> Dict[str, Any]:
    """把**已确认**的候选写进 `failure_cases`。

    三道拒绝，都不是可选项：

    1. `label` 为空 → 不导入。未确认的推断信号进了人工确认字段，就是把
       弱代理信号伪装成人类判断，`HUMAN_CONFIRMED_CATEGORIES` 那道白名单
       会原样放行，因为写进去的 category 字面上是合法的。
    2. 标签不属于该类候选 → 不导入，记进 `rejected`。
    3. `valid` / `valid-but-noise` / `not-expected` → 不产出 failure_case。
       前两者说明模型报对了，后者说明数据集标注偏严——都不是模型的错误。

    ## 顺带存 diff，因为轨道 F 卡在这里

    `failure_cases` 表本身没有 diff 字段，而把一条反馈提升成数据集样本
    必须有 diff。轨道 F 现在只能去 `store.get_task_payload` 取，而对大多数
    历史任务那里是 `None`。这里建任务时手上正好有对应样本的完整 diff
    （调用方本来就要加载数据集才能派生候选），存进 `task_payloads` 是顺手
    的事，能让这批反馈是**可提升的**而不是又一批死数据。

    `diffs` 由调用方传入而不是从候选文件里读：候选文件只带片段，为了让
    这一步能跑而把片段当成完整 diff 存进去，等于给轨道 F 埋一个截断的
    输入，而它看起来完全正常。宁可没有，不要假的。

    幂等：同一个 candidate_id 已经导入过就跳过。脚本会被重跑（补标之后
    再跑一次是正常操作），不去重的话同一条反馈会被计成两次出现，直接把
    频率分流的 `root_cause_min_occurrences` 顶过阈值。判重按确定性的
    `task_id` 逐条查，不扫 `list_failure_cases`——后者上限 500 行，表一长
    早期导入的行就落在窗口外，于是"没查到"被读成"没导过"，同一条反馈重复
    入库，而且是在数据变多之后才开始出错。

    `source` 一路透传到任务元数据和 `payload.provenance`，默认人工确认。
    模型标注的批次必须显式传 `SOURCE_MODEL_LABELLED`，否则它在库里与人工
    确认的反馈无法区分——见 `build_payload` 的说明。
    """
    if source not in SOURCES:
        raise ValueError("unknown feedback source: %s" % source)
    candidates = payload.get("candidates", [])
    diffs = diffs or {}
    imported: List[dict] = []
    skipped_existing: List[str] = []
    rejected: List[dict] = []
    not_feedback: List[str] = []
    unconfirmed: List[str] = []

    for candidate in candidates:
        candidate_id = candidate["candidate_id"]
        label = candidate.get("label")
        if label is None or label == "":
            unconfirmed.append(candidate_id)
            continue
        allowed = ALLOWED_LABELS.get(candidate.get("kind"), ())
        if label not in allowed:
            rejected.append({
                "candidate_id": candidate_id,
                "reason": "label %r is not valid for kind %r"
                          % (label, candidate.get("kind")),
            })
            continue
        category = LABEL_TO_CATEGORY.get(label)
        if category is None:
            not_feedback.append(candidate_id)
            continue
        task_id = "%s-%s" % (task_prefix, candidate_id)
        if store.list_task_failure_cases(task_id):
            skipped_existing.append(candidate_id)
            continue
        store.create(
            task_id, candidate.get("repository", "") or "unknown",
            candidate.get("pull_request"),
            {"source": source, "case_id": candidate["case_id"]},
            tenant_id,
        )
        diff = diffs.get(candidate["case_id"])
        if diff:
            store.save_task_payload(task_id, diff)
        store.record_failure_case(
            task_id, category, build_payload(candidate, source=source))
        imported.append({"candidate_id": candidate_id, "category": category,
                         "task_id": task_id, "diff_saved": bool(diff)})

    return {
        "imported": imported,
        "imported_count": len(imported),
        "skipped_already_imported": skipped_existing,
        "skipped_not_feedback": not_feedback,
        "skipped_unconfirmed": unconfirmed,
        "rejected": rejected,
        "categories": {
            category: sum(1 for item in imported if item["category"] == category)
            for category in sorted(set(LABEL_TO_CATEGORY.values()))
        },
    }


# --------------------------------------------------------------------------
# 人工标注这一步的工装（轨道 H 第二步）
#
# 194 条一次标完是不现实的，而"标完再说"会让 `failure_cases` 无限期停在 0
# 条。所以先确定性地抽一小批，把它渲染成一份人能直接填的清单。
#
# 这里**不产出任何 label**。一条由程序写出来的 label 是推断结论，而两步
# CLI 中间那道闸门的全部意义就是推断结论不得进 `failure_cases`——填了 label
# 列，`HUMAN_CONFIRMED_CATEGORIES` 那道白名单依然放行，因为它背后的数据是
# 编造的。工装只负责让人的那一步快。
# --------------------------------------------------------------------------


def sample_candidates(
    candidates: Sequence[dict], size: int, seed: int,
    kind: Optional[str] = None,
) -> List[dict]:
    """确定性抽样，与 `alert_labelling.sample_alerts` 同一做法与同一理由。

    先按 `candidate_id` 排序再抽：候选列表的顺序取决于派生时的遍历顺序，
    直接对它抽样的话，上游一改顺序，同一个种子就抽到另一批，已经标好的
    标签全部作废。

    `kind` 用于分类抽样。两类候选问的问题不同（"是不是误报" vs "该不该
    报"）、盲标要求不同，混在一份清单里让人来回切换判据，判定质量会掉。
    """
    import random

    pool = [item for item in candidates
            if kind is None or item.get("kind") == kind]
    ordered = sorted(pool, key=lambda item: item["candidate_id"])
    if size >= len(ordered):
        return list(ordered)
    return random.Random(seed).sample(ordered, size)


def _worksheet_fields(candidate: dict) -> List[tuple]:
    """一条候选在清单里要展示的字段，按判断时需要的顺序。

    `unmatched_finding` 侧刻意不展示 `cwe` / `defect_class` /
    `label_provenance` / `fix_pr_url`——那些是真值线索，见 `blind()`。这里
    只是排版；真正的剥离必须在派生时用 `--blind` 做，因为清单是从候选文件
    渲染的，候选文件里若还带着线索，人只要打开那个文件就看见了。
    """
    if candidate.get("kind") == KIND_UNMATCHED_EXPECTED:
        keys = ("case_id", "repository", "pull_request", "path", "line",
                "cwe", "severity", "defect_class", "label_provenance",
                "fix_pr_url")
    else:
        keys = ("case_id", "repository", "pull_request", "path", "line",
                "rule_id", "severity", "title", "explanation")
    return [(key, candidate.get(key)) for key in keys
            if candidate.get(key) not in (None, "")]


def render_worksheet(payload: Dict[str, Any], candidates: Sequence[dict]) -> str:
    """把一批候选渲染成 Markdown 清单，label 列留空。

    Markdown 而不是 CSV：判"该不该报"要读一段 diff，CSV 里一个塞了换行的
    单元格没法读，而读不到现场的判定不如判不了（`_excerpt` 找不到目标行时
    返回空串而不是退回 diff 开头，同一条理由）。

    每条候选下面留一行 `label:` 与一行 `note:`，填完之后由
    `apply_worksheet` 读回候选文件——**不**要求人去改那个 194 条的 JSON，
    在嵌套 JSON 里手工填 label 是最容易填错位置的做法，而填错位置的表现是
    一条反馈被归到另一条候选上。
    """
    lines = [
        "# 反馈候选人工确认清单",
        "",
        "来源：`%s`（回放 `%s`，匹配档 `%s`，派生于 %s）"
        % (payload.get("source", ""), payload.get("replay", ""),
           payload.get("match_tier", ""), payload.get("prepared_at", "")),
        "",
        "## 怎么填",
        "",
        "每条候选下面的 `label:` 后面写一个标签，`note:` 后面写理由（可空）。",
        "填完保存，然后跑 `apply-worksheet` 把标签写回候选文件，再跑",
        "`check` / `import`。**不要**直接编辑候选 JSON。",
        "",
        "标签空间按候选类型不同：",
        "",
        "- `unmatched_expected`（标注集里有、模型没报）——问的是**这个已知"
        "缺陷该不该被 reviewer 报出来**：",
        "  - `should-have-caught`：确认该报，这是一条真漏报；",
        "  - `not-expected`：不该要求 reviewer 报（标注偏严），**不产出反馈**；",
        "  - `unlabelled`：判不了。",
        "- `unmatched_finding`（模型报了、标注集里没有）——问的是**这条告警"
        "是不是误报**：",
        "  - `invalid`：确认误报，这是一条真误报；",
        "  - `valid`：标注外的真问题，模型报对了，**不产出反馈**；",
        "  - `valid-but-noise`：问题真实但不该在这个 PR 里提，**不产出反馈**；",
        "  - `unlabelled`：判不了。",
        "",
        "> `valid` / `valid-but-noise` / `not-expected` 刻意不产出 "
        "`failure_case`：前两者说明模型报对了，后者说明数据集标注偏严。"
        "把它们当误报导入等于教模型别再报真问题。",
        "",
        "`rule_id:` 只在 `should-have-caught` 上出现，且**可以留空**："
        "填进去的字符串会被拼成 `[focus-rule:<rule_id>]` 注入候选提示词，"
        "所以它必须是 reviewer 真认识的规则标识符。不确定就留空，反馈仍然"
        "通过类别计数生效。",
        "",
    ]
    for index, candidate in enumerate(candidates, 1):
        lines.append("---")
        lines.append("")
        lines.append("## %d. `%s`（%s）"
                     % (index, candidate["candidate_id"], candidate["kind"]))
        lines.append("")
        for key, value in _worksheet_fields(candidate):
            lines.append("- **%s**：%s" % (key, value))
        lines.append("")
        excerpt = candidate.get("diff_excerpt") or ""
        if excerpt:
            lines.append("```diff")
            lines.extend(excerpt.splitlines())
            lines.append("```")
        else:
            # 定位不到片段的候选人工无从判断，得说出来，别让它静静地变成
            # 一条 unlabelled。
            lines.append("> **没有 diff 片段**：这一行在 diff 里定位不到，"
                         "无法凭清单判断。填 `unlabelled`，或去看完整 PR。")
        lines.append("")
        lines.append("```")
        lines.append("candidate_id: %s" % candidate["candidate_id"])
        lines.append("label:")
        lines.append("note:")
        if candidate.get("kind") == KIND_UNMATCHED_EXPECTED:
            lines.append("rule_id:")
        lines.append("```")
        lines.append("")
    return "\n".join(lines) + "\n"


def parse_worksheet(text: str) -> Dict[str, Any]:
    """从填好的清单里读回 `candidate_id → {label, note, rule_id}`。

    只认 `candidate_id:` 之后紧跟的那几行，且要求 `candidate_id` 与 label
    成对出现：一段只有 label 没有 candidate_id 的文本无从归属，猜它属于
    上一条就是把一条判定挂到别人身上。

    返回 `{entries, problems}`。`problems` 非空时调用方**不得**写回——部分
    写回会产出一份"看起来标了一半"的候选文件，而其中有几条的归属是错的。
    """
    entries: Dict[str, Dict[str, str]] = {}
    problems: List[str] = []
    current: Optional[str] = None
    seen_order: List[str] = []
    for number, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if line.startswith("candidate_id:"):
            current = line[len("candidate_id:"):].strip()
            if not current:
                problems.append("line %d: empty candidate_id" % number)
                current = None
                continue
            if current in entries:
                problems.append(
                    "line %d: candidate_id %s appears twice" % (number, current))
                continue
            entries[current] = {"label": "", "note": "", "rule_id": ""}
            seen_order.append(current)
            continue
        for key in ("label", "note", "rule_id"):
            if line.startswith(key + ":"):
                value = line[len(key) + 1:].strip()
                if current is None:
                    if value:
                        problems.append(
                            "line %d: %s outside any candidate block"
                            % (number, key))
                    break
                entries[current][key] = value
                break
    # 填了 label 但标签不在标签空间里 —— 这是填错了，不是判不了，必须单列。
    for candidate_id in seen_order:
        label = entries[candidate_id]["label"]
        if label and label not in LABELS:
            problems.append(
                "%s: %r is not one of %s"
                % (candidate_id, label, ", ".join(LABELS)))
    return {"entries": entries, "problems": problems}


def apply_worksheet(
    payload: Dict[str, Any], entries: Dict[str, Dict[str, str]],
) -> Dict[str, Any]:
    """把清单里的标签合并回候选 payload。返回新 payload 与统计。

    未知 `candidate_id` **报错不忽略**：它意味着清单和候选文件对不上（比如
    清单是上一版候选派生出来的），那时其它条目的归属也不可信。

    已有非空 label 的候选**不被覆盖**：重标是一个显式动作，不能作为"又跑了
    一次 apply"的副产品发生。与 `stage_shadow` 默认拒绝而非覆盖同源。
    """
    candidates = [dict(item) for item in payload.get("candidates", [])]
    index = {item["candidate_id"]: item for item in candidates}
    unknown = sorted(set(entries) - set(index))
    applied: List[str] = []
    skipped_blank: List[str] = []
    conflicts: List[str] = []
    for candidate_id, values in sorted(entries.items()):
        candidate = index.get(candidate_id)
        if candidate is None:
            continue
        if not values.get("label"):
            skipped_blank.append(candidate_id)
            continue
        if candidate.get("label"):
            if candidate["label"] != values["label"]:
                conflicts.append(candidate_id)
            continue
        candidate["label"] = values["label"]
        candidate["note"] = values.get("note", "")
        rule_id = values.get("rule_id", "")
        if rule_id:
            candidate["rule_id"] = rule_id
        applied.append(candidate_id)
    return {
        "payload": {**payload, "candidates": candidates},
        "applied": applied,
        "skipped_blank": skipped_blank,
        "unknown_candidate_ids": unknown,
        "conflicts": conflicts,
    }