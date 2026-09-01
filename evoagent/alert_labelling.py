"""有效告警率的抽样、标注记录与重测一致率。

配套 rubric 见 docs/alert-rubric.md。这里只实现口径，判定标准在文档里。

三条硬约束，都写进了代码而不是靠自觉：
  1. 抽样确定性。种子入库，两轮重测抽到的必须是同一批样本，否则一致率
     算的是两个不同集合，没有意义。
  2. 第二轮标注**看不到**第一轮的标签与备注。看到就会锚定，一致率必然
     虚高——那测的是"我能不能记住上次选了什么"。load_round 会主动剥掉。
  3. unlabelled 不进有效告警率分母。空分母返回 None 而非 0.0。
"""
import hashlib
import json
import os
import random
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence, Tuple

# 四个标签。与 docs/alert-rubric.md 的标签空间一一对应，改这里必须同步改文档。
LABEL_VALID = "valid"
LABEL_NOISE = "valid-but-noise"
LABEL_INVALID = "invalid"
LABEL_UNLABELLED = "unlabelled"
LABELS = (LABEL_VALID, LABEL_NOISE, LABEL_INVALID, LABEL_UNLABELLED)

# 进有效告警率分母的标签。unlabelled 不在其中——它是"没有依据下判断"，
# 计入误报会系统性低估 precision，计入命中会高估。
JUDGEABLE_LABELS = (LABEL_VALID, LABEL_NOISE, LABEL_INVALID)

# 算作"有效"的标签。valid-but-noise 也算有效：问题真实存在。
# 它与 valid 的区别是该不该在这个 PR 里提，那是另一个维度，单独报。
EFFECTIVE_LABELS = (LABEL_VALID, LABEL_NOISE)

RUBRIC_VERSION = "v1"


@dataclass
class AlertRecord:
    """一条待标注的告警。

    刻意**不含** expected_findings：标注时看到真值就等于看答案，
    判定会向真值靠拢，有效告警率会虚高。位置是否落在标注集内由
    第 1 步单独判定，那一步用工具算（in_label_scope），不靠人看真值。
    """
    alert_id: str
    case_id: str
    path: str
    line: int
    rule_id: str
    severity: str
    title: str
    explanation: str
    diff_excerpt: str
    in_label_scope: bool
    label: Optional[str] = None
    note: str = ""

    def blinded(self) -> Dict[str, Any]:
        """给标注者看的形态：剥掉 label 与 note。

        这是重测协议的技术实现。第二轮看到上轮标签就会锚定，
        一致率虚高；看到上轮备注同理（备注里往往写着判定理由）。
        """
        payload = {key: value for key, value in vars(self).items()
                   if key not in {"label", "note"}}
        return payload


def alert_id(case_id: str, path: str, line: int, rule_id: str) -> str:
    """告警的稳定标识。

    用内容哈希而不是序号：序号会随 reviewer 输出顺序变化，两轮之间
    对不上。四元组足以定位一条告警，且重跑 reviewer 后仍然稳定。
    """
    raw = "%s|%s|%d|%s" % (case_id, path.replace("\\", "/"), line, rule_id)
    return hashlib.sha1(raw.encode("utf-8")).hexdigest()[:16]


# 位置容差。与评测的 line_tolerance 保持一致，不另取一个数：
# 标注口径与自动评分口径不一致时，两边数字就不能相互解释了。
LABEL_SCOPE_TOLERANCE = 2


def in_label_scope(
    finding_path: str, finding_line: int, expected: Sequence[dict],
    tolerance: int = LABEL_SCOPE_TOLERANCE,
) -> bool:
    """告警位置是否落在标注集覆盖范围内（rubric 第 1 步）。

    这一步用工具算而不是让人看真值：让人看 expected_findings 才能判位置，
    就等于把答案摊在标注者面前，后面三步的判定会全部向真值靠拢。
    """
    normalized = finding_path.replace("\\", "/").lstrip("ab/")
    for item in expected:
        item_path = str(item["path"]).replace("\\", "/").lstrip("ab/")
        if item_path != normalized:
            continue
        low = int(item["start_line"]) - tolerance
        high = int(item["end_line"]) + tolerance
        if low <= finding_line <= high:
            return True
    return False


def collect_alerts(
    reviewer, cases: Sequence[dict], excerpt_lines: int = 6,
) -> List[AlertRecord]:
    """跑 reviewer，把它产出的每条告警转成一条待标注记录。"""
    from .diff_parser import parse_unified_diff

    records: List[AlertRecord] = []
    for case in cases:
        parsed = parse_unified_diff(case["diff"])
        review_case = getattr(reviewer, "review_case", None)
        findings = (review_case(case, parsed) if review_case
                    else reviewer.review(case["diff"], parsed))
        expected = case.get("expected_findings") or []
        for finding in findings:
            records.append(AlertRecord(
                alert_id=alert_id(case["id"], finding.path, finding.line,
                                  finding.rule_id),
                case_id=case["id"],
                path=finding.path,
                line=finding.line,
                rule_id=finding.rule_id,
                severity=getattr(finding.severity, "value", finding.severity),
                title=finding.title,
                explanation=finding.explanation,
                diff_excerpt=_excerpt(case["diff"], finding.line, excerpt_lines),
                in_label_scope=in_label_scope(
                    finding.path, finding.line, expected),
            ))
    return records


def _excerpt(diff: str, line: int, span: int) -> str:
    """截取 diff 里 finding 附近的片段，供标注时看代码。

    给的是 diff 而不是整份文件：rubric 第 3 步要判"与本次改动是否相关"，
    只有 diff 能回答这个问题。
    """
    from .diff_parser import parse_unified_diff

    lines = diff.splitlines()
    # 找出 finding 那一行在 diff 文本里的位置。按**新文件行号**对齐，
    # 不是取第一条新增行——一个 diff 里可能有多个 hunk，取第一条会给出
    # 与告警无关的上下文，标注者判"相关性"时就看错了地方。
    parsed = parse_unified_diff(diff)
    target = next((item.content for item in parsed.added_lines
                   if item.line == line), None)
    center = 0
    if target is not None:
        for index, text in enumerate(lines):
            if text.startswith("+") and text[1:] == target:
                center = index
                break
    start = max(0, center - span)
    return "\n".join(lines[start:center + span + 1])


def sample_alerts(
    records: Sequence[AlertRecord], size: int, seed: int,
) -> List[AlertRecord]:
    """确定性抽样。

    先按 alert_id 排序再抽：records 的顺序取决于 reviewer 输出顺序，
    直接对它抽样的话，reviewer 一改输出顺序，同一个种子就抽到另一批，
    两轮重测对不上。排序把顺序依赖去掉。
    """
    ordered = sorted(records, key=lambda item: item.alert_id)
    if size >= len(ordered):
        return list(ordered)
    return random.Random(seed).sample(ordered, size)


def save_round(
    path: str, records: Sequence[AlertRecord], seed: int, round_name: str,
    stamp: str, source: str = "",
) -> None:
    """落盘一轮标注。

    stamp 由调用方传入而不是在这里取当前时间：取当前时间会让同一份输入
    产出不同文件，测试无法断言内容。时间戳的语义是"这一轮什么时候标的"，
    那是调用方才知道的事。
    """
    payload = {
        "rubric_version": RUBRIC_VERSION,
        "round": round_name,
        "seed": seed,                 # 入库，否则第二轮抽不到同一批
        "labelled_at": stamp,
        "source": source,
        "alerts": [vars(item) for item in records],
    }
    directory = os.path.dirname(path)
    if directory:
        os.makedirs(directory, exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, ensure_ascii=False, indent=2)


def load_round(path: str, blind: bool = False) -> Dict[str, Any]:
    """读一轮标注。blind=True 时剥掉 label 与 note。

    重测第二轮必须用 blind=True。这是工具层强制，不是靠标注者自觉——
    看到上轮标签就会锚定，一致率必然虚高，那测的是记忆而不是标准。
    """
    with open(path, encoding="utf-8") as handle:
        payload = json.load(handle)
    if blind:
        payload["alerts"] = [
            {key: value for key, value in item.items()
             if key not in {"label", "note"}}
            for item in payload["alerts"]
        ]
    return payload


def _ratio(numerator: int, denominator: int) -> Optional[float]:
    """分母为 0 返回 None。全库统一口径：没有样本 = 没有结论 ≠ 0.0。"""
    if denominator <= 0:
        return None
    return round(numerator / float(denominator), 4)


def effective_alert_rate(labels: Sequence[str]) -> Dict[str, Any]:
    """有效告警率。

    分母是 judgeable（= 总数 - unlabelled），不是总数。unlabelled 是
    "没有依据下判断"，留在分母里会把它当成误报，系统性低估。
    unlabelled 占比本身作为一个数单独报——它高就说明标注集覆盖不足，
    这个有效告警率能说明的事情就有限。
    """
    counts = {label: 0 for label in LABELS}
    for label in labels:
        counts[label] = counts.get(label, 0) + 1
    judgeable = sum(counts[label] for label in JUDGEABLE_LABELS)
    effective = sum(counts[label] for label in EFFECTIVE_LABELS)
    return {
        "counts": counts,
        "total": len(labels),
        "judgeable": judgeable,
        # 有效 = valid + valid-but-noise：问题真实存在。
        "effective_alert_rate": _ratio(effective, judgeable),
        # 严格版只算 valid。两个都报：前者答"说的对不对"，
        # 后者答"该不该在这个 PR 里说"。合成一个数会丢掉后一个问题。
        "strict_valid_rate": _ratio(counts[LABEL_VALID], judgeable),
        # 覆盖不足的直接指标。分母是总数（含 unlabelled），这里问的是
        # "这批告警里有多少判不了"，unlabelled 必须在分母里。
        "unlabelled_share": _ratio(counts[LABEL_UNLABELLED], len(labels)),
    }


def cohens_kappa(first: Sequence[str], second: Sequence[str]) -> Optional[float]:
    """两轮标注的 Cohen's κ。

    为什么不能只报原始一致率：标签分布不均时它会虚高。若 90% 的样本都是
    valid，一个每次都盲猜 valid 的标注者也能得到约 0.82 的一致率。
    κ 把"碰巧一致"的期望扣掉。

    返回 None 的两种情形都是"算不出"，不是"一致性为 0"：
      - 没有样本
      - 期望一致率恰好为 1（两轮都只用了同一个标签）——此时分母为 0
    """
    if not first or len(first) != len(second):
        return None
    total = len(first)
    observed = sum(1 for a, b in zip(first, second) if a == b) / float(total)
    expected = 0.0
    for label in set(list(first) + list(second)):
        expected += (first.count(label) / float(total)) * (
            second.count(label) / float(total))
    if expected >= 1.0:
        return None
    return round((observed - expected) / (1.0 - expected), 4)


def _paired_labels(
    round_one: Dict[str, Any], round_two: Dict[str, Any],
) -> Tuple[List[str], List[str], List[str]]:
    """按 alert_id 配对两轮标注，返回 (第一轮标签, 第二轮标签, 只出现一次的 id)。

    为什么按 alert_id 配对而不是按下标：第二轮是重新抽样保存的，
    文件里的顺序不保证和第一轮一致（save_round 不排序，抽样也可能改序）。
    按下标配对会把"标签相同但位置不同"记成不一致，一致率被无声压低。
    """
    first_map = {item["alert_id"]: item.get("label") for item in round_one["alerts"]}
    second_map = {item["alert_id"]: item.get("label") for item in round_two["alerts"]}
    shared = sorted(set(first_map) & set(second_map))
    unpaired = sorted(set(first_map) ^ set(second_map))
    return (
        [first_map[key] for key in shared],
        [second_map[key] for key in shared],
        unpaired,
    )


def retest_summary(
    round_one: Dict[str, Any], round_two: Dict[str, Any],
) -> Dict[str, Any]:
    """test-retest 汇总：自身一致率 + κ + 配对失败数。

    unpaired 单独报而不是静默丢弃：它不为 0 就说明两轮抽的不是同一批，
    此时一致率算的是两个不同集合的交集，代表性已经变了。
    """
    first, second, unpaired = _paired_labels(round_one, round_two)
    agreed = sum(1 for a, b in zip(first, second) if a == b)
    # 只在两轮都判得动的样本上再算一遍：unlabelled↔valid 的翻转是
    # "补上了依据"，和"标准不稳"是两回事，混在一起看不出是哪种。
    both_judgeable = [
        (a, b) for a, b in zip(first, second)
        if a in JUDGEABLE_LABELS and b in JUDGEABLE_LABELS
    ]
    return {
        "rubric_version": round_one.get("rubric_version"),
        "paired": len(first),
        "unpaired": unpaired,
        "raw_agreement": _ratio(agreed, len(first)),
        "cohens_kappa": cohens_kappa(first, second),
        "judgeable_paired": len(both_judgeable),
        "judgeable_agreement": _ratio(
            sum(1 for a, b in both_judgeable if a == b), len(both_judgeable)),
        # 两轮各自的有效告警率。差得远说明标准在漂，此时单轮的数字都不可信。
        "round_one_rate": effective_alert_rate(first)["effective_alert_rate"],
        "round_two_rate": effective_alert_rate(second)["effective_alert_rate"],
    }
