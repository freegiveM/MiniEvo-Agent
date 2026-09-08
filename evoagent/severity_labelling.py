"""expected_findings 严重度/类别重标注的口径、盲化与分歧统计。

配套 rubric 见 docs/severity-rubric.md。这里只实现口径，判定标准在文档里
（与 alert_labelling.py 同一分工）。

四条硬约束，都写进代码而不是靠 prompt 里写一句"请忽略"：

  1. **盲化**。judge 看不到原 severity/defect_class/cwe。看到就会锚定，
     分歧率必然虚低——那测的是"judge 能不能复读正则"。`blind_finding`
     主动剥掉这三个字段，而不是指望 prompt 自觉。
  2. **特权上下文照给**。human_patch（人类真实修复补丁）与 fix_pr_title
     必须给——它们不是答案泄漏：判的是"这个缺陷有多严重"，修复补丁
     揭示的是缺陷**性质**而非严重度档位。这正是把 judge 抬到接近人工
     标注的关键，也是原正则标注拿不到的信息。
  3. **不覆盖原标签**。重标结果并存于 `severity_llm`/`defect_class_llm`,
     原字段原样保留，`label_source` 标 "llm-judge-v1"。与轨道 C 的
     inferred-from-merge / manual-feedback 分档同一条原则：不同置信度的
     标注不能合并成同一个字段。
  4. **逐条落盘**。165 条判定是花钱的 API 调用，一次失败不能全部重来。
     `CheckpointStore` 每条 append + fsync，重跑跳过已完成的。
"""
import json
import os
import random
from typing import Any, Dict, List, Optional, Sequence

from .alert_labelling import _ratio, cohens_kappa

RUBRIC_VERSION = "severity-v1"
LABEL_SOURCE = "llm-judge-v1"

# 与 rubric 的四档一一对应。改这里必须同步改 docs/severity-rubric.md。
SEVERITIES = ("low", "medium", "high", "critical")
SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}

# 原八类（dataset_builder.DEFECT_CLASSES）+ 扩展类。扩展的理由见 rubric：
# 八类覆盖不住真实 bugfix 的主体，硬塞进去等于让 logic-boundary 当垃圾桶。
ORIGINAL_CLASSES = (
    "crypto-weak", "injection", "secret-exposure", "path-traversal",
    "concurrency", "resource-leak", "auth-bypass", "logic-boundary",
)
EXTENDED_CLASSES = (
    "input-validation", "contract-type", "state-machine",
    "encoding-escaping", "error-handling", "api-misuse", "no-defect",
)
DEFECT_CLASSES = ORIGINAL_CLASSES + EXTENDED_CLASSES

# confidence 低于此值计入 low_confidence_share 单独报。作用同
# alert_labelling 的 unlabelled_share：它高就说明即便有特权上下文也判不动。
LOW_CONFIDENCE_THRESHOLD = 0.5

# 盲化要剥掉的字段。单独列成常量而不是写死在函数里：这三个字段名若在
# 数据集里改了，漏改这里会导致静默泄漏，常量至少能被 grep 到。
BLINDED_FIELDS = ("severity", "defect_class", "cwe")

# 占位 CWE。schema 要求每条都给 cwe，judge 判成 no-defect 时无 CWE 可填，
# 于是编一个出来——v1 全量实测 164 条里有 5 条：CWE-000 ×3、CWE-0、N/A。
# 这不是 judge 乱答，是被 schema 逼的。归一化成 ""（无编号）而不是留着：
# "CWE-000" 混在真编号里会被下游当成一个真实的 CWE 分类。
#
# 不计入 invalid_fields：rubric 明确 CWE 不参与 severity 判定，也明确
# 不为 CWE 编号不精确扣分，把它当"judge 没按 schema 答"记账会污染
# invalid_field_count 这个本来用于发现真实 schema 违规的信号。
PLACEHOLDER_CWES = frozenset({
    "", "N/A", "NA", "NONE", "NULL", "UNKNOWN", "CWE-0", "CWE-000", "CWE-NONE",
})


def normalise_cwe(raw: Any) -> str:
    """把 judge 给的 cwe 归一化；占位/编造值收成空字符串。"""
    value = str(raw or "").strip().upper()
    return "" if value in PLACEHOLDER_CWES else value


def finding_id(case_id: str, path: str, start_line: int) -> str:
    """一条 expected_finding 的稳定标识。

    用 (case, path, start_line) 而不是数组下标：下标会随数据集重新生成
    而变化，两轮之间对不上。同一个 case 同一文件同一起始行只可能有一条
    expected_finding（dataset_builder 按位置去重），三元组足以定位。
    """
    return "%s|%s|%d" % (case_id, path.replace("\\", "/"), start_line)


def blind_finding(finding: Dict[str, Any]) -> Dict[str, Any]:
    """给 judge 看的形态：剥掉原 severity/defect_class/cwe。

    这是盲测协议的技术实现，对应 rubric"不能看到"那一节。保留 path 与
    行号——judge 需要知道判的是哪一处。
    """
    return {
        key: value for key, value in finding.items()
        if key not in BLINDED_FIELDS
    }


def build_judge_payload(record: Dict[str, Any]) -> Dict[str, Any]:
    """把一条 case 组装成 judge 的输入。

    刻意**不**含 reviewer 的输出：judge 若看到被评测对象报了什么会向它
    靠拢，等于让被测者参与制定尺子。也不含原标签（见 blind_finding）。
    """
    return {
        "repository": record.get("repository", ""),
        "domain": record.get("domain", ""),
        "fix_pr_title": record.get("fix_pr_title", ""),
        # 人类真实修复补丁。修复动作的形态直接反映缺陷性质：
        # 加锁→并发，加校验→输入校验，改比较符→边界。
        "human_patch": record.get("human_patch", ""),
        "diff_under_review": record.get("diff", ""),
        "locations_to_judge": [
            blind_finding(item) for item in record.get("expected_findings", [])
        ],
    }


def normalise_verdict(raw: Dict[str, Any]) -> Dict[str, Any]:
    """把 judge 的一条原始输出归一化。

    非法值不静默改写成默认值就完事——那会把"judge 没按 schema 答"伪装成
    一个正常判定。落进 `invalid_fields` 里单独报，让它可被追。
    """
    invalid: List[str] = []

    severity = str(raw.get("severity", "")).strip().lower()
    if severity not in SEVERITY_RANK:
        invalid.append("severity=%r" % raw.get("severity"))
        severity = None

    defect_class = str(raw.get("defect_class", "")).strip().lower()
    if defect_class not in DEFECT_CLASSES:
        invalid.append("defect_class=%r" % raw.get("defect_class"))
        defect_class = None

    try:
        confidence = float(raw.get("confidence", 0.0))
    except (TypeError, ValueError):
        invalid.append("confidence=%r" % raw.get("confidence"))
        confidence = 0.0
    confidence = max(0.0, min(1.0, confidence))

    return {
        "severity_llm": severity,
        "defect_class_llm": defect_class,
        "cwe_llm": normalise_cwe(raw.get("cwe")),
        "confidence": round(confidence, 3),
        # basis 必须引用 diff/human_patch 的具体内容（rubric 要求），
        # 这里不做内容校验——自动判"是否真的引用了"不可靠，留给人工抽查。
        "basis": str(raw.get("basis", ""))[:1000],
        "invalid_fields": invalid,
        "label_source": LABEL_SOURCE,
        "rubric_version": RUBRIC_VERSION,
    }


def _renormalise(record: Dict[str, Any]) -> Dict[str, Any]:
    """对读回来的 checkpoint 条目重跑一遍纯归一化。

    为什么需要：checkpoint 里的条目是**上一次运行**的 `normalise_verdict`
    产物，重跑时直接拿来用会绕过归一化逻辑的后续修正。v1 全量跑完后才发现
    5 条编造的占位 CWE（CWE-000/CWE-0/N/A），修了 `normalise_cwe` 但那 94 条
    缓存条目仍然带着旧值——花钱的 API 调用不该为了一次纯本地的字段清洗
    重跑，所以在读取侧补这一道。

    只做**不需要重新调用 LLM 的纯函数级归一化**。任何需要重新判定的修正
    （比如改了 rubric、换了 severity 档位定义）都不能在这里悄悄做——那要
    换 RUBRIC_VERSION 并真的重跑，否则结果里会混着两套口径的标签。
    """
    for verdict in record.get("verdicts") or []:
        verdict["cwe_llm"] = normalise_cwe(verdict.get("cwe_llm"))
    return record


class CheckpointStore:
    """逐条落盘的 JSONL 存储。

    165 条判定是花钱的 API 调用，一次失败不能全部重来——这与
    scripts/run_real_pr_regression_replay.py 的 CheckpointedReviewer 是
    同一条要求，也是同一个教训的产物（那次全量 replay 卡死两小时，
    进度全丢）。每条写完立刻 flush + fsync，硬杀进程也不丢已完成的。
    """

    def __init__(self, path: str):
        self.path = path
        self.done: Dict[str, Dict[str, Any]] = {}
        if path and os.path.exists(path):
            with open(path, "r", encoding="utf-8") as handle:
                for line in handle:
                    line = line.strip()
                    if not line:
                        continue
                    record = json.loads(line)
                    self.done[record["case_id"]] = _renormalise(record)

    def append(self, record: Dict[str, Any]) -> None:
        self.done[record["case_id"]] = record
        if not self.path:
            return
        os.makedirs(os.path.dirname(os.path.abspath(self.path)) or ".", exist_ok=True)
        with open(self.path, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, ensure_ascii=False) + "\n")
            handle.flush()
            os.fsync(handle.fileno())


# 人工校准轮要剥掉的字段。judge 的判定与依据全剥，**原标签也剥**——
# 原 severity 正是这次要证伪的对象，让人工看见就是让它锚定到被告席上。
# 同 alert-rubric 的盲测协议：工具层强制，不靠标注者自觉。
CALIBRATION_BLINDED_FIELDS = (
    "severity_llm", "defect_class_llm", "cwe_llm", "basis", "confidence",
    "invalid_fields", "original_severity", "original_defect_class",
    "original_cwe",
)

# 人工校准的判定门槛。两条必须**同时**满足，理由见 docs/severity-rubric.md：
# κ 单独达标可能建立在少数极端档位上，原始一致率单独达标可能只是碰巧
# ——147/165 都是 medium 的分布下，常量猜测就能拿到约 0.89 的原始一致率。
CALIBRATION_MIN_KAPPA = 0.6
CALIBRATION_MIN_AGREEMENT = 0.85


def stratified_calibration_sample(
    verdicts: Sequence[Dict[str, Any]], per_bucket: int = 10, seed: int = 0,
) -> List[Dict[str, Any]]:
    """按**新** severity 分层抽样，每桶 ≥per_bucket 条（不足则全取）。

    为什么按新 severity 而不是随机抽：新标签把 high_or_above 从 18 抬到
    44，最需要校准的恰恰是这批被抬上去的。随机抽 40 条会按分布落在
    medium 上（71/165），critical 只有 1 条大概率一条都抽不到——而那 1 条
    的对错直接影响 high_severity_recall 的分母。

    为什么不按 confidence 优先抽：v1 实测 `low_confidence_share = 0.0`，
    最低 0.7，这个信号在当前数据上是死的，用它排序等于随机排序。

    排序后再抽（不依赖 dict 迭代顺序或输入顺序），同一个 seed 在任何机器
    上抽到同一批——这是"抽样种子入库，保证可复现"的实现。
    """
    buckets: Dict[str, List[Dict[str, Any]]] = {}
    for item in verdicts:
        severity = item.get("severity_llm")
        if severity in SEVERITY_RANK:
            buckets.setdefault(severity, []).append(item)

    picked: List[Dict[str, Any]] = []
    for severity in SEVERITIES:
        pool = sorted(
            buckets.get(severity, []), key=lambda item: item.get("finding_id", ""),
        )
        rng = random.Random("%d|%s" % (seed, severity))
        # 每桶用独立 rng：加大 per_bucket 时已抽中的条目仍会被抽中，
        # 两批校准结果可以合并而不是互相不可比。
        rng.shuffle(pool)
        picked.extend(pool[: max(0, per_bucket)])
    return picked


def blind_for_calibration(verdict: Dict[str, Any]) -> Dict[str, Any]:
    """人工轮看到的形态：剥掉 judge 判定与原标签，留下定位和待填字段。"""
    item = {
        key: value for key, value in verdict.items()
        if key not in CALIBRATION_BLINDED_FIELDS
    }
    # 待填字段显式留空，人工直接改 json 即可；判不动的填 None 而不是硬凑
    # （同 alert-rubric 的 unlabelled：硬凑出来的一致率没有意义）。
    item["severity_human"] = None
    item["defect_class_human"] = None
    item["note"] = ""
    return item


def calibration_report(pairs: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    """人工 vs judge 的一致率、κ、漂移矩阵与门禁判定。

    `pairs` 每项需含 severity_human 与 severity_llm。人工未判（None 或
    非法值）的条目不进分母——它没有判定可比，留在分母里会把"没判"
    当成"判得不一样"，系统性压低一致率。
    """
    judged = [
        item for item in pairs
        if item.get("severity_human") in SEVERITY_RANK
        and item.get("severity_llm") in SEVERITY_RANK
    ]
    human = [item["severity_human"] for item in judged]
    llm = [item["severity_llm"] for item in judged]
    agreed = sum(1 for a, b in zip(human, llm) if a == b)

    agreement = _ratio(agreed, len(judged))
    kappa = cohens_kappa(human, llm)
    # 三态。任一为 None（没样本 / κ 无定义）时**不能**collapse 成 False：
    # 那会把"没测"伪装成"测了没过"。
    if agreement is None or kappa is None:
        meets_gate: Optional[bool] = None
    else:
        meets_gate = (
            kappa >= CALIBRATION_MIN_KAPPA
            and agreement >= CALIBRATION_MIN_AGREEMENT
        )

    return {
        "rubric_version": RUBRIC_VERSION,
        "label_source": LABEL_SOURCE,
        "sampled": len(pairs),
        "judged_by_human": len(judged),
        "agreement": agreement,
        "kappa": kappa,
        "drift": severity_drift(human, llm),
        "min_kappa": CALIBRATION_MIN_KAPPA,
        "min_agreement": CALIBRATION_MIN_AGREEMENT,
        "meets_gate": meets_gate,
        # 达标才允许写"LLM 标注，人工抽查校准一致率 x%"；仍不得简写成
        # "人工标注数据集"。未达标只能写"LLM 重标，未通过人工校准"，
        # 且不得用于门禁。
        "claim_allowed": (
            "LLM 标注，人工抽查校准一致率 %s" % agreement if meets_gate
            else "LLM 重标，未通过人工校准（不得用于门禁）"
        ),
    }


def severity_drift(
    original: Sequence[str], relabelled: Sequence[str],
) -> Dict[str, Dict[str, int]]:
    """混淆矩阵（原 severity → 新 severity）。

    为什么不能只报一个一致率标量：整体升级和整体降级对
    high_severity_recall 的影响方向**相反**（分母变大 vs 变小），
    一个标量看不出是哪种，而这正是重标最想知道的事。
    """
    matrix: Dict[str, Dict[str, int]] = {
        old: {new: 0 for new in SEVERITIES} for old in SEVERITIES
    }
    for old, new in zip(original, relabelled):
        if old in matrix and new in matrix[old]:
            matrix[old][new] += 1
    return matrix


def relabel_summary(pairs: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    """重标结果汇总：分歧率 + κ + 漂移矩阵 + 低置信占比。

    `pairs` 每项需含 original_severity / severity_llm / confidence /
    defect_class（原）/ defect_class_llm。
    """
    judged = [
        item for item in pairs
        if item.get("severity_llm") in SEVERITY_RANK
        and item.get("original_severity") in SEVERITY_RANK
    ]
    original = [item["original_severity"] for item in judged]
    relabelled = [item["severity_llm"] for item in judged]
    agreed = sum(1 for a, b in zip(original, relabelled) if a == b)

    upgraded = sum(
        1 for a, b in zip(original, relabelled)
        if SEVERITY_RANK[b] > SEVERITY_RANK[a]
    )
    downgraded = sum(
        1 for a, b in zip(original, relabelled)
        if SEVERITY_RANK[b] < SEVERITY_RANK[a]
    )

    high_before = sum(1 for item in original if SEVERITY_RANK[item] >= SEVERITY_RANK["high"])
    high_after = sum(1 for item in relabelled if SEVERITY_RANK[item] >= SEVERITY_RANK["high"])

    class_counts: Dict[str, int] = {}
    for item in pairs:
        key = item.get("defect_class_llm") or "(invalid)"
        class_counts[key] = class_counts.get(key, 0) + 1

    low_conf = sum(
        1 for item in pairs
        if float(item.get("confidence", 0.0)) < LOW_CONFIDENCE_THRESHOLD
    )
    invalid = sum(1 for item in pairs if item.get("invalid_fields"))

    return {
        "rubric_version": RUBRIC_VERSION,
        "label_source": LABEL_SOURCE,
        "total": len(pairs),
        "judged": len(judged),
        "severity_agreement": _ratio(agreed, len(judged)),
        # κ 必报：147/165 都是 medium，一个每次都猜 medium 的 judge 也能
        # 拿到约 0.79 的原始一致率。κ 扣掉碰巧一致的期望。
        "severity_kappa": cohens_kappa(original, relabelled),
        "upgraded": upgraded,
        "downgraded": downgraded,
        "severity_drift": severity_drift(original, relabelled),
        # 直接回答"high_severity_recall 的分母会怎么变"。
        "high_or_above_before": high_before,
        "high_or_above_after": high_after,
        "defect_class_distribution": dict(
            sorted(class_counts.items(), key=lambda kv: -kv[1])
        ),
        "no_defect_count": class_counts.get("no-defect", 0),
        "low_confidence_share": _ratio(low_conf, len(pairs)),
        "invalid_field_count": invalid,
    }