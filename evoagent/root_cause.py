"""根因指纹：把一条 failure_case 归到一个可计数的桶里。

## 为什么指纹必须是本地确定性的，不能用 LLM 聚类结果

原计划写的是"按聚类后的 root_cause_id 统计历史出现次数"。实现时发现这条
路有两个问题，都是结构性的：

1. **循环依赖**。聚类结果来自 `RootCauseEvolutionGenerator` 的那次 LLM
   调用，而统计出现次数的目的正是决定**要不要**发起那次调用。用调用的
   产出当调用的门禁输入，鸡生蛋。
2. **不可复现**。同一批 failure_case 两次跑出的簇名不同（LLM 采样、簇的
   粒度、命名都会漂），历史计数会随之漂。一个会漂的计数不能当阈值门禁的
   输入——今天 3 次达标，明天同样的数据 2 次不达标。

所以指纹在这里是**纯本地、纯确定性**的：只用 category + rule_id +
归一化路径，sha256 一下。它比 LLM 聚类粗（同一个 rule_id 在不同语义场景
下会被合并成一个桶），但它可复现、可解释、可当门禁输入。LLM 聚类仍然
有用，只是它的角色是**给人看的解释**，不是计数的依据。

## 为什么不落库成一列

`failure_cases` 表没有指纹列，而这里刻意不加。指纹是纯函数
`f(category, rule_id, path)`，随时可以现算；落库反而引入一个可能与函数
实现不一致的副本——改了归一化规则之后，老行里存的是旧指纹，新行是新的，
同一个根因会被算成两个桶。现算的成本是一次 sha256，可以忽略。

## 与轨道 F 的关系

轨道 F 的 val 晋升条件是"同一根因出现次数超过阈值"，用的必须是这里
同一个 `fingerprint()`。两处各写一份实现，就会出现"进 val 的标准"和
"触发候选生成的标准"悄悄分叉。
"""
import hashlib
import posixpath
import re
from typing import Any, Dict, Iterable, List, Optional


# 路径归一化：统一分隔符、去掉 ./ 前缀、小写化。不做更激进的归一化
# （比如剥掉目录只留文件名）——`a/utils.py` 和 `b/utils.py` 是两个文件，
# 合并它们会把不相关的缺陷算进同一个桶，从而虚高计数并让阈值提前达标。
_SEPARATORS = re.compile(r"[\\/]+")


def normalize_path(path: str) -> str:
    """把仓库内路径归一化到可比较的形式。"""
    value = _SEPARATORS.sub("/", str(path or "").strip())
    value = posixpath.normpath(value) if value else ""
    if value in {".", "/"}:
        return ""
    return value.lstrip("./").lower()


def fingerprint(
    category: str, rule_id: str = "", path: str = "",
) -> str:
    """一条 failure_case 的根因指纹（16 位十六进制）。

    截断到 16 位（64 bit）：这是一个用于分桶计数的键，不是安全摘要。
    64 bit 下的碰撞概率在本项目的数据规模（failure_case 量级 10^3-10^4）
    可以忽略，而短键让它在日志和报告里可读。
    """
    payload = "\x1f".join((
        str(category or "").strip().lower(),
        str(rule_id or "").strip().upper(),
        normalize_path(path),
    ))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]


def fingerprint_case(case: Dict[str, Any]) -> str:
    """从一条 store 里取出的 failure_case 行算指纹。

    `finding` 缺失或没有 rule_id 时，指纹退化为 (category, path) 甚至
    只有 category。这是刻意的：一条没有 rule_id 的反馈信息量确实更少，
    它会和其他同类无 rule_id 的反馈合并成一个粗桶。粗桶更容易达标阈值，
    但那也如实反映了"这个类别反复出现"——不精确，但不虚构。
    """
    payload = case.get("payload") or {}
    finding = payload.get("finding") or {}
    if not isinstance(finding, dict):
        finding = {}
    return fingerprint(
        str(case.get("category", "")),
        str(finding.get("rule_id", "")),
        str(finding.get("path", "")),
    )


def describe(case: Dict[str, Any]) -> str:
    """指纹的人类可读形式，用于报告和日志。"""
    payload = case.get("payload") or {}
    finding = payload.get("finding") or {}
    if not isinstance(finding, dict):
        finding = {}
    rule_id = str(finding.get("rule_id", "")).strip() or "no-rule"
    path = normalize_path(str(finding.get("path", ""))) or "no-path"
    return "%s@%s:%s" % (str(case.get("category", "")).strip(), rule_id, path)


def count_by_fingerprint(cases: Iterable[Dict[str, Any]]) -> Dict[str, int]:
    """按指纹计数。"""
    counts: Dict[str, int] = {}
    for case in cases:
        key = fingerprint_case(case)
        counts[key] = counts.get(key, 0) + 1
    return counts


def partition_by_occurrence(
    cases: List[Dict[str, Any]], history: Dict[str, int], threshold: int,
) -> Dict[str, List[Dict[str, Any]]]:
    """按"这个根因历史上出现过几次"把本轮 case 分成两档。

    `history` 是**含本轮**的全量计数（由调用方决定统计范围），不是
    "本轮之前"的计数。理由：一条根因在本轮里出现 3 次，和它在三轮里
    各出现 1 次，作为"这是系统性问题而非偶发"的证据强度是相当的；
    把本轮排除在外会让"一次性来了一批同类反馈"永远不达标。

    返回 `{"systematic": [...], "sporadic": [...]}`。低频的那一档不是
    被丢弃——调用方应当仍然把它写进记忆，只是不为它发起一次候选生成
    + 全量回放（那是几十次 LLM 调用的成本）。
    """
    threshold = max(1, int(threshold))
    systematic: List[Dict[str, Any]] = []
    sporadic: List[Dict[str, Any]] = []
    for case in cases:
        key = fingerprint_case(case)
        if history.get(key, 0) >= threshold:
            systematic.append(case)
        else:
            sporadic.append(case)
    return {"systematic": systematic, "sporadic": sporadic}