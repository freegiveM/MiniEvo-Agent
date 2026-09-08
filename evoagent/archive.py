"""版本档案与选亲：把"下一轮从哪个提示词改起"从隐式变成显式。

## 现状是单一血统爬山，这是一个已知的失效模式

改动之前，`_propose` 的 baseline 恒等于 `get_active_skill_version()`，
而被拒的候选存进 `skill_versions` 之后再无人问津——`parent_version` 这
一列有值，但没有任何代码读它来选亲。整个搜索退化成"从当前最优爬一步，
爬不上去就原地不动"。

两篇工作都直接指出这条路会卡死：

- **DGM**（arXiv:2505.22954）不维护单一血统，而是保留一个**档案**，每轮
  从档案里挑亲本。理由是"stepping stones"：一个当下分数平庸的版本，可能
  是后来突破的必要祖先。只从当前最优出发会锁死在局部最优。
- **GEPA**（arXiv:2507.19457）进一步指出，用**聚合分数**挑亲本会把
  "专才"淘汰掉——一个总分略低但在某几个 case 上唯一正确的候选，携带着
  别处没有的信息。它改为在**逐样本的 Pareto 前沿**上采样。

这个项目的 `evolution_runs.metrics.case_results` 恰好已经逐 case 记了
tp/fp/fn，所以 GEPA 那套 per-instance 前沿不需要新采数据，是现成的。

## 这个模块**不**改门禁

必须分清两个问题：

1. "候选比**正在服务真实流量的版本**更好吗" → 门禁问题，baseline 必须
   是 active 版本，这条不变。
2. "下一轮从哪个提示词改起" → 搜索问题，从档案里选亲。

只有 2 是这里管的。把 1 也改成"跟档案里最优比"会让门禁失去意义——它要
回答的就是"能不能替换掉现在这个"。所以 `select_parent` 的产出只影响
生成候选的起点，不进入 `decision` 的计算。

## 默认值仍然是 active

`strategy="active"` 是默认，行为与本改动之前完全一致。切到 `pareto` 或
`epsilon_greedy` 是一个显式选择——因为在当前样本量（validation 区间宽度
0.15-0.17）下，"档案里哪个更好"这个判断本身噪声很大，激进选亲有可能只是
在噪声里随机游走。基建先就位，策略切换等有数据支撑再说。
"""
import hashlib
from typing import Any, Dict, List, Optional, Sequence


STRATEGIES = ("active", "best", "pareto", "epsilon_greedy")


def _case_key(result: Dict[str, Any]) -> str:
    """逐样本前沿的键。

    优先用 case id，回落到 name。两者都缺时返回空串，调用方会跳过——
    一条认不出属于哪个 case 的结果无法参与逐样本比较。
    """
    for field in ("id", "name"):
        value = result.get(field)
        if value not in (None, ""):
            return str(value)
    return ""


def _case_score(result: Dict[str, Any]) -> Optional[float]:
    """单个 case 上的表现，用 F1 口径。

    与 `RegressionEvaluator` 的全局 f1 同一个公式（2tp/(2tp+fp+fn)），
    所以逐样本分数和总分是可以相互解释的。

    报错的 case 返回 None 而不是 0.0：一次调用失败不等于"测了得零分"，
    把它算成 0 会让一次网络抖动看起来像能力退化。这与
    `RegressionEvaluator` 的空分母口径是同一条原则。
    """
    if result.get("error"):
        return None
    try:
        tp = int(result.get("tp", 0))
        fp = int(result.get("fp", 0))
        fn = int(result.get("fn", 0))
    except (TypeError, ValueError):
        return None
    denominator = 2 * tp + fp + fn
    if denominator <= 0:
        # 没有期望、也没有误报 —— 这是一个干净样本被正确放过。算满分。
        return 1.0
    return (2 * tp) / denominator


def build_archive(
    versions: Sequence[Dict[str, Any]], runs: Sequence[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """把版本链和评测记录合成一份档案。

    每条记录带：version、score、是否 active、以及**逐样本分数表**（如果
    这个版本跑过评测）。逐样本表来自 `evolution_runs.metrics.candidate
    .case_results`，不需要重跑评测。

    没跑过评测的版本（deferred，比如当时没配模型）也留在档案里，只是
    `case_scores` 为空。不剔掉它们：DGM 的 stepping-stone 论点是"当下
    看不出价值的版本可能是后来突破的祖先"，而"没测过"比"测了很差"离
    "没价值"更远。
    """
    by_version: Dict[int, Dict[str, Any]] = {}
    for item in versions:
        version = item.get("version")
        if version is None:
            continue
        by_version[int(version)] = {
            "version": int(version),
            "prompt": item.get("prompt", ""),
            "score": float(item.get("score", 0.0) or 0.0),
            "active": bool(item.get("active")),
            "parent_version": item.get("parent_version"),
            "created_at": item.get("created_at", ""),
            "case_scores": {},
            "decision": None,
        }

    # 同一个版本可能有多条 run（重跑），取最近一条 —— runs 由 store 按
    # created_at DESC 返回，所以先到的是最新的，后面的不覆盖。
    for run in runs:
        version = run.get("candidate_version")
        if version is None:
            continue
        entry = by_version.get(int(version))
        if entry is None or entry["case_scores"]:
            continue
        entry["decision"] = run.get("decision")
        metrics = run.get("metrics") or {}
        candidate = metrics.get("candidate") or {}
        for result in candidate.get("case_results") or []:
            key = _case_key(result)
            if not key:
                continue
            score = _case_score(result)
            if score is not None:
                entry["case_scores"][key] = score

    return [by_version[key] for key in sorted(by_version, reverse=True)]


def pareto_frontier(archive: Sequence[Dict[str, Any]]) -> List[int]:
    """逐样本 Pareto 前沿上的版本号。

    定义（跟 GEPA 一致）：对每一个 case，找出在它上面取得最高分的版本；
    所有"在至少一个 case 上是最优"的版本构成前沿。

    这与"总分最高"是两件不同的事。一个总分略低、但在三条别人全错的
    case 上唯一正确的版本会进前沿——它携带着别处没有的信息，用总分排序
    会把它淘汰掉。

    没有任何逐样本数据时返回空列表，不是返回全部版本。调用方据此回落到
    别的策略——把"没有可比数据"伪装成"所有版本都在前沿"会让选亲变成
    随机抽取，而调用方以为自己在用 Pareto。
    """
    best_by_case: Dict[str, float] = {}
    for entry in archive:
        for case, score in entry["case_scores"].items():
            if case not in best_by_case or score > best_by_case[case]:
                best_by_case[case] = score
    if not best_by_case:
        return []
    frontier = set()
    for entry in archive:
        for case, score in entry["case_scores"].items():
            if score >= best_by_case[case]:
                frontier.add(entry["version"])
                break
    return sorted(frontier)


def frontier_weights(archive: Sequence[Dict[str, Any]]) -> Dict[int, int]:
    """每个版本在多少个 case 上是最优的。

    GEPA 用这个数当采样权重：在更多 case 上领先的版本更可能被选为亲本，
    但领先少数 case 的专才仍有非零概率。这里只算权重，不做采样——采样
    需要随机源，而随机源会让选亲不可复现，见 `select_parent` 的说明。
    """
    best_by_case: Dict[str, float] = {}
    for entry in archive:
        for case, score in entry["case_scores"].items():
            if case not in best_by_case or score > best_by_case[case]:
                best_by_case[case] = score
    weights: Dict[int, int] = {}
    for entry in archive:
        count = sum(
            1 for case, score in entry["case_scores"].items()
            if score >= best_by_case.get(case, 0.0)
        )
        if count:
            weights[entry["version"]] = count
    return weights


def select_parent(
    archive: Sequence[Dict[str, Any]], strategy: str = "active",
    seed: str = "", epsilon: float = 0.1,
) -> Optional[Dict[str, Any]]:
    """选出下一轮要改起的亲本。

    ## 为什么是确定性的伪随机，而不是 random.random()

    选亲影响候选内容，而候选内容进落盘记录、进 `evolution_runs`。用真
    随机源会让同一份输入两次跑出不同的亲本，那么"这次为什么产出了这个
    候选"就再也无法复现——而可复现是这个项目现有评测记录（提示词
    SHA-256、数据集指纹）一直在维护的性质。

    所以随机性来自 `seed` 的 sha256：调用方传一个稳定的种子（比如
    run 的输入指纹），同一输入永远选出同一个亲本，而不同输入之间的分布
    仍然是散的。

    ## 策略

    - `active`（默认）：当前服务真实流量的版本。行为与本改动之前一致。
    - `best`：档案里总分最高的。经典爬山，会淘汰专才。
    - `pareto`：逐样本前沿上按领先 case 数加权采样（GEPA）。
    - `epsilon_greedy`：以 epsilon 概率在全档案里采，否则取总分最高。

    没有可用数据时每个策略都回落到 `active`，回落是显式的（返回值里带
    `selection`），不静默。
    """
    if strategy not in STRATEGIES:
        raise ValueError("unsupported parent selection strategy: %s" % strategy)
    if not archive:
        return None

    active = next((item for item in archive if item["active"]), None)
    best = max(archive, key=lambda item: (item["score"], item["version"]))

    def _pick(entry, how, fallback_from=""):
        chosen = dict(entry)
        chosen["selection"] = {
            "strategy": strategy, "resolved": how,
            "fell_back_from": fallback_from,
        }
        return chosen

    if strategy == "active":
        return _pick(active or best, "active" if active else "best",
                     "" if active else "active")
    if strategy == "best":
        return _pick(best, "best")

    if strategy == "pareto":
        weights = frontier_weights(archive)
        if not weights:
            return _pick(active or best, "active" if active else "best", "pareto")
        picked = _weighted_choice(weights, seed)
        entry = next(item for item in archive if item["version"] == picked)
        return _pick(entry, "pareto")

    # epsilon_greedy
    if _unit_interval(seed) < max(0.0, min(1.0, epsilon)):
        picked = sorted(item["version"] for item in archive)
        chosen_version = picked[
            int(_unit_interval(seed + ":explore") * len(picked)) % len(picked)
        ]
        entry = next(item for item in archive if item["version"] == chosen_version)
        return _pick(entry, "explore")
    return _pick(best, "exploit")


def _unit_interval(seed: str) -> float:
    """把种子映射到 [0, 1)。确定性，无随机源。"""
    digest = hashlib.sha256(seed.encode("utf-8")).digest()
    return int.from_bytes(digest[:8], "big") / float(1 << 64)


def _weighted_choice(weights: Dict[int, int], seed: str) -> int:
    total = sum(weights.values())
    if total <= 0:
        return min(weights)
    target = _unit_interval(seed) * total
    cumulative = 0.0
    for version in sorted(weights):
        cumulative += weights[version]
        if target < cumulative:
            return version
    return max(weights)


def summarise(archive: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    """档案的报告视图。

    `versions_never_evaluated` 单独报出来：它是"档案里有多少条其实没有
    可比数据"，直接决定了 Pareto 选亲此刻有多少信息可用。混在总数里会
    让一个 20 版本的档案看起来比它实际能支撑的搜索更丰富。
    """
    frontier = pareto_frontier(archive)
    evaluated = [item for item in archive if item["case_scores"]]
    return {
        "versions": len(archive),
        "versions_evaluated": len(evaluated),
        "versions_never_evaluated": len(archive) - len(evaluated),
        "pareto_frontier": frontier,
        "frontier_size": len(frontier),
        "frontier_weights": frontier_weights(archive),
        "active_version": next(
            (item["version"] for item in archive if item["active"]), None),
        "best_version": (
            max(archive, key=lambda item: (item["score"], item["version"]))["version"]
            if archive else None
        ),
        "decisions": _count_decisions(archive),
    }


def _count_decisions(archive: Sequence[Dict[str, Any]]) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for entry in archive:
        key = entry.get("decision") or "unknown"
        counts[key] = counts.get(key, 0) + 1
    return counts