"""轨道 F：把**已人工确认**的 `failure_case` 提升成评测样本。

## 提升的目标是 `evaluation_cases`，不是 `datasets/*.jsonl`

这一点接手时最容易搞反。`datasets/real-pr-v1.jsonl` 是**输入语料**（95 条，
权威，不得静默重新生成，见交接文档第 11 节）；而 `_propose` 每轮真正拿来
打分的是 store 里的 `evaluation_cases` 表，现在只有 `DEFAULT_EVALUATION_CASES`
那几条 builtin 合成样本。所以"反馈变成样本"只能是写进 `evaluation_cases`：
写回 jsonl 既违反那条约束，也进不了进化回路。

## 三层里只有两层能落地，第三层显式记为局限

交接文档第 5 节口径 2 说 `bad_fix` "没有对应的指标槽位"。查证属实：
`_non_regressing` 的受保护指标（`score` / `precision` / `recall` /
`high_severity_recall` + 条件性的 `severity_accuracy` / `clean_accuracy`）
全部是**检出**指标。一条"发现对了但修复建议是错的"反馈提升成样本之后，
对任何一个指标都没有影响。

所以 `promote_case` **拒绝**提升 `bad_fix`，并在报告里写明原因是"当前评测
体系没有修复质量的真值"（第 13 节 B 的选项 3）。不选"加一个 fix_quality
指标"是因为数据集里没有修复建议的真值，那会造出又一个 `completeness`
式的空指标；不选"静默跳过"是因为一条被静默丢掉的反馈和一条被评估过后
判定不该提升的反馈，在报告上长得一模一样。

## `false_positive` 不能无条件当负样本

口径 2 原文是"`false_positive` 该进负样本（空 `expected_findings` →
clean_accuracy 侧）"。这一条**只在源样本本身干净时成立**。

`real-pr-v1.jsonl` 的每条样本都是反转 fix PR 得到的，diff 里**含着一个种子
缺陷**。拿这样一个 diff 配上 `expected_findings=[]` 写进评测集，断言的是
"这里不该报任何东西"——而这是假的：那个种子缺陷真的在里面，reviewer 报它
是对的。这个样本会把"报对了真缺陷"记成 clean_accuracy 上的一次失败，方向
正好教反。这与 `feedback_import` 拒绝把"标注外但确认有效"当误报是同一个
错误的另一副面孔。

所以：源样本 `expected_findings` 为空（来自 `real-pr-clean-v1.jsonl` 那批
负样本）时才提升成 clean 样本；否则拒绝，理由写清。宁可少一条样本，不要
一条方向反的样本。

## split 跟随仓库已有的一侧，且 holdout 一律拒绝

`tests/test_rejection_proof.py::test_repositories_do_not_cross_the_split_boundary`
钉的约束是仓库不跨分区——一个仓库同时出现在两边，holdout 就不再是"没见过
的分布"。所以提升出来的样本的 split 必须**查**仓库在语料里已有的一侧，
不能默认 validation。仓库在语料里查不到时拒绝而不是猜：猜错的后果是
holdout 被污染，而它在报告上完全看不出来。

仓库落在 holdout 一侧时同样拒绝：holdout 的反馈进了进化回路就等于拿隐藏集
调参（`derive_candidates` 的 `splits` 默认只取 validation 就是为了防这个）。
这里再拦一道，因为那个默认值可以被 `--splits` 覆盖。
"""
from typing import Any, Dict, List, Optional, Sequence

from .evolution import EvolutionEngine

# 能提升的类别，以及提升成哪一侧样本。
CATEGORY_POSITIVE = "missed_issue"
CATEGORY_CLEAN = "false_positive"

# 明确拒绝的类别。值是拒绝理由，会原样进报告——一条"评估过后判定不该提升"
# 的反馈必须与"被静默丢掉"分得开。
REFUSED_CATEGORIES = {
    "bad_fix": (
        "the evaluation system has no ground truth for fix quality; every "
        "protected metric (score/precision/recall/high_severity_recall/"
        "severity_accuracy/clean_accuracy) measures detection only, so a "
        "promoted bad_fix sample would enlarge the dataset without testing "
        "anything new"
    ),
    "accepted": (
        "an accepted review is not a defect signal; promoting it would add a "
        "sample with no expectation to check"
    ),
    "execution_error": (
        "an execution error is an outage, not a review defect; the harness "
        "already counts failed replays as missed positives"
    ),
}

# 只有人工确认过的类别才允许走到这里。与 `HUMAN_CONFIRMED_CATEGORIES`
# 同一份白名单，刻意复用而不是另写：另写一份，两份迟早分叉，而分叉的表现
# 是一条推断出来的类别绕过了确认闸门进了评测集。
CONFIRMED = EvolutionEngine.HUMAN_CONFIRMED_CATEGORIES


def split_index(cases: Sequence[dict]) -> Dict[str, str]:
    """仓库 → 它在语料里所在的 split。

    仓库跨分区时抛错而不是取其一：语料本身已经坏了，在这种语料上继续提升
    只会把污染扩大，而且下游那道 `test_repositories_do_not_cross_the_split_boundary`
    检查的是语料而不是提升结果，不会替我们发现。
    """
    sides: Dict[str, set] = {}
    for case in cases:
        repository = str(case.get("repository", "") or "")
        if not repository:
            continue
        sides.setdefault(repository, set()).add(str(case.get("split", "")))
    index: Dict[str, str] = {}
    for repository, splits in sorted(sides.items()):
        if len(splits) != 1:
            raise ValueError(
                "%s already crosses the split boundary (%s); refusing to "
                "promote against a corpus that violates the constraint the "
                "promotion is supposed to preserve"
                % (repository, ", ".join(sorted(splits)))
            )
        index[repository] = splits.pop()
    return index


def _case_index(cases: Sequence[dict]) -> Dict[str, dict]:
    return {str(case["id"]): case for case in cases}


def _expected_from_payload(payload: Dict[str, Any]) -> List[dict]:
    """`failure_case.payload.finding` → 一条 `expected_findings` 条目。

    字段名不同：评测样本用 `min_severity`（下限，`>=` 判定），反馈里存的是
    `severity`（那一条 finding 的严重度）。直接改名而不是补一个默认值：
    severity 缺失时给 "low" 等于把"不知道多严重"写成"最轻"，而这道下限
    会被 `high_severity_recall` 读，写低了那条受保护指标的分母就少一个。
    """
    finding = dict(payload.get("finding") or {})
    severity = str(finding.get("severity", "")).strip().lower()
    if not severity:
        raise ValueError("the confirmed finding carries no severity")
    expected: Dict[str, Any] = {
        "path": finding["path"],
        "line": int(finding["line"]),
        "min_severity": severity,
    }
    # rule_id 只在人工填过时才有（见 `feedback_import.build_payload`：拿 cwe
    # 顶替 rule_id 会往提示词里注入一条谁也执行不了的 `[focus-rule:CWE-193]`）。
    rule_id = str(finding.get("rule_id", "") or "").strip()
    if rule_id:
        expected["rule_id"] = rule_id
    if finding.get("cwe"):
        expected["cwe"] = finding["cwe"]
    return [expected]


def promote_case(
    failure_case: Dict[str, Any], cases: Sequence[dict],
    splits: Optional[Dict[str, str]] = None,
    name_prefix: str = "d6-confirmed",
) -> Dict[str, Any]:
    """判定一条反馈能不能提升，能的话产出待写入的评测样本。

    **只产出，不写库。** 判定与写入分开，因为"这批反馈里有几条能提升、被拒
    的各是什么理由"必须能在不动数据库的前提下看一遍（脚本的 `--dry-run`
    就是这个）。

    返回 `{promotable, reason, case}`。`promotable` 为 False 时 `case` 是
    None，`reason` 一定非空——一条被拒绝的反馈没有理由，等于被静默丢掉。
    """
    payload = failure_case.get("payload") or {}
    category = str(failure_case.get("category", "") or "")
    provenance = payload.get("provenance") or {}
    case_id = str(provenance.get("case_id", "") or "")

    if category not in CONFIRMED:
        return {
            "promotable": False,
            "reason": (
                "category %r is not in HUMAN_CONFIRMED_CATEGORIES; an inferred "
                "category must not reach the evaluation set" % category
            ),
            "case": None,
        }
    if category in REFUSED_CATEGORIES:
        return {
            "promotable": False, "reason": REFUSED_CATEGORIES[category],
            "case": None,
        }
    if category not in (CATEGORY_POSITIVE, CATEGORY_CLEAN):
        # 白名单里新增了一个类别但这里没处理。报错而不是跳过：静默跳过
        # 会让新类别的反馈永远进不了评测集，且没人知道。
        return {
            "promotable": False,
            "reason": "category %r has no promotion rule" % category,
            "case": None,
        }

    source = _case_index(cases).get(case_id)
    if source is None:
        return {
            "promotable": False,
            "reason": (
                "source case %r is not in the corpus, so there is no diff to "
                "promote; the diff must come from the corpus rather than from "
                "the feedback excerpt, which is only a fragment" % case_id
            ),
            "case": None,
        }

    repository = str(source.get("repository", "") or "")
    index = splits if splits is not None else split_index(cases)
    split = index.get(repository)
    if split is None:
        return {
            "promotable": False,
            "reason": (
                "repository %r has no existing side in the corpus; guessing a "
                "split would risk putting the same repository on both sides "
                "and holdout would stop being an unseen distribution"
                % repository
            ),
            "case": None,
        }
    if split == "holdout":
        return {
            "promotable": False,
            "reason": (
                "repository %r sits on the holdout side; feeding holdout "
                "feedback into the evolution loop is tuning on the hidden set"
                % repository
            ),
            "case": None,
        }

    truths = source.get("expected_findings") or []
    if category == CATEGORY_CLEAN:
        if truths:
            return {
                "promotable": False,
                "reason": (
                    "the source diff carries %d seed defect(s), so an empty "
                    "expected_findings would assert that nothing should be "
                    "reported here and would score a correct report of the "
                    "real defect as a clean-accuracy failure; only a source "
                    "case that is itself clean can become a negative sample"
                    % len(truths)
                ),
                "case": None,
            }
        expected: List[dict] = []
    else:
        try:
            expected = _expected_from_payload(payload)
        except (KeyError, TypeError, ValueError) as exc:
            return {
                "promotable": False,
                "reason": "the confirmed payload is not promotable: %s" % exc,
                "case": None,
            }

    candidate_id = str(provenance.get("candidate_id", "") or failure_case.get("id"))
    name = "%s-%s-%s" % (name_prefix, category, candidate_id)
    promoted = {
        "name": name[:120],
        "split": split,
        "diff": source.get("diff", ""),
        "expected": expected,
        "source": "d6-feedback-promoted",
        "repository": repository,
        "case_id": case_id,
        "category": category,
        "failure_case_id": failure_case.get("id"),
    }
    try:
        EvolutionEngine.validate_case(
            promoted["name"], promoted["diff"], expected, split)
    except ValueError as exc:
        # 最常见的形态：确认的 finding 指向的行不在 diff 的新增行里（标注
        # 的行号与反转后的 diff 差了几行）。拒绝而不是把行号挪到最近的新增
        # 行——挪过的样本看起来完全正常，而它断言的位置不是人确认的那个。
        return {
            "promotable": False,
            "reason": "the promoted case fails validate_case: %s" % exc,
            "case": None,
        }
    return {"promotable": True, "reason": "", "case": promoted}


def plan_promotions(
    failure_cases: Sequence[Dict[str, Any]], cases: Sequence[dict],
    name_prefix: str = "d6-confirmed",
) -> Dict[str, Any]:
    """整批反馈的提升计划。不写库。

    `refused` 逐条带理由并按类别计数：一批反馈里"7 条被拒因为源样本带种子
    缺陷"和"7 条被拒因为 bad_fix 没有指标槽位"要采取的行动完全不同，只报
    一个总数等于没报。
    """
    index = split_index(cases)
    promoted: List[dict] = []
    refused: List[dict] = []
    for failure_case in failure_cases:
        verdict = promote_case(failure_case, cases, index, name_prefix)
        if verdict["promotable"]:
            promoted.append(verdict["case"])
        else:
            refused.append({
                "failure_case_id": failure_case.get("id"),
                "category": failure_case.get("category"),
                "reason": verdict["reason"],
            })
    by_split: Dict[str, int] = {}
    by_category: Dict[str, int] = {}
    for case in promoted:
        by_split[case["split"]] = by_split.get(case["split"], 0) + 1
        by_category[case["category"]] = by_category.get(case["category"], 0) + 1
    return {
        "promoted": promoted,
        "refused": refused,
        "promoted_count": len(promoted),
        "refused_count": len(refused),
        "by_split": by_split,
        "by_category": by_category,
        # 提升出来的样本里有几条是 clean 侧。这个数直接决定
        # `clean_accuracy` 那道受保护指标在进化回路里有没有分母——为 0 时
        # 它是一道空门禁（与 holdout 的 high_severity_recall 同一形态）。
        "clean_samples": sum(1 for case in promoted if not case["expected"]),
    }


def apply_promotions(store, plan: Dict[str, Any]) -> Dict[str, Any]:
    """把提升计划写进 `evaluation_cases`。

    幂等靠 `save_evaluation_case` 的名字不可变语义：同名同内容返回既有行，
    同名不同内容抛 `ValueError`。后者**不吞**——它意味着同一个 candidate_id
    这次算出了不同的样本内容（比如语料被改过），静默覆盖会让评测集与它
    声称的来源不一致，而这在报告上看不出来。
    """
    written: List[str] = []
    existing: List[str] = []
    conflicts: List[dict] = []
    for case in plan.get("promoted", []):
        before = store.list_evaluation_cases(
            split=case["split"], active_only=False, limit=500)
        known = {item["name"] for item in before}
        try:
            store.save_evaluation_case(
                case["name"], case["split"], case["diff"], case["expected"],
                case["source"], True,
            )
        except ValueError as exc:
            conflicts.append({"name": case["name"], "error": str(exc)})
            continue
        (existing if case["name"] in known else written).append(case["name"])
    return {
        "written": written,
        "already_present": existing,
        "conflicts": conflicts,
        "written_count": len(written),
    }