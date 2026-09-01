"""End-to-end PR diff evaluation with reproducible matching and repair gates."""
import difflib
import hashlib
import json
import re
import time
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Tuple

from .diff_parser import parse_unified_diff
from .models import Finding, Severity
from .reviewer import Reviewer
from .verifier import RepairVerifier


SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}

# The evaluator compares CWE identities, not reviewer-specific rule names.
RULE_TO_CWE = {
    "SEC-EVAL": "CWE-95",
    "SEC-SUBPROCESS-SHELL": "CWE-78",
    "SEC-HARDCODED-SECRET": "CWE-798",
    "SEC-SQL-CONCAT": "CWE-89",
    "REL-EMPTY-EXCEPT": "CWE-703",
    "REL-DEBUG-PRINT": "CWE-532",
    "SEC-PATH-TRAVERSAL": "CWE-22",
    "SEC-YAML-LOAD": "CWE-502",
    "SEC-WEAK-HASH": "CWE-328",
    "SEC-INSECURE-TEMPFILE": "CWE-377",
    "SEC-WEAK-RANDOM": "CWE-330",
    "REL-UNBOUNDED-RETRY": "CWE-835",
    "SEC-ASSERT-AUTH": "CWE-617",
    "SEC-INSECURE-COOKIE": "CWE-614",
    "SEC-PICKLE-LOAD": "CWE-502",
    "REL-FLOAT-MONEY": "CWE-682",
    "REL-NAIVE-DATETIME": "CWE-367",
    "REL-BLOCKING-ASYNC": "CWE-400",
    "REL-NONATOMIC-WRITE": "CWE-362",
    "SEC-OPEN-REDIRECT": "CWE-601",
    "SEC-LOG-FORGING": "CWE-117",
}


# ── 命中口径：三档，不是一档 ─────────────────────────────────────────────
#
# 原实现只有一档：路径 + 行窗口 + **CWE 号完全相等**。这一档太严，会把
# 正确的发现判成漏报：RULE_TO_CWE["SEC-EVAL"] == "CWE-95"，而数据集给
# injection 类标的是 CWE-78。reviewer 正确指出了 `eval(` 这一行，却因为
# CWE 号不同而不算命中。但 CWE 是有层级的——74（注入）之下有 77/78/89/94/95，
# 它们是兄弟。要求兄弟节点号码相等，测的是"标注者和 reviewer 是否选了同一个
# 兄弟节点"，不是"reviewer 是否发现了这个缺陷"。
#
# 三档各自回答一个不同的问题，所以要分别报数而不是取一个：
#
#   location  路径 + 行窗口 ≤ tolerance
#             → "有没有指到出问题的那几行" = 定位能力
#   category  location + CWE 同族（八类之一）
#             → "有没有认出这是哪类问题" = 归因能力
#   cwe-exact location + CWE 号完全相等
#             → "CWE 编号是否一致"，**只在 CVE/GHSA 子集上有意义**：
#                那里的 CWE 来自安全公告，是权威的；其余样本的 CWE 由
#                分类器推断，拿它做严格比较是在测分类器而非 reviewer。
#
# 单调性：strict 的边集是 location 边集的子集，因此
# cwe-exact ≤ category ≤ location 恒成立。有单测锁住这条不变量——
# 它被破坏说明某一档的边构造写错了。

MATCH_LOCATION = "location"
MATCH_CATEGORY = "category"
MATCH_CWE_EXACT = "cwe-exact"
MATCH_TIERS = (MATCH_LOCATION, MATCH_CATEGORY, MATCH_CWE_EXACT)

# CWE → 八个缺陷族。族的划分与 dataset_builder.DEFECT_CLASSES 对齐
# （同一套八类），但**刻意不 import 它**：评测口径不该依赖数据集构造模块，
# 否则给采集器加一类缺陷会回溯改变历史评测结果，使数字不可比。
CWE_FAMILY = {
    # crypto-weak
    "CWE-326": "crypto-weak", "CWE-327": "crypto-weak", "CWE-328": "crypto-weak",
    "CWE-330": "crypto-weak", "CWE-295": "crypto-weak", "CWE-916": "crypto-weak",
    "CWE-757": "crypto-weak",
    # injection（CWE-74 族 + 反序列化 + 日志注入）
    "CWE-74": "injection", "CWE-77": "injection", "CWE-78": "injection",
    "CWE-88": "injection", "CWE-89": "injection", "CWE-90": "injection",
    "CWE-91": "injection", "CWE-94": "injection", "CWE-95": "injection",
    "CWE-917": "injection", "CWE-502": "injection", "CWE-117": "injection",
    # secret-exposure
    "CWE-200": "secret-exposure", "CWE-312": "secret-exposure",
    "CWE-522": "secret-exposure", "CWE-532": "secret-exposure",
    "CWE-798": "secret-exposure", "CWE-614": "secret-exposure",
    # path-traversal
    "CWE-22": "path-traversal", "CWE-23": "path-traversal",
    "CWE-36": "path-traversal", "CWE-73": "path-traversal",
    # auth-bypass
    "CWE-285": "auth-bypass", "CWE-287": "auth-bypass", "CWE-306": "auth-bypass",
    "CWE-862": "auth-bypass", "CWE-863": "auth-bypass", "CWE-617": "auth-bypass",
    # resource-leak
    "CWE-400": "resource-leak", "CWE-401": "resource-leak",
    "CWE-404": "resource-leak", "CWE-664": "resource-leak",
    "CWE-772": "resource-leak", "CWE-835": "resource-leak",
    "CWE-377": "resource-leak",
    # logic-boundary
    "CWE-20": "logic-boundary", "CWE-125": "logic-boundary",
    "CWE-193": "logic-boundary", "CWE-682": "logic-boundary",
    "CWE-703": "logic-boundary", "CWE-787": "logic-boundary",
    # concurrency
    "CWE-362": "concurrency", "CWE-366": "concurrency",
    "CWE-367": "concurrency", "CWE-543": "concurrency",
    # 刻意未映射：CWE-601（开放重定向）等落在八类之外的编号。
    # 未映射 → 永不 category 命中，这是正确行为：reviewer 报了一个不在
    # 本数据集标注体系里的类别，不该算作"认出了这类问题"。
}


def cwe_family(cwe: str) -> str:
    """Map a CWE id to one of the eight defect families, or '' when unknown."""
    return CWE_FAMILY.get(str(cwe).strip().upper(), "")


@dataclass
class Match:
    expected_index: int
    predicted_index: int
    location_distance: int


def _canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def dataset_fingerprint(cases: Iterable[dict]) -> str:
    """Fingerprint exactly what is scored, independent of JSONL formatting."""
    digest = hashlib.sha256()
    for case in sorted(cases, key=lambda item: str(item["id"])):
        digest.update(_canonical_json(case).encode("utf-8"))
        digest.update(b"\n")
    return digest.hexdigest()


def load_jsonl(path: str) -> List[dict]:
    cases = []
    with open(path, "r", encoding="utf-8") as handle:
        for line_number, raw in enumerate(handle, 1):
            if not raw.strip():
                continue
            try:
                case = json.loads(raw)
            except json.JSONDecodeError as exc:
                raise ValueError("invalid JSON on line %d: %s" % (line_number, exc)) from exc
            validate_case(case, line_number)
            cases.append(case)
    ids = [str(case["id"]) for case in cases]
    if len(ids) != len(set(ids)):
        raise ValueError("dataset contains duplicate case ids")
    return cases


def validate_case(case: dict, line_number: int = 0) -> None:
    prefix = "dataset line %d" % line_number if line_number else "evaluation case"
    for field in ("id", "repository", "pull_request", "split", "diff", "expected_findings"):
        if field not in case:
            raise ValueError("%s is missing %s" % (prefix, field))
    if case["split"] not in {"train", "validation", "holdout"}:
        raise ValueError("%s has invalid split" % prefix)
    parsed = parse_unified_diff(str(case["diff"]))
    if not parsed.files or not parsed.added_lines:
        raise ValueError("%s does not contain a scoreable unified diff" % prefix)
    if not isinstance(case["expected_findings"], list):
        raise ValueError("%s expected_findings must be an array" % prefix)
    added_locations = {
        (_normalized_path(item.path), int(item.line)) for item in parsed.added_lines
    }
    for expected in case["expected_findings"]:
        for field in ("path", "start_line", "end_line", "cwe", "severity"):
            if field not in expected:
                raise ValueError("%s finding is missing %s" % (prefix, field))
        if str(expected["severity"]).lower() not in SEVERITY_RANK:
            raise ValueError("%s finding has invalid severity" % prefix)
        if int(expected["start_line"]) > int(expected["end_line"]):
            raise ValueError("%s finding has an inverted line range" % prefix)
        expected_path = _normalized_path(str(expected["path"]))
        if not any(
            path == expected_path
            and int(expected["start_line"]) <= line <= int(expected["end_line"])
            for path, line in added_locations
        ):
            raise ValueError("%s finding does not cover an added line" % prefix)


def _normalized_path(path: str) -> str:
    value = path.replace("\\", "/").strip()
    return value[2:] if value.startswith(("a/", "b/")) else value


def _candidate_edges(
    expected: List[dict], predicted: List[Finding], line_tolerance: int,
    tier: str = MATCH_CWE_EXACT,
) -> Dict[int, List[Tuple[int, int]]]:
    """Build the bipartite edge set for one hit tier.

    tier 默认 MATCH_CWE_EXACT，与改动前的行为完全一致——现有调用方
    （evaluation_v2、evolution_proof、EndToEndEvaluationHarness）不传 tier 时
    行为不变，历史数字仍可复算。新口径通过显式传 tier 使用。
    """
    if tier not in MATCH_TIERS:
        raise ValueError("unknown match tier: %s" % tier)
    edges: Dict[int, List[Tuple[int, int]]] = {}
    for expected_index, truth in enumerate(expected):
        start = int(truth["start_line"])
        end = int(truth["end_line"])
        truth_path = _normalized_path(str(truth["path"]))
        truth_cwe = str(truth["cwe"]).upper()
        truth_family = cwe_family(truth_cwe)
        options = []
        for predicted_index, finding in enumerate(predicted):
            if _normalized_path(finding.path) != truth_path:
                continue
            finding_cwe = RULE_TO_CWE.get(finding.rule_id, finding.rule_id).upper()
            if tier == MATCH_CWE_EXACT and finding_cwe != truth_cwe:
                continue
            if tier == MATCH_CATEGORY:
                finding_family = cwe_family(finding_cwe)
                # 双方都要能映射到族且同族。truth 映射不出族时（数据集用了
                # 八类之外的 CWE）退回严格相等，而不是放任全部命中——
                # 无族信息时"同族"这个概念没有定义，宁可保守。
                if not truth_family:
                    if finding_cwe != truth_cwe:
                        continue
                elif finding_family != truth_family:
                    continue
            if start <= finding.line <= end:
                distance = 0
            else:
                distance = min(abs(finding.line - start), abs(finding.line - end))
            if distance <= line_tolerance:
                options.append((predicted_index, distance))
        edges[expected_index] = sorted(options, key=lambda item: (item[1], item[0]))
    return edges


def one_to_one_match(
    expected: List[dict], predicted: List[Finding], line_tolerance: int = 2,
    tier: str = MATCH_CWE_EXACT,
) -> List[Match]:
    """Maximum-cardinality bipartite matching with deterministic edge ordering.

    匹配算法本身**未改动**（计划要求"保留 one_to_one_match 不动"）：
    仍是最大基数二分匹配 + 受约束真值优先。改的只是喂给它的边集来自哪一档。
    这个分层是刻意的——命中口径是可以争论的，匹配算法不该跟着一起动。
    """
    edges = _candidate_edges(expected, predicted, line_tolerance, tier)
    prediction_owner: Dict[int, int] = {}

    def assign(expected_index: int, visited: set) -> bool:
        for predicted_index, _distance in edges.get(expected_index, []):
            if predicted_index in visited:
                continue
            visited.add(predicted_index)
            previous = prediction_owner.get(predicted_index)
            if previous is None or assign(previous, visited):
                prediction_owner[predicted_index] = expected_index
                return True
        return False

    # Constrained truths go first so flexible ranges do not consume their only edge.
    order = sorted(range(len(expected)), key=lambda index: (len(edges[index]), index))
    for expected_index in order:
        assign(expected_index, set())

    matches = []
    for predicted_index, expected_index in prediction_owner.items():
        distance = next(
            distance for index, distance in edges[expected_index]
            if index == predicted_index
        )
        matches.append(Match(expected_index, predicted_index, distance))
    return sorted(matches, key=lambda item: (item.expected_index, item.predicted_index))


def tiered_match(
    expected: List[dict], predicted: List[Finding], line_tolerance: int = 2,
) -> Dict[str, dict]:
    """Score one case at all three hit tiers plus the out-of-label count.

    ## 口径纪律：标注外 finding 不是"误报"

    `unlabelled` 统计的是"落在标注之外的 finding"。它**不等于误报**——
    数据集只标注了反转出来的那个种子缺陷，仓库里可能真有别的问题，
    reviewer 指出它们是对的。把这个数写成"误报"是口径造假。

    要得到真实的误报率必须靠人工复核（D5 的 rubric + 抽样），
    自动层只能报"噪声量"（每 PR 的标注外条数）。所以这里的字段名是
    `unlabelled` 而不是 `false_positives`——名字本身就是口径纪律。

    ## 为什么分档报而不取一个数

    三档回答三个不同的问题（定位 / 归因 / CWE 号一致）。取一个数会让
    "定位对了但归类错了"和"完全没找到"变成同一个数字，而这两件事对系统
    改进的指示完全不同：前者要改 prompt 的分类部分，后者要改扫描覆盖。
    """
    total_predicted = len(predicted)
    result: Dict[str, dict] = {}
    matched_by_tier: Dict[str, set] = {}
    for tier in MATCH_TIERS:
        matches = one_to_one_match(expected, predicted, line_tolerance, tier)
        matched_by_tier[tier] = {item.predicted_index for item in matches}
        result[tier] = {
            "tp": len(matches),
            "fn": len(expected) - len(matches),
            "matched_expected": sorted(item.expected_index for item in matches),
        }
    # 标注外条数按最宽的一档（location）算：一个 finding 只要指对了行，
    # 就不该被算成"标注外"，即使它把类别判错了。按严格档算会虚增噪声量。
    result["unlabelled"] = {
        "count": total_predicted - len(matched_by_tier[MATCH_LOCATION]),
        "total_predicted": total_predicted,
        "note": (
            "Findings outside the labelled seed defect. NOT false positives: "
            "the dataset only labels the reverted seed, and a reviewer may be "
            "correctly reporting a genuine unrelated issue."
        ),
    }
    return result


### 补丁改动范围断言 ###
#
# 没有这道断言时，一个改遍全文件的补丁能拿到 verified-draft：实测
# REL-DEBUG-PRINT 的修复是 `re.sub` 全文替换，finding 指向第 2 行，
# 补丁把 5 行文件里的 4 行 print 全删了——compile 过、风险移除过、
# 回归断言过，于是判为"可复核的草稿"。可它删掉了三行与缺陷无关的代码。
#
# 这与 MAX_SEED_SPAN 是同一条纪律的另一端：那条管标注范围别太宽，
# 这条管补丁范围别太宽。两者宽了都会让"命中"这件事失去意义。
SCOPE_WINDOW = 5        # 允许改动的行数半径（finding 行 ± 5）
                        # 取 5 而不是 0：真实修复常需要连带改几行——包一层
                        # try、把单行拆成两行、补一个 early return。
                        # 也不取 20（MAX_FIX_LINES 的值）：那是"整个 PR 的
                        # 改动上限"，这里是"单个 finding 的邻域"，后者必须更紧，
                        # 否则一个 PR 里两处相距 15 行的缺陷会互相掩护。


def _changed_line_numbers(before: str, after: str) -> List[int]:
    """补丁改动了原文的哪些行（按**原文**行号，1-based）。

    用 SequenceMatcher 做对齐，不是逐下标比较。插入一行会让它后面所有行
    的下标都错位，逐下标比较会把整个文件的余下部分都算成"改动过"，
    于是断言对任何插入类补丁都误报。
    """
    before_lines = before.splitlines()
    after_lines = after.splitlines()
    changed: List[int] = []
    matcher = difflib.SequenceMatcher(
        a=before_lines, b=after_lines, autojunk=False)
    for tag, i1, i2, _j1, _j2 in matcher.get_opcodes():
        if tag == "equal":
            continue
        if i1 == i2:
            # 纯插入：原文没有对应行。记插入点所在行，让它参与范围判定。
            changed.append(i1 + 1)
            continue
        changed.extend(range(i1 + 1, i2 + 1))
    return sorted(set(changed))


def _is_import_insertion(tag: str, inserted: List[str]) -> bool:
    """这一段改动是否是"纯插入 import"。

    为什么要放行：_ensure_import 把 import 插在文件第一行，而 finding
    可能在第 300 行。不放行的话每个需要补 import 的修复（secret → os、
    eval → json）都会被判越界，断言就只剩噪声。

    为什么按**段**判而不是整体判：整体判需要"整个补丁只插了 import"，
    可 secret/eval 的修复形态恰恰是"头部插 import + 改 finding 那一行"
    两段并存——整体判会把这种最常见的正常补丁判成越界（实测确认过）。
    """
    return tag == "insert" and bool(inserted) and all(
        line.strip().startswith(("import ", "from ")) for line in inserted)


def patch_scope_check(
    before: str, after: str, finding_line: int, window: int = SCOPE_WINDOW,
) -> Dict[str, Any]:
    """补丁改动是否落在 finding 邻域内。返回一条 checks 项。

    越界不单独设一档：一个改了 200 行无关代码的补丁，人类同样不能直接用，
    它属于 blocked。档位记录的是"能不能用"，越界的原因记在 detail 里。
    """
    before_lines = before.splitlines()
    after_lines = after.splitlines()
    matcher = difflib.SequenceMatcher(
        a=before_lines, b=after_lines, autojunk=False)
    low, high = finding_line - window, finding_line + window
    changed: List[int] = []
    out_of_scope: List[int] = []
    allowed_imports = 0
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag == "equal":
            continue
        lines = ([i1 + 1] if i1 == i2 else list(range(i1 + 1, i2 + 1)))
        changed.extend(lines)
        if _is_import_insertion(tag, after_lines[j1:j2]):
            allowed_imports += 1
            continue
        out_of_scope.extend(line for line in lines if not low <= line <= high)
    changed = sorted(set(changed))
    if not changed:
        # 没有改动。这不是越界，是"没生成补丁"——由 patch-generated 那项负责。
        return {"name": "patch-scope", "passed": True, "changed_lines": []}
    out_of_scope = sorted(set(out_of_scope))
    return {
        "name": "patch-scope",
        "passed": not out_of_scope,
        "changed_lines": changed,
        "out_of_scope": out_of_scope,
        "import_insertions": allowed_imports,
        "detail": "" if not out_of_scope else (
            "%d line(s) outside %d±%d" % (len(out_of_scope), finding_line, window)
        ),
    }


class FixtureRepairer:
    """Conservative deterministic repairer used by the controlled benchmark.

    Production repositories should replace this with a worktree-based repair runner.
    The same evaluator and gates can consume either implementation.
    """

    def repair(self, case: dict, finding: Finding) -> Dict[str, Any]:
        validation = dict(case.get("repair_validation") or {})
        path = finding.path
        content = str((case.get("after_files") or {}).get(path, ""))
        checks = []
        risk_pattern = str(validation.get("risk_pattern", ""))
        reproducible = bool(risk_pattern and re.search(risk_pattern, content, re.MULTILINE))
        checks.append({"name": "risk-reproduction", "passed": reproducible})
        if not validation.get("auto_fixable", False):
            checks.append({"name": "patch-generated", "passed": False})
            return {"passed": False, "checks": checks, "content": content}

        repaired = self._transform(content, finding)
        patch_applied = repaired != content
        checks.append({"name": "patch-generated", "passed": patch_applied})
        compile_result = RepairVerifier().verify_contents({path: repaired})
        compile_passed = bool(compile_result["passed"])
        checks.append({"name": "compile", "passed": compile_passed})
        risk_removed = bool(risk_pattern) and not re.search(
            risk_pattern, repaired, re.MULTILINE
        )
        checks.append({"name": "risk-removed", "passed": risk_removed})
        required = list(validation.get("required_after_patterns") or [])
        regression_passed = all(
            re.search(pattern, repaired, re.MULTILINE) for pattern in required
        )
        checks.append({"name": "regression-tests", "passed": regression_passed})
        # 范围断言放在最后：它是"这个补丁能不能给人看"的判定，
        # 前面几项先确认补丁本身有效，顺序符合读报告的思路。
        checks.append(patch_scope_check(content, repaired, finding.line))
        return {
            "passed": all(item["passed"] for item in checks),
            "checks": checks,
            "content": repaired,
        }

    @staticmethod
    def _transform(content: str, finding: Finding) -> str:
        rule = finding.rule_id
        if rule == "SEC-EVAL":
            value = re.sub(r"\beval\s*\(", "json.loads(", content)
            return FixtureRepairer._ensure_import(value, "json")
        if rule == "SEC-SUBPROCESS-SHELL":
            return re.sub(r"shell\s*=\s*True", "shell=False", content)
        if rule == "SEC-HARDCODED-SECRET":
            value = re.sub(
                r"(?m)^(\s*)(password|passwd|api_key|secret|token)\s*=\s*['\"][^'\"]+['\"]",
                lambda match: '%s%s = os.environ["%s"]' % (
                    match.group(1), match.group(2), match.group(2).upper()
                ),
                content,
            )
            return FixtureRepairer._ensure_import(value, "os")
        if rule == "SEC-SQL-CONCAT":
            return re.sub(
                r'(?m)^(\s*)cursor\.execute\(.+$',
                r'\1cursor.execute("SELECT * FROM users WHERE id = ?", (value,))',
                content,
            )
        if rule == "REL-EMPTY-EXCEPT":
            return content.replace("except Exception:", "except ValueError:")
        if rule == "REL-DEBUG-PRINT":
            return re.sub(r"(?m)^\s*(print|console\.log)\s*\(.+\)\s*$\n?", "", content)
        if rule == "SEC-PATH-TRAVERSAL":
            return re.sub(
                r"open\(base\s*/\s*user_path\)\.read\(\)",
                "read_under_base(base, user_path)",
                content,
            )
        return content

    @staticmethod
    def _ensure_import(content: str, module: str) -> str:
        if re.search(r"(?m)^\s*(import %s|from %s import)" % (module, module), content):
            return content
        return "import %s\n" % module + content


### 修复环节的分档口径 ###
#
# 为什么不报单一成功率：safe_fix_rate = repair_passed / repair_attempted
# 把三种完全不同的失败塞进同一个"没通过"里，而它们对使用者的含义相反：
#   没生成补丁          → agent 认了怂，人类什么都没得到，但也没被误导
#   生成了但没过验证    → agent 给了个错的补丁，验证挡住了 → 系统是安全的
#   生成了且过了验证    → 人类拿到一份可复核的草稿
# 前两者合并成一个数字，就看不出"挡住了多少"这件事——而那恰恰是这套
# 验证环节唯一的价值所在。一个 0.3 的 safe_fix_rate 可能是"七成没敢动"，
# 也可能是"七成给错了但都被拦下"，两种系统完全不该给同样的评价。
REPAIR_VERIFIED = "verified-draft"      # 全部检查通过：可复核的草稿
REPAIR_BLOCKED = "blocked"              # 生成了补丁但验证不通过：被拦下
REPAIR_SUGGESTION = "suggestion-only"   # 没生成补丁：只给了意见
# 第四种状态，**不是第四档质量**，而是"这一档没法判"：
# 原始代码里连风险都没复现出来，那么"风险是否被移除"这项检查无意义。
# 它是配置/夹具问题，不是修复能力问题。混进 blocked 会把配置错误
# 记成 agent 的失败——和 None ≠ 0.0 同一条纪律。
REPAIR_UNREPRODUCED = "unreproduced"

REPAIR_TIERS = (REPAIR_VERIFIED, REPAIR_BLOCKED, REPAIR_SUGGESTION,
                REPAIR_UNREPRODUCED)


def repair_tier(repair: Dict[str, Any]) -> str:
    """把一次修复结果归入某一档。

    判定顺序是有意的：先问"风险复现了吗"（前提），再问"有补丁吗"（意愿），
    最后才问"补丁对吗"（能力）。顺序反了会把前提失败误记成能力失败。
    """
    checks = {str(item.get("name")): bool(item.get("passed"))
              for item in repair.get("checks") or []}
    if "risk-reproduction" in checks and not checks["risk-reproduction"]:
        return REPAIR_UNREPRODUCED
    if not checks.get("patch-generated", False):
        return REPAIR_SUGGESTION
    return REPAIR_VERIFIED if repair.get("passed") else REPAIR_BLOCKED


class EndToEndEvaluationHarness:
    def __init__(
        self, line_tolerance: int = 2, repairer: Optional[FixtureRepairer] = None,
    ):
        self.line_tolerance = line_tolerance
        self.repairer = repairer

    def run(self, reviewer: Reviewer, cases: List[dict], name: str = "") -> Dict[str, Any]:
        started = time.monotonic()
        totals = self._empty_totals()
        case_results = []
        for case in cases:
            result = self._run_case(reviewer, case)
            case_results.append(result)
            self._accumulate(totals, result)
        metrics = self._metrics(totals)
        by_split = {}
        for split in ("validation", "holdout"):
            selected = [item for item in case_results if item["split"] == split]
            split_totals = self._empty_totals()
            for item in selected:
                self._accumulate(split_totals, item)
            by_split[split] = self._metrics(split_totals)
        source_kinds = sorted({
            str((case.get("source") or {}).get("kind", "unknown")) for case in cases
        })
        return {
            "schema_version": 1,
            "name": name or reviewer.name,
            "reviewer": reviewer.name,
            "dataset": {
                "cases": len(cases),
                "repositories": len({case["repository"] for case in cases}),
                "risk_cases": sum(bool(case["expected_findings"]) for case in cases),
                "clean_cases": sum(not case["expected_findings"] for case in cases),
                "source_kinds": source_kinds,
                "sha256": dataset_fingerprint(cases),
            },
            "metrics": metrics,
            "by_split": by_split,
            "duration_seconds": round(time.monotonic() - started, 4),
            "case_results": case_results,
        }

    def _run_case(self, reviewer: Reviewer, case: dict) -> Dict[str, Any]:
        expected = [
            item for item in case["expected_findings"]
            if bool(item.get("should_comment", True))
        ]
        result = {
            "id": case["id"],
            "repository": case["repository"],
            "pull_request": case["pull_request"],
            "split": case["split"],
            "expected": len(expected),
            "predicted": 0,
            "tp": 0,
            "fp": 0,
            "fn": len(expected),
            "severity_hits": 0,
            "high_total": sum(
                str(item["severity"]).lower() in {"high", "critical"} for item in expected
            ),
            "high_hits": 0,
            "clean_hit": False,
            "execution_success": False,
            "repair_attempted": 0,
            "repair_passed": 0,
            # 修复环节是否配置了。这个标记必须随结果一起走，不能在 _metrics
            # 里读 self：_metrics 是静态方法，且要为每个 split 分别算一次。
            # 它区分的是两件不同的事：
            #   repairer is None      → 修复环节**没跑** → e2e 无定义 (None)
            #   repairer 在但没匹配上 → 修复环节跑了没成 → e2e = 0.0
            # 只看 repair_attempted == 0 无法区分这两者。
            "repair_stage_active": self.repairer is not None,
            "repair_tiers": {tier: 0 for tier in REPAIR_TIERS},
            "e2e_success": False,
            "matches": [],
            "repair": [],
            "error": None,
        }
        try:
            parsed = parse_unified_diff(case["diff"])
            review_case = getattr(reviewer, "review_case", None)
            findings = (
                review_case(case, parsed)
                if review_case else reviewer.review(case["diff"], parsed)
            )
            matches = one_to_one_match(expected, findings, self.line_tolerance)
            result["predicted"] = len(findings)
            result["tp"] = len(matches)
            result["fp"] = len(findings) - len(matches)
            result["fn"] = len(expected) - len(matches)
            result["clean_hit"] = not expected and not findings
            result["execution_success"] = True
            matched_expected = set()
            for match in matches:
                truth = expected[match.expected_index]
                finding = findings[match.predicted_index]
                severity_hit = finding.severity.value == str(truth["severity"]).lower()
                high = str(truth["severity"]).lower() in {"high", "critical"}
                result["severity_hits"] += int(severity_hit)
                result["high_hits"] += int(high)
                matched_expected.add(match.expected_index)
                result["matches"].append({
                    "expected_index": match.expected_index,
                    "predicted_index": match.predicted_index,
                    "path": finding.path,
                    "line": finding.line,
                    "cwe": RULE_TO_CWE.get(finding.rule_id, finding.rule_id),
                    "rule_id": finding.rule_id,
                    "expected_severity": truth["severity"],
                    "predicted_severity": finding.severity.value,
                    "severity_hit": severity_hit,
                    "location_distance": match.location_distance,
                })
                if self.repairer is not None:
                    result["repair_attempted"] += 1
                    repair = self.repairer.repair(case, finding)
                    result["repair_passed"] += int(repair["passed"])
                    tier = repair_tier(repair)
                    result["repair_tiers"][tier] += 1
                    result["repair"].append({
                        "expected_index": match.expected_index,
                        "passed": repair["passed"],
                        "tier": tier,
                        "checks": repair["checks"],
                    })
            result["e2e_success"] = bool(
                expected
                and len(matched_expected) == len(expected)
                and result["repair_attempted"] == len(expected)
                and result["repair_passed"] == len(expected)
            )
        except Exception as exc:
            result["error"] = str(exc)[:1000]
        return result

    @staticmethod
    def _empty_totals() -> Dict[str, int]:
        return {
            "cases": 0, "risk_cases": 0, "clean_cases": 0, "tp": 0, "fp": 0,
            "fn": 0, "severity_hits": 0, "high_total": 0, "high_hits": 0,
            "clean_hits": 0, "execution_successes": 0, "repair_attempted": 0,
            "repair_passed": 0, "e2e_successes": 0,
            # False 是正确的初值：一个 case 都没跑过时，修复环节当然没跑过。
            "repair_stage_active": False,
            **{"repair_%s" % tier.replace("-", "_"): 0 for tier in REPAIR_TIERS},
        }

    @staticmethod
    def _accumulate(totals: Dict[str, int], result: dict) -> None:
        totals["cases"] += 1
        totals["risk_cases"] += int(result["expected"] > 0)
        totals["clean_cases"] += int(result["expected"] == 0)
        for field in (
            "tp", "fp", "fn", "severity_hits", "high_total", "high_hits",
            "repair_attempted", "repair_passed",
        ):
            totals[field] += int(result[field])
        for tier, count in (result.get("repair_tiers") or {}).items():
            key = "repair_%s" % tier.replace("-", "_")
            totals[key] = totals.get(key, 0) + int(count)
        totals["clean_hits"] += int(result["clean_hit"])
        totals["execution_successes"] += int(result["execution_success"])
        totals["e2e_successes"] += int(result["e2e_success"])
        # 只要有**任何**一个 case 跑过修复环节，这一批的 e2e 就是有定义的。
        # 用 or 而不是 and：混合情形（部分 case 配了 repairer）下，
        # e2e 至少对那部分有意义，报 None 会把已有的信息也丢掉。
        totals["repair_stage_active"] = bool(
            totals.get("repair_stage_active") or result.get("repair_stage_active")
        )

    @staticmethod
    def _metrics(totals: Dict[str, int]) -> Dict[str, Any]:
        """Compute metrics, reporting None (rendered as n/a) for empty denominators.

        ## 修掉的口径 bug

        原实现 `def ratio(numerator, denominator, empty=1.0)`——分母为零时默认
        返回 **1.0**（满分）。后果：一个**什么都不报的 reviewer** 在没有正样本
        的批次上同时拿到 recall=1.0、severity_accuracy=1.0、high_risk_recall=1.0、
        clean_accuracy=1.0，f1 也被 recall 抬起来。空集合不是"全对",
        是"这个比率没有定义"。

        改为返回 `None`。`None` 与 0.0 的区别是实质的：
        - 0.0 = "测过了，一个都没中" —— 是一个结论。
        - None = "没有样本，无法下结论" —— 报告里必须显示 n/a。

        把后者写成 0.0 会低估，写成 1.0 会高估，两者都是编造。

        ## 为什么不是全部改成 0.0（更省事的做法）

        0.0 会让门禁误判：`clean_accuracy_non_regression` 比较
        candidate >= baseline，若两边都因无 clean 样本而变成 0.0，门禁会
        "通过"——但它其实什么都没验证。None 会让门禁显式变成 not_applicable，
        这个区别在答辩时是可讲的：**门禁没有静默放行**。
        """
        def ratio(
            numerator: int, denominator: int, empty: Optional[float] = None,
        ) -> Optional[float]:
            return round(numerator / denominator, 4) if denominator else empty

        # precision / recall 的空集合语义仍是 None，但 f1 需要数值参与计算。
        precision = ratio(totals["tp"], totals["tp"] + totals["fp"])
        recall = ratio(totals["tp"], totals["tp"] + totals["fn"])
        # f1 只在两者都有定义时有定义。缺一个就是 None，不用 0 填充——
        # 用 0 填充会让"没有正样本"看起来像"全漏了"。
        if precision is None or recall is None:
            f1: Optional[float] = None
        elif precision + recall:
            f1 = round(2 * precision * recall / (precision + recall), 4)
        else:
            f1 = 0.0
        return {
            **totals,
            "precision": precision,
            "recall": recall,
            "f1": f1,
            "severity_accuracy": ratio(totals["severity_hits"], totals["tp"]),
            "high_risk_recall": ratio(totals["high_hits"], totals["high_total"]),
            "clean_accuracy": ratio(totals["clean_hits"], totals["clean_cases"]),
            # execution_success_rate 的分母是 cases。cases == 0 意味着这一批
            # 根本没跑，仍然是 None 而不是 0.0——"没跑"和"跑了全失败"不同。
            "execution_success_rate": ratio(
                totals["execution_successes"], totals["cases"]
            ),
            # 保留 safe_fix_rate：历史数字要能复算，门禁也在用它。
            # 但它是**有损**的——三档合并成一个数，见 REPAIR_VERIFIED 处的
            # 说明。答辩时应该报下面的三档，safe_fix_rate 只作为对照。
            "safe_fix_rate": ratio(totals["repair_passed"], totals["repair_attempted"]),
            # 三档各自的占比。分母统一用 judgeable（= attempted - unreproduced）：
            # 风险没复现的样本压根没进入"修复能力"的判定范围，留在分母里会
            # 把配置问题稀释进能力指标。分母为 0 仍返回 None，不返回 0.0。
            "repair_judgeable": max(
                0, totals["repair_attempted"] - totals["repair_unreproduced"]),
            "verified_draft_rate": ratio(
                totals["repair_verified_draft"],
                totals["repair_attempted"] - totals["repair_unreproduced"]),
            "blocked_rate": ratio(
                totals["repair_blocked"],
                totals["repair_attempted"] - totals["repair_unreproduced"]),
            "suggestion_only_rate": ratio(
                totals["repair_suggestion_only"],
                totals["repair_attempted"] - totals["repair_unreproduced"]),
            # e2e 的分母是 risk_cases（非空），但分子恒为 0 —— 因为
            # e2e_success 要求 repair_attempted == len(expected)，而修复环节
            # 未配置时 repair_attempted 恒为 0。于是它会报出 0.0，读起来是
            # "试了 100% 都失败"，真相是"从来没试"。
            #
            # 这与本函数开头讲的空分母是**同一类口径错误的镜像**：那次是
            # 分母为 0 时编造 1.0，这次是分子恒 0 时编造出一个结论。
            # safe_fix_rate 因为分母恰好也是 0，已经自动得到 None——
            # 它是碰巧对的，不是设计对的。
            "e2e_security_fix_rate": (
                ratio(totals["e2e_successes"], totals["risk_cases"])
                if totals.get("repair_stage_active") else None
            ),
        }


def _delta(candidate: Optional[float], baseline: Optional[float]) -> Optional[float]:
    """Difference of two metrics, or None when either side is undefined."""
    if candidate is None or baseline is None:
        return None
    return round(candidate - baseline, 4)


def _at_least(
    candidate: Optional[float], threshold: Optional[float], margin: float = 0.0,
) -> Optional[bool]:
    """Three-state gate comparison: True / False / None (not applicable).

    任一侧为 None（分母为零，比率无定义）时返回 None，**而不是 False 或 True**。

    为什么必须是三态：若无声当成 False，一个从来没有 clean 样本的数据集会让
    clean_accuracy 门禁永远失败，逼人去关掉这个门禁；若当成 True，门禁就是
    静默放行——报告上写着"门禁通过"，实际什么都没验证。返回 None 让报告
    显式写出 not_applicable，读的人能看见"这条没验证"。
    """
    if candidate is None or threshold is None:
        return None
    return candidate >= threshold + margin


def comparison_summary(
    baseline: dict, candidate: dict, minimum_f1_improvement: float = 0.02,
    minimum_execution_success: float = 0.98, minimum_safe_fix_rate: float = 0.75,
    minimum_e2e_fix_rate: float = 0.60,
) -> Dict[str, Any]:
    metrics = (
        "precision", "recall", "f1", "severity_accuracy", "high_risk_recall",
        "clean_accuracy", "execution_success_rate", "safe_fix_rate",
        "e2e_security_fix_rate",
    )
    quantitative_gates = {
        "validation_f1_improvement": {
            "passed": _at_least(
                candidate["by_split"]["validation"]["f1"],
                baseline["by_split"]["validation"]["f1"],
                minimum_f1_improvement,
            ),
            "minimum_delta": minimum_f1_improvement,
        },
        "high_risk_recall_non_regression": {
            "passed": _at_least(
                candidate["metrics"]["high_risk_recall"],
                baseline["metrics"]["high_risk_recall"],
            ),
        },
        "clean_accuracy_non_regression": {
            "passed": _at_least(
                candidate["metrics"]["clean_accuracy"],
                baseline["metrics"]["clean_accuracy"],
            ),
        },
        "holdout_f1_non_regression": {
            "passed": _at_least(
                candidate["by_split"]["holdout"]["f1"],
                baseline["by_split"]["holdout"]["f1"],
            ),
        },
        "execution_success": {
            "passed": _at_least(
                candidate["metrics"]["execution_success_rate"],
                minimum_execution_success,
            ),
            "minimum": minimum_execution_success,
        },
        "safe_fix_rate": {
            "passed": _at_least(
                candidate["metrics"]["safe_fix_rate"], minimum_safe_fix_rate
            ),
            "minimum": minimum_safe_fix_rate,
        },
        "e2e_security_fix_rate": {
            "passed": _at_least(
                candidate["metrics"]["e2e_security_fix_rate"], minimum_e2e_fix_rate
            ),
            "minimum": minimum_e2e_fix_rate,
        },
    }
    source_kinds = set(candidate["dataset"].get("source_kinds") or [])
    provenance_gate = {
        "passed": source_kinds == {"public-github-pr"},
        "required_source_kind": "public-github-pr",
        "actual_source_kinds": sorted(source_kinds),
    }
    gates = dict(quantitative_gates)
    gates["production_data_provenance"] = provenance_gate
    # None（not_applicable）不算通过：无法验证的门禁不能放行。这比
    # `all()` 把 None 当假值更明确——同时把 not_applicable 列出来，
    # 让读报告的人看见"这条没验证"，而不是以为它失败了。
    not_applicable = sorted(
        name for name, item in gates.items() if item["passed"] is None
    )
    quantitative_passed = all(
        item["passed"] is True for item in quantitative_gates.values()
    )
    return {
        "dataset_sha256": candidate["dataset"]["sha256"],
        "baseline": baseline["name"],
        "candidate": candidate["name"],
        "deltas": {
            metric: _delta(
                candidate["metrics"][metric], baseline["metrics"][metric]
            )
            for metric in metrics
        },
        "not_applicable_gates": not_applicable,
        "release_gate": {
            "passed": all(item["passed"] is True for item in gates.values()),
            "quantitative_passed": quantitative_passed,
            "production_activation_allowed": (
                quantitative_passed and provenance_gate["passed"]
            ),
            "gates": gates,
        },
    }
