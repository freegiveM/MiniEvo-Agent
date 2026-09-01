"""Reverted-fix dataset construction: pure logic, no network.

The collector (scripts/collect_reverted_fix_dataset.py) owns GitHub paging and
rate limits; everything that decides *what a case looks like* lives here so it
can be unit tested against fixtures.

为什么拆两层（对比既有 scripts/import_github_pr_dataset.py）：那个脚本把抓取、
反转、校验揉在一个文件里且没有测试，任何一条筛选规则改动都只能靠真跑 API 验证。
把判定逻辑抽成无 IO 的纯函数后，D2 的全部规则都能离线锁死，采集器只剩翻页。

构造方法的固有偏置（必须写进 limitation，不能藏）：
反转 diff 要求真实 fix **删除过**代码。若 fix 是纯新增（例如补上一个缺失的
权限检查、加一个 try/finally），反转后只剩删除行，没有新增行，
`validate_case` 会拒绝。因此本数据集系统性排除 "missing check" 类缺陷，
只覆盖 "wrong code" 类。这不是实现瑕疵，是构造方法的边界。
"""
import hashlib
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from .diff_parser import parse_unified_diff


class CaseRejected(Exception):
    """Raised when a PR cannot become a valid case. Carries a stable reason code.

    reason 用 code 而不是自由文本：采集器要按 reason 聚合出"淘汰漏斗"
    （候选 N 个 → 各条规则各淘汰多少 → 成品 M 个）。漏斗本身是答辩材料，
    它能回答"你的 100 个 PR 是怎么筛出来的"，free-form 字符串没法聚合。
    """

    def __init__(self, reason: str, detail: str = "") -> None:
        super().__init__("%s: %s" % (reason, detail) if detail else reason)
        self.reason = reason
        self.detail = detail


# ── 一、筛选阈值 ────────────────────────────────────────────────────────
#
# 阈值来源：doc 36 的五条筛选规则。这里给出可执行的具体数值，并说明
# 每个数值"取这个而不是别的"的理由——面试会问到具体数字。

MAX_FIX_LINES = 20      # 修复改动总行数上限
MAX_FIX_FILES = 3       # 修复触碰文件数上限
MAX_SEED_SPAN = 10      # 单个种子缺陷允许跨的连续行数上限
                        # 为什么要这一条：expected_findings 的 [start,end] 越宽，
                        # 命中判定越宽松，指标越虚高。10 行以上的连续新增
                        # 已经不能说"缺陷就在这几行"了，宁可丢样本。

TEST_PATH = re.compile(r"(^|/)(tests?|testing)/|(^|/)test_[^/]*\.py$|_test\.py$")

# PR 标题/正文的 bugfix 关键词。刻意不含 "improve" / "update" / "change"
# ——它们在 feature PR 里同样高频，加进来会显著抬高误标注率。
FIX_KEYWORDS = re.compile(
    r"(?i)\b(fix|fixes|fixed|bug|bugfix|regression|security|vulnerab\w*|"
    r"cve-\d{4}-\d+|ghsa-[\w-]+|exploit|leak|race condition|off[- ]by[- ]one|"
    r"crash|incorrect|broken)\b"
)
CVE_PATTERN = re.compile(r"(?i)\b(cve-\d{4}-\d{4,7}|ghsa-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4})\b")
LINKED_ISSUE = re.compile(r"(?i)(fix(?:es|ed)?|close[sd]?|resolve[sd]?)\s+#\d+")

# 排除类关键词：这些 PR 的"删除行"不是缺陷，反转后会产生假标注。
# revert 尤其危险——反转一个 revert 等于恢复原始正确代码，标注完全错误。
EXCLUDE_KEYWORDS = re.compile(
    r"(?i)\b(revert|reverts|reverting|refactor\w*|rename\w*|cleanup|clean up|"
    r"typo|format\w*|lint\w*|style|black|isort|flake8|"
    r"bump|upgrade|downgrade|dependabot|pre-commit|"
    r"changelog|docs?|documentation|comment|whitespace|deprecat\w*|"
    r"test only|add tests?|more tests?)\b"
)


# ── 二、缺陷分类（八类 → CWE → severity）────────────────────────────────
#
# 分类按"有缺陷的那段代码"（= 反转后的新增行）加 PR 标题判定，不看修复后代码。
#
# 关键观察（这是消融实验的一个信息来源，不是巧合）：
# 八类里只有 4 类能被现有 14 条确定性规则覆盖（下表 rule_covered）。
# auth-bypass / resource-leak / logic-boundary / concurrency 四类**没有**
# 对应规则，因此臂 A（rules-only）在这四类上的召回上限是 0。
# 这个上限不是实验结果，是可以事先算出来的——它正好说明"为什么需要 LLM 角色"。

@dataclass(frozen=True)
class DefectClass:
    name: str
    cwe: str
    severity: str
    rule_covered: bool          # 现有确定性规则集是否覆盖
    patterns: Tuple[re.Pattern, ...]


DEFECT_CLASSES: Tuple[DefectClass, ...] = (
    # 顺序即优先级：一段代码可能命中多条，先命中先归类。
    # 排序原则是"特征越字面、越不可能误判的放前面"，避免 logic-boundary
    # 这种宽泛类别吞掉本该归入 crypto-weak 的样本。
    DefectClass(
        "crypto-weak", "CWE-328", "high", True,
        (
            re.compile(r"(?i)\b(md5|sha1)\s*\("),
            re.compile(r"(?i)hashlib\.(md5|sha1)\b"),
            re.compile(r"(?i)\brandom\.(random|randint|choice|shuffle)\b"),
            re.compile(r"(?i)\b(DES|RC4|ECB)\b"),
            re.compile(r"(?i)verify\s*=\s*False|check_hostname\s*=\s*False"),
            re.compile(r"(?i)ssl\._create_unverified_context|CERT_NONE"),
            re.compile(r"(?i)AutoAddPolicy|WarningPolicy"),  # paramiko 主机密钥
        ),
    ),
    DefectClass(
        "injection", "CWE-78", "critical", True,
        (
            re.compile(r"\b(eval|exec)\s*\("),
            re.compile(r"\bshell\s*=\s*True\b"),
            re.compile(r"(?i)os\.(system|popen)\s*\("),
            re.compile(r"(?i)(execute|executemany|raw|query)\s*\(\s*(f['\"]|['\"].*(\+|%))"),
            re.compile(r"(?i)yaml\.load\s*\((?![^)]*Loader)"),
            re.compile(r"(?i)pickle\.loads?\s*\("),
            re.compile(r"(?i)autoescape\s*=\s*False"),
        ),
    ),
    DefectClass(
        "secret-exposure", "CWE-798", "high", True,
        (
            re.compile(
                r"(?i)\b(password|passwd|api[_-]?key|secret|token|credential)s?\b"
                r"\s*=\s*['\"][^'\"]{4,}['\"]"
            ),
            re.compile(
                r"(?i)(log\w*|print)\s*\([^)]*\b"
                r"(password|token|secret|api[_-]?key|authorization)\b"
            ),
        ),
    ),
    DefectClass(
        "path-traversal", "CWE-22", "high", True,
        (
            re.compile(r"(?i)os\.path\.join\s*\([^)]*\b(request|user|input|param|name|arg)"),
            re.compile(r"(?i)(extractall|extract)\s*\("),
            re.compile(r"(?i)\.\./"),
            re.compile(r"(?i)open\s*\(\s*(f['\"]|[^,)]*\+)"),
        ),
    ),
    DefectClass(
        "concurrency", "CWE-362", "high", False,
        (
            re.compile(r"(?i)\b(threading|asyncio)\.(Lock|Event|Semaphore|Condition)\b"),
            re.compile(r"(?i)\b(acquire|release)\s*\(\s*\)"),
            re.compile(r"(?i)os\.path\.exists\s*\([^)]*\)\s*(and|:)"),   # TOCTOU 形态
            re.compile(r"(?i)\b(create_task|ensure_future|run_until_complete|gather)\b"),
            re.compile(r"(?i)\basync\s+def\b|\bawait\b"),
            re.compile(r"(?i)\b(global|nonlocal)\b"),
        ),
    ),
    DefectClass(
        "resource-leak", "CWE-772", "medium", False,
        (
            re.compile(r"(?i)\b(open|connect|socket|Session|ClientSession)\s*\("),
            re.compile(r"(?i)timeout\s*=\s*(None|0)\b"),
            re.compile(r"(?i)\b(close|shutdown|__exit__|finally)\b"),
            re.compile(r"(?i)tempfile\.mktemp\s*\("),
        ),
    ),
    DefectClass(
        "auth-bypass", "CWE-285", "critical", False,
        (
            re.compile(r"(?i)\b(is_authenticated|has_perm|has_permission|require\w*|"
                       r"check_perm\w*|is_superuser|is_staff|authorize\w*)\b"),
            re.compile(r"(?i)\bassert\b.*\b(auth|perm|user|admin|token)\b"),
            re.compile(r"(?i)@(login_required|permission_required|csrf_exempt)"),
        ),
    ),
    # logic-boundary 放最后：它是兜底类别，特征最弱（比较运算符谁都有），
    # 放前面会吞掉大量本该归入前七类的样本。
    DefectClass(
        "logic-boundary", "CWE-193", "medium", False,
        (
            re.compile(r"(<=|>=|<|>|!=|==)"),
            re.compile(r"(?i)\b(len|range|index|slice|offset|count|size|limit)\b"),
            re.compile(r"[+-]\s*1\b"),
            re.compile(r"(?i)\b(and|or|not)\b"),
        ),
    ),
)

_CLASS_BY_NAME = {item.name: item for item in DEFECT_CLASSES}

# CVE/GHSA 类样本走单独的 CWE 归属：有 CVE 的 PR，CWE 应以公告为准而非猜。
# 采集器拿不到公告正文时退回分类器结果，并把 label_provenance 记为 cve
# 以便后续人工复核只看这个子集（严格 CWE 命中率只在这个子集上报数）。


def classify_defect(seed_lines: Sequence[str], title: str = "") -> DefectClass:
    """Classify the buggy code (reverted added lines) into one of eight classes.

    先按代码特征判，代码判不出来再看标题。反过来会更差：标题里的
    "fix race condition" 常常描述的是症状而非这几行代码本身的形态。
    """
    blob = "\n".join(seed_lines)
    for item in DEFECT_CLASSES:
        if any(pattern.search(blob) for pattern in item.patterns):
            return item
    lowered = title.lower()
    for item in DEFECT_CLASSES:
        if item.name.split("-")[0] in lowered:
            return item
    return _CLASS_BY_NAME["logic-boundary"]


# ── 三、难度分级 ────────────────────────────────────────────────────────
#
# 难度 = 定位与归因所需的上下文范围。这是可客观判定的，不靠"感觉难不难"。
#
# 优先级必须显式定义，否则同一个 PR 可能同时满足多条规则而结果不确定：
#   L4（语义/并发/状态）> L3（跨函数或跨文件）> L1（单行且规则可命中）> L2（兜底）
#
# 为什么 L4 优先于 L3：一个并发缺陷即使只改一行、只在一个文件里，
# 难点仍在运行时语义，不在上下文范围。范围小 ≠ 容易。
# 为什么 L1 需要"规则可命中"这个条件：单行但无字面特征（例如把 `>` 改成 `>=`）
# 不是 L1——规则集碰不到它，它对系统的难度和单函数级相当。

L4_CLASSES = frozenset({"concurrency", "resource-leak"})

# 与 evoagent/reviewer.py 的 14 条规则同源的字面特征（判 L1 用）。
# 这里不 import LocalRuleReviewer.RULES：分级判据必须和 reviewer 解耦，
# 否则将来给 reviewer 加规则会**回溯改变已发布数据集的难度标签**，
# 使历史数字不可比。宁可少量重复，换取数据集标签的稳定性。
L1_LITERAL = re.compile(
    r"(?i)(\b(eval|exec)\s*\(|shell\s*=\s*True|hashlib\.(md5|sha1)|"
    r"yaml\.load\s*\((?![^)]*Loader)|pickle\.loads?\s*\(|"
    r"verify\s*=\s*False|os\.(system|popen)\s*\(|tempfile\.mktemp|"
    r"\b(password|api[_-]?key|secret|token)\b\s*=\s*['\"][^'\"]{4,}['\"])"
)

HUNK_HEADER = re.compile(r"^@@ -\d+(?:,\d+)? \+\d+(?:,\d+)? @@\s*(.*)$")
DEF_LINE = re.compile(r"^[+\- ]?\s*(?:async\s+)?def\s+(\w+)")


def grade_difficulty(
    seed_lines: Sequence[str],
    files: Sequence[str],
    function_count: int,
    defect_class: str,
) -> str:
    """Assign L1-L4 by the context span needed to locate and attribute the defect."""
    if defect_class in L4_CLASSES:
        return "L4"
    if len(files) >= 2 or function_count >= 2:
        return "L3"
    if len(seed_lines) == 1 and L1_LITERAL.search(seed_lines[0]):
        return "L1"
    return "L2"


def count_touched_functions(diff: str) -> int:
    """Count distinct enclosing functions the diff touches.

    两个来源：(1) git 在 hunk header 尾部写的所属函数名（`@@ ... @@ def foo():`），
    (2) hunk 体内出现的 def 行。取并集去重。

    已知不精确：git 的 section heading 靠启发式（xfuncname），嵌套函数和
    装饰器会算错；数不出来时退回 1。**分级只用于分层报数，不参与命中判定**，
    所以这里的误差不会污染核心指标——只会让某条样本落到相邻难度档。
    这是刻意接受的精度/成本取舍。
    """
    names = set()
    for raw in diff.splitlines():
        header = HUNK_HEADER.match(raw)
        if header:
            heading = header.group(1).strip()
            match = DEF_LINE.match(heading)
            if match:
                names.add(match.group(1))
            continue
        if raw.startswith(("+", "-")) and not raw.startswith(("+++", "---")):
            match = DEF_LINE.match(raw)
            if match:
                names.add(match.group(1))
    return max(1, len(names))


# ── 四、diff 反转 ───────────────────────────────────────────────────────

NO_NEWLINE = "\\ No newline at end of file"
UNSUPPORTED_MARKERS = (
    "Binary files ",
    "GIT binary patch",
    "rename from ",
    "copy from ",
    "new file mode ",
    "deleted file mode ",
)

FILE_HEADER = re.compile(r"^diff --git a/(.+?) b/(.+)$")
HUNK_FULL = re.compile(
    r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@(.*)$"
)


def reverse_unified_diff(diff: str) -> str:
    """Swap the two sides of a unified diff: the fix's deletions become additions.

    实现要点：
    - `--- a/x` 与 `+++ b/x` 保持不变（同一路径两侧同名，交换无意义）；
      需要交换的是 hunk header 的两组行号和每行的 +/- 前缀。
    - `index <old>..<new>` 行被**丢弃**而不是交换：交换后的 blob hash 是错的，
      写一个错的 hash 比不写更糟（会误导任何试图用它定位 blob 的人）。
    - `\\ No newline at end of file` 出现时直接拒收该 PR（见
      UNSUPPORTED_MARKERS 邻近的校验）：这个标记归属于紧邻的某一侧，
      正确反转要跟踪它属于哪一侧。这类 PR 极少，拒收比写一段容易出错的
      归属推断更划算。
    """
    out: List[str] = []
    for raw in diff.splitlines():
        if raw.startswith("index ") or raw.startswith("similarity index "):
            continue
        header = HUNK_FULL.match(raw)
        if header:
            old_start, old_count, new_start, new_count, tail = header.groups()
            out.append("@@ -%s%s +%s%s @@%s" % (
                new_start, "" if new_count is None else "," + new_count,
                old_start, "" if old_count is None else "," + old_count,
                tail,
            ))
            continue
        if raw.startswith("+++") or raw.startswith("---") or raw.startswith("diff --git"):
            out.append(raw)
            continue
        if raw.startswith("+"):
            out.append("-" + raw[1:])
        elif raw.startswith("-"):
            out.append("+" + raw[1:])
        else:
            out.append(raw)
    return "\n".join(out) + "\n"


def split_diff_by_file(diff: str) -> List[Tuple[str, str]]:
    """Split a multi-file diff into (new_path, text) chunks, preserving order."""
    chunks: List[Tuple[str, str]] = []
    current_path = ""
    current: List[str] = []
    for raw in diff.splitlines():
        header = FILE_HEADER.match(raw)
        if header:
            if current_path:
                chunks.append((current_path, "\n".join(current) + "\n"))
            current_path = header.group(2).strip()
            current = [raw]
            continue
        if current_path:
            current.append(raw)
    if current_path:
        chunks.append((current_path, "\n".join(current) + "\n"))
    return chunks


def is_test_path(path: str) -> bool:
    return bool(TEST_PATH.search(path.replace("\\", "/")))


def count_changed_lines(diff: str) -> int:
    total = 0
    for raw in diff.splitlines():
        if raw.startswith(("+", "-")) and not raw.startswith(("+++", "---")):
            total += 1
    return total


# ── 五、污染切分 ────────────────────────────────────────────────────────


def contamination_split(merged_at: str, cutoff: str) -> str:
    """Classify a PR as pre-cutoff (possibly memorised) or post-cutoff (clean)."""
    merged = _parse_iso(merged_at)
    boundary = _parse_iso(cutoff)
    return "pre-cutoff" if merged < boundary else "post-cutoff"


def _parse_iso(value: str) -> datetime:
    text = str(value).strip().replace("Z", "+00:00")
    parsed = datetime.fromisoformat(text)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


# ── 六、成案 ────────────────────────────────────────────────────────────


@dataclass
class PullRequest:
    """The subset of GitHub PR metadata the builder needs."""
    repository: str
    number: int
    title: str
    body: str
    merged_at: str
    diff: str
    html_url: str = ""


def _seed_findings(
    reverted_diff: str, defect: DefectClass,
) -> List[dict]:
    """Turn contiguous runs of added lines into expected_findings ranges.

    一个连续新增行段 = 一个种子缺陷。不把整个文件的新增行并成一条：
    那会让 [start,end] 过宽，命中判定被稀释（见 MAX_SEED_SPAN 的理由）。
    """
    parsed = parse_unified_diff(reverted_diff)
    by_path: Dict[str, List[int]] = {}
    for line in parsed.added_lines:
        if is_test_path(line.path):
            continue
        if not line.path.endswith(".py"):
            continue
        if not line.content.strip():
            continue
        stripped = line.content.strip()
        if stripped.startswith("#"):
            continue
        by_path.setdefault(line.path, []).append(line.line)

    findings: List[dict] = []
    for path in sorted(by_path):
        numbers = sorted(by_path[path])
        run_start = numbers[0]
        previous = numbers[0]
        runs: List[Tuple[int, int]] = []
        for number in numbers[1:]:
            if number == previous + 1:
                previous = number
                continue
            runs.append((run_start, previous))
            run_start = previous = number
        runs.append((run_start, previous))
        for start, end in runs:
            if end - start + 1 > MAX_SEED_SPAN:
                raise CaseRejected(
                    "seed-span-too-wide",
                    "%s lines %d-%d" % (path, start, end),
                )
            findings.append({
                "path": path,
                "start_line": start,
                "end_line": end,
                "cwe": defect.cwe,
                "severity": defect.severity,
                "should_comment": True,
                "defect_class": defect.name,
            })
    return findings


def label_provenance(title: str, body: str) -> str:
    """Where the bugfix label came from — needed to scope CWE-strict reporting."""
    text = "%s\n%s" % (title, body or "")
    if CVE_PATTERN.search(text):
        return "cve"
    if LINKED_ISSUE.search(text):
        return "linked-issue"
    return "title-keyword"


# backport PR 的标题形态，实测来自 aiohttp 首页：
#   [PR #12787/4eb35886 backport][3.15] fix(connector): resolve race condition
# 一个修复常被 backport 到 2~3 个维护分支，于是同一个缺陷在数据集里出现
# 3 次。这不是"多了两条样本"，而是三重危害：
#   1. 指标被重复样本加权，等于给某个缺陷投了 3 票；
#   2. validation 与 holdout 若各拿到一份，holdout 就泄漏了；
#   3. 难度/类别分布被同一个修复扭曲。
BACKPORT_PATTERN = re.compile(r"(?i)\bbackport\b|^\s*\[\s*\d+\.\d+[\w.]*\s*\]")


def _fingerprint_lines(diff: str) -> List[str]:
    """只取以 +/- 开头的行。

    只留 +/- 行，就同时甩掉了三种噪声，而且是一个条件甩掉的：
    - hunk 头 @@ -120,7 +120,8 @@ ——backport 到不同分支时同一处修改
      的行号会偏移，@@ -120 与 @@ -134 描述的是同一个改动，含行号的哈希
      认不出这对重复。@@ 不以 +/- 开头，自动排除。
    - index 行的 blob 哈希——不同分支上必然不同，纯噪声。同样自动排除。
    - 上下文行——backport 时周边代码可能已漂移，但缺陷与修复是同一个。

    曾经额外写了一句 `if line.startswith("@@") or ...: continue`，变异测试
    证明那是死代码：@@ 和 index 行本来就不以 +/- 开头。删掉它并把理由写在
    这里，比留着一段永不生效的分支和一句归因错误的注释更好。

    +++/--- 文件头**故意保留**（它们以 +/- 开头）：同一处改动落在不同文件
    上不算重复，路径必须进指纹。
    """
    return [line.rstrip() for line in diff.splitlines()
            if line.startswith("+") or line.startswith("-")]


def diff_fingerprint(diff: str) -> str:
    """内容级指纹，用于跨 PR 去重。

    与标题模式是**互补**的两道，不是二选一：
    - 标题模式在抓 diff 前就能拦掉，省请求，但依赖各仓库的命名习惯；
    - 内容指纹不依赖命名，能抓到"同一修复由不同 PR 分别落地"，
      但必须先花一次请求拿到 diff。
    只留其一都会漏：只靠标题会漏掉不写 backport 字样的重复提交，
    只靠指纹会把该省的请求花掉。
    """
    return hashlib.sha1(
        "\n".join(_fingerprint_lines(diff)).encode("utf-8", errors="replace")
    ).hexdigest()


def screen_title(title: str, body: str) -> Optional[str]:
    """只看标题与正文的淘汰判定，返回淘汰原因或 None（= 通过）。

    为什么单独拆出来：这两条规则**不需要 diff**，而 diff 是采集器唯一
    要花请求的东西。原先它们只在 build_case 里跑，而 build_case 在
    pull_diff 之后调用——于是每个 dependabot PR 都要先花一次请求抓 diff
    再被标题规则淘汰。首轮 pilot 实测：53 次请求里 42 次是这样浪费的。

    标题和正文本来就随 list 端点免费返回，一页 100 条只要 1 次请求。
    把这两条前移到抓 diff 之前，同样配额能筛的候选数翻倍。

    build_case 仍然调用本函数，保持自身完整（离线单测不依赖采集器）。
    同一份判定跑两次的代价是两次短字符串正则，可以忽略；换来的是只有
    一处实现，不会两边漂移。
    """
    if BACKPORT_PATTERN.search(title or ""):
        # 放在 EXCLUDE 之前：backport 标题里常同时含 fix 字样，
        # 顺序反了会先被判成合格 bugfix。
        return "backport-duplicate"
    if EXCLUDE_KEYWORDS.search(title or ""):
        return "excluded-keyword"
    if not FIX_KEYWORDS.search("%s\n%s" % (title or "", body or "")):
        return "not-a-bugfix"
    return None


def build_case(
    pull: PullRequest, split: str, cutoff: str, domain: str = "",
) -> dict:
    """Build one validated-shape case from a merged fix PR, or raise CaseRejected.

    筛选顺序是刻意的：**先跑便宜且淘汰率高的规则**（关键词、行数），
    再跑要解析 diff 的规则。采集器在 rate limit 下按仓库分批跑，
    这个顺序直接决定能筛多少个 PR。
    """
    title = pull.title or ""
    body = pull.body or ""

    screened = screen_title(title, body)
    if screened is not None:
        raise CaseRejected(screened, title[:80])

    diff = pull.diff or ""
    if not diff.strip():
        raise CaseRejected("empty-diff")
    for marker in UNSUPPORTED_MARKERS:
        if marker in diff:
            raise CaseRejected("unsupported-diff", marker.strip())
    if NO_NEWLINE in diff:
        raise CaseRejected("unsupported-diff", "no-newline-marker")

    chunks = split_diff_by_file(diff)
    if not chunks:
        raise CaseRejected("unparsable-diff")
    if len(chunks) > MAX_FIX_FILES:
        raise CaseRejected("too-many-files", str(len(chunks)))
    if count_changed_lines(diff) > MAX_FIX_LINES:
        raise CaseRejected("too-many-lines", str(count_changed_lines(diff)))

    # 只保留非测试 .py 的文件块。测试文件的改动反转后不是缺陷；
    # 把它们留在待审 diff 里会让 agent 有机会从测试内容反推答案。
    code_chunks = [
        (path, text) for path, text in chunks
        if path.endswith(".py") and not is_test_path(path)
    ]
    if not code_chunks:
        raise CaseRejected("no-production-python")

    # 反转要求 fix 删除过代码。纯新增的 fix（补缺失检查）反转后没有新增行。
    # 这条规则划出了构造方法的边界，见模块 docstring。
    code_diff = "".join(text for _path, text in code_chunks)
    deletions = [
        raw for raw in code_diff.splitlines()
        if raw.startswith("-") and not raw.startswith("---")
    ]
    if not any(raw[1:].strip() and not raw[1:].strip().startswith("#") for raw in deletions):
        raise CaseRejected("fix-adds-only", "reversal would yield no added lines")

    reverted = reverse_unified_diff(code_diff)
    parsed = parse_unified_diff(reverted)
    if not parsed.files or not parsed.added_lines:
        raise CaseRejected("reversal-has-no-added-lines")

    seed_lines = [
        line.content for line in parsed.added_lines
        if line.content.strip() and not line.content.strip().startswith("#")
    ]
    if not seed_lines:
        raise CaseRejected("seed-lines-blank-or-comment-only")

    defect = classify_defect(seed_lines, title)
    findings = _seed_findings(reverted, defect)
    if not findings:
        raise CaseRejected("no-seed-findings")

    difficulty = grade_difficulty(
        seed_lines,
        [path for path, _text in code_chunks],
        count_touched_functions(code_diff),
        defect.name,
    )

    owner_repo = pull.repository.replace("/", "__")
    return {
        # ── validate_case 要求的字段 ──
        "id": "%s-pr-%d" % (owner_repo, pull.number),
        "repository": pull.repository,
        "pull_request": pull.number,
        "split": split,
        "diff": reverted,
        "expected_findings": findings,
        # ── 本数据集额外字段 ──
        "merged_at": pull.merged_at,
        "contamination_split": contamination_split(pull.merged_at, cutoff),
        "difficulty": difficulty,
        "defect_class": defect.name,
        "rule_covered": defect.rule_covered,
        "domain": domain,
        "label_provenance": label_provenance(title, body),
        "fix_pr_url": pull.html_url or "https://github.com/%s/pull/%d" % (
            pull.repository, pull.number,
        ),
        "fix_pr_title": title[:200],
        # human_patch = 人类的真实修复补丁（即原始 fix diff，未反转）。
        # 反转构造的免费红利：修复环节评测的真值不需要额外标注。
        "human_patch": code_diff,
        "source": {
            "kind": "real-pr-reverted-fix",
            "note": (
                "Buggy code is real (it existed in repository history), but the "
                "'incoming PR' framing is synthetic. Positive rate is inflated "
                "by construction; not comparable to organic PR benchmarks."
            ),
        },
    }


# ── 七、配额与覆盖复核 ──────────────────────────────────────────────────


@dataclass
class CoverageReport:
    total: int = 0
    by_split: Dict[str, int] = field(default_factory=dict)
    by_difficulty: Dict[str, int] = field(default_factory=dict)
    by_class: Dict[str, int] = field(default_factory=dict)
    by_contamination: Dict[str, int] = field(default_factory=dict)
    by_repository: Dict[str, int] = field(default_factory=dict)
    by_provenance: Dict[str, int] = field(default_factory=dict)
    rejections: Dict[str, int] = field(default_factory=dict)
    warnings: List[str] = field(default_factory=list)


TARGET_DIFFICULTY_SHARE = {"L1": 0.25, "L2": 0.35, "L3": 0.25, "L4": 0.15}
MIN_PER_CLASS = 6
MIN_PER_CONTAMINATION = 15


def summarise(cases: Iterable[dict], rejections: Optional[Dict[str, int]] = None) -> CoverageReport:
    """Report actual coverage against the sampling plan, with explicit warnings.

    这个函数存在的理由：repos.yaml 里的配额是**预期**，不是事实。
    采集跑完必须用实际产出复核，且**不达标要显式警告而不是静默通过**——
    否则 "每类至少 6 例" 这种设计承诺会在报数时变成一句没人核过的话。
    """
    # 先固化：下面要遍历两次（统计 + 切分重叠检查），传进来的是生成器时
    # 第二次遍历会拿到空序列，导致"仓库不相交"这条硬约束静默失效。
    cases = list(cases)
    report = CoverageReport(rejections=dict(rejections or {}))
    for case in cases:
        report.total += 1
        for key, bucket in (
            ("split", report.by_split),
            ("difficulty", report.by_difficulty),
            ("defect_class", report.by_class),
            ("contamination_split", report.by_contamination),
            ("repository", report.by_repository),
            ("label_provenance", report.by_provenance),
        ):
            value = str(case.get(key, "unknown"))
            bucket[value] = bucket.get(value, 0) + 1

    for item in DEFECT_CLASSES:
        count = report.by_class.get(item.name, 0)
        if count < MIN_PER_CLASS:
            report.warnings.append(
                "defect class %s has %d cases (< %d): a single class must not "
                "dominate the metric, and a near-empty class cannot be reported "
                "separately at all" % (item.name, count, MIN_PER_CLASS)
            )
    for level, share in sorted(TARGET_DIFFICULTY_SHARE.items()):
        count = report.by_difficulty.get(level, 0)
        expected = share * max(1, report.total)
        if count < expected * 0.6:
            report.warnings.append(
                "difficulty %s has %d cases, plan expected ~%.0f: the capability "
                "curve loses a rung" % (level, count, expected)
            )
    for bucket in ("pre-cutoff", "post-cutoff"):
        count = report.by_contamination.get(bucket, 0)
        if count < MIN_PER_CONTAMINATION:
            report.warnings.append(
                "%s has %d cases (< %d): the contamination comparison cannot "
                "carry any weight at this size" % (bucket, count, MIN_PER_CONTAMINATION)
            )

    validation_repos = {
        case["repository"] for case in cases if case.get("split") == "validation"
    }
    holdout_repos = {
        case["repository"] for case in cases if case.get("split") == "holdout"
    }
    overlap = validation_repos & holdout_repos
    if overlap:
        report.warnings.append(
            "HARD CONSTRAINT VIOLATED: repositories appear in both splits: %s"
            % ", ".join(sorted(overlap))
        )
    return report
