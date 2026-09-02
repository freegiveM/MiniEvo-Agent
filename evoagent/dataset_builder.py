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
#
# ── 关于 upgrade / docs 的两个例外（pilot 实测后加的）────────────────────
#
# 首轮 pilot 之后，我拿三个仓库约 600 个已合并 PR 量了这张表的误杀率：
# 16 条标题同时含 fix 类词又被 EXCLUDE 淘汰，其中 14 条杀对了
# （typo、broken link、lint），2 条是真损失，而且**坏在同一个地方**：
#
#   "Fix pipelining a rejected upgrade"          ← upgrade 是 HTTP Upgrade 头
#   "websocket_ping: fix ping interval ... and improve docs"  ← docs 在尾巴上
#
# 两条都是"这个词在这里不是它在依赖升级/文档 PR 里的那个意思"。
# 前者恰好是 L3/L4 协议边界样本——采样计划里最难凑够的那一类。
#
# 权衡过三种改法：
#   1. 删掉 upgrade / docs：会放进大量真的依赖升级和文档 PR，误标注率上升。
#      淘汰规则的代价是不对称的——漏掉一个样本只是少一条，
#      放进一个假标注会污染指标，所以不能往松的方向一刀切。
#   2. 改成看 diff 内容判定（比如只碰 .md 就算文档）：更准，但要花请求，
#      而 screen_title 存在的全部意义就是**在花请求之前**淘汰。
#   3. 只收紧这两个词的匹配条件，其余 22 个词不动。← 选这条
#
# 具体收紧方式也不同，因为两条的失败机制不同：
#   upgrade → 只在依赖升级的惯用搭配里才算（upgrade + 版本号/包名/to X.Y），
#             裸 upgrade 放行，让后面的 no-production-python / diff 规则接管。
#   docs   → 只在**开头**出现才算（"docs: ..." 是压倒性的文档 PR 惯例），
#             出现在句中不算。这条不会放进 "docs: fix typo"，
#             因为 typo 仍在表里、仍会被杀。
#
# 收紧 docs 之后又暴露出同一个毛病的另外两个词（这次是我自己测出来的，
# 不在那 16 条里，因为那三个仓库刚好没有这种标题）：
#
#   "Fix race condition in connector cleanup"   ← cleanup 是被修的对象
#   "Fix incorrect comment handling in parser"  ← comment 是被解析的对象
#
# 这两条分别属于 L4 并发/资源生命周期和 logic-boundary，也都是稀缺类。
# 处理方式和 docs 一致：只在标题**开头**（= 这个 PR 的主题）才算排除项。
# "cleanup: remove dead code" 仍会被杀，"fix ... cleanup" 会放行。
#
# 没有把这两条写进 EXCLUDE 主表，是因为主表是"词出现即淘汰"的简单语义，
# 混进带上下文条件的项会让它变得难读且容易误改。
EXCLUDE_KEYWORDS = re.compile(
    r"(?i)\b(revert|reverts|reverting|refactor\w*|rename\w*|clean up|"
    r"typo|format\w*|lint\w*|black|isort|flake8|"
    r"bump|downgrade|dependabot|pre-commit|"
    r"changelog|documentation|whitespace|deprecat\w*|"
    r"test only|add tests?|more tests?)\b"
)

# 发版提交：标题就是一个版本号。
#
# 抽查 60 条兜底样本时发现的，4/95 属于这种（httpx 三条、requests 一条）。
# 它们能过筛是因为 FIX_KEYWORDS 同时看标题**和正文**，而发版 PR 的正文是
# changelog，里面必然有 "fix" 字样。标题层拦不住，正文层反而帮了倒忙。
#
# 这是最坏的一种脏样本：反转之后"缺陷代码"是一行 __version__ = "0.28.0"。
# 任何审查器报它都算误报，不报又算漏报——这条样本无论如何都在给指标注噪声，
# 而且方向不定。相比之下"类别判不出来"只是信息不足，还能用。
#
# 只认标题**整体**是版本号，不认标题里含版本号：
# "Fix crash in 2.34 release path" 是真缺陷，必须放行。
RELEASE_TITLE = re.compile(
    r"(?i)^\s*(v(ersion)?\s*)?\d+\.\d+(\.\d+)?([-.\w]*)?\s*$"
)

# 版本号赋值行。用于在**内容层**再兜一次发版提交（标题可能是
# "Prepare 2.34.1" 这种，过得了 RELEASE_TITLE）。
VERSION_ASSIGNMENT = re.compile(
    r"""(?ix)
    ^\s*
    (__version__|__build__|VERSION|version|release|__release__)
    \s*(:\s*\w+\s*)?=          # 允许 version: str = "..."
    """
)

# upgrade 只在依赖升级的搭配里才算排除项。裸 "upgrade"（HTTP Upgrade 头、
# protocol upgrade）放行。
DEPENDENCY_UPGRADE = re.compile(
    r"(?i)\b(upgrade|upgrading)\b.{0,30}?"
    r"(\bto\b\s*v?\d|\bv?\d+\.\d+|\bdeps?\b|\bdependenc\w+|\brequirements?\b)"
)

# 这些词做 PR 主题时是排除项，做句中普通名词时不是。只认标题开头
# （"docs: ..." / "cleanup(x): ..." / "style - ..." 这类惯例写法）。
SUBJECT_ONLY_PREFIX = re.compile(
    r"(?i)^\s*(docs?|cleanup|comments?|style|styles)\b\s*[:(\[/-]"
)

# 放宽 comment 之后剩下的一个漏网口子，单独记一下，因为它划出了
# 只看标题这条路的**能力边界**：
#
#   "web: Fix an incomplete comment that was omitted"  ← 真文档 PR，会漏进来
#   "Fix incorrect comment handling in parser"          ← 真缺陷，要放行
#
# 两者的差别在 "comment" 是被修的**内容**还是被处理的**对象**，
# 标题里没有任何可靠信号能分开——"web:" 前缀让主题式判定也失效了。
#
# 选择是**不再收紧**，让前者漏进来。理由是这一层不是最后一道关，而且
# 下游那道关是**按内容判的，不是按文件名判的**（这点我核过代码才敢写）：
#
#   fix-adds-only / seed-lines-blank-or-comment-only 这两条在挑删除行和
#   种子行时都跳过 "#" 开头的行。纯改注释的 PR 反转后没有任何非注释新增行，
#   一定会被它们拒掉——即使它改的是 .py 文件、过得了 no-production-python。
#   （no-production-python 只管"有没有碰非测试 .py"，管不了"碰的是不是注释"。）
#
# 而如果为了堵它把 comment 放回"词出现即淘汰"，代价是稳定杀掉整类
# parser 缺陷样本。
#
# 判据仍是筛选规则的代价不对称：假接受会注入一条错标注、污染指标；
# 假拒绝只少一条样本。但这里的假接受**下游有按内容判的规则接管**，
# 假拒绝没人管——所以宁可放过去。代价只是多花一次 diff 请求。
DOC_ONLY_HINT = None  # 占位说明：刻意不加这条规则，理由见上。


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
    return classify_defect_with_basis(seed_lines, title)[0]


def classify_defect_with_basis(
    seed_lines: Sequence[str], title: str = "",
) -> "tuple":
    """同 classify_defect，但**同时返回这个标签是怎么来的**。

    为什么需要这个：第三批数据（95 条）报出 logic-boundary 占 90.5%，
    我一开始当成采样问题去修（先修了误杀词，又修了分母口径，通过率从
    9.5% 提到 34.2%），但这一类的占比几乎没动。量了才知道原因不在采样：

      代码特征命中        33 (34.7%)
      靠标题词             2 ( 2.1%)
      都没命中 -> 兜底     60 (63.2%)   ← 全部落进 logic-boundary

    也就是说 logic-boundary 这 86 条里，只有 26 条是**判定**为边界缺陷，
    60 条是"八类特征一个都没匹配上"的默认值。这两件事在报告里写成同一个
    数字，等于宣称"这批数据以边界缺陷为主"——而真实情况是"这批数据的
    类别大部分判不出来"。前者是结论，后者是承认无能，不能混。

    兜底本身不改（改成 unknown 会让 expected_findings 少一个 CWE，
    下游命中判定要跟着改，代价大且不解决根因）。改的是**留痕**：
    把依据一并返回，让报告能把"判出来的"和"兜底的"分开报。

    与 label_provenance 的区别：那个记的是"凭什么认定这是 bugfix"，
    这个记的是"凭什么认定它属于这一类"。两个都会错，但错法不同，
    混在一个字段里就没法分别追。

    ── 试过并否决的两条改法（都实测过，记下来避免重做）─────────────────

    A. 把删除行也喂进来判类别。动机是合理的：待审 diff 的删除行是人类
       修复引入的正确代码，agent 也看得见，用它不算泄漏。实测 95 条：

           只看 + 行     兜底 58 (61%)   logic-boundary 85 (89%)
           + 与 - 都看   兜底 37 (39%)   logic-boundary 79 (83%)

       兜底率降到 40% 硬线以下，看着像成功。但逐条查那 21 条"改善"的
       样本，判出来的类别**全部**是 logic-boundary，靠的是 `not in`、
       `for k, v in`、`maxsize` 这种特征——而任何一段正常 Python 都含
       比较符或 len/range/index。也就是说这不是"多判出了类别"，是给
       兜底类别开了一条更宽的入口：把 22 个样本从"诚实地标为判不出来"
       变成"被 logic-boundary 吞掉"。真实收益只有 6 条（非兜底非
       logic 的类别 10 -> 16），代价是兜底率这个指标本身失去意义。
       **61% 难看但诚实，39% 好看但是假的。**否决。

    B. 给七类各写一套自然语言标题词表（race/leak/auth/escape/tls/...），
       扩充 title-word 分支。在 59 条兜底上只多救 6 条，其中 1 条同时
       命中多类有歧义。收益太小，且标题描述的常是症状不是形态。否决。

    结论：兜底率高的根因不在"读少了 diff 的一半"，也不在"没读标题"，
    而在**八类分类体系本身覆盖不住真实 bugfix 的主体**。抽样读那 53 条
    判不出来的标题，主体是大小写归一化、类型契约、输入校验、转义编码、
    协议状态机——不是教科书式的八大安全缺陷。真正的对策是扩类别体系
    （试过 input-validation / contract-type / state-machine 三类的代码
    特征，只吃掉 24%，说明扩类也得配更细的模式），成本不小。

    在那之前的正确做法不是把数字修好看，而是**按数据实际支撑的粒度报数**：
    per-class 指标暂不报，只报总体与 rule_covered 两分。硬约束告警继续
    留在 40%，让它一直响——它响就是在提醒这件事没做完。
    """
    blob = "\n".join(seed_lines)
    for item in DEFECT_CLASSES:
        if any(pattern.search(blob) for pattern in item.patterns):
            return item, "code-pattern"
    lowered = title.lower()
    for item in DEFECT_CLASSES:
        if item.name.split("-")[0] in lowered:
            return item, "title-word"
    return _CLASS_BY_NAME["logic-boundary"], "fallback-default"


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
#
# ── L1 在真实数据上几乎不存在，这是定义的后果不是采样的运气 ──────────
#
# 采集后对账 repos.yaml 的先验预期，L1 实际产出 1/95（计划里六个仓库都
# 标了 L1 倾向）。放开配额重放全部 1020 个缓存 diff 后仍是 1/344。
# 拆开 L1 的两个条件量：
#
#     种子只有 1 行            155/344 (45.1%)
#     命中 L1_LITERAL 字面特征   3/344 ( 0.9%)   ← 瓶颈在这里
#     两个都满足 = L1            1/344 ( 0.3%)
#
# 原因是可以事后想明白的：eval(、shell=True、hashlib.md5、硬编码口令
# 这些形态，在成熟仓库里活不到需要开 PR 修——CI 的 linter/bandit 在
# 提交阶段就拦掉了。**能被字面规则命中的缺陷，通常不会成为 merged
# bugfix**。所以从 merged bugfix 反转构造，先天就采不到 L1。
#
# 不改 L1_LITERAL 去把数字凑上来：放宽它等于让 L1 名不副实（L1 的定义
# 就是"规则集碰得到"，放宽后规则集碰不到的样本会被标成 L1，D6 对照实验
# 里臂 A 在 L1 上应当有召回这个预期就不成立了）。正确的处理是承认这条
# 难度档在本构造方法下取不到样本，报数时明确写"L1 由受控基准集覆盖，
# 真实数据集不含 L1"——受控基准集里本来就有这类样本，两者互补。

L4_CLASSES = frozenset({"concurrency", "resource-leak"})

# 与 evoagent/reviewer.py 的 6 条规则同源的字面特征（判 L1 用）。
# 这里不 import LocalRuleReviewer.RULES：分级判据必须和 reviewer 解耦，
# 否则将来给 reviewer 加规则会**回溯改变已发布数据集的难度标签**，
# 使历史数字不可比。宁可少量重复，换取数据集标签的稳定性。
#
# 注：本表比 reviewer 的 6 条更宽（多了 hashlib.md5、verify=False、
# yaml.load、pickle.loads、mktemp）。刻意的：难度分级问的是"这类缺陷
# 是否属于字面可查的一档"，不是"当前这版 reviewer 恰好实现了哪几条"。
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
    # 这两条与上面同类（都是"这个 PR 不是 bugfix"），但需要上下文条件，
    # 理由见 EXCLUDE_KEYWORDS 上方的注释。归到同一个淘汰原因下，
    # 因为对漏斗统计来说它们就是一类。
    if RELEASE_TITLE.match(title or ""):
        # 单独一个原因，不并进 excluded-keyword：漏斗里要能看出发版提交
        # 有多少。并进去就分不清"关键词拦掉的"和"发版拦掉的"了。
        return "release-commit"
    if DEPENDENCY_UPGRADE.search(title or ""):
        return "excluded-keyword"
    if SUBJECT_ONLY_PREFIX.search(title or ""):
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

    chunks = split_diff_by_file(diff)
    if not chunks:
        raise CaseRejected("unparsable-diff")

    # 只保留非测试 .py 的文件块。测试文件的改动反转后不是缺陷；
    # 把它们留在待审 diff 里会让 agent 有机会从测试内容反推答案。
    code_chunks = [
        (path, text) for path, text in chunks
        if path.endswith(".py") and not is_test_path(path)
    ]

    # 不可反转标记的检查放在**筛完文件块之后**，而且逐块判。
    #
    # 原来是整份 diff 里出现标记就拒掉整个 PR。第一批数据（90 条）跑完
    # 用 977 个已缓存 diff 重放，量出这条是最大的损失来源：
    #
    #   unsupported-diff  366/977 (37.5%)，其中 new file mode 占 336 (91.8%)
    #
    # 也就是**约三分之一的候选**是因为"PR 里新增了某个文件"被整条丢掉的。
    # 但新增的那个文件通常是测试、changelog 或新模块——而这些块在上面
    # 已经被 code_chunks 筛掉了，本来就不会进入反转。为一个不会被用到的
    # 文件丢掉整条样本，是纯损失。
    #
    # 顺带纠正一个我一开始的误判：我以为类别塌成 91% logic-boundary 是
    # fix-adds-only（纯新增修复反转不了）造成的。重放数据否掉了这个说法
    # ——fix-adds-only 只占 2.3%。构造方法排除 missing-check 类这条边界
    # 是真的（模块 docstring 里写着），但它不是这批数据塌掉的原因。
    #
    # 为什么仍然逐块拒而不是全放开：反转 new file mode 的块是真的不可靠
    # （新增文件的 a/ 侧不存在，反转后要生成"删除整个文件"的 diff，
    # 而待审 diff 里出现删文件会让缺陷定位失去意义）。所以标记落在
    # **要用的块**里时照样拒，只是不再连累其他块。
    used = "".join(text for _path, text in code_chunks)
    for marker in UNSUPPORTED_MARKERS:
        if marker in used:
            raise CaseRejected("unsupported-diff", marker.strip())
    if NO_NEWLINE in used:
        raise CaseRejected("unsupported-diff", "no-newline-marker")

    # 规模上限也按**筛完之后的块**算，不按整份 diff 算。
    #
    # 这两条原来在筛选之前，量的是"这个 PR 一共动了多少"；但真正决定
    # 标注可靠性的是"待审 diff 有多大"——测试文件和 changelog 不进待审
    # diff，不该占额度。把标记检查改成逐块之后这点变得很明显：
    # too-many-files 从 130 涨到 343，涨的全是"改 1 个 py + 加 1 个测试"
    # 这种本来合格的 PR。
    #
    # **阈值本身一个都没动**（MAX_FIX_FILES=3、MAX_FIX_LINES=20）。
    # 改的是分母口径，不是把关口放松——这两件事在数据集构造里必须分清：
    # 放宽阈值会让待审 diff 变大、种子缺陷定位变糊、指标虚高；
    # 修正分母只是不再把不参与评测的文件算进来。
    if len(code_chunks) > MAX_FIX_FILES:
        raise CaseRejected("too-many-files", str(len(code_chunks)))
    if count_changed_lines(used) > MAX_FIX_LINES:
        raise CaseRejected("too-many-lines", str(count_changed_lines(used)))
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

    # 内容层再兜一次发版提交。标题层只挡住"标题就是版本号"那种；
    # "Prepare 2.34.1"、"Release candidate" 这类标题过得去，但种子行
    # 仍然全是版本号赋值——那种样本的"缺陷"是一行 __version__ = "..."，
    # 报它算误报、不报算漏报，无论如何都在注噪声。
    #
    # 条件是**全部**种子行都是版本号赋值，不是"含有"。真缺陷的修复里
    # 可能顺带碰一行版本号，那种要留下。
    if all(VERSION_ASSIGNMENT.match(line) for line in seed_lines):
        raise CaseRejected("release-commit", "seed lines are only version bumps")

    defect, class_basis = classify_defect_with_basis(seed_lines, title)
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
        # 这个标签是判出来的还是兜底的。fallback-default 的样本，其
        # defect_class 只表示"八类特征都没匹配上"，不表示判定为该类。
        # 报告必须把两者分开，否则 logic-boundary 的占比会被读成结论。
        "defect_class_basis": class_basis,
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
    by_class_basis: Dict[str, int] = field(default_factory=dict)
    rejections: Dict[str, int] = field(default_factory=dict)
    warnings: List[str] = field(default_factory=list)


TARGET_DIFFICULTY_SHARE = {"L1": 0.25, "L2": 0.35, "L3": 0.25, "L4": 0.15}
MIN_PER_CLASS = 6
MIN_PER_CONTAMINATION = 15

# 兜底类别占比的告警线。超过这条说明"类别分布"这个说法本身不成立：
# 报出来的多数标签只是默认值，不是判定结果。
#
# 取 0.4 的理由：低于这个比例时，主类里判出来的样本仍占多数，分布还能
# 当参考；超过之后，最大的那一类主要由"没匹配上"构成，再谈"以某类为主"
# 就是在把无能读成结论。这个数没有文献依据，是我按"主类是否仍以判定
# 为主"定的，写在这里以便后面有数据了可以改。
MAX_FALLBACK_SHARE = 0.4


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
            ("defect_class_basis", report.by_class_basis),
        ):
            value = str(case.get(key, "unknown"))
            bucket[value] = bucket.get(value, 0) + 1

    # 兜底类别占比要单独告警，而且要放在类别不足的告警**之前**报。
    #
    # 顺序是刻意的：如果多数标签是兜底来的，那么"某类不足 6 条"这些告警
    # 就是次要问题——先要知道的是"类别分布这件事本身有多大程度上不成立"。
    # 反过来先报一堆类别不足，读者会以为要去补那几类，而真正该做的是
    # 先修分类器或承认类别报不了。
    fallback = report.by_class_basis.get("fallback-default", 0)
    if report.total and fallback > report.total * MAX_FALLBACK_SHARE:
        report.warnings.append(
            "HARD CONSTRAINT VIOLATED: %d/%d (%.0f%%) of cases got their "
            "defect_class from the fallback default, not from a match. The class "
            "distribution below is therefore not a finding about these defects — "
            "it mostly reports what the classifier could not identify. Do not "
            "report per-class metrics until this is under %.0f%%."
            % (fallback, report.total, 100.0 * fallback / report.total,
               100.0 * MAX_FALLBACK_SHARE)
        )

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
