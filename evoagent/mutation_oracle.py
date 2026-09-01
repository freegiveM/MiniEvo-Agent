"""变异测试作为第二 Oracle：人工注入缺陷，标注强度最高。

## 为什么需要第二个 Oracle

现有唯一 Oracle 是"历史人类修复"（反转 fix PR）。它是**弱标签**：
标注来自 PR 标题关键词和"这几行被改过"，而不是"这里确实有缺陷"。
Oracle 强度阶梯（从强到弱）：

    人工注入缺陷（变异测试）  ← 本模块
      > 程序执行（测试通过/失败）
      > 历史人类修复（弱标签）   ← 现有数据集
      > LLM 打分
      > 人类主观判断

变异测试站在最上面一档：缺陷是我注入的，位置、类型、正确形态全部已知，
不存在"这行到底算不算缺陷"的争议。

## 与反转数据集的关系：互补，不是替代

诚实记录本方法的偏斜：变异算子产出的几乎全是 **logic-boundary** 类缺陷
（边界、控制流、常量）。它**测不到** crypto-weak / injection /
secret-exposure 这些需要领域知识的类别——没有哪个变异算子会把 sha256
改成 md5。所以：
- 反转数据集覆盖安全类缺陷，标注弱但类别真实；
- 变异测试覆盖逻辑类缺陷，标注强但类别单一。
两者都要，报数时分开报，不合并成一个总召回率。

## 一个有用的副作用

logic-boundary 恰好是现有 14 条确定性规则**覆盖不到**的 4 类之一。
所以在变异集上，arm A（纯规则）的召回天花板结构性地就是 0。这让变异集
成为一个干净的"LLM 能力隔离器"：A 与 B 的差不再混有规则的贡献。

## 等价变异体问题（本方法最主要的效度威胁）

有些变异不改变程序语义（equivalent mutant），此时"缺陷"并不存在，
标注是假的。这在变异测试文献里是公认的未解难题，一般判定不可判定。
本模块的处理：
- 对**自包含纯函数**做差分执行，实测输入输出不同才收作样本（强证据）；
- 无法执行的，标记 `equivalence_checked=False` 并在报告里单列，
  不混进主指标。
不假装解决了它，而是把不确定的部分隔离出去。
"""
import ast
from dataclasses import dataclass, replace
from typing import Any, Dict, List, Optional, Sequence, Tuple

from .diff_parser import parse_unified_diff
from .evaluation_harness import validate_case


@dataclass(frozen=True)
class Mutation:
    """一个变异体：改了哪一行、改成什么、属于哪类缺陷。"""

    operator: str               # 算子名，如 "comparison-boundary"
    line: int                   # 1-indexed，变异发生的行
    original_line: str          # 原始行文本（正确形态）
    mutated_line: str           # 变异后行文本（缺陷形态）
    defect_class: str           # 归入八类之一，供分类报数
    cwe: str
    severity: str
    description: str            # 人能读的说明，进 expected_findings
    # 是否用差分执行证明过"语义真的变了"。False 不代表等价，代表**未证**——
    # 这两者的区别和 None vs 0.0 是同一回事，不能混。
    equivalence_checked: bool = False
    # 为什么不止一个 bool：`False` 把两种完全不同的状态混在一起。
    #   not-attempted：差分执行没跑（点位不满足条件）→ 两个方向都没有证据
    #   no-difference：跑了，所有探测输入下行为相同 → **可能真等价**，
    #                  假标签就集中在这一档
    #   proven        ：找到了行为不同的输入 → 标签成立
    # 只看 bool 的话，no-difference 会被当成 not-attempted 一样无害，
    # 而它恰恰是唯一有反向证据的一档。同 None ≠ 0.0，往下多一层。
    equivalence_status: str = "not-attempted"


# 所有变异算子产出的缺陷都归 logic-boundary。
# 这不是偷懒：变异算子改的是比较、布尔、常量、控制流，本质都是逻辑边界。
# 硬要按 CWE 细分（CWE-193 off-by-one、CWE-570 恒假表达式……）会制造
# 一种"类别很丰富"的假象，而它们在评测里的行为完全一样。
MUTATION_DEFECT_CLASS = "logic-boundary"
MUTATION_CWE = "CWE-1077"       # Floating point / logic comparison 一族的父类
MUTATION_SEVERITY = "medium"

# 比较算子互换表。
#
# 只做**边界相邻**的互换（< ↔ <=），不做 < ↔ > 这种翻转。
# 理由：< 改成 > 通常让程序立刻大面积失败，那是"明显 bug"，
# 审查 agent 几乎必然发现，样本区分度低。而 < 改成 <= 只在边界值上出错，
# 这才是真实 off-by-one 的形态，也是审查真正的难点所在。
COMPARISON_SWAPS = {
    ast.Lt: ast.LtE, ast.LtE: ast.Lt,
    ast.Gt: ast.GtE, ast.GtE: ast.Gt,
}

BOOLEAN_SWAPS = {ast.And: ast.Or, ast.Or: ast.And}


class _SiteFinder(ast.NodeVisitor):
    """收集可变异的位置。

    为什么用 AST 而不是正则：正则会改到字符串字面量和注释里的 ">="，
    产出的"缺陷"根本不是代码。AST 只看语法结构，天然避开这一类。
    """

    def __init__(self) -> None:
        self.comparisons: List[ast.Compare] = []
        self.booleans: List[ast.BoolOp] = []
        self.constants: List[ast.Constant] = []
        self.weak_guards: List[ast.If] = []
        self.returns: List[ast.Return] = []

    def visit_Compare(self, node: ast.Compare) -> None:
        # 只收单比较（a < b），不收链式（a < b < c）：
        # 链式比较改一个算子的语义后果不直观，说不清"正确形态"是什么。
        if len(node.ops) == 1 and type(node.ops[0]) in COMPARISON_SWAPS:
            self.comparisons.append(node)
        self.generic_visit(node)

    def visit_BoolOp(self, node: ast.BoolOp) -> None:
        if type(node.op) in BOOLEAN_SWAPS and len(node.values) >= 2:
            self.booleans.append(node)
        self.generic_visit(node)

    def visit_Constant(self, node: ast.Constant) -> None:
        # 只动整数，且排除 bool（isinstance(True, int) 为真，必须显式排掉）。
        # 0/1 也排除：它们常作哨兵值，±1 后语义变化过于剧烈。
        if isinstance(node.value, int) and not isinstance(node.value, bool):
            if abs(node.value) > 1:
                self.constants.append(node)
        self.generic_visit(node)

    def visit_If(self, node: ast.If) -> None:
        # 只收"没有 else、条件是多项 and"的守卫式 if。
        # 无 else：删条件等于"少了一道检查"，语义干净。有 else 的话
        # 说不清缺陷是"少检查"还是"走错分支"。
        # 多项 and：只有这种才有东西可删。
        if (not node.orelse and isinstance(node.test, ast.BoolOp)
                and isinstance(node.test.op, ast.And)
                and len(node.test.values) >= 2):
            self.weak_guards.append(node)
        self.generic_visit(node)

    def visit_Return(self, node: ast.Return) -> None:
        # 只收**布尔形态**的返回值。
        # `return 100` 置反会变成 `return not (100)`，也就是 False——
        # 返回类型都变了。这种样本审查 agent 单看"类型不对"就能报出来，
        # 不需要判断逻辑，等于因为错误的理由变简单（同算子⑤的视觉线索问题）。
        if node.value is not None and _is_boolean_shaped(node.value):
            self.returns.append(node)
        self.generic_visit(node)


_OP_TEXT = {
    ast.Lt: "<", ast.LtE: "<=", ast.Gt: ">", ast.GtE: ">=",
}


def _is_boolean_shaped(node: ast.AST) -> bool:
    """这个表达式是不是"布尔形态"，也就是置反后类型不变。

    只按语法判断。Python 没有静态类型，`return flag` 里的 flag 到底是
    bool 还是 list 无法在语法层确定，所以裸变量名一律不收——宁可少收样本，
    也不要收进一个"置反后返回类型都变了"的假缺陷。
    """
    if isinstance(node, ast.Constant):
        return isinstance(node.value, bool)
    if isinstance(node, ast.UnaryOp):
        return isinstance(node.op, ast.Not)
    if isinstance(node, ast.BoolOp):
        # a and b 的值是其中一个操作数，不保证是 bool。只有操作数本身
        # 都是布尔形态时，整体才是。
        return all(_is_boolean_shaped(value) for value in node.values)
    return isinstance(node, ast.Compare)


def _single_line(node: ast.AST) -> bool:
    """节点是否只占一行。

    跨行表达式排除掉：本模块按"行"产出变异，跨行的改动无法表达成
    单行替换，而 expected_findings 的 [start,end] 一宽，命中判定就松，
    指标会虚高。宁可少收样本。
    """
    end = getattr(node, "end_lineno", None)
    return end is not None and node.lineno == end


def _replace_segment(line: str, node: ast.AST, replacement: str) -> Optional[str]:
    """把行内 [col_offset, end_col_offset) 段替换掉。

    按列偏移做替换而不是整行 unparse：整行 unparse 会顺手改掉缩进、
    引号风格、括号，产出的 diff 里混着大量无关改动，审查 agent 面对的
    输入就不再是"一处缺陷"了。
    """
    start = getattr(node, "col_offset", None)
    end = getattr(node, "end_col_offset", None)
    if start is None or end is None or end > len(line):
        return None
    return line[:start] + replacement + line[end:]


def _mutation(operator, line_no, lines, mutated_text, description):
    """组装 Mutation，统一做"变异后必须真的不同"这一层校验。"""
    original = lines[line_no - 1]
    if mutated_text is None or mutated_text == original:
        return None
    return Mutation(
        operator=operator, line=line_no, original_line=original,
        mutated_line=mutated_text, defect_class=MUTATION_DEFECT_CLASS,
        cwe=MUTATION_CWE, severity=MUTATION_SEVERITY, description=description,
    )


def generate_mutations(source: str) -> List[Mutation]:
    """对一段 Python 源码枚举所有可用变异体。

    返回顺序按算子分组、组内按行号——**确定性**是硬要求：
    评测要可复现，同一份源码每次必须给出同一批样本，不能依赖集合序。
    """
    tree = ast.parse(source)
    lines = source.splitlines()
    finder = _SiteFinder()
    finder.visit(tree)
    out: List[Mutation] = []

    # ① 比较边界：< ↔ <=。真实 off-by-one 的形态。
    for node in finder.comparisons:
        if not _single_line(node):
            continue
        op = node.ops[0]
        swapped = COMPARISON_SWAPS[type(op)]
        # 这里**不能**用 _replace_segment：ast.cmpop 子类（Lt/LtE/…）不带
        # col_offset，AST 只给表达式和语句节点位置信息。实测确认过。
        # 所以退化到整行文本替换，并靠 _swap_operator_in_line 的
        # "只出现一次才改"来保证不会改错位置。
        text = _swap_operator_in_line(
            lines[node.lineno - 1], _OP_TEXT[type(op)], _OP_TEXT[swapped],
        )
        mutation = _mutation(
            "comparison-boundary", node.lineno, lines, text,
            "Off-by-one: boundary comparison %s should be %s" % (
                _OP_TEXT[swapped], _OP_TEXT[type(op)]),
        )
        if mutation:
            out.append(mutation)

    # ② 布尔算子：and ↔ or。少一个必要条件，或多接受一种情况。
    for node in finder.booleans:
        if not _single_line(node):
            continue
        was = "and" if isinstance(node.op, ast.And) else "or"
        now = "or" if was == "and" else "and"
        text = _swap_operator_in_line(lines[node.lineno - 1], was, now, word=True)
        mutation = _mutation(
            "boolean-operator", node.lineno, lines, text,
            "Wrong boolean operator: '%s' should be '%s'" % (now, was),
        )
        if mutation:
            out.append(mutation)

    # ③ 常量 ±1：缓冲区大小、上限、索引偏移一类。
    for node in finder.constants:
        if not _single_line(node):
            continue
        text = _replace_segment(
            lines[node.lineno - 1], node, str(node.value + 1))
        mutation = _mutation(
            "constant-offset", node.lineno, lines, text,
            "Incorrect constant: %d should be %d" % (node.value + 1, node.value),
        )
        if mutation:
            out.append(mutation)

    # ④ 削弱守卫：从 `if a and b:` 里删掉一个合取项。
    #
    # 计划原文写的是"删 if 分支"，这里**故意换成削弱**，原因是结构性的：
    # validate_case 要求每个 expected_finding 必须覆盖一条**新增行**（`+` 行）。
    # 纯删除的变异只产出 `-` 行，没有任何新增行可指——这类样本根本过不了
    # 校验，硬造只能靠放宽校验，而放宽校验会让所有样本的命中判定一起变松。
    #
    # 削弱保住了同一种缺陷语义（少了一个必要条件 → 少一道检查），
    # 同时留下一条新增行（改写后的 guard）。它和算子②（and↔or）不重叠：
    # ② 换的是连接方式，④ 少的是条件本身。
    for node in finder.weak_guards:
        if not _single_line(node.test):
            continue
        # 删最后一个合取项：通常是最具体的那个检查，最像"漏写"。
        kept = node.test.values[:-1]
        rebuilt = (kept[0] if len(kept) == 1
                   else ast.BoolOp(op=ast.And(), values=kept))
        text = _replace_segment(
            lines[node.lineno - 1], node.test, ast.unparse(rebuilt))
        mutation = _mutation(
            "weakened-guard", node.lineno, lines, text,
            "Missing condition: the guard dropped a required check",
        )
        if mutation:
            # 少一道检查通常比算错边界更严重。
            out.append(replace(mutation, severity="high"))

    # ⑤ return 置反。
    #
    # 关键是**不能一律加 `not (...)`**：`return False` 变成
    # `return not (False)` 是真实代码里不会出现的写法。审查 agent 可以
    # 单靠"这行看起来很怪"就报出来，不需要理解逻辑——样本因为错误的理由
    # 变简单了，测出来的是"识别怪异写法"而不是"判断返回值对不对"。
    # 这类"视觉线索"是变异测试基准的常见效度陷阱。
    #
    # 所以按形态分三种，每种都产出真实代码里会出现的写法：
    #   return True   → return False   （直接翻，最常见的真实 bug）
    #   return not x  → return x       （漏写 not，也很常见）
    #   其他          → return not (x)
    for node in finder.returns:
        if not _single_line(node) or not _single_line(node.value):
            continue
        value = node.value
        if isinstance(value, ast.Constant) and isinstance(value.value, bool):
            replacement = "False" if value.value else "True"
        elif isinstance(value, ast.UnaryOp) and isinstance(value.op, ast.Not):
            replacement = ast.unparse(value.operand)
        else:
            replacement = "not (%s)" % ast.unparse(value)
        text = _replace_segment(lines[node.lineno - 1], value, replacement)
        mutation = _mutation(
            "negated-return", node.lineno, lines, text,
            "Inverted return value",
        )
        if mutation:
            out.append(mutation)

    return out


### 等价变异体：差分执行 ###
#
# 变异测试的核心效度威胁：有些变异不改变语义（等价变异体），这类样本的
# 标签是**假的**——agent 报"这里有缺陷"其实是错的，却被算成命中。
# 一般情况下判定等价性不可判定，所以这里只做能做的那部分：
#   跑得动 → 输出不同 → **证明**非等价（强证据，equivalence_checked=True）
#   跑得动 → 输出全同 → 仍标 False，报告成"未证明"
#   跑不动 → 标 False
# "未证明"≠"等价"。这和 None ≠ 0.0 是同一条口径纪律：
# 没测出来就不要假装测出了结论。

# 静态纯净筛查：函数体里出现这些名字就不跑差分执行。
# 这是**启发式**，不是可靠的纯函数判定——反射、间接调用都绕得过去。
# 它的目的只是别在评测过程里误伤磁盘和网络，不是给出安全保证。
IMPURE_NAMES = frozenset({
    "open", "exec", "eval", "compile", "input", "print", "__import__",
    "os", "sys", "io", "shutil", "subprocess", "socket", "urllib",
    "requests", "pathlib", "tempfile", "random", "time", "datetime",
})

# 无标注参数的探测值网格。刻意包含边界值：0/1/-1 和空串空表——
# 边界比较类变异只在边界附近才会露出差异，全喂 42 会测不出任何东西。
PROBE_VALUES: Tuple[Any, ...] = (0, 1, 2, -1, 4096, "", "a", True, False, None)
MAX_PROBE_CALLS = 200


def _is_probably_pure(func: ast.FunctionDef) -> bool:
    for node in ast.walk(func):
        if isinstance(node, ast.Name) and node.id in IMPURE_NAMES:
            return False
        if isinstance(node, ast.Attribute):
            root = node
            while isinstance(root, ast.Attribute):
                root = root.value
            if isinstance(root, ast.Name) and root.id in IMPURE_NAMES:
                return False
        if isinstance(node, (ast.Global, ast.Nonlocal, ast.Await,
                             ast.Import, ast.ImportFrom)):
            return False
    return True


def _enclosing_function(tree: ast.AST, line: int) -> Optional[ast.FunctionDef]:
    """找包住这一行的最内层函数；嵌套函数与方法都不要。

    只认模块顶层的普通函数：方法要先造 self，嵌套函数拿不到外层闭包，
    两者都会把"跑不动"误报成"输出相同"。
    """
    for node in tree.body:
        if (isinstance(node, ast.FunctionDef) and node.lineno <= line
                and (node.end_lineno or node.lineno) >= line
                and not node.decorator_list):
            return node
    return None


def _call_outcome(func, arguments) -> Any:
    """调用结果的可比较表示。异常也算一种输出。

    异常必须参与比较：`if n > 0` 改成 `if n >= 0` 常常表现为
    一边正常返回、一边 ZeroDivisionError。只比返回值会漏掉这类差异。
    """
    try:
        return ("value", repr(func(*arguments)))
    except Exception as error:      # noqa: BLE001 - 异常类型本身就是输出
        return ("error", type(error).__name__)


def _probe_values(func: ast.FunctionDef) -> Tuple[Any, ...]:
    """固定网格 + 从函数体里采到的常量及其邻居。

    为什么要采常量：边界类变异只在边界附近露出差异。`if n > 100` 改成
    `n > 101`，只有 n == 101 时行为才不同，而固定网格里不可能预置 101。
    实测确认过这一点——加这一步之前该样本报"未证明"。
    邻居 ±1 是必需的：常量本身往往两边同值（`>` 与 `>=` 在 n == 100
    上都返回 100），差异出现在紧邻的那一格。
    """
    harvested: List[int] = []
    for node in ast.walk(func):
        if (isinstance(node, ast.Constant) and isinstance(node.value, int)
                and not isinstance(node.value, bool)):
            harvested.extend((node.value - 1, node.value, node.value + 1))
    ordered: List[Any] = list(PROBE_VALUES)
    for value in harvested:
        if value not in ordered:        # 去重且保持确定顺序
            ordered.append(value)
    return tuple(ordered)


def _probe_arguments(func: ast.FunctionDef) -> List[Tuple[Any, ...]]:
    args = func.args
    if args.vararg or args.kwarg or args.kwonlyargs or len(args.args) > 2:
        # 参数一多，网格是指数增长。
        return []
    values = _probe_values(func)
    count = len(args.args)
    if count == 0:
        return [()]
    if count == 1:
        return [(value,) for value in values]
    # 两参数用笛卡尔积会超 MAX_PROBE_CALLS（上面 return [] 掉）。
    # 改成对角 + 少量错位组合：覆盖度不如全积，但能进预算。
    pairs = [(value, value) for value in values]
    pairs += [(values[i], values[(i + 1) % len(values)])
              for i in range(len(values))]
    return pairs


def _function_source(source: str, func: ast.FunctionDef) -> str:
    """切出单个顶层函数的源码。只对顶层函数成立（缩进为 0，无需 dedent）。"""
    lines = source.splitlines()
    return "\n".join(lines[func.lineno - 1:(func.end_lineno or func.lineno)])


def _compile_function(
    function_source: str, name: str, namespace: Dict[str, Any], tag: str,
):
    scope = dict(namespace)
    try:
        exec(compile(function_source, tag, "exec"), scope)
    except Exception:               # noqa: BLE001 - 编不过就放弃这个样本
        return None
    candidate = scope.get(name)
    return candidate if callable(candidate) else None


def check_equivalence(
    source: str, mutation: Mutation,
    module_globals: Optional[Dict[str, Any]] = None,
) -> Mutation:
    """尝试用差分执行**证明**这个变异非等价。

    只在"变异落在一个顶层、无装饰器、静态看起来纯的函数里，且参数不超过
    两个"时才跑。条件苛刻是故意的：跑不动就诚实标未证明，比编造一个
    equivalence_checked=True 要好。

    只 exec **这一个函数**，不 exec 整个模块。两个理由，实测都验证过：
      1. 整模块 exec 会在裸命名空间里跑 `from .models import ...`，
         直接 ImportError——本仓库 167 个可达点位里 147 个死在这里。
      2. 整模块 exec 会把模块顶层代码再跑一遍（一次原始一次变异），
         等于为了测一个函数触发两轮副作用。
    module_globals 由调用方给（通常是真实导入后的 module.__dict__），
    函数里引用的模块级名字从那里解析。
    """
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return mutation
    func = _enclosing_function(tree, mutation.line)
    if func is None or not _is_probably_pure(func):
        return mutation
    probes = _probe_arguments(func)
    if not probes or len(probes) > MAX_PROBE_CALLS:
        return mutation

    namespace = module_globals or {}
    mutated_source = apply_mutation(source, mutation)
    # 两侧都用同一条路径编译（切函数 + 同一份 globals），避免因为构造方式
    # 不同引入差异——那种差异会被误读成"变异造成的"。
    before = _compile_function(
        _function_source(source, func), func.name, namespace, "<original>")
    mutated_func = _enclosing_function(ast.parse(mutated_source), mutation.line)
    if mutated_func is None:
        return mutation
    after = _compile_function(
        _function_source(mutated_source, mutated_func), func.name,
        namespace, "<mutated>")
    if before is None or after is None:
        return mutation

    for arguments in probes:
        if _call_outcome(before, arguments) != _call_outcome(after, arguments):
            # 找到一个输入让两者行为不同 → 非等价，标签成立。
            return replace(mutation, equivalence_checked=True,
                           equivalence_status="proven")
    # 全部相同：**不**标 True。可能真等价（假标签），也可能只是探测值没
    # 覆盖到差异点。区分不了，但至少要和"没跑"分开记。
    return replace(mutation, equivalence_status="no-difference")


def apply_mutation(source: str, mutation: Mutation) -> str:
    """把变异应用到源码，返回变异后的完整源码。

    校验原行一致：如果传进来的 source 不是产出这个 Mutation 的那份，
    行号早就错位了，这时候静默改错行比报错糟糕得多。
    """
    lines = source.splitlines()
    index = mutation.line - 1
    if index < 0 or index >= len(lines):
        raise ValueError("mutation line %d out of range" % mutation.line)
    if lines[index] != mutation.original_line:
        raise ValueError(
            "source does not match mutation at line %d" % mutation.line)
    lines[index] = mutation.mutated_line
    return "\n".join(lines) + ("\n" if source.endswith("\n") else "")


CONTEXT_LINES = 3


def synthesize_diff(
    path: str, source: str, mutation: Mutation, context: int = CONTEXT_LINES,
) -> str:
    """把一个变异体渲染成 unified diff。

    方向很重要：**变异后的代码是 `+` 行**。agent 看到的是"这个 PR 引入了
    一处缺陷"，和反转修复 PR 数据集的方向一致——两个 Oracle 产出的输入
    形态必须相同，否则 A/B 对比里混进了"输入形态不同"这个额外变量。
    """
    lines = source.splitlines()
    index = mutation.line - 1
    start = max(0, index - context)
    end = min(len(lines), index + context + 1)
    body = []
    for position in range(start, end):
        if position == index:
            body.append("-" + lines[position])
            body.append("+" + mutation.mutated_line)
        else:
            body.append(" " + lines[position])
    # 旧文件此段行数 = 窗口行数；新文件同样（一删一增，净变化 0）。
    span = end - start
    return "\n".join([
        "diff --git a/%s b/%s" % (path, path),
        "--- a/%s" % path,
        "+++ b/%s" % path,
        "@@ -%d,%d +%d,%d @@" % (start + 1, span, start + 1, span),
    ] + body) + "\n"


def build_mutation_case(
    path: str, source: str, mutation: Mutation, index: int,
    split: str = "holdout", repository: str = "synthetic/mutation",
) -> dict:
    """产出一条能过 validate_case 的评测样本。

    split 默认 holdout：变异样本**不参与**任何调优。它的用途是给
    validation 上调出来的配置做一次独立检验，一旦进了 validation
    就会被间接拟合，"第二 Oracle"的独立性也就没了。
    """
    diff = synthesize_diff(path, source, mutation)
    parsed = parse_unified_diff(diff)
    added = [item for item in parsed.added_lines
             if item.content.strip() == mutation.mutated_line.strip()]
    if not added:
        raise ValueError("mutated line did not survive diff synthesis")
    line_number = added[0].line
    return {
        "id": "mutation-%s-%04d" % (mutation.operator, index),
        "repository": repository,
        "pull_request": 0,
        "split": split,
        "diff": diff,
        "expected_findings": [{
            "path": path,
            # 单行范围。变异只改一行，范围放宽会稀释命中判定。
            "start_line": line_number,
            "end_line": line_number,
            "cwe": mutation.cwe,
            "severity": mutation.severity,
            "should_comment": True,
            "defect_class": mutation.defect_class,
        }],
        # 下面这些字段不参与评分，只为可追溯：出了争议要能回到源头核对。
        "oracle": "mutation",
        "mutation_operator": mutation.operator,
        "mutation_description": mutation.description,
        "equivalence_checked": mutation.equivalence_checked,
        "equivalence_status": mutation.equivalence_status,
        "original_line": mutation.original_line,
    }


OPERATORS = (
    "comparison-boundary", "boolean-operator", "constant-offset",
    "weakened-guard", "negated-return",
)


def _module_globals(path: str) -> Dict[str, Any]:
    """导入这个文件对应的模块，取它的 globals 供差分执行解析名字。

    用正常 import，不是 exec：模块该有的包上下文、相对导入、依赖都由
    import 机制处理。失败就返回空字典——差分执行随后会因为编不过而
    诚实地标"未证明"。
    """
    if not path.endswith(".py"):
        return {}
    module_name = path[:-3].replace("\\", "/").strip("/").replace("/", ".")
    try:
        import importlib
        return vars(importlib.import_module(module_name))
    except Exception:               # noqa: BLE001 - 导不进来就放弃
        return {}


def build_mutation_dataset(
    sources: Sequence[Tuple[str, str]], per_operator: int = 12,
    split: str = "holdout", check: bool = True,
) -> List[dict]:
    """从 (路径, 源码) 列表产出变异评测集。

    **按算子配额轮转取样**，不是一路取满。理由：各算子可用点位数量差
    一个数量级（实测 constant-offset 与 negated-return 远多于
    weakened-guard）。不配额的话总体召回率其实主要在测一个算子，
    分算子看才有意义——这和数据集按难度分层是同一个道理。

    取样在每个算子内按 (路径, 行号) 排序后**等距抽**，不是取前 N 条：
    取前 N 会全挤在文件开头的几个函数里。
    """
    by_operator: Dict[str, List[Tuple[str, str, Mutation]]] = {
        name: [] for name in OPERATORS
    }
    for path, source in sources:
        try:
            mutations = generate_mutations(source)
        except SyntaxError:
            continue
        for mutation in mutations:
            by_operator.setdefault(mutation.operator, []).append(
                (path, source, mutation))

    picked: List[Tuple[str, str, Mutation]] = []
    for name in OPERATORS:
        pool = sorted(by_operator.get(name, []),
                      key=lambda item: (item[0], item[2].line))
        if not pool:
            continue
        if len(pool) <= per_operator:
            picked.extend(pool)
            continue
        step = len(pool) / float(per_operator)
        picked.extend(pool[int(index * step)] for index in range(per_operator))

    cases: List[dict] = []
    globals_cache: Dict[str, Dict[str, Any]] = {}
    for index, (path, source, mutation) in enumerate(picked):
        if check:
            if path not in globals_cache:
                globals_cache[path] = _module_globals(path)
            mutation = check_equivalence(source, mutation, globals_cache[path])
        try:
            cases.append(
                build_mutation_case(path, source, mutation, index, split=split))
        except ValueError:
            # 合成不出合法样本就丢掉，不要放宽 validate_case 去迁就它。
            continue
    return cases


def equivalence_summary(cases: Sequence[dict]) -> Dict[str, Any]:
    """等价性证明情况汇总。**分开报**，不合成一个数。

    "未证明"里混着真等价体和探测覆盖不到的点，两者比例不知道。
    把它折进召回率会让指标带上一个方向未知的偏差；单独列出来，
    读数的人至少知道有多少样本的标签没被证实。
    """
    status: Dict[str, int] = {
        "proven": 0, "no-difference": 0, "not-attempted": 0,
    }
    by_operator: Dict[str, Dict[str, int]] = {}
    for case in cases:
        key = str(case.get("equivalence_status", "not-attempted"))
        status[key] = status.get(key, 0) + 1
        bucket = by_operator.setdefault(
            case.get("mutation_operator", "?"),
            {"total": 0, "proven": 0, "no-difference": 0},
        )
        bucket["total"] += 1
        if key in bucket:
            bucket[key] += 1
    return {
        "total": len(cases),
        "by_status": status,
        # 最该盯的一个数：跑了差分执行、却没测出任何行为差异的样本占比。
        # 假标签集中在这里。它高就说明这批样本的标签可信度存疑，
        # 而不是说明 agent 表现好或差。
        "suspect_rate": (
            ratio_or_none(status["no-difference"],
                          status["no-difference"] + status["proven"])
        ),
        "by_operator": by_operator,
    }


def ratio_or_none(numerator: int, denominator: int) -> Optional[float]:
    """分母为 0 返回 None，不返回 0.0。

    这里分母为 0 的含义是"一个样本都没跑过差分执行"，那是**没有结论**；
    返回 0.0 会被读成"跑了，没有可疑样本"，是个相反的结论。
    """
    if denominator <= 0:
        return None
    return round(numerator / float(denominator), 4)


def _swap_operator_in_line(
    line: str, was: str, now: str, word: bool = False,
) -> Optional[str]:
    """在一行里替换算子，**仅当它恰好出现一次**。

    出现多次就放弃这个样本：改哪一个都说不清，而说不清的样本会污染标注。
    """
    needle = " %s " % was if word else was
    if line.count(needle) != 1:
        return None
    return line.replace(needle, " %s " % now if word else now)

