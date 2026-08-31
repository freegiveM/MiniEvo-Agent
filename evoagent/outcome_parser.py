"""Extract per-test outcomes from test-runner stdout.

为什么需要这个模块：verifier.compare 要做逐测试的 before/after 对照，
但 verify_worktree 原先只返回一个聚合布尔（returncode == 0）。聚合布尔
不足以区分"修好了一个原本失败的测试"和"把一个原本通过的测试搞坏了"
——而这个区别正是修复环节评测的全部内容。

## 方案对比

A. junit-xml（`--junit-xml=<path>`）—— 结构化、最可靠。
   否决：要求我们改写用户配置的 test_command。命令可能根本不是 pytest
   （`make test` / `tox` / `nox` / 自定义脚本），往里塞 pytest 专属参数会直接跑挂。

B. 用 pytest 插件 API 进程内收集 —— 最精确。
   否决：要求被测仓库的测试必须由 pytest 驱动，且要在同进程 import 它，
   与"隔离工作副本里跑子进程"的现有隔离模型冲突。

C. 解析 stdout（采纳）—— 不碰用户命令，认识几种主流格式，
   认不出来就退回聚合结果并**显式标注证据等级**。
   代价：依赖输出格式，且需要命令带 `-v`（pytest/unittest 默认不打印单条结果）。
   这个代价是可接受的，因为退化路径是明确的"证据不足"而不是错误结论。

D 也考虑过：跑两遍、第二遍只跑失败的测试。否决：成本翻倍，且拿不到
   "原本通过的现在失败了"这一侧——那恰恰是回归检测最重要的一侧。

## 证据等级

解析成功 → `per-test`：可做逐测试对照。
解析失败 → `aggregate-only`：只能比整套的红/绿。compare 在这个等级下
更保守（见 compare 的文档），因为"整套仍然失败"在聚合视角下无法区分
"修好了一部分"和"什么也没修好还搞坏了另一个"。

要拿到 per-test 证据，test_command 需带 -v：
    pytest -v --tb=no -p no:randomly
    python -m unittest -v
"""
import re
from typing import Dict


PASSED = "passed"
FAILED = "failed"
SKIPPED = "skipped"

# pytest -v: "tests/test_a.py::test_one PASSED   [ 33%]"
# 也匹配参数化 id（含方括号）与类内测试（多个 ::）。
_PYTEST_VERBOSE = re.compile(
    r"^(?P<id>[\w./\\-]+\.py(?:::[^\s:]+)+)\s+"
    r"(?P<outcome>PASSED|FAILED|ERROR|SKIPPED|XFAIL|XPASS)\b"
)

# pytest short summary (-ra): "FAILED tests/test_a.py::test_two - AssertionError"
_PYTEST_SUMMARY = re.compile(
    r"^(?P<outcome>PASSED|FAILED|ERROR|SKIPPED|XFAIL|XPASS)\s+"
    r"(?P<id>[\w./\\-]+\.py(?:::[^\s:]+)+)"
)

# unittest -v: "test_one (tests.test_a.TestA) ... ok"
# Python 3.11+ 会写成 "test_one (tests.test_a.TestA.test_one) ... ok"
_UNITTEST_VERBOSE = re.compile(
    r"^(?P<name>\w+)\s+\((?P<dotted>[\w.]+)\)"
    r"(?:\s+\[[^\]]*\])?\s+\.\.\.\s+"
    r"(?P<outcome>ok|OK|FAIL|ERROR|skipped|expected failure|unexpected success)\b"
)

# XFAIL/XPASS 归类的取舍：
# xfail（预期失败且确实失败）算 skipped——它是"已知问题",不是本次回归。
# xpass（预期失败但通过了）也算 skipped 而不是 passed：它常常意味着
# 测试标记过期，把它当 passed 会让 fail→pass 的收益统计混入噪声。
_PYTEST_OUTCOMES = {
    "PASSED": PASSED,
    "FAILED": FAILED,
    "ERROR": FAILED,
    "SKIPPED": SKIPPED,
    "XFAIL": SKIPPED,
    "XPASS": SKIPPED,
}
_UNITTEST_OUTCOMES = {
    "ok": PASSED,
    "OK": PASSED,
    "FAIL": FAILED,
    "ERROR": FAILED,
    "skipped": SKIPPED,
    "expected failure": SKIPPED,
    "unexpected success": SKIPPED,
}


def parse_test_outcomes(output: str) -> Dict[str, str]:
    """Map test id -> passed/failed/skipped. Empty dict when nothing is parseable.

    冲突解决：同一个 id 出现多次时（例如 pytest 既打 verbose 行又打
    short summary），**失败优先**。理由：short summary 只列失败项，
    若让后出现的行覆盖先出现的，顺序就会决定结论——那是不可复现的。
    """
    outcomes: Dict[str, str] = {}

    def record(test_id: str, outcome: str) -> None:
        previous = outcomes.get(test_id)
        if previous == FAILED:
            return
        if previous == PASSED and outcome == SKIPPED:
            return
        outcomes[test_id] = outcome

    for raw in (output or "").splitlines():
        line = raw.strip()
        if not line:
            continue
        match = _PYTEST_VERBOSE.match(line) or _PYTEST_SUMMARY.match(line)
        if match:
            record(
                _normalise_pytest_id(match.group("id")),
                _PYTEST_OUTCOMES[match.group("outcome")],
            )
            continue
        match = _UNITTEST_VERBOSE.match(line)
        if match:
            record(
                _normalise_unittest_id(match.group("dotted"), match.group("name")),
                _UNITTEST_OUTCOMES[match.group("outcome")],
            )
    return outcomes


def _normalise_pytest_id(test_id: str) -> str:
    return test_id.replace("\\", "/")


def _normalise_unittest_id(dotted: str, name: str) -> str:
    """Make 3.10 and 3.11+ unittest ids comparable.

    3.10: "test_one (tests.test_a.TestA)"        -> tests.test_a.TestA.test_one
    3.11: "test_one (tests.test_a.TestA.test_one)" -> tests.test_a.TestA.test_one

    不归一化的后果很隐蔽：before/after 若在不同 Python 版本下产生
    （例如缓存的基线结果），id 对不上会让所有测试都显示为
    "消失 + 新增"，从而误报大量回归。
    """
    if dotted.endswith("." + name):
        return dotted
    return "%s.%s" % (dotted, name)
