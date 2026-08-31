"""Compilation and test gates for generated repairs."""
import os
import shlex
import subprocess
import tempfile
import time
import zipfile
import io
import tokenize
from io import BytesIO
from typing import Dict, Iterable

from .outcome_parser import FAILED, PASSED, parse_test_outcomes


class RepairVerifier:
    def __init__(self, test_command: str = "", timeout_seconds: int = 120):
        self.test_command = test_command
        self.timeout_seconds = timeout_seconds

    def verify_contents(self, files: Dict[str, str]) -> dict:
        started = time.monotonic()
        checks = []
        for path, content in files.items():
            if path.endswith(".py"):
                try:
                    compile(content, path, "exec")
                    checks.append({"name": "compile:%s" % path, "passed": True})
                    list(tokenize.generate_tokens(io.StringIO(content).readline))
                    checks.append({"name": "cst-tokenize:%s" % path, "passed": True})
                except SyntaxError as exc:
                    checks.append({
                        "name": "compile:%s" % path, "passed": False,
                        "detail": "%s:%s: %s" % (path, exc.lineno, exc.msg),
                    })
                except (tokenize.TokenError, IndentationError) as exc:
                    checks.append({
                        "name": "cst-tokenize:%s" % path, "passed": False,
                        "detail": str(exc)[:1000],
                    })
        return {
            "passed": all(item["passed"] for item in checks),
            "checks": checks,
            "duration_seconds": round(time.monotonic() - started, 4),
        }

    def verify_worktree(self, root: str) -> dict:
        if not self.test_command:
            # checks 为空 → compare 的 test_evidence_present 为 False → 永不判通过。
            # 这与 patching.py 在无 test_command 时提前返回 suggestion-only 一致：
            # 没有测试就没有行为证据，"修好了"这句话没有出处。
            return {
                "passed": True, "checks": [], "test_outcomes": {},
                "evidence_level": "none",
                "note": "No repository test command configured.",
            }
        root = os.path.abspath(root)
        if not os.path.isdir(root):
            raise ValueError("verification worktree does not exist")
        command = shlex.split(self.test_command, posix=os.name != "nt")
        started = time.monotonic()
        env = {
            key: value for key, value in os.environ.items()
            if key in {"PATH", "SYSTEMROOT", "WINDIR", "LANG", "LC_ALL", "TMP", "TEMP"}
        }
        with tempfile.TemporaryDirectory(prefix="evoagent-verify-") as temp:
            env["TMPDIR"] = temp
            try:
                result = subprocess.run(
                    command, cwd=root, env=env, text=True, capture_output=True,
                    timeout=self.timeout_seconds, check=False,
                )
                passed = result.returncode == 0
                detail = (result.stdout + "\n" + result.stderr)[-8000:]
            except subprocess.TimeoutExpired as exc:
                passed = False
                detail = "verification exceeded %d seconds" % self.timeout_seconds
        # per-test 结果让 compare 能做逐测试对照（"原本失败的现在通过了"
        # 与"原本通过的现在失败了"是两件完全不同的事，聚合布尔区分不了）。
        # 解析不出来时 outcomes 为空，compare 会降级到 aggregate-only 并
        # 在结果里标出证据等级，而不是假装有逐测试证据。
        outcomes = parse_test_outcomes(detail)
        return {
            "passed": passed,
            "checks": [{"name": "repository-tests", "passed": passed, "detail": detail}],
            "test_outcomes": outcomes,
            "evidence_level": "per-test" if outcomes else "aggregate-only",
            "duration_seconds": round(time.monotonic() - started, 4),
        }

    def verify_archive(self, archive: bytes, files: Dict[str, str]) -> dict:
        """Verify changed files inside an isolated copy of the complete repository."""
        with tempfile.TemporaryDirectory(prefix="evoagent-repair-") as root:
            with zipfile.ZipFile(BytesIO(archive)) as bundle:
                for member in bundle.infolist():
                    normalized = os.path.normpath(member.filename).replace("\\", "/")
                    if normalized.startswith("../") or normalized.startswith("/"):
                        raise ValueError("repository archive contains an unsafe path")
                    target = os.path.abspath(os.path.join(root, normalized))
                    if not target.startswith(os.path.abspath(root) + os.sep):
                        raise ValueError("repository archive escapes the sandbox")
                    bundle.extract(member, root)
            entries = [item for item in os.scandir(root) if item.is_dir()]
            worktree = entries[0].path if len(entries) == 1 else root
            for path, content in files.items():
                target = os.path.abspath(os.path.join(worktree, path))
                if not target.startswith(os.path.abspath(worktree) + os.sep):
                    raise ValueError("repair path escapes the repository")
                os.makedirs(os.path.dirname(target), exist_ok=True)
                with open(target, "w", encoding="utf-8", newline="") as handle:
                    handle.write(content)
            compile_result = self.verify_contents(files)
            if not compile_result["passed"]:
                return compile_result
            test_result = self.verify_worktree(worktree)
            checks = compile_result["checks"] + test_result["checks"]
            return {
                "passed": compile_result["passed"] and test_result["passed"],
                "checks": checks,
                # 透传 per-test 结果，否则 compare 在 verify_archive 路径上
                # 永远只能拿到聚合布尔——而 patching.py 走的正是这条路径。
                "test_outcomes": test_result.get("test_outcomes", {}),
                "evidence_level": test_result.get("evidence_level", "aggregate-only"),
                "duration_seconds": round(
                    compile_result.get("duration_seconds", 0)
                    + test_result.get("duration_seconds", 0), 4
                ),
            }

    @staticmethod
    def compare(before: dict, after: dict) -> dict:
        """Judge a patch by per-test transitions, not by whether the suite is green.

        ## 修掉的语义 bug

        旧实现要求 `before.get("passed")` 为真才可能 `passed`：

            passed = bool(before.get("passed") and after.get("passed") and ...)

        也就是"基线必须已经全绿"。这个前提在修复场景里是反的——**存在缺陷时
        基线本来就该失败**。后果：一个真正修好了 bug 的补丁（基线红 → 补丁后绿）
        被判 `blocked`，而 patching.py:190 直接据此拒绝发布。修复环节的三档
        比例因此全部偏向 blocked，数字是假的。

        旧实现自己就暗示了正确意图：`behavioral_regression_detected` 写的是
        `before.passed and not after.passed`（原本通过、现在失败），方向是对的。
        错的只是 `passed` 的判据。

        ## 新判据：逐测试比较

        四种转移，各自的含义不同：

        | before | after | 含义 | 对结论的作用 |
        |---|---|---|---|
        | failed | passed | 修好了 | **收益**（fixed） |
        | passed | failed | 搞坏了 | **回归 → 一律 block** |
        | failed | failed | 没修好 | 中性（still_failing） |
        | passed | passed | 没碰坏 | 中性 |

        `passed` 的定义：**无回归，且至少修好一个**。

        两个刻意的选择：
        - 回归一票否决，不做"收益多于回归就放行"的权衡。理由：回归是确定的
          伤害，收益是待验证的改进；APR 的核心问题是 patch overfitting
          （测试通过但语义错误），在这个方向上必须保守。
        - "无回归但零收益"判 False。补丁没解决任何问题却改了代码，
          没有理由发布——即使它无害。

        ## 证据等级降级

        拿不到 per-test 结果时（test_command 没带 -v，或输出格式不认识）
        退回聚合布尔：要求 `not before.passed and after.passed`
        （红 → 绿）。这仍然比旧实现正确，但显著更弱：聚合视角下
        "整套仍然失败"无法区分"修好一部分"与"什么也没修好还搞坏另一个"。
        `evidence_level` 字段把这个区别暴露出去，报数时必须按等级分开报。
        """
        before_tests = [
            item for item in before.get("checks", [])
            if item.get("name") == "repository-tests"
        ]
        after_tests = [
            item for item in after.get("checks", [])
            if item.get("name") == "repository-tests"
        ]
        test_evidence_present = bool(before_tests and after_tests)

        before_outcomes = before.get("test_outcomes") or {}
        after_outcomes = after.get("test_outcomes") or {}
        per_test = bool(before_outcomes and after_outcomes)

        fixed, regressed, still_failing = [], [], []
        if per_test:
            for test_id, before_state in sorted(before_outcomes.items()):
                after_state = after_outcomes.get(test_id)
                if after_state is None:
                    # 测试消失：可能是补丁删了它，也可能是收集阶段就崩了。
                    # 两种都不能算收益，当成回归——补丁不该让测试凭空不见。
                    regressed.append(test_id)
                    continue
                if before_state == FAILED and after_state == PASSED:
                    fixed.append(test_id)
                elif before_state == PASSED and after_state == FAILED:
                    regressed.append(test_id)
                elif before_state == FAILED and after_state == FAILED:
                    still_failing.append(test_id)
            # after 里新出现且失败的测试也算回归（补丁引入了会失败的新测试）。
            for test_id, after_state in sorted(after_outcomes.items()):
                if test_id not in before_outcomes and after_state == FAILED:
                    regressed.append(test_id)
            passed = bool(test_evidence_present and fixed and not regressed)
        else:
            passed = bool(
                test_evidence_present
                and not before.get("passed")
                and after.get("passed")
            )

        return {
            "passed": passed,
            "baseline_passed": bool(before.get("passed")),
            "patched_passed": bool(after.get("passed")),
            "test_evidence_present": test_evidence_present,
            "evidence_level": "per-test" if per_test else "aggregate-only",
            "fixed_tests": sorted(set(fixed)),
            "regressed_tests": sorted(set(regressed)),
            "still_failing_tests": sorted(set(still_failing)),
            # 保留旧字段名与聚合语义：外部报告已在读它，改名等于无声破坏。
            "behavioral_regression_detected": bool(regressed) if per_test else bool(
                before.get("passed") and not after.get("passed")
            ),
        }
