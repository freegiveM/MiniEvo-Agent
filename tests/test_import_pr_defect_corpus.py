#!/usr/bin/env python3
"""`scripts/import_pr_defect_corpus.py` 的导入契约。

这个 loader 补的是第 17 节留下的缺口：误报侧有了分母之后，holdout 里只剩
1 条缺陷样本，`recall` 只有一个步长（要么 0.0 要么 1.0），而
`holdout_non_regression` 是参与 `decision` 的四道门之一。**一道分母为 1 的
门禁和一道分母为 0 的门禁一样，都是在假装工作。**

所以这里除了钉住幂等和拒收口径，还要钉住**报告必须给出各个分母**——包括
`high_severity_denominator`，那是这批语料**填不满**的一项（语料全是
medium），必须让它在报告上可见而不是被总数掩盖。
"""

from __future__ import annotations

import importlib.util
import io
import json
import shutil
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from evoagent.store import TaskStore

ROOT = Path(__file__).resolve().parents[1]


def load_module():
    """按路径加载脚本：scripts/ 不是包，正常 import 进不来。"""

    path = ROOT / "scripts" / "import_pr_defect_corpus.py"
    spec = importlib.util.spec_from_file_location("import_pr_defect_corpus", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


DIFF = """diff --git a/mod_%(i)d.py b/mod_%(i)d.py
index 1111111..2222222 100644
--- a/mod_%(i)d.py
+++ b/mod_%(i)d.py
@@ -1,2 +1,3 @@
 import os
+value_%(i)d = os.environ["TOKEN_%(i)d"]
 print(os.name)
"""


class ImportPrDefectCorpusTests(unittest.TestCase):
    def setUp(self) -> None:
        self.module = load_module()
        self.tmp = Path(tempfile.mkdtemp())
        self.db = self.tmp / "evo.db"
        TaskStore(str(self.db))

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _corpus(self, cases: list) -> Path:
        path = self.tmp / "corpus.jsonl"
        with path.open("w", encoding="utf-8") as handle:
            for case in cases:
                handle.write(json.dumps(case, ensure_ascii=False) + "\n")
        return path

    def _case(self, index: int, severity: str = "medium", **overrides) -> dict:
        case = {
            "id": "repo__pr-%d" % index,
            "split": "holdout",
            "diff": DIFF % {"i": index},
            "expected_findings": [
                {
                    "path": "mod_%d.py" % index,
                    "start_line": 2,
                    "end_line": 2,
                    "cwe": "CWE-798",
                    "severity": severity,
                }
            ],
        }
        case.update(overrides)
        return case

    def _run(self, corpus: Path, *extra) -> dict:
        argv = [
            "import_pr_defect_corpus.py",
            "--db", str(self.db),
            "--corpus", str(corpus),
            *extra,
        ]
        buffer = io.StringIO()
        original = sys.argv
        sys.argv = argv
        try:
            with redirect_stdout(buffer):
                self.assertEqual(0, self.module.main())
        finally:
            sys.argv = original
        return json.loads(buffer.getvalue())

    def test_defect_cases_are_imported_with_their_expected_findings(self) -> None:
        stats = self._run(self._corpus([self._case(1), self._case(2)]))
        self.assertEqual(2, stats["inserted"])
        store = TaskStore(str(self.db))
        cases = store.list_evaluation_cases("holdout", True, 50)
        self.assertEqual(2, len(cases))
        self.assertTrue(all(case["expected"] for case in cases))

    def test_the_end_line_is_carried_over(self) -> None:
        """`RegressionEvaluator` 按 [line, end_line] 区间配对。

        只导 start_line 会把"报在缺陷区间中段"误判成漏报，于是 recall 带上
        一个与 reviewer 能力无关的上限——分母有了，分子被系统性压低。
        """

        case = self._case(3)
        case["expected_findings"][0]["end_line"] = 2
        self._run(self._corpus([case]))
        store = TaskStore(str(self.db))
        expected = store.list_evaluation_cases("holdout", True, 5)[0]["expected"][0]
        self.assertEqual(2, expected["line"])
        self.assertEqual(2, expected["end_line"])

    def test_severity_becomes_min_severity(self) -> None:
        self._run(self._corpus([self._case(4, severity="high")]))
        store = TaskStore(str(self.db))
        expected = store.list_evaluation_cases("holdout", True, 5)[0]["expected"][0]
        self.assertEqual("high", expected["min_severity"])

    def test_a_rerun_reports_zero_inserted(self) -> None:
        """幂等要体现在**报告**上，不只是表里没有重复行。

        `save_evaluation_case` 对同名同内容的行直接返回已有行，所以只看它
        的返回值分不出"新插入"和"早就有了"。
        """

        corpus = self._corpus([self._case(index) for index in range(1, 6)])
        first = self._run(corpus)
        second = self._run(corpus)
        self.assertEqual(5, first["inserted"])
        self.assertEqual(0, second["inserted"])
        self.assertEqual(5, second["skipped_duplicate"])
        store = TaskStore(str(self.db))
        self.assertEqual(5, len(store.list_evaluation_cases("holdout", True, 50)))

    def test_only_the_target_split_is_imported(self) -> None:
        """默认只导 holdout。

        `real-pr-v1` 的 validation 与 holdout 切自同一批采集，把 validation
        也灌进来不增加独立信号，只会抬高两侧的相关性——而 holdout 的全部
        意义就是独立。
        """

        stats = self._run(
            self._corpus([self._case(6), self._case(7, split="validation")])
        )
        self.assertEqual(1, stats["inserted"])
        self.assertEqual(1, stats["skipped_other_split"])
        store = TaskStore(str(self.db))
        self.assertEqual(0, len(store.list_evaluation_cases("validation", True, 50)))

    def test_clean_cases_are_refused(self) -> None:
        """没有 expected_findings 的样本要走 import_clean_corpus.py。

        两条路的标签语义完全不同——"缺陷缺席"是代理信号，不是已验证正确。
        混在一个脚本里会让来源分不清。
        """

        stats = self._run(
            self._corpus([self._case(8), self._case(9, expected_findings=[])])
        )
        self.assertEqual(1, stats["inserted"])
        self.assertEqual(1, stats["skipped_not_defect"])

    def test_findings_off_the_added_lines_are_refused(self) -> None:
        """期望位置必须落在新增行上。

        否则这条样本永远算漏报，recall 被压到一个与 reviewer 无关的上限
        ——分母有了，分子永远算不出来。
        """

        bad = self._case(10)
        bad["expected_findings"][0]["start_line"] = 999
        bad["expected_findings"][0]["end_line"] = 999
        stats = self._run(self._corpus([bad, self._case(11)]))
        self.assertEqual(1, stats["inserted"])
        self.assertEqual(1, stats["skipped_unscoreable_diff"])
        self.assertTrue(stats["rejected"][0]["reason"])

    def test_dry_run_writes_nothing(self) -> None:
        corpus = self._corpus([self._case(index) for index in range(1, 4)])
        stats = self._run(corpus, "--dry-run")
        self.assertEqual(3, stats["inserted"])
        self.assertTrue(stats["dry_run"])
        store = TaskStore(str(self.db))
        self.assertEqual(0, len(store.list_evaluation_cases("holdout", True, 50)))

    def test_the_report_separates_the_defect_and_clean_denominators(self) -> None:
        """两个分母要分开报。

        只报总条数看不出问题：holdout 补进缺陷样本之前是 17 条，读起来
        像个正常规模的评测集，实际其中只有 1 条缺陷。
        """

        stats = self._run(self._corpus([self._case(i) for i in range(1, 7)]))
        holdout = stats["selected"]["holdout@20"]
        self.assertEqual(6, holdout["defect_denominator"])
        self.assertEqual(0, holdout["clean_denominator"])

    def test_the_high_severity_denominator_is_reported_separately(self) -> None:
        """`high_severity_recall` 的分母必须单独可见。

        这是**这批语料填不满**的一项：`real-pr-v1` 的 holdout 全是 medium
        （实测 40 条期望、0 条 high/critical）。总分母涨到 25 之后，
        `high_severity_recall` 的分母仍然是 1，而它是参与 decision 的四道
        受保护指标之一。不单独报，这个缺口就被总数掩盖了。
        """

        stats = self._run(
            self._corpus([self._case(i, severity="medium") for i in range(1, 5)])
        )
        holdout = stats["selected"]["holdout@20"]
        self.assertEqual(4, holdout["defect_denominator"])
        self.assertEqual(0, holdout["high_severity_denominator"])

        # 有 high 样本时该数才涨——钉住它数的是 high/critical，不是全部缺陷。
        stats = self._run(self._corpus([self._case(9, severity="critical")]))
        self.assertEqual(
            1, stats["selected"]["holdout@20"]["high_severity_denominator"]
        )


if __name__ == "__main__":
    unittest.main()