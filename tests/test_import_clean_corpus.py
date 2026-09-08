#!/usr/bin/env python3
"""`scripts/import_clean_corpus.py` 的导入契约。

这个 loader 只做一件事：把干净语料塞进 `evaluation_cases`，让误报侧的
`clean_accuracy` 有分母。它必须幂等、必须只收干净样本、而且**报告要诚实**
——一个在无事发生时仍报告 78 次插入的 loader，比一个报错的 loader 更难
发现问题。
"""

from __future__ import annotations

import importlib.util
import io
import json
import os
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

    path = ROOT / "scripts" / "import_clean_corpus.py"
    spec = importlib.util.spec_from_file_location("import_clean_corpus", path)
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


class ImportCleanCorpusTests(unittest.TestCase):
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

    def _case(self, index: int, **overrides) -> dict:
        case = {
            "id": "repo__pr-%d-clean" % index,
            "split": "validation",
            "diff": DIFF % {"i": index},
            "expected_findings": [],
        }
        case.update(overrides)
        return case

    def _run(self, corpus: Path, *extra) -> dict:
        argv = [
            "import_clean_corpus.py",
            "--db",
            str(self.db),
            "--corpus",
            str(corpus),
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

    def test_clean_cases_are_imported_with_an_empty_expected_list(self) -> None:
        stats = self._run(self._corpus([self._case(1), self._case(2)]))
        self.assertEqual(2, stats["inserted"])
        store = TaskStore(str(self.db))
        cases = store.list_evaluation_cases("validation", True, 50)
        self.assertEqual(2, len(cases))
        self.assertTrue(all(case["expected"] == [] for case in cases))

    def test_a_rerun_reports_zero_inserted_not_seventy_eight(self) -> None:
        """幂等要体现在**报告**上，不只是表里没有重复行。

        `save_evaluation_case` 对同名同内容的行直接返回已有行，所以只看它的
        返回值分不出"新插入"和"早就有了"——重跑会照样报 inserted=78。
        """

        corpus = self._corpus([self._case(index) for index in range(1, 6)])
        first = self._run(corpus)
        second = self._run(corpus)
        self.assertEqual(5, first["inserted"])
        self.assertEqual(0, second["inserted"])
        self.assertEqual(5, second["skipped_duplicate"])
        store = TaskStore(str(self.db))
        self.assertEqual(5, len(store.list_evaluation_cases("validation", True, 50)))

    def test_cases_with_findings_are_refused(self) -> None:
        """带 expected_findings 的样本必须走有人工确认闸门的那条路。

        从这里绕进来就等于让未确认的标签直接进评测集。
        """

        defective = self._case(
            9,
            expected_findings=[
                {
                    "path": "mod_9.py",
                    "start_line": 2,
                    "end_line": 2,
                    "cwe": "CWE-798",
                    "severity": "high",
                }
            ],
        )
        stats = self._run(self._corpus([defective, self._case(10)]))
        self.assertEqual(1, stats["inserted"])
        self.assertEqual(1, stats["skipped_not_clean"])

    def test_unscoreable_diffs_are_refused_with_a_reason(self) -> None:
        """取样能取到、评测跑不了的行不能进：分母有了，分子永远算不出来。"""

        stats = self._run(
            self._corpus([self._case(11, diff="not a diff at all"), self._case(12)])
        )
        self.assertEqual(1, stats["inserted"])
        self.assertEqual(1, stats["skipped_unscoreable_diff"])
        self.assertEqual(1, len(stats["rejected"]))
        self.assertTrue(stats["rejected"][0]["reason"])

    def test_unknown_splits_are_refused(self) -> None:
        stats = self._run(
            self._corpus([self._case(13, split="train"), self._case(14, split="nope")])
        )
        self.assertEqual(0, stats["inserted"])
        self.assertEqual(2, stats["skipped_bad_split"])

    def test_dry_run_writes_nothing(self) -> None:
        corpus = self._corpus([self._case(index) for index in range(1, 4)])
        stats = self._run(corpus, "--dry-run")
        self.assertEqual(3, stats["inserted"])
        self.assertTrue(stats["dry_run"])
        store = TaskStore(str(self.db))
        self.assertEqual(0, len(store.list_evaluation_cases("validation", True, 50)))

    def test_report_includes_the_actual_clean_denominator(self) -> None:
        """只报「插入了 N 条」不够。

        干净样本 id 更大，如果取样仍是平铺的，插进去也照样选不中，分母还是
        0。所以报告必须给出取样后的实际 clean 条数。
        """

        store = TaskStore(str(self.db))
        for index in range(50, 56):
            store.save_evaluation_case(
                "defect-%d" % index,
                "validation",
                DIFF % {"i": index},
                [{"path": "mod_%d.py" % index, "line": 2, "min_severity": "high"}],
            )
        stats = self._run(self._corpus([self._case(i) for i in range(1, 7)]))
        self.assertGreaterEqual(stats["selected"]["validation@20"]["clean_denominator"], 1)


if __name__ == "__main__":
    unittest.main()