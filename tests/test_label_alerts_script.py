"""标注工具的离线测试。

这个脚本是**唯一直接决定标注数据长什么样**的地方，它写错的后果不是崩，
而是产出一份看起来正常、口径已经坏了的标注文件——而标注文件是有效告警率
和重测一致率的唯一输入。所以三条 rubric 硬约束必须在这里锁住：

1. 第 1 步（是否落在标注集内）不问人。rubric 明确要求"用工具算，不靠人看
   真值"，问了人就等于让人代替工具判，而人此时看得到 diff 但看不到真值。
2. rubric 版本不符必须拒绝执行。混标出来的一轮数据没法解释。
3. --blind 必须在清空前要确认。它会丢弃已有标签，误触的代价是一轮标注白做。
"""
import json
import os
import subprocess
import sys
import tempfile
import unittest


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(ROOT, "scripts", "label_alerts.py")


def _payload(alerts, rubric_version="v1"):
    return {
        "rubric_version": rubric_version,
        "round": "r1",
        "seed": 1,
        "labelled_at": "2026-09-01",
        "source": "test",
        "alerts": alerts,
    }


def _alert(alert_id, in_scope=True, label=None):
    return {
        "alert_id": alert_id,
        "case_id": "pr-0001",
        "path": "src/a.py",
        "line": 3,
        "rule_id": "SEC-EVAL",
        "severity": "critical",
        "title": "t",
        "explanation": "e",
        "diff_excerpt": "+++ b/src/a.py\n@@ -1,2 +1,2 @@\n+eval(x)\n",
        "in_label_scope": in_scope,
        "label": label,
        "note": "",
    }


class LabelAlertsScriptTests(unittest.TestCase):
    def _run(self, payload, stdin, extra=()):
        handle = tempfile.NamedTemporaryFile(
            "w", suffix=".json", delete=False, encoding="utf-8")
        try:
            json.dump(payload, handle, ensure_ascii=False)
            handle.close()
            result = subprocess.run(
                [sys.executable, SCRIPT, handle.name, *extra],
                input=stdin, capture_output=True, text=True, cwd=ROOT,
                encoding="utf-8", errors="replace",
            )
            with open(handle.name, encoding="utf-8") as reader:
                written = json.load(reader)
            return result, written
        finally:
            for path in (handle.name, handle.name + ".tmp"):
                if os.path.exists(path):
                    os.unlink(path)

    def test_out_of_scope_alerts_are_decided_by_the_tool_not_the_person(self):
        """in_label_scope=False 时必须直接判 unlabelled，且**不消耗一次输入**。

        这条是 rubric "第 1 步用工具算，不靠人看真值" 的实现。测法是关键：
        只喂一次输入，但给两条告警——第一条 out-of-scope、第二条 in-scope。
        如果实现错误地为第一条也问了人，那唯一的这次输入会被第一条吃掉，
        第二条就拿不到答案。所以断言"第二条被标成 valid"同时证明了
        "第一条没有问人"，比直接断言标签更难被写死糊弄过去。
        """
        payload = _payload([_alert("a1", in_scope=False), _alert("a2")])
        _result, written = self._run(payload, stdin="1\n1\n")
        self.assertEqual("unlabelled", written["alerts"][0]["label"])
        self.assertIn("tool-decided", written["alerts"][0]["note"])
        self.assertEqual("valid", written["alerts"][1]["label"])

    def test_step_two_precedes_step_three(self):
        """事实不成立 -> invalid，且**不再问相关性**。

        rubric：第 2 步在第 3 步之前，一条既不成立又与改动无关的告警是
        invalid 不是 valid-but-noise，顺序反了会把事实错误洗成"噪声"。

        同样用输入数守恒来测：喂 "2"（不成立）再喂 "1"，若实现在判定
        invalid 后仍然问了相关性，那个 "1" 会被第一条吃掉，第二条无输入。
        """
        payload = _payload([_alert("a1"), _alert("a2")])
        _result, written = self._run(payload, stdin="2\n1\n1\n")
        self.assertEqual("invalid", written["alerts"][0]["label"])
        # 第二条拿到了完整的两步输入（1=成立、1=相关）才可能是 valid。
        self.assertEqual("valid", written["alerts"][1]["label"])

    def test_step_three_produces_the_noise_label(self):
        payload = _payload([_alert("a1")])
        _result, written = self._run(payload, stdin="1\n2\n")
        self.assertEqual("valid-but-noise", written["alerts"][0]["label"])

    def test_undecided_is_recorded_as_unlabelled_with_a_note(self):
        """拿不定主意判 unlabelled 并记备注，不允许为凑分母硬判。"""
        payload = _payload([_alert("a1")])
        _result, written = self._run(payload, stdin="3\nweird shape\n")
        self.assertEqual("unlabelled", written["alerts"][0]["label"])
        self.assertEqual("weird shape", written["alerts"][0]["note"])

    def test_a_rubric_version_mismatch_refuses_to_run(self):
        """版本不符必须拒绝且不写入。混标的一轮数据没法解释。"""
        payload = _payload([_alert("a1")], rubric_version="v0")
        result, written = self._run(payload, stdin="1\n1\n")
        self.assertEqual(2, result.returncode)
        self.assertIsNone(written["alerts"][0]["label"])

    def test_already_labelled_alerts_are_skipped_so_you_can_resume(self):
        """续标：已标的跳过，不重问也不覆盖。"""
        payload = _payload([_alert("a1", label="valid"), _alert("a2")])
        _result, written = self._run(payload, stdin="2\n")
        self.assertEqual("valid", written["alerts"][0]["label"])
        self.assertEqual("invalid", written["alerts"][1]["label"])

    def test_blind_mode_refuses_without_explicit_confirmation(self):
        """--blind 会丢弃已有标签，必须先确认。输入 no 时一个字节都不许改。"""
        payload = _payload([_alert("a1", label="valid")])
        result, written = self._run(payload, stdin="no\n", extra=("--blind",))
        self.assertEqual(2, result.returncode)
        self.assertEqual("valid", written["alerts"][0]["label"])

    def test_blind_mode_clears_previous_labels_once_confirmed(self):
        """确认后必须真的清空。留着上轮标签会锚定，一致率测的是记忆。"""
        payload = _payload([_alert("a1", label="valid"), _alert("a2", label="invalid")])
        # 第一条 1,1 -> valid；第二条 1,2 -> valid-but-noise。
        # 第二条刻意选一个**与它原有标签（invalid）不同**的结果：若实现没有
        # 真的清空，残留的 invalid 会让这条断言失败。用同值就测不出来了。
        _result, written = self._run(payload, stdin="yes\n1\n1\n1\n2\n",
                                     extra=("--blind",))
        # 两条都重标了，且第一条的新标签来自本轮输入而非残留。
        self.assertEqual("valid", written["alerts"][0]["label"])
        self.assertEqual("valid-but-noise", written["alerts"][1]["label"])

    def test_quitting_keeps_what_was_already_answered(self):
        """q 退出必须保留已答的，否则 30 条只能一次标完。"""
        payload = _payload([_alert("a1"), _alert("a2")])
        _result, written = self._run(payload, stdin="1\n1\nq\n")
        self.assertEqual("valid", written["alerts"][0]["label"])
        self.assertIsNone(written["alerts"][1]["label"])

    def test_an_unrecognised_answer_reprompts_instead_of_guessing(self):
        """乱输入必须重问，不能猜。

        猜错的代价是**默默记下一个你没打算给的标签**，而标签是整轮的产出。
        测法：先喂一个非法值，再喂合法值，最终标签必须来自后者。
        """
        payload = _payload([_alert("a1")])
        _result, written = self._run(payload, stdin="y\n1\n2\n")
        self.assertEqual("valid-but-noise", written["alerts"][0]["label"])


if __name__ == "__main__":
    unittest.main()
