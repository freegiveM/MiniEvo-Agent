"""轨道 H：`failure_cases` 的真实数据从哪来，以及什么不许进去。

## 钉住的缺口

六段闭环基建都通了，但 `failure_cases` 是空的——档案的逐样本分数、Pareto
选亲、轨道 F 的口径验证全都因此空转。D6 回放里有 173 个真实样本的模型输出，
和数据集的 `expected_findings` 一对就能得到差集。

## 这批测试里最要紧的两条

`test_unconfirmed_candidates_are_never_imported`：自动对出来的差集**不是
反馈**。`HUMAN_CONFIRMED_CATEGORIES` 那道白名单只看 category 字面值，
一条推断出来的 `false_positive` 会被原样放行进提示词进化——绕过白名单不需要
改白名单，只要在写库时撒个谎就够了。

`test_a_valid_out_of_scope_finding_is_not_a_false_positive`：标注外 finding
被人工确认为 `valid` 时**不产出 failure_case**。数据集只标了反转出来的那个
种子缺陷，r1 那 88 条标注里 83 条是 `valid`——把它们当误报灌进去，等于教
模型别再报真问题。
"""
import json
import os
import tempfile
import unittest

from evoagent.feedback_import import (
    KIND_UNMATCHED_EXPECTED,
    KIND_UNMATCHED_FINDING,
    LABEL_INVALID,
    LABEL_NOISE,
    LABEL_NOT_EXPECTED,
    LABEL_SHOULD_HAVE,
    LABEL_UNLABELLED,
    LABEL_VALID,
    SOURCE_MODEL_LABELLED,
    apply_worksheet,
    blind,
    build_payload,
    derive_candidates,
    import_confirmed,
    load_candidates,
    load_replay_checkpoint,
    parse_worksheet,
    render_worksheet,
    sample_candidates,
    save_candidates,
    validate_labels,
)
from evoagent.models import Finding, Severity
from evoagent.store import create_store

DIFF = """--- a/pkg/mod.py
+++ b/pkg/mod.py
@@ -10,4 +10,8 @@ def parse(items):
     total = 0
     for index in range(len(items)):
+        if index <= len(items):
+            total += items[index]
+    }
+    }
     return total
"""


# 默认 rule_id 直接用 CWE 号：`cwe-exact` 比的是
# `RULE_TO_CWE.get(rule_id, rule_id)`，映射表里没有的 rule_id 按自身比。
# 用 "R1" 这种假名字会让"本该命中"的样例其实一条都没命中，测试于是在
# 测一个不存在的场景。
def _finding(rule_id="CWE-193", path="pkg/mod.py", line=13, severity="high"):
    return Finding(
        rule_id=rule_id, severity=Severity(severity), title="t", explanation="e",
        path=path, line=line, evidence="ev", fix="fix", test="test",
    )


def _case(case_id="c1", split="validation", expected=None, **extra):
    case = {
        "id": case_id, "split": split, "repository": "org/repo",
        "pull_request": 7, "diff": DIFF, "label_provenance": "linked-issue",
        "fix_pr_url": "https://example.invalid/pr/7",
        "expected_findings": expected if expected is not None else [{
            "cwe": "CWE-193", "defect_class": "logic-boundary",
            "path": "pkg/mod.py", "start_line": 13, "end_line": 13,
            "severity": "high", "should_comment": True,
        }],
    }
    case.update(extra)
    return case


class DerivationTests(unittest.TestCase):
    def test_a_missed_expected_finding_becomes_a_candidate(self):
        candidates = derive_candidates([_case()], {"c1": []})

        self.assertEqual(1, len(candidates))
        self.assertEqual(KIND_UNMATCHED_EXPECTED, candidates[0]["kind"])
        self.assertEqual("CWE-193", candidates[0]["cwe"])
        # 派生阶段一律不带标签——它是候选，不是结论。
        self.assertIsNone(candidates[0]["label"])

    def test_an_out_of_scope_finding_becomes_a_candidate(self):
        candidates = derive_candidates(
            [_case()], {"c1": [_finding(), _finding("R9", line=99)]})

        kinds = [item["kind"] for item in candidates]
        self.assertEqual([KIND_UNMATCHED_FINDING], kinds)
        self.assertIsNone(candidates[0]["label"])

    def test_a_matched_finding_produces_no_candidate(self):
        self.assertEqual([], derive_candidates([_case()], {"c1": [_finding()]}))

    def test_holdout_is_excluded_by_default(self):
        """holdout 的反馈进提示词进化 = 拿隐藏集调参，门禁当场失效。"""
        cases = [_case("h1", split="holdout")]
        self.assertEqual([], derive_candidates(cases, {"h1": []}))
        self.assertEqual(
            1, len(derive_candidates(cases, {"h1": []}, splits=("holdout",))))

    def test_a_case_missing_from_the_replay_is_skipped(self):
        """回放里没有这一条，不等于模型看过之后什么都没报。

        当成零 findings 会凭空造出一批漏报候选。
        """
        self.assertEqual([], derive_candidates([_case()], {}))

    def test_a_failed_replay_case_is_not_read_as_silence(self):
        handle, path = tempfile.mkstemp(suffix=".jsonl")
        os.close(handle)
        try:
            with open(path, "w", encoding="utf-8") as out:
                out.write(json.dumps({"id": "c1", "error": "timeout",
                                      "findings": []}) + "\n")
                out.write(json.dumps({"id": "c2", "findings": [
                    _finding().to_dict()]}) + "\n")
            replay = load_replay_checkpoint(path)
        finally:
            os.unlink(path)

        self.assertNotIn("c1", replay)
        self.assertEqual(1, len(replay["c2"]))
        # 于是 c1 不产出任何候选，而不是产出一条"漏报"。
        self.assertEqual([], derive_candidates([_case("c1")], replay))

    def test_candidate_ids_are_stable_across_finding_order(self):
        """按内容而不是序号定 id：模型输出顺序一变，已标好的标签不能作废。"""
        first = derive_candidates(
            [_case()], {"c1": [_finding("R8", line=98), _finding("R9", line=99)]})
        second = derive_candidates(
            [_case()], {"c1": [_finding("R9", line=99), _finding("R8", line=98)]})

        self.assertEqual([item["candidate_id"] for item in first],
                         [item["candidate_id"] for item in second])

    def test_the_excerpt_locates_the_reported_line(self):
        """diff 里有两条一模一样的新增行时也要定位对。

        按内容回查原文会命中第一条 `+    }`，于是人工看到的是另一处代码。
        """
        candidates = derive_candidates([_case()], {"c1": []})
        excerpt = candidates[0]["diff_excerpt"]

        self.assertIn("if index <= len(items)", excerpt)

    def test_an_unlocatable_line_yields_an_empty_excerpt(self):
        """找不到就留空，不退回 diff 开头冒充"目标附近"。"""
        case = _case(expected=[{
            "cwe": "CWE-476", "path": "pkg/other.py", "start_line": 900,
            "end_line": 900, "severity": "low", "should_comment": True,
        }])
        candidates = derive_candidates([case], {"c1": []})
        self.assertEqual("", candidates[0]["diff_excerpt"])

    def test_missed_issue_candidates_carry_their_label_provenance(self):
        """`title-keyword` 与 `cve` 的可信度差很远，判"该不该报"时必须看得到。"""
        candidates = derive_candidates(
            [_case(label_provenance="title-keyword")], {"c1": []})
        self.assertEqual("title-keyword", candidates[0]["label_provenance"])

    def test_an_unknown_tier_is_rejected(self):
        with self.assertRaises(ValueError):
            derive_candidates([_case()], {"c1": []}, tier="made-up")


class BlindingTests(unittest.TestCase):
    def test_out_of_scope_candidates_are_blinded(self):
        """判"是不是误报"时看到真值就是看答案，判定会向真值靠拢。"""
        candidates = derive_candidates(
            [_case()], {"c1": [_finding("R9", line=99)]})
        stripped = blind(candidates)[0]

        for key in ("cwe", "defect_class", "label_provenance", "fix_pr_url"):
            self.assertNotIn(key, stripped)
        self.assertIn("diff_excerpt", stripped)

    def test_missed_issue_candidates_are_not_blinded(self):
        """两类候选的盲标要求不同——剥掉缺陷就无从判断"该不该报"。"""
        stripped = blind(derive_candidates([_case()], {"c1": []}))[0]
        self.assertEqual("CWE-193", stripped["cwe"])
        self.assertEqual("linked-issue", stripped["label_provenance"])


class LabelValidationTests(unittest.TestCase):
    def _candidates(self):
        """只取标注外 finding 那一类，好让下面的断言只关于标签本身。"""
        return [
            item for item in derive_candidates(
                [_case()], {"c1": [_finding("CWE-476", line=99)]})
            if item["kind"] == KIND_UNMATCHED_FINDING
        ]

    def test_a_wrong_kind_label_is_reported_separately_from_missing(self):
        """填错了（要有人回去改）和判不了（是个合法结论）不能合并。"""
        candidates = self._candidates()
        candidates[0]["label"] = LABEL_SHOULD_HAVE  # 只对漏报候选合法
        report = validate_labels(candidates)

        self.assertEqual([candidates[0]["candidate_id"]], report["invalid_label"])
        self.assertEqual([], report["missing_label"])

    def test_unlabelled_is_not_importable(self):
        candidates = self._candidates()
        candidates[0]["label"] = LABEL_UNLABELLED
        self.assertEqual(0, validate_labels(candidates)["importable"])

    def test_only_confirmed_defect_labels_are_importable(self):
        candidates = self._candidates()
        candidates[0]["label"] = LABEL_INVALID
        self.assertEqual(1, validate_labels(candidates)["importable"])


class PayloadTests(unittest.TestCase):
    def test_a_cwe_is_never_smuggled_in_as_a_rule_id(self):
        """**关键口径。**

        `auto_propose` 会把 `payload.finding.rule_id` 拼成 `[focus-rule:X]`
        注进提示词。数据集的 expected_findings 没有 rule_id，只有 cwe，
        而 `CWE-193` 恰好能通过 `FEEDBACK_RULE_ID` 正则。拿 cwe 顶替就会
        注入一条没有任何 reviewer 认识的规则，指标不动，然后被改进门禁
        判成"模型学不动"——实际是这里造了个假字段。
        """
        candidate = derive_candidates([_case()], {"c1": []})[0]
        candidate["label"] = LABEL_SHOULD_HAVE
        payload = build_payload(candidate)

        self.assertEqual("CWE-193", payload["finding"]["cwe"])
        self.assertNotIn("rule_id", payload["finding"])

    def test_a_human_supplied_rule_id_is_kept(self):
        candidate = derive_candidates([_case()], {"c1": []})[0]
        candidate["label"] = LABEL_SHOULD_HAVE
        candidate["rule_id"] = "OFF_BY_ONE"
        self.assertEqual("OFF_BY_ONE", build_payload(candidate)["finding"]["rule_id"])

    def test_the_payload_records_where_the_feedback_came_from(self):
        candidate = derive_candidates([_case()], {"c1": []})[0]
        candidate["label"] = LABEL_SHOULD_HAVE
        provenance = build_payload(candidate)["provenance"]

        self.assertEqual("d6-replay-human-confirmed", provenance["source"])
        self.assertEqual("c1", provenance["case_id"])
        self.assertEqual(LABEL_SHOULD_HAVE, provenance["label"])
        self.assertEqual("linked-issue", provenance["label_provenance"])

    def test_a_model_labelled_batch_does_not_claim_human_confirmation(self):
        """**关键口径。**

        模型标注的候选走同一条路径进库。`import_confirmed` 只看 label 和
        kind，它无从知道那个 label 是谁填的；provenance 是唯一记录这件事
        的地方。source 曾经是常量，于是模型标注的反馈在库里与人工确认的
        完全一样——note 里的 `[model-labelled]` 前缀挡不住这个，
        `HUMAN_CONFIRMED_CATEGORIES` 那道白名单挡的是 category，对来源
        不实的 provenance 完全无感。
        """
        candidate = derive_candidates([_case()], {"c1": []})[0]
        candidate["label"] = LABEL_SHOULD_HAVE
        payload = build_payload(candidate, source=SOURCE_MODEL_LABELLED)

        self.assertEqual("d6-replay-model-labelled",
                         payload["provenance"]["source"])

    def test_an_unknown_source_is_rejected_rather_than_written_through(self):
        """自由字符串会让溯源变成一个谁都能写的备注栏：拼错一个字母就
        产生一个新的"来源"，而按来源筛反馈的查询会静默漏掉它。"""
        candidate = derive_candidates([_case()], {"c1": []})[0]
        candidate["label"] = LABEL_SHOULD_HAVE
        with self.assertRaises(ValueError):
            build_payload(candidate, source="looks-official-enough")


class ImportTests(unittest.TestCase):
    def setUp(self):
        handle, self.path = tempfile.mkstemp(suffix=".db")
        os.close(handle)
        self.store = create_store("", self.path)

    def tearDown(self):
        if os.path.exists(self.path):
            os.unlink(self.path)

    def _payload(self, label, kind=KIND_UNMATCHED_EXPECTED, findings=None):
        candidates = derive_candidates([_case()], {"c1": findings or []})
        candidates = [item for item in candidates if item["kind"] == kind]
        for item in candidates:
            item["label"] = label
        return {"candidates": candidates}

    def test_unconfirmed_candidates_are_never_imported(self):
        """**本轨道最要紧的断言。**

        `HUMAN_CONFIRMED_CATEGORIES` 只看 category 字面值。一条推断出来的
        `false_positive` 会被原样放行进提示词进化——绕过白名单不需要改
        白名单，只要在写库时撒个谎就够了。
        """
        payload = self._payload(None)
        result = import_confirmed(self.store, payload)

        self.assertEqual(0, result["imported_count"])
        self.assertEqual(1, len(result["skipped_unconfirmed"]))
        self.assertEqual([], self.store.list_failure_cases())

    def test_a_confirmed_missed_issue_is_imported(self):
        result = import_confirmed(self.store, self._payload(LABEL_SHOULD_HAVE))

        self.assertEqual(1, result["imported_count"])
        cases = self.store.list_failure_cases()
        self.assertEqual("missed_issue", cases[0]["category"])
        self.assertEqual("CWE-193", cases[0]["payload"]["finding"]["cwe"])

    def test_a_confirmed_false_positive_is_imported(self):
        payload = self._payload(
            LABEL_INVALID, kind=KIND_UNMATCHED_FINDING,
            findings=[_finding("R9", line=99)])
        import_confirmed(self.store, payload)

        self.assertEqual(
            "false_positive", self.store.list_failure_cases()[0]["category"])

    def test_a_valid_out_of_scope_finding_is_not_a_false_positive(self):
        """**第二条最要紧的断言。**

        数据集只标了反转出来的那个种子缺陷；标注外的 finding 可能是真问题
        （r1 的 88 条标注里 83 条是 valid）。把它当误报导入等于教模型别再
        报真问题——这正是这个模块存在的理由。
        """
        for label in (LABEL_VALID, LABEL_NOISE):
            payload = self._payload(
                label, kind=KIND_UNMATCHED_FINDING,
                findings=[_finding("R9", line=99)])
            result = import_confirmed(self.store, payload)

            self.assertEqual(0, result["imported_count"], label)
            self.assertEqual(1, len(result["skipped_not_feedback"]), label)
        self.assertEqual([], self.store.list_failure_cases())

    def test_not_expected_is_a_dataset_problem_not_model_feedback(self):
        result = import_confirmed(self.store, self._payload(LABEL_NOT_EXPECTED))

        self.assertEqual(0, result["imported_count"])
        self.assertEqual(1, len(result["skipped_not_feedback"]))

    def test_a_wrong_kind_label_is_rejected_not_guessed(self):
        payload = self._payload(
            LABEL_SHOULD_HAVE, kind=KIND_UNMATCHED_FINDING,
            findings=[_finding("R9", line=99)])
        result = import_confirmed(self.store, payload)

        self.assertEqual(0, result["imported_count"])
        self.assertEqual(1, len(result["rejected"]))
        self.assertIn("not valid for kind", result["rejected"][0]["reason"])

    def test_importing_twice_does_not_double_count(self):
        """补标之后重跑是正常操作。重复入库会把同一条反馈计成两次出现，
        直接把频率分流的 root_cause_min_occurrences 顶过阈值。
        """
        payload = self._payload(LABEL_SHOULD_HAVE)
        import_confirmed(self.store, payload)
        second = import_confirmed(self.store, payload)

        self.assertEqual(0, second["imported_count"])
        self.assertEqual(1, len(second["skipped_already_imported"]))
        self.assertEqual(1, len(self.store.list_failure_cases()))

    def test_the_case_diff_is_stored_so_the_feedback_can_be_promoted(self):
        """轨道 F 卡在"failure_case 没有 diff"。这里手上正好有。"""
        payload = self._payload(LABEL_SHOULD_HAVE)
        result = import_confirmed(self.store, payload, diffs={"c1": DIFF})

        self.assertTrue(result["imported"][0]["diff_saved"])
        self.assertEqual(
            DIFF, self.store.get_task_payload(result["imported"][0]["task_id"]))

    def test_a_missing_diff_is_left_absent_rather_than_faked(self):
        """宁可没有，不要把片段当完整 diff 存进去——轨道 F 会拿到一个
        看起来完全正常的截断输入。
        """
        result = import_confirmed(self.store, self._payload(LABEL_SHOULD_HAVE))

        self.assertFalse(result["imported"][0]["diff_saved"])
        self.assertIsNone(
            self.store.get_task_payload(result["imported"][0]["task_id"]))

    def test_imported_feedback_is_visible_to_the_tenant_filtered_query(self):
        """`failure_cases` 的租户过滤走 JOIN tasks——没有真 task 行就查不到。"""
        import_confirmed(self.store, self._payload(LABEL_SHOULD_HAVE),
                         tenant_id="acme")

        self.assertEqual(1, len(self.store.list_failure_cases(False, 100, "acme")))
        self.assertEqual(0, len(self.store.list_failure_cases(False, 100, "other")))

    def test_imported_feedback_reaches_the_category_counts(self):
        """这就是轨道 H 要解锁的东西：进化那边靠这个计数取反馈。"""
        import_confirmed(self.store, self._payload(LABEL_SHOULD_HAVE))
        self.assertEqual(
            {"missed_issue": 1},
            self.store.count_failure_cases_by_category())


class RoundTripTests(unittest.TestCase):
    def test_candidates_survive_a_save_load_round_trip(self):
        handle, path = tempfile.mkstemp(suffix=".json")
        os.close(handle)
        try:
            candidates = derive_candidates([_case()], {"c1": []})
            save_candidates(path, candidates, source="ds", tier="cwe-exact",
                            stamp="2026-09-07", replay="d6")
            loaded = load_candidates(path)
        finally:
            os.unlink(path)

        self.assertEqual("2026-09-07", loaded["prepared_at"])
        self.assertEqual(candidates, loaded["candidates"])
        self.assertIn("不等于误报", loaded["note"])


class WorksheetTests(unittest.TestCase):
    """人工标注这一步的工装。**它不产出任何 label。**

    一条由程序写出来的 label 是推断结论，而两步 CLI 中间那道闸门的全部意义
    就是推断结论不得进 `failure_cases`——填了 label 列，
    `HUMAN_CONFIRMED_CATEGORIES` 那道白名单依然放行，因为它背后的数据是
    编造的。工装只负责让人的那一步快。
    """

    def _candidates(self, count=6):
        cases = [_case("c%d" % index) for index in range(count)]
        replay = {case["id"]: [] for case in cases}
        return derive_candidates(cases, replay)

    def _payload(self, candidates):
        return {
            "source": "ds", "replay": "d6", "match_tier": "cwe-exact",
            "prepared_at": "2026-09-07", "candidates": list(candidates),
        }

    def test_the_sample_is_deterministic_for_a_given_seed(self):
        """种子相同抽到同一批，否则第二轮标注对不上已标好的那批。"""
        pool = self._candidates(10)
        first = sample_candidates(pool, 4, seed=7)
        second = sample_candidates(pool, 4, seed=7)

        self.assertEqual(
            [item["candidate_id"] for item in first],
            [item["candidate_id"] for item in second],
        )

    def test_the_sample_does_not_depend_on_the_input_order(self):
        """候选列表顺序取决于派生时的遍历顺序。

        直接对它抽样的话，上游一改顺序，同一个种子就抽到另一批，已经标好
        的标签全部作废（与 `alert_labelling.sample_alerts` 同一理由）。
        """
        pool = self._candidates(10)
        shuffled = list(reversed(pool))

        self.assertEqual(
            {item["candidate_id"] for item in sample_candidates(pool, 4, 7)},
            {item["candidate_id"] for item in sample_candidates(shuffled, 4, 7)},
        )

    def test_a_kind_filter_keeps_one_question_per_worksheet(self):
        """两类候选问的问题不同、盲标要求不同，混在一份清单里让人来回切换判据。"""
        cases = [_case("c1"), _case("c2")]
        replay = {"c1": [], "c2": [_finding(), _finding("R9", line=99)]}
        pool = derive_candidates(cases, replay)
        picked = sample_candidates(pool, 10, 7, kind=KIND_UNMATCHED_FINDING)

        self.assertTrue(picked)
        self.assertEqual(
            {KIND_UNMATCHED_FINDING}, {item["kind"] for item in picked})

    def test_a_size_larger_than_the_pool_returns_everything(self):
        pool = self._candidates(3)
        self.assertEqual(3, len(sample_candidates(pool, 99, 7)))

    def test_the_worksheet_leaves_every_label_blank(self):
        """**本组最要紧的断言。**"""
        pool = self._candidates(3)
        text = render_worksheet(self._payload(pool), pool)

        self.assertEqual(3, text.count("label:\n"))
        for label in (LABEL_SHOULD_HAVE, LABEL_INVALID):
            # 标签空间作为说明出现是对的，但不能出现在 `label:` 之后。
            self.assertNotIn("label: %s" % label, text)

    def test_the_worksheet_states_which_labels_produce_no_feedback(self):
        """`valid` / `valid-but-noise` / `not-expected` 不产出 failure_case。

        不写清楚的话，标注者会以为"标注外的告警"就该标成误报，而那正是
        这个模块存在的理由要防的事。
        """
        pool = self._candidates(1)
        text = render_worksheet(self._payload(pool), pool)

        self.assertIn("不产出反馈", text)
        self.assertIn("教模型别再报真问题", text)

    def test_a_candidate_without_an_excerpt_says_so(self):
        """定位不到片段的候选凭清单判不了，得说出来。

        别让它静静地变成一条 unlabelled——那和"看过之后判不了"是两件事。
        """
        pool = self._candidates(1)
        pool[0]["diff_excerpt"] = ""
        text = render_worksheet(self._payload(pool), pool)

        self.assertIn("没有 diff 片段", text)

    def test_the_finding_side_worksheet_does_not_show_truth_hints(self):
        """`blind()` 剥过的候选渲染出来也不能带真值线索。

        只取 `unmatched_finding` 那一类：漏报侧刻意**保留** `label_provenance`
        与 `fix_pr_url`，因为那里要问的问题（"这个已知缺陷该不该报"）不给
        出缺陷就无从判断。盲标纪律是不对称的，见模块文档。
        """
        cases = [_case("c1")]
        replay = {"c1": [_finding("R9", line=99)]}
        pool = [item for item in blind(derive_candidates(cases, replay))
                if item["kind"] == KIND_UNMATCHED_FINDING]
        self.assertTrue(pool)
        body = render_worksheet(self._payload(pool), pool).split("---", 1)[-1]

        for hint in ("label_provenance", "fix_pr_url", "cwe", "defect_class"):
            self.assertNotIn(hint, body, hint)

    def test_a_filled_worksheet_round_trips_into_the_candidate_file(self):
        pool = self._candidates(2)
        payload = self._payload(pool)
        text = render_worksheet(payload, pool)
        filled = text.replace(
            "candidate_id: %s\nlabel:" % pool[0]["candidate_id"],
            "candidate_id: %s\nlabel: %s" % (pool[0]["candidate_id"],
                                             LABEL_SHOULD_HAVE),
        )
        parsed = parse_worksheet(filled)
        self.assertEqual([], parsed["problems"])

        result = apply_worksheet(payload, parsed["entries"])
        self.assertEqual([pool[0]["candidate_id"]], result["applied"])
        by_id = {item["candidate_id"]: item
                 for item in result["payload"]["candidates"]}
        self.assertEqual(LABEL_SHOULD_HAVE, by_id[pool[0]["candidate_id"]]["label"])
        # 没填的那条仍然未确认——空白不能被当成一个结论。
        self.assertIsNone(by_id[pool[1]["candidate_id"]]["label"])
        self.assertEqual([pool[1]["candidate_id"]], result["skipped_blank"])

    def test_a_label_outside_the_label_space_is_a_problem_not_an_unlabelled(self):
        """填错了（需要有人回去改）与判不了（一个合法的结论）必须分得开。"""
        parsed = parse_worksheet("candidate_id: abc\nlabel: probably-fine\n")

        self.assertEqual(1, len(parsed["problems"]))
        self.assertIn("probably-fine", parsed["problems"][0])

    def test_a_label_outside_any_candidate_block_is_refused_not_guessed(self):
        """猜它属于上一条就是把一条判定挂到别人身上。"""
        parsed = parse_worksheet("label: %s\n" % LABEL_SHOULD_HAVE)

        self.assertEqual({}, parsed["entries"])
        self.assertEqual(1, len(parsed["problems"]))

    def test_a_duplicated_candidate_id_is_a_problem(self):
        parsed = parse_worksheet(
            "candidate_id: abc\nlabel: %s\ncandidate_id: abc\nlabel: %s\n"
            % (LABEL_SHOULD_HAVE, LABEL_NOT_EXPECTED))

        self.assertTrue(parsed["problems"])

    def test_an_unknown_candidate_id_is_reported_not_ignored(self):
        """清单和候选文件对不上时，其它条目的归属也不可信。"""
        pool = self._candidates(1)
        result = apply_worksheet(
            self._payload(pool),
            {"not-a-real-id": {"label": LABEL_SHOULD_HAVE}},
        )

        self.assertEqual(["not-a-real-id"], result["unknown_candidate_ids"])

    def test_an_existing_label_is_not_overwritten(self):
        """重标是显式动作，不能作为"又跑了一次 apply"的副产品发生。"""
        pool = self._candidates(1)
        pool[0]["label"] = LABEL_SHOULD_HAVE
        result = apply_worksheet(
            self._payload(pool),
            {pool[0]["candidate_id"]: {"label": LABEL_NOT_EXPECTED}},
        )

        self.assertEqual([], result["applied"])
        self.assertEqual([pool[0]["candidate_id"]], result["conflicts"])
        self.assertEqual(
            LABEL_SHOULD_HAVE, result["payload"]["candidates"][0]["label"])

    def test_a_filled_rule_id_reaches_the_candidate(self):
        """rule_id 只在人工填了的时候才写，见 build_payload 的文档。"""
        pool = self._candidates(1)
        result = apply_worksheet(
            self._payload(pool),
            {pool[0]["candidate_id"]: {
                "label": LABEL_SHOULD_HAVE, "rule_id": "SEC-OFF-BY-ONE"}},
        )

        self.assertEqual(
            "SEC-OFF-BY-ONE", result["payload"]["candidates"][0]["rule_id"])

    def test_the_worksheet_is_reachable_from_the_cli(self):
        """写好了没人调用等于没写（`tiered_match` 零调用方的教训）。"""
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        with open(os.path.join(root, "scripts", "import_replay_feedback.py"),
                  encoding="utf-8") as handle:
            script = handle.read()

        self.assertIn("render_worksheet(", script)
        self.assertIn("apply_worksheet(", script)
        self.assertIn('"apply-worksheet"', script)


if __name__ == "__main__":
    unittest.main()