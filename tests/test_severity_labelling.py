"""`severity_labelling` 的口径测试：盲化、归一化、分歧统计。

## 为什么这个模块必须有测试

它产出的是**标签**。标签错了，下游每一个指标都跟着错，而且错得没有痕迹——
一个 `high_severity_recall` 数字看不出它的分母是怎么来的。这与评测器代码
不同：评测器算错通常会让数字明显异常，标签算错只会让数字**看起来正常但
含义变了**。

## 四条硬约束，逐条钉住

1. **盲化**：judge 看不到原 severity/defect_class/cwe。`BlindingTests`
   验证工具层真的剥掉了，而不是靠 prompt 里写一句"请忽略"。
2. **特权上下文照给**：human_patch 与 fix_pr_title 必须在 payload 里。
   `BlindingTests.test_the_privileged_context_is_deliberately_included`
   钉住这条——它容易在"加强盲化"时被误删。
3. **不覆盖原标签**：`normalise_verdict` 只产出 `*_llm` 字段。
4. **逐条落盘**：`CheckpointStore` 的 append + 恢复。

## 非法值不静默默认化

`normalise_verdict` 对非法 severity/defect_class 给 None 并记进
`invalid_fields`，而不是悄悄填一个 "medium"。后者会把"judge 没按 schema
答"伪装成一个正常判定，而 `medium` 恰好是原标签里占 89% 的那一档——
默认成它等于凭空制造一致率。
"""
import json
import os
import tempfile
import unittest

from evoagent.severity_labelling import (
    CALIBRATION_MIN_AGREEMENT,
    CALIBRATION_MIN_KAPPA,
    LABEL_SOURCE,
    RUBRIC_VERSION,
    CheckpointStore,
    blind_finding,
    blind_for_calibration,
    build_judge_payload,
    calibration_report,
    finding_id,
    normalise_cwe,
    normalise_verdict,
    relabel_summary,
    severity_drift,
    stratified_calibration_sample,
)


def _record():
    return {
        "id": "org__repo-pr-1",
        "repository": "org/repo",
        "domain": "web",
        "fix_pr_title": "fix: guard against empty header",
        "human_patch": "+ if not header:\n+     raise ValueError",
        "diff": "--- a/a.py\n+++ b/a.py\n@@ -1 +1 @@\n+parse(header)\n",
        "expected_findings": [
            {
                "path": "a.py", "start_line": 1, "end_line": 3,
                "severity": "medium", "defect_class": "logic-boundary",
                "cwe": "CWE-193",
            },
        ],
    }


class FindingIdTests(unittest.TestCase):
    def test_the_id_is_built_from_case_path_and_line(self):
        self.assertEqual("c|a/b.py|7", finding_id("c", "a/b.py", 7))

    def test_windows_separators_are_normalised(self):
        """同一条 finding 在两个平台上必须得到同一个 id，否则两轮标注对不上。"""
        self.assertEqual(
            finding_id("c", "a/b.py", 7), finding_id("c", "a\\b.py", 7),
        )

    def test_the_id_does_not_depend_on_array_position(self):
        """刻意不用下标：数据集重新生成时下标会变，三元组不会。"""
        self.assertEqual(finding_id("c", "a.py", 1), finding_id("c", "a.py", 1))


class BlindingTests(unittest.TestCase):
    def test_the_original_labels_are_stripped_at_the_tool_layer(self):
        blinded = blind_finding(_record()["expected_findings"][0])
        self.assertNotIn("severity", blinded)
        self.assertNotIn("defect_class", blinded)
        self.assertNotIn("cwe", blinded)

    def test_the_location_survives_blinding(self):
        """judge 仍然需要知道判的是哪一处——盲的是答案，不是题目。"""
        blinded = blind_finding(_record()["expected_findings"][0])
        self.assertEqual("a.py", blinded["path"])
        self.assertEqual(1, blinded["start_line"])
        self.assertEqual(3, blinded["end_line"])

    def test_the_payload_never_leaks_an_original_label(self):
        """整个 payload 序列化后不得出现原标签值。

        逐字段断言会漏掉"原标签被塞进某个嵌套结构"的情况，所以直接对
        序列化结果做子串检查。
        """
        blob = json.dumps(build_judge_payload(_record()), ensure_ascii=False)
        self.assertNotIn("CWE-193", blob)
        self.assertNotIn("logic-boundary", blob)

    def test_the_privileged_context_is_deliberately_included(self):
        """human_patch 与 fix_pr_title 必须给。

        这不是答案泄漏：判的是"这个缺陷有多严重"，修复补丁揭示的是缺陷
        **性质**而非严重度档位。这正是把 judge 抬到接近人工标注的关键。
        容易在"加强盲化"时被误删，所以钉住。
        """
        payload = build_judge_payload(_record())
        self.assertIn("raise ValueError", payload["human_patch"])
        self.assertIn("empty header", payload["fix_pr_title"])
        self.assertIn("parse(header)", payload["diff_under_review"])

    def test_the_payload_does_not_contain_the_reviewer_output(self):
        """judge 不能看被评测对象报了什么——那等于让被测者参与制定尺子。"""
        payload = build_judge_payload(_record())
        self.assertEqual(
            {"repository", "domain", "fix_pr_title", "human_patch",
             "diff_under_review", "locations_to_judge"},
            set(payload),
        )


class NormaliseCweTests(unittest.TestCase):
    def test_a_real_cwe_is_kept(self):
        self.assertEqual("CWE-193", normalise_cwe("cwe-193"))

    def test_the_fabricated_placeholders_become_empty(self):
        """v1 全量实测出现过的 5 条：CWE-000 ×3、CWE-0、N/A。

        judge 判 no-defect 时无 CWE 可填，但 schema 要求每条都给，于是编一个。
        留着会让 "CWE-000" 混在真编号里被当成一个真实分类。
        """
        for raw in ("CWE-000", "CWE-0", "N/A", "none", "unknown", "", None):
            self.assertEqual("", normalise_cwe(raw), raw)

    def test_whitespace_and_case_are_normalised(self):
        self.assertEqual("CWE-78", normalise_cwe("  cwe-78 "))


class NormaliseVerdictTests(unittest.TestCase):
    def test_a_well_formed_verdict_passes_through(self):
        verdict = normalise_verdict({
            "severity": "High", "defect_class": "concurrency",
            "cwe": "CWE-362", "confidence": 0.9, "basis": "adds a lock",
        })
        self.assertEqual("high", verdict["severity_llm"])
        self.assertEqual("concurrency", verdict["defect_class_llm"])
        self.assertEqual(LABEL_SOURCE, verdict["label_source"])
        self.assertEqual(RUBRIC_VERSION, verdict["rubric_version"])
        self.assertEqual([], verdict["invalid_fields"])

    def test_an_invalid_severity_is_none_not_a_silent_medium(self):
        """默认成 medium 等于凭空制造一致率——原标签里 89% 就是 medium。"""
        verdict = normalise_verdict({"severity": "catastrophic"})
        self.assertIsNone(verdict["severity_llm"])
        self.assertIn("severity='catastrophic'", verdict["invalid_fields"])

    def test_an_invalid_defect_class_is_traceable(self):
        verdict = normalise_verdict({"severity": "low", "defect_class": "vibes"})
        self.assertIsNone(verdict["defect_class_llm"])
        self.assertIn("defect_class='vibes'", verdict["invalid_fields"])

    def test_confidence_is_clamped_to_the_unit_range(self):
        self.assertEqual(1.0, normalise_verdict({"confidence": 3.0})["confidence"])
        self.assertEqual(0.0, normalise_verdict({"confidence": -1.0})["confidence"])

    def test_an_unparseable_confidence_is_recorded_not_swallowed(self):
        verdict = normalise_verdict({"confidence": "quite sure"})
        self.assertIn("confidence='quite sure'", verdict["invalid_fields"])

    def test_the_verdict_never_writes_an_original_label_field(self):
        """硬约束 3：重标结果并存，不覆盖。这里只产出 *_llm 字段。"""
        verdict = normalise_verdict({"severity": "low", "defect_class": "no-defect"})
        self.assertNotIn("severity", verdict)
        self.assertNotIn("defect_class", verdict)
        self.assertNotIn("cwe", verdict)

    def test_a_placeholder_cwe_is_not_counted_as_a_schema_violation(self):
        """CWE 占位值归一化但**不**计入 invalid_fields。

        rubric 明确 CWE 不参与 severity 判定、也不为编号不精确扣分。把它
        当 schema 违规记账会污染 invalid_field_count——那个字段是用来发现
        真实 schema 违规的。
        """
        verdict = normalise_verdict({
            "severity": "low", "defect_class": "no-defect", "cwe": "CWE-000",
        })
        self.assertEqual("", verdict["cwe_llm"])
        self.assertEqual([], verdict["invalid_fields"])


class SeverityDriftTests(unittest.TestCase):
    def test_the_matrix_records_direction_not_just_a_scalar(self):
        """升级和降级对 high_severity_recall 的影响方向相反，标量看不出来。"""
        matrix = severity_drift(
            ["medium", "medium", "high"], ["high", "low", "high"],
        )
        self.assertEqual(1, matrix["medium"]["high"])
        self.assertEqual(1, matrix["medium"]["low"])
        self.assertEqual(1, matrix["high"]["high"])
        self.assertEqual(0, matrix["high"]["low"])

    def test_unknown_labels_are_skipped_rather_than_crashing(self):
        matrix = severity_drift(["bogus"], ["high"])
        self.assertEqual(0, sum(sum(row.values()) for row in matrix.values()))


def _pair(original, llm, confidence=0.9, klass="logic-boundary"):
    return {
        "original_severity": original, "severity_llm": llm,
        "confidence": confidence, "defect_class_llm": klass,
        "invalid_fields": [],
    }


class RelabelSummaryTests(unittest.TestCase):
    def test_perfect_agreement(self):
        summary = relabel_summary([_pair("high", "high"), _pair("low", "low")])
        self.assertEqual(1.0, summary["severity_agreement"])
        self.assertEqual(0, summary["upgraded"])
        self.assertEqual(0, summary["downgraded"])

    def test_the_high_denominator_shift_is_reported_both_ways(self):
        """直接回答"high_severity_recall 的分母会怎么变"。

        v1 实测 18 → 44。跨标签版本比较这个指标是无效的，所以两个数都要报。
        """
        summary = relabel_summary([
            _pair("medium", "high"), _pair("medium", "high"), _pair("high", "low"),
        ])
        self.assertEqual(1, summary["high_or_above_before"])
        self.assertEqual(2, summary["high_or_above_after"])

    def test_kappa_discounts_chance_agreement(self):
        """全 medium 的原标签 + 常量猜 medium 的 judge：原始一致率满分，κ 无定义。

        这正是 κ 必报的理由：147/165 都是 medium，一个每次都猜 medium 的
        judge 也能拿到约 0.89 的原始一致率。
        """
        summary = relabel_summary([_pair("medium", "medium")] * 5)
        self.assertEqual(1.0, summary["severity_agreement"])
        self.assertIsNone(summary["severity_kappa"])

    def test_an_unjudged_pair_leaves_the_denominator(self):
        """severity_llm 是 None 的条目不进一致率分母——它没有判定可比。"""
        summary = relabel_summary([_pair("high", "high"), _pair("high", None)])
        self.assertEqual(2, summary["total"])
        self.assertEqual(1, summary["judged"])
        self.assertEqual(1.0, summary["severity_agreement"])

    def test_an_empty_input_gives_none_not_zero(self):
        """空分母口径：没样本 → None，不是 0.0（测过了一条没中）。"""
        summary = relabel_summary([])
        self.assertIsNone(summary["severity_agreement"])
        self.assertIsNone(summary["low_confidence_share"])

    def test_no_defect_is_counted_separately(self):
        """no-defect 条目单独报数，**不自动从数据集删除**——删数据要人工确认。"""
        summary = relabel_summary([
            _pair("medium", "low", klass="no-defect"), _pair("high", "high"),
        ])
        self.assertEqual(1, summary["no_defect_count"])

    def test_low_confidence_share_uses_the_full_denominator(self):
        summary = relabel_summary([
            _pair("high", "high", confidence=0.2), _pair("high", "high", confidence=0.9),
        ])
        self.assertEqual(0.5, summary["low_confidence_share"])


class CheckpointStoreTests(unittest.TestCase):
    def setUp(self):
        handle, self.path = tempfile.mkstemp(suffix=".jsonl")
        os.close(handle)
        os.unlink(self.path)

    def tearDown(self):
        if os.path.exists(self.path):
            os.unlink(self.path)

    def test_an_appended_record_is_reloaded_on_the_next_run(self):
        """逐条落盘的全部意义：重跑跳过已完成的，不重新花钱。"""
        CheckpointStore(self.path).append({"case_id": "a", "verdicts": []})
        self.assertEqual({"a"}, set(CheckpointStore(self.path).done))

    def test_a_missing_file_is_an_empty_store_not_an_error(self):
        self.assertEqual({}, CheckpointStore(self.path).done)

    def test_a_cached_placeholder_cwe_is_renormalised_on_read(self):
        """缓存条目是上一次运行的归一化产物，读回来要重跑纯归一化。

        v1 跑完后才发现 5 条编造的占位 CWE。花钱的 API 调用不该为一次纯
        本地的字段清洗重跑，所以读取侧补这一道。
        """
        CheckpointStore(self.path).append({
            "case_id": "a",
            "verdicts": [{"cwe_llm": "CWE-000", "severity_llm": "low"}],
        })
        reloaded = CheckpointStore(self.path).done["a"]
        self.assertEqual("", reloaded["verdicts"][0]["cwe_llm"])
        # 需要重新判定的字段不动——那要换 RUBRIC_VERSION 并真的重跑。
        self.assertEqual("low", reloaded["verdicts"][0]["severity_llm"])

    def test_an_errored_record_is_also_persisted(self):
        """失败也落盘：不然重跑会反复撞同一条，而且分母会静默少掉。"""
        CheckpointStore(self.path).append(
            {"case_id": "a", "error": "boom", "verdicts": []})
        self.assertEqual("boom", CheckpointStore(self.path).done["a"]["error"])


def _verdict(index, severity, human=None):
    item = {
        "finding_id": "case-%02d|a.py|1" % index,
        "severity_llm": severity, "defect_class_llm": "logic-boundary",
        "cwe_llm": "CWE-193", "basis": "because", "confidence": 0.9,
        "invalid_fields": [], "path": "a.py", "start_line": 1,
        "original_severity": "medium", "original_defect_class": "logic-boundary",
        "original_cwe": "CWE-193",
    }
    if human is not None:
        item["severity_human"] = human
    return item


class StratifiedSampleTests(unittest.TestCase):
    def test_every_bucket_is_represented_regardless_of_its_share(self):
        """按新 severity 分层，不是随机抽。

        新标签把 high_or_above 从 18 抬到 44，最需要校准的正是被抬上去的
        那批。随机抽会按分布落在 medium（71/165），critical 只有 1 条大概率
        一条都抽不到——而那 1 条直接影响 high_severity_recall 的分母。
        """
        pool = (
            [_verdict(i, "medium") for i in range(50)]
            + [_verdict(100 + i, "high") for i in range(5)]
            + [_verdict(200, "critical")]
        )
        picked = stratified_calibration_sample(pool, per_bucket=3, seed=1)
        got = {}
        for item in picked:
            got[item["severity_llm"]] = got.get(item["severity_llm"], 0) + 1
        self.assertEqual({"medium": 3, "high": 3, "critical": 1}, got)

    def test_the_same_seed_picks_the_same_batch(self):
        """种子入库保证可复现——这是 rubric 的明文要求。"""
        pool = [_verdict(i, "medium") for i in range(30)]
        first = stratified_calibration_sample(pool, per_bucket=5, seed=7)
        second = stratified_calibration_sample(pool, per_bucket=5, seed=7)
        self.assertEqual(
            [item["finding_id"] for item in first],
            [item["finding_id"] for item in second],
        )

    def test_the_result_does_not_depend_on_the_input_order(self):
        """先排序再洗牌：输入顺序变了（重跑重标）抽到的仍是同一批。"""
        pool = [_verdict(i, "medium") for i in range(30)]
        forward = stratified_calibration_sample(pool, per_bucket=5, seed=7)
        backward = stratified_calibration_sample(pool[::-1], per_bucket=5, seed=7)
        self.assertEqual(
            [item["finding_id"] for item in forward],
            [item["finding_id"] for item in backward],
        )

    def test_growing_the_bucket_keeps_the_earlier_picks(self):
        """加大 per_bucket 时已抽中的仍会被抽中，两批校准结果可以合并。

        每桶独立 rng 就是为了这个：用一个全局 rng 的话，桶大小一变整个
        序列都不同，第二批与第一批不可比，前一轮的人工劳动作废。
        """
        pool = [_verdict(i, "medium") for i in range(30)]
        small = stratified_calibration_sample(pool, per_bucket=5, seed=7)
        large = stratified_calibration_sample(pool, per_bucket=10, seed=7)
        self.assertEqual(
            [item["finding_id"] for item in small],
            [item["finding_id"] for item in large][:5],
        )

    def test_an_unjudged_verdict_is_not_sampled(self):
        """severity_llm 是 None 的条目没有可校准的判定。"""
        self.assertEqual(
            [], stratified_calibration_sample([_verdict(1, None)], per_bucket=5, seed=1),
        )


class CalibrationBlindingTests(unittest.TestCase):
    def test_the_judge_verdict_is_stripped(self):
        blinded = blind_for_calibration(_verdict(1, "high"))
        for key in ("severity_llm", "defect_class_llm", "basis", "confidence"):
            self.assertNotIn(key, blinded)

    def test_the_original_label_is_stripped_too(self):
        """原 severity 正是这次要证伪的对象。

        让人工看见它就是让人锚定到被告席上——那测的不是"人和 judge 对不
        对得上"，是"人会不会被原标签带跑"。
        """
        blinded = blind_for_calibration(_verdict(1, "high"))
        self.assertNotIn("original_severity", blinded)
        self.assertNotIn("original_defect_class", blinded)

    def test_the_location_and_the_blank_fields_survive(self):
        blinded = blind_for_calibration(_verdict(1, "high"))
        self.assertEqual("case-01|a.py|1", blinded["finding_id"])
        self.assertEqual("a.py", blinded["path"])
        self.assertIsNone(blinded["severity_human"])
        self.assertEqual("", blinded["note"])


class CalibrationReportTests(unittest.TestCase):
    def test_the_gate_needs_both_kappa_and_raw_agreement(self):
        """两条并列，不是任一。

        原标签分布里 147/165 是 medium，常量猜测器就能拿到约 0.89 的原始
        一致率——单看一致率无法区分"judge 准"和"两边都在猜众数"。
        """
        self.assertEqual(0.6, CALIBRATION_MIN_KAPPA)
        self.assertEqual(0.85, CALIBRATION_MIN_AGREEMENT)

    def test_a_constant_guesser_does_not_pass_despite_high_agreement(self):
        """全 medium 的两侧：原始一致率 1.0，κ 无定义 → 没有结论，不是达标。"""
        pairs = [{"severity_human": "medium", "severity_llm": "medium"}] * 20
        report = calibration_report(pairs)
        self.assertEqual(1.0, report["agreement"])
        self.assertIsNone(report["kappa"])
        self.assertIsNone(report["meets_gate"])

    def test_a_spread_and_agreeing_batch_passes(self):
        pairs = (
            [{"severity_human": "low", "severity_llm": "low"}] * 10
            + [{"severity_human": "high", "severity_llm": "high"}] * 9
            + [{"severity_human": "high", "severity_llm": "medium"}]
        )
        report = calibration_report(pairs)
        self.assertTrue(report["meets_gate"])
        self.assertIn("人工抽查校准", report["claim_allowed"])

    def test_a_disagreeing_batch_fails_and_says_so(self):
        pairs = (
            [{"severity_human": "low", "severity_llm": "high"}] * 10
            + [{"severity_human": "high", "severity_llm": "low"}] * 10
        )
        report = calibration_report(pairs)
        self.assertFalse(report["meets_gate"])
        self.assertIn("不得用于门禁", report["claim_allowed"])

    def test_an_empty_batch_gives_none_not_false(self):
        """三态不能塌成 False——那会把"没测"伪装成"测了没过"。"""
        report = calibration_report([])
        self.assertIsNone(report["meets_gate"])
        self.assertIsNone(report["agreement"])

    def test_an_unjudged_row_leaves_the_denominator_but_is_still_counted(self):
        """人工判不动的留 None，不进分母；但 sampled 仍报总数。

        留在分母里会把"没判"当成"判得不一样"，系统性压低一致率。
        两个数都报，读者才能看出这个一致率的覆盖面。
        """
        pairs = [
            {"severity_human": "high", "severity_llm": "high"},
            {"severity_human": None, "severity_llm": "low"},
        ]
        report = calibration_report(pairs)
        self.assertEqual(2, report["sampled"])
        self.assertEqual(1, report["judged_by_human"])


if __name__ == "__main__":
    unittest.main()