"""有效告警率标注层的测试。

重点不在"函数能跑"，而在几条容易无声出错的口径：
  - unlabelled 有没有被排除在分母外
  - 空分母返回的是 None 还是 0.0
  - 第二轮盲标有没有真的剥掉标签
  - 两轮配对是按 alert_id 还是按下标
"""
import json
import os
import tempfile
import unittest

from evoagent.alert_labelling import (
    LABEL_INVALID, LABEL_NOISE, LABEL_UNLABELLED, LABEL_VALID, RUBRIC_VERSION,
    AlertRecord, alert_id, cohens_kappa, effective_alert_rate, in_label_scope,
    load_round, retest_summary, sample_alerts, save_round,
)


def _record(index: int, label=None, note: str = "") -> AlertRecord:
    return AlertRecord(
        alert_id=alert_id("CASE-%d" % index, "app/x.py", index, "R-%d" % index),
        case_id="CASE-%d" % index,
        path="app/x.py",
        line=index,
        rule_id="R-%d" % index,
        severity="high",
        title="t%d" % index,
        explanation="e%d" % index,
        diff_excerpt="+ code",
        in_label_scope=True,
        label=label,
        note=note,
    )


class EffectiveRateTests(unittest.TestCase):

    def test_unlabelled_is_out_of_the_denominator(self):
        """3 valid + 1 unlabelled 应当是 3/3 而不是 3/4。

        这是全文件最重要的一条：unlabelled 留在分母里等于把"判不了"
        当成误报，有效告警率被系统性低估。
        """
        summary = effective_alert_rate(
            [LABEL_VALID] * 3 + [LABEL_UNLABELLED])
        self.assertEqual(summary["judgeable"], 3)
        self.assertEqual(summary["effective_alert_rate"], 1.0)

    def test_noise_counts_as_effective_but_not_as_strict_valid(self):
        """valid-but-noise 进有效、不进严格有效。两个数必须分开。"""
        summary = effective_alert_rate([LABEL_VALID, LABEL_NOISE])
        self.assertEqual(summary["effective_alert_rate"], 1.0)
        self.assertEqual(summary["strict_valid_rate"], 0.5)

    def test_invalid_pulls_the_rate_down(self):
        summary = effective_alert_rate([LABEL_VALID, LABEL_INVALID])
        self.assertEqual(summary["effective_alert_rate"], 0.5)

    def test_all_unlabelled_gives_none_not_zero(self):
        """全是 unlabelled 时分母为 0，返回 None。

        0.0 会被读成"一条有效的都没有"（一个结论），而实际是
        "一条都没判"（无结论）。两者证据方向相反。
        """
        summary = effective_alert_rate([LABEL_UNLABELLED] * 5)
        self.assertIsNone(summary["effective_alert_rate"])
        self.assertEqual(summary["unlabelled_share"], 1.0)

    def test_empty_input_gives_none_everywhere(self):
        summary = effective_alert_rate([])
        self.assertIsNone(summary["effective_alert_rate"])
        self.assertIsNone(summary["unlabelled_share"])

    def test_unlabelled_share_keeps_unlabelled_in_its_denominator(self):
        """unlabelled_share 的分母是总数，和有效告警率相反。

        这里问的是"这批告警有多少判不了"，把 unlabelled 排除在分母外
        会让这个数恒为 0，覆盖不足就永远看不见。
        """
        summary = effective_alert_rate(
            [LABEL_VALID, LABEL_VALID, LABEL_UNLABELLED, LABEL_UNLABELLED])
        self.assertEqual(summary["unlabelled_share"], 0.5)


class KappaTests(unittest.TestCase):

    def test_kappa_is_lower_than_raw_agreement_when_labels_are_skewed(self):
        """这条是 κ 存在的理由。

        18/20 都是 valid，两轮在其中 19 条上一致 → 原始一致率 0.95。
        但这种分布下瞎猜 valid 也能得到很高的一致率，κ 扣掉这部分后
        明显更低。若两个数接近，说明 κ 没在算校正。
        """
        first = [LABEL_VALID] * 18 + [LABEL_INVALID, LABEL_INVALID]
        second = [LABEL_VALID] * 18 + [LABEL_INVALID, LABEL_VALID]
        raw = 19 / 20.0
        kappa = cohens_kappa(first, second)
        self.assertAlmostEqual(raw, 0.95)
        self.assertLess(kappa, raw)
        self.assertGreater(kappa, 0.0)

    def test_perfect_agreement_on_mixed_labels_is_one(self):
        labels = [LABEL_VALID, LABEL_INVALID, LABEL_NOISE, LABEL_VALID]
        self.assertEqual(cohens_kappa(labels, list(labels)), 1.0)

    def test_single_label_everywhere_gives_none(self):
        """两轮都只用一个标签时期望一致率为 1，κ 的分母是 0。

        返回 None 而不是 1.0：此时数据不含任何区分信息，
        报 1.0 会被读成"一致性完美"，那是错的结论。
        """
        labels = [LABEL_VALID] * 6
        self.assertIsNone(cohens_kappa(labels, labels))

    def test_length_mismatch_gives_none(self):
        self.assertIsNone(cohens_kappa([LABEL_VALID], [LABEL_VALID] * 2))

    def test_empty_gives_none(self):
        self.assertIsNone(cohens_kappa([], []))

    def test_systematic_flip_can_go_negative(self):
        """完全反着标时 κ 为负。负值有意义：比随机还差。"""
        first = [LABEL_VALID, LABEL_INVALID, LABEL_VALID, LABEL_INVALID]
        second = [LABEL_INVALID, LABEL_VALID, LABEL_INVALID, LABEL_VALID]
        self.assertLess(cohens_kappa(first, second), 0.0)


class BlindingTests(unittest.TestCase):

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, "round1.json")
        save_round(self.path, [_record(1, LABEL_VALID, "因为 X 所以有效")],
                   seed=7, round_name="r1", stamp="2026-09-01")

    def test_blinded_load_strips_label_and_note(self):
        """备注也必须剥掉，不只是标签。

        备注里往往写着判定理由，看到理由和看到结论一样会锚定。
        """
        payload = load_round(self.path, blind=True)
        alert = payload["alerts"][0]
        self.assertNotIn("label", alert)
        self.assertNotIn("note", alert)
        self.assertIn("explanation", alert)   # 判定需要的信息要留下

    def test_unblinded_load_keeps_everything(self):
        """算一致率时需要读上轮标签，所以默认不剥。

        剥不剥是调用点的选择：标注时 blind=True，统计时 blind=False。
        """
        alert = load_round(self.path)["alerts"][0]
        self.assertEqual(alert["label"], LABEL_VALID)

    def test_record_blinded_view_also_strips(self):
        view = _record(2, LABEL_INVALID, "n").blinded()
        self.assertNotIn("label", view)
        self.assertNotIn("note", view)

    def test_seed_is_persisted(self):
        """种子不入库，第二轮就抽不到同一批样本。"""
        with open(self.path, encoding="utf-8") as handle:
            self.assertEqual(json.load(handle)["seed"], 7)

    def test_rubric_version_is_persisted(self):
        """rubric 改版后旧标注不能和新标注混算，靠这个字段区分。"""
        self.assertEqual(load_round(self.path)["rubric_version"], RUBRIC_VERSION)


class SamplingTests(unittest.TestCase):

    def test_same_seed_gives_same_sample(self):
        records = [_record(i) for i in range(30)]
        first = [item.alert_id for item in sample_alerts(records, 10, seed=42)]
        second = [item.alert_id for item in sample_alerts(records, 10, seed=42)]
        self.assertEqual(first, second)

    def test_reviewer_output_order_does_not_change_the_sample(self):
        """这条挡的是最隐蔽的一种失效。

        reviewer 换个输出顺序，若抽样依赖列表顺序，同一个种子就抽到
        另一批样本，两轮重测配不上，而且不会报错。
        """
        records = [_record(i) for i in range(30)]
        forward = [item.alert_id for item in sample_alerts(records, 10, seed=42)]
        backward = [item.alert_id
                    for item in sample_alerts(list(reversed(records)), 10, seed=42)]
        self.assertEqual(forward, backward)

    def test_size_larger_than_pool_returns_everything(self):
        records = [_record(i) for i in range(3)]
        self.assertEqual(len(sample_alerts(records, 10, seed=1)), 3)


def _round(records, name="r1"):
    return {
        "rubric_version": RUBRIC_VERSION,
        "round": name,
        "seed": 1,
        "labelled_at": "2026-09-01",
        "source": "",
        "alerts": [vars(item) for item in records],
    }


class RetestTests(unittest.TestCase):

    def test_pairing_is_by_alert_id_not_by_index(self):
        """第二轮顺序打乱后，一致率仍应是 1.0。

        按下标配对会把"标签相同但位置不同"记成不一致，一致率被无声压低，
        看起来像标准不稳，其实是配对写错了。
        """
        # 四条记录必须带**不同**的标签。全给 valid 的话，倒序前后两个序列
        # 逐位相同，按下标配对也会得到 1.0——那样这条测试通过的是另一个
        # 机制，把配对改成按下标也不会红（实测确认过）。
        labels = {0: LABEL_VALID, 1: LABEL_INVALID,
                  2: LABEL_NOISE, 3: LABEL_VALID}
        first = [_record(i, labels[i]) for i in range(4)]
        second = list(reversed([_record(i, labels[i]) for i in range(4)]))
        summary = retest_summary(_round(first), _round(second, "r2"))
        self.assertEqual(summary["paired"], 4)
        self.assertEqual(summary["raw_agreement"], 1.0)

    def test_unpaired_alerts_are_reported_not_dropped(self):
        """两轮样本不同时必须报出来。

        静默取交集算出的一致率是另一个集合上的数，代表性已经变了，
        而调用方不会知道。
        """
        first = [_record(0, LABEL_VALID), _record(1, LABEL_VALID)]
        second = [_record(0, LABEL_VALID), _record(2, LABEL_VALID)]
        summary = retest_summary(_round(first), _round(second, "r2"))
        self.assertEqual(summary["paired"], 1)
        self.assertEqual(len(summary["unpaired"]), 2)

    def test_disagreement_lowers_raw_agreement(self):
        first = [_record(0, LABEL_VALID), _record(1, LABEL_VALID)]
        second = [_record(0, LABEL_VALID), _record(1, LABEL_INVALID)]
        summary = retest_summary(_round(first), _round(second, "r2"))
        self.assertEqual(summary["raw_agreement"], 0.5)

    def test_judgeable_agreement_excludes_unlabelled_flips(self):
        """unlabelled→valid 的翻转不算"标准不稳"。

        它是"这轮补上了依据"，和判定标准漂移是两件事。混在一个数里
        看不出是哪一种，所以额外报一个只算两轮都判得动的样本的一致率。
        """
        first = [_record(0, LABEL_VALID), _record(1, LABEL_UNLABELLED)]
        second = [_record(0, LABEL_VALID), _record(1, LABEL_VALID)]
        summary = retest_summary(_round(first), _round(second, "r2"))
        self.assertEqual(summary["raw_agreement"], 0.5)
        self.assertEqual(summary["judgeable_paired"], 1)
        self.assertEqual(summary["judgeable_agreement"], 1.0)

    def test_both_round_rates_are_reported(self):
        """两轮各自的有效告警率差得远，说明标准在漂，单轮数字都不可信。"""
        first = [_record(0, LABEL_VALID), _record(1, LABEL_VALID)]
        second = [_record(0, LABEL_INVALID), _record(1, LABEL_INVALID)]
        summary = retest_summary(_round(first), _round(second, "r2"))
        self.assertEqual(summary["round_one_rate"], 1.0)
        self.assertEqual(summary["round_two_rate"], 0.0)

    def test_no_overlap_gives_none_not_zero(self):
        first = [_record(0, LABEL_VALID)]
        second = [_record(9, LABEL_VALID)]
        summary = retest_summary(_round(first), _round(second, "r2"))
        self.assertEqual(summary["paired"], 0)
        self.assertIsNone(summary["raw_agreement"])
        self.assertIsNone(summary["cohens_kappa"])


class ScopeTests(unittest.TestCase):

    EXPECTED = [{"path": "app/x.py", "start_line": 10, "end_line": 12}]

    def test_inside_the_range_is_in_scope(self):
        self.assertTrue(in_label_scope("app/x.py", 11, self.EXPECTED))

    def test_tolerance_extends_both_ends(self):
        """容差取 2，与评测的 line_tolerance 一致，不另立一套。"""
        self.assertTrue(in_label_scope("app/x.py", 8, self.EXPECTED))
        self.assertTrue(in_label_scope("app/x.py", 14, self.EXPECTED))

    def test_just_outside_tolerance_is_out_of_scope(self):
        self.assertFalse(in_label_scope("app/x.py", 7, self.EXPECTED))
        self.assertFalse(in_label_scope("app/x.py", 15, self.EXPECTED))

    def test_other_file_is_out_of_scope(self):
        self.assertFalse(in_label_scope("app/y.py", 11, self.EXPECTED))

    def test_diff_prefixes_are_normalised(self):
        """diff 里的路径带 a/ b/ 前缀，不归一化会让所有告警都判成越界。"""
        self.assertTrue(in_label_scope("b/app/x.py", 11, self.EXPECTED))


if __name__ == "__main__":
    unittest.main()
