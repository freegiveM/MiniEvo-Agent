"""采集器 pilot 模式的预算语义测试。

为什么这些测试值得写：pilot 的全部价值在于"绝不超过 N 次请求"。如果预算
能被超出，它就不是一个能在 60 次/小时配额下安全运行的工具，而是一个会把
配额烧干、让后续连排查都做不了的陷阱。所以这里测的是边界本身。

只替换传输层（urlopen），不替换 _get。如果继承 GitHub 并重写 _get，测到的
就是测试里那份预算检查的副本，而不是生产代码里的那份——那种测试在实现改坏
时不会转红。
"""
import io
import json
import os
import shutil
import sys
import tempfile
import unittest
import urllib.error
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)
SCRIPTS = os.path.join(ROOT, "scripts")
if SCRIPTS not in sys.path:
    sys.path.insert(0, SCRIPTS)

import collect_reverted_fix_dataset as collector  # noqa: E402
from collect_reverted_fix_dataset import (  # noqa: E402
    PILOT_BUDGET,
    BudgetExhausted,
    GitHub,
)


class _Response(io.BytesIO):
    """够 urlopen 的 with 语句用的最小响应对象。"""

    def __init__(self, body="[]", headers=None):
        io.BytesIO.__init__(self, body.encode("utf-8"))
        self.headers = headers or {}

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
        return False


class _Transport(object):
    """记账用的假 urlopen。

    body 要按 URL 分流：list 端点必须返回**非空**的已合并 PR 列表，否则
    collect 的内层循环会立刻 break，pull_diff 一次都不会被调用——预算也就
    永远耗不尽。变异测试正是在这里发现原先那版 transport 无效的。
    """

    def __init__(self, headers=None, pulls=None, diff="diff --git a/x b/x\n"):
        self.calls = 0
        self.urls = []
        self.headers = headers or {}
        self.pulls = pulls
        self.diff = diff

    def __call__(self, request, timeout=None):
        self.calls += 1
        url = request.full_url
        self.urls.append(url)
        if "/pulls?" in url:
            items = self.pulls
            if items is None:
                items = []
            return _Response(json.dumps(items), self.headers)
        return _Response(self.diff, self.headers)


class BudgetTestCase(unittest.TestCase):
    def setUp(self):
        self.transport = _Transport()
        self.real_urlopen = urllib.request.urlopen
        urllib.request.urlopen = self.transport
        self.slept = []
        self.real_sleep = collector.time.sleep
        collector.time.sleep = self.slept.append
        self.addCleanup(self._restore)
        # 必须用临时缓存目录：diff 命中磁盘缓存就不发请求，预算永远耗不尽，
        # 测试会因为"上一次跑留下的缓存"而随机变绿。
        self.cache = tempfile.mkdtemp(prefix="evoagent-pilot-")
        self.addCleanup(shutil.rmtree, self.cache, True)

    def _restore(self):
        urllib.request.urlopen = self.real_urlopen
        collector.time.sleep = self.real_sleep

    def _client(self, max_requests=0, rate_floor=0):
        return GitHub("", self.cache, verbose=False,
                      max_requests=max_requests, rate_floor=rate_floor)


class HardCapTests(BudgetTestCase):
    def test_the_budget_is_never_exceeded(self):
        client = self._client(max_requests=3)
        for _ in range(3):
            client.list_merged_pulls("o/r", 1)
        with self.assertRaises(BudgetExhausted):
            client.list_merged_pulls("o/r", 2)
        # 关键断言是 transport.calls，不是 client.requests：前者是"真的发出去
        # 几次"。只断言后者的话，一个"先发请求再记账"的实现也能过。
        self.assertEqual(self.transport.calls, 3)

    def test_the_refusal_sends_nothing_at_all(self):
        client = self._client(max_requests=1)
        client.list_merged_pulls("o/r", 1)
        before = self.transport.calls
        for _ in range(5):
            with self.assertRaises(BudgetExhausted):
                client.list_merged_pulls("o/r", 1)
        # 超预算后反复调用不应该再漏任何一次请求出去。
        self.assertEqual(self.transport.calls, before)

    def test_zero_means_unlimited(self):
        # 0 是"不限"而不是"一次都不许"。默认值就是 0，若语义反了，
        # 认证后的正式采集会在第一次请求就抛。
        client = self._client(max_requests=0)
        for _ in range(6):
            client.list_merged_pulls("o/r", 1)
        self.assertEqual(self.transport.calls, 6)

    def test_the_default_pilot_budget_fits_the_unauthenticated_quota(self):
        # 未认证配额 60/小时。默认预算必须严格小于它，否则默认跑一次就把
        # 配额烧干，连 rate_limit 查询都做不了。
        self.assertLess(PILOT_BUDGET, 60)


class RateFloorTests(BudgetTestCase):
    """floor 可调的理由：未认证时固定 floor=50 会让第 10 次请求就睡到下个小时。"""

    def test_floor_zero_never_sleeps_on_a_low_unauthenticated_quota(self):
        # 未认证时 remaining 从 59 一路降，全都低于默认 floor=50。
        self.transport.headers = {"X-RateLimit-Remaining": "9",
                                  "X-RateLimit-Reset": "0"}
        client = self._client(max_requests=2, rate_floor=0)
        client.list_merged_pulls("o/r", 1)
        client.list_merged_pulls("o/r", 2)
        self.assertEqual(self.slept, [])

    def test_a_positive_floor_still_sleeps_when_quota_runs_low(self):
        # 认证路径的保护不能因为加了 pilot 就失效。
        self.transport.headers = {"X-RateLimit-Remaining": "9",
                                  "X-RateLimit-Reset": "0"}
        client = self._client(max_requests=1, rate_floor=50)
        client.list_merged_pulls("o/r", 1)
        self.assertEqual(len(self.slept), 1)


class CollectStopsCleanlyTests(BudgetTestCase):
    """预算用尽必须是"提前收尾"，不是"整轮失败"。

    这条最容易写错：把 BudgetExhausted 抛到 main 会丢掉这一轮已采到的 case
    和已统计的淘汰漏斗——而漏斗恰恰是 pilot 唯一的产出。
    """

    def _plan(self):
        return {"defaults": {"max_pages": 3}, "repos": [
            {"name": "o/r1", "split": "validation", "target_prs": 2},
            {"name": "o/r2", "split": "holdout", "target_prs": 2},
        ]}

    def _pulls(self, count=4):
        # merged_at 必填：list_merged_pulls 会过滤掉未合并的关闭 PR。
        # 标题故意用能过 EXCLUDE 的 bugfix 词，好让流程真正走到 pull_diff。
        return [{"number": 100 + i, "title": "fix crash in handler",
                 "body": "", "merged_at": "2024-01-0%dT00:00:00Z" % (i + 1),
                 "html_url": "https://example.invalid/%d" % (100 + i)}
                for i in range(count)]

    def test_the_diff_request_is_what_exhausts_the_budget(self):
        # 这条是前置条件的自测：证明 list 之后确实会发 diff 请求。
        # 没有它，下面两条可能因为"根本没走到 pull_diff"而假绿——
        # 变异测试抓到过这个坑。
        self.transport.pulls = self._pulls()
        client = self._client(max_requests=3)
        collector.collect(client, self._plan(), "2024-07-01", 10)
        diff_calls = [u for u in self.transport.urls if "/pulls?" not in u]
        self.assertGreater(len(diff_calls), 0)

    def test_exhausting_the_budget_returns_partial_results(self):
        self.transport.pulls = self._pulls()
        client = self._client(max_requests=2)
        # 不抛异常就是本条的断言：collect 必须自己收尾。
        cases, rejections = collector.collect(client, self._plan(), "2024-07-01", 10)
        self.assertIsInstance(cases, list)
        self.assertIsInstance(rejections, dict)
        self.assertEqual(self.transport.calls, 2)

    def test_the_budget_can_also_run_out_on_a_list_request(self):
        """预算耗尽有两个发生点，list 和 diff，各需要独立捕获。

        算术（假 transport 忽略 page 参数，每页返回同一批 PR 号）：
          仓库1 第1页：list=1，diff 100..103 = 2..5
          仓库1 第2页：list=6，四个 diff 全部命中磁盘缓存 → 0 次请求
        所以第 7 次请求是仓库1 第3页的 list。预算设 6，耗尽点正好落在 list 上。

        **磁盘缓存是这里的关键**，第一次算漏了它，以为要 15 次。缓存命中
        不发请求也不计预算——这正是 --resume 二次运行零请求的原因。
        变异测试证明：没有这条，删掉 list 处的捕获不会转红。
        """
        self.transport.pulls = self._pulls(count=4)
        client = self._client(max_requests=6)
        cases, rejections = collector.collect(client, self._plan(), "2024-07-01", 99)
        self.assertEqual(self.transport.calls, 6)
        last = self.transport.urls[-1]
        self.assertIn("/pulls?", last)   # 最后一次确实是 list
        self.assertTrue(rejections)

    def test_the_rejection_funnel_survives_budget_exhaustion(self):
        # 漏斗计数必须活着回来——pilot 的唯一产出就是它。
        # 给足预算让前几个候选被淘汰并记账，再让预算在中途耗尽。
        self.transport.pulls = self._pulls(count=8)
        client = self._client(max_requests=4)
        cases, rejections = collector.collect(client, self._plan(), "2024-07-01", 10)
        # 假 diff 不含合法 hunk，会被判 unsupported-diff，所以漏斗必然非空。
        self.assertTrue(rejections)
        self.assertEqual(sum(rejections.values()) > 0, True)


if __name__ == "__main__":
    unittest.main()
