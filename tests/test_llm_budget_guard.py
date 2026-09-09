"""预算耗尽必须报成预算问题，不管 content 是空串还是半截。

`max_tokens` 在推理模型上同时封顶 reasoning + content，所以预算耗尽有两种
表现：

- 推理吃光全部预算 → `content` 是空串；
- 推理吃掉大部分、`content` 只写了一半 → **截断的 JSON**。

原来的守卫只看 content 空不空，于是第二种掉进 `json.loads`，被报成
"Unterminated string starting at char 5103"。同一个病根产出两条完全不同的
消息，其中一条把人指向 JSON 解析——照着它查永远查不到预算上。回路 C 第一轮
就是这么死的，而且它取决于推理多花了几百个 token，表现为间歇性失败。

判据因此改成 `finish_reason`。
"""
import json
import unittest
import urllib.request

from evoagent.llm import JsonChatClient


class _Response:
    """够 urlopen 的 with 语句用的最小响应对象。"""

    def __init__(self, body):
        self._body = json.dumps(body).encode("utf-8")

    def read(self):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _body(content, finish_reason, reasoning_tokens=11740):
    return {
        "choices": [{
            "message": {"content": content},
            "finish_reason": finish_reason,
        }],
        "usage": {
            "completion_tokens": 13299,
            "prompt_tokens": 4333,
            "completion_tokens_details": {"reasoning_tokens": reasoning_tokens},
        },
    }


class TokenBudgetGuardTests(unittest.TestCase):
    def setUp(self):
        self.client = JsonChatClient(
            "https://example.invalid/v1", "test-key", "reasoning-model",
            provider="deepseek",
        )
        self._real_urlopen = urllib.request.urlopen

    def tearDown(self):
        urllib.request.urlopen = self._real_urlopen

    def _respond(self, body):
        urllib.request.urlopen = lambda *a, **k: _Response(body)

    def _call(self):
        return self.client.complete_json(
            "evolution-root-cause", "system", "user", None, 16000)

    def test_truncated_json_is_reported_as_a_budget_problem(self):
        """**本组最要紧的断言。** 这就是回路 C 第一轮的真实形态。

        半截的 JSON 报成 "Unterminated string" 会把人指向解析器，而病根在
        预算。错误消息必须点名 finish_reason 和 usage 数字。
        """
        # 一份在字符串中间断掉的 JSON，与真实截断一模一样。
        self._respond(_body('{"candidate": {"prompt_additions": ["do not rep',
                            "length"))

        with self.assertRaises(RuntimeError) as caught:
            self._call()

        message = str(caught.exception)
        self.assertIn("token budget", message)
        self.assertIn("finish_reason=length", message)
        self.assertIn("reasoning_tokens=11740", message)
        # 半截内容的长度要报出来：它区分了"推理吃光了"和"写了一半"。
        self.assertIn("content_chars=", message)
        self.assertNotIn("Unterminated", message)

    def test_a_truncation_that_happens_to_parse_is_still_refused(self):
        """截断处恰好是合法 JSON 时**更**危险，不是更安全。

        一份缺了后半截的候选会被当成完整的候选送进门禁——与本仓库反复出现
        的那类"假装成功"是同一种错误。所以这道检查必须在 json.loads 之前。
        """
        self._respond(_body('{"candidate": {}}', "length"))

        with self.assertRaises(RuntimeError) as caught:
            self._call()

        self.assertIn("token budget", str(caught.exception))

    def test_empty_content_is_still_caught(self):
        """预算耗尽的第一种表现，原来就拦得住，不能在改判据时丢掉。"""
        self._respond(_body("", "length"))

        with self.assertRaises(RuntimeError) as caught:
            self._call()

        self.assertIn("token budget", str(caught.exception))

    def test_an_empty_content_without_length_is_also_refused(self):
        """content 空串但 finish_reason 不是 length：仍然产不出候选。

        判据改成 finish_reason 之后，这一支靠的是那个 `or`。少了它，一次
        返回空串的调用会掉进 json.loads("")，回到原来那条误导性消息。
        """
        self._respond(_body("   ", "stop"))

        with self.assertRaises(RuntimeError) as caught:
            self._call()

        self.assertIn("token budget", str(caught.exception))

    def test_a_complete_response_is_returned_unchanged(self):
        """收紧不能误伤正常返回：finish_reason=stop + 完整 JSON 照常通过。"""
        self._respond(_body('{"candidate": {"prompt_additions": ["a"]}}',
                            "stop"))

        self.assertEqual(
            {"candidate": {"prompt_additions": ["a"]}}, self._call())


if __name__ == "__main__":
    unittest.main()