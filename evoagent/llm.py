"""Small OpenAI-compatible JSON client with auditable usage accounting."""
import json
import socket
import time
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional

from .telemetry import ExecutionLedger


class JsonChatClient:
    def __init__(
        self, base_url: str, api_key: str, model: str,
        provider: str = "openai-compatible", timeout: int = 60,
        extra_headers: Optional[Dict[str, str]] = None,
    ):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.model = model
        self.provider = provider
        self.timeout = timeout
        self.extra_headers = dict(extra_headers or {})

    def complete_json(
        self, role: str, system: str, user: str,
        ledger: Optional[ExecutionLedger] = None,
        max_tokens: Optional[int] = None,
        retry_on_blank: bool = True,
    ) -> Dict[str, Any]:
        payload: Dict[str, Any] = {
            "model": self.model,
            "temperature": 0,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "response_format": {"type": "json_object"},
        }
        if max_tokens:
            payload["max_tokens"] = int(max_tokens)
        headers = {
            "Authorization": "Bearer " + self.api_key,
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        headers.update(self.extra_headers)
        request = urllib.request.Request(
            self.base_url + "/chat/completions",
            data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
            headers=headers, method="POST",
        )
        started = time.monotonic()
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                body = json.loads(response.read().decode("utf-8"))
            choice = body["choices"][0]
            content = choice["message"]["content"]
            # 判据是 finish_reason，不是 content 空不空。
            #
            # 推理模型上 max_tokens 同时封顶 reasoning + content，预算耗尽有
            # **两种**表现：推理吃光全部预算 → content 空串；推理吃掉大部分、
            # content 只写了一半 → 截断的 JSON。原来只拦第一种，第二种掉进
            # json.loads，报成 "Unterminated string starting at char 5103"，
            # 于是同一个病根产出两条完全不同的消息，其中一条把人指向 JSON
            # 解析——照着它查永远查不到预算上。
            #
            # 而且第二种更隐蔽：它取决于推理多花了几百个 token，表现为**间歇
            # 性失败**，同样的输入重放一次往往就过了。
            #
            # 截断的 JSON 恰好能解析出来时也要拦（所以这道检查在 json.loads
            # 之前）。那比报错更危险：一份缺了后半截的候选会被当成完整的候选
            # 送进门禁——与本仓库反复出现的那类"假装成功"是同一种错误。
            usage = body.get("usage") or {}
            details = usage.get("completion_tokens_details") or {}
            budget_note = (
                "completion_tokens=%s, reasoning_tokens=%s, max_tokens=%s, "
                "content_chars=%d" % (
                    usage.get("completion_tokens"),
                    details.get("reasoning_tokens"),
                    max_tokens,
                    len(content or ""),
                )
            )
            if choice.get("finish_reason") == "length":
                raise ValueError(
                    "model output hit the token budget (finish_reason=length, %s); "
                    "raise the token budget for reasoning models" % budget_note
                )
            # finish_reason=stop 但 content 是空串或纯空白，是**另一个**病根，
            # 不能报成预算耗尽。实测 deepseek-v4-flash 在 JSON 模式下会出现：
            # 整轮把话说在 reasoning_content 里、结尾停在"让我调工具"，然后
            # content 通道只吐一串空格就正常收尾（finish_reason=stop，
            # completion_tokens 远低于 max_tokens）。之前这条和 length 合并成
            # 一条 "hit the token budget"，于是把人指向抬预算——抬到 16000 也
            # 没用，因为根本没到顶。
            #
            # 这是模型侧的间歇行为，不是我们的输入坏了：重放同一个输入往往就
            # 过了。所以补一次带 nudge 的重试，而不是直接判失败——单次瞬时空
            # 回答被当成"这个 case 模型答不出来"，会把漏报记到评测账上，比多
            # 花一次调用贵。重试仍然有界（只一次），失败照旧抛错，不会变成
            # 无限烧钱的循环。
            if not (content or "").strip():
                if retry_on_blank:
                    # 光说"现在就回答"没用（实测重试仍然空回答）。空回答几乎
                    # 全部发生在模型想调工具的那一步：它在 reasoning 里盘算
                    # 要调哪个工具，然后 content 通道只吐空格。把工具通道显
                    # 式关掉、要求以 { 开头，实测同一个失败输入连续三次都能
                    # 正常返回 final。
                    #
                    # 这样降级掉的是"这一步本来想补一次工具证据"，不是把结论
                    # 编出来：模型仍然只能用已有的 diff 和 observations 作答，
                    # 拿不到证据就只能少报，不会凭空多报。少报会照实记进召回，
                    # 而整轮抛错会把这条 case 直接记成执行失败——前者是可解释
                    # 的度量损失，后者是把模型侧的间歇行为算成产品缺陷。
                    return self.complete_json(
                        role, system,
                        user + (
                            "\n\nThe tool channel is now CLOSED for this request: "
                            "no further tool calls are permitted. Reply with the "
                            "{\"action\":\"final\",...} object based only on the diff "
                            "and observations already given. Begin your reply with "
                            "the { character."
                        ),
                        ledger, max_tokens=max_tokens, retry_on_blank=False,
                    )
                raise ValueError(
                    "model returned blank content with finish_reason=stop (%s); "
                    "the answer stayed in reasoning_content and never reached the "
                    "content channel" % budget_note
                )
            # 推理模型在 JSON 模式下偶尔会把下一步想做的好几个 tool call 一次
            # 性全部吐出来，一个挨一个的独立 JSON 对象（不是数组，是原样拼接），
            # 而 loop 协议每步只认第一个 action。原来直接 json.loads(content)
            # 整段解析，第二个对象一出现就报 "Extra data"——这不是坏输出，
            # 是模型多算了几步，只解析第一个对象、丢弃其余，与"每步一个
            # action"的协议语义一致，且不会掩盖真正截断/损坏的 JSON（第一个
            # 对象本身解析不出来时 raw_decode 照样抛错）。
            result, _ = json.JSONDecoder().raw_decode(content.lstrip())
            if not isinstance(result, dict):
                raise ValueError("model JSON root is not an object")
            if ledger:
                ledger.record_model(
                    role, self.provider, self.model, body.get("usage") or {},
                    int((time.monotonic() - started) * 1000), True,
                )
            return result
        except urllib.error.HTTPError as exc:
            detail = exc.read(1000).decode("utf-8", errors="replace")
            message = "%s API returned HTTP %d: %s" % (
                self.provider, exc.code, detail,
            )
        except (urllib.error.URLError, socket.timeout, ValueError, KeyError,
                IndexError, TypeError, json.JSONDecodeError) as exc:
            message = "%s JSON request failed: %s" % (self.provider, exc)
        if ledger:
            ledger.record_model(
                role, self.provider, self.model, {},
                int((time.monotonic() - started) * 1000), False, message,
            )
        raise RuntimeError(message)
