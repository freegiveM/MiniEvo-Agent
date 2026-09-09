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
            if choice.get("finish_reason") == "length" or not (content or "").strip():
                usage = body.get("usage") or {}
                details = usage.get("completion_tokens_details") or {}
                raise ValueError(
                    "model output hit the token budget (finish_reason=%s, "
                    "completion_tokens=%s, reasoning_tokens=%s, max_tokens=%s, "
                    "content_chars=%d); raise the token budget for reasoning models"
                    % (
                        choice.get("finish_reason"),
                        usage.get("completion_tokens"),
                        details.get("reasoning_tokens"),
                        max_tokens,
                        len(content or ""),
                    )
                )
            result = json.loads(content)
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
