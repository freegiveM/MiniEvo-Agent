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
            # 推理模型上 max_tokens 同时封顶 reasoning + content：预算被推理
            # 吃完时 content 是空串，finish_reason 是 length。直接 json.loads("")
            # 会报 "Expecting value: line 1 column 1"，把一个预算问题说成模型
            # 返回了非法 JSON——照着那条消息去查 JSON 解析永远查不到病根。
            if not (content or "").strip():
                usage = body.get("usage") or {}
                details = usage.get("completion_tokens_details") or {}
                raise ValueError(
                    "model returned empty content (finish_reason=%s, "
                    "completion_tokens=%s, reasoning_tokens=%s, max_tokens=%s); "
                    "raise the token budget for reasoning models"
                    % (
                        choice.get("finish_reason"),
                        usage.get("completion_tokens"),
                        details.get("reasoning_tokens"),
                        max_tokens,
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
